import os
import glob
import pickle
import threading
import time
import itertools
import yaml
import random
from . import imageutil
import string
from queue import Queue
from .funcaptcha import FunCaptchaSession, Proxy, BadGameTypeOrVariant, BannedProxy
from .fingerprint import Fingerprint, Window

DB_PATH = "solver/solver-db"
hash_method = imageutil.methods["average_hash"]
hash_length = 6
masking = True

## load db if it exists
if not os.path.exists(DB_PATH):
    os.mkdir(DB_PATH)
    cache = dict()
    appear = dict()
else:
    if os.path.exists(os.path.join(DB_PATH, "cache.p")):
        with open(os.path.join(DB_PATH, "cache.p"), "rb") as f:
            cache = pickle.load(f)
    else:
        cache = dict()
    if os.path.exists(os.path.join(DB_PATH, "appear.p")):
        with open(os.path.join(DB_PATH, "appear.p"), "rb") as f:
            appear = pickle.load(f)
    else:
        appear = dict()

def prepare_image(im, label=None):
    im = imageutil.remove_background(im)
    im = im.crop(im.getbbox())
    if masking:
        im = imageutil.mask(im)
    return im

def rnd_str():
    charset = string.ascii_letters + string.digits
    l = random.randint(6, 18)
    return "".join(random.choice(charset) for _ in range(l))

class Solver:
    def __init__(self, public_key: str, service_url: str, proxies: list):
        self.public_key = public_key
        self.service_url = service_url

        self.solve_queue = Queue()
        self.resubmit_queue = Queue()

        self.solve_workers = list()
        self.resubmit_workers = list()

        self.success_count = 0
        self.failure_count = 0

        self.identities = list()
        for fp in glob.glob(os.path.join("solver", "identities", "*.yaml")):
            with open(fp) as f:
                identity = yaml.safe_load(f)
                identity["fingerprint"]["jsbd"] = eval(identity["fingerprint"]["jsbd"])
                self.identities.append(identity)

        self.identity_iter = itertools.cycle(self.identities)
        self.proxy_iter = itertools.cycle(proxies)

    def get_solve(self):
        return self.solve_queue.get(True)
    
    def resubmit(self, ch):
        self.resubmit_queue.put(ch)

    def get_identity(self):
        proxy = Proxy(next(self.proxy_iter))
        info = next(self.identity_iter)
        window = Window(
            title="Roblox",
            url=info["urls"][self.public_key].format(username=rnd_str()))
        fp = Fingerprint(
            user_agent=info["fingerprint"]["user_agent"],
            protochain_hash=info["fingerprint"]["protochain_hash"],
            sec_fetch=info["fingerprint"]["sec_fetch"],
            content_type_value=info["fingerprint"]["content_type_value"],
            accept_language_value=info["fingerprint"]["accept_language_value"],
            jsbd_gen=info["fingerprint"]["jsbd"],
            DNT=info["fingerprint"]["donottrack"],
            L=info["fingerprint"]["lang"],
            D=info["fingerprint"]["depth"],
            PR=info["fingerprint"]["pixel_ratio"],
            S=info["fingerprint"]["resolution"],
            AS=info["fingerprint"]["available"],
            SS=info["fingerprint"]["sessionstorage"],
            LS=info["fingerprint"]["localstorage"],
            IDB=info["fingerprint"]["indexeddb"],
            B=info["fingerprint"]["B"],
            ODB=info["fingerprint"]["opendb"],
            CPUC=info["fingerprint"]["cpuclass"],
            PK=info["fingerprint"]["platform_key"],
            JSF=info["fingerprint"]["fonts"],
            P=info["fingerprint"]["plugins"],
            T=info["fingerprint"]["touch"],
            H=info["fingerprint"]["hardware_concurrency"],
            SWF=info["fingerprint"]["swf"]
        )
        return proxy, fp, window
    
    def start(self, solvers: int, resubmitters: int):
        sworkers = [SolveWorker(self) for _ in range(solvers)]
        rworkers = [ResubmitWorker(self) for _ in range(resubmitters)]

        for sw in sworkers: self.solve_workers.append(sw)
        for rw in rworkers: self.resubmit_workers.append(rw)
        for sw in sworkers: sw.start()
        for rw in rworkers: rw.start()

class ResubmitWorker(threading.Thread):
    def __init__(self, s):
        self._s = s
        super().__init__()
    
    def run(self):
        while 1:
            ch = self._s.resubmit_queue.get(True)
            if ch.resubmitted: continue
            try:
                ch.resubmitted = True
                if ch.check_answer(None, bypass=True):
                    self._s.solve_queue.put(ch)
            except Exception as err:
                print("Error while resubmitting challenge:",
                      err)

class SolveWorker(threading.Thread):
    def __init__(self, s):
        self._s = s
        super().__init__()

    def new_session(self):
        proxy, fp, window = self._s.get_identity()
        s = FunCaptchaSession(
            public_key=self._s.public_key,
            service_url=self._s.service_url,
            window=window,
            fingerprint=fp,
            analytics=True,
            proxy=proxy,
            whitelisted_types=[1]
        )
        self.session = s

    def run(self):
        self.new_session()
        while 1:
            try:
                ch = self.session.get_challenge()
                
                if not ch.image_urls:
                    self._s.solve_queue.put(ch)
                    continue

                for imdata in ch.images:
                    im = imageutil.to_pil(imdata)
                    mim = prepare_image(im, label="main")
                    mh = imageutil.hash_image(mim, hash_method, hash_length)
                    appear[mh] = 1
                    
                    for rn in range(1, int(360/ch.rotate_degree)):
                        rd = ch.rotate_degree * rn
                        rk = "%s|%.2f" % (mh, rd)
                        rh = cache.get(rk)
                        if not rh:
                            rim = prepare_image(im.rotate(rd*-1), label="rotate")
                            rh = imageutil.hash_image(rim, hash_method, hash_length)
                            cache[rk] = rh
                        if not rh in appear:
                            break
                    
                    solved = ch.check_answer(rd)

                if solved:
                    self._s.solve_queue.put(ch)
                    self._s.success_count += 1
                else:
                    self._s.failure_count += 1

            except (BadGameTypeOrVariant, BannedProxy):
                self.new_session()

            except Exception as err:
                print("Error while solving:", err)
                self.new_session()

class DBSaveWorker(threading.Thread):
    def __init__(self, interval: int = 60):
        self.interval = interval
        super().__init__()
    
    def run(self):
        while 1:
            time.sleep(self.interval)
            try:
                d = pickle.dumps(dict(cache))
                with open(os.path.join(DB_PATH, "cache.p"), "wb") as f:
                    f.write(d)
                
                d = pickle.dumps(dict(appear))
                with open(os.path.join(DB_PATH, "appear.p"), "wb") as f:
                    f.write(d)
                del d
            except Exception as err:
                print("Error while trying to save files:",
                      err)

DBSaveWorker().start()

if __name__ == "__main__":
    s = Solver(
        public_key="A2A14B1D-1AF3-C791-9BBC-EE33CC7A0A6F",
        service_url="https://roblox-api.arkoselabs.com",
        window=dict(
            title="Roblox",
            url="https://www.roblox.com/account/signupredir"),
        proxies=open("proxies.txt").read().splitlines())
    s.start(100, 1)

    while 1:
        ch = s.get_solve()
        print(ch.full_token)
        s.resubmit(ch)
