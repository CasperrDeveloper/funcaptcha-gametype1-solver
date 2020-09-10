## FunCaptcha module for Python 3
## twitter.com/h0nde
## 2020-09-06

## This library was mostly used with the Roblox iOS app's specifics in mind
## so you may need to look out for certain changes that were introduced with that

import http.client
import json
import random
import string
import hashlib
import sys
import time
import os
import math
from base64 import b64encode, b64decode
from .fingerprint import Fingerprint, Window
from urllib.parse import urlparse, urlencode
from Crypto.Cipher import AES

API_BREAKER = {
    "method_1": lambda x,y: dict(x=y,y=x),
    "method_2": lambda x,y: dict(x=y,y=(y+x)*x),
    "method_3": lambda x,y: dict(a=x,b=y),
    "method_4": lambda x,y: [x,y],
    "method_5": lambda x,y: list(map(math.sqrt, [y,x])),
}


def cryptojs_encrypt(data: (str, bytes), key: str) -> str:
    data = data + chr(16-len(data)%16)*(16-len(data)%16)

    salt = b"".join(random.choice(string.ascii_lowercase).encode() for x in range(8))
    salted, dx = b"", b""
    while len(salted) < 48:
        dx = hashlib.md5(dx+key.encode()+salt).digest()
        salted += dx

    key = salted[:32]
    iv = salted[32:32+16]
    aes = AES.new(key, AES.MODE_CBC, iv)

    encrypted_data = {"ct": b64encode(aes.encrypt(data.encode())).decode("utf-8"), "iv": iv.hex(), "s": salt.hex()}
    return json.dumps(encrypted_data, separators=(',', ':'))


def cryptojs_decrypt(data: (str, bytes), key: str) -> bytes:
    data = json.loads(data)
    dk = key.encode()+bytes.fromhex(data["s"])

    md5 = [hashlib.md5(dk).digest()]
    result = md5[0]
    for i in range(1, 3+1):
        md5.insert(i, hashlib.md5((md5[i-1]+dk)).digest())
        result += md5[i]
    
    aes = AES.new(result[:32], AES.MODE_CBC, bytes.fromhex(data["iv"]))
    data = aes.decrypt(b64decode(data["ct"]))
    return data


class Proxy:
    def __init__(self, proxy, type="http"):
        u = urlparse("https://%s" % proxy)
        self.type = type
        self.host = u.hostname
        self.port = u.port
        self.username = u.username
        self.password = u.password

        self.xsrf_token = None

    def __hash__(self):
        return hash((self.host.lower(), self.port, self.username,
                    self.password))

    def __repr__(self):
        auth = ""
        if self.username:
            auth = "%s:%s@" % (self.username, self.password)
        return "%s%s:%s" % (auth, self.host, self.port)


class BannedProxy(Exception): pass
class BadGameTypeOrVariant(Exception): pass

class FunCaptchaChallenge:
    #session: FunCaptchaSession
    fp: Fingerprint
    full_token: str
    session_token: str
    challenge_token: str
    region: str
    meta: int
    lang: str
    analytics_tier: str
    secure: int
    rotate_degree: int
    waves: int
    guesses: list
    image_ekey: str
    image_urls: list
    request_data: dict
    game_type: int

    
    def __init__(self, session, start_time, full_token, session_token, region,
                meta, lang, analytics_tier, secure=None):
        self.resubmitted = False
        self.session = session
        self.start_time = start_time
        self.whitelisted_types = self.session.whitelisted_types
        self.whitelisted_variants = self.session.whitelisted_variants
        self.proxy = self.session.proxy
        self.service = session.service
        self.window = session.window
        self.fp = session.fp
        self.get_conn = session.get_conn
        self.full_token = full_token
        self.session_token = session_token
        self.region = region
        self.meta = meta
        self.lang = lang
        self.analytics_tier = analytics_tier
        self.guesses = []
        self.image_ekey = None
        self.secure = secure
        self.analytics = session.analytics
        self.request_data = {}
        self.game_type = None
        self.close_conns = session.close_conns

        ## get session url
        if self.analytics:
            self.visit()
        if self.analytics and 1==1:
            self.send_analytics(session_token=self.session_token,
                                render_type="canvas",
                                category="Site URL",
                                analytics_tier=self.analytics_tier,
                                action=self.window.url,
                                sid=self.region)
        self.load()
        if self.analytics:
            self.send_analytics(session_token=self.session_token,
                                render_type="canvas",
                                game_token=self.challenge_token,
                                category="loaded",
                                game_type=self.game_type,
                                analytics_tier=self.analytics_tier,
                                action="game loaded",
                                sid=self.region)
        self.request_data["sc"] = self.fp.get_xy()
        if self.encrypted_mode:
            self.get_encryption_key()
        if self.analytics:
            self.send_analytics(session_token=self.session_token,
                                render_type="canvas",
                                game_token=self.challenge_token,
                                category="begin app",
                                game_type=self.game_type,
                                analytics_tier=self.analytics_tier,
                                action="user clicked verify",
                                sid=self.region)
    

    @property
    def elapsed_time(self):
        return round(time.time()-self.start_time, 2)

    
    def __repr__(self):
        return "<Challenge (Token:%s, Type:%d, Variant:%s, Imageset:%s, Breaker:%s, Waves:%d, Degree:%d, Resubmitted: %s, Elapsed:%.2fs)>" % \
            (self.challenge_token, self.game_type, self.game_variant,
             self.imageset,
             self.api_breaker, self.waves, self.rotate_degree,
             self.resubmitted, self.elapsed_time)


    def load(self):
        data = urlencode({
            "sid": self.region,
            "token": self.session_token,
            "analytics_tier": self.analytics_tier,
            "data[status]": "init",
            "lang": self.lang,
            "render_type": "canvas"
        })
        headers = self.fp.get_headers(
            host=self.service, method="POST", data=data,
            cache_control=True, xml=True,
            origin="https://%s" % self.service,
            referer=self.get_session_url(),
            timestamp=True,
            fetch_site="same-origin", fetch_mode="cors",
            fetch_dest="empty")
        self.add_requested_headers(headers)
        conn = self.get_conn(self.service)
        conn.putrequest("POST", "/fc/gfct/",
                        skip_host=True, skip_accept_encoding=True)
        for header, value in headers:
            conn.putheader(header, value)
        conn.endheaders()
        conn.send(data.encode("UTF-8"))

        resp = conn.getresponse()
        data = resp.read()
        data = json.loads(data)
        
        if "error" in data:
            raise BannedProxy("DENIED ACCESS")
        self.challenge_token = data["challengeID"]
        self.game_type = data["game_data"]["gameType"]
        self.game_variant = data["game_data"].get("game_variant")
        self.waves = data["game_data"]["waves"]
        self.encrypted_mode = data["game_data"]["customGUI"].get("encrypted_mode") == 1
        self.image_urls = data["game_data"]["customGUI"]["_challenge_imgs"]
        self.imageset = self.image_urls[0].split("production/")[1].split("/")[0] \
                        if self.image_urls and "production/" in self.image_urls[0] \
                        else None
        self.api_breaker = data["game_data"]["customGUI"].get("api_breaker")
        self.rotate_degree = float(int(data["game_data"]["customGUI"]["_guiFontColr"].replace("#", "")[-3:], 16)) if "_guiFontColr" in data["game_data"]["customGUI"] else None
        if self.rotate_degree and self.rotate_degree > 113: self.rotate_degree = self.rotate_degree/10

        if self.whitelisted_types is not None \
            and not self.game_type in self.whitelisted_types:
            raise BadGameTypeOrVariant("Non-whitelisted game type: %d" \
                            % self.game_type)
                        
        if self.game_variant and self.whitelisted_variants is not None \
            and not self.game_variant.lower() in self.whitelisted_variants:
            raise BadGameTypeOrVariant("Non-whitelisted game variant: %s" \
                            % self.game_variant)



    """
    Gets referer url for game session page
    """
    def get_session_url(self):
        params = "&".join([
            q.replace("#", "%23")
            for q in self.full_token.split("|")
        ])
        return "https://%s/fc/gc/?token=%s" \
            % (self.service, params)


    """
    Adds XRW headers to parameter
    """
    def add_requested_headers(self, headers):
        ts = str(int(self.fp.get_timestamp() * 100000))
        if self.game_type == 3:
            rdata = dict()
        else:
            rdata = self.request_data
        data = cryptojs_encrypt(
            json.dumps(rdata, separators=(',', ':')),
            "REQUESTED%sID" % self.session_token)
        headers.append(["X-NewRelic-Timestamp", ts])
        headers.append(["X-Requested-ID", data])

    
    """
    Visits session page
    """
    def visit(self):
        headers = self.fp.get_headers(
            host=self.service, method="GET", data=None,
            cache_control=False, xml=False,
            timestamp=False,
            referer=self.window.url,
            origin=None,
            fetch_site="cross-site", fetch_mode="navigate",
            fetch_dest="iframe")
        
        u = urlparse(self.get_session_url())
        path = u.path + "?" + u.query
        conn = self.get_conn(self.service)
        conn.putrequest("GET", path)
        for k,v in headers:
            conn.putheader(k,v)
        conn.endheaders()
        resp = conn.getresponse()
        data = resp.read()


    """
    Sends analytics request with specified parameters
    """
    def send_analytics(self, **kwargs):
        data = urlencode(kwargs)
        headers = self.fp.get_headers(
            host=self.service, method="POST", data=data,
            cache_control=True, xml=True,
            timestamp=True,
            origin="https://%s" % self.service,
            referer=self.get_session_url(),
            fetch_site="same-origin", fetch_mode="cors",
            fetch_dest="empty")
        self.add_requested_headers(headers)

        conn = self.get_conn(self.service)
        conn.putrequest("POST", "/fc/a/",
                        skip_host=True, skip_accept_encoding=True)    
        for header, value in headers:
            conn.putheader(header, value)
        conn.endheaders()
        conn.send(data.encode("UTF-8"))

        resp = conn.getresponse()
        data = resp.read()
        data = json.loads(data)
        return data


    """
    Get starter encryption key for images
    """
    def get_encryption_key(self):
        data = urlencode({
            "session_token": self.session_token,
            "sid": self.region,
            "game_token": self.challenge_token
        })
        headers = self.fp.get_headers(
            host=self.service, method="POST", data=data,
            cache_control=True, xml=True,
            origin="https://%s" % self.service,
            referer=self.get_session_url(),
            fetch_site="same-origin", fetch_mode="cors",
            fetch_dest="empty", timestamp=True)
        self.add_requested_headers(headers)

        conn = self.get_conn(self.service)
        conn.putrequest("POST", "/fc/ekey/",
                        skip_host=True, skip_accept_encoding=True)    
        for header, value in headers:
            conn.putheader(header, value)
        conn.endheaders()
        conn.send(data.encode("UTF-8"))

        resp = conn.getresponse()
        data = resp.read()
        data = json.loads(data)

        self.image_ekey = data.get("decryption_key")
        return data  


    """
    Check answer
    """
    def check_answer(self, guess=None, bypass=False):
        if guess:
            if not "dc" in self.request_data:
                self.request_data["dc"] = self.fp.get_xy()
            if len(self.guesses)+1 >= self.waves:
                self.request_data["ech"] = "{:.2f}".format(guess) if self.game_type == 1 else guess

            if self.game_type == 1:
                self.guesses.append(guess)
                
            elif self.game_type == 3:
                x,y = guess
                guess = API_BREAKER[self.api_breaker](x,y)
                self.guesses.append(guess)
            
        if self.game_type == 1:
            gdata = ",".join(map("{:.2f}".format, self.guesses))

        elif self.game_type == 3:
            gdata = json.dumps(self.guesses, separators=(',', ':'))

        data = urlencode({
            "sid": self.region,
            "game_token": self.challenge_token,
            "session_token": self.session_token,
            "guess": cryptojs_encrypt(gdata, self.session_token),
            "analytics_tier": self.analytics_tier
        })
        headers = self.fp.get_headers(
            host=self.service, method="POST", data=data,
            cache_control=True, xml=True,
            origin="https://%s" % self.service,
            referer=self.get_session_url(),
            fetch_site="same-origin", fetch_mode="cors",
            fetch_dest="empty", timestamp=True)
        self.add_requested_headers(headers)

        conn = self.get_conn(self.service, bypass=bypass)
        conn.putrequest("POST", "/fc/ca/",
                        skip_host=True, skip_accept_encoding=True)    
        for header, value in headers:
            conn.putheader(header, value)
        conn.endheaders()
        conn.send(data.encode("UTF-8"))
        resp = conn.getresponse()
        data = resp.read()
        data = json.loads(data)
        if bypass:
            conn.close()
        if data.get("decryption_key"):
            self.image_ekey = data["decryption_key"]
        return data.get("solved")
    
    
    """
    Iterate over images
    """
    @property
    def images(self):
        conn = self.get_conn(urlparse(self.image_urls[0]).hostname)
        for image_url in self.image_urls:
            url = urlparse(image_url)
            conn.putrequest("GET", url.path + ("?" + url.query if url.query else ""))
            conn.endheaders()
            resp = conn.getresponse()
            data = resp.read()
            if self.image_ekey:
                image = cryptojs_decrypt(data, self.image_ekey)
            else:
                image = data

            try:
                image.decode("ascii")
                image = b64decode(image)
            except: pass

            yield image


class FunCaptchaSession:
    public_key: str
    service: str
    window: Window
    fp: Fingerprint
    proxy: str
    conn: dict

    def __init__(self, public_key, service_url, window,
                fingerprint, analytics=False, proxy=None,
                whitelisted_types=[],
                whitelisted_variants=[]):
        self.public_key = public_key
        self.service = urlparse(service_url).netloc
        self.window = window
        self.analytics = analytics
        self.fp = fingerprint
        self.proxy = proxy
        self.whitelisted_types = whitelisted_types
        self.whitelisted_variants = whitelisted_variants
        self.conn = {}


    """
    Creates or caches HTTP connections
    """
    def get_conn(self, domain, https=True, bypass=False):
        if not bypass and (domain in self.conn and (time.time()-self.conn[domain].last_used)<=30):
            return self.conn[domain]
        args = dict(timeout=5)
        if https:
            if self.proxy:
                conn = http.client.HTTPSConnection(self.proxy.host, self.proxy.port, **args)
            else:
                conn = http.client.HTTPSConnection(domain, **args)
        else:
            if self.proxy:
                conn = http.client.HTTPConnection(self.proxy.host, self.proxy.port, **args)
            else:
                conn = http.client.HTTPConnection(domain, **args)
        if self.proxy:
            conn.set_tunnel(domain)

        conn.last_used = time.time()
        if not bypass:
            self.conn[domain] = conn
        return conn
    
    """ Clear cache of connections """
    def close_conns(self):
        for k, conn in list(self.conn.items()):
            conn.close()
            del self.conn[k]

    """
    Generates data for the `bda` field in get_challenge
    """
    def get_bda(self):
        bda = []
        features = self.fp.get_features()
        jsbd = self.fp.get_jsbd(self.window)
        ts = self.fp.get_timestamp()
        bda.append(dict(
            key="api_type",
            value="js"
        ))
        bda.append(dict(
            key="p",
            value=1
        ))
        bda.append(dict(
            key="f",
            value=self.fp.fp_hash
        ))
        bda.append(dict(
            key="n",
            value=b64encode(str(int(ts)).encode("utf-8")).decode("utf-8")
        ))
        bda.append(dict(
            key="wh",
            value="%s|%s" % (self.window.hash, self.fp.protochain_hash)
        ))
        bda.append(dict(
            key="fe",
            value=features
        ))
        bda.append(dict(
            key="ife_hash",
            value=self.fp.ife()
        ))
        bda.append(dict(
            key="cs",
            value=1
        ))
        bda.append(dict(
            key="jsbd",
            value=json.dumps(jsbd, separators=(',', ':'))
        ))

        ## Calculate encryption key
        timeframe = int(ts - (ts % 21600))
        key = self.fp.user_agent + str(timeframe)

        ## JSON -> AES -> BASE64
        data = json.dumps(bda, separators=(',', ':'))
        data = cryptojs_encrypt(data, key)
        data = b64encode(data.encode("utf-8")).decode("utf-8")
        return data


    """
    Requests challenge and creates instance for it
    """    
    def get_challenge(self):
        start_time = time.time()
        bda = self.get_bda()
        data = urlencode({
            "bda": bda,
            "public_key": self.public_key,
            "site": self.window.origin,
            "userbrowser": self.fp.user_agent,
            "simulate_rate_limit": 0,
            "simulated": 0,
            "language": "en",
            "rnd": self.fp.get_float()
        })
        headers = self.fp.get_headers(
            host=self.service, method="POST", data=data,
            origin=self.window.origin, referer=self.window.url,
            fetch_site="cross-site", fetch_mode="cors",
            fetch_dest="empty")

        conn = self.get_conn(self.service)
        conn.putrequest("POST", "/fc/gt2/public_key/%s" % self.public_key,
                        skip_host=True, skip_accept_encoding=True)  
        for header, value in headers:
            conn.putheader(header, value)
        conn.endheaders()
        conn.send(data.encode("UTF-8"))

        resp = conn.getresponse()
        data = resp.read()
        if resp.status != 200:
            raise BannedProxy("This proxy/IP address is banned")

        ch_data = json.loads(data)
        token_data = {k:v for k,v in (f.split("=") \
            for f in ("token="+ch_data["token"]).split("|"))}
        ch = FunCaptchaChallenge(
            session=self,
            start_time=start_time,
            full_token=ch_data["token"],
            session_token=token_data["token"],
            region=token_data["r"],
            meta=int(token_data["meta"]),
            lang=token_data.get("lang"),
            analytics_tier=int(token_data["at"]),
            secure="s" in token_data and int(token_data["s"])
        )
        return ch
