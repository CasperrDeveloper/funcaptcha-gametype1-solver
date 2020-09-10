import secrets
import random
import time
import re
import json
from urllib.parse import urlparse
import os
import subprocess

with open("solver/fp.js") as f:
    fps = f.read().strip()

def get_ife(fe):
    ife = subprocess.check_output(["node", "-e", fps,
                                    ", ".join(fe), "38"]).decode("UTF-8")
    return ife

""" Simulated browser window """
class Window:
    title: str
    url: str
    hash: str

    def __init__(self, title: str, url: str):
        self.title = title
        u = urlparse(url)
        self.origin = "%s://%s" % (u.scheme, u.netloc)
        self.url = url
        self.hash = secrets.token_hex(16)


""" Simulated browser """
class Fingerprint:
    user_agent: str
    sec_fetch: bool
    extra_headers: dict
    fp_hash: bool
    content_type_value: str
    accept_language_value: str

    DNT: str
    L: str
    D: int
    PR: int
    S: str
    AS: str
    TO: int
    SS: bool
    LS: bool
    IDB: bool
    B: bool
    ODB: bool
    CPUC: str
    PK: str
    CFP: int
    FR: bool
    FOS: bool
    FB: bool
    JSF: str
    P: str
    T: str
    H: int
    SWF: bool


    def __init__(self,
                 user_agent,
                 content_type_value="application/x-www-form-urlencoded; charset=UTF-8",
                 accept_language_value="en-gb",
                 extra_headers={},
                 sec_fetch=True,
                 protochain_hash="5d76839801bc5904a4f12f1731a7b6d1",
                 jsbd_gen=None,
                 DNT="unknown",
                 L="en-gb",
                 D=24,
                 PR=1,
                 S="1920,1080",
                 AS="1920,1040",
                 TO=None,
                 SS=True,
                 LS=True,
                 IDB=True,
                 B=False,
                 ODB=True,
                 CPUC="unknown",
                 PK="Win32",
                 CFP=None,
                 FR=False,
                 FOS=False,
                 FB=False,
                 JSF="Arial,Arial Hebrew,Arial Rounded MT Bold,Courier,Courier New,Georgia,Helvetica,Helvetica Neue,Palatino,Times,Times New Roman,Trebuchet MS,Verdana",
                 P="Chrome PDF Plugin,Chrome PDF Viewer,Native Client",
                 T="0,false,false",
                 H="8",
                 SWF=False):
        self.user_agent = user_agent
        self.content_type_value = content_type_value
        self.accept_language_value = accept_language_value
        self.extra_headers = extra_headers
        self.sec_fetch = sec_fetch
        self.jsbd_gen = jsbd_gen
        
        self.fp_hash = secrets.token_hex(16)
        self.protochain_hash = protochain_hash
        self._ife = None

        self.DNT = DNT
        self.L = L
        self.D = D
        self.PR = PR
        self.S = S
        self.AS = AS
        self.TO = TO or (60 * random.randint(-6, 6))
        self.SS = SS
        self.LS = LS
        self.IDB = IDB
        self.B = B
        self.ODB = ODB
        self.CPUC = CPUC
        self.PK = PK
        self.CFP = CFP or random.randint(-35492349, 2395492344)
        self.FR = FR
        self.FOS = FOS
        self.FB = FB
        self.JSF = JSF
        self.P = P
        self.T = T
        self.H = H
        self.SWF = SWF
        

    def ife(self):
        if self._ife:
            return self._ife

        ife = get_ife(self.get_features())

        self._ife = ife
        return self._ife

    
    def get_features(self):
        f = [
            "DNT:%s" % self.DNT,
            "L:%s" % self.L,
            "D:%d" % self.D,
            "PR:%s" % str(self.PR),
            "S:%s" % self.S,
            "AS:%s" % self.AS,
            "TO:%d" % self.TO,
            "SS:%s" % str(self.SS).lower(),
            "LS:%s" % str(self.LS).lower(),
            "IDB:%s" % str(self.IDB).lower(),
            "B:%s" % str(self.B).lower(),
            "ODB:%s" % str(self.ODB).lower(),
            "CPUC:%s" % self.CPUC,
            "PK:%s" % self.PK,
            "CFP:%d" % self.CFP,
            "FR:%s" % str(self.FR).lower(),
            "FOS:%s" % str(self.FOS).lower(),
            "FB:%s" % str(self.FB).lower(),
            "JSF:%s" % self.JSF,
            "P:%s" % self.P,
            "T:%s" % self.T,
            "H:%s" % str(self.H),
            "SWF:%s" % str(self.SWF).lower(),
        ]
        return f

    
    def get_jsbd(self, window):
        return (self.jsbd_gen and self.jsbd_gen(window)) or {
            "HL": 1,
            "NCE": True,
            "DT": window.title,
            "NWD": "false",
            "DMTO": 1,
            "DOTO": 1
        }


    def get_timestamp(self):
        return time.time()


    def get_random(self, s, e):
        return random.randint(s, e)

    
    def get_float(self):
        return random.uniform(0, 1)

    def get_xy(self) -> list:
        start_pos = [117, 248]
        button_size = [90, 28]
        new_pos = [
            start_pos[0] + random.randint(1, button_size[0]),
            start_pos[1] + random.randint(1, button_size[1])]
        return new_pos


    def get_headers(self, host, method, data, origin, referer,
                    cache_control=False, xml=False,
                    fetch_site=None, fetch_mode=None, fetch_dest=None,
                    timestamp=False):
        headers = []
        headers.append(["Host", host])
        headers.append(["Connection", "keep-alive"])
        if data:
            headers.append(["Content-Length", len(data)])
        headers.append(["User-Agent", self.user_agent])
        if data:
            headers.append(["Content-Type", self.content_type_value])
        headers.append(["Accept", "*/*"])
        if cache_control:
            headers.append(["Cache-Control", "no-cache"])
        if xml:
            headers.append(["X-Requested-With", "XMLHttpRequest"])
        if origin:
            headers.append(["Origin", origin])
        if self.sec_fetch:
            headers.append(["Sec-Fetch-Site", fetch_site])
            headers.append(["Sec-Fetch-Mode", fetch_mode])
            headers.append(["Sec-Fetch-Dest", fetch_dest])
        for hk, hv in self.extra_headers.items():
            headers.append([hk, hv])
        headers.append(["Referer", referer])
        headers.append(["Accept-Encoding", "gzip, deflate, br"])
        headers.append(["Accept-Language", self.accept_language_value])
        if timestamp:
            ts = self.get_timestamp() * 100000
            headers.append(["Cookie", "timestamp=%d" % ts])
        return headers