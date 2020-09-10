# Funcaptcha Solver (Gametype 1)
This project aims to simplify the automated solving of FunCaptcha challenges. Currently it is limited to only game type 1 (the rotating one).

Identity profiles can be found in the *identities* folder, depending on the website you might need to add referral URLs to them.

# Sample Usage
```python
from solver import Solver
import requests

with open("proxies.txt") as f:
  solver = Solver(
    public_key="A2A14B1D-1AF3-C791-9BBC-EE33CC7A0A6F",
    service_url="https://roblox-api.arkoselabs.com",
    proxies=f.read().splitlines())

solver.start(solvers=100, resubmitters=100)

while 1:
  ## wait for solved challenge
  ch = solver.get_solved()
  print("token:", ch.full_token)
  
  ## submit token to website
  requests.post(
    url="https://something/api/something",
    json={
      "token": ch.full_token
    },
    proxies={"https": "https://%s:%d" % (ch.proxy.host, ch.proxy.port)}
  )
  
  ## all tokens can be re-used once, just call .resubmit after you're done
  ## and it'll automatically be added to the solve queue after it's been re-submitted
  solver.resubmit(ch)
  
```
