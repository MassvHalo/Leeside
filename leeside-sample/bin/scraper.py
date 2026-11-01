#!/usr/bin/env python3
"""Attack scraper (docs/windside.md section 4): Python requests with a
spoofed Chrome UA, no assets, fixed 300 ms cadence. --no-cookie drops
cookie persistence (fresh client per request). Prints a summary line."""
import sys
import time

import requests

ARGS = [a for a in sys.argv[1:] if a != "--no-cookie"]
NO_COOKIE = "--no-cookie" in sys.argv
BASE = ARGS[0].rstrip("/")
N = int(ARGS[1]) if len(ARGS) > 1 else 120
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
PAGES = ["/", "/about", "/venues/1", "/venues/2", "/venues/3", "/venues/4", "/venues/5", "/venues/6"]

s = requests.Session()
s.headers["User-Agent"] = UA
codes = {}
for i in range(N):
    if NO_COOKIE:
        r = requests.get(BASE + PAGES[i % len(PAGES)], headers={"User-Agent": UA}, timeout=10)
    else:
        r = s.get(BASE + PAGES[i % len(PAGES)], timeout=10)
    codes[r.status_code] = codes.get(r.status_code, 0) + 1
    time.sleep(0.3)
print(f"   scraper: {N} requests, status counts {codes}")
