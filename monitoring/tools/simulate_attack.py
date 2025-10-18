#!/usr/bin/env python3
"""Simple attack generator to exercise rate limits and logging.

It will perform repeated failing login attempts and invalid file access (get-version) requests
against the local docker-compose services (assumes server available at http://localhost:5000).
"""
import time
import requests
import threading

SERVER = "http://localhost:5000"

def fail_logins(n=20, interval=0.5):
    for i in range(n):
        try:
            r = requests.post(SERVER + "/api/login", json={"email": f"attacker{i}@example.com", "password": "badpass"}, timeout=3)
            print("login", i, r.status_code)
        except Exception as e:
            print("login err", e)
        time.sleep(interval)

def invalid_versions(n=20, interval=0.2):
    for i in range(n):
        try:
            # random-looking link
            link = f"bad-link-{i}-{int(time.time())}"
            r = requests.get(SERVER + f"/api/get-version/{link}", timeout=3)
            print("get-version", i, r.status_code)
        except Exception as e:
            print("get-version err", e)
        time.sleep(interval)

if __name__ == "__main__":
    threads = []
    t1 = threading.Thread(target=fail_logins, args=(50, 0.2))
    t2 = threading.Thread(target=invalid_versions, args=(200, 0.05))
    threads.extend([t1, t2])
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    print("done")
