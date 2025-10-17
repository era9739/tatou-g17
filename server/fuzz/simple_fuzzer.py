# fuzz/simple_fuzzer.py
"""
Simple targeted fuzzer for Tatou API (JSON fields + file upload).
- Edit BASE for your server base URL (http://localhost:5000)
- Add/adjust endpoints to match your API.
"""
from pathlib import Path
import random
import string
import requests
import time
import json
import os

BASE = os.environ.get("TATOU_BASE", "http://localhost:5000")

# endpoints to fuzz (adjust names to match your server)
ENDPOINTS_JSON = [
    ("/create-user", "POST", ["login", "password", "email"]),
    ("/login", "POST", ["email", "password"]),
    ("/get-watermarking-methods", "GET", []),
]

UPLOAD_ENDPOINT = ("/upload-document", "POST")  # change if your API path differs

# Mutators
def random_string(n=16):
    return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(n))

def long_string(n=10000):
    return "A" * n

def binary_blob(n=1024):
    return bytes(random.getrandbits(8) for _ in range(n))

PAYLOAD_MUTATORS = [
    lambda: {"login": random_string(8), "password": random_string(12), "email": f"{random_string(6)}@x.test"},
    lambda: {"login": "", "password": "", "email": ""},
    lambda: {"login": long_string(20000), "password": "p", "email": "a@b"},
    lambda: {"login": "<script>alert(1)</script>", "password": "p", "email": "x@y"},
    lambda: {"login": random_string(6), "password": random_string(6), "email": "not-an-email"},
]

def fuzz_json(endpoint, method, fields):
    url = BASE.rstrip("/") + endpoint
    for i in range(50):
        payload = None
        if method == "POST":
            try:
                gen = random.choice(PAYLOAD_MUTATORS)
                payload = gen()
                r = requests.post(url, json=payload, timeout=10)
            except Exception as e:
                print(f"[ERR] JSON fuzz {endpoint} iter {i} -> {e}")
                continue
        else:
            try:
                r = requests.get(url, timeout=10)
            except Exception as e:
                print(f"[ERR] JSON fuzz GET {endpoint} -> {e}")
                continue

        print(f"[{r.status_code}] {method} {endpoint} / payload={str(payload)[:80]} / len={len(r.content)}")
        time.sleep(0.1)

def fuzz_upload(endpoint_tuple, sample_pdf_path=None):
    endpoint, method = endpoint_tuple
    url = BASE.rstrip("/") + endpoint
    if method != "POST":
        return
    # generate mutated files using simple strategies
    for size in [0, 16, 256, 1024, 2048]:
        # mutate: empty, tiny, medium random bytes, or use a real PDF if available
        if sample_pdf_path and Path(sample_pdf_path).exists():
            # sometimes send a real PDF
            files = {"file": open(sample_pdf_path, "rb")}
        else:
            files = {"file": ("fuzz.pdf", binary_blob(size), "application/pdf")}
        try:
            r = requests.post(url, files=files, timeout=15)
        except Exception as e:
            print(f"[ERR] upload fuzz {size} -> {e}")
            continue
        print(f"[{r.status_code}] UPLOAD {endpoint} size={size} len={len(r.content)}")
        if sample_pdf_path and Path(sample_pdf_path).exists():
            files["file"].close()
        time.sleep(0.2)

def main():
    print("Starting simple fuzz session against", BASE)
    # JSON endpoints
    for ep in ENDPOINTS_JSON:
        fuzz_json(*ep)
    # Uploads: point to small sample pdf inside repo if exists
    sample = "tests/data/sample.pdf"
    fuzz_upload(UPLOAD_ENDPOINT, sample_pdf_path=sample)

if __name__ == "__main__":
    main()
