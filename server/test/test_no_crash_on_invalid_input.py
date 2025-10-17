#test_no_crash_on_invalid_input.py
import requests

BASE_URL = "http://localhost:5000"

def test_invalid_login_payload_does_not_crash():
    payload = {"login": "<script>alert(1)</script>", "password": "", "email": "x@y"}
    resp = requests.post(f"{BASE_URL}/login", json=payload)
    assert resp.status_code in [400, 405, 404]
