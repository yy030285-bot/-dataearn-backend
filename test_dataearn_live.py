import os
import uuid
import requests

BASE_URL = os.environ["REACT_APP_BACKEND_URL"].rstrip("/")


def test_registration_cookie_me_consent_and_redemption():
    s = requests.Session()
    email = f"test_{uuid.uuid4().hex[:10]}@example.com"
    r = s.post(f"{BASE_URL}/api/auth/register", json={"name": "Test Participant", "email": email, "password": "TestPass123!", "consent": False})
    assert r.status_code == 200
    user = r.json()
    assert user["email"] == email and user["points"] == 5000 and user["role"] == "user"
    assert "access_token" in s.cookies and "refresh_token" in s.cookies
    assert s.get(f"{BASE_URL}/api/auth/me").json()["id"] == user["id"]
    assert s.post(f"{BASE_URL}/api/rewards/redeem", json={"reward_id": "r-500", "amount": 500, "points": 4500}).status_code == 403
    assert s.post(f"{BASE_URL}/api/user/consent", json={"consent": True}).status_code == 200
    redeemed = s.post(f"{BASE_URL}/api/rewards/redeem", json={"reward_id": "r-500", "amount": 500, "points": 4500})
    assert redeemed.status_code == 200
    assert redeemed.json()["withdrawal"]["amount"] == 500
    assert s.get(f"{BASE_URL}/api/auth/me").json()["points"] == 500


def test_admin_login_and_role_guard():
    admin = requests.Session()
    r = admin.post(f"{BASE_URL}/api/auth/login", json={"email": "admin@dataearn.demo", "password": "DataEarnAdmin!2025"})
    assert r.status_code == 200 and r.json()["role"] == "admin"
    assert admin.get(f"{BASE_URL}/api/admin/overview").status_code == 200
    anon = requests.Session()
    assert anon.get(f"{BASE_URL}/api/auth/me").status_code == 401
    assert anon.get(f"{BASE_URL}/api/admin/overview").status_code == 401