from fastapi.testclient import TestClient
import os
from app import app

# Mock credentials so authlib doesn't crash on init if missing from .env
os.environ.setdefault("GOOGLE_CLIENT_ID", "dummy_google_id")
os.environ.setdefault("GOOGLE_CLIENT_SECRET", "dummy_google_secret")
os.environ.setdefault("GITHUB_CLIENT_ID", "dummy_github_id")
os.environ.setdefault("GITHUB_CLIENT_SECRET", "dummy_github_secret")
os.environ.setdefault("SESSION_SECRET", "dummy_session_secret")

client = TestClient(app)

print("\n--- Testing Google OAuth Redirect ---")
res_google = client.get("/login/google", allow_redirects=False)
print("Status Code:", res_google.status_code)
print("Redirect URL:", res_google.headers.get("location"))

print("\n--- Testing GitHub OAuth Redirect ---")
res_github = client.get("/login/github", allow_redirects=False)
print("Status Code:", res_github.status_code)
print("Redirect URL:", res_github.headers.get("location"))
