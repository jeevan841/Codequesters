"""
routers/auth.py — Authentication, signup, login, OAuth routes.
"""

import bcrypt
import json
import os
import re

from authlib.integrations.starlette_client import OAuth
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, field_validator
from slowapi import Limiter
from slowapi.util import get_remote_address

from core.db import get_db
from core.security import (
    COOKIE_NAME,
    get_current_user,
    set_auth_cookie,
)

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)


def _hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def _verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except Exception:
        return False

# ─── OAuth ────────────────────────────────────────────────────────────────────
oauth = OAuth()
oauth.register(
    name="google",
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)
oauth.register(
    name="github",
    client_id=os.getenv("GITHUB_CLIENT_ID"),
    client_secret=os.getenv("GITHUB_CLIENT_SECRET"),
    access_token_url="https://github.com/login/oauth/access_token",
    authorize_url="https://github.com/login/oauth/authorize",
    api_base_url="https://api.github.com/",
    client_kwargs={"scope": "user:email"},
)

# ─── Models ───────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    email: str
    password: str


class SignupRequest(BaseModel):
    email: str
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        if not re.search(r"[0-9!@#$%^&*()\-_=+\[\]{};:',.<>?/\\|`~]", v):
            raise ValueError("Password must contain at least one digit or special character.")
        return v


# ─── DB helper ────────────────────────────────────────────────────────────────

def get_or_create_oauth_user(email: str) -> int:
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE email = %s", (email,))
        row = cur.fetchone()
        if not row:
            cur.execute("INSERT INTO users (email) VALUES (%s) RETURNING id", (email,))
            new_row = cur.fetchone()
            user_id = new_row[0] if new_row else None
            conn.commit()
        else:
            user_id = row[0]
        cur.close()
    return user_id


# ─── Routes ───────────────────────────────────────────────────────────────────

@router.post("/login")
@limiter.limit("10/minute")
def login(data: LoginRequest, request: Request, response: Response):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, password FROM users WHERE email = %s", (data.email,))
        row = cur.fetchone()
        cur.close()
    if not row:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    user_id, hashed_pwd = row
    if not hashed_pwd or not _verify_password(data.password, hashed_pwd):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    set_auth_cookie(response, user_id)
    return {"status": "success"}


@router.post("/signup")
@limiter.limit("5/minute")
def signup(data: SignupRequest, request: Request, response: Response):
    with get_db() as conn:
        cur = conn.cursor()
        hashed = _hash_password(data.password)
        try:
            cur.execute(
                "INSERT INTO users (email, password) VALUES (%s, %s)",
                (data.email, hashed),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            cur.close()
            raise HTTPException(status_code=400, detail="User already exists")
        cur.close()
    return {"status": "signup success"}


@router.post("/logout")
def logout(response: Response):
    response.delete_cookie(COOKIE_NAME)
    return {"status": "logged out"}


@router.get("/api/me")
def me(user_id: int = Depends(get_current_user)):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT email FROM users WHERE id = %s", (user_id,))
        row = cur.fetchone()
        cur.close()
    if not row:
        raise HTTPException(status_code=401, detail="User not found")
    return {"user_id": user_id, "email": row[0]}


@router.get("/login/google")
async def login_google(request: Request):
    redirect_uri = request.url_for("auth_google")
    return await oauth.google.authorize_redirect(request, redirect_uri)


@router.get("/auth/google")
async def auth_google(request: Request):
    token = await oauth.google.authorize_access_token(request)
    user = token.get("userinfo")
    if not user:
        resp = await oauth.google.get("https://openidconnect.googleapis.com/v1/userinfo", token=token)
        user = resp.json()
    email = user["email"]
    user_id = get_or_create_oauth_user(email)
    safe_name = json.dumps(user.get("name", email))
    html = f"""<!DOCTYPE html><html><body><script>
      document.cookie = "username=" + encodeURIComponent({safe_name}) + "; path=/; SameSite=Lax";
      window.location.href = "/dashboard.html";
    </script></body></html>"""
    response = HTMLResponse(content=html)
    set_auth_cookie(response, user_id)
    return response


@router.get("/login/github")
async def login_github(request: Request):
    redirect_uri = request.url_for("auth_github")
    return await oauth.github.authorize_redirect(request, redirect_uri)


@router.get("/auth/github")
async def auth_github(request: Request):
    token = await oauth.github.authorize_access_token(request)
    resp = await oauth.github.get("user", token=token)
    user = resp.json()
    email = user.get("email")
    if not email:
        emails_resp = await oauth.github.get("user/emails", token=token)
        for entry in emails_resp.json():
            if entry.get("primary") and entry.get("verified"):
                email = entry["email"]
                break
        if not email:
            raise HTTPException(status_code=400, detail="Could not retrieve a verified email from GitHub.")
    user_id = get_or_create_oauth_user(email)
    display_name = json.dumps(user.get("name") or user.get("login") or email)
    html = f"""<!DOCTYPE html><html><body><script>
      document.cookie = "username=" + encodeURIComponent({display_name}) + "; path=/; SameSite=Lax";
      window.location.href = "/dashboard.html";
    </script></body></html>"""
    response = HTMLResponse(content=html)
    set_auth_cookie(response, user_id)
    return response
