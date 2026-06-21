"""
core/security.py — JWT helpers and auth dependency shared by all routers.
"""
import os
import jwt
from fastapi import HTTPException, Request, Response

COOKIE_NAME = "session"
SESSION_SECRET = os.getenv("SESSION_SECRET", "")
JWT_ALGORITHM = "HS256"
SECURE_COOKIES = os.getenv("SECURE_COOKIES", "false").lower() == "true"


def create_jwt(user_id: int) -> str:
    return jwt.encode({"sub": str(user_id)}, SESSION_SECRET, algorithm=JWT_ALGORITHM)


def decode_jwt(token: str) -> int:
    try:
        payload = jwt.decode(token, SESSION_SECRET, algorithms=[JWT_ALGORITHM])
        return int(payload["sub"])
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


def get_current_user(request: Request) -> int:
    """FastAPI dependency — reads the httpOnly session cookie."""
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return decode_jwt(token)


def set_auth_cookie(response: Response, user_id: int) -> str:
    token = create_jwt(user_id)
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,
        secure=SECURE_COOKIES,
        samesite="lax",
        max_age=86400 * 7,
    )
    return token
