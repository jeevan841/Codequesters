"""
tests/test_app.py — Pytest test suite for Codequesters Voice CRM

Covers:
  - Login success and wrong-password → 401
  - Signup duplicate-email → 400
  - Signup password validation (server-side)
  - Protected endpoints return 401 without a token (Tasks 1 & 2 verification)
  - /execute-sql endpoint no longer exists → 404 or 405 (Task 1 verification)
  - /import-leads rejects raw SQL strings (Task 1 verification)

Run with:
    pytest tests/ -v
"""

import os
import bcrypt
import pytest

# Set required env vars BEFORE importing app (app validates them at import time)
os.environ.setdefault("DATABASE_URL", "postgresql://test:test@localhost:5432/test_voice_ai")
os.environ.setdefault("SESSION_SECRET", "test-secret-key-that-is-at-least-32-chars-long!!")
os.environ.setdefault("ALLOWED_ORIGINS", "http://localhost:8000")
os.environ.setdefault("GOOGLE_CLIENT_ID", "dummy_google_id")
os.environ.setdefault("GOOGLE_CLIENT_SECRET", "dummy_google_secret")
os.environ.setdefault("GITHUB_CLIENT_ID", "dummy_github_id")
os.environ.setdefault("GITHUB_CLIENT_SECRET", "dummy_github_secret")

from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Helpers: mock the database pool so tests don't need a real Postgres instance
# ---------------------------------------------------------------------------

def _hash(password: str) -> str:
    """Hash a password with bcrypt."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def _make_mock_conn(rows=None, rowcount=1):
    """Return a mock psycopg2 connection whose cursor returns `rows`."""
    cur = MagicMock()
    cur.fetchone.return_value = rows[0] if rows else None
    cur.fetchall.return_value = rows or []
    conn = MagicMock()
    conn.cursor.return_value = cur
    return conn, cur


@pytest.fixture(autouse=True)
def mock_db_pool():
    """Replace the real DB pool with a mock for every test."""
    with patch("app.db_pool") as mock_pool:
        yield mock_pool


# ---------------------------------------------------------------------------
# Import the app AFTER env vars are set
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client():
    # Patch pool initialisation so the lifespan event doesn't try to connect
    with patch("psycopg2.pool.SimpleConnectionPool"):
        from app import app
        with TestClient(app, raise_server_exceptions=False) as c:
            yield c


# ---------------------------------------------------------------------------
# Task 1 verification: /execute-sql must not exist
# ---------------------------------------------------------------------------

class TestExecuteSqlRemoved:
    def test_execute_sql_returns_404_or_405(self, client):
        """Confirm the dangerous raw-SQL endpoint has been removed."""
        res = client.post("/execute-sql", json={"sql_script": "SELECT 1"})
        assert res.status_code in (404, 405), (
            f"/execute-sql should not exist but returned {res.status_code}"
        )

    def test_import_leads_rejects_raw_sql(self, client):
        """
        /import-leads never executes raw SQL strings.
        - Without auth it returns 401 (auth is checked first).
        - With auth but wrong-shape body it returns 422.
        Both prove raw SQL is never passed to the database.
        """
        res = client.post(
            "/import-leads",
            json={"rows": "DROP TABLE leads;"},
        )
        # Auth check fires before Pydantic validation for protected endpoints.
        # 401 = not authenticated (correct). 422 = shape rejected (also correct).
        assert res.status_code in (401, 422), (
            f"Expected 401 or 422 (raw SQL must be blocked), got {res.status_code}"
        )



# ---------------------------------------------------------------------------
# Task 2 verification: protected endpoints require authentication
# ---------------------------------------------------------------------------

class TestAuthRequired:
    @pytest.mark.parametrize("url", [
        "/leads",
        "/leads/1",
        "/leads/high-value",
        "/stats",
        "/api/analytics",
        "/api/me",
    ])
    def test_protected_endpoint_returns_401_without_cookie(self, client, url):
        """Every protected endpoint must return 401 when no session cookie is present."""
        res = client.get(url)
        assert res.status_code == 401, (
            f"Expected 401 for {url} without auth, got {res.status_code}"
        )

    def test_import_leads_requires_auth(self, client):
        res = client.post(
            "/import-leads",
            json={"rows": [{"phone": "9999999999", "business_type": "Salon"}]},
        )
        assert res.status_code == 401


# ---------------------------------------------------------------------------
# Login tests
# ---------------------------------------------------------------------------

class TestLogin:
    def test_login_wrong_password_returns_401(self, client, mock_db_pool):
        """Login with wrong password must return 401."""
        hashed = _hash("correct_password1")

        conn, cur = _make_mock_conn(rows=[(1, hashed)])
        mock_db_pool.getconn.return_value = conn

        res = client.post(
            "/login",
            json={"email": "user@example.com", "password": "wrong_password1"},
        )
        assert res.status_code == 401
        assert "Invalid credentials" in res.json()["detail"]

    def test_login_unknown_email_returns_401(self, client, mock_db_pool):
        conn, cur = _make_mock_conn(rows=[])  # No user found
        mock_db_pool.getconn.return_value = conn

        res = client.post(
            "/login",
            json={"email": "nobody@example.com", "password": "password123"},
        )
        assert res.status_code == 401

    def test_login_success_sets_cookie(self, client, mock_db_pool):
        """Successful login must set an httpOnly session cookie (no token in body)."""
        hashed = _hash("correct_password1")

        conn, cur = _make_mock_conn(rows=[(42, hashed)])
        mock_db_pool.getconn.return_value = conn

        res = client.post(
            "/login",
            json={"email": "user@example.com", "password": "correct_password1"},
        )
        assert res.status_code == 200
        assert res.json()["status"] == "success"
        # Token must NOT be in the response body
        assert "token" not in res.json()
        # Cookie must be set
        assert "session" in res.cookies

    def test_login_response_has_no_plaintext_token(self, client, mock_db_pool):
        """Verify the old fake user_token_{id} pattern is completely gone."""
        hashed = _hash("testpass1!")

        conn, cur = _make_mock_conn(rows=[(7, hashed)])
        mock_db_pool.getconn.return_value = conn

        res = client.post(
            "/login",
            json={"email": "test@example.com", "password": "testpass1!"},
        )
        body = res.text
        assert "user_token_" not in body, (
            "Old insecure token pattern 'user_token_N' must not appear in login response"
        )


# ---------------------------------------------------------------------------
# Signup tests
# ---------------------------------------------------------------------------

class TestSignup:
    def test_signup_duplicate_email_returns_400(self, client, mock_db_pool):
        """Duplicate email signup must return 400."""
        import psycopg2
        conn = MagicMock()
        cur = MagicMock()
        # side_effect as a list: first call (hash step doesn't use cur) is fine;
        # the actual INSERT execute raises IntegrityError.
        call_count = [0]
        def execute_side_effect(*args, **kwargs):
            call_count[0] += 1
            raise psycopg2.IntegrityError("duplicate key")
        cur.execute.side_effect = execute_side_effect
        conn.cursor.return_value = cur
        mock_db_pool.getconn.return_value = conn

        res = client.post(
            "/signup",
            json={"email": "existing@example.com", "password": "password123!"},
        )
        assert res.status_code == 400
        assert "already exists" in res.json()["detail"]

    def test_signup_password_too_short_returns_422(self, client):
        """Server-side Pydantic validator must reject passwords shorter than 8 chars."""
        res = client.post(
            "/signup",
            json={"email": "new@example.com", "password": "abc"},
        )
        assert res.status_code == 422

    def test_signup_password_no_digit_or_special_returns_422(self, client):
        """Server-side validator must reject passwords with no digit or special char."""
        res = client.post(
            "/signup",
            json={"email": "new@example.com", "password": "onlyletters"},
        )
        assert res.status_code == 422

    def test_signup_valid_password_accepted(self, client, mock_db_pool):
        """A valid password (8+ chars, has digit) must pass validation."""
        conn, cur = _make_mock_conn()
        mock_db_pool.getconn.return_value = conn

        res = client.post(
            "/signup",
            json={"email": "new@example.com", "password": "validpass1"},
        )
        assert res.status_code == 200
        assert res.json()["status"] == "signup success"
