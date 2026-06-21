# Codequesters — AI Voice Call CRM

An AI-powered outbound/inbound voice call CRM built on **FastAPI** + **PostgreSQL**, connected to **Exotel** telephony for voice automation, **Groq** (or local **Ollama**) for LLM transcription and lead extraction, and OAuth login via Google and GitHub.

---

## What it does

1. **Exotel Voice Agent** — When a call comes in, Exotel forwards the audio recording to `/process`. The app transcribes it with Groq Whisper, extracts lead data (business type, team size, revenue, intent score) via LLM, and saves it to the database.
2. **AI Outbound Dialer** — The `/make-call` endpoint triggers an outbound Exotel call to any phone number.
3. **CRM Dashboard** — A static web UI (`/dashboard.html`) shows live lead data, call transcripts, analytics, and supports bulk CSV lead imports.
4. **OAuth Login** — Secure login via Google or GitHub OAuth, plus email/password signup.

---

## Architecture

```
Browser → FastAPI (app.py)
                ├── /process   ← Exotel webhook (audio → Groq Whisper → LLM → Postgres)
                ├── /leads     ← CRM CRUD (JWT-authenticated)
                ├── /stats     ← Aggregated metrics
                ├── /login     ← Email/password login
                ├── /auth/google, /auth/github ← OAuth callbacks
                └── /          ← Static files (dashboard.html, login.html, signup.html)
```

---

## Prerequisites

- Python 3.11+
- PostgreSQL 14+ (running locally or via Docker)
- A [Groq API key](https://console.groq.com/keys) (free tier available)
- Exotel account (for telephony features)
- Google and/or GitHub OAuth app credentials (for social login)

---

## Local Setup

### 1. Clone and install dependencies

```bash
git clone https://github.com/jeevan841/Codequesters.git
cd Codequesters
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure environment variables

```bash
cp .env.example .env
# Edit .env and fill in all required values (see table below)
```

### 3. Create the database

```bash
# Make sure PostgreSQL is running, then:
python create_db.py
```

### 4. Run the development server

```bash
uvicorn app:app --reload --port 8000
```

Open [http://localhost:8000/login.html](http://localhost:8000/login.html) in your browser.

---

## Environment Variables

All variables are **required** unless marked optional. The app will refuse to start if a required variable is missing.

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | ✅ | Full PostgreSQL DSN — `postgresql://user:pass@host:port/dbname` |
| `SESSION_SECRET` | ✅ | 32-byte random secret for JWT signing. Generate: `python -c "import secrets; print(secrets.token_hex(32))"` |
| `ALLOWED_ORIGINS` | ✅ | Comma-separated list of trusted origins for CORS. E.g. `http://localhost:8000,https://yourdomain.com` |
| `SECURE_COOKIES` | optional | Set `true` in production (requires HTTPS). Default: `false` |
| `GOOGLE_CLIENT_ID` | optional | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | optional | Google OAuth client secret |
| `GITHUB_CLIENT_ID` | optional | GitHub OAuth client ID |
| `GITHUB_CLIENT_SECRET` | optional | GitHub OAuth client secret |
| `GROQ_API_KEY` | optional | Groq API key (required if `USE_LOCAL_LLM=false`) |
| `USE_LOCAL_LLM` | optional | `true` to use Ollama instead of Groq. Default: `false` |
| `LOCAL_MODEL_NAME` | optional | Ollama model name. Default: `llama3` |
| `EXOTEL_SID` | optional | Exotel account SID |
| `EXOTEL_API_KEY` | optional | Exotel API key |
| `EXOTEL_API_TOKEN` | optional | Exotel API token |
| `EXOTEL_VIRTUAL_NUMBER` | optional | Exotel virtual phone number |
| `MY_PHONE` | optional | Your real phone number for the `/voice` endpoint |
| `DB_HOST` | ✅ (create_db.py only) | Database host |
| `DB_PORT` | optional | Database port. Default: `5432` |
| `DB_USER` | ✅ (create_db.py only) | Database user |
| `DB_PASSWORD` | ✅ (create_db.py only) | Database password |
| `DB_NAME` | optional | Database name. Default: `voice_ai` |

---

## Running via Docker

```bash
# Build image
docker build -t codequesters .

# Run (pass env vars from your .env file)
docker run --env-file .env -p 8000:8080 codequesters
```

---

## Running Tests

```bash
pip install pytest pytest-asyncio
pytest tests/ -v
```

---

## API Reference

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/login` | — | Email/password login (sets httpOnly cookie) |
| `POST` | `/signup` | — | Create new account |
| `POST` | `/logout` | — | Clear session cookie |
| `GET` | `/api/me` | 🔒 | Returns current user info |
| `GET` | `/login/google` | — | Start Google OAuth flow |
| `GET` | `/login/github` | — | Start GitHub OAuth flow |
| `GET` | `/leads` | 🔒 | List all CRM leads |
| `GET` | `/leads/{id}` | 🔒 | Get a single lead |
| `GET` | `/leads/high-value` | 🔒 | List high-value leads |
| `POST` | `/import-leads` | 🔒 | Bulk import leads from JSON rows |
| `GET` | `/stats` | 🔒 | Aggregated dashboard stats |
| `GET` | `/api/analytics` | 🔒 | Endpoint analytics data |
| `GET` | `/voice` | — | Exotel voice webhook (inbound) |
| `POST` | `/process` | — | Exotel recording webhook |
| `POST` | `/make-call` | — | Trigger outbound Exotel call |

> 🔒 = Requires a valid session cookie (obtained via `/login` or OAuth)

---

## Security Notes

- Session tokens are stored in **httpOnly, SameSite=Lax cookies** — not localStorage.
- All database queries use **parameterized statements** — no raw SQL execution.
- CORS is restricted to explicitly listed origins via `ALLOWED_ORIGINS`.
- The app will **not start** if `DATABASE_URL`, `SESSION_SECRET`, or `ALLOWED_ORIGINS` are missing.
- Rate limiting is applied to `/login` (10/min) and `/signup` (5/min).
- OAuth display names are safely encoded with `json.dumps()` before HTML embedding.

---

## ⚠️ Credential Rotation Notice

The original version of this repository committed `service-account.json` and a `.env` file containing Google OAuth credentials to git history. If you were using those credentials:

1. **Rotate your Google OAuth client secret** at [console.cloud.google.com](https://console.cloud.google.com)
2. **Revoke any existing tokens** issued under the old credentials
3. Ensure `service-account.json` is rotated if it contained service account keys