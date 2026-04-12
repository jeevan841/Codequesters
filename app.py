from fastapi import FastAPI, WebSocket, Request
from fastapi.responses import Response
import json, base64, os
import psycopg2
import ollama
from twilio.twiml.voice_response import VoiceResponse, Connect
import requests
from transformers import AutoProcessor, AutoModelForCausalLM

app = FastAPI()

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv

load_dotenv()

app.add_middleware(SessionMiddleware, secret_key="some-random-secret-key")

import time
from collections import defaultdict

api_stats = defaultdict(lambda: {"hits": 0, "last_accessed": "-"})

@app.middleware("http")
async def track_endpoints(request: Request, call_next):
    path = request.url.path
    api_stats[path]["hits"] += 1
    api_stats[path]["last_accessed"] = time.strftime("%Y-%m-%d %H:%M:%S")
    response = await call_next(request)
    return response

@app.get("/api/analytics")
def get_analytics():
    results = []
    
    # Get all registered FastAPI routes
    for route in app.routes:
        if hasattr(route, "methods"):
            path = route.path
            methods = list(route.methods)
            name = route.name
            
            # Combine with live stats if available
            stats = api_stats.get(path, {"hits": 0, "last_accessed": "-"})
            
            if stats["hits"] > 0:
                results.append({
                    "path": path,
                    "methods": ", ".join(methods),
                    "name": name.replace("_", " ").title(),
                    "hits": stats["hits"],
                    "last_accessed": stats["last_accessed"]
                })
            
    # Include dynamic hits that aren't strict registered routes (like static files)
    for path, stats in api_stats.items():
        if not any(r["path"] == path for r in results):
             results.append({
                "path": path,
                "methods": "N/A",
                "name": "Static/Unknown Request",
                "hits": stats["hits"],
                "last_accessed": stats["last_accessed"]
            })
             
    return results

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

from fastapi import HTTPException
from pydantic import BaseModel
import psycopg2
from passlib.context import CryptContext

DB_URL = os.getenv("DATABASE_URL", "postgresql://postgres:the123@localhost:5433/voice_ai")

def get_db():
    return psycopg2.connect(DB_URL)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class LoginRequest(BaseModel):
    email: str
    password: str

@app.post("/login")
def login(data: LoginRequest):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT id, password FROM users WHERE email = %s", (data.email,))
    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    user_id, hashed_pwd = row
    if not hashed_pwd or not pwd_context.verify(data.password, hashed_pwd):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    return {"status": "success", "token": f"user_token_{user_id}"}

class SignupRequest(BaseModel):
    email: str
    password: str

@app.post("/signup")
def signup(data: SignupRequest):
    conn = get_db()
    cur = conn.cursor()

    hashed = pwd_context.hash(data.password)

    try:
        cur.execute(
            "INSERT INTO users (email, password) VALUES (%s, %s)",
            (data.email, hashed)
        )
        conn.commit()
    except:
        return {"error": "User already exists"}

    cur.close()
    conn.close()

    return {"status": "signup success"}

def get_or_create_oauth_user(email: str):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE email = %s", (email,))
    row = cur.fetchone()
    if not row:
        cur.execute("INSERT INTO users (email) VALUES (%s) RETURNING id", (email,))
        user_id = cur.fetchone()[0]
        conn.commit()
    else:
        user_id = row[0]
    cur.close()
    conn.close()
    return user_id

@app.get("/login/google")
async def login_google(request: Request):
    redirect_uri = request.url_for("auth_google")
    return await oauth.google.authorize_redirect(request, redirect_uri)

@app.get("/auth/google")
async def auth_google(request: Request):
    try:
        token = await oauth.google.authorize_access_token(request)
    except Exception as e:
        return {"error": f"Token authorization failed: {str(e)}"}
        
    user = token.get("userinfo")
    
    if not user:
        # Fallback: Sometimes the OpenID ID token isn't parsed automatically; manually hitting the endpoint is safer.
        try:
            resp = await oauth.google.get("https://openidconnect.googleapis.com/v1/userinfo", token=token)
            user = resp.json()
        except Exception as e:
            return {"error": f"Could not fetch user profile: {str(e)}"}

    if not user or "email" not in user:
        return {"error": "Google profile missing required email address", "details": user}

    email = user["email"]
    
    try:
        user_id = get_or_create_oauth_user(email)
    except Exception as e:
        return {"error": f"Database user creation failed: {str(e)}"}

    token_str = f"user_token_{user_id}"
    html_content = f"""
    <html>
        <body>
            <script>
                localStorage.setItem("sessionToken", "{token_str}");
                localStorage.setItem("userName", "{user.get('name', email)}");
                window.location.href = "/dashboard.html";
            </script>
        </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@app.get("/login/github")
async def login_github(request: Request):
    redirect_uri = request.url_for("auth_github")
    return await oauth.github.authorize_redirect(request, redirect_uri)

@app.get("/auth/github")
async def auth_github(request: Request):
    token = await oauth.github.authorize_access_token(request)
    resp = await oauth.github.get("user", token=token)
    user = resp.json()
    
    email = user.get("email")
    if not email:
        email = f"{user['login']}@github.com"
        
    user_id = get_or_create_oauth_user(email)

    token_str = f"user_token_{user_id}"
    html_content = f"""
    <html>
        <body>
            <script>
                localStorage.setItem("sessionToken", "{token_str}");
                localStorage.setItem("userName", "{user.get('name') or user.get('login', email)}");
                window.location.href = "/dashboard.html";
            </script>
        </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@app.get("/leads")
def get_all_leads():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM leads ORDER BY created_at DESC")
    rows = cur.fetchall()

    cur.close()
    conn.close()

    leads = []
    for row in rows:
        leads.append({
            "id": row[0],
            "phone": row[1],
            "business_type": row[2],
            "team_size": row[3],
            "revenue": row[4],
            "meeting_time": row[5],
            "summary": row[6],
            "transcript": row[7],
            "created_at": str(row[8])
        })

    return leads

@app.get("/leads/{lead_id}")
def get_lead(lead_id: int):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM leads WHERE id = %s", (lead_id,))
    row = cur.fetchone()

    cur.close()
    conn.close()

    if not row:
        return {"error": "Lead not found"}

    return {
        "id": row[0],
        "phone": row[1],
        "business_type": row[2],
        "team_size": row[3],
        "revenue": row[4],
        "meeting_time": row[5],
        "summary": row[6],
        "transcript": row[7],
        "created_at": str(row[8])
    }

@app.get("/stats")
def get_stats():
    conn = get_db()
    cur = conn.cursor()

    # Total calls
    cur.execute("SELECT COUNT(*) FROM leads")
    total_calls = cur.fetchone()[0]

    # Meetings booked
    cur.execute("SELECT COUNT(*) FROM leads WHERE meeting_time IS NOT NULL")
    meetings = cur.fetchone()[0]

    # Revenue estimation (simple logic)
    cur.execute("SELECT COUNT(*) FROM leads WHERE team_size IS NOT NULL")
    leads_count = cur.fetchone()[0]

    estimated_revenue = leads_count * 2000  # simple hack

    cur.close()
    conn.close()

    return {
        "total_calls": total_calls,
        "meetings_booked": meetings,
        "estimated_revenue": estimated_revenue
    }

@app.get("/leads/high-value")
def high_value_leads():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT * FROM leads
        WHERE team_size IS NOT NULL
        ORDER BY created_at DESC
    """)

    rows = cur.fetchall()

    cur.close()
    conn.close()

    return [{"id": r[0], "business_type": r[2], "team_size": r[3]} for r in rows]


# DB CONFIG
DB_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/voice_ai")


# ---------------------------
# DATABASE
# ---------------------------
def save_to_db(data):
    conn = psycopg2.connect(DB_URL)
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO leads 
        (phone, business_type, team_size, revenue_estimate, meeting_time, call_summary, transcript)
        VALUES (%s,%s,%s,%s,%s,%s,%s)
    """, (
        data.get("phone"),
        data.get("business_type"),
        data.get("team_size"),
        data.get("revenue"),
        data.get("meeting_time"),
        data.get("summary"),
        data.get("transcript")
    ))

    conn.commit()
    cur.close()
    conn.close()


# ---------------------------
# LLM FUNCTIONS (GEMMA)
# ---------------------------
def llm_extract(text):
    prompt = f"""
    Extract:
    business_type, team_size, revenue, meeting_time

    Text: {text}

    Return JSON only.
    """

    res = ollama.chat(
        model="gemma4:e4b",
        messages=[{"role": "user", "content": prompt}]
    )

    try:
        return json.loads(res["message"]["content"])
    except:
        return {}


def llm_summary(text):
    prompt = f"Summarize this call in 12 words:\n{text}"

    res = ollama.chat(
        model="gemma4:e4b",
        messages=[{"role": "user", "content": prompt}]
    )

    return res["message"]["content"]


def llm_reply(text):
    prompt = f"""
    You are Riya, Hyderabad sales assistant.
    Respond in Hinglish/Hindi/Telugu/English naturally.
    Max 15 words. Book meeting.

    User: {text}
    """

    res = ollama.chat(
        model="gemma4:e4b",
        messages=[{"role": "user", "content": prompt}]
    )

    return res["message"]["content"]

# ---------------------------
# TTS
# ---------------------------
def text_to_speech(text):
    url = "https://api.elevenlabs.io/v1/text-to-speech/oO7sLA3dWfQXsKeSAjpA"

    headers = {
        "xi-api-key": os.getenv("ELEVEN_API_KEY"),
        "Content-Type": "application/json"
    }

    data = {
        "text": text,
        "voice_settings": {
            "stability": 0.5,
            "similarity_boost": 0.5
        }
    }

    response = requests.post(url, json=data, headers=headers)
    return response.content


class AICallRequest(BaseModel):
    text: str

@app.post("/ai-call")
def ai_call(data: AICallRequest):
    reply = llm_reply(data.text)
    audio_bytes = text_to_speech(reply)
    payload = base64.b64encode(audio_bytes).decode("utf-8")
    return {"reply": reply, "audio": payload}


@app.get("/test-db")
def test_db():
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT 1;")
        result = cur.fetchone()
        cur.close()
        conn.close()
        return {"status": "DB connected", "result": result}
    except Exception as e:
        return {"error": str(e)}
from fastapi.responses import JSONResponse

# ---------------------------
# EXOTEL JSON CONNECT APPLET
# ---------------------------
@app.get("/voice")
async def voice(request: Request):
    print("CALL RECEIVED:", dict(request.query_params))

    return JSONResponse({
        "destination": {
            "numbers": ["+91YOUR_PHONE"]
        },
        "record": True,
        "max_ringing_duration": 30,
        "max_conversation_duration": 300
    })

@app.post("/process")
async def process(request: Request):
    form = await request.form()
    recording_url = form.get("RecordingUrl")

    # Download audio
    if recording_url:
        audio_data = requests.get(recording_url).content

    # TEMP STT (replace later)
    user_text = "mera salon hai 5 log hai demo chahiye"

    # LLM Reply
    reply = llm_reply(user_text)

    # CRM Extraction & Postgres Pipeline
    extracted = llm_extract(user_text)
    summary = llm_summary(user_text)
    
    # We use 'From' from the Exotel form if it exists, else default placeholder
    caller_phone = form.get("From", "ExotelUser")

    save_to_db({
        "phone": caller_phone,
        "business_type": extracted.get("business_type"),
        "team_size": extracted.get("team_size"),
        "revenue": extracted.get("revenue"),
        "meeting_time": extracted.get("meeting_time"),
        "summary": summary,
        "transcript": user_text
    })

    return Response(content=f"""
<Response>
    <Say voice="woman">{reply}</Say>
</Response>
""", media_type="text/xml")




# ---------------------------
# RAW SQL CONVERTER EXECUTOR
# ---------------------------
class SQLExecRequest(BaseModel):
    sql_script: str

@app.post("/execute-sql")
def execute_sql(data: SQLExecRequest):
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute(data.sql_script)
        conn.commit()
        return {"status": "success"}
    except Exception as e:
        conn.rollback()
        return {"error": str(e)}
    finally:
        cur.close()
        conn.close()


# Mount static files (HTML/CSS/JS) so they can be securely served directly from the same port
app.mount("/", StaticFiles(directory=".", html=True), name="static")