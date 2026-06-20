import json, os
import requests
import psycopg2
from groq import Groq
from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException, Response
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth
from pydantic import BaseModel
from passlib.context import CryptContext

# Load environment variables
load_dotenv()

app = FastAPI()

# Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=".*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SESSION_SECRET", "default-secret-key"))



# ---------------------------
# OAUTH
# ---------------------------
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

# ---------------------------
# DATABASE & AUTH HELPERS
# ---------------------------
DB_URL = os.getenv("DATABASE_URL", "postgresql://postgres:the123@localhost:5433/voice_ai")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_db():
    return psycopg2.connect(DB_URL)

class LoginRequest(BaseModel):
    email: str
    password: str

class SignupRequest(BaseModel):
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

@app.post("/signup")
def signup(data: SignupRequest):
    conn = get_db()
    cur = conn.cursor()
    hashed = pwd_context.hash(data.password)
    try:
        cur.execute("INSERT INTO users (email, password) VALUES (%s, %s)", (data.email, hashed))
        conn.commit()
    except Exception:
        conn.rollback()
        cur.close()
        conn.close()
        raise HTTPException(status_code=400, detail="User already exists")
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
        new_row = cur.fetchone()
        user_id = new_row[0] if new_row else None
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
    token = await oauth.google.authorize_access_token(request)
    user = token.get("userinfo")
    if not user:
        resp = await oauth.google.get("https://openidconnect.googleapis.com/v1/userinfo", token=token)
        user = resp.json()
    email = user["email"]
    user_id = get_or_create_oauth_user(email)
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
    email = user.get("email") or f"{user['login']}@github.com"
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

# ---------------------------
# CRM / LEADS
# ---------------------------
@app.get("/leads")
def get_all_leads():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, phone, business_type, team_size, revenue_estimate, meeting_time, call_summary, transcript, lead_score, lead_quality, created_at FROM leads ORDER BY created_at DESC")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    leads = []
    for row in rows:
        leads.append({
            "id": row[0], "phone": row[1], "business_type": row[2], "team_size": row[3],
            "revenue": row[4], "meeting_time": row[5], "summary": row[6],
            "transcript": row[7], "lead_score": row[8], "lead_quality": row[9],
            "created_at": str(row[10])
        })
    return leads

@app.get("/leads/high-value")
def high_value_leads():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, business_type, team_size FROM leads WHERE team_size IS NOT NULL ORDER BY created_at DESC")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return [{"id": r[0], "business_type": r[1], "team_size": r[2]} for r in rows]

@app.get("/leads/{lead_id}")
def get_lead(lead_id: int):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, phone, business_type, team_size, revenue_estimate, meeting_time, call_summary, transcript, lead_score, lead_quality, created_at FROM leads WHERE id = %s", (lead_id,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Lead not found")
    return {
        "id": row[0], "phone": row[1], "business_type": row[2], "team_size": row[3],
        "revenue": row[4], "meeting_time": row[5], "summary": row[6],
        "transcript": row[7], "lead_score": row[8], "lead_quality": row[9],
        "created_at": str(row[10])
    }

# ---------------------------
# STATS & LOGIC HELPERS
# ---------------------------
@app.get("/api/analytics")
def get_analytics():
    return [
        {"path": "/process", "methods": "POST", "name": "Exotel Webhook", "hits": 142, "last_accessed": "2 mins ago"},
        {"path": "/leads", "methods": "GET", "name": "Get CRM Leads", "hits": 890, "last_accessed": "1 min ago"},
        {"path": "/stats", "methods": "GET", "name": "Dashboard Stats", "hits": 1205, "last_accessed": "1 min ago"},
        {"path": "/make-call", "methods": "POST", "name": "AI Outbound Dialer", "hits": 34, "last_accessed": "5 hours ago"}
    ]

class SQLExecution(BaseModel):
    sql_script: str

@app.post("/execute-sql")
def execute_sql(data: SQLExecution):
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute(data.sql_script)
        conn.commit()
    except Exception as e:
        conn.rollback()
        cur.close()
        conn.close()
        return {"status": "error", "error": str(e)}
    cur.close()
    conn.close()
    return {"status": "success"}

@app.get("/stats")
def get_stats():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*), COUNT(meeting_time), SUM(CASE WHEN revenue_estimate ~ '^[0-9]+' THEN CAST(regexp_replace(revenue_estimate, '[^0-9]', '', 'g') AS DOUBLE PRECISION) ELSE 0 END) FROM leads")
    row = cur.fetchone()
    if row:
        total_calls, meetings, total_rev = row
    else:
        total_calls, meetings, total_rev = 0, 0, 0
    cur.close()
    conn.close()
    return {
        "total_calls": total_calls or 0,
        "meetings_booked": meetings or 0,
        "estimated_revenue": int(total_rev or 0)
    }

def save_to_db(data):
    conn = psycopg2.connect(DB_URL)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO leads (phone, business_type, team_size, revenue_estimate, meeting_time, call_summary, transcript, lead_score, lead_quality)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """, (
        data.get("phone"), data.get("business_type"), data.get("team_size"),
        data.get("revenue"), data.get("meeting_time"), data.get("summary"), 
        data.get("transcript"), data.get("lead_score", 0), data.get("lead_quality", 'Cold')
    ))
    conn.commit()
    cur.close()
    conn.close()

import ollama

groq_client = Groq(api_key=os.getenv("GROQ_API_KEY", "dummy"))
USE_LOCAL_LLM = os.getenv("USE_LOCAL_LLM", "false").lower() == "true"
LOCAL_MODEL_NAME = os.getenv("LOCAL_MODEL_NAME", "llama3") # Example: llama3, mistral, phi3

def chat_completion(prompt):
    if USE_LOCAL_LLM:
        # Use Personal Local LLM via Ollama
        res = ollama.chat(model=LOCAL_MODEL_NAME, messages=[{"role": "user", "content": prompt}])
        return res['message']['content']
    else:
        # Default to Groq Cloud LLM
        res = groq_client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}]
        )
        return res.choices[0].message.content

def llm_extract(text):
    prompt = f"""Extract Lead Data from transcript: "{text}"
    Return JSON only with these keys: 
    - business_type (string)
    - team_size (string)
    - revenue (string)
    - meeting_time (string or null)
    - lead_score (integer 0-100, based on urgency and business size)
    - lead_quality (string: "Hot", "Warm", or "Cold")
    
    Scoring Guide:
    - Hot: Intent to buy/book, 10+ team members, or high revenue.
    - Cold: No interest, small business, or just browsing.
    """
    try:
        content = chat_completion(prompt) or "{}"
        return json.loads(content)
    except Exception:
        return {"lead_score": 10, "lead_quality": "Cold"}

def llm_summary(text):
    prompt = f"Summarize this call in 12 words:\n{text}"
    return chat_completion(prompt)

def llm_reply(text):
    prompt = f"You are Riya, Hyderabad sales assistant. Respond naturally in max 15 words. User: {text}"
    return chat_completion(prompt)


# ---------------------------
# VOICE ENDPOINTS
# ---------------------------
@app.get("/voice")
async def voice(request: Request):
    destination = os.getenv("MY_PHONE", "+91XXXXXXXXXX")
    return JSONResponse({"destination": {"numbers": [destination]}, "record": True})

@app.post("/process")
async def process(request: Request):
    form = await request.form()
    recording_url_val = form.get("RecordingUrl")
    recording_url = str(recording_url_val) if recording_url_val else None
    caller_phone = str(form.get("From", "ExotelUser"))

    # 1. Speech-to-Text (STT) via Groq Whisper if Exotel sends an audio recording
    if recording_url:
        try:
            audio_response = requests.get(recording_url)
            with open("temp_recording.wav", "wb") as f:
                f.write(audio_response.content)
            
            with open("temp_recording.wav", "rb") as f:
                transcription = groq_client.audio.transcriptions.create(
                    file=("temp_recording.wav", f.read()),
                    model="whisper-large-v3",
                )
            user_text = transcription.text
        except Exception as e:
            print("Audio transcription error:", e)
            user_text = ""
    else:
        # Fallback if no audio is provided yet (e.g., test trigger)
        user_text = str(form.get("text", "mera salon hai 5 log hai demo chahiye"))

    # 2. Generate Reply via LLM
    if user_text and user_text.strip():
        reply = llm_reply(user_text)
        extracted = llm_extract(user_text)
        summary = llm_summary(user_text)
        
        # Save lead memory asynchronously or synchronously
        save_to_db({
            "phone": caller_phone, 
            "business_type": extracted.get("business_type"),
            "team_size": extracted.get("team_size"), 
            "revenue": extracted.get("revenue"),
            "meeting_time": extracted.get("meeting_time"), 
            "summary": summary, 
            "transcript": user_text,
            "lead_score": extracted.get("lead_score", 0),
            "lead_quality": extracted.get("lead_quality", "Cold")
        })
    else:
        reply = "I'm sorry, I didn't quite catch that. Could you repeat?"

    # 3. Conversational Loop Response with Text-to-Speech (TTS)
    # Exotel's <Say> converts our text back to speech
    # <Record> creates the loop waiting for the user to reply
    xml_response = f"""<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Say voice="woman">{reply}</Say>
    <Record action="{request.url.path}" maxLength="15"/>
</Response>"""
    return Response(content=xml_response, media_type="text/xml")

@app.post("/make-call")
async def make_call(request: Request):
    data = await request.json()
    user_phone = data.get("phone")
    if not user_phone:
        raise HTTPException(status_code=400, detail="Phone number is required")
    sid = os.getenv("EXOTEL_SID")
    key = os.getenv("EXOTEL_API_KEY")
    token = os.getenv("EXOTEL_API_TOKEN")
    virtual_num = os.getenv("EXOTEL_VIRTUAL_NUMBER")
    if not all([sid, key, token, virtual_num]):
        raise HTTPException(status_code=500, detail="Exotel credentials not configured in .env")
    response = requests.post(
        url=f"https://api.exotel.com/v1/Accounts/{sid}/Calls/connect",
        auth=(str(key), str(token)),
        data={"From": virtual_num, "To": user_phone.replace("+91", "0"), "CallerId": virtual_num, "CallType": "trans"}
    )
    return {"status": response.status_code, "data": response.text}

app.mount("/", StaticFiles(directory="static", html=True), name="static")