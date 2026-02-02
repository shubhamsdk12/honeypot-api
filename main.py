import uvicorn
import json
import re
import requests
import random
from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.responses import JSONResponse
from typing import Dict, Any, Set

# ================= CONFIGURATION =================
API_KEY = "helloworld123"
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

# ================= STATE MANAGEMENT =================
sessions: Dict[str, Any] = {}

# ================= PATTERNS & SCRIPTS =================
PATTERNS = {
    "upi": re.compile(r'[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{3,}'),
    "phone": re.compile(r'\b[6-9]\d{9}\b'),
    "link": re.compile(r'http[s]?://[^\s]+'),
    "bank": re.compile(r'\b\d{9,18}\b')
}

SCAM_KEYWORDS = ["urgent", "verify", "block", "suspend", "kyc", "expire", "pan", "aadhar", "account"]

# Scripted Persona (The "Martha" Fallback)
RESPONSES = [
    "I am not very good with technology. What do I need to do?",
    "My grandson usually handles this. Can you explain slowly?",
    "Oh dear, I don't want my account blocked. How do I fix it?",
    "I can't find my glasses. Which number should I read?",
    "Is this going to cost money? I am on a pension."
]

app = FastAPI()

# ================= HELPER FUNCTIONS =================

def extract_intel(text: str, session: dict):
    """
    Extracts regex patterns and updates the session intel.
    """
    text_lower = text.lower()
    
    # 1. Regex Extraction
    session["intel"]["upi"].update(PATTERNS["upi"].findall(text))
    session["intel"]["phone"].update(PATTERNS["phone"].findall(text))
    session["intel"]["links"].update(PATTERNS["link"].findall(text))
    session["intel"]["accounts"].update(PATTERNS["bank"].findall(text))
    
    # 2. Keyword Scoring
    for word in SCAM_KEYWORDS:
        if word in text_lower:
            session["intel"]["keywords"].add(word)
            session["scam_score"] += 1

def send_callback_background(session_id: str, session: dict):
    """
    Runs in BACKGROUND. Sends data to GUVI without blocking the reply.
    """
    if session["finalized"]:
        return

    # Trigger Logic: High Score OR Sensitive Data Found OR Long Conversation
    has_data = len(session["intel"]["upi"]) > 0 or len(session["intel"]["links"]) > 0
    high_score = session["scam_score"] >= 2
    long_convo = session["turns"] >= 5

    if has_data or high_score or long_convo:
        # Match the PDF Schema EXACTLY
        payload = {
            "sessionId": session_id,
            "scamDetected": True,
            "totalMessagesExchanged": session["turns"],
            "extractedIntelligence": {
                "bankAccounts": list(session["intel"]["accounts"]),
                "upiIds": list(session["intel"]["upi"]),
                "phishingLinks": list(session["intel"]["links"]),
                "phoneNumbers": list(session["intel"]["phone"]),
                "suspiciousKeywords": list(session["intel"]["keywords"])
            },
            "agentNotes": "Rule-based Agent detected urgency and extracted payment details."
        }
        
        try:
            print(f"🚀 [BACKGROUND] Sending Callback for {session_id}...")
            requests.post(GUVI_CALLBACK_URL, json=payload, timeout=5)
            session["finalized"] = True
            print("✅ Callback Sent Successfully")
        except Exception as e:
            print(f"❌ Callback Failed: {e}")

# ================= API ENDPOINTS =================

@app.get("/")
async def root():
    return {"status": "online", "message": "Honeypot Active"}

@app.head("/")
async def root_head():
    return {"status": "online"}

@app.get("/honeypot")
async def honeypot_get():
    return {"status": "online", "message": "Send POST request to this endpoint"}

@app.post("/honeypot")
async def honeypot(request: Request, background_tasks: BackgroundTasks):
    """
    1. Accepts Request (Crash-Proof)
    2. Runs Logic
    3. Queues Callback
    4. Returns JSON Schema Match
    """
    
    # 1. Auth Check
    api_key = request.headers.get("x-api-key") or request.headers.get("X-API-KEY")
    if api_key != API_KEY:
        return JSONResponse(status_code=401, content={"status": "error", "message": "Invalid API Key"})

    # 2. Parse Body safely
    try:
        raw = await request.body()
        data = json.loads(raw) if raw else {}
    except:
        data = {}

    # 3. Session Setup
    session_id = data.get("sessionId", "unknown")
    
    # Extract 'text' from message object or string
    msg_raw = data.get("message", "")
    text = msg_raw.get("text", "") if isinstance(msg_raw, dict) else str(msg_raw)

    if session_id not in sessions:
        sessions[session_id] = {
            "turns": 0,
            "scam_score": 0,
            "finalized": False,
            "intel": {
                "upi": set(), "phone": set(), "links": set(), 
                "accounts": set(), "keywords": set()
            }
        }
    
    session = sessions[session_id]
    session["turns"] += 1
    
    # 4. Intelligence Logic
    extract_intel(text, session)
    
    # 5. Generate Reply (Scripted Random Choice)
    reply = random.choice(RESPONSES)
    if "bank" in text.lower():
        reply = "Which bank account is this regarding? I have two."
    elif "verify" in text.lower():
        reply = "How do I verify? Do I need to click something?"

    # 6. Schedule Callback (Does NOT block response)
    background_tasks.add_task(send_callback_background, session_id, session)

    # 7. Return Response (Matches PDF Schema)
    return {
        "status": "success",
        "reply": reply
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)