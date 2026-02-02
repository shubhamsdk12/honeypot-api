from fastapi import FastAPI, Header, BackgroundTasks, HTTPException
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import re
import requests
import uvicorn

# ================= CONFIGURATION =================
# REQ: Secures access using an API key
API_KEY = "helloworld123"  # Replace with a secure key in production
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

# ================= IN-MEMORY STORAGE =================
# REQ: Handle multi-turn conversations
sessions = {}

# ================= REGEX & PATTERNS =================
# REQ: Extract scam-related intelligence
PATTERNS = {
    "upi": re.compile(r'[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{3,}'),
    "phone": re.compile(r'\b[6-9]\d{9}\b'), # Basic Indian mobile pattern
    "link": re.compile(r'http[s]?://[^\s]+'),
    "bank": re.compile(r'\b\d{9,18}\b')
}

SCAM_KEYWORDS = ["urgent", "verify", "block", "suspend", "kyc", "expire", "pan", "aadhar", "account", "otp"]

# ================= PYDANTIC MODELS (STRICT PDF COMPLIANCE) =================
class IncomingMessage(BaseModel):
    sender: str
    text: str
    timestamp: Optional[str] = None

class HoneypotRequest(BaseModel):
    sessionId: str
    message: IncomingMessage
    conversationHistory: Optional[List[Dict[str, Any]]] = []
    metadata: Optional[Dict[str, Any]] = None

# ================= HELPER FUNCTIONS =================

def extract_intelligence(text: str, session: dict):
    """Extracts regex patterns and updates the session intel."""
    text_lower = text.lower()
    
    # Extract entities
    session["intel"]["upi"].update(PATTERNS["upi"].findall(text))
    session["intel"]["phone"].update(PATTERNS["phone"].findall(text))
    session["intel"]["links"].update(PATTERNS["link"].findall(text))
    session["intel"]["accounts"].update(PATTERNS["bank"].findall(text))
    
    # Check keywords for scoring
    for word in SCAM_KEYWORDS:
        if word in text_lower:
            session["intel"]["keywords"].add(word)
            session["scam_score"] += 1

def send_guvi_callback(session_id: str, session: dict):
    """
    REQ: Mandatory Final Result Callback
    Sends data to GUVI. This runs in the background.
    """
    # Only send if we haven't already finalized this session
    if session.get("finalized"):
        return

    # Trigger Logic: Send if we found sensitive data OR conversation is long enough
    has_data = len(session["intel"]["upi"]) > 0 or len(session["intel"]["links"]) > 0 or len(session["intel"]["accounts"]) > 0
    is_scam_likely = session["scam_score"] >= 2
    is_long_convo = session["turns"] >= 5

    if has_data or is_scam_likely or is_long_convo:
        # Prepare payload exactly as per PDF Page 13-14
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
            "agentNotes": "Scam intent detected. Extracted intelligence via automated agent."
        }
        
        try:
            print(f"🚀 Sending Callback for {session_id}...")
            response = requests.post(GUVI_CALLBACK_URL, json=payload, timeout=5)
            print(f"✅ Callback Status: {response.status_code}")
            session["finalized"] = True
        except Exception as e:
            print(f"❌ Callback Failed: {e}")

# ================= API ENDPOINTS =================

app = FastAPI()

@app.get("/")
def root():
    """Fixes the 404 error by handling the tester's connectivity probe."""
    return {"status": "online", "message": "Honeypot Active"}

@app.get("/health")
def health():
    """Optional health check for Render."""
    return {"status": "healthy"}

@app.post("/honeypot")
def honeypot(data: HoneypotRequest, background_tasks: BackgroundTasks, x_api_key: str = Header(None)):
    """
    REQ: Main API Endpoint
    """
    # 1. Auth Check
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    session_id = data.sessionId
    text = data.message.text

    # 2. Session Management
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

    # 3. Intelligence Extraction
    extract_intelligence(text, session)

    # 4. Agent Persona (Basic Scripted - Upgrade this to AI later)
    # REQ: Maintain a believable human-like persona
    reply = "I am a bit confused. Can you explain that again?"
    if "bank" in text.lower():
        reply = "Which bank account is this regarding? I have an account with SBI."
    elif "verify" in text.lower():
        reply = "I don't know how to do that. Is it difficult?"
    elif "urgent" in text.lower():
        reply = "Please don't rush me, I get nervous."

    # 5. Schedule Callback (Critical: Run in background to keep API fast)
    background_tasks.add_task(send_guvi_callback, session_id, session)

    # 6. Response
    # REQ: Return structured JSON response
    return {
        "status": "success",
        "reply": reply
    }

if __name__ == "__main__":
    # Render uses the PORT environment variable
    import os
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)