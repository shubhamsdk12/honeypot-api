import uvicorn
from fastapi import FastAPI, Header, HTTPException, Request
import re
import requests
from typing import Optional

app = FastAPI()

# ================= CONFIG =================

API_KEY = "helloworld123"
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

# ================= SESSION MEMORY =================

SESSION_STORE = {}

# ================= RULE SET =================

SCAM_KEYWORDS = [
    "urgent", "immediately", "today",
    "blocked", "suspended", "closed",
    "verify", "kyc", "update",
    "bank", "upi", "otp",
    "click", "link", "refund"
]

LINK_PATTERN = re.compile(r"http[s]?://|www\.", re.IGNORECASE)
UPI_PATTERN = re.compile(r"\b[\w.-]+@[\w.-]+\b")
PHONE_PATTERN = re.compile(r"\b\d{10}\b")

# ================= INTELLIGENCE HELPERS =================

def normalize_message(raw_msg) -> tuple[str, str]:
    """
    Robust normalizer that handles String, Dict, or None without crashing.
    """
    if isinstance(raw_msg, str):
        return "scammer", raw_msg
    elif isinstance(raw_msg, dict):
        return raw_msg.get("sender", "scammer"), raw_msg.get("text", "")
    return "scammer", ""

def detect_scam(text: str) -> bool:
    text = text.lower()
    return (
        any(k in text for k in SCAM_KEYWORDS)
        or LINK_PATTERN.search(text)
        or UPI_PATTERN.search(text)
        or PHONE_PATTERN.search(text)
    )

def extract_intelligence(text: str, session_data: dict):
    # Extract UPIs
    for upi in UPI_PATTERN.findall(text):
        session_data["intelligence"]["upiIds"].add(upi)

    # Extract Phones
    for phone in PHONE_PATTERN.findall(text):
        session_data["intelligence"]["phoneNumbers"].add(phone)

    # Extract Links
    if LINK_PATTERN.search(text):
        session_data["intelligence"]["phishingLinks"].add(text)

    # Extract Keywords
    for kw in SCAM_KEYWORDS:
        if kw in text.lower():
            session_data["intelligence"]["suspiciousKeywords"].add(kw)

def generate_reply(session_data: dict, text: str) -> str:
    text = text.lower()
    
    if not session_data["scam_detected"]:
        return "I received your message, but I am not sure what you mean."

    if "bank" not in text:
        return "Which bank is this regarding? I have accounts in a few."

    if any(w in text for w in ["upi", "otp", "payment"]):
        return "I am trying to find my card. Why do you need this right now?"

    if LINK_PATTERN.search(text):
        return "I cannot click that link, my phone says it is unsafe. Can you text me the info?"

    return "I am a bit confused. Can you explain the steps clearly?"

# ================= CALLBACK LOGIC =================

def should_finalize(session_data: dict) -> bool:
    if not session_data["scam_detected"]:
        return False
    intel = session_data["intelligence"]
    
    # Finalize if we have extracted CRITICAL intel or conversation is long
    return (len(intel["upiIds"]) > 0 or len(intel["phishingLinks"]) > 0 or session_data["message_count"] >= 5)

def send_final_callback(session_id: str, session_data: dict):
    intel = session_data["intelligence"]

    payload = {
        "sessionId": session_id,
        "scamDetected": True,
        "totalMessagesExchanged": session_data["message_count"],
        "extractedIntelligence": {
            "bankAccounts": [],
            "upiIds": list(intel["upiIds"]),
            "phishingLinks": list(intel["phishingLinks"]),
            "phoneNumbers": list(intel["phoneNumbers"]),
            "suspiciousKeywords": list(intel["suspiciousKeywords"])
        },
        "agentNotes": "Rule-based scam detection with autonomous engagement"
    }

    try:
        requests.post(GUVI_CALLBACK_URL, json=payload, timeout=5)
    except Exception as e:
        print(f"Callback Failed: {e}")

# ================= API ENDPOINTS =================

# --- FIX START: This is what you were missing! ---
@app.get("/")
async def root():
    return {"status": "online", "message": "Honeypot is running"}

@app.head("/")
async def root_head():
    return {"status": "online"}
# --- FIX END ---

@app.post("/honeypot")
async def honeypot(request: Request, x_api_key: str = Header(None)):
    """
    Handles the main logic safely.
    """
    
    # 1. Auth Check
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    # 2. Parse Body Safely (No Pydantic Crash)
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    # 3. Extract Fields
    session_id = body.get("sessionId", "unknown_session")
    raw_message = body.get("message")
    
    sender, text = normalize_message(raw_message)

    # 4. Initialize Session
    if session_id not in SESSION_STORE:
        SESSION_STORE[session_id] = {
            "messages": [],
            "message_count": 0,
            "scam_detected": False,
            "finalized": False,
            "intelligence": {
                "upiIds": set(),
                "phoneNumbers": set(),
                "phishingLinks": set(),
                "suspiciousKeywords": set()
            }
        }

    session = SESSION_STORE[session_id]
    session["message_count"] += 1

    # 5. Run Intelligence Logic
    extract_intelligence(text, session)

    if detect_scam(text):
        session["scam_detected"] = True

    # 6. Generate Reply
    reply = generate_reply(session, text)

    # 7. Handle Callback
    if not session["finalized"] and should_finalize(session):
        send_final_callback(session_id, session)
        session["finalized"] = True

    # 8. Return Response
    return {
        "status": "success",
        "reply": reply
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)