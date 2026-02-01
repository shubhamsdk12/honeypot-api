from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from typing import List, Optional, Union
import re
import requests

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

# ================= MODELS =================

class MessageObject(BaseModel):
    sender: Optional[str] = "scammer"
    text: str
    timestamp: Optional[str] = None


class RequestBody(BaseModel):
    sessionId: str
    # 🔥 CRITICAL FIX: message can be STRING or OBJECT
    message: Union[str, MessageObject]
    conversationHistory: Optional[list] = None
    metadata: Optional[dict] = None

# ================= HELPERS =================

def normalize_message(msg: Union[str, MessageObject]) -> tuple[str, str]:
    """
    Returns (sender, text)
    """
    if isinstance(msg, str):
        return "scammer", msg
    return msg.sender or "scammer", msg.text

# ================= SCAM DETECTION =================

def detect_scam(text: str) -> bool:
    text = text.lower()
    return (
        any(k in text for k in SCAM_KEYWORDS)
        or LINK_PATTERN.search(text)
        or UPI_PATTERN.search(text)
        or PHONE_PATTERN.search(text)
    )

# ================= INTELLIGENCE EXTRACTION =================

def extract_intelligence(text: str, session_data: dict):
    for upi in UPI_PATTERN.findall(text):
        session_data["intelligence"]["upiIds"].add(upi)

    for phone in PHONE_PATTERN.findall(text):
        session_data["intelligence"]["phoneNumbers"].add(phone)

    if LINK_PATTERN.search(text):
        session_data["intelligence"]["phishingLinks"].add(text)

    for kw in SCAM_KEYWORDS:
        if kw in text.lower():
            session_data["intelligence"]["suspiciousKeywords"].add(kw)

# ================= REPLY LOGIC =================

def generate_reply(session_data: dict, text: str) -> str:
    text = text.lower()

    if not session_data["scam_detected"]:
        return "Okay, could you please explain a bit more?"

    if "bank" not in text:
        return "Which bank is this regarding?"

    if any(w in text for w in ["upi", "otp", "payment"]):
        return "Why do you need this information right now?"

    if LINK_PATTERN.search(text):
        return "I’m unable to open links right now. What does it say?"

    return "I’m a bit confused. Can you explain the steps clearly?"

# ================= FINAL CALLBACK =================

def should_finalize(session_data: dict) -> bool:
    if not session_data["scam_detected"]:
        return False
    intel = session_data["intelligence"]
    return (
        session_data["message_count"] >= 5
        or intel["upiIds"]
        or intel["phishingLinks"]
    )


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
    except Exception:
        pass

# ================= API ENDPOINT =================

@app.post("/honeypot")
def honeypot(
    body: RequestBody,
    x_api_key: str = Header(None)
):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    sender, text = normalize_message(body.message)
    session_id = body.sessionId

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

    extract_intelligence(text, session)

    if detect_scam(text):
        session["scam_detected"] = True

    reply = generate_reply(session, text)

    if not session["finalized"] and should_finalize(session):
        send_final_callback(session_id, session)
        session["finalized"] = True

    return {
        "status": "success",
        "reply": reply
    }
