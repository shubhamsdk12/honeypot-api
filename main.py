from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import re
import requests

app = FastAPI()

# 🔐 API KEY
API_KEY = "helloworld123"

# 🔗 GUVI CALLBACK
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

# -------------------- SESSION MEMORY --------------------

SESSION_STORE = {}  # in-memory storage

# -------------------- RULE SET --------------------

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

# -------------------- MODELS --------------------

class Message(BaseModel):
    sender: str
    text: str
    timestamp: Optional[str] = None


class RequestBody(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: Optional[List[Message]] = []
    metadata: Optional[dict] = None

# -------------------- SCAM DETECTION --------------------

def detect_scam(text: str) -> bool:
    text_lower = text.lower()

    if any(keyword in text_lower for keyword in SCAM_KEYWORDS):
        return True

    if LINK_PATTERN.search(text):
        return True

    if UPI_PATTERN.search(text) or PHONE_PATTERN.search(text):
        return True

    return False

# -------------------- INTELLIGENCE EXTRACTION --------------------

def extract_intelligence(text: str, session_data: dict):
    text_lower = text.lower()

    for upi in UPI_PATTERN.findall(text):
        session_data["intelligence"]["upiIds"].add(upi)

    for phone in PHONE_PATTERN.findall(text):
        session_data["intelligence"]["phoneNumbers"].add(phone)

    if LINK_PATTERN.search(text):
        session_data["intelligence"]["phishingLinks"].add(text)

    for keyword in SCAM_KEYWORDS:
        if keyword in text_lower:
            session_data["intelligence"]["suspiciousKeywords"].add(keyword)

# -------------------- REPLY STRATEGY --------------------

def generate_reply(session_data: dict, current_text: str) -> str:
    text = current_text.lower()

    if not session_data["scam_detected"]:
        return "Okay, could you please explain a bit more?"

    if "bank" not in text and not any(
        "bank" in msg["text"].lower()
        for msg in session_data["messages"]
        if msg["sender"] == "scammer"
    ):
        return "Which bank is this regarding?"

    if any(word in text for word in ["upi", "otp", "payment"]):
        return "Why do you need this information right now?"

    if LINK_PATTERN.search(text):
        return "I’m not able to open links right now. What exactly does it say?"

    return "I’m a bit confused. Can you explain the process step by step?"

# -------------------- FINAL CALLBACK HELPERS --------------------

def should_finalize(session_data: dict) -> bool:
    if not session_data["scam_detected"]:
        return False

    if session_data["message_count"] >= 6:
        return True

    intel = session_data["intelligence"]
    if intel["upiIds"] or intel["phishingLinks"]:
        return True

    return False


def build_final_payload(session_id: str, session_data: dict) -> dict:
    intel = session_data["intelligence"]

    return {
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
        "agentNotes": "Rule-based detection: urgency, financial request, redirection tactics observed"
    }


def send_final_callback(payload: dict):
    try:
        response = requests.post(
            GUVI_CALLBACK_URL,
            json=payload,
            timeout=5
        )
        print("GUVI callback status:", response.status_code)
    except Exception as e:
        print("GUVI callback failed:", str(e))

# -------------------- API ENDPOINT --------------------

@app.post("/honeypot")
def honeypot_endpoint(
    body: RequestBody,
    x_api_key: str = Header(None)
):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    session_id = body.sessionId
    incoming_text = body.message.text

    # 🧠 Initialize session
    if session_id not in SESSION_STORE:
        SESSION_STORE[session_id] = {
            "messages": [],
            "scam_detected": False,
            "message_count": 0,
            "finalized": False,
            "intelligence": {
                "upiIds": set(),
                "phoneNumbers": set(),
                "phishingLinks": set(),
                "suspiciousKeywords": set()
            }
        }

    session_data = SESSION_STORE[session_id]

    # 🧠 Store incoming message
    session_data["messages"].append({
        "sender": body.message.sender,
        "text": incoming_text
    })
    session_data["message_count"] += 1

    # 🕵️ Extract intelligence
    extract_intelligence(incoming_text, session_data)

    # 🧠 Scam detection
    if detect_scam(incoming_text):
        session_data["scam_detected"] = True

    # 🤖 Generate reply
    reply_text = generate_reply(session_data, incoming_text)

    # 🧠 Store agent reply
    session_data["messages"].append({
        "sender": "agent",
        "text": reply_text
    })

    # 🚨 Final callback (only once)
    if not session_data["finalized"] and should_finalize(session_data):
        payload = build_final_payload(session_id, session_data)
        print("FINAL PAYLOAD:", payload)  # temporary debug
        send_final_callback(payload)
        session_data["finalized"] = True

    return {
        "status": "success",
        "reply": reply_text
    }
