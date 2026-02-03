from fastapi import FastAPI, Header, HTTPException
from typing import List, Optional, Union
from pydantic import BaseModel

app = FastAPI()

# ================= CONFIG =================
API_KEY = "shriRAM"
# =========================================


# ---------- MODELS ----------
class Message(BaseModel):
    sender: str
    text: str
    timestamp: Union[int, str]   # ACCEPT BOTH


class HistoryItem(BaseModel):
    sender: str
    text: str
    timestamp: Union[int, str]


class Metadata(BaseModel):
    channel: Optional[str] = None
    language: Optional[str] = None
    locale: Optional[str] = None


class HoneypotRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: Optional[List[HistoryItem]] = []
    metadata: Optional[Metadata] = None


# ---------- LOGIC ----------
def detect_scam(text: str) -> bool:
    keywords = [
        "blocked",
        "verify",
        "upi",
        "account",
        "suspended",
        "urgent",
        "immediately"
    ]
    text = text.lower()
    return any(word in text for word in keywords)


def agent_reply() -> str:
    return "Why will my account be blocked?"


# ---------- ENDPOINT ----------
@app.post("/")
def honeypot(
    body: HoneypotRequest,
    x_api_key: str = Header(None)
):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    scam = detect_scam(body.message.text)

    # 🔥 ROUND-1 SAFE RESPONSE
    if scam:
        return {
            "status": "success",
            "reply": agent_reply()
        }

    return {
        "status": "success",
        "reply": "Okay."
    }
