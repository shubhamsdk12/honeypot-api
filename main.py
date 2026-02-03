from fastapi import FastAPI, Header, HTTPException
from typing import Optional, List, Any
from pydantic import BaseModel, ConfigDict

app = FastAPI()

API_KEY = "shriRAM"


# ---------- MODELS (LENIENT) ----------

class Message(BaseModel):
    sender: Optional[str] = None
    text: Optional[str] = None
    timestamp: Optional[Any] = None

    model_config = ConfigDict(extra="allow")


class HoneypotRequest(BaseModel):
    sessionId: Optional[str] = None
    message: Optional[Message] = None
    conversationHistory: Optional[Any] = None
    metadata: Optional[Any] = None

    model_config = ConfigDict(extra="allow")


# ---------- LOGIC ----------

def detect_scam(text: Optional[str]) -> bool:
    if not text:
        return False
    keywords = ["blocked", "verify", "upi", "account", "urgent"]
    text = text.lower()
    return any(k in text for k in keywords)


# ---------- ENDPOINT ----------

@app.post("/")
def honeypot(
    body: HoneypotRequest,
    x_api_key: Optional[str] = Header(None)
):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    text = body.message.text if body.message else ""

    if detect_scam(text):
        return {
            "status": "success",
            "reply": "Why will my account be blocked?"
        }

    return {
        "status": "success",
        "reply": "Okay."
    }


# OPTIONAL: health check (not required)
@app.get("/")
def health():
    return {"status": "ok"}
