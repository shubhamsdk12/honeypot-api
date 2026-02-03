from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from typing import List, Optional

app = FastAPI()

# -------------------- SECRET --------------------
MY_SECRET_API_KEY = "pri"

# -------------------- SCHEMAS --------------------
class Message(BaseModel):
    sender: str
    text: str
    timestamp: str

class RequestPayload(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[Message]
    metadata: Optional[dict] = {}

# -------------------- ENDPOINT --------------------
@app.post("/honeypot")
async def honeypot(
    payload: RequestPayload,
    x_api_key: str = Header(None)
):
    if x_api_key != MY_SECRET_API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

    total_msgs = len(payload.conversationHistory) + 1

    return {
        "status": "success",
        "scamDetected": False,
        "engagementMetrics": {
            "totalMessagesExchanged": total_msgs,
            "detected_tactics": []
        },
        "extractedIntelligence": {
            "bankAccounts": [],
            "upiIds": [],
            "phishingLinks": []
        },
        "agentNotes": "Initial honeypot endpoint test successful."
    }

# -------------------- HEALTH CHECK --------------------
@app.get("/")
def root():
    return {"status": "ok"}
