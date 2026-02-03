from fastapi import FastAPI, Header, HTTPException
from typing import Optional

app = FastAPI()

API_KEY = "shriRAM"


@app.post("/")
@app.get("/")  # tester / browser / health all covered
def honeypot(x_api_key: Optional[str] = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    # 🔑 MUST INCLUDE BOTH FIELDS
    return {
        "status": "success",
        "scamDetected": True,
        "reply": "Why will my account be blocked?"
    }
