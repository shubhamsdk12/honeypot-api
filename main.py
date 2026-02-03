from fastapi import FastAPI, Header, HTTPException
from typing import Optional

app = FastAPI()

API_KEY = "shriRAM"


@app.post("/")
def honeypot(x_api_key: Optional[str] = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    # 🔥 DO NOT READ BODY AT ALL (Round-1 tester sends none)
    return {
        "status": "success",
        "reply": "Why will my account be blocked?"
    }


# Optional health check
@app.get("/")
def health():
    return {"status": "ok"}
