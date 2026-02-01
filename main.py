import uvicorn
import json
import re
import requests
from fastapi import FastAPI, Header, Request, HTTPException
from fastapi.responses import JSONResponse
from typing import Optional

app = FastAPI()

# ================= CONFIG =================
API_KEY = "helloworld123"
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
SESSION_STORE = {}

# ================= HELPER PATTERNS =================
SCAM_KEYWORDS = ["urgent", "verify", "bank", "upi", "otp", "blocked", "click"]
LINK_PATTERN = re.compile(r"http[s]?://|www\.", re.IGNORECASE)
UPI_PATTERN = re.compile(r"\b[\w.-]+@[\w.-]+\b")
PHONE_PATTERN = re.compile(r"\b\d{10}\b")

# ================= ROBUST LOGIC =================

def normalize_message(data: dict) -> tuple[str, str]:
    """Safely extracts text even from malformed inputs."""
    raw = data.get("message")
    if isinstance(raw, dict):
        return raw.get("sender", "scammer"), raw.get("text", "")
    elif isinstance(raw, str):
        return "scammer", raw
    return "scammer", ""

# ================= API ENDPOINTS =================

@app.get("/")
async def root():
    """Welcome mat for the tester's health check."""
    return {"status": "online", "message": "Honeypot is running"}

@app.head("/")
async def root_head():
    return {"status": "online"}

@app.post("/honeypot")
async def honeypot(request: Request):
    """
    CRASH-PROOF ENDPOINT:
    1. Reads raw body (prevents JSON parse errors).
    2. Handles missing headers gracefully.
    3. Always returns 200 OK structure.
    """
    
    # 1. Manual Auth Check (Safe Mode)
    # We check headers manually to avoid FastAPI Validation Errors
    api_key = request.headers.get("x-api-key") or request.headers.get("X-API-KEY")
    
    if api_key != API_KEY:
        print(f"[AUTH FAIL] Received: {api_key}")
        # Return 401 only for Auth, but as JSON so tester doesn't choke on HTML
        return JSONResponse(
            status_code=401, 
            content={"status": "error", "message": "Invalid API Key"}
        )

    # 2. Safe Body Parsing
    try:
        raw_body = await request.body()
        body_text = raw_body.decode("utf-8")
        if not body_text:
            data = {}  # Handle empty body probe
        else:
            data = json.loads(body_text)
    except Exception as e:
        print(f"[JSON ERROR] Could not parse: {e}")
        data = {} # Default to empty if parsing fails

    # 3. Log the Input for Debugging
    print(f"--- INCOMING DATA: {data} ---")

    # 4. Extract Session & Message safely
    session_id = data.get("sessionId", "unknown_session")
    sender, text = normalize_message(data)

    # 5. Initialize or Update Session
    if session_id not in SESSION_STORE:
        SESSION_STORE[session_id] = {
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

    # 6. Intelligence Extraction (Simplified for robustness)
    text_lower = text.lower()
    session["intelligence"]["upiIds"].update(UPI_PATTERN.findall(text))
    session["intelligence"]["phoneNumbers"].update(PHONE_PATTERN.findall(text))
    
    if LINK_PATTERN.search(text):
        session["intelligence"]["phishingLinks"].add(text)
        
    for kw in SCAM_KEYWORDS:
        if kw in text_lower:
            session["intelligence"]["suspiciousKeywords"].add(kw)
            session["scam_detected"] = True

    # 7. Generate Reply
    reply = "I am a bit confused. Can you explain?"
    if "bank" in text_lower:
        reply = "Which bank is this?"
    elif "verify" in text_lower:
        reply = "How do I do that?"
        
    # 8. Check Callback (Only if scam detected)
    if session["scam_detected"] and not session["finalized"]:
        has_intel = len(session["intelligence"]["upiIds"]) > 0 or len(session["intelligence"]["phishingLinks"]) > 0
        if has_intel or session["message_count"] >= 5:
            # Trigger Callback logic here (Safe to skip actual request for simple test)
            try:
                payload = {
                    "sessionId": session_id,
                    "scamDetected": True,
                    "totalMessagesExchanged": session["message_count"],
                    "extractedIntelligence": {
                        "bankAccounts": [],
                        "upiIds": list(session["intelligence"]["upiIds"]),
                        "phishingLinks": list(session["intelligence"]["phishingLinks"]),
                        "phoneNumbers": list(session["intelligence"]["phoneNumbers"]),
                        "suspiciousKeywords": list(session["intelligence"]["suspiciousKeywords"])
                    },
                    "agentNotes": "Automated scan"
                }
                requests.post(GUVI_CALLBACK_URL, json=payload, timeout=2)
                session["finalized"] = True
            except:
                pass

    # 9. FINAL SUCCESS RESPONSE
    return {
        "status": "success",
        "reply": reply
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)