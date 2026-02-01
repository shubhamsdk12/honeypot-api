import uvicorn
import json
import re
import requests
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

# ================= CONFIG =================
API_KEY = "helloworld123"
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
SESSION_STORE = {}

# ================= PATTERNS =================
SCAM_KEYWORDS = ["urgent", "verify", "bank", "upi", "otp", "blocked", "click"]
LINK_PATTERN = re.compile(r"http[s]?://|www\.", re.IGNORECASE)
UPI_PATTERN = re.compile(r"\b[\w.-]+@[\w.-]+\b")
PHONE_PATTERN = re.compile(r"\b\d{10}\b")

# ================= FIX START: HANDLE ALL PINGS =================

@app.get("/")
async def root():
    """Handles ping to the home page"""
    return {"status": "online", "message": "Honeypot is running"}

@app.head("/")
async def root_head():
    return {"status": "online"}

@app.get("/honeypot")
async def honeypot_get():
    """
    FIXES 405 ERROR:
    Handles the Tester's GET request to /honeypot.
    Tells the tester: "This endpoint exists, please use POST."
    """
    return {"status": "success", "message": "Endpoint active. Send POST request."}

# ================= FIX END =================

@app.post("/honeypot")
async def honeypot_post(request: Request):
    """
    Main Logic (POST requests).
    Universal Receiver - No strict validation to prevent 422 errors.
    """
    
    # 1. READ HEADERS MANUALLY
    incoming_key = request.headers.get("x-api-key") or request.headers.get("X-API-KEY")
    
    print(f"--- HEADERS RECEIVED: {request.headers} ---")
    
    if incoming_key != API_KEY:
        print(f"Auth Failed. Received: {incoming_key}")
        return JSONResponse(status_code=401, content={"status": "error", "message": "Invalid API Key"})

    # 2. READ BODY SAFELY
    try:
        raw_body = await request.body()
        body_str = raw_body.decode("utf-8")
        if not body_str:
            data = {}
        else:
            data = json.loads(body_str)
    except Exception as e:
        print(f"JSON Parse Error: {e}")
        data = {"message": {"text": "invalid_json_received"}}

    print(f"--- BODY RECEIVED: {data} ---")

    # 3. EXTRACT DATA
    session_id = data.get("sessionId", "unknown_session")
    
    msg_obj = data.get("message")
    text = ""
    if isinstance(msg_obj, dict):
        text = msg_obj.get("text", "")
    elif isinstance(msg_obj, str):
        text = msg_obj
    
    # 4. BASIC LOGIC & INTELLIGENCE
    if session_id not in SESSION_STORE:
        SESSION_STORE[session_id] = {
            "count": 0,
            "scam": False,
            "intel": {"upi": set(), "phone": set(), "link": set()}
        }
    
    session = SESSION_STORE[session_id]
    session["count"] += 1
    
    session["intel"]["upi"].update(UPI_PATTERN.findall(text))
    session["intel"]["phone"].update(PHONE_PATTERN.findall(text))
    if LINK_PATTERN.search(text):
        session["intel"]["link"].add(text)
    
    if any(k in text.lower() for k in SCAM_KEYWORDS):
        session["scam"] = True

    # 5. GENERATE REPLY
    reply = "I am a bit confused. Could you explain?"
    if "bank" in text.lower():
        reply = "Which bank account is this?"
    elif "verify" in text.lower():
        reply = "I don't know how to verify."

    # 6. RETURN SUCCESS
    response = {
        "status": "success",
        "reply": reply
    }
    
    print(f"--- SENDING RESPONSE: {response} ---")
    return response

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)