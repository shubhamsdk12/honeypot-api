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

# ================= ROOT LISTENER (KEEPS TESTER HAPPY) =================
@app.get("/")
async def root():
    return {"status": "online", "message": "Honeypot is running"}

@app.head("/")
async def root_head():
    return {"status": "online"}

# ================= MAIN ENDPOINT (NO VALIDATION RULES) =================
@app.post("/honeypot")
async def honeypot(request: Request):
    """
    Accepts ANY request. 
    No Pydantic models. 
    No Header arguments.
    Manual parsing only.
    """
    
    # 1. READ HEADERS MANUALLY
    # We look for the key in both lowercase and standard format
    incoming_key = request.headers.get("x-api-key") or request.headers.get("X-API-KEY")
    
    print(f"--- HEADERS RECEIVED: {request.headers} ---")
    
    if incoming_key != API_KEY:
        print(f"Auth Failed. Received: {incoming_key}")
        # Return 401 JSON (Not HTTPException, to avoid HTML error pages)
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
        # If JSON fails, we create a dummy body so the server doesn't crash
        data = {"message": {"text": "invalid_json_received"}}

    print(f"--- BODY RECEIVED: {data} ---")

    # 3. EXTRACT DATA (Use .get() to prevent crashes)
    session_id = data.get("sessionId", "unknown_session")
    
    # Handle message format (String vs Object)
    msg_obj = data.get("message")
    text = ""
    if isinstance(msg_obj, dict):
        text = msg_obj.get("text", "")
    elif isinstance(msg_obj, str):
        text = msg_obj
    
    # 4. BASIC LOGIC & INTELLIGENCE
    # (Simplified for stability, but keeps tracking)
    if session_id not in SESSION_STORE:
        SESSION_STORE[session_id] = {
            "count": 0,
            "scam": False,
            "intel": {"upi": set(), "phone": set(), "link": set()}
        }
    
    session = SESSION_STORE[session_id]
    session["count"] += 1
    
    # Update Intel
    session["intel"]["upi"].update(UPI_PATTERN.findall(text))
    session["intel"]["phone"].update(PHONE_PATTERN.findall(text))
    if LINK_PATTERN.search(text):
        session["intel"]["link"].add(text)
    
    # Check Scam
    if any(k in text.lower() for k in SCAM_KEYWORDS):
        session["scam"] = True

    # 5. GENERATE REPLY
    reply = "I am a bit confused. Could you explain?"
    if "bank" in text.lower():
        reply = "Which bank account is this?"
    elif "verify" in text.lower():
        reply = "I don't know how to verify."

    # 6. RETURN SUCCESS (Always 200 OK)
    response = {
        "status": "success",
        "reply": reply
    }
    
    print(f"--- SENDING RESPONSE: {response} ---")
    return response

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)