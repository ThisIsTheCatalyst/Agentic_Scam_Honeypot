"""
Honeypot API backend.
Uses Redis for session state.
Requires REDIS_URL environment variable.
"""

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
import requests
import os
import logging
from typing import List, Dict, Optional

from session_store import get_session, save_session
from agent.agent import agent_step

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ----------------------------
# Required Environment Variables
# ----------------------------
API_KEY = os.getenv("API_KEY", "dev_key")
REDIS_URL = os.getenv("REDIS_URL")

if not REDIS_URL:
    raise ValueError("REDIS_URL environment variable is required")

CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

app = FastAPI(title="Agentic Honeypot API", version="1.0")


# ----------------------------
# Request/Response models (per spec)
# ----------------------------
class Message(BaseModel):
    sender: str
    text: str
    timestamp: int


class HoneypotRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: Optional[List[dict]] = None
    metadata: Optional[Dict] = None


# ----------------------------
# Health check
# ----------------------------
@app.get("/")
def health():
    return {"status": "backend running"}


# ----------------------------
# Honeypot API
# ----------------------------
@app.post("/api/honeypot")
def honeypot(
    body: HoneypotRequest,
    x_api_key: Optional[str] = Header(None, alias="x-api-key"),
):
    # 1. API Authentication
    if not x_api_key or x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    session_id = body.sessionId
    incoming_text = body.message.text

    # 2. Load or create session (Redis)
    session = get_session(session_id)

    # 3. Run agent step
    agent_output = agent_step(session, incoming_text)

    # 4. Persist updated session
    save_session(session_id, session)

    # 5. Mandatory final result callback (once per session)
    if agent_output["should_finalize"] and not session.get("finalized", False):
        session["finalized"] = True
        save_session(session_id, session)

        intelligence = session.get("intelligence", {})
        payload = {
            "sessionId": session_id,
            "scamDetected": session.get("scam_detected", True),
            "totalMessagesExchanged": len(session.get("messages", [])),
            "extractedIntelligence": {
                "bankAccounts": intelligence.get("bankAccounts", []),
                "upiIds": intelligence.get("upiIds", []),
                "phishingLinks": intelligence.get("phishingLinks", []),
                "phoneNumbers": intelligence.get("phoneNumbers", []),
                "suspiciousKeywords": intelligence.get("suspiciousKeywords", []),
            },
            "agentNotes": agent_output["agent_notes"],
        }

        try:
            requests.post(CALLBACK_URL, json=payload, timeout=5)
            logger.info("Final result callback sent for session %s", session_id)
        except Exception as e:
            logger.error("Callback failed: %s", e)

    # 6. Agent output (per spec)
    return {
        "status": "success",
        "reply": agent_output["reply"],
    }


# ----------------------------
# Run locally
# ----------------------------
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
