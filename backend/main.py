"""
main.py — Argus FastAPI backend.

Endpoints:
  POST /api/login                  — session auth
  POST /api/logout
  GET  /api/health                 — sanity check, shows live state counts
  POST /api/agent/investigate      — Splunk webhook target
  GET  /api/alerts                 — list all received alerts (AlertFeed)
  GET  /api/incidents              — list all completed incident reports
  GET  /api/incidents/{id}         — get one incident report
  WS   /ws/incidents               — real-time agent step stream

Run:
  uvicorn main:app --reload --port 8000
"""

from __future__ import annotations

from agent import run_agent
import json
import logging
import os
import uuid
from datetime import datetime
from typing import Any

from dotenv import load_dotenv

load_dotenv()  # must happen before any os.environ reads

from fastapi import (
    BackgroundTasks,
    Cookie,
    FastAPI,
    HTTPException,
    Request,
    Response,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.middleware.cors import CORSMiddleware

from models import LoginRequest, LoginResponse, SplunkAlert

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
log = logging.getLogger("argus.main")

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Argus — Agentic Incident Responder",
    version="1.0.0",
)

CORS_ORIGIN = os.environ.get("CORS_ORIGIN", "http://localhost:5173")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[CORS_ORIGIN],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# In-memory state
# Phase 1: no database. Agent writes to these dicts in Phase 2.
# ---------------------------------------------------------------------------

DEMO_PASSWORD: str = os.environ.get("DEMO_PASSWORD", "argus2026")

sessions:      dict[str, str]  = {}   # session_token → username
pending_alerts: dict[str, dict] = {}  # alert_id → SplunkAlert.model_dump()
incidents:     dict[str, dict]  = {}  # incident_id → IncidentReport dict
ws_clients:    dict[str, WebSocket] = {}  # client_id → WebSocket


# ---------------------------------------------------------------------------
# Auth helper
# ---------------------------------------------------------------------------

def require_auth(session: str | None) -> str:
    """Raise 401 if session is missing or invalid. Returns username."""
    if not session or session not in sessions:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    return sessions[session]


# ---------------------------------------------------------------------------
# WebSocket broadcast helper
# Called by agent loop in Phase 2, and by webhook in Phase 1
# ---------------------------------------------------------------------------

async def broadcast(message: dict) -> None:
    """Push a message to every connected WebSocket client."""
    dead: list[str] = []
    for client_id, ws in ws_clients.items():
        try:
            await ws.send_json(message)
        except Exception:
            dead.append(client_id)
    for client_id in dead:
        ws_clients.pop(client_id, None)
        log.info("Removed dead WebSocket client: %s", client_id)


# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------

@app.post("/api/login", response_model=LoginResponse)
async def login(credentials: LoginRequest, response: Response) -> LoginResponse:
    if credentials.password != DEMO_PASSWORD:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid password",
        )
    token = str(uuid.uuid4())
    sessions[token] = "analyst"
    response.set_cookie(
        key="session",
        value=token,
        httponly=True,
        samesite="strict",
        # secure=True  ← enable in production behind HTTPS
    )
    log.info("Login successful — session %s…", token[:8])
    return LoginResponse(status="authenticated", username="analyst")


@app.post("/api/logout")
async def logout(
    response: Response,
    session: str | None = Cookie(default=None),
) -> dict:
    if session:
        sessions.pop(session, None)
    response.delete_cookie("session")
    return {"status": "logged out"}


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/api/health")
async def health() -> dict:
    return {
        "status":          "ok",
        "service":         "argus",
        "timestamp":       datetime.utcnow().isoformat(),
        "active_sessions": len(sessions),
        "pending_alerts":  len(pending_alerts),
        "incidents":       len(incidents),
        "ws_clients":      len(ws_clients),
    }

@app.get("/")
def root():
    return {"status": "Argus backend running 🚀"}

# ---------------------------------------------------------------------------
# Splunk webhook — POST /api/agent/investigate
#
# Phase 1 behaviour:
#   1. Parse payload
#   2. Normalise into SplunkAlert
#   3. Store in pending_alerts
#   4. Broadcast new_alert event to WebSocket clients
#   5. Return 200
#
# Phase 2 will add:
#   background_tasks.add_task(run_agent, alert.alert_id)
# ---------------------------------------------------------------------------

@app.post("/api/agent/investigate")
async def receive_alert(
    request: Request,
    background_tasks: BackgroundTasks,
) -> dict:
    """
    Splunk webhook target.

    Splunk fires this when a saved search alert triggers.
    Configure in Splunk: Settings → Searches → [alert] → Edit Alert Actions → Webhook
    URL: http://<your-host>:8000/api/agent/investigate
    """

    # Read raw bytes first — never lose data on parse failure
    raw: bytes = await request.body()

    try:
        body: dict[str, Any] = json.loads(raw)
    except json.JSONDecodeError:
        log.warning("Non-JSON webhook payload received: %s", raw[:300])
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Request body must be valid JSON",
        )

    log.info("=== SPLUNK WEBHOOK RECEIVED ===")
    log.info(json.dumps(body, indent=2, default=str))

    # Splunk webhook body structure:
    #   body["result"]        — first matching event from the search
    #   body["sid"]           — search job ID
    #   body["search_name"]   — name of the saved search that fired
    #   body["result_count"]  — number of matching events

    result: dict = body.get("result", {})

    alert_payload = {
        "alert_id":     f"ALERT-{str(uuid.uuid4())[:8].upper()}",
        "search_name":  body.get("search_name", "Unknown Search"),
        "search_id":    body.get("sid", ""),
        "result_count": int(body.get("result_count", 0)),
        "src_ip":       result.get("src_ip") or result.get("src") or None,
        "host":         result.get("host") or None,
        "timestamp":    datetime.utcnow().isoformat(),
        "raw_result":   result,
    }

    try:
        alert = SplunkAlert(**alert_payload)
    except Exception as exc:
        log.error("SplunkAlert validation error: %s — using minimal model", exc)
        alert = SplunkAlert(
            alert_id=alert_payload["alert_id"],
            search_name=alert_payload["search_name"],
            search_id=alert_payload["search_id"],
        )

    pending_alerts[alert.alert_id] = alert.model_dump()

    log.info(
        "Alert stored → id=%s  search=%s  src_ip=%s  host=%s",
        alert.alert_id, alert.search_name, alert.src_ip, alert.host,
    )

    # Notify all connected frontend clients immediately
    await broadcast({
        "type":  "new_alert",
        "alert": alert.model_dump(),
    })

    from agent import run_agent

    background_tasks.add_task(
        run_agent,
        alert.alert_id,
        pending_alerts,
        incidents,
        broadcast,
    )

    return {
        "status":   "received",
        "alert_id": alert.alert_id,
        "message":  "Alert queued for investigation",
    }


# ---------------------------------------------------------------------------
# Alerts & Incidents REST endpoints
# ---------------------------------------------------------------------------

@app.get("/api/alerts")
async def list_alerts(
    session: str | None = Cookie(default=None),
) -> dict:
    """All pending alerts — feeds the AlertFeed component."""
    require_auth(session)
    return {
        "alerts": list(pending_alerts.values()),
        "count":  len(pending_alerts),
    }


@app.get("/api/incidents")
async def list_incidents(
    session: str | None = Cookie(default=None),
) -> dict:
    """All completed incident reports."""
    require_auth(session)
    return {
        "incidents": list(incidents.values()),
        "count":     len(incidents),
    }


@app.get("/api/incidents/{incident_id}")
async def get_incident(
    incident_id: str,
    session: str | None = Cookie(default=None),
) -> dict:
    """Single incident report by ID."""
    require_auth(session)
    report = incidents.get(incident_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )
    return report


# ---------------------------------------------------------------------------
# WebSocket — /ws/incidents
#
# Phase 1: connects, assigns a client ID, sends a ping, stays alive.
# Phase 2: broadcast() is called by the agent loop after every step.
#
# Message types sent to clients:
#   {"type": "ping"}
#   {"type": "new_alert",  "alert": {...}}
#   {"type": "plan",       "action": "...", "reasoning": "...", "iteration": N}
#   {"type": "result",     "action": "...", "data": {...},      "iteration": N}
#   {"type": "done",       "incident_id": "...", "report": {...}}
#   {"type": "error",      "message": "..."}
# ---------------------------------------------------------------------------

@app.websocket("/ws/incidents")
async def ws_incidents(websocket: WebSocket) -> None:
    await websocket.accept()

    client_id = str(uuid.uuid4())[:8]
    ws_clients[client_id] = websocket

    log.info(
        "WebSocket connected: client=%s  total_clients=%d",
        client_id, len(ws_clients),
    )

    # Welcome ping so client confirms the connection is live
    await websocket.send_json({"type": "ping", "client_id": client_id})

    try:
        while True:
            # Keep-alive: client sends "ping", we reply "pong"
            msg = await websocket.receive_text()
            if msg.strip() == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        log.info("WebSocket disconnected: client=%s", client_id)
    finally:
        ws_clients.pop(client_id, None)


# ---------------------------------------------------------------------------
# Dev entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("BACKEND_PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)