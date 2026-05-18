"""
main.py — Argus FastAPI backend.

Endpoints:
  POST /api/login                  — session auth
  POST /api/logout
  GET  /api/health                 — sanity check, shows live state counts
  POST /api/agent/investigate      — Splunk webhook target
  POST /api/agent/reinvestigate/{alert_id} — UI re-run on existing alert
  GET  /api/alerts                 — list all received alerts (AlertFeed)
  GET  /api/incidents              — list all completed incident reports
  GET  /api/incidents/{id}         — get one incident report
  WS   /ws/incidents               — real-time agent step stream

Run:
  uvicorn main:app --reload --port 8001
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
# ---------------------------------------------------------------------------

DEMO_PASSWORD: str = os.environ.get("DEMO_PASSWORD", "argus2026")

sessions:       dict[str, str]      = {}  # session_token → username
pending_alerts: dict[str, dict]     = {}  # alert_id → SplunkAlert.model_dump()
incidents:      dict[str, dict]     = {}  # incident_id → IncidentReport dict
ws_clients:     dict[str, WebSocket] = {}  # client_id → WebSocket


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
# This is called by Splunk (or your test curl). Always a new alert.
# ---------------------------------------------------------------------------

@app.post("/api/agent/investigate")
async def receive_alert(
    request: Request,
    background_tasks: BackgroundTasks,
) -> dict:
    """
    Splunk webhook target. Called by Splunk when a saved search fires.
    Every call = a new alert with a new alert_id.
    """
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

    # Broadcast the new alert to the UI immediately
    await broadcast({
        "type":  "new_alert",
        "alert": alert.model_dump(),
    })

    # Run the agent in the background
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
# UI re-investigate — POST /api/agent/reinvestigate/{alert_id}
# Called by the Investigate button in AlertFeed. No new alert created.
# ---------------------------------------------------------------------------

@app.post("/api/agent/reinvestigate/{alert_id}")
async def reinvestigate(
    alert_id: str,
    background_tasks: BackgroundTasks,
    session: str | None = Cookie(default=None),
) -> dict:
    """
    Re-run the agent on an already-stored alert.
    Does NOT create a new alert or broadcast new_alert.
    Called by the UI Investigate button.
    """
    require_auth(session)
    if alert_id not in pending_alerts:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert {alert_id} not found",
        )

    log.info("Re-investigating alert: %s", alert_id)
    background_tasks.add_task(run_agent, alert_id, pending_alerts, incidents, broadcast)
    return {"status": "queued", "alert_id": alert_id}


@app.delete("/api/alerts/{alert_id}")
async def delete_alert(
    alert_id: str,
    session: str | None = Cookie(default=None),
) -> dict:
    require_auth(session)
    if alert_id not in pending_alerts:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    pending_alerts.pop(alert_id, None)
    return {"status": "deleted", "alert_id": alert_id}

# ---------------------------------------------------------------------------
# Alerts & Incidents REST endpoints
# ---------------------------------------------------------------------------

@app.get("/api/alerts")
async def list_alerts(
    session: str | None = Cookie(default=None),
) -> dict:
    require_auth(session)
    return {
        "alerts": list(pending_alerts.values()),
        "count":  len(pending_alerts),
    }


@app.get("/api/incidents")
async def list_incidents(
    session: str | None = Cookie(default=None),
) -> dict:
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

    await websocket.send_json({"type": "ping", "client_id": client_id})

    try:
        while True:
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
    port = int(os.environ.get("BACKEND_PORT", 8001))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)