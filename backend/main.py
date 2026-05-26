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
import time
import uuid
from datetime import datetime
from typing import Any

from dotenv import load_dotenv

load_dotenv()

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
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type"],
)

# ---------------------------------------------------------------------------
# In-memory state
# ---------------------------------------------------------------------------

WEBHOOK_SECRET: str | None = os.environ.get("WEBHOOK_SECRET")
SECURE_COOKIES: bool       = os.environ.get("SECURE_COOKIES", "false").lower() == "true"

# Caps to prevent unbounded memory growth under high alert load
MAX_PENDING_ALERTS: int = int(os.environ.get("MAX_PENDING_ALERTS", "500"))
MAX_INCIDENTS:      int = int(os.environ.get("MAX_INCIDENTS", "1000"))

_raw_pw = os.environ.get("PASSWORD", "")
if not _raw_pw:
    raise RuntimeError(
        "PASSWORD is not set. Set PASSWORD in your .env file before starting Argus."
    )
PASSWORD: str = _raw_pw

if not WEBHOOK_SECRET:
    log.error(
        "\n%s\n  ARGUS: WEBHOOK_SECRET is not set — "
        "/api/agent/investigate is open to anyone.\n"
        "  Set WEBHOOK_SECRET in .env before exposing this service.\n%s",
        "=" * 60, "=" * 60,
    )

# Session TTL
SESSION_TTL: int = 86_400  # 24 hours

# sessions: token → {"username": str, "expires_at": float}
sessions:       dict[str, dict]      = {}
pending_alerts: dict[str, dict]      = {}
incidents:      dict[str, dict]      = {}
ws_clients:     dict[str, WebSocket] = {}

# Login rate limiting: IP → list of failure timestamps
_login_failures: dict[str, list[float]] = {}
_RATE_WINDOW = 300  # 5 minutes
_RATE_MAX    = 5    # max failures before lockout


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def require_auth(session: str | None) -> str:
    """Raise 401 if session is missing, invalid, or expired. Returns username."""
    now = time.time()
    entry = sessions.get(session or "")
    if not entry:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    if now > entry["expires_at"]:
        sessions.pop(session, None)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired")
    return entry["username"]


def _check_rate_limit(ip: str) -> None:
    now = time.time()
    recent = [t for t in _login_failures.get(ip, []) if now - t < _RATE_WINDOW]
    _login_failures[ip] = recent
    if len(recent) >= _RATE_MAX:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts — try again later.",
        )


def _record_failure(ip: str) -> None:
    _login_failures.setdefault(ip, []).append(time.time())


# ---------------------------------------------------------------------------
# WebSocket broadcast helper
# ---------------------------------------------------------------------------

async def broadcast(message: dict) -> None:
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
async def login(
    credentials: LoginRequest,
    request: Request,
    response: Response,
) -> LoginResponse:
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)

    if credentials.password != PASSWORD:
        _record_failure(client_ip)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password")

    # Clear failure history on successful login
    _login_failures.pop(client_ip, None)

    token = str(uuid.uuid4())
    sessions[token] = {"username": "analyst", "expires_at": time.time() + SESSION_TTL}

    response.set_cookie(
        key="session",
        value=token,
        httponly=True,
        samesite="strict",
        secure=SECURE_COOKIES,
        max_age=SESSION_TTL,
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
# Health (authenticated)
# ---------------------------------------------------------------------------

@app.get("/api/health")
async def health(session: str | None = Cookie(default=None)) -> dict:
    require_auth(session)
    return {
        "status":          "ok",
        "service":         "argus",
        "timestamp":       datetime.utcnow().isoformat() + "Z",
        "active_sessions": len(sessions),
        "pending_alerts":  len(pending_alerts),
        "incidents":       len(incidents),
        "ws_clients":      len(ws_clients),
    }


@app.get("/")
def root():
    return {"status": "Argus backend running"}


# ---------------------------------------------------------------------------
# Splunk webhook — POST /api/agent/investigate
# ---------------------------------------------------------------------------

@app.post("/api/agent/investigate")
async def receive_alert(
    request: Request,
    background_tasks: BackgroundTasks,
) -> dict:
    if WEBHOOK_SECRET:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or auth[7:] != WEBHOOK_SECRET:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing webhook secret",
            )

    raw: bytes = await request.body()

    try:
        body: dict[str, Any] = json.loads(raw)
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Request body must be valid JSON",
        )

    result: dict = body.get("result", {})

    # Log only safe summary fields — not the full body which may contain sensitive data
    log.info(
        "=== SPLUNK WEBHOOK RECEIVED === search=%r  sid=%r  result_count=%s  src_ip=%s  host=%s",
        body.get("search_name", "—"),
        body.get("sid", "—"),
        body.get("result_count", "—"),
        result.get("src_ip") or result.get("src", "—"),
        result.get("host", "—"),
    )

    alert_payload = {
        "alert_id":     f"ALERT-{str(uuid.uuid4())[:8].upper()}",
        "search_name":  body.get("search_name", "Unknown Search"),
        "search_id":    body.get("sid", ""),
        "result_count": int(body.get("result_count", 0)),
        "src_ip":       result.get("src_ip") or result.get("src") or None,
        "host":         result.get("host") or None,
        "timestamp":    datetime.utcnow().isoformat() + "Z",
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

    # Evict oldest alert if cap is reached
    if len(pending_alerts) >= MAX_PENDING_ALERTS:
        oldest = next(iter(pending_alerts))
        pending_alerts.pop(oldest, None)
        log.warning("MAX_PENDING_ALERTS reached — evicted oldest alert: %s", oldest)

    pending_alerts[alert.alert_id] = alert.model_dump()

    log.info(
        "Alert stored → id=%s  search=%s  src_ip=%s  host=%s",
        alert.alert_id, alert.search_name, alert.src_ip, alert.host,
    )

    await broadcast({"type": "new_alert", "alert": alert.model_dump()})

    # Evict oldest incident if cap is reached
    if len(incidents) >= MAX_INCIDENTS:
        oldest = next(iter(incidents))
        incidents.pop(oldest, None)
        log.warning("MAX_INCIDENTS reached — evicted oldest incident: %s", oldest)

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
# ---------------------------------------------------------------------------

@app.post("/api/agent/reinvestigate/{alert_id}")
async def reinvestigate(
    alert_id: str,
    background_tasks: BackgroundTasks,
    session: str | None = Cookie(default=None),
) -> dict:
    require_auth(session)
    if len(alert_id) > 64:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="alert_id too long")
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
    if len(alert_id) > 64:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="alert_id too long")
    if alert_id not in pending_alerts:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    pending_alerts.pop(alert_id, None)
    return {"status": "deleted", "alert_id": alert_id}


# ---------------------------------------------------------------------------
# Alerts & Incidents REST endpoints
# ---------------------------------------------------------------------------

@app.get("/api/alerts")
async def list_alerts(session: str | None = Cookie(default=None)) -> dict:
    require_auth(session)
    return {"alerts": list(pending_alerts.values()), "count": len(pending_alerts)}


@app.get("/api/incidents")
async def list_incidents(session: str | None = Cookie(default=None)) -> dict:
    require_auth(session)
    return {"incidents": list(incidents.values()), "count": len(incidents)}


@app.get("/api/incidents/{incident_id}")
async def get_incident(
    incident_id: str,
    session: str | None = Cookie(default=None),
) -> dict:
    require_auth(session)
    if len(incident_id) > 64:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="incident_id too long")
    report = incidents.get(incident_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )
    return report


# ---------------------------------------------------------------------------
# WebSocket — /ws/incidents (authenticated)
# ---------------------------------------------------------------------------

@app.websocket("/ws/incidents")
async def ws_incidents(
    websocket: WebSocket,
    session: str | None = Cookie(default=None),
) -> None:
    # Authenticate before accepting the connection
    now = time.time()
    entry = sessions.get(session or "")
    if not entry or now > entry["expires_at"]:
        await websocket.close(code=4401)
        return

    await websocket.accept()

    client_id = str(uuid.uuid4())[:8]
    ws_clients[client_id] = websocket

    log.info(
        "WebSocket connected: client=%s  user=%s  total=%d",
        client_id, entry["username"], len(ws_clients),
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
