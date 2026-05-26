"""
models.py — All Pydantic models for Argus.

Four groups:
  1. SplunkAlert         — inbound webhook payload from Splunk
  2. IncidentReport      — full investigation output (+ sub-models)
  3. AgentStep           — one reasoning step streamed over WebSocket
  4. Auth                — login request / response
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Shared literals
# ---------------------------------------------------------------------------

Severity   = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
Confidence = Literal["HIGH", "MEDIUM", "LOW"]
IOCType    = Literal["ip", "domain", "hash"]


# ---------------------------------------------------------------------------
# 1. Inbound Splunk alert (webhook payload)
# ---------------------------------------------------------------------------

class SplunkAlert(BaseModel):
    """
    Normalised representation of what Splunk POSTs to /api/agent/investigate.

    Splunk's webhook body:
      {
        "sid":          "scheduler__admin__botsv3__RMD5...",
        "search_name":  "SSH Brute Force Detected",
        "result_count": "1",
        "result": {
          "src_ip": "45.142.212.100",
          "host":   "web-server-01",
          "_time":  "2023-09-12T22:01:00"
        }
      }

    extra="allow" so unknown Splunk fields don't cause validation errors.
    """
    model_config = {"extra": "allow"}

    alert_id:     str       = Field(..., description="Generated UUID for this alert")
    search_name:  str       = Field(..., description="Name of the saved search that fired")
    search_id:    str       = Field(default="", description="Splunk search job SID")
    result_count: int       = Field(default=0)
    src_ip:       str | None = Field(default=None, description="Source IP from alert result")
    host:         str | None = Field(default=None, description="Affected host")
    timestamp:    str       = Field(
        default_factory=lambda: datetime.utcnow().isoformat() + "Z"
    )
    raw_result:   dict      = Field(
        default_factory=dict,
        description="Full unmodified Splunk result dict"
    )


# ---------------------------------------------------------------------------
# 2. Incident report sub-models
# ---------------------------------------------------------------------------

class TimelineEvent(BaseModel):
    time:            str = Field(..., description="HH:MM:SS")
    event:           str = Field(..., description="Human-readable description")
    raw_log:         str = Field(default="")
    mitre_tactic:    str = Field(default="")
    mitre_technique: str = Field(default="", description="e.g. T1110.001 — Brute Force")
    source:          str = Field(default="", description="Splunk sourcetype")


class MitreEntry(BaseModel):
    tactic:         str
    technique_id:   str
    technique_name: str


class IOCMatch(BaseModel):
    ioc:        str
    type:       IOCType
    threat:     str
    feeds:      list[str]   = Field(default_factory=list)
    confidence: Confidence


# ---------------------------------------------------------------------------
# 2. Full incident report
# ---------------------------------------------------------------------------

class IncidentReport(BaseModel):
    incident_id:          str
    alert_id:             str
    timestamp:            str      = Field(
        default_factory=lambda: datetime.utcnow().isoformat() + "Z"
    )
    severity:             Severity
    attack_type:          str
    summary:              str      = Field(..., description="One-paragraph plain-language summary")
    timeline:             list[TimelineEvent] = Field(default_factory=list)
    affected_systems:     list[str]           = Field(default_factory=list)
    compromised_accounts: list[str]           = Field(default_factory=list)
    mitre_mapping:        list[MitreEntry]    = Field(default_factory=list)
    ioc_matches:          list[IOCMatch]      = Field(default_factory=list)
    recommendations:      list[str]           = Field(default_factory=list)
    agent_iterations:     int                 = Field(default=0)
    actions_taken:        list[str]           = Field(default_factory=list)


# ---------------------------------------------------------------------------
# 3. Auth
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    password: str


class LoginResponse(BaseModel):
    status:   Literal["authenticated"]
    username: str