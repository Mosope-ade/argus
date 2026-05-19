"""
agent.py — The Argus LLM-driven planner loop.

This is the core of the project. Everything else supports this.

Flow:
  1. Receive alert_id
  2. Load alert from pending_alerts
  3. Initialize investigation state
  4. Loop (max MAX_ITERATIONS):
       a. LLM chooses next action
       b. Stream "plan" step to WebSocket clients
       c. Execute the chosen tool against Splunk
       d. Stream "result" step to WebSocket clients
       e. Append result to state["findings"]
       f. If action == "generate_report", break
  5. LLM generates final IncidentReport from full state
  6. Store report in incidents dict
  7. Stream "done" event to WebSocket clients

The LLM drives the investigation path — it is not predetermined.
Different alert types produce different investigation sequences.
"""

from __future__ import annotations

import asyncio
import logging
import os
import uuid
from datetime import datetime

from llm_provider import get_llm_provider, LLMProvider, _parse_json
from models import AgentStep, IncidentReport
from prompts import build_planner_prompt, build_reporter_prompt
from splunk_client import SplunkClient
from tools import execute_tool, TOOL_REGISTRY

log = logging.getLogger("argus.agent")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MAX_ITERATIONS: int = int(os.environ.get("MAX_AGENT_ITERATIONS", "3"))

# All actions the planner can choose from.
# "generate_report" is the terminal action — breaks the loop.
# "fetch_alert_data" is always executed first before the LLM loop starts.
AVAILABLE_ACTIONS: list[str] = [
    "check_login_success",
    "expand_to_network_logs",
    "check_process_execution",
    "check_lateral_movement",
    "correlate_ioc",
    "check_outbound_connections",
    "build_timeline",
    "generate_report",
]


# ---------------------------------------------------------------------------
# Agent runner
# ---------------------------------------------------------------------------

class ArgusAgent:
    """
    Stateless agent class. One instance per investigation.
    Created fresh for each alert — no shared state between runs.
    """

    def __init__(
        self,
        alert: dict,
        broadcast_fn,          # async callable(dict) — sends to WebSocket clients
        incidents_store: dict, # shared dict to write the completed report into
    ) -> None:
        self.alert          = alert
        self.alert_id       = alert.get("alert_id", "UNKNOWN")
        self.broadcast      = broadcast_fn
        self.incidents      = incidents_store
        self.llm: LLMProvider   = get_llm_provider()
        self.splunk: SplunkClient = SplunkClient()

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def run(self) -> str:
        """
        Run the full investigation loop.

        Returns:
            incident_id of the completed report.
        """
        alert_id = self.alert.get("alert_id", "UNKNOWN")
        log.info("=== ARGUS INVESTIGATION STARTED: %s ===", alert_id)

        # Initialize investigation state
        state: dict = {
            "alert":        self.alert,
            "findings":     [],
            "actions_taken": [],
            "iteration":    0,
        }

        # ---------------------------------------------------------------
        # Step 0: Always fetch the raw alert data first.
        # This gives the LLM concrete evidence to reason about from
        # iteration 1 — avoids wasting a planning step on uncertainty.
        # ---------------------------------------------------------------
        log.info("Step 0: fetch_alert_data (always first)")
        await self._stream_plan(
            action="fetch_alert_data",
            reasoning="Always fetch the raw alert events first to give the planner concrete data.",
            iteration=0,
        )

        init_result = await execute_tool("fetch_alert_data", state, self.splunk)
        state["findings"].append(init_result)
        state["actions_taken"].append("fetch_alert_data")

        await self._stream_result(
            action="fetch_alert_data",
            data={"event_count": init_result.get("count", 0)},
            iteration=0,
        )

        # ---------------------------------------------------------------
        # Main planner loop
        # ---------------------------------------------------------------
        while state["iteration"] < MAX_ITERATIONS:
            state["iteration"] += 1
            iteration = state["iteration"]

            remaining_actions = [
                a for a in AVAILABLE_ACTIONS
                if a not in state["actions_taken"]
            ]

            if not remaining_actions:
                log.info("No remaining actions — breaking loop")
                break

            # ---- LLM chooses next action ----
            try:
                system_prompt, user_prompt = build_planner_prompt(
                    state, remaining_actions
                )
                decision = await self._plan(system_prompt, user_prompt)
            except Exception as exc:
                log.error("Planner LLM call failed: %s", exc)
                await self._stream_error(f"Planner failed: {exc}")
                break

            action    = decision.get("action", "")
            reasoning = decision.get("reasoning", "")

            log.info(
                "[iter %d] LLM chose: %s — %s",
                iteration, action, reasoning,
            )

            # Validate the action — LLM occasionally hallucinates action names
            if action not in AVAILABLE_ACTIONS and action != "generate_report":
                log.warning(
                    "LLM returned unknown action '%s' — defaulting to build_timeline",
                    action,
                )
                action    = "build_timeline"
                reasoning = "Corrected invalid action — building timeline with current findings."

            # Stream the plan step to the UI
            await self._stream_plan(
                action=action,
                reasoning=reasoning,
                iteration=iteration,
            )

            state["actions_taken"].append(action)

            # ---- Terminal action: generate_report ----
            if action == "generate_report":
                log.info("[iter %d] Terminal action — generating report", iteration)
                break

            # ---- Execute the chosen tool ----
            result = await execute_tool(action, state, self.splunk)
            state["findings"].append(result)

            # Stream the result step to the UI
            await self._stream_result(
                action=action,
                data=self._summarise_result(result),
                iteration=iteration,
            )

        # ---------------------------------------------------------------
        # Ensure build_timeline ran before generating the report
        # ---------------------------------------------------------------
        if "build_timeline" not in state["actions_taken"]:
            log.info("Running build_timeline before report generation")
            timeline_result = await execute_tool("build_timeline", state, self.splunk)
            state["findings"].append(timeline_result)
            state["actions_taken"].append("build_timeline")

        # ---------------------------------------------------------------
        # Generate the final incident report
        # ---------------------------------------------------------------
        log.info("Generating final incident report...")
        try:
            system_prompt, user_prompt = build_reporter_prompt(state)
            report_dict = await self._generate_report(system_prompt, user_prompt)
        except Exception as exc:
            log.error("Report generation failed: %s", exc)
            await self._stream_error(f"Report generation failed: {exc}")
            report_dict = self._fallback_report(state)

        # Stamp the report with agent metadata
        incident_id = f"INC-{str(uuid.uuid4())[:6].upper()}"
        report_dict["incident_id"]      = incident_id
        report_dict["alert_id"]         = alert_id
        report_dict["agent_iterations"] = state["iteration"]
        report_dict["actions_taken"]    = state["actions_taken"]

        # Validate against Pydantic schema — fixes type issues silently
        try:
            validated = IncidentReport(**report_dict)
            final_report = validated.model_dump()
        except Exception as exc:
            log.warning("Report validation warning (using raw dict): %s", exc)
            final_report = report_dict

        # Store in shared incidents dict so REST endpoints can serve it
        self.incidents[incident_id] = final_report

        log.info(
            "=== INVESTIGATION COMPLETE: %s → %s (severity=%s) ===",
            alert_id, incident_id, final_report.get("severity", "UNKNOWN"),
        )

        # Stream the done event with the full report
        await self.broadcast({
            "type":        "done",
            "alert_id":    self.alert_id,
            "incident_id": incident_id,
            "report":      final_report,
        })

        return incident_id

    # ------------------------------------------------------------------
    # LLM calls
    # ------------------------------------------------------------------

    async def _plan(self, system: str, user: str) -> dict:
        provider = self.llm

        for attempt in range(2):
            try:
                if hasattr(provider, "_call"):
                    raw = await provider._call(system, user)
                    if not raw or not raw.strip():
                        raise ValueError("LLM returned empty response")
                    return _parse_json(raw)
                else:
                    raise AttributeError("LLM provider has no _call method")
            except Exception as exc:
                if attempt == 0:
                    log.warning(
                        "Planner attempt 1 failed (%s: %s) — retrying",
                        type(exc).__name__, exc,
                    )
                    await asyncio.sleep(1)
                else:
                    log.error(
                        "Planner failed after 2 attempts (%s: %s)",
                        type(exc).__name__, exc,
                        exc_info=True,
                    )
                    raise

    async def _generate_report(self, system: str, user: str) -> dict:
        provider = self.llm
        if hasattr(provider, "_call"):
            raw = await provider._call(system, user)
            if not raw or not raw.strip():
                raise ValueError("LLM returned empty response for report generation")
            return _parse_json(raw)
        else:
            raise RuntimeError("LLM provider does not expose _call method")

    # ------------------------------------------------------------------
    # WebSocket streaming helpers
    # ------------------------------------------------------------------

    async def _stream_plan(
        self, action: str, reasoning: str, iteration: int
    ) -> None:
        await self.broadcast({
            "type":      "plan",
            "alert_id":  self.alert_id,
            "action":    action,
            "reasoning": reasoning,
            "iteration": iteration,
            "timestamp": datetime.utcnow().isoformat(),
        })

    async def _stream_result(
        self, action: str, data: dict, iteration: int
    ) -> None:
        await self.broadcast({
            "type":      "result",
            "alert_id":  self.alert_id,
            "action":    action,
            "data":      data,
            "iteration": iteration,
            "timestamp": datetime.utcnow().isoformat(),
        })

    async def _stream_error(self, message: str) -> None:
        await self.broadcast({
            "type":      "error",
            "message":   message,
            "timestamp": datetime.utcnow().isoformat(),
        })

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _summarise_result(self, result: dict) -> dict:
        """
        Extract a concise summary from a tool result for the UI.
        The full result is in state["findings"] — this is just for display.
        """
        tool = result.get("tool", "")

        if tool == "check_login_success":
            if result.get("success"):
                return {
                    "summary": f"Successful login found: user='{result.get('user')}' at {result.get('login_time')}",
                    "success": True,
                }
            return {"summary": "No successful logins found", "success": False}

        if tool == "expand_to_network_logs":
            return {
                "summary": f"{len(result.get('connections', []))} unique network connections found",
                "connection_count": len(result.get("connections", [])),
            }

        if tool == "check_process_execution":
            cmds = [c.get("command", "") for c in result.get("commands", [])[:5]]
            return {
                "summary": f"{result.get('count', 0)} commands found",
                "commands": cmds,
            }

        if tool == "check_lateral_movement":
            moved = result.get("moved", False)
            count = result.get("count", 0)
            return {
                "summary": f"Lateral movement {'detected' if moved else 'not detected'} — {count} events",
                "moved": moved,
            }

        if tool == "correlate_ioc":
            hit = result.get("hit", False)
            matches = result.get("matches", [])
            return {
                "summary": f"{'IOC MATCH' if hit else 'No IOC matches'} — checked {len(result.get('checked', []))} indicators",
                "hit": hit,
                "matches": [m.get("ioc") for m in matches],
            }

        if tool == "check_outbound_connections":
            return {
                "summary": f"{len(result.get('outbound', []))} outbound connections, {len(result.get('suspicious', []))} suspicious",
                "has_c2": result.get("has_c2_indicators", False),
            }

        if tool == "build_timeline":
            return {
                "summary": f"Timeline built: {result.get('event_count', 0)} events, {len(result.get('mitre_mapping', []))} MITRE techniques",
                "event_count": result.get("event_count", 0),
            }

        return {"summary": f"Tool {tool} completed", "count": result.get("count", 0)}

    def _fallback_report(self, state: dict) -> dict:
        """
        Minimal valid report used when LLM report generation fails.
        Ensures the investigation always produces a usable output.
        """
        alert = state.get("alert", {})

        # Pull timeline from findings if build_timeline ran
        timeline = []
        mitre_mapping = []
        ioc_matches = []
        for finding in state.get("findings", []):
            if finding.get("tool") == "build_timeline":
                timeline      = finding.get("timeline", [])
                mitre_mapping = finding.get("mitre_mapping", [])
            if finding.get("tool") == "correlate_ioc":
                ioc_matches = finding.get("matches", [])

        return {
            "incident_id":          "INC-FALLBACK",
            "alert_id":             alert.get("alert_id", ""),
            "timestamp":            datetime.utcnow().isoformat(),
            "severity":             "HIGH",
            "attack_type":          alert.get("search_name", "Unknown"),
            "summary":              (
                f"Automated investigation of alert '{alert.get('search_name')}' "
                f"from source {alert.get('src_ip')} against host {alert.get('host')}. "
                "LLM report generation failed — manual review required."
            ),
            "timeline":             timeline,
            "affected_systems":     [alert.get("host", "")] if alert.get("host") else [],
            "compromised_accounts": [],
            "mitre_mapping":        mitre_mapping,
            "ioc_matches":          ioc_matches,
            "recommendations":      [
                "Manual investigation required — automated report generation failed.",
                f"Review Splunk logs for source IP: {alert.get('src_ip', 'unknown')}",
                f"Review host: {alert.get('host', 'unknown')}",
            ],
            "agent_iterations":     state.get("iteration", 0),
            "actions_taken":        state.get("actions_taken", []),
        }


# ---------------------------------------------------------------------------
# Top-level runner — called from main.py as a background task
# ---------------------------------------------------------------------------

async def run_agent(
    alert_id: str,
    pending_alerts: dict,
    incidents: dict,
    broadcast_fn,
) -> None:
    """
    Entry point called by main.py as a FastAPI BackgroundTask.

    Args:
        alert_id:      ID of the alert to investigate
        pending_alerts: Shared dict of received alerts
        incidents:     Shared dict to write the completed report into
        broadcast_fn:  Async function to push WebSocket messages
    """
    alert = pending_alerts.get(alert_id)
    if not alert:
        log.error("run_agent: alert_id %s not found in pending_alerts", alert_id)
        await broadcast_fn({
            "type":    "error",
            "message": f"Alert {alert_id} not found",
        })
        return

    agent = ArgusAgent(
        alert=alert,
        broadcast_fn=broadcast_fn,
        incidents_store=incidents,
    )

    try:
        incident_id = await agent.run()
        log.info("run_agent complete: %s → %s", alert_id, incident_id)
    except Exception as exc:
        log.exception("run_agent crashed for alert %s: %s", alert_id, exc)
        await broadcast_fn({
            "type":    "error",
            "message": f"Investigation failed for {alert_id}: {exc}",
        })