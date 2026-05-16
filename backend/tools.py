"""
tools.py — All 7 agent tool implementations.

Every tool:
  - Is async
  - Takes the current investigation state dict + a SplunkClient instance
  - Returns a dict of findings that gets appended to state["findings"]
  - Uses bounded SPL time windows (never unbounded scans)
  - Is read-only — no write operations anywhere

Tools:
  1. fetch_alert_data         — pull the raw alert events from Splunk by SID
  2. check_login_success      — did the brute force work?
  3. expand_to_network_logs   — what network activity happened?
  4. check_process_execution  — what commands were run post-login?
  5. check_lateral_movement   — did the attacker move to other hosts?
  6. correlate_ioc            — are any IPs/domains known malicious?
  7. check_outbound_connections — was data sent out?
  8. build_timeline           — compile all findings chronologically + MITRE map
"""

from __future__ import annotations

import json
import logging
from datetime import datetime

from mitre_map import map_event, get_unique_techniques
from splunk_client import SplunkClient

log = logging.getLogger("argus.tools")


# ---------------------------------------------------------------------------
# IOC intel loader — loaded once at import time
# ---------------------------------------------------------------------------

def _load_ioc_intel() -> dict:
    import os
    intel_path = os.path.join(os.path.dirname(__file__), "ioc_intel.json")
    try:
        with open(intel_path) as f:
            return json.load(f)
    except Exception as exc:
        log.error("Failed to load ioc_intel.json: %s", exc)
        return {"ips": {}, "domains": {}, "hashes": {}}


_IOC_INTEL: dict = _load_ioc_intel()


# ---------------------------------------------------------------------------
# Helper: extract context from state
# ---------------------------------------------------------------------------

def _get_src_ip(state: dict) -> str:
    return (
        state.get("alert", {}).get("src_ip")
        or state.get("alert", {}).get("raw_result", {}).get("src_ip")
        or ""
    )

def _get_host(state: dict) -> str:
    return (
        state.get("alert", {}).get("host")
        or state.get("alert", {}).get("raw_result", {}).get("host")
        or "*"
    )

def _get_time_window(state: dict) -> str:
    """Use the alert timestamp as earliest bound if available."""
    ts = state.get("alert", {}).get("timestamp", "")
    if ts:
        try:
            dt = datetime.fromisoformat(ts)
            # Search from 5 minutes before the alert
            return dt.strftime("%m/%d/%Y:%H:%M:%S")
        except Exception:
            pass
    return "-30m"

def _first_finding(state: dict, key: str):
    """Walk findings list and return first value found for a key."""
    for finding in state.get("findings", []):
        val = finding.get(key)
        if val:
            return val
    return None


# ---------------------------------------------------------------------------
# Tool 1: fetch_alert_data
# ---------------------------------------------------------------------------

async def fetch_alert_data(state: dict, client: SplunkClient) -> dict:
    """
    Pull the events that triggered the alert from Splunk using the search SID.
    Falls back to a broad src_ip query if the SID is unavailable.
    """
    src_ip     = _get_src_ip(state)
    search_id  = state.get("alert", {}).get("search_id", "")
    index      = client.index
    time_window = _get_time_window(state)

    tool_name = "fetch_alert_data"

    if search_id:
        # Try to fetch directly from the Splunk job
        events = await client.fetch_alert_events(search_id, max_results=50)
        if events:
            log.info("[%s] Fetched %d events from SID %s", tool_name, len(events), search_id)
            return {
                "tool":      tool_name,
                "source":    "splunk_job",
                "search_id": search_id,
                "events":    events,
                "count":     len(events),
            }

    # Fallback: query by src_ip
    if src_ip:
        spl = (
            f'index={index} src_ip="{src_ip}" '
            f'earliest="{time_window}" | head 50'
        )
        events = await client.search(spl, max_results=50)
        log.info("[%s] Fallback query returned %d events", tool_name, len(events))
        return {
            "tool":   tool_name,
            "source": "fallback_query",
            "spl":    spl,
            "events": events,
            "count":  len(events),
        }

    log.warning("[%s] No SID and no src_ip — cannot fetch alert data", tool_name)
    return {"tool": tool_name, "events": [], "count": 0, "error": "no_src_ip_or_sid"}


# ---------------------------------------------------------------------------
# Tool 2: check_login_success
# ---------------------------------------------------------------------------

async def check_login_success(state: dict, client: SplunkClient) -> dict:
    """
    Check whether the brute force attempt succeeded.
    Looks for 'Accepted password' or 'Accepted publickey' from the same src_ip.
    """
    src_ip      = _get_src_ip(state)
    index       = client.index
    time_window = _get_time_window(state)
    tool_name   = "check_login_success"

    if not src_ip:
        return {"tool": tool_name, "success": False, "error": "no_src_ip"}

    spl = (
        f'index={index} sourcetype=linux_secure src_ip="{src_ip}" '
        f'("Accepted password" OR "Accepted publickey") '
        f'earliest="{time_window}" | head 20'
    )
    results = await client.search(spl, max_results=20)

    if not results:
        log.info("[%s] No successful logins found for %s", tool_name, src_ip)
        return {
            "tool":    tool_name,
            "success": False,
            "src_ip":  src_ip,
            "count":   0,
        }

    # Extract key fields from the first successful login
    first = results[0]
    user  = first.get("user") or first.get("_raw", "").split("for ")[-1].split(" ")[0]
    time  = first.get("_time", "")

    log.info("[%s] Successful login found: user=%s time=%s", tool_name, user, time)
    return {
        "tool":           tool_name,
        "success":        True,
        "src_ip":         src_ip,
        "user":           user,
        "login_time":     time,
        "count":          len(results),
        "raw_events":     results[:5],  # keep top 5 for context
    }


# ---------------------------------------------------------------------------
# Tool 3: expand_to_network_logs
# ---------------------------------------------------------------------------

async def expand_to_network_logs(state: dict, client: SplunkClient) -> dict:
    """
    Pull network stream events for the affected host around the time of the alert.
    """
    host        = _get_host(state)
    src_ip      = _get_src_ip(state)
    index       = client.index
    time_window = _get_time_window(state)
    tool_name   = "expand_to_network_logs"

    spl = (
        f'index={index} sourcetype="stream:*" '
        f'(host="{host}" OR src_ip="{src_ip}" OR dest_ip="{src_ip}") '
        f'earliest="{time_window}" | head 50'
    )
    results = await client.search(spl, max_results=50)

    # Summarise unique connections
    connections: list[dict] = []
    seen: set[str] = set()
    for row in results:
        src  = row.get("src_ip", "")
        dest = row.get("dest_ip", "")
        port = row.get("dest_port", "")
        key  = f"{src}-{dest}-{port}"
        if key not in seen:
            seen.add(key)
            connections.append({
                "src_ip":    src,
                "dest_ip":   dest,
                "dest_port": port,
                "proto":     row.get("proto", ""),
                "time":      row.get("_time", ""),
            })

    log.info("[%s] Found %d unique network connections", tool_name, len(connections))
    return {
        "tool":        tool_name,
        "host":        host,
        "connections": connections,
        "raw_count":   len(results),
    }


# ---------------------------------------------------------------------------
# Tool 4: check_process_execution
# ---------------------------------------------------------------------------

async def check_process_execution(state: dict, client: SplunkClient) -> dict:
    """
    Look for commands run by the attacker after gaining access.
    Uses the compromised user and login time extracted from check_login_success.
    """
    tool_name = "check_process_execution"

    # Pull context from prior findings
    user       = _first_finding(state, "user")
    login_time = _first_finding(state, "login_time")
    host       = _get_host(state)
    index      = client.index

    if not user:
        # Fall back to a host-scoped search if we don't have a username yet
        time_window = _get_time_window(state)
        spl = (
            f'index={index} sourcetype=linux_secure host="{host}" '
            f'earliest="{time_window}" | head 30'
        )
    else:
        earliest = login_time or _get_time_window(state)
        spl = (
            f'index={index} (sourcetype=linux_secure OR sourcetype=syslog) '
            f'host="{host}" user="{user}" '
            f'earliest="{earliest}" | head 30'
        )

    results = await client.search(spl, max_results=30)

    # Extract command strings from raw log lines
    commands: list[dict] = []
    for row in results:
        raw = row.get("_raw", "")
        cmd = row.get("command") or row.get("process") or ""
        if not cmd:
            # Try to extract from raw log — look for common patterns
            for keyword in ["whoami", "ifconfig", "netstat", "uname", "ps aux",
                            "cat /etc", "ls -", "find /", "wget ", "curl ",
                            "python", "bash", "nc ", "nmap"]:
                if keyword in raw.lower():
                    cmd = keyword
                    break
        if cmd or raw:
            commands.append({
                "time":    row.get("_time", ""),
                "command": cmd,
                "raw":     raw[:200],  # truncate long lines
                "mitre":   map_event(raw) or map_event(cmd),
            })

    log.info("[%s] Found %d command events for user=%s", tool_name, len(commands), user)
    return {
        "tool":     tool_name,
        "user":     user,
        "host":     host,
        "commands": commands,
        "count":    len(commands),
    }


# ---------------------------------------------------------------------------
# Tool 5: check_lateral_movement
# ---------------------------------------------------------------------------

async def check_lateral_movement(state: dict, client: SplunkClient) -> dict:
    """
    Check for movement from the initially compromised host to other internal hosts.
    Looks for SSH connections originating from the affected host to internal IPs.
    """
    tool_name   = "check_lateral_movement"
    host        = _get_host(state)
    user        = _first_finding(state, "user")
    index       = client.index
    time_window = _get_time_window(state)

    spl = (
        f'index={index} '
        f'(sourcetype=linux_secure OR sourcetype="stream:tcp") '
        f'("ssh" OR "scp") '
        f'src_host="{host}" dest_ip!="{_get_src_ip(state)}" '
        f'earliest="{time_window}" | head 20'
    )
    results = await client.search(spl, max_results=20)

    movements: list[dict] = []
    for row in results:
        dest_ip   = row.get("dest_ip", "")
        dest_host = row.get("dest_host", row.get("dest", ""))
        if dest_ip or dest_host:
            movements.append({
                "src_host":  host,
                "dest_ip":   dest_ip,
                "dest_host": dest_host,
                "time":      row.get("_time", ""),
                "raw":       row.get("_raw", "")[:200],
            })

    log.info("[%s] Found %d lateral movement events", tool_name, len(movements))
    return {
        "tool":              tool_name,
        "src_host":          host,
        "lateral_movements": movements,
        "count":             len(movements),
        "moved":             len(movements) > 0,
    }


# ---------------------------------------------------------------------------
# Tool 6: correlate_ioc
# ---------------------------------------------------------------------------

async def correlate_ioc(state: dict, client: SplunkClient) -> dict:
    """
    Check all IPs and domains seen in the investigation against ioc_intel.json.
    Pure dict lookup — instant, no external API, no rate limits.
    """
    tool_name = "correlate_ioc"

    # Collect every IP and domain seen across all findings
    candidates: set[str] = set()

    # Always include the original src_ip
    src_ip = _get_src_ip(state)
    if src_ip:
        candidates.add(src_ip)

    # Walk all findings for any IPs or domains
    for finding in state.get("findings", []):
        # Network connections
        for conn in finding.get("connections", []):
            for field in ("src_ip", "dest_ip"):
                val = conn.get(field, "")
                if val and not val.startswith("10.") and not val.startswith("192.168."):
                    candidates.add(val)

        # Lateral movement destinations
        for move in finding.get("lateral_movements", []):
            val = move.get("dest_ip", "")
            if val:
                candidates.add(val)

        # Raw events — look for IP-like strings
        for event in finding.get("events", []) + finding.get("raw_events", []):
            raw = event.get("_raw", "")
            import re
            for ip in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', raw):
                if not (ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("127.")):
                    candidates.add(ip)

    # Look up each candidate
    matches: list[dict] = []
    checked: list[str]  = []

    for candidate in candidates:
        checked.append(candidate)

        # Check IPs
        if candidate in _IOC_INTEL.get("ips", {}):
            intel = _IOC_INTEL["ips"][candidate]
            matches.append({
                "ioc":        candidate,
                "type":       "ip",
                "threat":     intel["threat"],
                "confidence": intel["confidence"],
                "feeds":      intel["feeds"],
                "tags":       intel.get("tags", []),
            })
            log.info("[%s] IOC MATCH: %s → %s", tool_name, candidate, intel["threat"])

        # Check domains
        elif candidate in _IOC_INTEL.get("domains", {}):
            intel = _IOC_INTEL["domains"][candidate]
            matches.append({
                "ioc":        candidate,
                "type":       "domain",
                "threat":     intel["threat"],
                "confidence": intel["confidence"],
                "feeds":      intel["feeds"],
                "tags":       intel.get("tags", []),
            })
            log.info("[%s] IOC MATCH: %s → %s", tool_name, candidate, intel["threat"])

    log.info(
        "[%s] Checked %d candidates, found %d matches",
        tool_name, len(checked), len(matches),
    )
    return {
        "tool":      tool_name,
        "checked":   checked,
        "matches":   matches,
        "hit":       len(matches) > 0,
        "hit_count": len(matches),
    }


# ---------------------------------------------------------------------------
# Tool 7: check_outbound_connections
# ---------------------------------------------------------------------------

async def check_outbound_connections(state: dict, client: SplunkClient) -> dict:
    """
    Look for suspicious outbound traffic from the affected host.
    Excludes RFC1918 private address space — only public destinations.
    Flags known suspicious ports: 4444, 1337, 8080, 9001 (Tor).
    """
    tool_name   = "check_outbound_connections"
    host        = _get_host(state)
    index       = client.index
    time_window = _get_time_window(state)

    spl = (
        f'index={index} sourcetype="stream:tcp" '
        f'(src_host="{host}" OR src_ip="{_get_src_ip(state)}") '
        f'NOT dest_ip="10.*" NOT dest_ip="192.168.*" NOT dest_ip="172.16.*" '
        f'earliest="{time_window}" '
        f'| stats count by src_ip, dest_ip, dest_port '
        f'| sort -count | head 20'
    )
    results = await client.search(spl, max_results=20)

    suspicious_ports = {4444, 1337, 8080, 8443, 9001, 9050, 6667}

    outbound: list[dict] = []
    for row in results:
        try:
            port = int(row.get("dest_port", 0))
        except (ValueError, TypeError):
            port = 0

        outbound.append({
            "src_ip":    row.get("src_ip", ""),
            "dest_ip":   row.get("dest_ip", ""),
            "dest_port": port,
            "count":     row.get("count", 0),
            "suspicious": port in suspicious_ports,
        })

    suspicious = [c for c in outbound if c["suspicious"]]

    log.info(
        "[%s] %d outbound connections, %d suspicious",
        tool_name, len(outbound), len(suspicious),
    )
    return {
        "tool":        tool_name,
        "host":        host,
        "outbound":    outbound,
        "suspicious":  suspicious,
        "has_c2_indicators": len(suspicious) > 0,
    }


# ---------------------------------------------------------------------------
# Tool 8: build_timeline
# ---------------------------------------------------------------------------

async def build_timeline(state: dict, client: SplunkClient) -> dict:
    """
    Compile all findings into a chronological attack timeline.
    Applies MITRE keyword mapping to each event.
    This is always the last tool called before generate_report.
    """
    tool_name = "build_timeline"
    events: list[dict] = []

    for finding in state.get("findings", []):

        # Login failures → timeline entry
        if finding.get("tool") == "fetch_alert_data":
            for ev in finding.get("events", [])[:3]:
                raw = ev.get("_raw", "")
                mitre = map_event(raw)
                events.append({
                    "time":            _fmt_time(ev.get("_time", "")),
                    "event":           "Alert trigger event",
                    "raw_log":         raw[:300],
                    "mitre_tactic":    mitre[2] if mitre else "",
                    "mitre_technique": f"{mitre[0]} — {mitre[1]}" if mitre else "",
                    "source":          ev.get("sourcetype", ""),
                    "_sort_key":       ev.get("_time", ""),
                })

        # Successful login
        if finding.get("tool") == "check_login_success" and finding.get("success"):
            events.append({
                "time":            _fmt_time(finding.get("login_time", "")),
                "event":           f"Successful SSH login as user '{finding.get('user', 'unknown')}'",
                "raw_log":         (finding.get("raw_events") or [{}])[0].get("_raw", "")[:300],
                "mitre_tactic":    "Defense Evasion",
                "mitre_technique": "T1078 — Valid Accounts",
                "source":          "linux_secure",
                "_sort_key":       finding.get("login_time", ""),
            })

        # Process execution
        if finding.get("tool") == "check_process_execution":
            for cmd in finding.get("commands", [])[:5]:
                raw   = cmd.get("raw", "")
                mitre = cmd.get("mitre") or map_event(raw)
                events.append({
                    "time":            _fmt_time(cmd.get("time", "")),
                    "event":           f"Command executed: {cmd.get('command', 'unknown')}",
                    "raw_log":         raw[:300],
                    "mitre_tactic":    mitre[2] if mitre else "Execution",
                    "mitre_technique": f"{mitre[0]} — {mitre[1]}" if mitre else "",
                    "source":          "linux_secure",
                    "_sort_key":       cmd.get("time", ""),
                })

        # Lateral movement
        if finding.get("tool") == "check_lateral_movement":
            for move in finding.get("lateral_movements", []):
                events.append({
                    "time":            _fmt_time(move.get("time", "")),
                    "event":           f"Lateral movement to {move.get('dest_ip') or move.get('dest_host', 'unknown')}",
                    "raw_log":         move.get("raw", "")[:300],
                    "mitre_tactic":    "Lateral Movement",
                    "mitre_technique": "T1021.004 — Remote Services: SSH",
                    "source":          "linux_secure",
                    "_sort_key":       move.get("time", ""),
                })

        # Outbound / C2
        if finding.get("tool") == "check_outbound_connections":
            for conn in finding.get("suspicious", []):
                events.append({
                    "time":            "",
                    "event":           f"Suspicious outbound to {conn['dest_ip']}:{conn['dest_port']}",
                    "raw_log":         f"src={conn['src_ip']} dest={conn['dest_ip']} port={conn['dest_port']}",
                    "mitre_tactic":    "Command and Control",
                    "mitre_technique": "T1071 — Application Layer Protocol",
                    "source":          "stream:tcp",
                    "_sort_key":       "",
                })

        # IOC matches
        if finding.get("tool") == "correlate_ioc":
            for match in finding.get("matches", []):
                events.append({
                    "time":            "",
                    "event":           f"IOC match: {match['ioc']} — {match['threat']}",
                    "raw_log":         f"ioc={match['ioc']} confidence={match['confidence']}",
                    "mitre_tactic":    "Command and Control",
                    "mitre_technique": "T1071 — Application Layer Protocol",
                    "source":          "ioc_intel",
                    "_sort_key":       "",
                })

    # Sort chronologically — events without timestamps go to the end
    events.sort(key=lambda e: e.get("_sort_key") or "9999")

    # Strip the internal sort key before returning
    for ev in events:
        ev.pop("_sort_key", None)

    # Collect all raw logs for MITRE deduplication
    all_raw = [e.get("raw_log", "") for e in events]
    mitre_mapping = get_unique_techniques(all_raw)

    log.info("[%s] Timeline compiled: %d events, %d MITRE techniques", tool_name, len(events), len(mitre_mapping))
    return {
        "tool":          tool_name,
        "timeline":      events,
        "mitre_mapping": mitre_mapping,
        "event_count":   len(events),
    }


# ---------------------------------------------------------------------------
# Helper: format _time strings from Splunk
# ---------------------------------------------------------------------------

def _fmt_time(splunk_time: str) -> str:
    """
    Convert a Splunk _time value to HH:MM:SS for display.
    Splunk returns epoch floats or ISO strings depending on output mode.
    """
    if not splunk_time:
        return ""
    try:
        # Try epoch float first
        from datetime import timezone
        ts = float(splunk_time)
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%H:%M:%S")
    except (ValueError, TypeError):
        pass
    try:
        # Try ISO string
        dt = datetime.fromisoformat(str(splunk_time).replace("Z", "+00:00"))
        return dt.strftime("%H:%M:%S")
    except Exception:
        pass
    # Return as-is if we can't parse it
    return str(splunk_time)


# ---------------------------------------------------------------------------
# Tool dispatcher — called by agent.py
# ---------------------------------------------------------------------------

TOOL_REGISTRY: dict[str, callable] = {
    "fetch_alert_data":          fetch_alert_data,
    "check_login_success":       check_login_success,
    "expand_to_network_logs":    expand_to_network_logs,
    "check_process_execution":   check_process_execution,
    "check_lateral_movement":    check_lateral_movement,
    "correlate_ioc":             correlate_ioc,
    "check_outbound_connections": check_outbound_connections,
    "build_timeline":            build_timeline,
}


async def execute_tool(
    action: str,
    state: dict,
    client: SplunkClient,
) -> dict:
    """
    Execute a named tool. Called by the agent loop.

    Args:
        action: Tool name string — must be in TOOL_REGISTRY
        state:  Current investigation state
        client: SplunkClient instance

    Returns:
        Tool result dict. Never raises — returns error dict on failure.
    """
    tool_fn = TOOL_REGISTRY.get(action)

    if not tool_fn:
        log.error("Unknown tool requested: %s", action)
        return {"tool": action, "error": f"Unknown tool: {action}"}

    try:
        log.info("Executing tool: %s", action)
        result = await tool_fn(state, client)
        return result
    except Exception as exc:
        log.exception("Tool %s raised an exception: %s", action, exc)
        return {
            "tool":  action,
            "error": str(exc),
        }