"""
tools.py — All 8 agent tool implementations.

Every tool:
  - Is async
  - Takes the current investigation state dict + a SplunkClient instance
  - Returns a dict of findings appended to state["findings"]
  - Is read-only — no write operations anywhere

BOTS v3 confirmed field structure:
  - linux_secure has NO src_ip field — IP is inside _raw only
  - Brute force string: "Invalid user" or "input_userauth_request: invalid user"
  - Successful login string: "Accepted publickey" (not "Accepted password")
  - Hosts: gacrux.i-0920036c8ca91e501, mars.i-08e52f8b5a034012d
  - _time: ISO format 2018-08-20T16:13:47.000+0100
  - osquery:results has command execution data
  - stream:tcp / aws:cloudwatchlogs:vpcflow has network flow data
  - All queries use earliest=0 (data is from 2018)
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime

from mitre_map import map_event, get_unique_techniques
from splunk_client import SplunkClient

log = logging.getLogger("argus.tools")


# ---------------------------------------------------------------------------
# IOC intel — loaded once at import time
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
# Helpers
# ---------------------------------------------------------------------------

_VALID_IP_RE = re.compile(
    r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$'
)

def _validate_ip(ip: str) -> str:
    """Return ip if it is a valid IPv4 address, else empty string."""
    if ip and _VALID_IP_RE.match(str(ip).strip()):
        return str(ip).strip()
    return ""

def _get_src_ip(state: dict) -> str:
    raw = (
        state.get("alert", {}).get("src_ip")
        or state.get("alert", {}).get("raw_result", {}).get("src_ip")
        or ""
    )
    return _validate_ip(raw)

def _get_host(state: dict) -> str:
    return (
        state.get("alert", {}).get("host")
        or state.get("alert", {}).get("raw_result", {}).get("host")
        or ""
    )

def _first_finding(state: dict, key: str):
    """Walk findings and return first non-empty value for a key."""
    for finding in state.get("findings", []):
        val = finding.get(key)
        if val:
            return val
    return None

def _extract_ips(text: str) -> list[str]:
    """Extract all IPv4 addresses from a string."""
    return re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)

def _is_private(ip: str) -> bool:
    """Return True if IP is RFC1918, loopback, or link-local."""
    return (
        ip.startswith("10.")
        or ip.startswith("127.")
        or ip.startswith("169.254.")
        or ip.startswith("192.168.")
        or any(ip.startswith(f"172.{i}.") for i in range(16, 32))
    )

def _fmt_time(splunk_time: str) -> str:
    """
    Convert Splunk _time to HH:MM:SS.
    BOTS v3 format: 2018-08-20T16:13:47.000+0100
    """
    if not splunk_time:
        return ""
    try:
        dt = datetime.fromisoformat(str(splunk_time).replace("Z", "+00:00"))
        return dt.strftime("%H:%M:%S")
    except Exception:
        pass
    try:
        from datetime import timezone
        ts = float(splunk_time)
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%H:%M:%S")
    except Exception:
        pass
    return str(splunk_time)


# ---------------------------------------------------------------------------
# Tool 1: fetch_alert_data
# ---------------------------------------------------------------------------

async def fetch_alert_data(state: dict, client: SplunkClient) -> dict:
    """
    Fetch events related to the alert from Splunk.

    BOTS v3: linux_secure has no src_ip field.
    We search _raw for the attacker IP to find brute force events.
    Brute force indicators: "Invalid user", "input_userauth_request"
    """
    tool_name = "fetch_alert_data"
    src_ip    = _get_src_ip(state)
    search_id = state.get("alert", {}).get("search_id", "")
    index     = client.index

    # Try SID first — skip test SIDs
    if search_id and search_id not in ("test-001", "test-002", ""):
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

    # Fallback: search _raw for attacker IP in linux_secure
    if src_ip:
        spl = (
            f'search index={index} sourcetype=linux_secure '
            f'_raw="*{src_ip}*" '
            f'earliest=0 | head 50'
        )
        events = await client.search(spl, max_results=50)
        log.info("[%s] Raw search returned %d events for %s", tool_name, len(events), src_ip)

        if events:
            return {
                "tool":   tool_name,
                "source": "raw_search",
                "spl":    spl,
                "events": events,
                "count":  len(events),
            }

        # If still nothing, try broader search for any brute force activity
        log.info("[%s] No events for %s — trying broad brute force search", tool_name, src_ip)
        spl2 = (
            f'search index={index} sourcetype=linux_secure '
            f'("Invalid user" OR "input_userauth_request") '
            f'earliest=0 | head 50'
        )
        events2 = await client.search(spl2, max_results=50)
        log.info("[%s] Broad brute force search returned %d events", tool_name, len(events2))
        return {
            "tool":   tool_name,
            "source": "broad_search",
            "spl":    spl2,
            "events": events2,
            "count":  len(events2),
        }

    log.warning("[%s] No SID and no src_ip", tool_name)
    return {"tool": tool_name, "events": [], "count": 0, "error": "no_src_ip_or_sid"}


# ---------------------------------------------------------------------------
# Tool 2: check_login_success
# ---------------------------------------------------------------------------

async def check_login_success(state: dict, client: SplunkClient) -> dict:
    """
    Check whether any SSH login succeeded.

    BOTS v3: Successful logins use "Accepted publickey" not "Accepted password".
    Suspicious login: ec2-user from 91.207.175.249 (in our IOC list).
    Search _raw since there is no src_ip field on linux_secure.
    """
    tool_name = "check_login_success"
    src_ip    = _get_src_ip(state)
    index     = client.index

    # Search for any accepted login from the attacker IP
    if src_ip:
        spl = (
            f'search index={index} sourcetype=linux_secure '
            f'("Accepted publickey" OR "Accepted password") '
            f'_raw="*{src_ip}*" '
            f'earliest=0 | head 20'
        )
        results = await client.search(spl, max_results=20)

        if results:
            first = results[0]
            raw   = first.get("_raw", "")
            user_match = re.search(
                r'Accepted (?:publickey|password) for (\S+)', raw
            )
            user       = user_match.group(1) if user_match else "unknown"
            login_time = first.get("_time", "")

            log.info("[%s] Login found for %s: user=%s", tool_name, src_ip, user)
            return {
                "tool":       tool_name,
                "success":    True,
                "src_ip":     src_ip,
                "user":       user,
                "login_time": login_time,
                "count":      len(results),
                "raw_events": results[:5],
            }

    # Also check for the known suspicious login in BOTS v3
    # 91.207.175.249 logged in as ec2-user — this is the IOC match case
    spl_suspicious = (
        f'search index={index} sourcetype=linux_secure '
        f'("Accepted publickey" OR "Accepted password") '
        f'earliest=0 | head 20'
    )
    all_logins = await client.search(spl_suspicious, max_results=20)

    # Filter for logins from non-legitimate IPs
    suspicious_logins = []
    legitimate_ips = {"157.97.121.132", "166.170.40.8"}  # known good from event_type data

    for row in all_logins:
        raw  = row.get("_raw", "")
        ips  = _extract_ips(raw)
        for ip in ips:
            if ip not in legitimate_ips and not _is_private(ip):
                suspicious_logins.append(row)
                break

    if suspicious_logins:
        first = suspicious_logins[0]
        raw   = first.get("_raw", "")
        user_match = re.search(r'Accepted (?:publickey|password) for (\S+)', raw)
        user       = user_match.group(1) if user_match else "unknown"
        src_match  = re.search(r'from ([\d.]+)', raw)
        found_ip   = src_match.group(1) if src_match else src_ip

        log.info("[%s] Suspicious login found: user=%s from=%s", tool_name, user, found_ip)
        return {
            "tool":       tool_name,
            "success":    True,
            "src_ip":     found_ip,
            "user":       user,
            "login_time": first.get("_time", ""),
            "count":      len(suspicious_logins),
            "raw_events": suspicious_logins[:5],
        }

    log.info("[%s] No successful logins found", tool_name)
    return {
        "tool":    tool_name,
        "success": False,
        "src_ip":  src_ip,
        "count":   0,
    }


# ---------------------------------------------------------------------------
# Tool 3: expand_to_network_logs
# ---------------------------------------------------------------------------

async def expand_to_network_logs(state: dict, client: SplunkClient) -> dict:
    """
    Pull network events involving the attacker IP.

    BOTS v3 has rich network data:
      - stream:tcp (84k events) — has src_ip/dest_ip fields
      - stream:dns (218k events) — DNS lookups
      - aws:cloudwatchlogs:vpcflow (97k) — VPC flow logs
      - cisco:asa (80k) — firewall logs
    """
    tool_name = "expand_to_network_logs"
    src_ip    = _get_src_ip(state)
    host      = _get_host(state)
    index     = client.index

    connections: list[dict] = []
    seen: set[str] = set()

    # Search 1: stream:tcp — has proper IP fields
    if src_ip:
        spl1 = (
            f'search index={index} sourcetype="stream:tcp" '
            f'(src_ip="{src_ip}" OR dest_ip="{src_ip}") '
            f'earliest=0 | head 30'
        )
        results1 = await client.search(spl1, max_results=30)
        for row in results1:
            src  = row.get("src_ip", "")
            dest = row.get("dest_ip", "")
            port = str(row.get("dest_port", ""))
            key  = f"{src}-{dest}-{port}"
            if key not in seen:
                seen.add(key)
                connections.append({
                    "src_ip":     src,
                    "dest_ip":    dest,
                    "dest_port":  port,
                    "proto":      "tcp",
                    "time":       row.get("_time", ""),
                    "sourcetype": "stream:tcp",
                })

    # Search 2: cisco:asa firewall logs — contains IP in _raw
    if src_ip:
        spl2 = (
            f'search index={index} sourcetype="cisco:asa" '
            f'_raw="*{src_ip}*" '
            f'earliest=0 | head 20'
        )
        results2 = await client.search(spl2, max_results=20)
        for row in results2:
            raw  = row.get("_raw", "")
            ips  = _extract_ips(raw)
            src  = row.get("src_ip", ips[0] if ips else "")
            dest = row.get("dest_ip", ips[1] if len(ips) > 1 else "")
            port = str(row.get("dest_port", ""))
            key  = f"{src}-{dest}-{port}"
            if key not in seen and (src or dest):
                seen.add(key)
                connections.append({
                    "src_ip":     src,
                    "dest_ip":    dest,
                    "dest_port":  port,
                    "proto":      "",
                    "time":       row.get("_time", ""),
                    "sourcetype": "cisco:asa",
                })

    # Search 3: VPC flow logs
    if src_ip:
        spl3 = (
            f'search index={index} sourcetype="aws:cloudwatchlogs:vpcflow" '
            f'_raw="*{src_ip}*" '
            f'earliest=0 | head 20'
        )
        results3 = await client.search(spl3, max_results=20)
        for row in results3:
            raw  = row.get("_raw", "")
            ips  = _extract_ips(raw)
            src  = ips[0] if ips else ""
            dest = ips[1] if len(ips) > 1 else ""
            key  = f"{src}-{dest}"
            if key not in seen and (src or dest):
                seen.add(key)
                connections.append({
                    "src_ip":     src,
                    "dest_ip":    dest,
                    "dest_port":  "",
                    "proto":      "",
                    "time":       row.get("_time", ""),
                    "sourcetype": "vpcflow",
                })

    log.info("[%s] Found %d unique connections", tool_name, len(connections))
    return {
        "tool":        tool_name,
        "host":        host,
        "connections": connections,
        "raw_count":   len(connections),
    }


# ---------------------------------------------------------------------------
# Tool 4: check_process_execution
# ---------------------------------------------------------------------------

async def check_process_execution(state: dict, client: SplunkClient) -> dict:
    """
    Look for attacker commands after gaining access.

    BOTS v3: osquery:results has process/command execution data (219k events).
    Also check syslog (283k events) for command activity.
    """
    tool_name  = "check_process_execution"
    user       = _first_finding(state, "user")
    host       = _get_host(state)
    src_ip     = _get_src_ip(state)
    index      = client.index

    commands: list[dict] = []

    recon_terms = (
        '"whoami" OR "ifconfig" OR "netstat" OR "uname" OR '
        '"id" OR "hostname" OR "passwd" OR "shadow" OR '
        '"wget" OR "curl" OR "python" OR "bash" OR '
        '"nc" OR "nmap" OR "ps" OR "ls" OR "find"'
    )

    # Search 1: osquery:results — best source for command execution in BOTS v3
    spl1 = (
        f'search index={index} sourcetype="osquery:results" '
        f'earliest=0 | head 30'
    )
    if host:
        spl1 = (
            f'search index={index} sourcetype="osquery:results" '
            f'_raw="*{host}*" '
            f'earliest=0 | head 30'
        )
    results1 = await client.search(spl1, max_results=30)

    for row in results1:
        raw = row.get("_raw", "")
        cmd = row.get("cmdline") or row.get("path") or row.get("name") or ""
        if not cmd:
            for keyword in [
                "whoami", "ifconfig", "netstat", "uname", "id",
                "hostname", "wget", "curl", "python", "bash",
                "nc", "nmap", "ps", "passwd", "shadow"
            ]:
                if keyword in raw.lower():
                    cmd = keyword
                    break
        commands.append({
            "time":    row.get("_time", ""),
            "command": cmd,
            "raw":     raw[:200],
            "mitre":   map_event(raw) or (map_event(cmd) if cmd else None),
        })

    # Search 2: syslog for recon commands
    if not commands:
        spl2 = (
            f'search index={index} sourcetype=syslog '
            f'({recon_terms}) '
            f'earliest=0 | head 30'
        )
        if user and user != "unknown":
            spl2 = (
                f'search index={index} sourcetype=syslog '
                f'_raw="*{user}*" ({recon_terms}) '
                f'earliest=0 | head 30'
            )
        results2 = await client.search(spl2, max_results=30)

        for row in results2:
            raw = row.get("_raw", "")
            cmd = ""
            for keyword in [
                "whoami", "ifconfig", "netstat", "uname", "id",
                "hostname", "wget", "curl", "python", "bash", "nc", "nmap"
            ]:
                if keyword in raw.lower():
                    cmd = keyword
                    break
            commands.append({
                "time":    row.get("_time", ""),
                "command": cmd,
                "raw":     raw[:200],
                "mitre":   map_event(raw) or (map_event(cmd) if cmd else None),
            })

    log.info("[%s] Found %d command events", tool_name, len(commands))
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
    Check for movement from compromised host to other internal systems.

    BOTS v3: Check linux_secure for accepted logins between internal hosts,
    and stream:tcp for internal TCP connections.
    """
    tool_name = "check_lateral_movement"
    host      = _get_host(state)
    user      = _first_finding(state, "user")
    src_ip    = _get_src_ip(state)
    index     = client.index

    movements: list[dict] = []

    # Search 1: linux_secure — accepted logins between internal hosts
    login_user = user or "ec2-user"
    spl1 = (
        f'search index={index} sourcetype=linux_secure '
        f'"Accepted" _raw="*{login_user}*" '
        f'earliest=0 | head 20'
    )
    results1 = await client.search(spl1, max_results=20)

    for row in results1:
        raw  = row.get("_raw", "")
        ips  = _extract_ips(raw)
        # Internal movement = destination is private, source is not the original attacker
        internal = [ip for ip in ips if _is_private(ip)]
        external = [ip for ip in ips if not _is_private(ip) and ip != src_ip]

        if internal:
            movements.append({
                "src_host":  host,
                "dest_ip":   internal[0],
                "dest_host": "",
                "time":      row.get("_time", ""),
                "raw":       raw[:200],
            })

    # Search 2: stream:tcp for internal-to-internal connections after compromise
    if not movements and src_ip:
        spl2 = (
            f'search index={index} sourcetype="stream:tcp" '
            f'src_ip="{src_ip}" '
            f'(dest_ip="10.*" OR dest_ip="172.*" OR dest_ip="192.168.*") '
            f'earliest=0 | head 20'
        )
        results2 = await client.search(spl2, max_results=20)

        for row in results2:
            dest_ip = row.get("dest_ip", "")
            if dest_ip:
                movements.append({
                    "src_host":  host,
                    "dest_ip":   dest_ip,
                    "dest_host": row.get("dest_host", ""),
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
    Check all IPs seen in the investigation against ioc_intel.json.
    Pure dict lookup — instant, no external API, no rate limits.
    """
    tool_name  = "correlate_ioc"
    candidates: set[str] = set()

    # Always check the original src_ip
    src_ip = _get_src_ip(state)
    if src_ip:
        candidates.add(src_ip)

    # Walk all findings for additional IPs
    for finding in state.get("findings", []):

        # Network connections
        for conn in finding.get("connections", []):
            for field in ("src_ip", "dest_ip"):
                val = conn.get(field, "")
                if val and not _is_private(val):
                    candidates.add(val)

        # Lateral movement destinations
        for move in finding.get("lateral_movements", []):
            val = move.get("dest_ip", "")
            if val and not _is_private(val):
                candidates.add(val)

        # Raw events — extract all IPs
        for event in finding.get("events", []) + finding.get("raw_events", []):
            raw = event.get("_raw", "")
            for ip in _extract_ips(raw):
                if not _is_private(ip):
                    candidates.add(ip)

        # Outbound connections
        for conn in finding.get("outbound", []) + finding.get("suspicious", []):
            val = conn.get("dest_ip", "")
            if val and not _is_private(val):
                candidates.add(val)

    # Lookup every candidate
    matches: list[dict] = []
    checked: list[str]  = list(candidates)

    for candidate in candidates:
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
        "[%s] Checked %d candidates, %d matches",
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
    Look for suspicious outbound traffic to public IPs.

    BOTS v3: stream:tcp has proper src_ip/dest_ip fields.
    Also check cisco:asa for firewall-logged outbound connections.
    """
    tool_name = "check_outbound_connections"
    src_ip    = _get_src_ip(state)
    host      = _get_host(state)
    index     = client.index

    suspicious_ports = {4444, 1337, 8080, 8443, 9001, 9050, 6667, 443, 80}
    high_risk_ports  = {4444, 1337, 9001, 9050, 6667}

    outbound: list[dict] = []

    # Search 1: stream:tcp — has IP fields
    spl1 = (
        f'search index={index} sourcetype="stream:tcp" '
        f'src_ip="{src_ip}" '
        f'NOT dest_ip="10.*" NOT dest_ip="192.168.*" NOT dest_ip="172.*" '
        f'earliest=0 '
        f'| stats count by src_ip, dest_ip, dest_port '
        f'| sort -count | head 20'
    )
    results1 = await client.search(spl1, max_results=20)

    for row in results1:
        try:
            port = int(row.get("dest_port", 0))
        except (ValueError, TypeError):
            port = 0

        outbound.append({
            "src_ip":     row.get("src_ip", ""),
            "dest_ip":    row.get("dest_ip", ""),
            "dest_port":  port,
            "count":      row.get("count", 0),
            "suspicious": port in high_risk_ports,
            "sourcetype": "stream:tcp",
        })

    # Search 2: cisco:asa — firewall denied/allowed outbound
    if src_ip:
        spl2 = (
            f'search index={index} sourcetype="cisco:asa" '
            f'_raw="*{src_ip}*" '
            f'NOT _raw="*10.*" '
            f'earliest=0 | head 20'
        )
        results2 = await client.search(spl2, max_results=20)

        for row in results2:
            raw  = row.get("_raw", "")
            ips  = _extract_ips(raw)
            dest = next((ip for ip in ips if not _is_private(ip) and ip != src_ip), "")
            if dest:
                outbound.append({
                    "src_ip":     src_ip,
                    "dest_ip":    dest,
                    "dest_port":  0,
                    "count":      1,
                    "suspicious": False,
                    "sourcetype": "cisco:asa",
                })

    suspicious = [c for c in outbound if c["suspicious"]]

    log.info(
        "[%s] %d outbound connections, %d suspicious",
        tool_name, len(outbound), len(suspicious),
    )
    return {
        "tool":              tool_name,
        "host":              host,
        "outbound":          outbound,
        "suspicious":        suspicious,
        "has_c2_indicators": len(suspicious) > 0,
    }


# ---------------------------------------------------------------------------
# Tool 8: build_timeline
# ---------------------------------------------------------------------------

async def build_timeline(state: dict, client: SplunkClient) -> dict:
    """
    Compile all findings into a chronological attack timeline.
    Applies MITRE keyword mapping to each event.
    Always runs last before generate_report.
    """
    tool_name = "build_timeline"
    events: list[dict] = []

    for finding in state.get("findings", []):

        # Raw alert events — brute force activity
        if finding.get("tool") == "fetch_alert_data":
            for ev in finding.get("events", [])[:3]:
                raw   = ev.get("_raw", "")
                mitre = map_event(raw)
                # Determine event description from raw content
                if "Invalid user" in raw or "input_userauth_request" in raw:
                    desc = "SSH brute force — invalid user attempt"
                elif "Disconnected" in raw or "Connection closed" in raw:
                    desc = "SSH connection rejected — brute force activity"
                else:
                    desc = "Alert trigger event"

                events.append({
                    "time":            _fmt_time(ev.get("_time", "")),
                    "event":           desc,
                    "raw_log":         raw[:300],
                    "mitre_tactic":    mitre[2] if mitre else "Credential Access",
                    "mitre_technique": f"{mitre[0]} — {mitre[1]}" if mitre else "T1110.001 — Brute Force",
                    "source":          ev.get("sourcetype", "linux_secure"),
                    "_sort_key":       ev.get("_time", ""),
                })

        # Successful login
        if finding.get("tool") == "check_login_success" and finding.get("success"):
            raw = (finding.get("raw_events") or [{}])[0].get("_raw", "")
            events.append({
                "time":            _fmt_time(finding.get("login_time", "")),
                "event":           f"Successful SSH login as '{finding.get('user', 'unknown')}' from {finding.get('src_ip', '')}",
                "raw_log":         raw[:300],
                "mitre_tactic":    "Defense Evasion",
                "mitre_technique": "T1078 — Valid Accounts",
                "source":          "linux_secure",
                "_sort_key":       finding.get("login_time", ""),
            })

        # Network connections
        if finding.get("tool") == "expand_to_network_logs":
            for conn in finding.get("connections", [])[:3]:
                events.append({
                    "time":            _fmt_time(conn.get("time", "")),
                    "event":           f"Network connection: {conn.get('src_ip')} → {conn.get('dest_ip')}:{conn.get('dest_port')}",
                    "raw_log":         f"src={conn.get('src_ip')} dest={conn.get('dest_ip')} port={conn.get('dest_port')} proto=tcp",
                    "mitre_tactic":    "Discovery",
                    "mitre_technique": "T1049 — System Network Connections Discovery",
                    "source":          conn.get("sourcetype", "stream:tcp"),
                    "_sort_key":       conn.get("time", ""),
                })

        # Process execution / recon commands
        if finding.get("tool") == "check_process_execution":
            for cmd in finding.get("commands", [])[:5]:
                raw   = cmd.get("raw", "")
                mitre = cmd.get("mitre") or map_event(raw)
                events.append({
                    "time":            _fmt_time(cmd.get("time", "")),
                    "event":           f"Command executed: {cmd.get('command') or 'unknown'}",
                    "raw_log":         raw[:300],
                    "mitre_tactic":    mitre[2] if mitre else "Execution",
                    "mitre_technique": f"{mitre[0]} — {mitre[1]}" if mitre else "",
                    "source":          "osquery:results",
                    "_sort_key":       cmd.get("time", ""),
                })

        # Lateral movement
        if finding.get("tool") == "check_lateral_movement":
            for move in finding.get("lateral_movements", []):
                dest = move.get("dest_ip") or move.get("dest_host") or "unknown"
                events.append({
                    "time":            _fmt_time(move.get("time", "")),
                    "event":           f"Lateral movement detected — connection to {dest}",
                    "raw_log":         move.get("raw", "")[:300],
                    "mitre_tactic":    "Lateral Movement",
                    "mitre_technique": "T1021.004 — Remote Services: SSH",
                    "source":          "linux_secure",
                    "_sort_key":       move.get("time", ""),
                })

        # Suspicious outbound / C2
        if finding.get("tool") == "check_outbound_connections":
            for conn in finding.get("suspicious", []):
                events.append({
                    "time":            "",
                    "event":           f"Suspicious outbound to {conn['dest_ip']}:{conn['dest_port']}",
                    "raw_log":         f"src={conn['src_ip']} dest={conn['dest_ip']} port={conn['dest_port']}",
                    "mitre_tactic":    "Command and Control",
                    "mitre_technique": "T1071 — Application Layer Protocol",
                    "source":          conn.get("sourcetype", "stream:tcp"),
                    "_sort_key":       "",
                })

        # IOC matches
        if finding.get("tool") == "correlate_ioc":
            for match in finding.get("matches", []):
                events.append({
                    "time":            "",
                    "event":           f"IOC confirmed: {match['ioc']} — {match['threat']}",
                    "raw_log":         f"ioc={match['ioc']} type={match['type']} confidence={match['confidence']}",
                    "mitre_tactic":    "Command and Control",
                    "mitre_technique": "T1071 — Application Layer Protocol",
                    "source":          "ioc_intel",
                    "_sort_key":       "",
                })

    # Sort chronologically — empty sort keys go to end
    events.sort(key=lambda e: e.get("_sort_key") or "9999")

    # Strip internal sort key
    for ev in events:
        ev.pop("_sort_key", None)

    # Build deduplicated MITRE mapping
    all_raw       = [e.get("raw_log", "") for e in events]
    mitre_mapping = get_unique_techniques(all_raw)

    log.info(
        "[%s] Timeline: %d events, %d MITRE techniques",
        tool_name, len(events), len(mitre_mapping),
    )
    return {
        "tool":          tool_name,
        "timeline":      events,
        "mitre_mapping": mitre_mapping,
        "event_count":   len(events),
    }


# ---------------------------------------------------------------------------
# Tool dispatcher
# ---------------------------------------------------------------------------

TOOL_REGISTRY: dict[str, callable] = {
    "fetch_alert_data":            fetch_alert_data,
    "check_login_success":         check_login_success,
    "expand_to_network_logs":      expand_to_network_logs,
    "check_process_execution":     check_process_execution,
    "check_lateral_movement":      check_lateral_movement,
    "correlate_ioc":               correlate_ioc,
    "check_outbound_connections":  check_outbound_connections,
    "build_timeline":              build_timeline,
}


async def execute_tool(
    action: str,
    state: dict,
    client: SplunkClient,
) -> dict:
    """
    Execute a named tool. Called by the agent loop.
    Never raises — returns error dict on failure so the loop always continues.
    """
    tool_fn = TOOL_REGISTRY.get(action)

    if not tool_fn:
        log.error("Unknown tool: %s", action)
        return {"tool": action, "error": f"Unknown tool: {action}"}

    try:
        log.info("Executing tool: %s", action)
        return await tool_fn(state, client)
    except Exception as exc:
        log.exception("Tool %s crashed: %s", action, exc)
        return {"tool": action, "error": str(exc)}