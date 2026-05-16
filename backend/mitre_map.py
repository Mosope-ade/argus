"""
mitre_map.py — Deterministic MITRE ATT&CK keyword mapping.

No LLM call needed. Instant dict lookup.
Called by build_timeline() in tools.py to tag each log event.

Usage:
    from mitre_map import map_event

    result = map_event("Failed password for root from 45.142.212.100")
    # → ("T1110.001", "Brute Force: Password Guessing", "Credential Access")

    result = map_event("hello world")
    # → None
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Keyword → (technique_id, technique_name, tactic)
#
# Rules:
#   - Keys are lowercase substrings to match against log lines
#   - First match wins — order matters for overlapping keywords
#   - Keep the most specific keywords above the more generic ones
# ---------------------------------------------------------------------------

MITRE_MAP: dict[str, tuple[str, str, str]] = {
    # Credential Access
    "failed password":        ("T1110.001", "Brute Force: Password Guessing",        "Credential Access"),
    "authentication failure":  ("T1110.001", "Brute Force: Password Guessing",        "Credential Access"),
    "invalid user":           ("T1110.001", "Brute Force: Password Guessing",        "Credential Access"),
    "too many authentication": ("T1110.001", "Brute Force: Password Guessing",        "Credential Access"),

    # Defense Evasion / Initial Access
    "accepted password":      ("T1078",     "Valid Accounts",                         "Defense Evasion"),
    "accepted publickey":     ("T1078",     "Valid Accounts",                         "Defense Evasion"),
    "session opened":         ("T1078",     "Valid Accounts",                         "Defense Evasion"),

    # Discovery
    "whoami":                 ("T1033",     "System Owner/User Discovery",            "Discovery"),
    "ifconfig":               ("T1016",     "System Network Configuration Discovery", "Discovery"),
    "ipconfig":               ("T1016",     "System Network Configuration Discovery", "Discovery"),
    "netstat":                ("T1049",     "System Network Connections Discovery",   "Discovery"),
    "nmap":                   ("T1046",     "Network Service Discovery",              "Discovery"),
    "arp -a":                 ("T1018",     "Remote System Discovery",                "Discovery"),
    "ping -c":                ("T1018",     "Remote System Discovery",                "Discovery"),
    "uname -a":               ("T1082",     "System Information Discovery",           "Discovery"),
    "cat /etc/passwd":        ("T1087.001", "Account Discovery: Local Account",       "Discovery"),
    "cat /etc/shadow":        ("T1003.008", "OS Credential Dumping: /etc/shadow",     "Credential Access"),
    "ps aux":                 ("T1057",     "Process Discovery",                      "Discovery"),
    "ls -la":                 ("T1083",     "File and Directory Discovery",           "Discovery"),
    "find /":                 ("T1083",     "File and Directory Discovery",           "Discovery"),

    # Lateral Movement
    "ssh ":                   ("T1021.004", "Remote Services: SSH",                   "Lateral Movement"),
    "scp ":                   ("T1021.004", "Remote Services: SSH",                   "Lateral Movement"),
    "rsync":                  ("T1021.004", "Remote Services: SSH",                   "Lateral Movement"),

    # Command and Control / C2
    "nc ":                    ("T1059",     "Command and Scripting Interpreter",      "Execution"),
    "ncat":                   ("T1059",     "Command and Scripting Interpreter",      "Execution"),
    "netcat":                 ("T1059",     "Command and Scripting Interpreter",      "Execution"),
    "dest_port=4444":         ("T1071",     "Application Layer Protocol",             "Command and Control"),
    "dest_port=1337":         ("T1071",     "Application Layer Protocol",             "Command and Control"),
    "dest_port=8080":         ("T1071",     "Application Layer Protocol",             "Command and Control"),

    # Execution
    "python":                 ("T1059.006", "Command and Scripting Interpreter: Python", "Execution"),
    "python3":                ("T1059.006", "Command and Scripting Interpreter: Python", "Execution"),
    "bash -i":                ("T1059.004", "Unix Shell",                             "Execution"),
    "/bin/bash":              ("T1059.004", "Unix Shell",                             "Execution"),
    "/bin/sh":                ("T1059.004", "Unix Shell",                             "Execution"),
    "perl -e":                ("T1059",     "Command and Scripting Interpreter",      "Execution"),
    "ruby -e":                ("T1059",     "Command and Scripting Interpreter",      "Execution"),

    # Command and Control — tool transfer
    "wget ":                  ("T1105",     "Ingress Tool Transfer",                  "Command and Control"),
    "curl ":                  ("T1105",     "Ingress Tool Transfer",                  "Command and Control"),

    # Defense Evasion
    "base64":                 ("T1027",     "Obfuscated Files or Information",        "Defense Evasion"),
    "chmod":                  ("T1222",     "File and Directory Permissions Modification", "Defense Evasion"),
    "chattr":                 ("T1222",     "File and Directory Permissions Modification", "Defense Evasion"),
    "history -c":             ("T1070.003", "Indicator Removal: Clear Command History","Defense Evasion"),
    "unset histfile":         ("T1070.003", "Indicator Removal: Clear Command History","Defense Evasion"),
    "shred":                  ("T1070.004", "Indicator Removal: File Deletion",       "Defense Evasion"),

    # Persistence
    "crontab":                ("T1053.003", "Scheduled Task/Job: Cron",               "Persistence"),
    "useradd":                ("T1136.001", "Create Account: Local Account",          "Persistence"),
    "adduser":                ("T1136.001", "Create Account: Local Account",          "Persistence"),
    "passwd":                 ("T1098",     "Account Manipulation",                   "Persistence"),
    "ssh-keygen":             ("T1098.004", "Account Manipulation: SSH Authorized Keys","Persistence"),
    "authorized_keys":        ("T1098.004", "Account Manipulation: SSH Authorized Keys","Persistence"),
    "/etc/rc.local":          ("T1037.004", "Boot or Logon Init Scripts: RC Scripts", "Persistence"),
    "systemctl enable":       ("T1543.002", "Create or Modify System Process: Systemd Service","Persistence"),

    # Privilege Escalation
    "sudo ":                  ("T1548.003", "Abuse Elevation Control: Sudo",          "Privilege Escalation"),
    "sudo -l":                ("T1548.003", "Abuse Elevation Control: Sudo",          "Privilege Escalation"),
    "pkexec":                 ("T1548",     "Abuse Elevation Control Mechanism",      "Privilege Escalation"),
    "setuid":                 ("T1548.001", "Setuid and Setgid",                      "Privilege Escalation"),
    "su root":                ("T1548",     "Abuse Elevation Control Mechanism",      "Privilege Escalation"),

    # Exfiltration
    "scp -r":                 ("T1041",     "Exfiltration Over C2 Channel",           "Exfiltration"),
    "/dev/tcp":               ("T1041",     "Exfiltration Over C2 Channel",           "Exfiltration"),
}


def map_event(log_line: str) -> tuple[str, str, str] | None:
    """
    Match a log line against the MITRE keyword map.

    Args:
        log_line: Raw log string to classify.

    Returns:
        (technique_id, technique_name, tactic) if matched, else None.

    Example:
        map_event("Failed password for backup from 45.142.212.100")
        → ("T1110.001", "Brute Force: Password Guessing", "Credential Access")
    """
    log_lower = log_line.lower()
    for keyword, mapping in MITRE_MAP.items():
        if keyword in log_lower:
            return mapping
    return None


def map_events_bulk(log_lines: list[str]) -> list[tuple[str, str, str] | None]:
    """
    Map a list of log lines in one call.
    Returns a list of the same length — None where no match was found.
    """
    return [map_event(line) for line in log_lines]


def get_unique_techniques(log_lines: list[str]) -> list[dict]:
    """
    Given a list of log lines, return deduplicated MITRE technique dicts
    suitable for the incident report's mitre_mapping field.

    Returns:
        [{"tactic": str, "technique_id": str, "technique_name": str}, ...]
    """
    seen: set[str] = set()
    results: list[dict] = []

    for line in log_lines:
        match = map_event(line)
        if match and match[0] not in seen:
            seen.add(match[0])
            results.append({
                "technique_id":   match[0],
                "technique_name": match[1],
                "tactic":         match[2],
            })

    return results