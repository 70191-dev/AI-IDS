"""
AI-IDS Shared Utilities
───────────────────────
Provides alert logging, severity assessment, and attack-type-specific
mitigation recommendations.
"""

import csv
from datetime import datetime
from pathlib import Path

# Find project root (works regardless of path nesting or special chars)
_p = Path(__file__).resolve().parent
while _p != _p.parent:
    if (_p / "env" / "requirements.txt").exists():
        break
    _p = _p.parent
else:
    _p = Path.cwd()
PROJECT_ROOT = _p
LOGS_DIR = PROJECT_ROOT / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)
ALERT_LOG = LOGS_DIR / "alerts.csv"

# Rotate the CSV backup once it exceeds this size.
ALERT_LOG_MAX_BYTES = 5 * 1024 * 1024  # 5 MB

# ── Severity thresholds ──────────────────────────────────────────
SEVERITY_THRESHOLDS = {
    "Critical": 0.95,
    "High":     0.80,
    "Medium":   0.60,
    "Low":      0.40,
}

# ── Attack-type-specific mitigation recommendations ──────────────
MITIGATION_DB = {
    "DoS": {
        "description": "Denial of Service — overwhelms a target with traffic to exhaust resources.",
        "Critical": [
            "Immediately enable rate limiting on the targeted service.",
            "Activate DDoS protection (e.g., Cloudflare, AWS Shield) if available.",
            "Block the source IP at the firewall level.",
            "Contact the ISP if the attack volume exceeds local capacity.",
            "Document all evidence for incident response report.",
        ],
        "High": [
            "Enable connection rate limiting for the targeted port.",
            "Monitor for additional source IPs joining the attack.",
            "Prepare to redirect traffic through a scrubbing service.",
            "Alert the network operations team.",
        ],
        "Medium": [
            "Log the event and monitor for escalation.",
            "Verify the target service is still responsive.",
            "Consider implementing SYN cookies if SYN flood is detected.",
        ],
        "Low": [
            "Record the event in the alert log.",
            "Continue monitoring — may be a probe before a larger attack.",
        ],
    },
    "DDoS": {
        "description": "Distributed Denial of Service — coordinated attack from multiple sources.",
        "Critical": [
            "IMMEDIATELY activate upstream DDoS mitigation (ISP or cloud provider).",
            "Enable BGP blackhole routing for severely affected IPs.",
            "Isolate the targeted system from the network if necessary.",
            "Escalate to senior security team and management.",
            "Begin forensic capture of traffic samples.",
        ],
        "High": [
            "Activate cloud-based DDoS protection services.",
            "Begin tracking and blocking attacking source IP ranges.",
            "Scale backend resources if possible to absorb traffic.",
            "Notify all stakeholders about potential service degradation.",
        ],
        "Medium": [
            "Monitor attack volume for signs of escalation.",
            "Identify whether traffic is volumetric or application-layer.",
            "Prepare incident response playbook for potential escalation.",
        ],
        "Low": [
            "Record the event — low-volume DDoS may be reconnaissance.",
            "Update threat intelligence with source IP information.",
        ],
    },
    "Port Scan": {
        "description": "Network reconnaissance — attacker probing for open ports and services.",
        "Critical": [
            "The source is performing aggressive scanning — block immediately.",
            "Audit all services on scanned ports for known vulnerabilities.",
            "Check if any scanned ports are unintentionally exposed.",
            "Enable port knocking or move sensitive services to non-standard ports.",
        ],
        "High": [
            "Block the scanning source IP at the perimeter firewall.",
            "Review and tighten firewall rules to minimize exposed ports.",
            "Check for follow-up exploitation attempts from the same source.",
        ],
        "Medium": [
            "Log source IP and targeted ports for threat intelligence.",
            "Verify only necessary ports are open on public-facing systems.",
        ],
        "Low": [
            "Record the scan event — single-port probes are common.",
            "No immediate action required unless patterns emerge.",
        ],
    },
    "Brute Force": {
        "description": "Password guessing attack — repeated login attempts against authentication services.",
        "Critical": [
            "Immediately lock the targeted account(s) and reset credentials.",
            "Block the source IP at the authentication service level.",
            "Enable multi-factor authentication (MFA) if not already active.",
            "Audit login logs for any successful unauthorized access.",
            "Check for lateral movement if a compromise is suspected.",
        ],
        "High": [
            "Implement account lockout policies (e.g., 5 failed attempts).",
            "Add the source IP to a temporary blocklist.",
            "Notify affected users to change passwords.",
            "Review authentication logs for anomalies.",
        ],
        "Medium": [
            "Enable CAPTCHA or rate limiting on login endpoints.",
            "Monitor for continued attempts from the same source.",
            "Ensure strong password policies are enforced.",
        ],
        "Low": [
            "Log the attempt — occasional failed logins are normal.",
            "Review if the source IP is a known bad actor.",
        ],
    },
    "Web Attack": {
        "description": "Application-layer attack — SQL injection, XSS, or brute force against web services.",
        "Critical": [
            "Immediately enable WAF (Web Application Firewall) blocking rules.",
            "Take the affected application offline for emergency patching.",
            "Check for data exfiltration or database tampering.",
            "Perform a security audit of the targeted web application.",
            "Preserve server logs for forensic analysis.",
        ],
        "High": [
            "Activate WAF rules to block common attack patterns.",
            "Review application logs for successful injection attempts.",
            "Patch known vulnerabilities in the targeted application.",
            "Restrict access to admin panels and sensitive endpoints.",
        ],
        "Medium": [
            "Enable input validation and output encoding if not present.",
            "Review application for OWASP Top 10 vulnerabilities.",
            "Monitor for repeated attempts from the same source.",
        ],
        "Low": [
            "Log the attempt for security review.",
            "Ensure web application security headers are configured.",
        ],
    },
    "Bot": {
        "description": "Botnet activity — compromised system communicating with command and control servers.",
        "Critical": [
            "IMMEDIATELY isolate the suspected compromised host from the network.",
            "Scan the host for malware and rootkits.",
            "Block communication to identified C2 (command & control) IPs.",
            "Check for other systems on the network showing similar behavior.",
            "Initiate full incident response procedure.",
        ],
        "High": [
            "Monitor the host's network traffic for C2 communication patterns.",
            "Run a full antivirus and anti-malware scan on the host.",
            "Block identified C2 domains/IPs at the DNS and firewall level.",
            "Check for data exfiltration attempts.",
        ],
        "Medium": [
            "Investigate the host for signs of compromise.",
            "Cross-reference destination IPs with threat intelligence feeds.",
            "Monitor for periodic beaconing patterns (regular interval callbacks).",
        ],
        "Low": [
            "Log the suspicious activity for further analysis.",
            "Update endpoint protection signatures.",
        ],
    },
    "Infiltration": {
        "description": "Network infiltration — attacker has gained internal access and is moving laterally.",
        "Critical": [
            "CRITICAL: Potential internal compromise detected.",
            "Immediately segment the affected network zone.",
            "Disable potentially compromised user accounts.",
            "Begin comprehensive incident response — assume breach.",
            "Engage forensic analysts to determine scope of compromise.",
            "Preserve all logs, memory dumps, and disk images.",
        ],
        "High": [
            "Investigate the source system for signs of compromise.",
            "Audit privilege escalation and lateral movement attempts.",
            "Review recent changes to user permissions and group memberships.",
            "Enable enhanced logging on all critical systems.",
        ],
        "Medium": [
            "Verify whether the traffic is legitimate internal communication.",
            "Review access control lists for the affected network segment.",
            "Check for unusual data transfers or access patterns.",
        ],
        "Low": [
            "Log the event and correlate with other alerts.",
            "Review baseline of normal internal traffic patterns.",
        ],
    },
}

# Generic fallback
GENERIC_MITIGATION = {
    "Critical": [
        "Immediately isolate the affected host from the network.",
        "Escalate to the security operations team for incident response.",
        "Capture full packet data for forensic analysis.",
        "Review firewall rules and block the source IP.",
    ],
    "High": [
        "Monitor the source IP for continued suspicious activity.",
        "Review recent connections from the flagged source.",
        "Consider temporarily rate-limiting the source.",
        "Notify the network administrator.",
    ],
    "Medium": [
        "Log the event for further analysis.",
        "Cross-reference with known threat intelligence feeds.",
        "Monitor for repeated patterns from the same source.",
    ],
    "Low": [
        "Record the event in the alert log.",
        "No immediate action required — continue monitoring.",
    ],
}


def get_severity(score: float) -> str:
    """Map prediction confidence score to severity level."""
    for level, threshold in SEVERITY_THRESHOLDS.items():
        if score >= threshold:
            return level
    return "Low"


def get_mitigation(attack_type: str, severity: str) -> dict:
    """Return attack-type-specific mitigation recommendations."""
    if attack_type in MITIGATION_DB:
        info = MITIGATION_DB[attack_type]
        return {
            "attack_type": attack_type,
            "description": info["description"],
            "severity": severity,
            "recommendations": info.get(severity, info.get("Low", [])),
        }
    else:
        return {
            "attack_type": attack_type or "Unknown",
            "description": "Unclassified malicious activity detected.",
            "severity": severity,
            "recommendations": GENERIC_MITIGATION.get(severity, GENERIC_MITIGATION["Low"]),
        }


def rotate_csv_if_large(path: Path = ALERT_LOG, max_bytes: int = ALERT_LOG_MAX_BYTES) -> None:
    """Rename the alert CSV when it exceeds max_bytes so a fresh file is started."""
    try:
        if path.exists() and path.stat().st_size > max_bytes:
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            path.rename(path.with_name(f"{path.stem}-{stamp}.csv.bak"))
    except OSError:
        # Best-effort rotation; never block a prediction on a rename failure.
        pass


def log_alert(flow_id: str, score: float, label: int, attack_type: str = "",
              severity: str = "", features: dict = None):
    """Append an alert entry to the CSV log file (SQL is primary store; this is a backup)."""
    rotate_csv_if_large()
    file_exists = ALERT_LOG.exists() and ALERT_LOG.stat().st_size > 0

    with open(ALERT_LOG, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow([
                "time", "flow_id", "score", "label", "attack_type",
                "severity", "dst_port", "protocol"
            ])
        writer.writerow([
            datetime.now().isoformat(timespec="seconds"),
            flow_id,
            round(score, 4),
            "Attack" if label == 1 else "Benign",
            attack_type,
            severity,
            features.get("destination_port", features.get("dst_port", "")) if features else "",
            features.get("protocol", "") if features else "",
        ])
