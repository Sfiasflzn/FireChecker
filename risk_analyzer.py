"""
risk_analyzer.py - Module 3: Risk Analysis for FireChecker.

Analyses the findings produced by rule_checker.py (Module 2) and, for each one:
  * calculates a project-defined risk score from 0 to 100,
  * assigns a risk level (High / Medium / Low),
  * explains how the score was built (score_breakdown + reason),
  * gives a practical fix recommendation.
It also returns an overall summary for the terminal output and JSON report.

The score is FireChecker's own scoring model. It is NOT a CVSS score or a
compliance grade, and a finding is a review flag, not proof of a vulnerability.

Scoring model (score = breadth + service + position, capped at 100):
  breadth   how wide the allowed source/destination range is
  service   how risky the protocol/port is
  position  rules near the top of the ACL match first and shadow later rules
Duplicate rules get a fixed low score because they add clutter, not exposure.
Only "permit" rules are scored; "deny" rules reduce exposure.

Finding format expected from Module 2 (rule_checker.py):
  {"line_number": 3, "rule": "permit ip any any", "issue": "...",
   "severity": "High", "recommendation": "..."}
"""

from __future__ import annotations

import ipaddress
from typing import Any

# ---------------------------------------------------------------------------
# Scoring weights - kept in one place so they are easy to explain and tune.
# ---------------------------------------------------------------------------

# Points for how broad an address range is: (largest prefix length in tier, points).
# Checked from the widest tier down. "any" counts as /0, "host" as /32.
#   /0-/7 (any)   /8-/16 (large)   /17-/31 (subnet)   /32 (single host)
SOURCE_TIERS = [(7, 30), (16, 20), (31, 10), (32, 0)]
DESTINATION_TIERS = [(7, 15), (16, 10), (31, 5), (32, 0)]

SERVICE_ALL_TRAFFIC = 30      # protocol "ip" = every protocol and port
SERVICE_WHOLE_PROTOCOL = 25   # tcp/udp with no port = every port of that protocol
SERVICE_ICMP = 5

# Destination port -> (points, short description). Unlisted ports score 0.
RISKY_PORTS = {
    23: (20, "Telnet sends logins and data in cleartext"),
    21: (20, "FTP sends credentials in cleartext"),
    69: (20, "TFTP has no authentication"),
    161: (20, "SNMP v1/v2c uses cleartext community strings"),
    3389: (15, "RDP is a common brute-force and exploit target"),
    445: (15, "SMB is a common target for worms and ransomware"),
    22: (10, "SSH is a common brute-force target when widely exposed"),
    80: (5, "HTTP traffic is unencrypted"),
}

# Cisco lets you write well-known ports by name.
PORT_NAMES = {
    "ftp": 21, "ftp-data": 20, "ssh": 22, "telnet": 23, "smtp": 25,
    "domain": 53, "tftp": 69, "www": 80, "http": 80, "pop3": 110,
    "snmp": 161, "https": 443,
}

POSITION_BONUS = 10      # rule sits in the first half of the ACL
DUPLICATE_SCORE = 15     # fixed score for an exact duplicate rule

HIGH_THRESHOLD = 70
MEDIUM_THRESHOLD = 40

PORT_OPERATORS = {"eq", "neq", "lt", "gt"}


# ---------------------------------------------------------------------------
# Reading rule fields
# ---------------------------------------------------------------------------

def address_prefix(address: str | None) -> int:
    """Return the prefix length (0-32) of a Cisco ACL address.

    Accepts "any", "host 10.0.0.5", "10.0.0.0 0.0.0.255" (address + wildcard)
    or CIDR like "10.0.0.0/24". Anything unreadable returns 0 (treated as
    "any") so a strange rule is flagged for review instead of being hidden.
    """
    if not address:
        return 0
    text = address.strip().lower()
    if text == "any":
        return 0
    if text.startswith("host "):
        return 32
    parts = text.split()
    try:
        if len(parts) == 2:
            # ipaddress understands Cisco wildcard masks written as a hostmask.
            return ipaddress.IPv4Network(f"{parts[0]}/{parts[1]}", strict=False).prefixlen
        if len(parts) == 1:
            return ipaddress.IPv4Network(parts[0], strict=False).prefixlen
    except ValueError:
        pass
    return 0


def to_port(value: Any) -> int | None:
    """Turn a port given as a number or a Cisco name (e.g. 'telnet') into an int."""
    if value is None:
        return None
    text = str(value).strip().lower()
    if text.isdigit():
        return int(text)
    return PORT_NAMES.get(text)


def parse_rule_text(rule_text: str) -> dict[str, Any]:
    """Split an ACL line into action, protocol, source, destination and port.

    Handles lines such as:
        permit tcp any any eq 23
        10 permit ip 192.168.1.0 0.0.0.255 any
        access-list 101 permit tcp any host 192.0.2.10 eq telnet
    """
    tokens = rule_text.lower().split()
    if tokens[:1] == ["access-list"]:
        tokens = tokens[2:]                       # drop "access-list <id>"
    if tokens and tokens[0].isdigit():
        tokens = tokens[1:]                       # drop a sequence number

    fields: dict[str, Any] = {"action": "", "protocol": "",
                              "src": None, "dst": None, "port": None}
    if len(tokens) < 2:
        return fields
    fields["action"], fields["protocol"] = tokens[0], tokens[1]

    def read_address(i: int) -> tuple[str | None, int]:
        if i >= len(tokens):
            return None, i
        if tokens[i] == "any":
            return "any", i + 1
        if tokens[i] == "host" and i + 1 < len(tokens):
            return f"host {tokens[i + 1]}", i + 2
        if i + 1 < len(tokens) and tokens[i + 1][0].isdigit():
            return f"{tokens[i]} {tokens[i + 1]}", i + 2   # address + wildcard
        return tokens[i], i + 1

    def read_port(i: int) -> tuple[str | None, int]:
        if i + 1 < len(tokens) and tokens[i] in PORT_OPERATORS:
            return tokens[i + 1], i + 2
        if i + 2 < len(tokens) and tokens[i] == "range":
            return tokens[i + 1], i + 3
        return None, i

    position = 2
    fields["src"], position = read_address(position)
    _, position = read_port(position)             # source port is not scored
    fields["dst"], position = read_address(position)
    port, _ = read_port(position)
    fields["port"] = to_port(port)
    return fields


def finding_text(finding: dict[str, Any]) -> str:
    """The ACL line of a finding (Module 2 calls it 'rule')."""
    return str(finding.get("rule") or finding.get("raw_rule") or "")


def is_duplicate(finding: dict[str, Any]) -> bool:
    """True if Module 2 marked this finding as a duplicate rule."""
    return (finding.get("duplicate_of") is not None
            or "duplicate" in str(finding.get("issue", "")).lower())


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def tier_points(prefix: int, tiers: list[tuple[int, int]]) -> int:
    """Points for a prefix length using the widest tier it falls into."""
    for max_prefix, points in tiers:
        if prefix <= max_prefix:
            return points
    return 0


def service_points(protocol: str, port: int | None) -> tuple[int, str]:
    """Points and a short explanation for the protocol/port a rule allows."""
    if protocol == "ip":
        return SERVICE_ALL_TRAFFIC, "allows every protocol and port"
    if protocol in ("tcp", "udp") and port is None:
        return SERVICE_WHOLE_PROTOCOL, f"allows every {protocol.upper()} port"
    if protocol == "icmp":
        return SERVICE_ICMP, "allows ICMP"
    if port in RISKY_PORTS:
        return RISKY_PORTS[port]
    return 0, ""


def position_points(line_number: int | None, rule_lines: list[int]) -> int:
    """Bonus if the rule is in the first half of the ACL (it matches first)."""
    if not rule_lines or line_number not in rule_lines:
        return 0
    rule_index = rule_lines.index(line_number) + 1          # 1-based rule number
    return POSITION_BONUS if rule_index <= len(rule_lines) / 2 else 0


def risk_level(score: int) -> str:
    """Convert a 0-100 score into High / Medium / Low."""
    if score >= HIGH_THRESHOLD:
        return "High"
    if score >= MEDIUM_THRESHOLD:
        return "Medium"
    return "Low"


# ---------------------------------------------------------------------------
# Recommendations
# ---------------------------------------------------------------------------

PORT_ADVICE = {
    23: "replace Telnet with SSH (port 22)",
    21: "replace FTP with SFTP or FTPS",
    69: "allow TFTP only from the management subnet, or use SCP",
    161: "use SNMPv3 and allow it only from the monitoring server",
    3389: "expose RDP only through a VPN or jump host",
    445: "expose SMB only through a VPN or jump host",
    22: "allow SSH only from trusted management IP addresses",
    80: "prefer HTTPS (port 443)",
}


def recommend(finding: dict[str, Any], fields: dict[str, Any]) -> str:
    """Build a practical fix suggestion from what the rule actually allows."""
    if is_duplicate(finding):
        return (f"Remove the rule on line {finding.get('line_number', '?')}; it repeats "
                "an earlier rule. Keep one copy so the ACL is easier to review.")
    if fields["action"] != "permit":
        return "No change needed; deny rules reduce exposure."

    steps = []
    if address_prefix(fields["src"]) <= 16:
        steps.append("restrict the source to the specific host or subnet that needs access")
    if address_prefix(fields["dst"]) <= 16:
        steps.append("limit the destination to the servers that provide the service")
    if fields["protocol"] == "ip":
        steps.append("replace 'ip' with the exact protocol and port required")
    elif fields["protocol"] in ("tcp", "udp") and fields["port"] is None:
        steps.append("add 'eq <port>' so only the required port is allowed")
    if fields["port"] in PORT_ADVICE:
        steps.append(PORT_ADVICE[fields["port"]])

    if not steps:
        return "Review whether this rule is still required and document its purpose."
    text = "; ".join(steps)
    return text[0].upper() + text[1:] + "."


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def assess_finding(finding: dict[str, Any], rule_lines: list[int]) -> dict[str, Any]:
    """Work out score, level, breakdown, reason and recommendation for one finding."""
    fields = parse_rule_text(finding_text(finding))

    if is_duplicate(finding):
        breakdown = {"duplicate": DUPLICATE_SCORE}
        reason = "Exact duplicate of another rule; adds clutter but no new access."
    elif fields["action"] != "permit":
        breakdown = {}
        reason = "Deny rule; does not increase exposure."
    else:
        src_prefix = address_prefix(fields["src"])
        dst_prefix = address_prefix(fields["dst"])
        svc_points, svc_reason = service_points(fields["protocol"], fields["port"])
        breakdown = {
            "source_breadth": tier_points(src_prefix, SOURCE_TIERS),
            "destination_breadth": tier_points(dst_prefix, DESTINATION_TIERS),
            "service": svc_points,
            "position": position_points(finding.get("line_number"), rule_lines),
        }
        parts = [f"source /{src_prefix}", f"destination /{dst_prefix}"]
        if svc_reason:
            parts.append(svc_reason)
        if breakdown["position"]:
            parts.append("matched early in the ACL")
        reason = "Permit rule: " + ", ".join(parts) + "."

    score = min(sum(breakdown.values()), 100)
    return {
        "risk_score": score,
        "severity": risk_level(score),
        "score_breakdown": breakdown,
        "reason": reason,
        "recommendation": recommend(finding, fields),
    }


def calculate_risk(findings: list[dict[str, Any]],
                   rules: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Analyse Module 2's findings and return the overall risk summary.

    Each finding is updated in place with risk_score, severity, score_breakdown,
    reason and recommendation, so report_generator.py and the web templates
    show the scored results without any change to their code. Findings are
    re-ordered from highest to lowest risk.

    Args:
        findings: list of finding dicts from rule_checker.check_acl_rules().
        rules: optional list from config_reader.parse_acl_rules(); when given,
            rule order is used in the score (rules near the top score higher).

    Returns:
        {"total_score", "risk_level", "total_findings", "severity_counts"}
        total_score is the highest finding score: the overall risk of an ACL
        is set by its most dangerous rule, not by how many minor issues it has.

    Raises:
        TypeError: if findings is not a list of dictionaries.
    """
    if not isinstance(findings, list) or not all(isinstance(f, dict) for f in findings):
        raise TypeError("findings must be a list of dictionaries")

    rule_lines = [r.get("line_number") for r in (rules or [])]
    for finding in findings:
        finding.update(assess_finding(finding, rule_lines))
    findings.sort(key=lambda f: (-f["risk_score"], f.get("line_number") or 0))

    counts = {"High": 0, "Medium": 0, "Low": 0}
    for finding in findings:
        counts[finding["severity"]] += 1

    total_score = findings[0]["risk_score"] if findings else 0
    return {
        "total_score": total_score,
        "risk_level": risk_level(total_score),
        "total_findings": len(findings),
        "severity_counts": counts,
    }
