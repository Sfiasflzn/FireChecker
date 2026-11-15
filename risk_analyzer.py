"""
Risk Analysis

risk_analyzer.py - FireChecker companion module.

Takes the findings dictionary produced by rule_checker.py and:
  1. Classifies each flagged rule as Low / Medium / High risk.
  2. Calculates a custom risk score (0-100) and explains how it was reached.
  3. Generates practical remediation suggestions.
  4. Returns a JSON-serializable report and can export it to a local file.

EXPECTED INPUT (from rule_checker.py)
-------------------------------------
A dict keyed by finding category, each holding a list of findings:

    {
      "broad_access": [{"line_number": 3, "rule": "permit ip any any"}],
      "telnet":       [{"line_number": 7, "rule": "permit tcp any host 10.0.0.5 eq 23"}],
      "duplicates":   [{"line_number": 12, "rule": "permit tcp any any eq 80",
                        "duplicate_of": 5}],
      "broad_ranges": [{"line_number": 9, "rule": "permit tcp 10.0.0.0 0.255.255.255 any eq 443"}]
    }

The module is deliberately tolerant: category names and item keys have a few
accepted aliases (see CATEGORY_ALIASES and _first_key), and an item may also
be a plain rule string. If your rule_checker.py uses different key names,
adjust those two spots only.
"""

from __future__ import annotations

import json
import math
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# 1. CONSTANTS: categories, risk levels, scoring weights
# ---------------------------------------------------------------------------

LOW, MEDIUM, HIGH = "Low", "Medium", "High"
LEVEL_ORDER = {LOW: 0, MEDIUM: 1, HIGH: 2}

# Canonical issue types and the accepted names rule_checker.py might use.
CATEGORY_ALIASES: Dict[str, str] = {
    "broad_access": "broad_access", "permit_any_any": "broad_access",
    "any_any": "broad_access",
    "telnet": "telnet", "telnet_exposure": "telnet",
    "duplicate": "duplicate", "duplicates": "duplicate",
    "duplicate_rules": "duplicate",
    "broad_range": "broad_range", "broad_ranges": "broad_range",
    "overly_broad": "broad_range", "overly_broad_ranges": "broad_range",
}

# Minimum risk level implied by the *type* of finding, regardless of score.
# This matches the project rules: High = permit ip any any,
# Medium = Telnet / broad ranges, Low = duplicates.
CATEGORY_FLOOR: Dict[str, str] = {
    "broad_access": HIGH,
    "telnet": MEDIUM,
    "broad_range": MEDIUM,
    "duplicate": LOW,
}

# Scoring weights: they add up to 100, so a rule's raw score is 0-100.
W_SOURCE = 30      # how much of the network can originate traffic
W_DEST = 20        # how much of the network can be reached
W_SERVICE = 35     # how dangerous the permitted service/protocol is
W_PORT_SCOPE = 15  # how many ports are opened

EXTRA_ISSUE_BONUS = 5     # added per additional issue on the same rule
DUPLICATE_DAMPING = 0.25  # duplicates are a hygiene issue, not an exposure
DENY_DAMPING = 0.20       # a flagged 'deny' rule can't open anything up

# Score -> level thresholds (the final level is the HIGHER of this and the
# category floor above).
HIGH_THRESHOLD = 60
MEDIUM_THRESHOLD = 30

# Fallback scores when a rule's text can't be parsed.
FALLBACK_SCORE = {"broad_access": 85.0, "telnet": 45.0,
                  "broad_range": 40.0, "duplicate": 10.0}

# Well-known port names used in Cisco ACLs -> numbers.
PORT_NAMES = {
    "ftp-data": 20, "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25,
    "domain": 53, "tftp": 69, "www": 80, "http": 80, "pop3": 110,
    "ntp": 123, "snmp": 161, "snmptrap": 162, "bgp": 179, "ldap": 389,
    "https": 443, "syslog": 514, "ms-sql-s": 1433, "rdp": 3389,
}

# Service risk on a 0-10 scale (10 = most dangerous). Cleartext management
# and legacy file/remote-access protocols score highest.
PORT_RISK = {
    23: 10,                         # Telnet: cleartext remote shell
    21: 8, 20: 8, 69: 8,            # FTP / TFTP: cleartext, often unauthenticated
    3389: 8,                        # RDP
    135: 8, 137: 8, 138: 8, 139: 8, 445: 8,  # NetBIOS / SMB
    161: 7, 162: 7,                 # SNMP (v1/v2c community strings)
    1433: 7, 3306: 7, 5432: 7,      # databases
    22: 4,                          # SSH: encrypted but still admin access
    25: 4, 110: 4, 389: 4, 514: 4,  # legacy mail/directory/syslog
    80: 3, 53: 3, 123: 2, 179: 3,
    443: 2,                         # HTTPS
}
DEFAULT_PORT_RISK = 3          # unknown specific port
ANY_PORT_RISK = 9              # tcp/udp with no port restriction
PROTOCOL_RISK = {"ip": 10, "icmp": 3}  # 'ip' = every protocol and port
DEFAULT_PROTOCOL_RISK = 5

# ---------------------------------------------------------------------------
# 2. DATA STRUCTURES
# ---------------------------------------------------------------------------


@dataclass
class ParsedRule:
    """The parts of an ACL line that matter for scoring."""
    action: str                           # permit / deny
    protocol: str                         # ip / tcp / udp / icmp ...
    src_host_bits: int                    # 0 = single host ... 32 = any
    dst_host_bits: int
    dst_ports: Optional[List[Tuple[int, int]]]  # None = no port restriction


@dataclass
class ScoreBreakdown:
    """Every component of the score, so the result is fully explainable."""
    source_breadth: float      # 0.0 - 1.0
    destination_breadth: float
    service_risk: float        # 0.0 - 1.0 (risk on 0-10 scale / 10)
    port_scope: float
    source_points: float
    destination_points: float
    service_points: float
    port_points: float
    adjustments: List[str]
    total: float


@dataclass
class RuleAssessment:
    """Analyzed result for one flagged ACL rule (one entry in the report)."""
    line_number: Optional[int]
    rule: str
    issues: List[str]
    risk_level: str
    risk_score: float
    score_breakdown: Dict[str, Any]
    score_explanation: str
    recommendations: List[str] = field(default_factory=list)

# ---------------------------------------------------------------------------
# 3. PARSING HELPERS (just enough Cisco ACL syntax for scoring)
# ---------------------------------------------------------------------------

_DOTTED = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _parse_address(tokens: List[str], i: int) -> Tuple[int, int]:
    """Parse one address spec; return (host_bits, next_index).

    host_bits is the number of 'free' bits: 'any' -> 32, '/24' -> 8,
    'host x.x.x.x' -> 0. Wildcard masks are counted by their 1-bits.
    """
    tok = tokens[i]
    if tok == "any":
        return 32, i + 1
    if tok == "host":
        return 0, i + 2
    if "/" in tok:                                   # CIDR: a.b.c.d/len
        return 32 - int(tok.split("/")[1]), i + 1
    if _DOTTED.match(tok):
        if i + 1 < len(tokens) and _DOTTED.match(tokens[i + 1]):  # wildcard
            wildcard = tokens[i + 1]
            bits = sum(bin(int(o)).count("1") for o in wildcard.split("."))
            return bits, i + 2
        return 0, i + 1                              # bare address = host
    raise ValueError(f"unrecognised address token: {tok}")


def _port_number(tok: str) -> int:
    return int(tok) if tok.isdigit() else PORT_NAMES[tok]


def _parse_ports(tokens: List[str], i: int):
    """Parse an optional port operator; return (ranges_or_None, next_index)."""
    if i >= len(tokens):
        return None, i
    op = tokens[i]
    try:
        if op == "eq":
            ports, i = [], i + 1
            while i < len(tokens) and (tokens[i].isdigit() or tokens[i] in PORT_NAMES):
                ports.append(_port_number(tokens[i]))
                i += 1
            return [(p, p) for p in ports], i
        if op == "range":
            return [(_port_number(tokens[i + 1]), _port_number(tokens[i + 2]))], i + 3
        if op == "gt":
            return [(_port_number(tokens[i + 1]) + 1, 65535)], i + 2
        if op == "lt":
            return [(0, _port_number(tokens[i + 1]) - 1)], i + 2
        if op == "neq":
            return [(0, 65535)], i + 2          # nearly everything
    except (KeyError, ValueError, IndexError):
        return None, i + 1
    return None, i


def parse_rule(text: str) -> Optional[ParsedRule]:
    """Parse an ACL line into a ParsedRule, or None if it can't be parsed."""
    tokens = text.strip().lower().split()
    try:
        if tokens and tokens[0] == "access-list":    # numbered ACL prefix
            tokens = tokens[2:]
        if tokens and tokens[0].isdigit():           # named-ACL sequence no.
            tokens = tokens[1:]
        action, protocol = tokens[0], tokens[1]
        if action not in ("permit", "deny"):
            return None
        i = 2
        src_bits, i = _parse_address(tokens, i)
        if protocol in ("tcp", "udp"):               # source port (rarely used)
            _, i = _parse_ports(tokens, i)
        dst_bits, i = _parse_address(tokens, i)
        dst_ports = None
        if protocol in ("tcp", "udp"):
            dst_ports, i = _parse_ports(tokens, i)
        return ParsedRule(action, protocol, src_bits, dst_bits, dst_ports)
    except (IndexError, ValueError):
        return None

# ---------------------------------------------------------------------------
# 4. RISK SCORING (project-defined model)
# ---------------------------------------------------------------------------


def _service_risk(rule: ParsedRule) -> Tuple[float, str]:
    """Return (risk 0-10, human-readable label) for the permitted service."""
    if rule.protocol in ("tcp", "udp"):
        if rule.dst_ports is None:
            return ANY_PORT_RISK, f"{rule.protocol.upper()} on any port"
        # Use the riskiest port in the rule (e.g. 'eq 80 23' -> Telnet counts)
        worst, label = 0, ""
        for lo, hi in rule.dst_ports:
            if hi - lo > 1000:                       # a wide range is "any-like"
                risk, name = ANY_PORT_RISK, f"wide port range {lo}-{hi}"
            else:
                ports = range(lo, hi + 1)
                risk = max(PORT_RISK.get(p, DEFAULT_PORT_RISK) for p in ports)
                name = f"port(s) {lo}" if lo == hi else f"ports {lo}-{hi}"
            if risk > worst:
                worst, label = risk, name
        return worst, label
    return (PROTOCOL_RISK.get(rule.protocol, DEFAULT_PROTOCOL_RISK),
            f"protocol '{rule.protocol}'")


def _port_scope(rule: ParsedRule) -> float:
    """How many ports are opened, 0.0 (one port) to 1.0 (all 65,536).

    Log scale, so 1 port -> 0.0, ~1,000 ports -> 0.6, every port -> 1.0.
    Non-port protocols (ip, icmp) are treated as fully open for 'ip'.
    """
    if rule.protocol == "ip":
        return 1.0
    if rule.protocol not in ("tcp", "udp"):
        return 0.0
    if rule.dst_ports is None:
        return 1.0
    width = sum(hi - lo + 1 for lo, hi in rule.dst_ports)
    return min(1.0, math.log2(max(width, 1)) / 16)


def calculate_risk_score(rule: Optional[ParsedRule],
                         issues: List[str]) -> Tuple[float, ScoreBreakdown]:
    """Custom risk score from 0 (harmless) to 100 (wide open).

    Formula (permit rules):
        score = 30 * source_breadth        # any = 1.0, /24 = 0.25, host = 0
              + 20 * destination_breadth   # same scale
              + 35 * service_risk          # Telnet = 1.0, HTTPS = 0.2, ip = 1.0
              + 15 * port_scope            # 1 port = 0, all ports = 1.0
    Adjustments applied afterwards:
        + 5 for each additional issue found on the same rule
        x 0.25 if the rule is only a duplicate (hygiene, not exposure)
        x 0.20 if the rule is a 'deny' (it cannot open anything)
    Breadth = free host bits / 32, so it grows with the size of the range.
    """
    if rule is None:
        # Unparseable text: fall back to the worst baseline of its issue types.
        base = max(FALLBACK_SCORE.get(i, 20.0) for i in issues)
        bd = ScoreBreakdown(0, 0, 0, 0, 0, 0, 0, 0,
                            ["rule text could not be parsed; baseline used"],
                            base)
        return base, bd

    src_b = rule.src_host_bits / 32
    dst_b = rule.dst_host_bits / 32
    svc_raw, _ = _service_risk(rule)
    svc_b = svc_raw / 10
    port_b = _port_scope(rule)

    src_pts, dst_pts = W_SOURCE * src_b, W_DEST * dst_b
    svc_pts, port_pts = W_SERVICE * svc_b, W_PORT_SCOPE * port_b
    score = src_pts + dst_pts + svc_pts + port_pts
    notes: List[str] = []

    if len(issues) > 1:
        bonus = EXTRA_ISSUE_BONUS * (len(issues) - 1)
        score += bonus
        notes.append(f"+{bonus} for {len(issues)} overlapping issues")
    if issues == ["duplicate"]:
        score *= DUPLICATE_DAMPING
        notes.append(f"x{DUPLICATE_DAMPING} (duplicate-only: redundancy, not exposure)")
    if rule.action == "deny":
        score *= DENY_DAMPING
        notes.append(f"x{DENY_DAMPING} (deny rule)")

    score = round(min(score, 100.0), 1)
    return score, ScoreBreakdown(src_b, dst_b, svc_b, port_b,
                                 round(src_pts, 1), round(dst_pts, 1),
                                 round(svc_pts, 1), round(port_pts, 1),
                                 notes, score)


def explain_score(rule: Optional[ParsedRule], bd: ScoreBreakdown) -> str:
    """Plain-English explanation of how the score was calculated."""
    if rule is None:
        return (f"Rule text could not be parsed, so a baseline score of "
                f"{bd.total} was used based on the finding type.")
    _, svc_label = _service_risk(rule)
    parts = [
        f"source breadth {bd.source_breadth:.2f} x {W_SOURCE} = {bd.source_points}",
        f"destination breadth {bd.destination_breadth:.2f} x {W_DEST} = {bd.destination_points}",
        f"service risk ({svc_label}) {bd.service_risk:.2f} x {W_SERVICE} = {bd.service_points}",
        f"port scope {bd.port_scope:.2f} x {W_PORT_SCOPE} = {bd.port_points}",
    ]
    text = "Score = " + " + ".join(parts)
    if bd.adjustments:
        text += "; adjustments: " + ", ".join(bd.adjustments)
    return text + f" -> {bd.total}/100."

# ---------------------------------------------------------------------------
# 5. CLASSIFICATION
# ---------------------------------------------------------------------------


def classify_risk(score: float, issues: List[str]) -> str:
    """Final level = the higher of the score-based level and the category floor.

    The floor keeps the project rules intact (a 'permit ip any any' is always
    High) while the score can still escalate e.g. Telnet from 'any' to High.
    """
    if score >= HIGH_THRESHOLD:
        by_score = HIGH
    elif score >= MEDIUM_THRESHOLD:
        by_score = MEDIUM
    else:
        by_score = LOW
    floor = max((CATEGORY_FLOOR[i] for i in issues), key=LEVEL_ORDER.get)
    return max(by_score, floor, key=LEVEL_ORDER.get)

# ---------------------------------------------------------------------------
# 6. FIX SUGGESTIONS
# ---------------------------------------------------------------------------


def generate_recommendations(rule: Optional[ParsedRule], issues: List[str],
                             duplicate_of: Optional[int] = None) -> List[str]:
    """Actionable, rule-specific remediation advice (one entry per issue)."""
    recs: List[str] = []

    if "broad_access" in issues:
        recs.append(
            "Replace this blanket permit with explicit rules for only the "
            "traffic that is needed: name the source networks, destination "
            "hosts, protocol and ports. Then end the ACL with 'deny ip any "
            "any log' so anything unexpected is blocked and visible in logs.")
    if "telnet" in issues:
        recs.append(
            "Telnet sends credentials in cleartext. Migrate the device to SSH "
            "(port 22), then remove this rule or replace it with 'eq 22'. If "
            "Telnet must stay temporarily, limit the source to a single "
            "management host and set a removal date.")
    if "broad_range" in issues:
        parts = []
        if rule is None or rule.src_host_bits >= 24:
            parts.append("restrict the source to the specific subnets or "
                         "hosts that need access (e.g. a /24 or 'host x.x.x.x' "
                         "instead of 'any' or a /8)")
        if rule is None or rule.dst_host_bits >= 24:
            parts.append("narrow the destination to the actual servers or "
                         "the smallest subnet that hosts them")
        if rule is not None and rule.protocol in ("tcp", "udp") \
                and rule.dst_ports is None:
            parts.append("limit the destination ports to the required "
                         "service(s), e.g. 'eq 443'")
        if not parts:
            parts.append("narrow the address range and ports to what is "
                         "strictly required")
        recs.append("Overly broad range: " + "; ".join(parts) + ".")
    if "duplicate" in issues:
        of = f" of the rule on line {duplicate_of}" if duplicate_of else ""
        recs.append(
            f"This rule is an exact duplicate{of}. Confirm the original is "
            "correct and in the right order, then remove this copy to keep "
            "the ACL short and easier to audit. Keep it only if it was added "
            "deliberately (e.g. for a different ACL or a hit-count purpose).")

    # Extra advice when the parsed rule shows a risky service on a wide source.
    if (rule and rule.action == "permit" and rule.src_host_bits == 32
            and "broad_access" not in issues):
        recs.append("Source is 'any': add a specific source network, or "
                    "front the service with a VPN or jump host.")
    return recs

# ---------------------------------------------------------------------------
# 7. INPUT NORMALISATION
# ---------------------------------------------------------------------------


def _first_key(item: Dict[str, Any], names: Tuple[str, ...]) -> Any:
    """Return the first present value among several accepted key names."""
    for n in names:
        if n in item and item[n] is not None:
            return item[n]
    return None


def _normalise_findings(findings: Dict[str, Any]) -> Dict[Tuple, Dict[str, Any]]:
    """Group findings by rule so each flagged rule is assessed once.

    Returns {(line_number, rule_text): {"issues": set, "duplicate_of": int}}.
    """
    grouped: Dict[Tuple, Dict[str, Any]] = {}
    for category, items in findings.items():
        issue = CATEGORY_ALIASES.get(str(category).lower())
        if issue is None or not isinstance(items, list):
            continue                                  # skip unknown/metadata keys
        for item in items:
            if isinstance(item, str):
                item = {"rule": item}
            line = _first_key(item, ("line_number", "line_no", "line", "lineno"))
            text = _first_key(item, ("rule", "rule_text", "text", "raw")) or ""
            key = (line, text)
            entry = grouped.setdefault(key, {"issues": set(), "duplicate_of": None})
            entry["issues"].add(issue)
            dup = _first_key(item, ("duplicate_of", "original_line", "first_seen"))
            if dup is not None:
                entry["duplicate_of"] = dup
    return grouped

# ---------------------------------------------------------------------------
# 8. PUBLIC API
# ---------------------------------------------------------------------------


def analyze_findings(findings: Dict[str, Any]) -> Dict[str, Any]:
    """Main entry point: findings dict in, JSON-serializable report dict out."""
    assessments: List[RuleAssessment] = []

    for (line, text), info in _normalise_findings(findings).items():
        issues = sorted(info["issues"], key=lambda i: -LEVEL_ORDER[CATEGORY_FLOOR[i]])
        parsed = parse_rule(text) if text else None
        score, breakdown = calculate_risk_score(parsed, issues)
        assessments.append(RuleAssessment(
            line_number=line,
            rule=text,
            issues=issues,
            risk_level=classify_risk(score, issues),
            risk_score=score,
            score_breakdown=asdict(breakdown),
            score_explanation=explain_score(parsed, breakdown),
            recommendations=generate_recommendations(parsed, issues,
                                                     info["duplicate_of"]),
        ))

    # Most dangerous first (then by line number for stable output).
    assessments.sort(key=lambda a: (-a.risk_score,
                                    a.line_number if isinstance(a.line_number, int) else 0))

    counts = {LOW: 0, MEDIUM: 0, HIGH: 0}
    for a in assessments:
        counts[a.risk_level] += 1
    scores = [a.risk_score for a in assessments]

    return {
        "report_metadata": {
            "tool": "FireChecker risk_analyzer",
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        },
        "summary": {
            "total_flagged_rules": len(assessments),
            "by_risk_level": counts,
            "highest_score": max(scores, default=0),
            "average_score": round(sum(scores) / len(scores), 1) if scores else 0,
        },
        "scoring_model": {
            "weights": {"source_breadth": W_SOURCE, "destination_breadth": W_DEST,
                        "service_risk": W_SERVICE, "port_scope": W_PORT_SCOPE},
            "thresholds": {"high": f">= {HIGH_THRESHOLD}",
                           "medium": f">= {MEDIUM_THRESHOLD}", "low": "below that"},
            "category_floor": CATEGORY_FLOOR,
            "note": ("Final level is the higher of the score-based level and "
                     "the minimum level implied by the finding type."),
        },
        "assessments": [asdict(a) for a in assessments],
    }


def export_report_json(report: Dict[str, Any], path: str, indent: int = 2) -> str:
    """Write the report to a local JSON file and return the path."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=indent)
    return path


def print_summary(report: Dict[str, Any]) -> None:
    """Short console view of the report."""
    s = report["summary"]
    print(f"Flagged rules: {s['total_flagged_rules']}  "
          f"High: {s['by_risk_level'][HIGH]}  Medium: {s['by_risk_level'][MEDIUM]}  "
          f"Low: {s['by_risk_level'][LOW]}")
    for a in report["assessments"]:
        print(f"\n[{a['risk_level'].upper()} {a['risk_score']}] "
              f"line {a['line_number']}: {a['rule']}")
        print(f"  issues: {', '.join(a['issues'])}")
        print(f"  why:    {a['score_explanation']}")
        for r in a["recommendations"]:
            print(f"  fix:    {r}")


# ---------------------------------------------------------------------------
# 9. CLI: python risk_analyzer.py findings.json [-o report.json]
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python risk_analyzer.py findings.json [report.json]")
        sys.exit(1)
    with open(sys.argv[1], encoding="utf-8") as fh:
        result = analyze_findings(json.load(fh))
    print_summary(result)
    if len(sys.argv) > 2:
        print(f"\nReport written to {export_report_json(result, sys.argv[2])}")
