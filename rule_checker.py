"""
Rule Detection
rule_checker.py - rule-level security checks for FireChecker.

Reads Cisco IOS-style IPv4 ACL text (a file path or a list of lines), parses
each rule, and runs four checks:

    1. Broad access        e.g. ``permit ip any any``
    2. Telnet exposure     e.g. ``permit tcp any any eq 23`` / ``eq telnet``
    3. Duplicate rules     exact duplicates within the same ACL, with line numbers
    4. Overly broad ranges ``any`` or very short prefixes (/0 ... /7 by default)

Every check returns a list of finding dictionaries with a uniform shape so a
risk analyzer can consume them directly:

    {
        "check":        "broad_access",
        "severity":     "critical" | "high" | "medium" | "low",
        "line_number":  12,              # primary line (1-based, original file)
        "line_numbers": [12],            # all lines involved
        "acl":          "101",           # ACL number or name
        "rule":         "access-list 101 permit ip any any",
        "message":      "human readable explanation",
        "parsed":       {action, protocol, source, destination, ...},
        "details":      {check-specific data},
    }

Supported syntax:
    * Numbered ACLs:  ``access-list 101 permit tcp any any eq 23``
    * Named ACLs:     ``ip access-list extended NAME`` followed by rules
                      (optional sequence numbers, e.g. ``10 permit ...``)
    * Standard ACLs:  ``access-list 10 permit 192.168.1.0 0.0.0.255``
    * Addresses:      ``any``, ``host A.B.C.D``, ``A.B.C.D wildcard``,
                      ``A.B.C.D/N`` (CIDR), ``object-group NAME`` (opaque)
    * Ports:          eq / neq / lt / gt / range, numeric or named (telnet, www ...)

Lines that are not ACL rules (``interface ...``, ``ip access-group ...``) and
``remark`` lines are ignored. Rule-like lines that cannot be parsed are
reported under ``parse_errors`` instead of aborting the audit.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import sys
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# Types and constants
# --------------------------------------------------------------------------- #

LineSource = Union[str, os.PathLike, Iterable[Union[str, Tuple[int, str]]]]
Finding = Dict[str, Any]
NumberedLine = Tuple[int, str]

CHECK_BROAD_ACCESS = "broad_access"
CHECK_TELNET = "telnet_exposure"
CHECK_DUPLICATES = "duplicate_rules"
CHECK_BROAD_RANGES = "overly_broad_ranges"

SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"

TELNET_PORT = 23
DEFAULT_MIN_PREFIX_LENGTH = 8  # prefixes shorter than /8 are "overly broad"

_ACTIONS = ("permit", "deny")
_PORT_OPERATORS = ("eq", "neq", "lt", "gt", "range")
_PORT_PROTOCOLS = ("tcp", "udp")
_PROTOCOL_NUMBERS = {"1": "icmp", "6": "tcp", "17": "udp"}

# Common Cisco IOS port keywords. Unknown names are kept but left unresolved,
# which is safe: they can never match Telnet (23).
_PORT_NAMES = {
    "ftp-data": 20, "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25,
    "tacacs": 49, "domain": 53, "bootps": 67, "bootpc": 68, "tftp": 69,
    "finger": 79, "www": 80, "pop2": 109, "pop3": 110, "sunrpc": 111,
    "ident": 113, "nntp": 119, "ntp": 123, "netbios-ns": 137,
    "netbios-dgm": 138, "netbios-ss": 139, "snmp": 161, "snmptrap": 162,
    "bgp": 179, "irc": 194, "ldap": 389, "https": 443, "isakmp": 500,
    "exec": 512, "login": 513, "cmd": 514, "syslog": 514, "lpd": 515,
    "rip": 520, "uucp": 540, "klogin": 543, "kshell": 544,
}


# --------------------------------------------------------------------------- #
# Exceptions
# --------------------------------------------------------------------------- #

class RuleCheckerError(Exception):
    """Base class for all rule_checker errors."""


class ConfigReadError(RuleCheckerError):
    """The ACL source (file or list) could not be read."""


class RuleParseError(RuleCheckerError):
    """A single ACL line could not be parsed."""


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class AddressSpec:
    """A source or destination address specification."""

    kind: str                          # any | host | network | object_group
    text: str                          # normalized text, e.g. "10.0.0.0 0.0.0.255"
    address: Optional[str] = None
    wildcard: Optional[str] = None
    prefix_length: Optional[int] = None  # None if non-contiguous or unknown
    implicit: bool = False             # True for the implied "any" of standard ACLs

    @property
    def is_any(self) -> bool:
        """True for ``any`` and for any /0 equivalent (0.0.0.0 255.255.255.255)."""
        return self.prefix_length == 0


@dataclass(frozen=True)
class PortSpec:
    """A port match such as ``eq 23`` or ``range 20 25``."""

    operator: str
    tokens: Tuple[str, ...]
    values: Tuple[Optional[int], ...]  # None where a port name is unknown

    def matches(self, port: int) -> bool:
        """Return True if this port spec would match ``port``."""
        known = [v for v in self.values if v is not None]
        if self.operator == "eq":
            return port in known
        if self.operator == "neq":
            return port not in known
        if self.operator == "lt":
            return bool(known) and port < known[0]
        if self.operator == "gt":
            return bool(known) and port > known[0]
        if self.operator == "range":
            return len(known) == 2 and known[0] <= port <= known[1]
        return False

    def __str__(self) -> str:
        return f"{self.operator} {' '.join(self.tokens)}"


@dataclass
class ACLRule:
    """A parsed ACL entry."""

    line_number: int
    raw: str
    acl_id: str
    acl_type: str                      # "standard" | "extended"
    action: str                        # "permit" | "deny"
    protocol: str
    src: AddressSpec
    dst: AddressSpec
    src_port: Optional[PortSpec] = None
    dst_port: Optional[PortSpec] = None
    options: Tuple[str, ...] = ()
    normalized: str = ""               # lowercase, single-spaced, no sequence number


# --------------------------------------------------------------------------- #
# 1. Configuration reader
# --------------------------------------------------------------------------- #

def load_acl_lines(source: LineSource) -> List[NumberedLine]:
    """
    Load ACL lines, dropping comments and blank lines.

    Args:
        source: Either
            * a path (``str`` or ``os.PathLike``) to an ACL text file, or
            * an iterable of lines, where each item is a ``str`` (line numbers
              are then the 1-based list positions) or an ``(int, str)`` tuple
              carrying the original line number.

    Returns:
        List of ``(line_number, stripped_text)`` tuples. Lines that are empty
        or start with ``!`` are removed, but line numbers keep pointing at the
        original positions.

    Raises:
        ConfigReadError: file missing/unreadable, or list items of a bad type.
    """
    if isinstance(source, (str, os.PathLike)):
        numbered = list(enumerate(_read_file(source), start=1))
    else:
        numbered = _normalize_line_items(source)

    result: List[NumberedLine] = []
    for line_number, text in numbered:
        stripped = text.strip()
        if not stripped or stripped.startswith("!"):
            continue
        result.append((line_number, stripped))
    return result


def _read_file(path: Union[str, os.PathLike]) -> List[str]:
    """Read a text file into a list of lines (no trailing newlines)."""
    try:
        # utf-8-sig drops a BOM; errors="replace" keeps odd bytes from aborting.
        with open(path, "r", encoding="utf-8-sig", errors="replace") as handle:
            return [line.rstrip("\r\n") for line in handle]
    except FileNotFoundError as exc:
        raise ConfigReadError(f"ACL file not found: {path}") from exc
    except IsADirectoryError as exc:
        raise ConfigReadError(f"Expected a file but got a directory: {path}") from exc
    except PermissionError as exc:
        raise ConfigReadError(f"Permission denied reading ACL file: {path}") from exc
    except OSError as exc:
        raise ConfigReadError(f"Could not read ACL file {path}: {exc}") from exc


def _normalize_line_items(items: Iterable[Any]) -> List[NumberedLine]:
    """Validate a list of lines / (line_number, text) tuples."""
    try:
        materialized = list(items)
    except TypeError as exc:
        raise ConfigReadError(
            "ACL source must be a file path or an iterable of lines"
        ) from exc

    numbered: List[NumberedLine] = []
    for position, item in enumerate(materialized, start=1):
        if isinstance(item, str):
            numbered.append((position, item))
        elif (
            isinstance(item, tuple)
            and len(item) == 2
            and isinstance(item[0], int)
            and isinstance(item[1], str)
        ):
            numbered.append(item)
        else:
            raise ConfigReadError(
                f"Unsupported ACL line at position {position}: "
                f"expected str or (int, str), got {type(item).__name__}"
            )
    return numbered


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #

def parse_rules(lines: Sequence[NumberedLine]) -> Tuple[List[ACLRule], List[Dict[str, Any]]]:
    """
    Parse numbered ACL lines into :class:`ACLRule` objects.

    Tracks ``ip access-list standard|extended NAME`` headers so that indented
    named-ACL entries are attributed to the right ACL. Non-ACL configuration
    lines are ignored; malformed rule lines are collected, not raised.

    Returns:
        ``(rules, parse_errors)`` where each parse error is
        ``{"line_number", "rule", "error"}``.
    """
    rules: List[ACLRule] = []
    errors: List[Dict[str, Any]] = []
    context: Optional[Tuple[str, str]] = None  # (acl name, acl type)

    for line_number, text in lines:
        tokens = text.split()
        if not tokens:
            continue
        try:
            info, context = _interpret_line(tokens, context)
            if info is None:
                continue
            acl_id, acl_type, body = info
            rules.append(_build_rule(line_number, text, acl_id, acl_type, body))
        except (RuleParseError, ValueError, IndexError) as exc:
            logger.warning("Line %d could not be parsed: %s", line_number, exc)
            errors.append({"line_number": line_number, "rule": text, "error": str(exc)})

    return rules, errors


def _interpret_line(
    tokens: List[str], context: Optional[Tuple[str, str]]
) -> Tuple[Optional[Tuple[str, str, List[str]]], Optional[Tuple[str, str]]]:
    """
    Classify one line.

    Returns ``(rule_info, new_context)`` where ``rule_info`` is
    ``(acl_id, acl_type, body_tokens)`` for rule lines and ``None`` otherwise.
    """
    first = tokens[0].lower()
    second = tokens[1].lower() if len(tokens) > 1 else ""

    # Numbered form (also ASA-style "access-list NAME extended permit ...")
    if first == "access-list":
        if len(tokens) < 3:
            raise RuleParseError("Incomplete 'access-list' command")
        acl_id, rest = tokens[1], tokens[2:]
        if rest[0].lower() == "remark":
            return None, context
        if rest[0].lower() in ("standard", "extended"):
            return (acl_id, rest[0].lower(), rest[1:]), context
        return (acl_id, _acl_type_for_number(acl_id), rest), context

    # Named ACL header
    if first == "ip" and second == "access-list":
        kind = tokens[2].lower() if len(tokens) > 2 else ""
        if kind in ("standard", "extended"):
            if len(tokens) < 4:
                raise RuleParseError("Missing ACL name in 'ip access-list' header")
            return None, (tokens[3], kind)
        return None, None  # resequence, role-based, etc.

    if first == "remark":
        return None, context

    # Rule inside a named ACL, optionally prefixed with a sequence number
    start = 0
    if first.isdigit() and second in _ACTIONS + ("remark",):
        if second == "remark":
            return None, context
        start = 1

    if tokens[start].lower() in _ACTIONS:
        body = tokens[start:]
        if context is None:
            return ("unnamed", _guess_acl_type(body), body), context
        return (context[0], context[1], body), context

    # Anything else (interface, hostname, ip access-group ...) ends ACL mode
    return None, None


def _acl_type_for_number(acl_id: str) -> str:
    """Map a numbered ACL to 'standard' or 'extended'."""
    if acl_id.isdigit():
        number = int(acl_id)
        if 1 <= number <= 99 or 1300 <= number <= 1999:
            return "standard"
        if 100 <= number <= 199 or 2000 <= number <= 2699:
            return "extended"
    raise RuleParseError(f"Unsupported ACL number or name '{acl_id}'")


def _guess_acl_type(body: List[str]) -> str:
    """Guess standard vs extended for a rule that has no ACL context."""
    if len(body) > 1:
        probe = body[1].lower()
        if probe in ("any", "host") or "." in probe or "/" in probe:
            return "standard"
    return "extended"


def _build_rule(
    line_number: int, raw: str, acl_id: str, acl_type: str, body: List[str]
) -> ACLRule:
    """Build an ACLRule from the tokens starting at permit/deny."""
    if not body or body[0].lower() not in _ACTIONS:
        found = body[0] if body else "<nothing>"
        raise RuleParseError(f"Expected 'permit' or 'deny', found '{found}'")

    action = body[0].lower()
    normalized = " ".join(token.lower() for token in body)

    if acl_type == "standard":
        src, idx = _parse_address(body, 1, wildcard_required=False)
        dst = AddressSpec("any", "any", prefix_length=0, implicit=True)
        return ACLRule(
            line_number, raw, acl_id, acl_type, action, "ip", src, dst,
            options=tuple(t.lower() for t in body[idx:]), normalized=normalized,
        )

    if len(body) < 2:
        raise RuleParseError("Missing protocol")
    protocol = _normalize_protocol(body[1])
    has_ports = protocol in _PORT_PROTOCOLS

    src, idx = _parse_address(body, 2, wildcard_required=True)
    src_port = dst_port = None
    if has_ports:
        src_port, idx = _parse_port(body, idx)
    dst, idx = _parse_address(body, idx, wildcard_required=True)
    if has_ports:
        dst_port, idx = _parse_port(body, idx)

    return ACLRule(
        line_number, raw, acl_id, acl_type, action, protocol, src, dst,
        src_port, dst_port, tuple(t.lower() for t in body[idx:]), normalized,
    )


def _normalize_protocol(token: str) -> str:
    low = _PROTOCOL_NUMBERS.get(token.lower(), token.lower())
    if not low.replace("-", "").isalnum():
        raise RuleParseError(f"Invalid protocol '{token}'")
    return low


def _is_ipv4(token: str) -> bool:
    try:
        ipaddress.IPv4Address(token)
        return True
    except ValueError:
        return False


def _wildcard_to_prefix(wildcard: str) -> Optional[int]:
    """
    Convert a wildcard mask to a prefix length.

    Returns None for non-contiguous masks (e.g. 0.0.0.254), which have no
    single prefix-length equivalent.
    """
    inverted = (~int(ipaddress.IPv4Address(wildcard))) & 0xFFFFFFFF
    bits = f"{inverted:032b}"
    if "01" in bits:
        return None
    return bits.count("1")


def _parse_address(
    tokens: List[str], idx: int, *, wildcard_required: bool
) -> Tuple[AddressSpec, int]:
    """Parse an address spec starting at ``tokens[idx]``; return (spec, next_idx)."""
    if idx >= len(tokens):
        raise RuleParseError("Missing address specification")

    token = tokens[idx]
    low = token.lower()

    if low == "any":
        return AddressSpec("any", "any", prefix_length=0), idx + 1

    if low == "host":
        if idx + 1 >= len(tokens) or not _is_ipv4(tokens[idx + 1]):
            raise RuleParseError("'host' must be followed by an IPv4 address")
        addr = tokens[idx + 1]
        return (
            AddressSpec("host", f"host {addr}", addr, "0.0.0.0", 32),
            idx + 2,
        )

    if low == "object-group":
        if idx + 1 >= len(tokens):
            raise RuleParseError("'object-group' must be followed by a name")
        return AddressSpec("object_group", f"object-group {tokens[idx + 1]}"), idx + 2

    if "/" in token:
        try:
            net = ipaddress.IPv4Network(token, strict=False)
        except ValueError as exc:
            raise RuleParseError(f"Invalid CIDR notation '{token}'") from exc
        return (
            AddressSpec(
                "network", token, str(net.network_address),
                str(net.hostmask), net.prefixlen,
            ),
            idx + 1,
        )

    if _is_ipv4(token):
        nxt = tokens[idx + 1] if idx + 1 < len(tokens) else None
        if nxt is not None and _is_ipv4(nxt):
            wildcard, consumed = nxt, 2
        elif wildcard_required:
            raise RuleParseError(f"Missing wildcard mask after '{token}'")
        else:
            wildcard, consumed = "0.0.0.0", 1  # standard ACL: implicit host
        return (
            AddressSpec(
                "network", f"{token} {wildcard}", token, wildcard,
                _wildcard_to_prefix(wildcard),
            ),
            idx + consumed,
        )

    raise RuleParseError(f"Unrecognized address specification '{token}'")


def _looks_like_port(token: str) -> bool:
    return token.isdigit() or token.lower() in _PORT_NAMES


def _resolve_port(token: str) -> Optional[int]:
    """Resolve a numeric or named port; None if the name is unknown."""
    if token.isdigit():
        value = int(token)
        if value > 65535:
            raise RuleParseError(f"Port out of range: {token}")
        return value
    return _PORT_NAMES.get(token.lower())


def _parse_port(tokens: List[str], idx: int) -> Tuple[Optional[PortSpec], int]:
    """Parse an optional port operator and its operand(s)."""
    if idx >= len(tokens) or tokens[idx].lower() not in _PORT_OPERATORS:
        return None, idx

    operator = tokens[idx].lower()
    idx += 1

    if operator == "range":
        if idx + 1 >= len(tokens):
            raise RuleParseError("'range' requires two ports")
        raw = tokens[idx:idx + 2]
        idx += 2
    else:
        if idx >= len(tokens):
            raise RuleParseError(f"'{operator}' requires a port")
        raw = [tokens[idx]]
        idx += 1
        if operator in ("eq", "neq"):  # newer IOS allows several ports
            while idx < len(tokens) and _looks_like_port(tokens[idx]):
                raw.append(tokens[idx])
                idx += 1

    values = tuple(_resolve_port(t) for t in raw)
    return PortSpec(operator, tuple(t.lower() for t in raw), values), idx


# --------------------------------------------------------------------------- #
# Finding builder
# --------------------------------------------------------------------------- #

def _make_finding(
    check: str,
    severity: str,
    rule: ACLRule,
    message: str,
    details: Optional[Dict[str, Any]] = None,
    line_numbers: Optional[List[int]] = None,
) -> Finding:
    """Build a finding dict with the uniform schema described in the module docstring."""
    return {
        "check": check,
        "severity": severity,
        "line_number": rule.line_number,
        "line_numbers": line_numbers if line_numbers is not None else [rule.line_number],
        "acl": rule.acl_id,
        "rule": rule.raw,
        "message": message,
        "parsed": {
            "action": rule.action,
            "protocol": rule.protocol,
            "source": rule.src.text,
            "destination": rule.dst.text,
            "source_port": str(rule.src_port) if rule.src_port else None,
            "destination_port": str(rule.dst_port) if rule.dst_port else None,
        },
        "details": details or {},
    }


# --------------------------------------------------------------------------- #
# 2. Broad access detection
# --------------------------------------------------------------------------- #

def _is_unrestricted(rule: ACLRule) -> bool:
    """True if a rule matches all traffic from any source to any destination."""
    if not (rule.src.is_any and rule.dst.is_any):
        return False
    if rule.acl_type == "standard" or rule.protocol == "ip":
        return True
    # tcp/udp any any with no port restriction is effectively "permit ip any any"
    return (
        rule.protocol in _PORT_PROTOCOLS
        and rule.src_port is None
        and rule.dst_port is None
    )


def check_broad_access(rules: Sequence[ACLRule]) -> List[Finding]:
    """
    Detect permit rules that allow everything, such as ``permit ip any any``.

    Flags permit entries where both source and destination are ``any`` (or a
    /0 equivalent) and the protocol is ``ip`` or ``tcp``/``udp`` without port
    limits, plus standard-ACL ``permit any``.

    Severity: critical for ``ip``; high for tcp/udp or standard ACLs.
    """
    findings: List[Finding] = []
    for rule in rules:
        if rule.action != "permit" or not _is_unrestricted(rule):
            continue
        if rule.acl_type == "standard":
            severity = SEVERITY_HIGH
            message = "Standard ACL permits traffic from any source"
        elif rule.protocol == "ip":
            severity = SEVERITY_CRITICAL
            message = "Rule permits all IP traffic from any source to any destination"
        else:
            severity = SEVERITY_HIGH
            message = (
                f"Rule permits all {rule.protocol.upper()} traffic from any "
                "source to any destination with no port restriction"
            )
        findings.append(
            _make_finding(
                CHECK_BROAD_ACCESS, severity, rule, message,
                {"acl_type": rule.acl_type},
            )
        )
    return findings


# --------------------------------------------------------------------------- #
# 3. Telnet exposure detection
# --------------------------------------------------------------------------- #

def check_telnet_exposure(rules: Sequence[ACLRule]) -> List[Finding]:
    """
    Detect permit rules that explicitly allow Telnet (TCP/23).

    Matches ``eq 23`` / ``eq telnet`` as well as ranges and comparisons that
    cover port 23 (e.g. ``range 20 25``, ``lt 1024``, ``neq 80``). Only the
    destination port is considered. Rules with no port restriction
    (``permit ip any any``) allow Telnet implicitly but are reported by
    :func:`check_broad_access` rather than here.
    """
    findings: List[Finding] = []
    for rule in rules:
        if rule.action != "permit" or rule.protocol != "tcp" or rule.dst_port is None:
            continue
        if not rule.dst_port.matches(TELNET_PORT):
            continue
        findings.append(
            _make_finding(
                CHECK_TELNET, SEVERITY_HIGH, rule,
                "Rule permits Telnet (TCP/23), which sends credentials in cleartext",
                {
                    "port": TELNET_PORT,
                    "match_operator": rule.dst_port.operator,
                    "port_expression": str(rule.dst_port),
                    "explicit_telnet": rule.dst_port.operator == "eq",
                },
            )
        )
    return findings


# --------------------------------------------------------------------------- #
# 4. Duplicate rule check
# --------------------------------------------------------------------------- #

def check_duplicate_rules(rules: Sequence[ACLRule]) -> List[Finding]:
    """
    Find exact duplicate entries within the same ACL.

    Two rules are duplicates when they belong to the same ACL and their text
    is identical after lowercasing, collapsing whitespace and removing any
    sequence number. Returns one finding per duplicated rule (not per copy);
    ``line_numbers`` lists every occurrence, and ``details`` separates the
    first occurrence from the redundant ones.
    """
    groups: Dict[Tuple[str, str], List[ACLRule]] = defaultdict(list)
    for rule in rules:
        groups[(rule.acl_id, rule.normalized)].append(rule)

    findings: List[Finding] = []
    for group in groups.values():
        if len(group) < 2:
            continue
        first, extras = group[0], group[1:]
        line_numbers = [r.line_number for r in group]
        findings.append(
            _make_finding(
                CHECK_DUPLICATES, SEVERITY_LOW, first,
                f"Rule appears {len(group)} times in ACL '{first.acl_id}' "
                f"(lines {', '.join(map(str, line_numbers))})",
                {
                    "occurrences": len(group),
                    "first_occurrence": first.line_number,
                    "duplicate_lines": [r.line_number for r in extras],
                },
                line_numbers=line_numbers,
            )
        )
    return findings


# --------------------------------------------------------------------------- #
# 5. Overly broad ranges
# --------------------------------------------------------------------------- #

def check_overly_broad_ranges(
    rules: Sequence[ACLRule], min_prefix_length: int = DEFAULT_MIN_PREFIX_LENGTH
) -> List[Finding]:
    """
    Detect permit rules whose source or destination range is unnecessarily wide.

    A side is flagged when it is ``any``, a /0 equivalent (``0.0.0.0
    255.255.255.255``), or has a prefix length shorter than
    ``min_prefix_length``. The implied destination of a standard ACL is not
    flagged. Non-contiguous wildcard masks and object-groups cannot be
    measured and are skipped.

    Args:
        rules: Parsed rules.
        min_prefix_length: Prefixes shorter than this are flagged (0-32).
            Default 8 flags /0 through /7; use 1 to flag only any// 0.

    Severity: high if both sides are wide, otherwise medium.

    Note:
        ``permit ip any any`` is also reported by :func:`check_broad_access`;
        the risk analyzer may want to de-duplicate on ``line_number``.

    Raises:
        ValueError: if ``min_prefix_length`` is not an int between 0 and 32.
    """
    if (
        isinstance(min_prefix_length, bool)
        or not isinstance(min_prefix_length, int)
        or not 0 <= min_prefix_length <= 32
    ):
        raise ValueError("min_prefix_length must be an integer between 0 and 32")

    findings: List[Finding] = []
    for rule in rules:
        if rule.action != "permit":
            continue
        wide: List[Dict[str, Any]] = []
        for side, spec in (("source", rule.src), ("destination", rule.dst)):
            if spec.implicit or spec.prefix_length is None:
                continue
            if spec.prefix_length < min_prefix_length:
                wide.append(
                    {"side": side, "value": spec.text, "prefix_length": spec.prefix_length}
                )
        if not wide:
            continue

        severity = SEVERITY_HIGH if len(wide) == 2 else SEVERITY_MEDIUM
        sides = " and ".join(item["side"] for item in wide)
        findings.append(
            _make_finding(
                CHECK_BROAD_RANGES, severity, rule,
                f"Rule uses an overly broad {sides} range",
                {"wide_sides": wide, "min_prefix_length": min_prefix_length},
            )
        )
    return findings


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #

def run_all_checks(
    source: LineSource, min_prefix_length: int = DEFAULT_MIN_PREFIX_LENGTH
) -> Dict[str, Any]:
    """
    Load, parse and run every check; return one structured result.

    Returns:
        {
            "source": path or "<list>",
            "config_lines": int,        # non-comment, non-blank lines
            "rules_analyzed": int,
            "parse_errors": [{"line_number", "rule", "error"}, ...],
            "findings": {check_name: [finding, ...], ...},
            "summary": {"total_findings", "by_check", "by_severity"},
        }

    Raises:
        ConfigReadError: the source could not be read.
        ValueError: invalid ``min_prefix_length``.
    """
    lines = load_acl_lines(source)
    rules, parse_errors = parse_rules(lines)

    findings = {
        CHECK_BROAD_ACCESS: check_broad_access(rules),
        CHECK_TELNET: check_telnet_exposure(rules),
        CHECK_DUPLICATES: check_duplicate_rules(rules),
        CHECK_BROAD_RANGES: check_overly_broad_ranges(rules, min_prefix_length),
    }

    by_severity: Dict[str, int] = defaultdict(int)
    for items in findings.values():
        for item in items:
            by_severity[item["severity"]] += 1

    return {
        "source": os.fspath(source) if isinstance(source, (str, os.PathLike)) else "<list>",
        "config_lines": len(lines),
        "rules_analyzed": len(rules),
        "parse_errors": parse_errors,
        "findings": findings,
        "summary": {
            "total_findings": sum(len(v) for v in findings.values()),
            "by_check": {name: len(items) for name, items in findings.items()},
            "by_severity": dict(by_severity),
        },
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Minimal CLI: ``python rule_checker.py acl.txt [--min-prefix N]``."""
    parser = argparse.ArgumentParser(description="FireChecker rule checks for IOS ACL files")
    parser.add_argument("acl_file", help="path to an ACL text file")
    parser.add_argument(
        "--min-prefix", type=int, default=DEFAULT_MIN_PREFIX_LENGTH,
        help="flag prefixes shorter than this (default: %(default)s)",
    )
    args = parser.parse_args(argv)

    try:
        result = run_all_checks(args.acl_file, args.min_prefix)
    except (ConfigReadError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
