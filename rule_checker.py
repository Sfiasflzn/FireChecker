
import re


def check_acl_rules(rules):
    """
    Identify potentially risky firewall ACL rules.
    """

    findings = []

    for rule in rules:
        raw_rule = rule["raw_rule"].strip()
        normalized_rule = re.sub(r"\s+", " ", raw_rule.lower())
        line_number = rule["line_number"]

        # Check unrestricted IP traffic access
        if re.search(
            r"\bpermit\s+ip\s+any\s+any\b",
            normalized_rule
        ):
            findings.append({
                "line_number": line_number,
                "rule": raw_rule,
                "issue": "Unrestricted traffic access",
                "severity": "High",
                "recommendation": (
                    "Review the rule and restrict traffic "
                    "to trusted sources and required destinations."
                )
            })

        # Check Telnet access through TCP port 23
        if re.search(
            r"\bpermit\s+tcp\b.*\beq\s+23\b",
            normalized_rule
        ):
            findings.append({
                "line_number": line_number,
                "rule": raw_rule,
                "issue": "Telnet access detected",
                "severity": "High",
                "recommendation": (
                    "Replace Telnet with SSH where appropriate "
                    "and restrict access to trusted management hosts."
                )
            })

        # Check SSH access through TCP port 22
        if re.search(
            r"\bpermit\s+tcp\b.*\beq\s+22\b",
            normalized_rule
        ):
            findings.append({
                "line_number": line_number,
                "rule": raw_rule,
                "issue": "SSH access may be exposed",
                "severity": "Medium",
                "recommendation": (
                    "Restrict SSH access to trusted management "
                    "IP addresses and review the permitted sources."
                )
            })

    return findings
