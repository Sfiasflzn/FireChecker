
def check_acl_rules(rules):
    """
    Identify potentially risky firewall ACL rules.
    """

    findings = []

    for rule in rules:
        raw_rule = rule["raw_rule"].lower()
        line_number = rule["line_number"]

        # Check unrestricted access
        if "permit ip any any" in raw_rule:
            findings.append({
                "line_number": line_number,
                "rule": rule["raw_rule"],
                "issue": "Unrestricted traffic access",
                "severity": "High",
                "recommendation": (
                    "Review the rule and restrict traffic "
                    "to trusted sources and required destinations."
                )
            })

        # Check Telnet access
        elif "eq 23" in raw_rule and "permit" in raw_rule:
            findings.append({
                "line_number": line_number,
                "rule": rule["raw_rule"],
                "issue": "Telnet access detected",
                "severity": "High",
                "recommendation": (
                    "Replace Telnet with SSH where appropriate."
                )
            })

        # Check SSH exposure
        elif "eq 22" in raw_rule and "permit" in raw_rule:
            findings.append({
                "line_number": line_number,
                "rule": rule["raw_rule"],
                "issue": "SSH access may be exposed",
                "severity": "Medium",
                "recommendation": (
                    "Restrict SSH access to trusted management IP addresses."
                )
            })

    return findings
