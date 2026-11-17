
def calculate_risk(findings):
    """
    Calculate overall firewall risk score based on findings.
    """

    if not isinstance(findings, list):
        raise ValueError("Findings must be provided as a list.")

    severity_points = {
        "critical": 15,
        "high": 10,
        "medium": 5,
        "low": 2
    }

    severity_breakdown = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0
    }

    total_score = 0

    for finding in findings:

        if not isinstance(finding, dict):
            raise ValueError("Each finding must be a dictionary.")

        severity = finding.get("severity")

        if not isinstance(severity, str):
            raise ValueError("Finding severity must be a valid string.")

        severity = severity.strip().lower()

        if severity not in severity_points:
            raise ValueError(
                f"Unknown severity level: {severity}"
            )

        total_score += severity_points[severity]

        severity_breakdown[severity.capitalize()] += 1

    # Determine overall risk level
    if total_score >= 20:
        risk_level = "Critical"
    elif total_score >= 10:
        risk_level = "High"
    elif total_score >= 5:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "total_score": total_score,
        "risk_level": risk_level,
        "total_findings": len(findings),
        "severity_breakdown": severity_breakdown
    }
