
def calculate_risk(findings):
    """
    Calculate overall firewall risk score.
    """

    severity_points = {
        "High": 10,
        "Medium": 5,
        "Low": 2
    }

    total_score = 0

    for finding in findings:
        severity = finding.get("severity", "Low")
        total_score += severity_points.get(severity, 0)

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
        "total_findings": len(findings)
    }
