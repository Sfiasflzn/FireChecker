
import json
from pathlib import Path
from datetime import datetime, timezone


def generate_report(findings, risk_summary, output_file):
    """
    Generate a detailed JSON firewall security assessment report.
    """

    # Validate input
    if not isinstance(findings, list):
        raise ValueError("Findings must be provided as a list.")

    if not isinstance(risk_summary, dict):
        raise ValueError("Risk summary must be a dictionary.")

    required_fields = [
        "total_findings",
        "total_score",
        "risk_level"
    ]

    for field in required_fields:
        if field not in risk_summary:
            raise ValueError(
                f"Missing risk summary field: {field}"
            )

    # Prepare audit report
    report = {
        "tool": "FireChecker",
        "version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),

        "audit": {
            "audit_scope": risk_summary.get(
                "audit_scope", "Not specified"
            ),
            "configuration_file": risk_summary.get(
                "configuration_file", "Not specified"
            ),
            "audit_mode": risk_summary.get(
                "audit_mode",
                "Offline configuration analysis"
            )
        },

        "summary": {
            "total_findings": risk_summary["total_findings"],
            "risk_score": risk_summary["total_score"],
            "risk_level": risk_summary["risk_level"],
            "severity_breakdown": risk_summary.get(
                "severity_breakdown",
                {
                    "Critical": 0,
                    "High": 0,
                    "Medium": 0,
                    "Low": 0
                }
            )
        },

        "findings": findings
    }

    # Prepare output directory
    output_path = Path(output_file)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    # Save JSON report
    try:
        with output_path.open("w", encoding="utf-8") as file:
            json.dump(
                report,
                file,
                indent=4,
                ensure_ascii=False
            )

    except OSError as error:
        raise OSError(
            f"Unable to generate report: {error}"
        )

    return str(output_path)
