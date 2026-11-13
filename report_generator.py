
import json
from pathlib import Path
from datetime import datetime, timezone


def generate_report(findings, risk_summary, output_file):
    """
    Generate a JSON firewall security assessment report.
    """

    report = {
        "tool": "FireChecker",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_findings": risk_summary["total_findings"],
            "risk_score": risk_summary["total_score"],
            "risk_level": risk_summary["risk_level"]
        },
        "findings": findings
    }

    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    return str(output_path)
