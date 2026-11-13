
from pathlib import Path

from config_reader import read_config, parse_acl_rules
from rule_checker import check_acl_rules
from risk_analyzer import calculate_risk
from report_generator import generate_report


def run_firechecker(config_file):
    print("\n===================================")
    print("          FIRECHECKER")
    print("   Firewall Security Assessment")
    print("===================================\n")

    try:
        # Step 1: Read configuration
        print("[1/4] Reading configuration...")
        config_lines = read_config(config_file)

        # Step 2: Parse ACL rules
        print("[2/4] Parsing ACL rules...")
        rules = parse_acl_rules(config_lines)

        # Step 3: Check security issues
        print("[3/4] Checking security rules...")
        findings = check_acl_rules(rules)

        # Step 4: Calculate risk
        risk_summary = calculate_risk(findings)

        # Generate report
        report_path = generate_report(
            findings,
            risk_summary,
            "output/firechecker_report.json"
        )

        print("\n========== ASSESSMENT RESULT ==========")
        print(f"Total ACL rules : {len(rules)}")
        print(f"Total findings  : {risk_summary['total_findings']}")
        print(f"Risk score      : {risk_summary['total_score']}")
        print(f"Risk level      : {risk_summary['risk_level']}")
        print(f"Report saved    : {report_path}")
        print("=======================================\n")

    except (FileNotFoundError, ValueError, OSError) as error:
        print(f"\n[ERROR] {error}")


if __name__ == "__main__":
    run_firechecker("samples/safe_acl.txt")
