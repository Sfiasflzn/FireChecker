
import argparse

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
        print("[1/4] Reading configuration...")
        config_lines = read_config(config_file)

        print("[2/4] Parsing ACL rules...")
        rules = parse_acl_rules(config_lines)

        print("[3/4] Checking security rules...")
        findings = check_acl_rules(rules)

        print("[4/4] Calculating risk...")
        risk_summary = calculate_risk(findings)

        report_path = generate_report(
            findings,
            risk_summary,
            "output/firechecker_report.json"
        )

        print("\n========== ASSESSMENT RESULT ==========")
        print(f"Configuration   : {config_file}")
        print(f"Total ACL rules : {len(rules)}")
        print(f"Total findings  : {risk_summary['total_findings']}")
        print(f"Risk score      : {risk_summary['total_score']}")
        print(f"Risk level      : {risk_summary['risk_level']}")
        print(f"Report saved    : {report_path}")
        print("=======================================\n")

    except (FileNotFoundError, ValueError, OSError) as error:
        print(f"\n[ERROR] {error}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="FireChecker - Firewall Security Assessment Tool"
    )

    parser.add_argument(
        "config_file",
        help="Path to the firewall configuration file"
    )

    args = parser.parse_args()
    run_firechecker(args.config_file)
