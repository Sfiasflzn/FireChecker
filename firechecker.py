
import argparse
import ipaddress
import re
import sys

from config_reader import read_config, parse_acl_rules
from rule_checker import check_acl_rules
from risk_analyzer import calculate_risk
from report_generator import generate_report


def display_banner():
    print("\n===================================")
    print("          FIRECHECKER")
    print("   Firewall Security Assessment")
    print("===================================\n")


def display_legal_disclaimer():
    print("========== LEGAL DISCLAIMER ==========")
    print("FireChecker is an offline firewall configuration")
    print("security assessment tool.")
    print()
    print("This tool does not perform network scanning,")
    print("penetration testing or unauthorized access.")
    print()
    print("Only analyze configuration files that you own")
    print("or have explicit permission to assess.")
    print()
    print("Users must comply with applicable Malaysian laws,")
    print("including the Computer Crimes Act 1997.")
    print("======================================\n")


def validate_scope(scope):
    """
    Validate the supplied audit scope.
    Scope is recorded only. No network scanning is performed.
    """

    scope = scope.strip()

    if not scope:
        raise ValueError("Audit scope cannot be empty.")

    if any(char.isspace() for char in scope):
        raise ValueError("Scope must not contain whitespace.")

    try:
        network = ipaddress.ip_network(scope, strict=False)
        return str(network)

    except ValueError:
        pass

    if re.fullmatch(r"[A-Za-z0-9.-]+", scope):
        if (
            len(scope) <= 253
            and not scope.startswith(".")
            and not scope.endswith(".")
            and ".." not in scope
        ):
            return scope.lower()

    raise ValueError(
        "Invalid scope. Enter an IP address, IP range, "
        "domain or hostname."
    )


def confirm_authorization():
    """
    Ask the user to confirm legal authorization.
    """

    print("AUTHORIZATION CONFIRMATION")
    print("You must have permission to analyze the")
    print("firewall configuration provided.\n")

    confirmation = input(
        "Do you have authorization to perform this audit? (yes/no): "
    ).strip().lower()

    if confirmation != "yes":
        print("\n[STOP] Authorization not confirmed.")
        return False

    return True


def run_firechecker(config_file, scope):
    display_banner()
    display_legal_disclaimer()

    if not confirm_authorization():
        return

    validated_scope = validate_scope(scope)

    print("\n========== AUDIT INFORMATION ==========")
    print(f"Audit scope : {validated_scope}")
    print(f"Config file : {config_file}")
    print("Audit mode  : Offline configuration analysis")
    print("=======================================\n")

    print("[1/4] Reading configuration...")
    config_lines = read_config(config_file)

    print("[2/4] Parsing ACL rules...")
    rules = parse_acl_rules(config_lines)

    print("[3/4] Checking security rules...")
    findings = check_acl_rules(rules)

    print("[4/4] Calculating risk...")
    risk_summary = calculate_risk(findings)

    # Add audit information to the report
    risk_summary["audit_scope"] = validated_scope
    risk_summary["configuration_file"] = config_file
    risk_summary["audit_mode"] = "Offline configuration analysis"

    report_path = generate_report(
        findings,
        risk_summary,
        "output/firechecker_report.json"
    )

    print("\n========== ASSESSMENT RESULT ==========")
    print(f"Configuration   : {config_file}")
    print(f"Audit scope     : {validated_scope}")
    print(f"Total ACL rules : {len(rules)}")
    print(f"Total findings  : {risk_summary['total_findings']}")
    print(f"Risk score      : {risk_summary['total_score']}")
    print(f"Risk level      : {risk_summary['risk_level']}")
    print(f"Report saved    : {report_path}")
    print("=======================================\n")


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="FireChecker - Offline Firewall Security Assessment Tool"
    )

    parser.add_argument(
        "config_file",
        help="Path to the firewall configuration file"
    )

    parser.add_argument(
        "--scope",
        required=True,
        help="Authorized audit scope (IP, IP range, domain or hostname)"
    )

    args = parser.parse_args()

    try:
        run_firechecker(args.config_file, args.scope)

    except KeyboardInterrupt:
        print("\n\n[STOP] FireChecker audit interrupted by user.")
        sys.exit(130)

    except (FileNotFoundError, ValueError, OSError) as error:
        print(f"\n[ERROR] {error}")
        sys.exit(1)
