import argparse
import inspect
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
SAMPLE_FILE = BASE_DIR / "samples" / "safe_acl.txt"
OUTPUT_DIR = BASE_DIR / "output"


def make_parser():
    parser = argparse.ArgumentParser(
        description="FireChecker: local firewall ACL security audit",
        epilog=(
            "Examples:\n"
            "  python cli_report.py --config samples/safe_acl.txt\n"
            "  python cli_report.py --config samples/risky_acl.txt --dry-run\n"
            "  python cli_report.py --config samples/risky_acl.txt --output risky.json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--config",
        default=str(SAMPLE_FILE),
        help="Path to a local Cisco IOS ACL text file"
    )

    parser.add_argument(
        "--scope",
        default="127.0.0.1",
        help="Approved host/IP range label (no network connection is made)"
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show results without saving a JSON report"
    )

    parser.add_argument(
        "--output",
        default="firechecker_report.json",
        help="JSON filename to save in the output folder"
    )

    return parser


def ask_permission(config_file, scope):
    print("\n=== FIRECHECKER | LEGAL NOTICE ===")
    print("For authorized, offline firewall configuration auditing only.")
    print("Unauthorized access may violate Malaysia's Computer Crimes Act 1997 (Act 563).")
    print("Only assess configurations you own or are allowed to review.")
    print(f"Configuration: {config_file}")
    print(f"Authorized scope: {scope}")
    print("Scope is recorded for confirmation; this tool reads a local file only.")
    print("Original configuration files will not be modified.")

    try:
        response = input("Type YES to confirm authorization: ")
    except EOFError:
        return False

    return response.strip() == "YES"


def report_path(filename):
    if (
        not filename
        or filename in (".", "..")
        or "/" in filename
        or "\\" in filename
        or not filename.lower().endswith(".json")
    ):
        raise ValueError(
            "--output must be a JSON filename, e.g. audit.json"
        )

    return OUTPUT_DIR / filename


def print_results(rules, findings, summary):
    print("\n========= FIRECHECKER RESULTS =========")

    print(f"ACL rules    : {len(rules)}")
    print(f"Findings     : {summary['total_findings']}")
    print(f"Risk score   : {summary['total_score']}")
    print(f"Risk level   : {summary['risk_level']}")

    if not findings:
        print("No issues detected by the current rule checks.")

    else:
        print("\nSecurity findings:")

        for finding in findings:
            number = finding.get("line_number", "?")
            severity = finding.get("severity", "Review")
            issue = finding.get("issue", "Rule needs review")

            print(f"  Line {number} | {severity} | {issue}")

            if finding.get("recommendation"):
                print(
                    f"    Recommendation: {finding['recommendation']}"
                )

    print("=======================================")


def run_audit(config_file, dry_run, output_filename):
    from config_reader import read_config, parse_acl_rules
    from rule_checker import check_acl_rules
    from risk_analyzer import calculate_risk
    from report_generator import generate_report

    print("[1/4] Reading configuration...")
    config_lines = read_config(config_file)

    print("[2/4] Parsing ACL rules...")
    rules = parse_acl_rules(config_lines)

    if not rules:
        raise ValueError(
            "No supported ACL rules found in the configuration."
        )

    print("[3/4] Checking firewall rules...")
    findings = check_acl_rules(rules)

    print("[4/4] Calculating risk...")

    if "rules" in inspect.signature(calculate_risk).parameters:
        summary = calculate_risk(findings, rules=rules)
    else:
        summary = calculate_risk(findings)

    print_results(rules, findings, summary)

    if dry_run:
        print("[DRY RUN] Results displayed. No report saved.")

    else:
        saved_file = generate_report(
            findings,
            summary,
            str(report_path(output_filename))
        )

        print(f"JSON report saved: {saved_file}")

    return summary


def main(argv=None):
    arguments = make_parser().parse_args(argv)

    try:
        report_path(arguments.output)

        if not ask_permission(arguments.config, arguments.scope):
            print("[CANCELLED] Authorization was not confirmed.")
            return 1

        run_audit(
            arguments.config,
            arguments.dry_run,
            arguments.output
        )

        return 0

    except KeyboardInterrupt:
        print("\n[STOPPED] Audit cancelled by Ctrl+C.")
        return 130

    except (
        FileNotFoundError,
        ValueError,
        OSError,
        UnicodeError,
        ModuleNotFoundError
    ) as error:

        print(f"[ERROR] {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
