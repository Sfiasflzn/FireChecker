# FireChecker

**Offline Firewall Configuration Security Assessment Tool**

FireChecker is a Python-based command-line tool designed to analyze firewall configuration files, identify potentially risky Access Control List (ACL) rules, calculate security risk scores, and generate JSON assessment reports.

## 1. Project Overview

FireChecker helps users review firewall configurations through offline security analysis.

### Key Features

- Read firewall configuration files.
- Extract and parse ACL rules.
- Detect potentially risky firewall rules.
- Identify unrestricted traffic access.
- Detect Telnet access and potentially exposed SSH access.
- Calculate security risk scores.
- Generate structured JSON assessment reports.
- Require user authorization before performing an assessment.
- Validate the declared audit scope.

## 2. Security Assessment Category

**Category:** Defensive Security Assessment – Firewall Configuration Analysis.

FireChecker supports defensive security reviews by identifying potentially insecure firewall ACL configurations.

It performs offline configuration analysis and does not conduct active network scanning, exploitation, or penetration testing.

## 3. System Requirements

- Windows, Linux, or macOS
- Python 3.10 or later
- Git (optional, for cloning the repository)

No external Python packages are required. FireChecker uses Python Standard Library modules.

## 4. Installation

Clone the repository:

```bash
git clone https://github.com/Sfiasflzn/FireChecker.git
```

Navigate to the project directory:

```bash
cd FireChecker
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate the virtual environment on Windows:

```powershell
.venv\Scripts\Activate.ps1
```

No additional package installation is necessary.

## 5. Usage

Run FireChecker using the following command:

```bash
python firechecker.py <configuration_file> --scope <authorized_scope>
```

Example:

```bash
python firechecker.py samples/safe_acl.txt --scope 192.168.1.0/24
```

The tool will:

1. Display the legal disclaimer.
2. Request authorization confirmation.
3. Validate the supplied audit scope.
4. Read the firewall configuration.
5. Parse ACL rules.
6. Check for potentially risky rules.
7. Calculate the risk score.
8. Generate a JSON assessment report.

The user must enter `yes` to confirm authorization before the assessment proceeds.

To view available command-line options:

```bash
python firechecker.py --help
```

## 6. Risk Assessment

FireChecker uses a custom severity-based scoring model.

| Severity | Score |
|---|---:|
| Critical | 15 |
| High | 10 |
| Medium | 5 |
| Low | 2 |

### Risk Classification

| Risk Score | Risk Level |
|---|---|
| 0–4 | Low |
| 5–9 | Medium |
| 10–19 | High |
| 20 and above | Critical |

These thresholds are project-defined assessment heuristics and are not an industry-standard risk rating.

## 7. Output Reports

Assessment reports are generated in JSON format.

**Default output location:**

```text
output/firechecker_report.json
```

The report contains:

- Assessment timestamp
- Audit scope
- Configuration file information
- Assessment mode
- Total findings
- Risk score and risk level
- Severity breakdown
- Detailed security findings and recommendations

Generated reports and uploaded configuration files are excluded from Git tracking by default.

## 8. Ethical Guidelines

FireChecker is designed for authorized defensive security assessment.

Users must:

- Only analyze firewall configurations they own or have explicit permission to assess.
- Obtain authorization before conducting an audit.
- Define the intended audit scope.
- Follow applicable laws and organizational security policies.
- Avoid unauthorized access, exploitation, or network activities.

**Legal Disclaimer:** Users are responsible for ensuring compliance with applicable Malaysian laws, including the Computer Crimes Act 1997.

FireChecker does not establish ownership or authorization merely by validating an audit scope.

## 9. Rules of Engagement (RoE)

Before conducting an assessment:

1. Obtain explicit permission from the system or configuration owner.
2. Define the authorized audit scope.
3. Analyze only configuration files within the authorized assessment.
4. Do not perform unauthorized network scanning or exploitation.
5. Do not distribute confidential configuration files or assessment reports.
6. Stop the assessment if authorization is withdrawn or an issue occurs.

**Emergency Stop:** Press `Ctrl + C` to interrupt the running process.

## 10. Limitations

- Supports offline firewall configuration analysis only.
- Does not connect to firewall devices.
- Does not perform live network scanning.
- Detection is based on predefined ACL patterns.
- Does not cover every Cisco IOS ACL syntax or firewall configuration format.
- Risk scores are heuristic assessments and should not replace professional security reviews.

## 11. Project Structure

```text
FireChecker/
├── samples/
│   ├── safe_acl.txt
│   └── risky_acl.txt
├── output/
├── uploads/
├── config_reader.py
├── rule_checker.py
├── risk_analyzer.py
├── report_generator.py
├── firechecker.py
├── requirements.txt
├── README.md
├── LICENSE
└── .gitignore
```

## 12. Responsible Disclosure

If a security issue or software defect is identified, report it privately to the project maintainer through the repository's GitHub contact or issue reporting channel.

Do not publish sensitive configuration files or confidential information.

## 13. License

This project is distributed under the license included in this repository. See the `LICENSE` file for details.
