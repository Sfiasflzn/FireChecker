"""Unit tests for risk_analyzer.py (Module 3).

Run from the project folder with:  python -m unittest discover tests
"""

import os
import sys
import unittest

PROJECT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, PROJECT_DIR)

from config_reader import parse_acl_rules, read_config
from risk_analyzer import (address_prefix, calculate_risk, parse_rule_text,
                           risk_level)
from rule_checker import check_acl_rules


def make_finding(line_number, rule, issue="Test issue"):
    """A finding in the same format rule_checker.py produces."""
    return {"line_number": line_number, "rule": rule, "issue": issue,
            "severity": "High", "recommendation": "placeholder"}


class TestHelpers(unittest.TestCase):
    def test_address_prefix(self):
        self.assertEqual(address_prefix("any"), 0)
        self.assertEqual(address_prefix("host 192.0.2.10"), 32)
        self.assertEqual(address_prefix("192.168.1.0 0.0.0.255"), 24)
        self.assertEqual(address_prefix("10.0.0.0 0.0.255.255"), 16)
        self.assertEqual(address_prefix("not-an-ip"), 0)   # unreadable -> flagged

    def test_parse_rule_text(self):
        fields = parse_rule_text("access-list 101 permit tcp any host 192.0.2.10 eq telnet")
        self.assertEqual(fields["action"], "permit")
        self.assertEqual(fields["protocol"], "tcp")
        self.assertEqual(fields["src"], "any")
        self.assertEqual(fields["dst"], "host 192.0.2.10")
        self.assertEqual(fields["port"], 23)

    def test_risk_level_boundaries(self):
        self.assertEqual(risk_level(70), "High")
        self.assertEqual(risk_level(69), "Medium")
        self.assertEqual(risk_level(40), "Medium")
        self.assertEqual(risk_level(39), "Low")


class TestScoring(unittest.TestCase):
    def test_plan_examples_with_rule_order(self):
        # 8-rule ACL; findings on rules 3, 6 and 7 (lines 3, 6, 7).
        rules = [{"line_number": n, "raw_rule": "x"} for n in range(1, 9)]
        findings = [
            make_finding(3, "permit ip any any"),
            make_finding(6, "permit tcp any any eq 23"),
            make_finding(7, "permit tcp any any eq 23", "Duplicate rule"),
        ]
        summary = calculate_risk(findings, rules)
        scores = {f["line_number"]: (f["risk_score"], f["severity"]) for f in findings}
        self.assertEqual(scores, {3: (85, "High"), 6: (65, "Medium"), 7: (15, "Low")})
        self.assertEqual(summary["severity_counts"], {"High": 1, "Medium": 1, "Low": 1})
        self.assertEqual(summary["risk_level"], "High")
        self.assertEqual([f["line_number"] for f in findings], [3, 6, 7])  # sorted

    def test_recommendations_replace_placeholder(self):
        findings = [make_finding(1, "permit tcp any any eq 23")]
        calculate_risk(findings)
        self.assertIn("SSH", findings[0]["recommendation"])

    def test_narrow_rule_is_low(self):
        findings = [make_finding(1, "permit tcp host 192.0.2.5 host 192.0.2.10 eq 443")]
        calculate_risk(findings)
        self.assertEqual(findings[0]["severity"], "Low")

    def test_deny_rule_scores_zero(self):
        findings = [make_finding(1, "deny ip any any log")]
        calculate_risk(findings)
        self.assertEqual(findings[0]["risk_score"], 0)

    def test_no_findings(self):
        self.assertEqual(calculate_risk([]),
                         {"total_score": 0, "risk_level": "Low", "total_findings": 0,
                          "severity_counts": {"High": 0, "Medium": 0, "Low": 0}})

    def test_invalid_input(self):
        with self.assertRaises(TypeError):
            calculate_risk("not a list")


class TestWithTeamModules(unittest.TestCase):
    """Runs Module 1 -> Module 2 -> Module 3 on the project's sample files."""

    def run_pipeline(self, sample):
        lines = read_config(os.path.join(PROJECT_DIR, "samples", sample))
        rules = parse_acl_rules(lines)
        findings = check_acl_rules(rules)
        return findings, calculate_risk(findings, rules)

    def test_risky_sample(self):
        findings, summary = self.run_pipeline("risky_acl.txt")
        self.assertEqual(summary["total_findings"], 3)
        self.assertEqual(summary["risk_level"], "High")
        for finding in findings:
            for key in ("risk_score", "severity", "score_breakdown", "reason",
                        "recommendation"):
                self.assertIn(key, finding)

    def test_safe_sample(self):
        findings, summary = self.run_pipeline("safe_acl.txt")
        self.assertEqual(summary["total_findings"], 0)
        self.assertEqual(summary["risk_level"], "Low")


if __name__ == "__main__":
    unittest.main()
