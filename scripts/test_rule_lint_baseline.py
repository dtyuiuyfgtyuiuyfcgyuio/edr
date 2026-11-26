import unittest

from check_rule_lint_baseline import check_report


class RuleLintBaselineTests(unittest.TestCase):
    def setUp(self):
        self.baseline = {
            "version": 1,
            "warnings": [
                {"rule_id": "EDR-010", "code": "band_leak", "reason": "known"},
                {"rule_id": "EDR-020", "code": "bad_mitre", "reason": "known"},
            ],
        }

    def test_accepts_known_warnings_and_disappearance(self):
        report = {
            "errorCount": 0,
            "warningCount": 1,
            "issues": [
                {"severity": "warning", "ruleId": "EDR-020", "code": "bad_mitre"}
            ],
        }
        self.assertEqual(check_report(report, self.baseline), [])

    def test_rejects_new_rule_code_pair_even_if_total_is_unchanged(self):
        report = {
            "errorCount": 0,
            "warningCount": 2,
            "issues": [
                {"severity": "warning", "ruleId": "EDR-010", "code": "band_leak"},
                {"severity": "warning", "ruleId": "EDR-030", "code": "over_match"},
            ],
        }
        errors = check_report(report, self.baseline)
        self.assertEqual(len(errors), 1)
        self.assertIn("EDR-030", errors[0])
        self.assertIn("over_match", errors[0])

    def test_rejects_lint_errors(self):
        report = {
            "errorCount": 1,
            "warningCount": 0,
            "issues": [
                {"severity": "error", "ruleId": "EDR-040", "code": "bad_regex"}
            ],
        }
        self.assertTrue(any("error" in error.lower() for error in
                            check_report(report, self.baseline)))

    def test_rejects_warning_count_inconsistent_with_issue_list(self):
        report = {
            "errorCount": 0,
            "warningCount": 1,
            "issues": [],
        }
        with self.assertRaises(ValueError):
            check_report(report, self.baseline)

    def test_rejects_duplicate_baseline_keys(self):
        bad_baseline = {
            "version": 1,
            "warnings": [
                {"rule_id": "EDR-010", "code": "band_leak", "reason": "one"},
                {"rule_id": "EDR-010", "code": "band_leak", "reason": "two"},
            ],
        }
        with self.assertRaises(ValueError):
            check_report({"errorCount": 0, "issues": []}, bad_baseline)


if __name__ == "__main__":
    unittest.main()
