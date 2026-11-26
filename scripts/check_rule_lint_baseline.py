#!/usr/bin/env python3
"""Reject new (rule ID, warning code) pairs from edr_rule_lint JSON output."""

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Sequence, Set, Tuple


def _warning_keys(rows: Any, *, baseline: bool) -> Set[Tuple[str, str]]:
    label = "baseline warnings" if baseline else "lint warnings"
    if not isinstance(rows, list):
        raise ValueError(f"{label} must be a list")
    keys: Set[Tuple[str, str]] = set()
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"{label}[{index}] must be an object")
        if baseline:
            rule_id, code = row.get("rule_id"), row.get("code")
            if not isinstance(row.get("reason"), str) or not row["reason"].strip():
                raise ValueError(f"{label}[{index}] needs a non-empty reason")
        else:
            rule_id, code = row.get("ruleId"), row.get("code")
        if not isinstance(rule_id, str) or not rule_id.strip():
            raise ValueError(f"{label}[{index}] has no rule ID")
        if not isinstance(code, str) or not code.strip():
            raise ValueError(f"{label}[{index}] has no warning code")
        key = (rule_id, code)
        if key in keys and baseline:
            raise ValueError(f"duplicate {label} key: {rule_id}/{code}")
        keys.add(key)
    return keys


def check_report(report: Any, baseline: Any) -> List[str]:
    """Return violations; baseline entries may disappear but may not grow."""
    if not isinstance(baseline, dict) or baseline.get("version") != 1:
        raise ValueError("baseline must be a version 1 object")
    baseline_keys = _warning_keys(baseline.get("warnings"), baseline=True)
    if not isinstance(report, dict):
        raise ValueError("lint JSON root must be an object")
    issues = report.get("issues")
    if not isinstance(issues, list):
        raise ValueError("lint JSON must contain an issues list")
    if not isinstance(report.get("errorCount"), int):
        raise ValueError("lint JSON must contain an integer errorCount")
    if not isinstance(report.get("warningCount"), int):
        raise ValueError("lint JSON must contain an integer warningCount")
    for index, issue in enumerate(issues):
        if not isinstance(issue, dict):
            raise ValueError(f"lint issues[{index}] must be an object")
        if issue.get("severity") not in {"error", "warning"}:
            raise ValueError(f"lint issues[{index}] has an unknown severity")

    errors = [issue for issue in issues if issue.get("severity") == "error"]
    violations: List[str] = []
    if report["errorCount"] != 0 or errors:
        violations.append(
            f"rule lint reported {report['errorCount']} errors "
            f"({len(errors)} error issue records)"
        )

    warning_rows = [issue for issue in issues if issue.get("severity") == "warning"]
    if report["warningCount"] != len(warning_rows):
        raise ValueError("lint warningCount does not match warning issue records")
    current_keys = _warning_keys(warning_rows, baseline=False)
    additions = sorted(current_keys - baseline_keys)
    for rule_id, code in additions:
        violations.append(f"new rule lint warning: {rule_id}/{code}")
    return violations


def load_json_file(path: Path, description: str) -> Any:
    try:
        with path.open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read {description} {path}: {exc}") from exc


def main(argv: Sequence[str] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument(
        "lint_command", nargs=argparse.REMAINDER,
        help="edr_rule_lint command and arguments, after --",
    )
    args = parser.parse_args(argv)
    command = list(args.lint_command)
    if command and command[0] == "--":
        command.pop(0)
    if not command:
        parser.error("provide edr_rule_lint and its arguments after --")

    try:
        baseline = load_json_file(args.baseline, "baseline")
        completed = subprocess.run(command, check=False, text=True,
                                   encoding="utf-8", capture_output=True)
        if completed.returncode != 0:
            detail = completed.stderr.strip() or completed.stdout.strip()
            raise ValueError(
                f"linter exited with status {completed.returncode}"
                + (f": {detail}" if detail else "")
            )
        try:
            report = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise ValueError(f"linter did not produce valid JSON: {exc}") from exc
        violations = check_report(report, baseline)
    except (OSError, ValueError) as exc:
        print(f"rule lint baseline check failed: {exc}", file=sys.stderr)
        return 1

    if violations:
        for violation in violations:
            print(f"ERROR: {violation}", file=sys.stderr)
        return 1
    known = len(baseline["warnings"])
    current = sum(issue.get("severity") == "warning"
                  for issue in report["issues"] if isinstance(issue, dict))
    print(f"rule lint baseline passed: {current} warnings, {known} known warning keys")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
