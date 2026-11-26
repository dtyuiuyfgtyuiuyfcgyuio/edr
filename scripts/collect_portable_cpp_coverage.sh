#!/usr/bin/env bash
# Linux-only coverage for the event bus and rule lint unit tests.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_dir="${1:-${TMPDIR:-/tmp}/edr-portable-cpp-coverage}"
mkdir -p "$output_dir"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/edr-cpp-coverage.XXXXXX")"
trap 'rm -rf "$work_dir"' EXIT

g++ -std=c++17 -O0 -g --coverage -fprofile-abs-path \
    -I"$repo_root/user" -I"$repo_root/common" -pthread \
    "$repo_root/user/event_bus.cpp" \
    "$repo_root/tests/event_delivery_tests.cpp" \
    -o "$work_dir/event_delivery_tests"
"$work_dir/event_delivery_tests"

g++ -std=c++17 -O0 -g --coverage -fprofile-abs-path \
    -I"$repo_root/user" -I"$repo_root/common" \
    "$repo_root/user/rule_lint.cpp" \
    "$repo_root/tests/rule_lint_test_main.cpp" "$repo_root/tests/rule_lint_tests.cpp" \
    -o "$work_dir/rule_lint_tests"
"$work_dir/rule_lint_tests"

(
    cd "$work_dir"
    gcov -b -c event_delivery_tests-event_bus.gcno rule_lint_tests-rule_lint.gcno > gcov-output.txt
)
cp "$work_dir/event_bus.cpp.gcov" "$work_dir/rule_lint.cpp.gcov" "$output_dir/"
awk '/^File .*\/user\/(event_bus|rule_lint)\.cpp/ { print; if (getline) print }' \
    "$work_dir/gcov-output.txt" > "$output_dir/summary.txt"
cat "$output_dir/summary.txt"
printf 'Line details: %s\n' "$output_dir"
