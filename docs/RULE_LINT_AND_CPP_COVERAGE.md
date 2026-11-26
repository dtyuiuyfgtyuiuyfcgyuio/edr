# Rule lint baseline and C++ coverage

## Rule lint warning baseline

The current production catalog has 526 rules and 23 lint warnings. It includes 9 score-band warnings, 12 ATT&CK metadata warnings, and 2 compatibility-ID warnings. The reviewed `(rule ID, warning code)` pairs and their evidence are in `scripts/rule_lint_warning_baseline.json`.

No rule JSON was changed for this baseline. The current score bands either have explicit rule/source evidence, or their emitted-value range is wider than the specific 50–54 lint overlap. Tightening a regex based only on the linter suggestion could change behavior for supported scores or imply a new discrete-score contract. ATT&CK metadata was left empty where no mapping is established in the rule text; IDs are retained where tests or comments establish compatibility.

Run the baseline gate from the repository root after building `edr_rule_lint`:

```sh
python scripts/test_rule_lint_baseline.py
python scripts/check_rule_lint_baseline.py \
  --baseline scripts/rule_lint_warning_baseline.json -- \
  build/edr_rule_lint rules/rules.json --json
```

On Windows, replace the executable path with `build-ci/edr_rule_lint.exe`. The gate requires valid linter JSON, a successful linter exit, and no lint errors. It fails for any newly observed `(ruleId, code)` warning pair; a known pair may disappear without updating the baseline. New warnings must be reviewed and have a reason before the baseline is expanded.

## Windows coverage report

The PowerShell collector uses OpenCppCoverage 0.9.9.0 to report lines in `user/` and `common/` reached by `edr_native_tests`. It runs CTest under the coverage process with child tracking, and emits Cobertura XML plus HTML. The tool's CLI supports repeated `--sources`/`--modules` options and multiple export formats; this repository script passes each source root as its own option.

OpenCppCoverage can be installed on a hosted Windows runner with the pinned Chocolatey package:

```powershell
choco install opencppcoverage --version=0.9.9.0 --yes --no-progress
```

The native test executable must be built with Debug PDB information. The existing CI Release build does not guarantee those symbols. Use a separate Debug build directory for coverage (or reconfigure the existing build after its Release tests have completed), then build `edr_native_tests` and run:

```powershell
cmake -S . -B build-ci-coverage -G Ninja `
  -DCMAKE_BUILD_TYPE=Debug -DCMAKE_SYSTEM_VERSION=10.0.22621.0 `
  -DEDR_IMONITOR=OFF -DBUILD_TESTING=ON
cmake --build build-ci-coverage --target edr_native_tests --parallel 4
ctest --test-dir build-ci-coverage -N
./scripts/collect_cpp_coverage.ps1 `
  -BuildDirectory build-ci-coverage `
  -OutputDirectory "$env:RUNNER_TEMP\edr-cpp-coverage"
```

The report is observational. The Windows workflow collects it in a separate job on manual runs. The job uploads XML and HTML from `RUNNER_TEMP` as a CI artifact. The build and test gates run on their normal schedule.

## Portable Linux coverage probe

Use GCC/gcov to measure the platform-neutral event bus and rule lint units.

```sh
bash scripts/collect_portable_cpp_coverage.sh "${TMPDIR:-/tmp}/edr-portable-cpp-coverage"
```

The script builds and runs both unit suites, then writes `summary.txt` and per-source `.gcov` files to the requested output directory. Both suites passed in the Linux baseline run. GCC reported 38.21% of 390 instrumented lines for `event_bus.cpp` and 85.57% of 298 for `rule_lint.cpp`. The Windows coverage report is collected separately.

Tool references: [OpenCppCoverage command-line reference](https://github.com/OpenCppCoverage/OpenCppCoverage/wiki/Command-line-reference) documents repeated source/module filters, child process collection, and Cobertura/HTML exports. [Release 0.9.9.0](https://github.com/OpenCppCoverage/OpenCppCoverage/releases/tag/release-0.9.9.0) and the [Chocolatey package](https://community.chocolatey.org/packages/opencppcoverage/0.9.9.0) provide the pinned Windows tool build.
