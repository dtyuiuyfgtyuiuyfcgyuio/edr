#include "rule_lint.h"

#include <iostream>
#include <string>

int main(int argc, char** argv) {
    if ((argc != 2 && argc != 3) ||
        (argc == 3 && std::string(argv[2]) != "--json")) {
        std::cerr << "usage: edr_rule_lint <path> [--json]\n";
        return 2;
    }
    edr::RuleLintReport report;
    std::string fatal;
    const bool parsed = edr::LintRulesFile(argv[1], &report, &fatal);
    std::cout << edr::FormatRuleLintReport(report, argc == 3) << '\n';
    return parsed && report.errorCount == 0 ? 0 : 1;
}
