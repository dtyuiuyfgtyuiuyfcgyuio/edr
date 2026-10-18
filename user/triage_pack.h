/*
 * triage_pack.h - One-shot, read-only forensic diagnostic export.
 *
 * Inputs are opened with full sharing and never modified. Use while the
 * agent is stopped: ledger windows are bounded by each file's observed
 * size, not a globally consistent snapshot across different files.
 *
 * Layout: redacted config.json, rules_summary.json (count/parse_ok/full
 * source SHA-256), three *.tail.jsonl ledgers, and manifest.json LAST.
 * Manifest version 2 hashes the exported bytes and declares redaction,
 * missing/unreadable inputs, source line counts and omitted long lines.
 * These local hashes do not provide an external authenticity anchor.
 */
#ifndef EDR_TRIAGE_PACK_H
#define EDR_TRIAGE_PACK_H

#include <cstddef>
#include <string>

namespace edr {

struct TriageOptions {
    /* Config structure and numeric/boolean switches; ALL string values and
     * credential-named fields are redacted, including URL strings and future
     * string options. Invalid/non-object/deep config fails closed. Diagnostic
     * output is not a restorable configuration. Ledgers may still contain
     * sensitive evidence: control distribution of the resulting pack. */
    std::string configPath;
    /* Hash/count summary only, never copy the rules file. */
    std::string rulesPath;
    std::string alertsPath;
    std::string incidentsPath;
    std::string responseAuditPath;

    /* Required local drive directory. UNC/device paths, alternate streams,
     * drive roots and reparse ancestors are refused. Missing components are
     * created with an owner-only protected DACL. Existing directory ACLs are
     * preserved. Ancestors are pinned without write/delete sharing during
     * export; outputs receive a protected owner-only DACL regardless of
     * directory inheritance. Existing non-input names/output/tmp files are
     * refused; compatible input-ledger directories remain supported. */
    std::string outDir;
    /* Accepted 100..100000; invalid values are errors, not clamped. */
    size_t tailLines = 1000;
};

/* Return zero on success, otherwise fill error and return nonzero.
 * dryRun hashes/inspects inputs and prints the redacted planned manifest;
 * it neither creates the output directory nor writes files.
 *
 * Missing/unreadable input entries remain missing=true, with explicit
 * not_configured/not_found/unreadable reasons. Available ledger windows
 * declare source_lines/status; lines exceeding 16 MiB are omitted entirely
 * and counted in omitted_lines (never emit damaged JSON fragments).
 * Retained lines, including the last line without an EOL, receive an EOL.
 * Config/rules whole-file reads are capped at 64 MiB.
 *
 * CREATE_NEW exclusive handles remain open through OS flush and handle-based
 * no-replace rename. Failures delete only objects created by this invocation
 * via their handles, best-effort. Absence of manifest.json denotes interrupted
 * export; a manifest describes collection limits, not global completeness.
 */
int WriteTriagePack(const TriageOptions& opts, bool dryRun, std::string& error);

} // namespace edr

#endif /* EDR_TRIAGE_PACK_H */
