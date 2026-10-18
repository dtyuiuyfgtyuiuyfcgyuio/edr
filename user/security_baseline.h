/*
 * security_baseline.h - Host security configuration baseline check.
 *
 * Reads a set of security-relevant system configurations (Defender status,
 * firewall, UAC, LSA protection, etc.) and prints a human-readable report.
 */
#ifndef EDR_SECURITY_BASELINE_H
#define EDR_SECURITY_BASELINE_H

namespace edr {

/* Run all baseline checks and print the report to stdout. Returns the
 * number of FAIL items (0 = all passed). */
int RunSecurityBaseline();

} // namespace edr

#endif /* EDR_SECURITY_BASELINE_H */
