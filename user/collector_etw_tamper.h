/*
 * collector_etw_tamper.h - ETW tampering / telemetry-impairment collector.
 *
 * Watches for defense-evasion that kills or weakens ETW-based telemetry:
 *   - session_stopped:      one of the agent's own ETW trace sessions
 *                           (EDR-Proctrace-*, EDR-NetTrace-*, EDR-DnsTrace-*,
 *                           EDR-PipeTrace-<pid>) was stopped or torn down.
 *   - provider_disabled:    a protected defensive ETW provider (PowerShell
 *                           4104, Sysmon, AMSI, kernel process/network, DNS,
 *                           Defender) that was previously enabled is now
 *                           disabled system-wide.
 *   - etw_event_write_patched: a process's ntdll.dll EtwEventWrite prologue
 *                           no longer matches the pristine copy, the classic
 *                           patchETW / memory-ETW-bypass indicator.
 *
 * The collector is a bounded poll thread; all three checks run on one poll
 * interval. Every signal is emitted as an EDR_EVT_ETW_TAMPER event carrying
 * field::kEtwTamperType. Pure classification helpers are exposed for unit
 * tests (they require no live ETW state).
 */
#ifndef EDR_COLLECTOR_ETW_TAMPER_H
#define EDR_COLLECTOR_ETW_TAMPER_H

#include <cstdint>
#include <string>
#include <vector>

#include "collector.h"

namespace edr {

struct EtwTamperConfig {
    uint32_t pollMs = 30000;             /* poll interval (ms); config key etw_tamper_poll_ms */
    std::vector<std::string> protectedGuids; /* provider GUIDs to watch for disable */
    bool watchSessions = true;           /* watch the agent's own EDR-* ETW sessions */
    bool scanProcesses = false;          /* ntdll EtwEventWrite patch scan (opt-in) */
    std::vector<std::string> skipImages; /* process base names to skip in the patch scan */
};

/* Factory. Returns an ICollector that never blocks Start (false = unavailable). */
ICollector* CreateEtwTamperCollector(const EtwTamperConfig& cfg);

/* ---- Pure helpers (unit-testable, no ETW state) ------------------------ */

/* Friendly display name for well-known provider GUIDs; empty when unknown.
 * Accepts "{...}" or bare "xxxxxxxx-..." case-insensitively. */
std::string EtwTamperGuidToName(const std::string& guid);

/* True when the observed EtwEventWrite prologue differs from the pristine
 * copy. An empty pristine (could not be read) is treated as "no baseline"
 * and never reports a patch. */
bool EtwEventWriteLooksPatched(const std::vector<uint8_t>& observed,
                               const std::vector<uint8_t>& pristine);

/* Lowercase hex encoding of raw bytes (used for prologue fingerprints). */
std::string EtwTamperHexBytes(const uint8_t* data, size_t byteCount);

/* True when a trace session name is one of the agent's own ETW sessions for
 * the given agent pid (EDR-Proctrace-<pid>, EDR-NetTrace-<pid>,
 * EDR-DnsTrace-<pid>, EDR-PipeTrace-<pid>). Case-insensitive. */
bool EtwTamperIsAgentSession(const std::wstring& sessionName, uint32_t agentPid);

} // namespace edr

#endif /* EDR_COLLECTOR_ETW_TAMPER_H */
