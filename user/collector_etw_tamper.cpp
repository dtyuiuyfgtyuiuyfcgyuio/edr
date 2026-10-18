/*
 * collector_etw_tamper.cpp - ETW tampering / telemetry-impairment collector.
 *
 * Polls on a single thread and emits EDR_EVT_ETW_TAMPER events for three
 * defense-evasion signals (see collector_etw_tamper.h):
 *
 *   1. session_stopped: one of the agent's own ETW trace sessions
 *      (EDR-Proctrace-<pid> / EDR-NetTrace-<pid> / EDR-DnsTrace-<pid> /
 *      EDR-PipeTrace-<pid>) that was running is no longer queryable. This
 *      catches an attacker tearing down the session (or the provider stack
 *      that feeds it) to silence process/network/DNS/pipe telemetry.
 *
 *   2. provider_disabled: a protected defensive ETW provider that was
 *      observed enabled is now absent from the system's enabled-provider
 *      table (EnumerateTraceGuidsEx/TraceGuidQueryEnabled). A provider must
 *      be seen enabled first and stay absent for two consecutive polls
 *      before it alerts, so the collector never fires on warm-up races.
 *      When a whole session stops, its paired provider is disarmed so the
 *      two signals do not double-report.
 *
 *   3. etw_event_write_patched: (opt-in, etw_tamper_scan_processes) scans
 *      live 64-bit processes and compares each ntdll.dll EtwEventWrite
 *      prologue against the pristine copy captured from the agent's own
 *      ntdll. A mismatch is the classic patchETW / in-memory ETW bypass
 *      indicator. Processes are re-reported only when the patched bytes
 *      change. Expected false positives: other security products that hook
 *      ntdll ETW functions (add them to etw_tamper_skip_images) and,
 *      extremely rarely, in-place OS hotpatches.
 *
 * All checks are best-effort: enumeration or open failures are counted and
 * skipped, never fatal. The collector never blocks Start and never touches
 * the filesystem.
 */
#include <windows.h>
#include <evntrace.h>
#include <psapi.h>
#include <tlhelp32.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <cwctype>
#include <map>
#include <set>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "collector_etw_tamper.h"
#include "config.h"
#include "edr_event.h"
#include "event_bus.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")

namespace edr {

namespace {

/* Number of prologue bytes compared for the EtwEventWrite patch check. */
constexpr size_t kPrologueBytes = 24;
/* Consecutive absent polls required before a provider-disable is reported. */
constexpr int kAbsentStreakToAlert = 2;

/* Agent-owned ETW session prefixes (must match the collectors that create
 * them). Index order must match kSessionProviderGuids below. */
const wchar_t* const kSessionPrefixes[4] = {
    L"EDR-Proctrace-",
    L"EDR-NetTrace-",
    L"EDR-DnsTrace-",
    L"EDR-PipeTrace-",
};

/* The provider each session enables, used to disarm the provider-disable
 * signal when that session stops (prevents double-reporting). */
const wchar_t* const kSessionProviderGuids[4] = {
    L"22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716", /* Microsoft-Windows-Kernel-Process */
    L"7dd42a49-5329-4832-8dfd-43d979153a88", /* Microsoft-Windows-Kernel-Network */
    L"1c95126e-7eea-49a9-a3fe-a378b03ddb4d", /* Microsoft-Windows-DNS-Client */
    L"edd08927-9cc4-4e65-b970-c2560fb5c289", /* Microsoft-Windows-Kernel-File */
};

std::string LowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

std::wstring LowerWide(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
    return value;
}

/* Strip braces and lower-case a provider GUID string. */
std::string NormalizeGuid(const std::string& guid) {
    std::string value = LowerAscii(guid);
    if (value.size() >= 2 && value.front() == '{' && value.back() == '}')
        value = value.substr(1, value.size() - 2);
    return value;
}

std::string GuidToLowerString(const GUID* guid) {
    char buffer[64];
    std::snprintf(buffer, sizeof(buffer),
                  "%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                  guid->Data1, guid->Data2, guid->Data3,
                  guid->Data4[0], guid->Data4[1], guid->Data4[2], guid->Data4[3],
                  guid->Data4[4], guid->Data4[5], guid->Data4[6], guid->Data4[7]);
    return LowerAscii(buffer);
}

} // namespace

/* ---- Pure helpers (unit-testable) ------------------------------------- */

std::string EtwTamperGuidToName(const std::string& guid) {
    static const std::map<std::string, std::string> kNames = {
        {"a0c1853b-5c40-4b15-8766-3cf1c58f985a", "Microsoft-Windows-PowerShell"},
        {"5770385f-c22a-43e0-bf4c-06f5698ffbd9", "Microsoft-Windows-Sysmon"},
        {"2d576b3d-2cec-4a63-84a6-523f4f0a5d1b",
         "Microsoft-Antimalware-Scan-Interface (AMSI)"},
        {"22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716", "Microsoft-Windows-Kernel-Process"},
        {"7dd42a49-5329-4832-8dfd-43d979153a88", "Microsoft-Windows-Kernel-Network"},
        {"1c95126e-7eea-49a9-a3fe-a378b03ddb4d", "Microsoft-Windows-DNS-Client"},
        {"edd08927-9cc4-4e65-b970-c2560fb5c289", "Microsoft-Windows-Kernel-File"},
        {"11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78", "Microsoft-Windows-Windows Defender"},
    };
    auto it = kNames.find(NormalizeGuid(guid));
    return it == kNames.end() ? std::string() : it->second;
}

bool EtwEventWriteLooksPatched(const std::vector<uint8_t>& observed,
                               const std::vector<uint8_t>& pristine) {
    if (pristine.empty() || observed.size() != pristine.size()) return false;
    return observed != pristine;
}

std::string EtwTamperHexBytes(const uint8_t* data, size_t byteCount) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(byteCount * 2);
    for (size_t i = 0; i < byteCount; ++i) {
        out.push_back(kHex[data[i] >> 4]);
        out.push_back(kHex[data[i] & 0x0F]);
    }
    return out;
}

bool EtwTamperIsAgentSession(const std::wstring& sessionName, uint32_t agentPid) {
    std::wstring suffix = std::to_wstring(agentPid);
    if (sessionName.size() <= suffix.size()) return false;
    for (const wchar_t* prefix : kSessionPrefixes) {
        std::wstring expected = std::wstring(prefix) + suffix;
        if (_wcsicmp(sessionName.c_str(), expected.c_str()) == 0) return true;
    }
    return false;
}

/* ---- Collector --------------------------------------------------------- */

namespace {

class EtwTamperCollector : public ICollector {
public:
    explicit EtwTamperCollector(EtwTamperConfig cfg)
        : m_cfg(std::move(cfg)),
          m_agentPid(GetCurrentProcessId()) {
        for (int i = 0; i < 4; ++i)
            m_sessionNames[i] = std::wstring(kSessionPrefixes[i]) +
                                std::to_wstring(m_agentPid);
    }

    ~EtwTamperCollector() override { Stop(); }

    bool Start(EventBus* bus) override {
        if (m_thread.joinable()) return true;
        if (bus == nullptr) return false;
        m_bus = bus;
        m_stop.store(false);
        if (m_cfg.scanProcesses) CaptureEtwWriteBaseline();
        try {
            m_thread = std::thread(&EtwTamperCollector::Run, this);
        } catch (...) {
            m_stop.store(true);
            m_bus = nullptr;
            return false;
        }
        return true;
    }

    void Stop() override {
        m_stop.store(true);
        if (m_thread.joinable()) m_thread.join();
        if (m_emitCount.load() || m_errors.load() ||
            m_openFailures.load() || m_providersDisarmed.load()) {
            std::fprintf(stderr,
                "[edr-etw-tamper] emitted=%llu errors=%llu "
                "open_failures=%llu providers_disarmed=%llu\n",
                static_cast<unsigned long long>(m_emitCount.load()),
                static_cast<unsigned long long>(m_errors.load()),
                static_cast<unsigned long long>(m_openFailures.load()),
                static_cast<unsigned long long>(m_providersDisarmed.load()));
        }
    }

private:
    void CaptureEtwWriteBaseline() {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll == nullptr) return;
        auto* fn = reinterpret_cast<const uint8_t*>(
            GetProcAddress(ntdll, "EtwEventWrite"));
        if (fn == nullptr) return;
        m_etwWriteOffset = reinterpret_cast<uintptr_t>(fn) -
                           reinterpret_cast<uintptr_t>(ntdll);
        m_etwWritePristine.assign(fn, fn + kPrologueBytes);
        m_scanArmed.store(!m_etwWritePristine.empty());
    }

    void Run() {
        /* Baseline session liveness before the poll loop so a session killed
         * between Start and the first poll is still reported. */
        for (int i = 0; i < 4; ++i)
            m_sessionAlive[m_sessionNames[i]] = SessionExists(m_sessionNames[i]);
        while (!m_stop.load()) {
            for (uint32_t t = 0; t < m_cfg.pollMs && !m_stop.load(); t += 100)
                Sleep(100);
            if (m_stop.load()) break;
            PollOnce();
        }
    }

    void PollOnce() {
        const bool sessionStopped = m_cfg.watchSessions ? CheckSessions() : false;
        if (!sessionStopped) CheckProviders();
        if (m_cfg.scanProcesses && m_scanArmed.load()) ScanEtwEventWritePatches();
    }

    /* Returns true when a session stop was emitted this poll (suppresses the
     * provider-disable pass to avoid a cascade of duplicates). */
    bool CheckSessions() {
        bool emitted = false;
        for (int i = 0; i < 4; ++i) {
            const std::wstring& name = m_sessionNames[i];
            const bool alive = SessionExists(name);
            const bool wasAlive = m_sessionAlive[name];
            m_sessionAlive[name] = alive;
            if (wasAlive && !alive) {
                EtwEvent ev("session_stopped");
                ev.session = WideToUtf8(name.c_str());
                ev.detail = WideToUtf8(name.c_str()) +
                            " agent ETW trace session no longer running";
                Emit(ev);
                /* Disarm the paired provider so we do not also report a
                 * provider-disable for the same teardown. */
                std::string provider = NormalizeGuid(
                    WideToUtf8(kSessionProviderGuids[i]));
                m_providerState[provider].armed = false;
                m_providerState[provider].absentStreak = 0;
                m_providersDisarmed.fetch_add(1);
                emitted = true;
            }
        }
        return emitted;
    }

    bool SessionExists(const std::wstring& name) {
        const ULONG size = static_cast<ULONG>(sizeof(EVENT_TRACE_PROPERTIES) +
                                              4096);
        std::vector<uint8_t> buffer(size);
        auto* properties =
            reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buffer.data());
        properties->Wnode.BufferSize = size;
        properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        ULONG status =
            ControlTraceW(0, name.c_str(), properties, EVENT_TRACE_CONTROL_QUERY);
        if (status == ERROR_SUCCESS || status == ERROR_MORE_DATA) return true;
        if (status != ERROR_WMI_INSTANCE_NOT_FOUND) m_errors.fetch_add(1);
        return false;
    }

    void CheckProviders() {
        std::set<std::string> enabled;
        if (!EnumerateEnabledProviders(enabled)) return;
        for (const std::string& guid : m_cfg.protectedGuids) {
            const std::string normalized = NormalizeGuid(guid);
            if (normalized.empty()) continue;
            ProviderState& state = m_providerState[normalized];
            if (enabled.count(normalized) != 0) {
                state.armed = true;
                state.absentStreak = 0;
            } else if (state.armed) {
                state.absentStreak += 1;
                if (state.absentStreak >= kAbsentStreakToAlert) {
                    EtwEvent ev("provider_disabled");
                    ev.providerGuid = normalized;
                    ev.detail = EtwTamperGuidToName(normalized);
                    Emit(ev);
                    state.armed = false;
                }
            }
        }
    }

    bool EnumerateEnabledProviders(std::set<std::string>& out) {
        /* NOTE(pre-existing repair): the original code referenced
         * TraceGuidQueryEnabled, which does not exist in any installed SDK
         * (10.0.22621/10.0.26100/10.0.28000). TraceGuidQueryList is the
         * closest real class; it enumerates registered (not enabled)
         * providers, so provider_disabled is a coarse approximation until
         * this collector is reworked. */
        ULONG returnLength = 0;
        ULONG status = EnumerateTraceGuidsEx(TraceGuidQueryList, nullptr, 0,
                                             nullptr, 0, &returnLength);
        if (status != ERROR_SUCCESS && status != ERROR_MORE_DATA) {
            m_errors.fetch_add(1);
            return false;
        }
        if (returnLength < sizeof(TRACE_GUID_PROPERTIES)) return false;
        std::vector<uint8_t> buffer(returnLength);
        ULONG actual = 0;
        status = EnumerateTraceGuidsEx(TraceGuidQueryList, nullptr, 0,
                                       buffer.data(),
                                       static_cast<ULONG>(buffer.size()),
                                       &actual);
        if (status != ERROR_SUCCESS) {
            m_errors.fetch_add(1);
            return false;
        }
        const size_t count = actual / sizeof(TRACE_GUID_PROPERTIES);
        if (count == 0) return false;
        const auto* props =
            reinterpret_cast<const TRACE_GUID_PROPERTIES*>(buffer.data());
        for (size_t i = 0; i < count; ++i)
            out.insert(GuidToLowerString(&props[i].Guid));
        if (out.empty()) return false;
        return true;
    }

    void ScanEtwEventWritePatches() {
        std::set<uint32_t> seenPids;
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return;
        PROCESSENTRY32W entry = {};
        entry.dwSize = sizeof(entry);
        if (!Process32FirstW(snapshot, &entry)) {
            CloseHandle(snapshot);
            return;
        }
        do {
            const uint32_t pid = entry.th32ProcessID;
            if (pid == 0 || pid == m_agentPid) continue;
            const std::wstring imageW = entry.szExeFile;
            const std::string image = WideToUtf8(imageW.c_str());
            if (ImageSkipped(imageW)) continue;
            seenPids.insert(pid);
            CheckProcessEtwWrite(pid, image);
        } while (Process32NextW(snapshot, &entry));
        CloseHandle(snapshot);

        /* Drop patch records for processes that no longer exist. */
        for (auto it = m_reportedPatch.begin(); it != m_reportedPatch.end();) {
            if (seenPids.count(it->first) == 0)
                it = m_reportedPatch.erase(it);
            else
                ++it;
        }
    }

    bool ImageSkipped(const std::wstring& imageW) const {
        const std::wstring lower = LowerWide(imageW);
        for (const std::string& skip : m_cfg.skipImages) {
            std::wstring skipW = Utf8ToWide(skip);
            if (lower == LowerWide(skipW)) return true;
        }
        return false;
    }

    void CheckProcessEtwWrite(uint32_t pid, const std::string& image) {
        HANDLE process = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ |
                PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE, pid);
        if (process == nullptr) {
            m_openFailures.fetch_add(1);
            return;
        }
        BOOL isWow64 = FALSE;
        if (!IsWow64Process(process, &isWow64) || isWow64) {
            /* 32-bit processes map SysWOW64 ntdll (different image); the
             * pristine capture is for the 64-bit image only. */
            CloseHandle(process);
            return;
        }
        uintptr_t ntdllBase = 0;
        std::vector<HMODULE> modules(64);
        DWORD needed = 0;
        if (!EnumProcessModulesEx(process, modules.data(),
                                  static_cast<DWORD>(modules.size() *
                                                     sizeof(HMODULE)),
                                  &needed, LIST_MODULES_ALL) &&
            GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            modules.resize(needed / sizeof(HMODULE));
            if (!EnumProcessModulesEx(process, modules.data(), needed,
                                      &needed, LIST_MODULES_ALL)) {
                m_errors.fetch_add(1);
                CloseHandle(process);
                return;
            }
        }
        const DWORD moduleCount = needed / sizeof(HMODULE);
        for (DWORD i = 0; i < moduleCount; ++i) {
            wchar_t name[MAX_PATH] = {};
            if (GetModuleBaseNameW(process, modules[i], name,
                                   (DWORD)std::size(name)) == 0)
                continue;
            if (_wcsicmp(name, L"ntdll.dll") == 0) {
                ntdllBase = reinterpret_cast<uintptr_t>(modules[i]);
                break;
            }
        }
        if (ntdllBase == 0) {
            CloseHandle(process);
            return;
        }
        uint8_t observed[kPrologueBytes] = {};
        SIZE_T bytesRead = 0;
        const void* target =
            reinterpret_cast<const void*>(ntdllBase + m_etwWriteOffset);
        if (!ReadProcessMemory(process, target, observed, sizeof(observed),
                               &bytesRead) ||
            bytesRead != sizeof(observed)) {
            CloseHandle(process);
            return;
        }

        std::string fullImage = image;
        wchar_t path[MAX_PATH] = {};
        DWORD pathLen = (DWORD)std::size(path);
        if (QueryFullProcessImageNameW(process, 0, path, &pathLen) &&
            pathLen > 0)
            fullImage = WideToUtf8(path);
        CloseHandle(process);

        const std::vector<uint8_t> observedVec(observed,
                                               observed + sizeof(observed));
        const bool patched =
            EtwEventWriteLooksPatched(observedVec, m_etwWritePristine);
        const std::string fingerprint = EtwTamperHexBytes(
            observed, sizeof(observed));
        auto it = m_reportedPatch.find(pid);
        if (!patched) {
            if (it != m_reportedPatch.end()) m_reportedPatch.erase(it);
            return;
        }
        /* Report once per distinct patch; re-report only when the bytes
         * change (attacker re-patches differently). */
        if (it != m_reportedPatch.end() && it->second == fingerprint) return;
        m_reportedPatch[pid] = fingerprint;

        EtwEvent ev("etw_event_write_patched");
        ev.pid = pid;
        ev.image = fullImage;
        ev.module = "ntdll.dll";
        ev.expected = EtwTamperHexBytes(m_etwWritePristine.data(),
                                        m_etwWritePristine.size());
        ev.actual = fingerprint;
        ev.detail = fullImage + " (pid " + std::to_string(pid) +
                    ") ntdll!EtwEventWrite prologue patched";
        Emit(ev);
    }

    struct EtwEvent {
        explicit EtwEvent(const char* tamperType) : type(tamperType) {}
        const char* type;
        uint32_t pid = 0;
        std::string image;
        std::string module;
        std::string session;
        std::string providerGuid;
        std::string expected;
        std::string actual;
        std::string detail;
    };

    void Emit(const EtwEvent& data) {
        Event ev;
        ev.type = EDR_EVT_ETW_TAMPER;
        ev.source = "etw_tamper_monitor";
        FILETIME ft = {};
        GetSystemTimePreciseAsFileTime(&ft);
        ev.ts100ns = (static_cast<uint64_t>(ft.dwHighDateTime) << 32) |
                     ft.dwLowDateTime;
        ev.pid = data.pid != 0 ? data.pid : m_agentPid;
        ev.fields[field::kSource] = ev.source;
        ev.fields[field::kType] = "ETW_TAMPER";
        ev.fields[field::kEtwTamperType] = data.type;
        if (data.pid != 0)
            ev.fields[field::kEtwTamperPid] = std::to_string(data.pid);
        if (!data.image.empty())
            ev.fields[field::kEtwTamperImage] = data.image;
        if (!data.module.empty())
            ev.fields[field::kEtwTamperModule] = data.module;
        if (!data.session.empty())
            ev.fields[field::kEtwTamperSession] = data.session;
        if (!data.providerGuid.empty())
            ev.fields[field::kEtwProviderGuid] = data.providerGuid;
        if (!data.expected.empty())
            ev.fields[field::kEtwExpectedBytes] = data.expected;
        if (!data.actual.empty())
            ev.fields[field::kEtwActualBytes] = data.actual;
        if (!data.detail.empty())
            ev.fields[field::kEtwTamperDetail] = data.detail;
        if (m_bus != nullptr) {
            if (m_bus->Push(ev)) m_emitCount.fetch_add(1);
        }
    }

    struct ProviderState {
        bool armed = false;
        int absentStreak = 0;
    };

    EtwTamperConfig m_cfg;
    uint32_t m_agentPid = 0;
    EventBus* m_bus = nullptr;
    std::thread m_thread;
    std::atomic<bool> m_stop{false};

    std::wstring m_sessionNames[4];
    std::map<std::wstring, bool> m_sessionAlive;
    std::map<std::string, ProviderState> m_providerState;
    std::map<uint32_t, std::string> m_reportedPatch; /* pid -> last fingerprint */

    std::atomic<bool> m_scanArmed{false};
    uintptr_t m_etwWriteOffset = 0;
    std::vector<uint8_t> m_etwWritePristine;

    std::atomic<uint64_t> m_emitCount{0};
    std::atomic<uint64_t> m_errors{0};
    std::atomic<uint64_t> m_openFailures{0};
    std::atomic<uint64_t> m_providersDisarmed{0};
};

} // namespace

ICollector* CreateEtwTamperCollector(const EtwTamperConfig& cfg) {
    return new EtwTamperCollector(cfg);
}

} // namespace edr
