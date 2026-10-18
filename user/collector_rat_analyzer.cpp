/*
 * collector_rat_analyzer.cpp - See collector_rat_analyzer.h.
 *
 * Scoring model (pure function RatAnalyzerScoreProcess, unit-testable):
 *   - RAT_LOADER_SVCHOST_ABNORMAL_PARENT (+30): svchost.exe whose parent is
 *     not services.exe (svchost is always spawned by the service manager).
 *   - RAT_LOADER_CONHOST_SERVICE_PARENT (+20): conhost.exe whose parent is
 *     services.exe or wininit.exe (hidden-console pattern).
 *   - RAT_LOADER_RUNDLL_ABNORMAL_PARENT (+15): rundll32.exe whose parent is
 *     not one of the ordinary launchers (explorer/cmd/msiexec/script hosts/
 *     services/svchost/wininit).
 *   - RAT_EVASION_<tool> (+10..20): known analysis / anti-debug / anti-VM
 *     utilities that RATs probe for (debuggers, sniffers, process viewers).
 *   - RAT_MASQUERADE_PATH (+35): a protected system basename (svchost.exe,
 *     lsass.exe, winlogon.exe, ...) whose full path is outside the trusted
 *     system directories.
 *   - RAT_USER_WRITABLE_PATH (+15, booster only): the image sits in a
 *     user-writable location (Temp, AppData, ProgramData, Public,
 *     Downloads, Desktop) and at least one other flag already fired.
 *   Score is capped at 100. Verdicts: >= 55 MALICIOUS, >= 30 SUSPICIOUS,
 *   otherwise MONITOR.
 *
 * The scan thread snapshots the process table, resolves the parent image by
 * pid, and resolves the full image path (PROCESS_QUERY_LIMITED_INFORMATION)
 * only when the basename checks already scored or the basename is a
 * protected system name, so handle churn stays bounded. Each process is
 * re-reported at most once per dedup window, or immediately when its score
 * increases. Events are EDR_EVT_RAT_ANALYZER with rat_score / rat_flags /
 * rat_verdict.
 */
#include <windows.h>
#include <tlhelp32.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "collector_rat_analyzer.h"
#include "config.h"
#include "edr_event.h"
#include "event_bus.h"

namespace edr {

namespace {

std::string LowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

std::string BaseName(const std::string& value) {
    size_t slash = value.find_last_of("\\/");
    return LowerAscii(slash == std::string::npos ? value
                                                 : value.substr(slash + 1));
}

bool ContainsAny(const std::string& value,
                 std::initializer_list<const char*> needles) {
    for (const char* needle : needles) {
        if (value.find(needle) != std::string::npos) return true;
    }
    return false;
}

bool IsProtectedSystemName(const std::string& base) {
    static const std::set<std::string> names = {
        "svchost.exe", "conhost.exe", "lsass.exe", "winlogon.exe",
        "services.exe", "csrss.exe", "smss.exe", "wininit.exe",
        "spoolsv.exe", "taskhostw.exe", "dllhost.exe"
    };
    return names.count(base) != 0;
}

bool IsUnderSystemDirectory(const std::string& lowerPath) {
    static const char* const kPrefixes[] = {
        "c:\\windows\\system32\\", "c:/windows/system32/",
        "c:\\windows\\syswow64\\", "c:/windows/syswow64/",
        "c:\\windows\\winsxs\\",   "c:/windows/winsxs/"
    };
    for (const char* prefix : kPrefixes) {
        const size_t length = std::strlen(prefix);
        if (lowerPath.size() >= length &&
            lowerPath.compare(0, length, prefix) == 0)
            return true;
    }
    return false;
}

bool IsUserWritableLocation(const std::string& lowerPath) {
    if (lowerPath.find("\\users\\") != std::string::npos &&
        ContainsAny(lowerPath, {"\\appdata\\", "\\downloads\\",
                                 "\\desktop\\"}))
        return true;
    return ContainsAny(lowerPath, {"\\windows\\temp\\", "c:\\temp\\",
                                    "\\programdata\\"});
}

/* Weighted analysis / anti-debug / anti-VM tool table. */
int AnalysisToolWeight(const std::string& base) {
    static const std::map<std::string, int> kTools = {
        {"taskmgr3g.exe", 20}, {"processhacker.exe", 20},
        {"pchunter.exe", 20}, {"powertool.exe", 20},
        {"wireshark.exe", 15}, {"httpdebugger.exe", 15},
        {"fiddler.exe", 10}, {"procmon.exe", 15},
        {"procmon64.exe", 15}, {"procexp.exe", 15},
        {"procexp64.exe", 15}, {"regmon.exe", 15},
        {"filemon.exe", 15}, {"dbgview.exe", 10},
        {"ntsd.exe", 15}, {"cdb.exe", 15},
        {"windbg.exe", 15}, {"ollydbg.exe", 20},
        {"x64dbg.exe", 20}, {"x32dbg.exe", 20},
        {"ida.exe", 15}, {"ida64.exe", 15},
        {"vmtoolsd.exe", 10}, {"vboxservice.exe", 10},
        {"vboxtray.exe", 10}, {"tcpview.exe", 10},
        {"tcpview64.exe", 10}, {"autoruns.exe", 10},
        {"autoruns64.exe", 10}
    };
    auto found = kTools.find(base);
    return found == kTools.end() ? 0 : found->second;
}

bool IsOrdinaryRundll32Parent(const std::string& parent) {
    static const std::set<std::string> kParents = {
        "explorer.exe", "cmd.exe", "msiexec.exe", "services.exe",
        "svchost.exe", "wininit.exe", "wscript.exe", "cscript.exe",
        "powershell.exe", "pwsh.exe", "wmiprvse.exe"
    };
    return kParents.count(parent) != 0;
}

uint64_t Now100ns() {
    FILETIME ft = {};
    GetSystemTimePreciseAsFileTime(&ft);
    return (static_cast<uint64_t>(ft.dwHighDateTime) << 32) |
           ft.dwLowDateTime;
}

} // namespace

/* ---- Pure helpers (unit-testable) ------------------------------------- */

RatScoreResult RatAnalyzerScoreProcess(const std::string& image,
                                       const std::string& parentImage,
                                       const std::string& fullPath) {
    RatScoreResult result;
    const std::string base = BaseName(image);
    if (base.empty()) return result;

    if (base == "svchost.exe" && !parentImage.empty() &&
        parentImage != "services.exe") {
        result.score += 30;
        result.flags.push_back("RAT_LOADER_SVCHOST_ABNORMAL_PARENT");
    }
    if (base == "conhost.exe" &&
        (parentImage == "services.exe" || parentImage == "wininit.exe")) {
        result.score += 20;
        result.flags.push_back("RAT_LOADER_CONHOST_SERVICE_PARENT");
    }
    if (base == "rundll32.exe" && !parentImage.empty() &&
        !IsOrdinaryRundll32Parent(parentImage)) {
        result.score += 15;
        result.flags.push_back("RAT_LOADER_RUNDLL_ABNORMAL_PARENT");
    }

    const int toolWeight = AnalysisToolWeight(base);
    if (toolWeight > 0) {
        result.score += toolWeight;
        result.flags.push_back("RAT_EVASION_" + base);
    }

    /* Masquerade: protected system basename running outside system dirs. */
    if (IsProtectedSystemName(base) && !fullPath.empty() &&
        !IsUnderSystemDirectory(LowerAscii(fullPath))) {
        result.score += 35;
        result.flags.push_back("RAT_MASQUERADE_PATH");
    }

    /* User-writable placement is a booster, never a standalone trigger. */
    if (result.score > 0 && !fullPath.empty() &&
        IsUserWritableLocation(LowerAscii(fullPath))) {
        result.score += 15;
        result.flags.push_back("RAT_USER_WRITABLE_PATH");
    }

    if (result.score > 100) result.score = 100;
    return result;
}

const char* RatAnalyzerVerdict(int score) {
    if (score >= 55) return "MALICIOUS";
    if (score >= 30) return "SUSPICIOUS";
    return "MONITOR";
}

/* ---- Collector -------------------------------------------------------- */

namespace {

struct ProcessInfo {
    std::string image;   /* lowercase basename */
    uint32_t ppid = 0;
};

class RatAnalyzerCollector : public ICollector {
public:
    explicit RatAnalyzerCollector(const RatAnalyzerConfig& cfg)
        : m_cfg(cfg) {}
    ~RatAnalyzerCollector() override { Stop(); }

    bool Start(EventBus* bus) override {
        if (m_thread.joinable()) return true;
        if (bus == nullptr) return false;
        m_bus = bus;
        m_stop.store(false);
        try {
            m_thread = std::thread(&RatAnalyzerCollector::Run, this);
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
    }

private:
    /* Full image path for a pid; empty when unavailable. */
    static std::string ImagePathForPid(DWORD pid) {
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                                     FALSE, pid);
        if (!process) return std::string();
        wchar_t buffer[MAX_PATH * 4] = {};
        DWORD size = static_cast<DWORD>(std::size(buffer));
        std::string result;
        if (QueryFullProcessImageNameW(process, 0, buffer, &size)) {
            result = WideToUtf8(buffer, size);
        }
        CloseHandle(process);
        return result;
    }

    void ScanOnce() {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return;

        std::map<DWORD, ProcessInfo> processes;
        PROCESSENTRY32W entry = {};
        entry.dwSize = sizeof(entry);
        if (Process32FirstW(snap, &entry)) {
            do {
                ProcessInfo info;
                info.image = LowerAscii(WideToUtf8(entry.szExeFile));
                info.ppid = entry.th32ParentProcessID;
                processes[entry.th32ProcessID] = info;
            } while (Process32NextW(snap, &entry) && !m_stop.load());
        }
        CloseHandle(snap);

        const uint64_t now = Now100ns();
        const uint64_t dedup100ns =
            static_cast<uint64_t>(m_cfg.dedupWindowSeconds) * 10000000ULL;

        for (const auto& item : processes) {
            if (m_stop.load()) break;
            const DWORD pid = item.first;
            const ProcessInfo& info = item.second;
            if (info.image.empty() || pid == 0) continue;

            const std::string parentImage = [&]() -> std::string {
                auto found = processes.find(info.ppid);
                return found == processes.end() ? std::string()
                                                : found->second.image;
            }();

            /* Resolve the path only when the basename checks could matter:
             * already scored by basename (booster) or a protected system
             * name (masquerade check). Bounded handle churn. */
            const RatScoreResult basenameScore =
                RatAnalyzerScoreProcess(info.image, parentImage, "");
            std::string fullPath;
            if (basenameScore.score > 0 || IsProtectedSystemName(info.image)) {
                fullPath = LowerAscii(ImagePathForPid(pid));
            }

            RatScoreResult scored =
                RatAnalyzerScoreProcess(info.image, parentImage, fullPath);
            if (scored.score < static_cast<int>(m_cfg.minScore)) continue;

            /* Dedup: re-report only after the window, or on score increase. */
            auto seen = m_lastSeen.find(pid);
            if (seen != m_lastSeen.end() &&
                now >= seen->second.lastEmit100ns &&
                now - seen->second.lastEmit100ns <= dedup100ns &&
                scored.score <= seen->second.lastScore) {
                continue;
            }

            std::string flags;
            for (const std::string& flag : scored.flags) {
                if (!flags.empty()) flags += ",";
                flags += flag;
            }

            Event ev;
            ev.type = EDR_EVT_RAT_ANALYZER;
            ev.ts100ns = now;
            ev.pid = pid;
            ev.ppid = info.ppid;
            ev.source = "rat_analyzer";
            ev.fields[field::kSource] = ev.source;
            ev.fields[field::kType] = "RAT_ANALYZER";
            ev.fields[field::kImage] = info.image;
            if (!fullPath.empty()) ev.fields[field::kRatImagePath] = fullPath;
            if (!parentImage.empty()) ev.fields[field::kRatParentImage] = parentImage;
            ev.fields[field::kRatScore] = std::to_string(scored.score);
            ev.fields[field::kRatFlags] = flags;
            ev.fields[field::kRatVerdict] = RatAnalyzerVerdict(scored.score);
            if (m_bus) m_bus->Push(ev);

            LastSeen& state = m_lastSeen[pid];
            state.lastEmit100ns = now;
            state.lastScore = scored.score;
            if (m_lastSeen.size() > m_cfg.stateCapacity)
                m_lastSeen.erase(m_lastSeen.begin());
        }
    }

    void Run() {
        while (!m_stop.load()) {
            ScanOnce();
            for (uint32_t t = 0; t < m_cfg.scanIntervalSeconds * 10 &&
                                !m_stop.load(); ++t) {
                Sleep(100);
            }
        }
    }

    struct LastSeen {
        uint64_t lastEmit100ns = 0;
        int lastScore = 0;
    };

    RatAnalyzerConfig m_cfg;
    EventBus* m_bus = nullptr;
    std::thread m_thread;
    std::atomic<bool> m_stop{false};
    std::map<DWORD, LastSeen> m_lastSeen;
};

} // namespace

ICollector* CreateRatAnalyzerCollector(const RatAnalyzerConfig& cfg) {
    return new RatAnalyzerCollector(cfg);
}

} // namespace edr
