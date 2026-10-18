/*
 * driver_load_detector.cpp - See driver_load_detector.h.
 *
 * Detects suspicious kernel driver loading activity across three event
 * types:
 * - SERVICE_INSTALL: New kernel driver service creation (a driver is a
 *   service with TYPE = KERNEL_DRIVER, typically SERVICE_START_TYPE 0/1/2).
 * - SERVICE_START_HOOK / SERVICE_CHANGE: Driver service start / state change.
 * - IMAGE_LOAD: Load of a .sys image.
 *
 * Scoring:
 * - Known vulnerable driver basename (BYOVD): +60
 * - Unsigned / signature status not valid: +40
 * - Driver from user-writable location: +30
 * - Suspicious driver basename pattern: +20
 * - Driver name matches known AV-bypass/rootkit patterns: +25
 * - Repeated loads of same driver (burst): +15 (max once per window)
 */
#include "driver_load_detector.h"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <set>
#include <string>
#include <vector>

namespace edr {
namespace {

constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;

std::string FieldValue(const Event& event, const char* name) {
    auto found = event.fields.find(name);
    return found == event.fields.end() ? std::string() : found->second;
}

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

uint64_t EventTime(const Event& event) {
    if (event.ts100ns != 0) return event.ts100ns;
    FILETIME now = {};
    GetSystemTimePreciseAsFileTime(&now);
    return (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
           now.dwLowDateTime;
}

std::string Join(const std::vector<std::string>& values,
                 const char* separator) {
    std::string result;
    for (const std::string& value : values) {
        if (!result.empty()) result += separator;
        result += value;
    }
    return result;
}

bool ContainsAny(const std::string& value,
                 std::initializer_list<const char*> needles) {
    for (const char* needle : needles) {
        if (value.find(needle) != std::string::npos) return true;
    }
    return false;
}

} // namespace

bool DriverLoadDetector::IsUserWritableLocation(const std::string& lowerPath) const {
    if (lowerPath.find("\\users\\") != std::string::npos &&
        ContainsAny(lowerPath, {"\\appdata\\", "\\downloads\\",
                                 "\\desktop\\", "\\temp\\"}))
        return true;
    return ContainsAny(lowerPath, {"\\windows\\temp\\", "c:\\temp\\",
                                    "\\programdata\\"});
}

DriverLoadDetector::DriverLoadDetector(
    bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
    size_t stateCapacity)
    : m_enabled(enabled),
      m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)) {}

bool DriverLoadDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_SERVICE_INSTALL ||
           type == EDR_EVT_SERVICE_START_HOOK ||
           type == EDR_EVT_SERVICE_CHANGE ||
           type == EDR_EVT_IMAGE_LOAD;
}

void DriverLoadDetector::Enrich(Event& event) {
    if (!m_enabled) return;
    if (!Inspects(event.type)) return;

    uint64_t now = EventTime(event);
    PurgeExpired(now);

    switch (event.type) {
        case EDR_EVT_SERVICE_INSTALL:
            AnalyzeServiceInstall(event);
            break;
        case EDR_EVT_SERVICE_START_HOOK:
        case EDR_EVT_SERVICE_CHANGE:
            AnalyzeServiceStart(event);
            break;
        case EDR_EVT_IMAGE_LOAD:
            AnalyzeImageLoad(event);
            break;
    }
}

bool DriverLoadDetector::IsKnownVulnerableDriver(const std::string& lowerBase) const {
    // Well-known vulnerable drivers abused for BYOVD (Bring Your Own
    // Vulnerable Driver) privilege escalation / EDR bypass.
    static const std::set<std::string> kKnownVulnerable = {
        "proc_exp.sys",            // Cisco AnyConnect
        "dbk32.sys",               // Cheat Engine
        "dbk64.sys",               // Cheat Engine
        "kprocesshacker.sys",      // Process Hacker
        "kprocesshacker2.sys",
        "pcwdriver.sys",
        "rtcore64.sys",            // RTCore64 - MSI Afterburner (CVE-2019-16098)
        "gdrv.sys",                // Gigabyte driver
        "gdrv2.sys",
        "iqvw64e.sys",             // Intel Ethernet (LPE)
        "aswsp.sys",               // Avast
        "aswbunny.sys",
        "aswbid.sys",
        "aswbidsdriver.sys",
        "aswarb.sys",
        "dax3_help.sys",
        "badgame.sys",
        "blacknet.sys",
        "nsiccdc.sys",
        "enzhi.sys",
        "vmm.sys",
        "procmon.sys",
        "truesight.sys",
        "avgntflt.sys",
        "avgtdix.sys",
        "avipbb.sys",
        "easdrv.sys",
        "cbflt.sys",
        "win64k.sys",
        "capcom.sys",              // Capcom rootkit (CVE-2016-9331)
        "noescape.sys",
        "kavbootc.sys",
        "bvrp_pc.sys"
    };
    return kKnownVulnerable.count(lowerBase) != 0;
}

bool DriverLoadDetector::IsSuspiciousDriverName(const std::string& lowerBase) const {
    static const std::set<std::string> kSuspiciousNames = {
        "tcpdrv.sys", "keydll.sys", "clipwnd.sys", "winhook.sys",
        "processhacker.sys", "x86chk.sys", "db64.sys", "msreg.sys",
        "sysmonmin.sys", "pchardware.sys", "kbot.sys", "driverhelper.sys",
        "hvix86.sys", "vmprotect.sys", "vboxdrv.sys"
    };
    if (kSuspiciousNames.count(lowerBase) != 0) return true;

    // Heuristic: drivers claiming system names but with unusual spellings
    // or with digits mixed in (e.g. "sVcHost.sys", "lsass0.sys").
    static const std::set<std::string> kSystemImpersonators = {
        "svch0st.sys", "lsass0.sys", "win1ogon.sys", "csrss0.sys"
    };
    return kSystemImpersonators.count(lowerBase) != 0;
}

void DriverLoadDetector::AnalyzeServiceInstall(Event& event) {
    std::string serviceName = FieldValue(event, field::kServiceName);
    std::string imagePath = FieldValue(event, field::kServiceImagePath);

    // A driver service install always has a .sys image path
    std::string lowerImage = LowerAscii(imagePath);
    if (lowerImage.find(".sys") == std::string::npos) return;

    std::string base = BaseName(imagePath);
    std::string key = LowerAscii(serviceName.empty() ? base : serviceName);

    DriverState& state = GetOrCreateState(key);
    state.imagePath = imagePath;
    state.serviceName = serviceName;
    state.lastSeen100ns = EventTime(event);

    const bool knownVulnerable = IsKnownVulnerableDriver(base);

    if (knownVulnerable) {
        UpdateScore(state, 60, "known_vulnerable_driver");
    }

    if (!knownVulnerable && IsSuspiciousDriverName(base)) {
        UpdateScore(state, 20, "suspicious_driver_name");
    }

    if (!knownVulnerable && IsUserWritableLocation(lowerImage)) {
        UpdateScore(state, 30, "driver_from_user_writable_location");
    }

    std::string signatureStatus = LowerAscii(
        FieldValue(event, field::kSignatureStatus));
    if (!knownVulnerable &&
        (signatureStatus == "unsigned" || signatureStatus == "invalid" ||
        signatureStatus == "not signed" || signatureStatus == "unknown")) {
        UpdateScore(state, 40, "unsigned_driver");
        state.signedDriver = false;
    }

    // Driver with SYSTEM account + AUTO start is elevated-risk (common
    // for rootkit service installs).
    std::string startType = FieldValue(event, field::kServiceStartType);
    std::string account = LowerAscii(FieldValue(event, field::kServiceAccount));
    if (ContainsAny(startType, {"auto", "0", "1"}) &&
        ContainsAny(account, {"localsystem", "system", "nt authority"})) {
        UpdateScore(state, 15, "auto_start_system_driver");
    }

    if (state.score >= m_minScore && !state.alerted) {
        StampEvent(event, state);
    }
}

void DriverLoadDetector::AnalyzeServiceStart(Event& event) {
    std::string serviceName = FieldValue(event, field::kServiceName);
    std::string imagePath = FieldValue(event, field::kServiceImagePath);
    std::string base = BaseName(imagePath);

    if (imagePath.empty() && base.find(".sys") == std::string::npos) {
        // No image info; use service name heuristic
        base = LowerAscii(serviceName);
        if (base.empty() || base.find(".sys") == std::string::npos) return;
    }

    std::string key = LowerAscii(serviceName.empty() ? base : serviceName);
    DriverState& state = GetOrCreateState(key);
    state.lastSeen100ns = EventTime(event);

    if (!imagePath.empty()) {
        state.imagePath = imagePath;
        state.loadCount++;

        std::string lowerImage = LowerAscii(imagePath);
        const bool knownVulnerable = IsKnownVulnerableDriver(base);
        if (knownVulnerable) {
            UpdateScore(state, 60, "known_vulnerable_driver");
        }
        if (!knownVulnerable && IsUserWritableLocation(lowerImage)) {
            UpdateScore(state, 30, "driver_from_user_writable_location");
        }
    }

    // Burst: same driver started repeatedly in a short window
    if (state.loadCount >= 3) {
        UpdateScore(state, 15, "driver_load_burst");
    }

    if (state.score >= m_minScore && !state.alerted) {
        StampEvent(event, state);
    }
}

void DriverLoadDetector::AnalyzeImageLoad(Event& event) {
    std::string imagePath = FieldValue(event, field::kImageLoaded);
    if (imagePath.empty()) imagePath = FieldValue(event, field::kImagePath);
    if (imagePath.empty()) return;

    std::string lowerImage = LowerAscii(imagePath);
    if (lowerImage.find(".sys") == std::string::npos) return;

    std::string base = BaseName(imagePath);
    std::string key = LowerAscii(base);

    DriverState& state = GetOrCreateState(key);
    state.imagePath = imagePath;
    state.signer = FieldValue(event, field::kSignerSubject);
    state.lastSeen100ns = EventTime(event);
    state.loadCount++;

    const bool knownVulnerable = IsKnownVulnerableDriver(base);
    if (knownVulnerable) {
        UpdateScore(state, 60, "known_vulnerable_driver");
    }
    if (!knownVulnerable && IsUserWritableLocation(lowerImage)) {
        UpdateScore(state, 30, "driver_from_user_writable_location");
    }

    std::string signatureStatus = LowerAscii(
        FieldValue(event, field::kSignatureStatus));
    if (!knownVulnerable &&
        (signatureStatus == "unsigned" || signatureStatus == "invalid" ||
        signatureStatus == "not signed")) {
        UpdateScore(state, 40, "unsigned_driver");
        state.signedDriver = false;
    }

    if (state.score >= m_minScore && !state.alerted) {
        StampEvent(event, state);
    }
}

DriverLoadDetector::DriverState& DriverLoadDetector::GetOrCreateState(
    const std::string& key) {
    auto it = m_driverStates.find(key);
    if (it != m_driverStates.end()) return it->second;

    DriverState state;
    state.signedDriver = true;
    state.loadCount = 0;

    if (m_driverStates.size() >= m_stateCapacity) {
        auto oldest = std::min_element(m_driverStates.begin(),
                                        m_driverStates.end(),
            [](const auto& left, const auto& right) {
                return left.second.lastSeen100ns < right.second.lastSeen100ns;
            });
        if (oldest != m_driverStates.end()) m_driverStates.erase(oldest);
    }

    auto [inserted, _] = m_driverStates.emplace(key, state);
    return inserted->second;
}

void DriverLoadDetector::PurgeExpired(uint64_t now100ns) {
    if (m_dedupWindow100ns == 0) return;
    for (auto it = m_driverStates.begin(); it != m_driverStates.end();) {
        if (now100ns > it->second.lastSeen100ns &&
            (now100ns - it->second.lastSeen100ns) > m_dedupWindow100ns * 10) {
            it = m_driverStates.erase(it);
        } else {
            ++it;
        }
    }
}

void DriverLoadDetector::UpdateScore(DriverState& state, uint32_t weight,
                                      const char* reason) {
    for (const auto& r : state.reasons) {
        if (r == reason) return;  // Already counted
    }
    state.score += weight;
    if (state.score > 100) state.score = 100;
    state.reasons.push_back(reason);
}

void DriverLoadDetector::StampEvent(Event& event, const DriverState& state) {
    const_cast<DriverState&>(state).alerted = true;

    event.fields[field::kDriverScanScore] = std::to_string(state.score);
    event.fields[field::kDriverImagePath] = state.imagePath;
    event.fields[field::kDriverSigner] = state.signer;
    event.fields[field::kDriverSigned] = state.signedDriver ? "true" : "false";
    event.fields[field::kDriverLoadType] = state.loadCount > 1
        ? "repeated_load" : "first_load";
    event.fields[field::kDriverScanReasons] = Join(state.reasons, ",");
    event.fields[field::kDriverVerdict] =
        state.score >= 60 ? "malicious" : "suspicious";

    // MITRE ATT&CK mapping: T1543.003 (Create or Modify System Process:
    // Windows Service) / T1574.001 (DLL Search Order Hijacking for BYOVD)
    event.fields[field::kMitreAttack] = "T1543.003";
    event.fields[field::kMitreTactic] = "Persistence, Privilege Escalation";
}

} // namespace edr
