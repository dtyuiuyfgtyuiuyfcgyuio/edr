#include "silverfox_detector.h"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <fstream>
#include <initializer_list>
#include <set>
#include <sstream>
#include <stdexcept>

#include "edr_event.h"
#include "json_lite.h"

namespace edr {
namespace {

constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;

std::string LowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

std::string FieldValue(const Event& event, const char* name) {
    auto found = event.fields.find(name);
    return found == event.fields.end() ? std::string() : found->second;
}

std::string BaseName(const std::string& value) {
    size_t slash = value.find_last_of("\\/");
    return LowerAscii(slash == std::string::npos ? value : value.substr(slash + 1));
}

std::string DirectoryName(const std::string& value) {
    std::string lower = LowerAscii(value);
    size_t slash = lower.find_last_of("\\/");
    return slash == std::string::npos ? std::string() : lower.substr(0, slash);
}

bool ContainsAny(const std::string& value,
                 std::initializer_list<const char*> needles) {
    for (const char* needle : needles) {
        if (value.find(needle) != std::string::npos) return true;
    }
    return false;
}

bool IsUserWritableLocation(const std::string& value) {
    const std::string lower = LowerAscii(value);
    if (lower.find("\\users\\") != std::string::npos &&
        ContainsAny(lower, {"\\appdata\\", "\\downloads\\", "\\desktop\\"}))
        return true;
    return ContainsAny(lower, {"\\windows\\temp\\", "c:\\temp\\",
                               "\\programdata\\"});
}

bool IsArchiveTempLocation(const std::string& value) {
    const std::string lower = LowerAscii(value);
    return ContainsAny(lower, {"\\temp\\rar$", "\\temp\\7z",
                               "\\temp\\bandizip\\", "\\temp\\haozip\\"});
}

bool ContainsPayloadExtension(const std::string& value) {
    const std::string lower = LowerAscii(value);
    return ContainsAny(lower, {".exe", ".dll", ".scr", ".cpl", ".com",
                               ".dat", ".tmp", ".cab", ".js", ".vbs",
                               ".hta", ".ps1"});
}

bool IsPortableExecutablePath(const std::string& value) {
    const std::string lower = LowerAscii(value);
    if (lower.size() < 4) return false;
    const std::string extension = lower.substr(lower.size() - 4);
    return ContainsAny(extension, {".exe", ".dll", ".scr", ".cpl", ".com"});
}

bool IsLolbin(const std::string& image) {
    const std::string base = BaseName(image);
    static const std::set<std::string> names = {
        "rundll32.exe", "regsvr32.exe", "mshta.exe", "wscript.exe",
        "cscript.exe", "powershell.exe", "pwsh.exe"
    };
    return names.count(base) != 0;
}

bool IsInstallerOrArchiver(const std::string& image) {
    const std::string base = BaseName(image);
    static const std::set<std::string> names = {
        "setup.exe", "install.exe", "installer.exe", "update.exe",
        "winrar.exe", "rar.exe", "7z.exe", "7zg.exe", "bandizip.exe",
        "haozip.exe", "360zip.exe"
    };
    return names.count(base) != 0 || base.find("setup") != std::string::npos ||
           base.find("installer") != std::string::npos;
}

bool IsSystemNameOutsideSystemDirectory(const std::string& image) {
    const std::string base = BaseName(image);
    static const std::set<std::string> names = {
        "svchost.exe", "conhost.exe", "dllhost.exe", "taskhostw.exe",
        "runtimebroker.exe", "securityhealthservice.exe",
        /* SilverFox lineages additionally masquerade under these names
         * in user-writable directories (public reporting). */
        "wudfhost.exe", "winlogon.exe", "lsass.exe", "services.exe"
    };
    if (names.count(base) == 0) return false;
    const std::string lower = LowerAscii(image);
    if (lower.find('\\') == std::string::npos &&
        lower.find('/') == std::string::npos)
        return false;
    return lower.find("\\windows\\system32\\") == std::string::npos &&
           lower.find("\\windows\\syswow64\\") == std::string::npos &&
           lower.find("\\windows\\systemapps\\") == std::string::npos;
}
bool IsUntrustedSignature(const Event& event) {
    const std::string status =
        LowerAscii(FieldValue(event, field::kSignatureStatus));
    return status == "unsigned_embedded" || status == "untrusted" ||
           status == "revoked" || status == "expired";
}

bool LooksLikeDefenderTamper(const std::string& text) {
    const std::string lower = LowerAscii(text);
    const std::string setPreference = std::string("set-") + "mppreference";
    const std::string addPreference = std::string("add-") + "mppreference";
    const std::string disableRealtime =
        std::string("disable") + "realtimemonitoring";
    const std::string exclusionPath = std::string("exclusion") + "path";
    const std::string exclusionProcess = std::string("exclusion") + "process";
    const std::string disableSpyware = std::string("disable") + "antispyware";
    if (lower.find(setPreference) != std::string::npos &&
        lower.find(disableRealtime) != std::string::npos)
        return true;
    if (lower.find(addPreference) != std::string::npos &&
        (lower.find(exclusionPath) != std::string::npos ||
         lower.find(exclusionProcess) != std::string::npos))
        return true;
    return lower.find("windows defender") != std::string::npos &&
           (lower.find(disableRealtime) != std::string::npos ||
            lower.find(disableSpyware) != std::string::npos);
}

bool LooksLikeTaskPersistence(const std::string& image,
                              const std::string& commandLine) {
    if (BaseName(image) != "schtasks.exe") return false;
    const std::string lower = LowerAscii(commandLine);
    const bool create = lower.find("/create") != std::string::npos ||
                        lower.find("-create") != std::string::npos;
    return create && ContainsPayloadExtension(lower) &&
           (IsUserWritableLocation(lower) || IsArchiveTempLocation(lower));
}

bool IsRunKey(const std::string& key) {
    const std::string lower = LowerAscii(key);
    return lower.find("\\currentversion\\run\\") != std::string::npos ||
           lower.find("\\currentversion\\runonce\\") != std::string::npos;
}

bool IsInjectionEvent(const Event& event) {
    return event.type == EDR_EVT_PROCESS_ACCESS &&
           FieldValue(event, field::kCrossProcess) == "true" &&
           FieldValue(event, field::kAccessCreateThread) == "true" &&
           FieldValue(event, field::kAccessVmOperation) == "true" &&
           FieldValue(event, field::kAccessVmWrite) == "true";
}

/*
 * Vulnerable drivers publicly reported as abused by SilverFox /
 * ValleyRAT lineages to terminate security software and escalate from
 * user mode (BYOVD - Bring Your Own Vulnerable Driver). Matching is on
 * the driver file name token; a legitimate tool that merely mentions
 * these names in a command line does not match because we require the
 * full ".sys" name.
 */
constexpr const char* const kByovdDriverNames[] = {
    "rtcore64.sys",     /* Micro-Star Afterburner driver         */
    "dbutil_2_3.sys",   /* Dell DBUtil                           */
    "gmer.sys",         /* GMER rootkit detector                 */
    "procexp152.sys",   /* Process Explorer driver               */
    "msiosd64.sys",     /* MSI OSD driver                        */
    "iqvw64e.sys",      /* Intel NIC diagnostics driver          */
};

bool IsByovdDriverReference(const std::string& lowerText) {
    for (const char* name : kByovdDriverNames) {
        if (lowerText.find(name) != std::string::npos) return true;
    }
    return false;
}

/*
 * Security-software processes that SilverFox / Gh0stRAT-lineage loaders
 * are known to open with kill or write rights before attempting to
 * terminate or blind them. Matched on the basename of the TARGET image.
 */
bool IsSecuritySoftwareTarget(const std::string& targetImage) {
    static const std::set<std::string> names = {
        "msmpeng.exe",        /* Microsoft Defender            */
        "360tray.exe",        /* 360 Safe Guard tray           */
        "360safe.exe",        /* 360 Total Security            */
        "zhudongfangyu.exe",  /* 360 active defense            */
        "hipstray.exe",       /* Huorong tray                  */
        "hipsdaemon.exe",     /* Huorong daemon                */
        "usysdiag.exe",       /* Huorong engine                */
        "qqpctray.exe",       /* Tencent PC Manager tray       */
        "kxetray.exe",        /* Kingsoft antivirus tray       */
        "baidusd.exe",        /* Baidu antivirus               */
    };
    return names.count(BaseName(targetImage)) != 0;
}

/*
 * A PROCESS_ACCESS event against security software carrying rights that
 * enable killing it (create-thread), blinding it (VM write), or reading
 * its state for tamper planning (VM read).
 */
bool IsSecuritySoftwareTamperAccess(const Event& event) {
    if (event.type != EDR_EVT_PROCESS_ACCESS) return false;
    if (!IsSecuritySoftwareTarget(FieldValue(event, field::kTargetImage)))
        return false;
    return FieldValue(event, field::kAccessCreateThread) == "true" ||
           FieldValue(event, field::kAccessVmWrite) == "true" ||
           FieldValue(event, field::kAccessVmRead) == "true";
}

bool HasSignal(const std::vector<std::string>& signals,
               const std::string& signal) {
    return std::find(signals.begin(), signals.end(), signal) != signals.end();
}

template <typename State>
bool AddSignal(State& state, const std::string& signal, int score) {
    if (HasSignal(state.signals, signal)) return false;
    state.signals.push_back(signal);
    state.score = std::min(100, state.score + score);
    return true;
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

uint64_t EventTime(const Event& event) {
    if (event.ts100ns != 0) return event.ts100ns;
    FILETIME now = {};
    GetSystemTimePreciseAsFileTime(&now);
    return (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
           now.dwLowDateTime;
}

bool IsHex(const std::string& value, size_t length) {
    return value.size() == length &&
        std::all_of(value.begin(), value.end(), [](unsigned char c) {
            return std::isxdigit(c) != 0;
        });
}
bool IsValidDomain(const std::string& value) {
    if (value.empty() || value.size() > 253 || value.front() == '.' ||
        value.back() == '.' || value.find("..") != std::string::npos)
        return false;
    bool dot = false;
    size_t labelLength = 0;
    for (unsigned char c : value) {
        if (c == '.') {
            if (labelLength == 0 || labelLength > 63) return false;
            labelLength = 0;
            dot = true;
        } else if (std::isalnum(c) || c == '-') {
            ++labelLength;
        } else {
            return false;
        }
    }
    return dot && labelLength != 0 && labelLength <= 63;
}

bool IsValidIpv4(const std::string& value) {
    size_t begin = 0;
    for (int part = 0; part < 4; ++part) {
        size_t end = value.find('.', begin);
        if (part == 3) end = std::string::npos;
        if ((part < 3 && end == std::string::npos) ||
            (part == 3 && value.find('.', begin) != std::string::npos))
            return false;
        std::string token = value.substr(begin,
            end == std::string::npos ? std::string::npos : end - begin);
        if (token.empty() || token.size() > 3 ||
            !std::all_of(token.begin(), token.end(), [](unsigned char c) {
                return std::isdigit(c) != 0;
            }))
            return false;
        if (token.size() > 1 && token.front() == '0') return false;
        if (std::stoul(token) > 255) return false;
        if (end == std::string::npos) return part == 3;
        begin = end + 1;
    }
    return false;
}

bool DomainMatches(const std::string& host, const std::string& indicator) {
    std::string canonical = LowerAscii(host);
    while (!canonical.empty() && canonical.back() == '.') canonical.pop_back();
    if (canonical == indicator) return true;
    return canonical.size() > indicator.size() &&
           canonical.compare(canonical.size() - indicator.size(),
                             indicator.size(), indicator) == 0 &&
           canonical[canonical.size() - indicator.size() - 1] == '.';
}

std::string Sha256Value(const Event& event) {
    std::string direct = LowerAscii(FieldValue(event, field::kSha256));
    if (IsHex(direct, 64)) return direct;
    const std::string hashes = LowerAscii(FieldValue(event, field::kHashes));
    size_t position = hashes.find("sha256=");
    if (position == std::string::npos) return {};
    position += 7;
    std::string candidate = hashes.substr(position, 64);
    return IsHex(candidate, 64) ? candidate : std::string();
}

const jsonlite::Value& Required(const jsonlite::Value& object,
                                const char* name, jsonlite::Type type) {
    const jsonlite::Value* value = object.find(name);
    if (value == nullptr || value->type != type)
        throw std::runtime_error(std::string("indicator field '") + name +
                                 "' is missing or has the wrong type");
    return *value;
}

void RequireExactKeys(const jsonlite::Value& object) {
    static const std::set<std::string> allowed = {
        "id", "type", "value", "confidence", "status", "source_url",
        "observed_at"
    };
    for (const auto& item : object.object) {
        if (allowed.count(item.first) == 0)
            throw std::runtime_error("unknown indicator field '" +
                                     item.first + "'");
    }
}

} // namespace

SilverFoxDetector::SilverFoxDetector(bool enabled,
                                     uint32_t correlationWindowSeconds,
                                     size_t stateCapacity)
    : m_enabled(enabled),
      m_window100ns(static_cast<uint64_t>(correlationWindowSeconds) *
                    kFiletimeTicksPerSecond),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)) {}

bool SilverFoxDetector::LoadIndicators(const std::string& path,
                                       std::string& error) {
    error.clear();
    try {
        std::ifstream input(path, std::ios::binary);
        if (!input) throw std::runtime_error("cannot open IOC file: " + path);
        std::stringstream text;
        text << input.rdbuf();
        jsonlite::Value root = jsonlite::parse(text.str());
        if (root.type != jsonlite::Type::Object)
            throw std::runtime_error("IOC root must be an object");
        const jsonlite::Value& schema =
            Required(root, "schema_version", jsonlite::Type::Number);
        if (schema.number != 2.0)
            throw std::runtime_error("IOC schema_version must be 2");
        const jsonlite::Value& family =
            Required(root, "family", jsonlite::Type::String);
        if (LowerAscii(family.str) != "silverfox")
            throw std::runtime_error("IOC family must be SilverFox");
        const jsonlite::Value& values =
            Required(root, "indicators", jsonlite::Type::Array);

        std::vector<Indicator> loaded;
        std::set<std::string> ids;
        std::set<std::string> uniqueValues;
        for (const jsonlite::Value& entry : values.array) {
            if (entry.type != jsonlite::Type::Object)
                throw std::runtime_error("indicator entry must be an object");
            RequireExactKeys(entry);
            const std::string id =
                Required(entry, "id", jsonlite::Type::String).str;
            const std::string type = LowerAscii(
                Required(entry, "type", jsonlite::Type::String).str);
            const std::string value = LowerAscii(
                Required(entry, "value", jsonlite::Type::String).str);
            const std::string confidence = LowerAscii(
                Required(entry, "confidence", jsonlite::Type::String).str);
            const std::string status = LowerAscii(
                Required(entry, "status", jsonlite::Type::String).str);
            const std::string source =
                Required(entry, "source_url", jsonlite::Type::String).str;
            const std::string observed =
                Required(entry, "observed_at", jsonlite::Type::String).str;
            if (id.empty() || !ids.insert(id).second)
                throw std::runtime_error(
                    "indicator ids must be non-empty and unique");
            if (status != "active" && status != "retired" &&
                status != "candidate")
                throw std::runtime_error(
                    "indicator status must be active, retired, or candidate");
            if (status != "active") continue;
            if (confidence != "medium" && confidence != "high")
                throw std::runtime_error(
                    "active indicator confidence must be medium or high");
            if ((source.rfind("https://", 0) != 0 &&
                 source.rfind("http://", 0) != 0) || observed.empty())
                throw std::runtime_error(
                    "active indicator requires source_url and observed_at");

            Indicator indicator;
            indicator.id = id;
            indicator.value = value;
            indicator.confidence = confidence;
            indicator.sourceUrl = source;
            indicator.observedAt = observed;
            if (type == "sha256") {
                indicator.type = IndicatorType::Sha256;
                if (!IsHex(value, 64))
                    throw std::runtime_error(
                        "sha256 indicator must contain 64 hex digits");
            } else if (type == "certificate_sha256") {
                indicator.type = IndicatorType::CertificateSha256;
                if (!IsHex(value, 64))
                    throw std::runtime_error(
                        "certificate_sha256 indicator must contain 64 hex digits");
            } else if (type == "domain") {
                indicator.type = IndicatorType::Domain;
                if (!IsValidDomain(value))
                    throw std::runtime_error("domain indicator is invalid");
            } else if (type == "ipv4") {
                indicator.type = IndicatorType::Ipv4;
                if (!IsValidIpv4(value))
                    throw std::runtime_error("ipv4 indicator is invalid");
            } else {
                throw std::runtime_error(
                    "unsupported indicator type '" + type + "'");
            }
            const std::string unique = type + ":" + value;
            if (!uniqueValues.insert(unique).second)
                throw std::runtime_error("duplicate active indicator value");
            loaded.push_back(std::move(indicator));
        }
        m_indicators.swap(loaded);
        return true;
    } catch (const std::exception& exception) {
        error = exception.what();
        return false;
    }
}

void SilverFoxDetector::PurgeExpired(uint64_t now100ns) {
    for (auto it = m_states.begin(); it != m_states.end();) {
        if (now100ns >= it->second.lastSeen100ns &&
            now100ns - it->second.lastSeen100ns > m_window100ns)
            it = m_states.erase(it);
        else
            ++it;
    }
}

void SilverFoxDetector::StoreState(uint32_t pid, ProcessState state) {
    if (pid == 0 || state.signals.empty()) return;
    if (m_states.find(pid) == m_states.end() &&
        m_states.size() >= m_stateCapacity) {
        auto oldest = std::min_element(m_states.begin(), m_states.end(),
            [](const auto& left, const auto& right) {
                return left.second.lastSeen100ns <
                       right.second.lastSeen100ns;
            });
        if (oldest != m_states.end()) m_states.erase(oldest);
    }
    m_states[pid] = std::move(state);
}
void SilverFoxDetector::Enrich(Event& event) {
    if (!m_enabled) return;
    const uint64_t now = EventTime(event);
    PurgeExpired(now);
    if (event.type == EDR_EVT_PROCESS_STOP) {
        m_states.erase(event.pid);
        return;
    }

    ProcessState state;
    const std::string identity =
        LowerAscii(event.processIdentity);
    if (event.type != EDR_EVT_PROCESS_START && event.pid != 0) {
        auto existing = m_states.find(event.pid);
        if (existing != m_states.end()) {
            const bool identityMismatch = !identity.empty() &&
                !existing->second.identity.empty() &&
                identity != existing->second.identity;
            if (!identityMismatch)
                state = existing->second;
            else
                m_states.erase(existing);
        }
    } else if (event.pid != 0) {
        m_states.erase(event.pid);
    }
    if (!identity.empty())
        state.identity = identity;
    const size_t initialSignalCount = state.signals.size();

    std::vector<std::string> matchedIds;
    std::vector<std::string> matchedTypes;
    std::vector<std::string> matchedSources;
    std::string bestIocConfidence;
    const std::string sha256 = Sha256Value(event);
    const std::string certificate =
        LowerAscii(FieldValue(event, field::kSignerCertificateSha256));
    const std::string host = FieldValue(event, field::kTargetHost);
    const std::string ip = FieldValue(event, field::kDstIp);
    for (const Indicator& indicator : m_indicators) {
        bool matched = false;
        const char* typeName = "";
        const char* signal = "";
        int score = 0;
        switch (indicator.type) {
        case IndicatorType::Sha256:
            matched = !sha256.empty() && sha256 == indicator.value;
            typeName = "sha256";
            signal = "VERIFIED_HASH_IOC";
            score = 100;
            break;
        case IndicatorType::CertificateSha256:
            matched = IsHex(certificate, 64) &&
                      certificate == indicator.value;
            typeName = "certificate_sha256";
            signal = "VERIFIED_CERTIFICATE_IOC";
            score = 95;
            break;
        case IndicatorType::Domain:
            matched = !host.empty() &&
                      DomainMatches(host, indicator.value);
            typeName = "domain";
            signal = "VERIFIED_NETWORK_IOC";
            score = 85;
            break;
        case IndicatorType::Ipv4:
            matched = ip == indicator.value;
            typeName = "ipv4";
            signal = "VERIFIED_NETWORK_IOC";
            score = 85;
            break;
        }
        if (!matched) continue;
        AddSignal(state, signal, score);
        matchedIds.push_back(indicator.id);
        matchedTypes.push_back(typeName);
        matchedSources.push_back(indicator.sourceUrl);
        if (indicator.confidence == "high" ||
            bestIocConfidence.empty())
            bestIocConfidence = indicator.confidence;
    }

    const std::string image = FieldValue(event, field::kImage);
    const std::string parentImage =
        FieldValue(event, field::kParentImage);
    const std::string commandLine =
        FieldValue(event, field::kCommandLine);
    const std::string scriptText =
        FieldValue(event, field::kScriptBlockText);
    const std::string content =
        commandLine.empty() ? scriptText : commandLine;
    bool suspiciousContext = state.score >= 25;

    if (event.type == EDR_EVT_PROCESS_START) {
        if (IsUserWritableLocation(image) &&
            IsPortableExecutablePath(image))
            AddSignal(state, "USER_WRITABLE_EXECUTION", 15);
        if (IsArchiveTempLocation(image) ||
            IsArchiveTempLocation(commandLine))
            AddSignal(state, "ARCHIVE_TEMP_EXECUTION", 30);
        if (IsSystemNameOutsideSystemDirectory(image))
            AddSignal(state, "MASQUERADED_SYSTEM_BINARY", 55);
        if (IsUntrustedSignature(event))
            AddSignal(state, "UNTRUSTED_EXECUTABLE", 15);
        if (IsLolbin(image) &&
            IsInstallerOrArchiver(parentImage) &&
            ContainsPayloadExtension(commandLine) &&
            (IsUserWritableLocation(commandLine) ||
             IsArchiveTempLocation(commandLine))) {
            AddSignal(state, "FAKE_INSTALLER_CHAIN", 45);
            AddSignal(state, "USER_WRITABLE_PAYLOAD_ARGUMENT", 20);
        }
        auto parent = m_states.find(event.ppid);
        if (parent != m_states.end() &&
            parent->second.score >= 25)
            AddSignal(state, "SUSPICIOUS_PARENT_CHAIN", 20);
        suspiciousContext = state.score >= 25;
        if (LooksLikeTaskPersistence(image, commandLine)) {
            AddSignal(state, "USER_WRITABLE_TASK_PERSISTENCE", 25);
            if (HasSignal(state.signals, "SUSPICIOUS_PARENT_CHAIN") ||
                IsArchiveTempLocation(commandLine))
                AddSignal(state, "CORRELATED_TASK_PERSISTENCE", 35);
        }
    }

    if (!content.empty() && LooksLikeDefenderTamper(content)) {
        AddSignal(state, "DEFENDER_TAMPER", 35);
        if (suspiciousContext ||
            IsUserWritableLocation(content) ||
            IsArchiveTempLocation(content))
            AddSignal(state, "CORRELATED_DEFENDER_TAMPER", 35);
    }

    if (event.type == EDR_EVT_IMAGE_LOAD) {
        const std::string target =
            FieldValue(event, field::kTargetImage);
        const std::string targetBase = BaseName(target);
        const bool targetDll = targetBase.size() > 4 &&
            targetBase.substr(targetBase.size() - 4) == ".dll";
        const bool sameDirectory =
            !DirectoryName(image).empty() &&
            DirectoryName(image) == DirectoryName(target);
        if (targetDll && IsUserWritableLocation(target) &&
            (sameDirectory || IsUserWritableLocation(image))) {
            AddSignal(state, "USER_WRITABLE_SIDELOAD", 25);
            if (IsUntrustedSignature(event)) {
                AddSignal(state, "UNTRUSTED_SIDELOAD_DLL", 15);
                AddSignal(state, "CORRELATED_USER_WRITABLE_SIDELOAD", 30);
            } else if (suspiciousContext) {
                AddSignal(state, "CORRELATED_USER_WRITABLE_SIDELOAD", 30);
            }
        }
    }

    if (IsInjectionEvent(event)) {
        AddSignal(state, "PROCESS_INJECTION", 60);
        if (suspiciousContext ||
            IsUserWritableLocation(image))
            AddSignal(state, "CORRELATED_PROCESS_INJECTION", 20);
    }

    /* SilverFox BYOVD plane: loading or staging a known-abused vulnerable
     * driver, typically to kill security software from kernel mode. */
    if (event.type == EDR_EVT_IMAGE_LOAD ||
        event.type == EDR_EVT_FILE_CREATE ||
        event.type == EDR_EVT_PROCESS_START ||
        event.type == EDR_EVT_SERVICE_INSTALL) {
        const std::string byovdText = LowerAscii(
            image + " " + commandLine + " " +
            FieldValue(event, field::kTargetImage) + " " +
            FieldValue(event, field::kFilePath));
        if (IsByovdDriverReference(byovdText)) {
            AddSignal(state, "BYOVD_DRIVER_ARTIFACT", 60);
            if (suspiciousContext)
                AddSignal(state, "CORRELATED_BYOVD_DRIVER_ARTIFACT", 25);
        }
    }

    /* SilverFox security-software tamper plane: opening an AV/EDR
     * process with kill / write / read rights ahead of a termination
     * attempt. This is the user-mode half of the BYOVD kill chain. */
    if (IsSecuritySoftwareTamperAccess(event)) {
        AddSignal(state, "SECURITY_SOFTWARE_TAMPER_ACCESS", 65);
        if (suspiciousContext ||
            IsUserWritableLocation(image))
            AddSignal(state, "CORRELATED_SECURITY_SOFTWARE_TAMPER", 20);
    }

    if (event.type == EDR_EVT_NET_CONNECT) {
        if (HasSignal(state.signals, "PROCESS_INJECTION"))
            AddSignal(state, "POST_INJECTION_NETWORK", 35);
        else if (state.score >= 50)
            AddSignal(state, "SUSPICIOUS_PROCESS_NETWORK", 20);
    }

    if (event.type == EDR_EVT_REG_WRITE &&
        IsRunKey(FieldValue(event, field::kRegKey))) {
        if (state.score >= 25)
            AddSignal(state, "CORRELATED_RUNKEY_PERSISTENCE", 45);
        else if (IsUserWritableLocation(
                     FieldValue(event, field::kRegValue)))
            AddSignal(state, "USER_WRITABLE_RUNKEY_PERSISTENCE", 20);
    }

    if (event.type == EDR_EVT_FILE_CREATE) {
        const std::string path =
            FieldValue(event, field::kFilePath);
        if (state.score >= 25 &&
            IsUserWritableLocation(path) &&
            IsPortableExecutablePath(path))
            AddSignal(state, "SUSPICIOUS_PAYLOAD_DROP", 25);
    }

    if (state.signals.empty()) return;
    if (state.signals.size() > initialSignalCount ||
        !matchedIds.empty())
        state.lastSeen100ns = std::max(state.lastSeen100ns, now);
    StoreState(event.pid, state);
    if (state.score < 25) return;

    event.fields[field::kSilverFoxFamily] = "SilverFox";
    event.fields[field::kSilverFoxScore] =
        std::to_string(state.score);
    event.fields[field::kSilverFoxConfidence] =
        state.score >= 80 ? "high" :
        state.score >= 50 ? "medium" : "low";
    event.fields[field::kSilverFoxSignals] =
        Join(state.signals, ",");
    event.fields[field::kSilverFoxEvidenceCount] =
        std::to_string(state.signals.size());
    if (!matchedIds.empty()) {
        event.fields[field::kSilverFoxIocIds] =
            Join(matchedIds, ",");
        event.fields[field::kSilverFoxIocTypes] =
            Join(matchedTypes, ",");
        event.fields[field::kSilverFoxIocSources] =
            Join(matchedSources, ",");
        event.fields[field::kSilverFoxIocConfidence] =
            bestIocConfidence;
    }
}

} // namespace edr
