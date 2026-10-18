/*
 * task_abuse_detector.cpp - Scheduled task abuse scoring (T1053.005).
 */
#include "task_abuse_detector.h"

#include <algorithm>
#include <cctype>
#include <cstdio>

namespace edr {

namespace {

std::string LowerAscii(const std::string& text) {
    std::string out = text;
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return out;
}

bool Contains(const std::string& haystack, const char* needle) {
    return haystack.find(needle) != std::string::npos;
}

bool EndsWith(const std::string& text, const char* suffix) {
    const size_t len = strlen(suffix);
    return text.size() >= len &&
           text.compare(text.size() - len, len, suffix) == 0;
}

/* True when the name looks like a bare {GUID}. */
bool IsGuidOnlyName(const std::string& lowerName) {
    if (lowerName.size() != 38 || lowerName.front() != '{' ||
        lowerName.back() != '}')
        return false;
    for (size_t i = 1; i < 37; ++i) {
        const char c = lowerName[i];
        const bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        const bool dash = c == '-' && (i == 9 || i == 14 || i == 19 || i == 24);
        if (!hex && !dash) return false;
    }
    return true;
}

} // namespace

TaskAbuseDetector::TaskAbuseDetector(const Settings& settings)
    : m_settings(settings),
      m_dedupWindow100ns(
          static_cast<uint64_t>(settings.dedupWindowSeconds) *
          kFiletimeTicksPerSecond),
      m_burstWindow100ns(
          static_cast<uint64_t>(settings.deleteBurstWindowSeconds) *
          kFiletimeTicksPerSecond) {}

/* static */
bool TaskAbuseDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_TASK_SCHEDULER;
}

bool TaskAbuseDetector::AnalyzeName(const std::string& rawName,
                                    Finding* out) const {
    const std::string name = LowerAscii(rawName);

    /* RTLO U+202E is 0xE2 0x80 0xAE in UTF-8. */
    if (name.find("\xE2\x80\xAE") != std::string::npos) {
        *out = Finding{75, "rtlo disguised task name"};
        return true;
    }
    static const char* const kOuterExts[] = {
        ".pdf.", ".jpg.", ".jpeg.", ".png.", ".gif.", ".txt.", ".doc.",
        ".docx.", ".xls.", ".xlsx.", ".pptx.", ".mp3.", ".mp4.", ".zip.",
        ".rar."
    };
    static const char* const kInnerExts[] = {
        "exe", "scr", "com", "pif", "bat", "cmd", "js", "vbs", "wsf"
    };
    /* "report.pdf.exe" style: any benign extension immediately followed
     * by an executable one inside the same name. */
    for (const char* outer : kOuterExts) {
        for (const char* inner : kInnerExts) {
            if (name.find(std::string(outer) + inner) !=
                std::string::npos) {
                *out = Finding{75, "double extension task name"};
                return true;
            }
        }
    }
    static const char* const kInterpreters[] = {
        "powershell", "wscript", "cscript", "mshta", "cmd.exe",
        "rundll32", "regsvr32"
    };
    static const char* const kWritableDirs[] = {
        "\\temp\\", "\\appdata\\", "\\programdata\\", "\\users\\public\\",
        "\\windows\\temp\\"
    };
    bool hasInterpreter = false;
    for (const char* marker : kInterpreters)
        if (Contains(name, marker)) { hasInterpreter = true; break; }
    bool hasWritablePath = false;
    for (const char* marker : kWritableDirs)
        if (Contains(name, marker)) { hasWritablePath = true; break; }
    if (hasInterpreter || hasWritablePath) {
        *out = Finding{70, hasInterpreter
                              ? "interpreter keyword embedded in task name"
                              : "user-writable path embedded in task name"};
        return true;
    }
    return false;
}

bool TaskAbuseDetector::AnalyzeDeleteBurst(const std::string& userContext,
                                           uint64_t now100ns,
                                           Finding* out) {
    std::deque<uint64_t>& times = m_deleteTimes[userContext];
    times.push_back(now100ns);
    while (!times.empty() && now100ns >= m_burstWindow100ns &&
           now100ns - times.front() > m_burstWindow100ns)
        times.pop_front();
    if (times.size() < m_settings.deleteBurstThreshold) return false;
    times.clear(); /* one burst alert per cleanup wave */
    *out = Finding{60, "mass scheduled task deletion (cleanup)"};
    return true;
}

void TaskAbuseDetector::Stamp(Event& event, const Finding& finding,
                              const std::string& taskKey) {
    event.fields[field::kTaskAbuseScore] = std::to_string(finding.score);
    event.fields[field::kTaskAbuseVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kTaskAbuseSignals] = finding.signal;
    event.fields[field::kTaskAbuseTask] = taskKey;
}

void TaskAbuseDetector::Enrich(Event& event) {
    if (!m_settings.enabled) return;

    auto opIt = event.fields.find(field::kOperationType);
    if (opIt == event.fields.end()) return;

    if (opIt->second == "TASK_DELETED") {
        auto userIt = event.fields.find(field::kTaskUserContext);
        auto nameIt = event.fields.find(field::kTaskName);
        Finding finding;
        if (!AnalyzeDeleteBurst(userIt != event.fields.end()
                                    ? userIt->second
                                    : std::string("unknown"),
                                event.ts100ns, &finding))
            return;
        Stamp(event, finding,
              nameIt != event.fields.end() ? nameIt->second
                                           : std::string());
        return;
    }

    if (opIt->second != "TASK_REGISTERED" &&
        opIt->second != "TASK_UPDATED")
        return;

    auto nameIt = event.fields.find(field::kTaskName);
    if (nameIt == event.fields.end()) return;
    const std::string& taskName = nameIt->second;

    Finding finding;
    if (!AnalyzeName(taskName, &finding)) {
        if (IsGuidOnlyName(LowerAscii(taskName))) {
            finding = Finding{55, "opaque guid-only task name"};
        } else {
            return;
        }
    }

    const uint64_t now = event.ts100ns;
    auto it = m_lastAlert.find(taskName);
    if (it != m_lastAlert.end()) {
        if (m_dedupWindow100ns != 0 && now >= it->second &&
            now - it->second < m_dedupWindow100ns)
            return;
        it->second = now;
    } else {
        if (m_settings.stateCapacity > 0 &&
            m_lastAlert.size() >= m_settings.stateCapacity) {
            m_lastAlert.clear();
            std::fprintf(stderr,
                "[edr-taskabuse] state capacity %zu reached; dedup reset\n",
                m_settings.stateCapacity);
        }
        m_lastAlert.emplace(taskName, now);
    }

    Stamp(event, finding, taskName);
}

} // namespace edr
