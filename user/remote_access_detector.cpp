/*
 * remote_access_detector.cpp - See remote_access_detector.h.
 */
#include "remote_access_detector.h"

#include <windows.h>

#include <algorithm>
#include <cerrno>
#include <cctype>
#include <cstdlib>

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

uint32_t ParsePid(const std::string& text, uint32_t fallback) {
    if (text.empty()) return fallback;
    errno = 0;
    char* end = nullptr;
    const unsigned long value = std::strtoul(text.c_str(), &end, 10);
    if (errno != 0 || end == text.c_str()) return fallback;
    return static_cast<uint32_t>(value);
}

std::string Verdict(uint32_t score) {
    if (score >= 75) return "MALICIOUS";
    if (score >= 55) return "SUSPICIOUS";
    return "";
}

} // namespace

RemoteAccessDetector::RemoteAccessDetector(bool enabled,
                                           uint32_t windowSeconds,
                                           size_t stateCapacity)
    : m_enabled(enabled),
      m_window100ns(static_cast<uint64_t>(windowSeconds) *
                    kFiletimeTicksPerSecond),
      m_windowSeconds(windowSeconds),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)) {}

bool RemoteAccessDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START || type == EDR_EVT_NET_LISTENER ||
           type == EDR_EVT_NAMED_PIPE || type == EDR_EVT_SERVICE_CHANGE ||
           type == EDR_EVT_SERVICE_INSTALL;
}

bool RemoteAccessDetector::IsKnownTool(const std::string& rawBase) {
    const std::string base = LowerAscii(rawBase);
    static const char* kTools[] = {
        "anydesk.exe", "teamviewer.exe", "teamviewer_service.exe",
        "teamviewer_host.exe", "todesk.exe", "todesk_service.exe",
        "rustdesk.exe", "splashtop_service.exe", "splashtop_streamer.exe",
        "splashtopclient.exe", "cwsupport.exe", "connectwisecontrol.exe",
        "logmein.exe", "logmein_systray.exe", "lmiguardian.exe", "dwrcs.exe",
        "vncserver.exe", "winvnc4.exe", "winvnc.exe", "tvnserver.exe",
        "uvnc_service.exe", "r_server.exe", "radmin.exe", "dwarestorationmanager.exe"
    };
    for (const char* tool : kTools) {
        if (base == tool) return true;
    }
    return false;
}

void RemoteAccessDetector::PurgeExpired(uint64_t now100ns) {
    for (auto it = m_procs.begin(); it != m_procs.end();) {
        if (now100ns >= it->second.lastSeen100ns &&
            now100ns - it->second.lastSeen100ns > m_window100ns) {
            it = m_procs.erase(it);
        } else {
            ++it;
        }
    }
}

uint32_t RemoteAccessDetector::PidOf(const Event& event) const {
    if (event.type == EDR_EVT_PROCESS_START) return event.pid;
    if (event.type == EDR_EVT_NET_LISTENER)
        return ParsePid(FieldValue(event, field::kListenerPid), event.pid);
    if (event.type == EDR_EVT_NAMED_PIPE)
        return ParsePid(FieldValue(event, field::kPid), event.pid);
    return 0;
}

uint32_t RemoteAccessDetector::ComputeScore(const ProcState& state) const {
    /* A known remote-access tool was observed; the raw pre-breadth floor is
     * deliberately below the 55 SUSPICIOUS bar and only a second corroborating
     * signal (process start + service, pipe, or listener) lifts it above.
     * WriteState drops anything that never got there. */
    uint32_t score = 45;
    if (state.toolViaProcess) score += 15;
    if (state.sawService) score += 15;
    if (state.sawPipe) score += 15;
    if (state.sawListener) score += 30;
    return std::min(100u, score);
}

std::string RemoteAccessDetector::SignalList(const ProcState& state) const {
    std::string signals;
    const char* names[] = {"process", "service", "pipe", "listener"};
    const bool flags[] = {!state.tool.empty(), state.sawService,
                          state.sawPipe, state.sawListener};
    for (size_t i = 0; i < 4; ++i) {
        if (!flags[i]) continue;
        if (!signals.empty()) signals += ",";
        signals += names[i];
    }
    return signals.empty() ? "process" : signals;
}

void RemoteAccessDetector::WriteState(Event& event, const ProcState& state) {
    const uint32_t score = ComputeScore(state);
    /* House scoring contract: below 55 there is no verdict, so stamping the
     * score would publish a dead letter that no rule can consume. Analysis is
     * still recorded (the envelope writer observes WriteState calls), the
     * fields are simply withheld. */
    if (Verdict(score).empty()) return;
    event.fields[field::kRemoteAccessScore] = std::to_string(score);
    event.fields[field::kRemoteAccessTool] = state.tool;
    event.fields[field::kRemoteAccessSignals] = SignalList(state);
    event.fields[field::kRemoteAccessWindowSeconds] =
        std::to_string(m_windowSeconds);
    const std::string verdict = Verdict(score);
    if (!verdict.empty()) event.fields[field::kRemoteAccessVerdict] = verdict;
}

void RemoteAccessDetector::Enrich(Event& event) {
    if (!m_enabled) return;
    const uint64_t now = EventTime(event);
    PurgeExpired(now);

    if (event.type == EDR_EVT_SERVICE_CHANGE ||
        event.type == EDR_EVT_SERVICE_INSTALL) {
        const std::string base =
            BaseName(FieldValue(event, field::kServiceImagePath));
        if (!IsKnownTool(base)) return;
        ProcState state;
        state.tool = base;
        state.sawService = true;
        state.lastSeen100ns = now;
        WriteState(event, state);
        return;
    }

    const uint32_t pid = PidOf(event);
    if (pid == 0) return;

    if (event.type == EDR_EVT_PROCESS_START) {
        const std::string base =
            BaseName(FieldValue(event, field::kImage));
        if (!IsKnownTool(base)) return;
        ProcState& state = m_procs[pid];
        state.tool = base;
        state.toolViaProcess = true;
        state.lastSeen100ns = now;
        WriteState(event, state);
        return;
    }

    auto it = m_procs.find(pid);
    if (it == m_procs.end() || !IsKnownTool(it->second.tool)) {
        /* Listener-first ordering: a known remote tool that is already
         * listening without a prior process-start observation. */
        if (event.type == EDR_EVT_NET_LISTENER) {
            const std::string base =
                BaseName(FieldValue(event, field::kListenerProcess));
            if (IsKnownTool(base)) {
                ProcState& state = m_procs[pid];
                state.tool = base;
                state.sawListener = true;
                state.lastSeen100ns = now;
                WriteState(event, state);
            }
        }
        return;
    }

    bool changed = false;
    if (event.type == EDR_EVT_NET_LISTENER &&
        FieldValue(event, field::kListenerAction) == "added") {
        it->second.sawListener = true;
        changed = true;
    } else if (event.type == EDR_EVT_NAMED_PIPE &&
               FieldValue(event, field::kPipeOperation) == "created") {
        it->second.sawPipe = true;
        changed = true;
    }
    if (changed) {
        it->second.lastSeen100ns = now;
        WriteState(event, it->second);
    }
}

} // namespace edr
