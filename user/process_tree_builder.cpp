#include "process_tree_builder.h"
#include "event_bus.h"
#include "edr_event.h"

#include <windows.h>

#include <cstdio>
#include <sstream>

namespace edr {
namespace {

std::string JsonEscape(const std::string& value) {
    std::string out;
    out.reserve(value.size() + 8);
    for (char c : value) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x",
                                  static_cast<unsigned int>(c));
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

} // namespace

void ProcessTreeBuilder::Observe(const Event& event) {
    // Tampering and file deletion identify a subject, but supply no parent evidence.
    // Leave ancestry and the previously observed image unchanged.
    if (event.pid == 0 || event.type == EDR_EVT_PROCESS_TAMPERING ||
        event.type == EDR_EVT_FILE_DELETE) return;
    const auto image = event.fields.find(field::kImage);
    AddParentChild(event.ppid, event.pid,
        image == event.fields.end() ? "" : image->second);
}

void ProcessTreeBuilder::AddParentChild(uint32_t parentPid, uint32_t childPid,
                                        const std::string& image) {
    std::lock_guard<std::mutex> lock(m_mutex);
    const uint64_t nowMs = GetTickCount64();
    ProcessRecord& rec = m_processes[childPid];
    if (rec.pid == 0) rec.firstSeenMs = nowMs;
    rec.pid = childPid;
    rec.parentPid = parentPid;
    rec.image = image;
    rec.lastSeenMs = nowMs;
}

std::string ProcessTreeBuilder::GetProcessTreeJson(uint32_t pid,
                                                   uint32_t maxDepth) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::string out;
    BuildNodeJsonLocked(pid, 0, maxDepth, out);
    return out.empty() ? "{}" : out;
}

void ProcessTreeBuilder::PruneOldEntries(uint64_t nowMs, uint64_t maxAgeMs) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (maxAgeMs == 0) return;
    for (auto it = m_processes.begin(); it != m_processes.end();) {
        if (nowMs >= it->second.lastSeenMs &&
            nowMs - it->second.lastSeenMs > maxAgeMs) {
            it = m_processes.erase(it);
        } else {
            ++it;
        }
    }
}

bool ProcessTreeBuilder::HasProcess(uint32_t pid) {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_processes.find(pid) != m_processes.end();
}

std::vector<uint32_t> ProcessTreeBuilder::GetAncestors(uint32_t pid,
                                                       uint32_t maxDepth) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<uint32_t> ancestors;
    uint32_t current = pid;
    for (uint32_t i = 0; i < maxDepth; ++i) {
        auto it = m_processes.find(current);
        if (it == m_processes.end()) break;
        const uint32_t parent = it->second.parentPid;
        if (parent == 0) break;
        ancestors.push_back(parent);
        current = parent;
    }
    return ancestors;
}

std::vector<uint32_t> ProcessTreeBuilder::GetChildren(uint32_t pid) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<uint32_t> children;
    for (const auto& entry : m_processes) {
        if (entry.second.parentPid == pid) children.push_back(entry.first);
    }
    return children;
}

void ProcessTreeBuilder::BuildNodeJsonLocked(uint32_t pid, uint32_t depth,
                                             uint32_t maxDepth,
                                             std::string& out) {
    auto it = m_processes.find(pid);
    if (it == m_processes.end()) {
        out.clear();
        return;
    }
    const ProcessRecord& rec = it->second;
    std::ostringstream oss;
    oss << "{\"pid\":" << rec.pid
        << ",\"parent_pid\":" << rec.parentPid
        << ",\"image\":\"" << JsonEscape(rec.image) << "\""
        << ",\"first_seen_ms\":" << rec.firstSeenMs
        << ",\"last_seen_ms\":" << rec.lastSeenMs << ",\"children\":[";
    bool first = true;
    for (const auto& entry : m_processes) {
        if (entry.second.parentPid != pid) continue;
        std::string childOut;
        BuildNodeJsonLocked(entry.first, depth + 1, maxDepth, childOut);
        if (childOut.empty()) continue;
        if (!first) oss << ",";
        first = false;
        oss << childOut;
    }
    oss << "]}";
    out = oss.str();
}

} // namespace edr
