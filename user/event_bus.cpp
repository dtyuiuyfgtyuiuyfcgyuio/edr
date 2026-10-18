#include "event_bus.h"
#include <cstdio>
#include <optional>

namespace edr {

static void AcknowledgeConsumption(const Event& event, bool accepted) noexcept {
    if (!event.onConsumed) return;
    try { event.onConsumed(accepted); }
    catch (...) {
        std::fprintf(stderr, "[edr-bus] consumption acknowledgment failed\n");
    }
}

static void AppendField(std::string& key, const Event& ev, const char* name) {
    auto it = ev.fields.find(name);
    if (it != ev.fields.end()) {
        key.append("|").append(name).append("=").append(it->second);
    }
}

static std::string LowerAscii(std::string value) {
    for (char& ch : value) {
        if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch - 'A' + 'a');
    }
    return value;
}

static bool IsBarePidIdentity(const std::string& identity) {
    const std::string lower = LowerAscii(identity);
    if (lower.rfind("pid:", 0) == 0) return true;
    if (lower.empty()) return false;
    for (unsigned char ch : lower) {
        if (ch < '0' || ch > '9') return false;
    }
    return true;
}

static std::string FieldValue(const Event& ev, const char* name) {
    auto it = ev.fields.find(name);
    return it == ev.fields.end() ? std::string() : it->second;
}

static std::string SemanticKey(const Event& ev) {
    std::string identity;
    if (ev.pid != 0 && ev.processStartTime100ns != 0) {
        /* This provider-neutral identity makes Sysmon GUIDs and ETW's
         * sequence/PID identities converge only on exact instance evidence. */
        identity = "pid:" + std::to_string(ev.pid) + "@" +
                   std::to_string(ev.processStartTime100ns);
    } else if (!ev.processIdentity.empty() &&
               !IsBarePidIdentity(ev.processIdentity)) {
        /* Provider-scoped opaque identity is a fallback. Only exact
         * PID+creation time above can canonicalize across providers. */
        std::string source = ev.source;
        if (source.empty()) source = FieldValue(ev, field::kSource);
        identity = "opaque:" + LowerAscii(source) + ":" +
                   ev.processIdentity;
    }
    if (identity.empty()) return {};

    std::string key = std::to_string(ev.type) + "|endpoint=" +
                      LowerAscii(FieldValue(ev, field::kEndpointId)) +
                      "|process=" + identity;
    size_t semanticLength = key.size();
    switch (ev.type) {
    case 1:
    case 2:
        AppendField(key, ev, field::kImage);
        AppendField(key, ev, field::kPpid);
        break;
    case 3:
        AppendField(key, ev, field::kRegKey);
        AppendField(key, ev, field::kRegValue);
        AppendField(key, ev, field::kRegOperation);
        AppendField(key, ev, field::kRegOldTarget);
        AppendField(key, ev, field::kRegNewTarget);
        break;
    case 4:
        AppendField(key, ev, field::kFilePath);
        break;
    case 5:
        AppendField(key, ev, field::kDstIp);
        AppendField(key, ev, field::kDstPort);
        AppendField(key, ev, field::kProtocol);
        AppendField(key, ev, field::kSrcIp);
        AppendField(key, ev, field::kSrcPort);
        break;
    case 7:
        AppendField(key, ev, field::kImageLoaded);
        AppendField(key, ev, field::kTargetImage);
        AppendField(key, ev, field::kHashes);
        break;
    case 8:
        AppendField(key, ev, field::kTargetHost);
        AppendField(key, ev, field::kDnsQueryName);
        AppendField(key, ev, field::kDnsQueryType);
        AppendField(key, ev, field::kDnsServerIp);
        break;
    case 10:
        AppendField(key, ev, field::kTargetUser);
        AppendField(key, ev, field::kTargetDomain);
        AppendField(key, ev, field::kSrcIp);
        AppendField(key, ev, field::kLogonType);
        AppendField(key, ev, field::kOperationType);
        break;
    case 11:
        AppendField(key, ev, field::kTargetUser);
        AppendField(key, ev, field::kOperationType);
        break;
    case 12:
        AppendField(key, ev, field::kServiceName);
        break;
    case 13:
        AppendField(key, ev, field::kWmiEventId);
        AppendField(key, ev, field::kWmiQuery);
        AppendField(key, ev, field::kWmiOperation);
        AppendField(key, ev, field::kWmiResultCode);
        AppendField(key, ev, field::kWmiProviderName);
        AppendField(key, ev, field::kWmiProviderPath);
        AppendField(key, ev, field::kOperationType);
        break;
    case 14:
        AppendField(key, ev, field::kTaskName);
        AppendField(key, ev, field::kOperationType);
        break;
    case 15:
        AppendField(key, ev, field::kPrivilegeOperation);
        AppendField(key, ev, field::kPrivilegeList);
        AppendField(key, ev, field::kProcessName);
        break;
    case 16:
        AppendField(key, ev, field::kScriptBlockId);
        AppendField(key, ev, field::kScriptMessageNumber);
        AppendField(key, ev, field::kScriptReassemblyStatus);
        break;
    case 17:
        AppendField(key, ev, field::kTargetPid);
        AppendField(key, ev, field::kStartAddress);
        break;
    case 18:
        AppendField(key, ev, field::kTargetPid);
        AppendField(key, ev, field::kBaseAddress);
        AppendField(key, ev, field::kMemorySize);
        break;
    case 19:
        AppendField(key, ev, field::kFilePath);
        AppendField(key, ev, field::kFileOffset);
        AppendField(key, ev, field::kFileLength);
        break;
    case 20:
        AppendField(key, ev, field::kTargetPid);
        AppendField(key, ev, field::kThreadId);
        AppendField(key, ev, field::kStartAddress);
        break;
    case 21:
        AppendField(key, ev, field::kTargetPid);
        AppendField(key, ev, field::kThreadId);
        break;
    case 22:
        AppendField(key, ev, field::kTargetPid);
        AppendField(key, ev, field::kBaseAddress);
        AppendField(key, ev, field::kMemorySize);
        break;
    case 23:
        AppendField(key, ev, field::kFilePath);
        break;
    case 24:
        AppendField(key, ev, field::kUsbDriveLetter);
        AppendField(key, ev, field::kUsbSerial);
        AppendField(key, ev, field::kUsbDeviceName);
        AppendField(key, ev, field::kUsbAction);
        break;
    case 25:
        AppendField(key, ev, field::kListenerIp);
        AppendField(key, ev, field::kListenerPort);
        AppendField(key, ev, field::kListenerProtocol);
        AppendField(key, ev, field::kListenerPid);
        AppendField(key, ev, field::kListenerAction);
        break;
    case 26:
        AppendField(key, ev, field::kServiceName);
        AppendField(key, ev, field::kServiceAction);
        AppendField(key, ev, field::kServiceImagePath);
        break;
    case 27:
        AppendField(key, ev, field::kCriticalProcessImage);
        AppendField(key, ev, field::kCriticalProcessPid);
        AppendField(key, ev, field::kCriticalProcessAction);
        break;
    case 28:
        AppendField(key, ev, field::kFimPath);
        AppendField(key, ev, field::kFimAction);
        AppendField(key, ev, field::kFimSha256);
        break;
    case 29:
        AppendField(key, ev, field::kShareName);
        AppendField(key, ev, field::kShareAction);
        AppendField(key, ev, field::kSharePath);
        break;
    case 30:
        AppendField(key, ev, field::kSource);
        AppendField(key, ev, field::kType);
        break;
    case 49:
        AppendField(key, ev, field::kTargetPid);
        AppendField(key, ev, field::kAccessMask);
        AppendField(key, ev, field::kObjectType);
        break;
    case 50:
        AppendField(key, ev, field::kOldFilePath);
        break;
    case 51:
        AppendField(key, ev, field::kRegKey);
        AppendField(key, ev, field::kRegValue);
        AppendField(key, ev, field::kRegOperation);
        break;
    case 53:
        AppendField(key, ev, field::kFirewallRuleName);
        AppendField(key, ev, field::kFirewallAction);
        AppendField(key, ev, field::kFirewallDir);
        AppendField(key, ev, field::kFirewallLocalPort);
        break;
    case 54:
        AppendField(key, ev, field::kPipeName);
        AppendField(key, ev, field::kPipeOperation);
        break;
    default:
        AppendField(key, ev, field::kAccountName);
        AppendField(key, ev, field::kGroupName);
        AppendField(key, ev, field::kAccountAction);
        AppendField(key, ev, field::kGroupAction);
        AppendField(key, ev, field::kAccountType);
        break;
    }
    return key.size() == semanticLength ? std::string() : key;
}

void SemanticDeduplicator::Forget(const Event& ev) {
    const auto key = SemanticKey(ev);
    if (!key.empty()) m_seen.erase(key);
}

bool SemanticDeduplicator::IsDuplicate(const Event& ev) {
    const auto key = SemanticKey(ev);
    if (key.empty()) return false;

    constexpr uint64_t kWindow = 2ULL * 10000000ULL;
    constexpr size_t kMaxEntries = 4096;
    auto found = m_seen.find(key);
    bool duplicate = found != m_seen.end() && ev.ts100ns >= found->second &&
                     ev.ts100ns - found->second <= kWindow;
    if (!duplicate) {
        if (found == m_seen.end()) m_seen[key] = ev.ts100ns;
        else if (ev.ts100ns > found->second) found->second = ev.ts100ns;
    }
    if (m_seen.size() > kMaxEntries) {
        uint64_t cutoff = ev.ts100ns > kWindow ? ev.ts100ns - kWindow : 0;
        for (auto it = m_seen.begin(); it != m_seen.end();) {
            if (it->second < cutoff) it = m_seen.erase(it); else ++it;
        }
        if (m_seen.size() > kMaxEntries) m_seen.erase(m_seen.begin());
    }
    return duplicate;
}

EventBus::EventBus(size_t capacity) : m_capacity(capacity) {}

EventBus::~EventBus() {
    Stop();
}

void EventBus::Start(ISink* sink) {
    m_sink = sink;
    m_stop.store(false);
    m_thread = std::thread(&EventBus::ConsumerLoop, this);
}

void EventBus::Stop() {
    std::deque<QueuedEvent> abandoned;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_thread.joinable()) {
            abandoned.swap(m_queue);
            m_stats.abandoned += abandoned.size();
            m_dropped.fetch_add(abandoned.size());
        } else {
            m_stop.store(true);
        }
    }
    for (const auto& item : abandoned) AcknowledgeConsumption(item.event, false);
    m_cv.notify_all();
    if (m_thread.joinable()) {
        m_thread.join();
    }
}

bool EventBus::Push(const Event& ev) {
    bool dropped = false;
    std::optional<Event> evicted;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_capacity == 0) {
            m_dropped.fetch_add(1);
            ++m_stats.overflowDropped;
            dropped = true;
            evicted = ev;
        } else {
            if (m_queue.size() >= m_capacity) {
                evicted = std::move(m_queue.front().event);
                m_queue.pop_front();
                m_dropped.fetch_add(1);
                ++m_stats.overflowDropped;
                dropped = true;
            }
            m_queue.push_back({ev, std::chrono::steady_clock::now()});
            if (m_queue.size() > m_stats.highWatermark)
                m_stats.highWatermark = m_queue.size();
        }
    }
    if (evicted) AcknowledgeConsumption(*evicted, false);
    m_cv.notify_one();
    return !dropped;
}

size_t EventBus::Pending() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_queue.size();
}

EventBusStats EventBus::SnapshotStats() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    EventBusStats sample = m_stats;
    sample.capacity = m_capacity;
    sample.pending = m_queue.size();
    sample.dropped = m_dropped.load();
    if (!m_queue.empty()) {
        const auto age = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - m_queue.front().enqueued).count();
        sample.oldestPendingMs = age > 0 ? static_cast<uint64_t>(age) : 0;
    }
    return sample;
}

void EventBus::ConsumerLoop() {
    for (;;) {
        Event ev;
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_cv.wait(lock, [&] { return m_stop.load() || !m_queue.empty(); });
            if (m_stop.load() && m_queue.empty()) {
                return;
            }
            ev = std::move(m_queue.front().event);
            m_queue.pop_front();
            m_stats.inFlight = 1;
        }
        if (m_deduplicator.IsDuplicate(ev)) {
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_stats.inFlight = 0;
                ++m_stats.consumed;
                ++m_stats.deduplicated;
            }
            AcknowledgeConsumption(ev, true);
            continue;
        }
        bool consumed = false;
        try {
            if (m_sink != nullptr) {
                m_sink->OnEvent(ev);
                consumed = true;
            }
        } catch (...) {
            std::fprintf(stderr, "[edr-bus] consumer failed; event not acknowledged\n");
        }
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_stats.inFlight = 0;
            if (consumed) ++m_stats.consumed;
            else {
                ++m_stats.consumerFailed;
                m_dropped.fetch_add(1);
            }
        }
        if (!consumed) m_deduplicator.Forget(ev);
        AcknowledgeConsumption(ev, consumed);
    }
}

const char* EventTypeName(uint16_t type) {
    switch (type) {
    case 1: return "PROCESS_START";
    case 2: return "PROCESS_STOP";
    case 3: return "REG_WRITE";
    case 4: return "FILE_CREATE";
    case 5: return "NET_CONNECT";
    case 6: return "STATS";
    case 7: return "IMAGE_LOAD";
    case 8: return "DNS_QUERY";
    case 9: return "PROCESS_ACCESS";
    case 10: return "LOGON";
    case 11: return "ACCOUNT_CHANGE";
    case 12: return "SERVICE_INSTALL";
    case 13: return "WMI_EVENT";
    case 14: return "TASK_SCHEDULER";
    case 15: return "PRIVILEGE";
    case 16: return "POWERSHELL_SCRIPT";
    case 17: return "THREAD_CREATE";
    case 18: return "PROCESS_READ";
    case 19: return "FILE_READ";
    case 20: return "APC_INJECT";
    case 21: return "CONTEXT_CHANGE";
    case 22: return "MEMORY_WRITE";
    case 23: return "FILE_DELETE";
    case 24: return "USB_DEVICE";
    case 25: return "NET_LISTENER";
    case 26: return "SERVICE_CHANGE";
    case 27: return "CRITICAL_PROCESS";
    case 28: return "FILE_INTEGRITY";
    case 29: return "SHARE_CHANGE";
    case 30: return "BLOCK";
    case 31: return "DEFENDER";
    case 32: return "RPC_CREATE_PROCESS";
    case 33: return "WINDOWS_HOOK";
    case 34: return "SERVICE_INSTALL_HOOK";
    case 35: return "SERVICE_START_HOOK";
    case 36: return "SERVICE_CONFIG_CHANGE";
    case 37: return "CO_INSTANCE";
    case 38: return "SECTION_MAP";
    case 39: return "HANDLE_DUPLICATE";
    case 40: return "INPUT_SIMULATION";
    case 41: return "SYSTEM_SHUTDOWN";
    case 42: return "SYSTEM_TIME_CHANGE";
    case 43: return "CLIPBOARD_ACCESS";
    case 44: return "WALLPAPER_CHANGE";
    case 45: return "CAMERA_ACCESS";
    case 46: return "KEYLOGGER";
    case 47: return "POWERSHELL_HOOK";
    case 48: return "AUDIT_LOG";
    case 49: return "HANDLE_OPEN";
    case 50: return "FILE_RENAME";
    case 51: return "REG_DELETE";
    case 52: return "LOCAL_ACCOUNT";
    case 53: return "FIREWALL_RULE";
    case 54: return "NAMED_PIPE";
    case 55: return "ETW_TAMPER";
    case 56: return "RAT_ANALYZER";
    case 57: return "RDP_SESSION";
    case 58: return "INCIDENT_CORRELATED";
    default: return "UNKNOWN";
    }
}

} // namespace edr
