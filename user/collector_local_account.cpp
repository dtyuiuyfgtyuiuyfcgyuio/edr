/* Complete, bounded local-user and local-group snapshots. Each domain keeps
 * its last complete baseline through failures or a missing configured group. */
#include <windows.h>
#include <lm.h>
#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <utility>
#include <vector>
#include "collector.h"
#include "collector_local_account.h"
#include "collector_runtime_health.h"
#include "config.h"
#include "edr_event.h"

namespace edr {
namespace {
using Status = LocalAccountQueryStatus;
constexpr size_t kMaxGroups = 32;
constexpr size_t kMaxGroupBytes = 1024;
constexpr size_t kMaxValueBytes = 4096;
constexpr size_t kMaxEntries = 16384;
constexpr size_t kMaxPages = 256;
constexpr size_t kDomainBudget = 4 * 1024 * 1024;
constexpr size_t kRetainedBudget = 16 * 1024 * 1024;
constexpr DWORD kPageBytes = 64 * 1024;

bool ValidText(const std::string& value, size_t limit, bool allowEmpty = true) {
    if (value.empty()) return allowEmpty;
    return value.size() <= limit && value.find('\0') == std::string::npos &&
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
            static_cast<int>(value.size()), nullptr, 0) != 0;
}
class NetBuffer {
public:
    LPBYTE data = nullptr;
    ~NetBuffer() { if (data) NetApiBufferFree(data); }
    NetBuffer() = default;
    NetBuffer(const NetBuffer&) = delete;
    NetBuffer& operator=(const NetBuffer&) = delete;
};
// Check pointers and terminators against the returned allocation before reading.
bool ReadText(const NetBuffer& buffer, DWORD bytes, const wchar_t* text,
              std::string& result, bool allowNull) {
    if (!text) { result.clear(); return allowNull; }
    const auto base = reinterpret_cast<uintptr_t>(buffer.data);
    const auto address = reinterpret_cast<uintptr_t>(text);
    if (address < base || address - base >= bytes || address % alignof(wchar_t)) return false;
    const size_t available = (bytes - (address - base)) / sizeof(wchar_t);
    const size_t bound = (std::min)(available, kMaxValueBytes + 1);
    size_t length = 0;
    while (length < bound && text[length] != L'\0') ++length;
    if (length == bound || length > kMaxValueBytes) return false;
    if (length != 0 && WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
        text, static_cast<int>(length), nullptr, 0, nullptr, nullptr) == 0)
        return false;
    const std::wstring bounded(text, length);
    result = WideToUtf8(bounded.c_str());
    return (length == 0 || !result.empty()) && ValidText(result, kMaxValueBytes);
}

LocalAccountPage QueryNativePage(const std::string& group, uint64_t resume) {
    LocalAccountPage page;
    NetBuffer buffer;
    DWORD read = 0, total = 0;
    NET_API_STATUS status;
    if (group.empty()) {
        if (resume > MAXDWORD) return page;
        DWORD handle = static_cast<DWORD>(resume);
        status = NetUserEnum(nullptr, 2, FILTER_NORMAL_ACCOUNT, &buffer.data,
                             kPageBytes, &read, &total, &handle);
        page.resumeHandle = handle;
    } else {
        if (resume > static_cast<uint64_t>(~DWORD_PTR(0))) return page;
        DWORD_PTR handle = static_cast<DWORD_PTR>(resume);
        const std::wstring wide = Utf8ToWide(group);
        status = NetLocalGroupGetMembers(nullptr, wide.c_str(), 2, &buffer.data,
                                         kPageBytes, &read, &total, &handle);
        page.resumeHandle = handle;
        if (status == ERROR_NO_SUCH_ALIAS || status == NERR_GroupNotFound) {
            page.status = Status::Missing;
            return page;
        }
    }
    if (status != NERR_Success && status != ERROR_MORE_DATA) return page;
    DWORD bytes = 0;
    if (read > kMaxEntries || (read && !buffer.data) ||
        (buffer.data && (NetApiBufferSize(buffer.data, &bytes) != NERR_Success ||
                         bytes > kDomainBudget))) return page;
    const size_t stride = group.empty() ? sizeof(USER_INFO_2) : sizeof(LOCALGROUP_MEMBERS_INFO_2);
    if (read > bytes / stride) return page;
    for (DWORD i = 0; i < read; ++i) {
        if (group.empty()) {
            const auto& raw = reinterpret_cast<const USER_INFO_2*>(buffer.data)[i];
            LocalAccountUser user;
            if (!ReadText(buffer, bytes, raw.usri2_name, user.name, false) || user.name.empty() ||
                !ReadText(buffer, bytes, raw.usri2_full_name, user.fullName, true)) return {};
            user.enabled = (raw.usri2_flags & UF_ACCOUNTDISABLE) == 0;
            page.users.push_back(std::move(user));
        } else {
            const auto& raw = reinterpret_cast<const LOCALGROUP_MEMBERS_INFO_2*>(buffer.data)[i];
            std::string full;
            if (!ReadText(buffer, bytes, raw.lgrmi2_domainandname, full, false) || full.empty()) return {};
            LocalAccountMember member;
            const auto slash = full.find('\\');
            member.domain = slash == std::string::npos ? "" : full.substr(0, slash);
            member.name = slash == std::string::npos ? full : full.substr(slash + 1);
            page.members.push_back(std::move(member));
        }
    }
    page.status = status == NERR_Success ? Status::Complete : Status::MoreData;
    return page;
}

enum class Result { Complete, Missing, Failed };
struct Candidate {
    Result result = Result::Failed;
    std::map<std::string, LocalAccountUser> users;
    std::map<std::string, LocalAccountMember> members;
    size_t charge = 0;
    bool capacity = false;
    bool invalid = false;
};
struct Domain {
    std::string group;
    Candidate baseline;
    bool seeded = false;
    // 0 unqueried, 1 complete, 2 missing, 3 failed.
    unsigned state = 0;
};
struct Coverage {
    uint64_t complete = 0, missing = 0, failed = 0, pending = 0, retained = 0;
};
} // namespace

class LocalAccountCollector : public ICollector {
public:
    LocalAccountCollector(uint32_t pollMs, const std::vector<std::string>& groups,
                          LocalAccountQuery query)
        : m_pollMs((std::max)(1u, pollMs)), m_query(std::move(query)) {
        if (!m_query) m_query = QueryNativePage;
        m_domains.push_back({}); // User domain is always monitored.
        const std::vector<std::string> defaults = {
            "Administrators", "Remote Desktop Users", "Backup Operators"};
        const auto& selected = groups.empty() ? defaults : groups;
        if (selected.size() > kMaxGroups) { m_configValid = false; return; }
        std::set<std::string> seen;
        for (const auto& group : selected) {
            if (!ValidText(group, kMaxGroupBytes, false)) { m_configValid = false; return; }
            // Duplicate configured domains consume no extra retained baseline.
            if (seen.insert(group).second) {
                Domain domain; domain.group = group; m_domains.push_back(std::move(domain));
            }
        }
        m_configCharge = m_domains.capacity() * sizeof(Domain);
        for (const auto& domain : m_domains)
            m_configCharge += 2 * domain.group.size();
        PublishCoverage();
    }
    ~LocalAccountCollector() override { Stop(); }

    bool Start(EventBus* bus) override {
        if (m_thread.joinable()) return !m_workerFailed.load();
        if (!bus) return false;
        m_explicitStop.store(false);
        if (!m_configValid) return false;
        m_bus = bus;
        m_stop.store(false);
        m_workerFailed.store(false);
        for (auto& domain : m_domains) {
            domain.baseline = {}; domain.seeded = false; domain.state = 0;
        }
        PublishCoverage();
        try { m_thread = std::thread(&LocalAccountCollector::Run, this); }
        catch (...) {
            m_stop.store(true); m_workerFailed.store(true);
            m_health.RecordSourceError(); m_bus = nullptr; return false;
        }
        return true;
    }
    void Stop() override {
        m_explicitStop.store(true);
        m_stop.store(true);
        m_wake.notify_all();
        if (m_thread.joinable()) m_thread.join();
        m_bus = nullptr;
    }
    CollectorHealthSnapshot GetHealthSnapshot() const override {
        const bool stopped = m_explicitStop.load();
        auto sample = m_health.Snapshot(!stopped && m_workerFailed.load() ? "source_error" : "stopped");
        Coverage coverage;
        { std::lock_guard<std::mutex> lock(m_coverageMutex); coverage = m_coverage; }
        if (!stopped && !m_configValid) sample.state = "config_error";
        else if (!stopped && m_workerFailed.load()) sample.state = "source_error";
        else if (!stopped && sample.running) {
            sample.state = coverage.failed ? "source_error" :
                coverage.missing ? "coverage_degraded" : coverage.pending ? "starting" : "running";
        }
        sample.counters["configured_groups"] = m_domains.size() - 1;
        sample.counters["successful_domains"] = coverage.complete;
        sample.counters["missing_groups"] = coverage.missing;
        sample.counters["failed_domains"] = coverage.failed;
        sample.counters["pending_domains"] = coverage.pending;
        sample.counters["retained_bytes"] = coverage.retained;
        sample.counters["source_available"] = m_configValid && !m_workerFailed.load() &&
            coverage.complete == m_domains.size() ? 1 : 0;
        sample.counters["capacity_rejections"] = m_capacityRejections.load();
        sample.counters["invalid_snapshots"] = m_invalidSnapshots.load();
        sample.counters["missing_group_observations"] = m_missingObservations.load();
        return sample;
    }
private:
    Candidate QueryDomain(const std::string& group) {
        Candidate candidate;
        std::set<uint64_t> handles{0};
        uint64_t resume = 0;
        for (size_t pageIndex = 0; pageIndex < kMaxPages && !m_stop.load(); ++pageIndex) {
            LocalAccountPage page = m_query(group, resume);
            if (page.status == Status::Failed) return candidate;
            if (page.status == Status::Missing) {
                // A missing result is not an empty complete membership list.
                if (!group.empty() && pageIndex == 0 && page.users.empty() && page.members.empty())
                    candidate.result = Result::Missing;
                else candidate.invalid = true;
                return candidate;
            }
            if (page.status != Status::Complete && page.status != Status::MoreData) {
                candidate.invalid = true; return candidate;
            }
            if ((group.empty() && !page.members.empty()) || (!group.empty() && !page.users.empty())) {
                candidate.invalid = true; return candidate;
            }
            const size_t count = group.empty() ? page.users.size() : page.members.size();
            const size_t existing = group.empty() ? candidate.users.size() : candidate.members.size();
            if (count > kMaxEntries - existing) { candidate.capacity = true; return candidate; }
            for (auto& user : page.users) {
                if (user.name.size() > kMaxValueBytes || user.fullName.size() > kMaxValueBytes) {
                    candidate.capacity = true; return candidate;
                }
                if (!ValidText(user.name, kMaxValueBytes, false) || !ValidText(user.fullName, kMaxValueBytes)) {
                    candidate.invalid = true; return candidate;
                }
                // Includes duplicated map keys and a conservative per-entry node allowance.
                const size_t charge = 256 + 2 * (user.name.size() + user.fullName.size());
                if (charge > kDomainBudget - candidate.charge) { candidate.capacity = true; return candidate; }
                const std::string key = user.name;
                if (!candidate.users.emplace(key, std::move(user)).second) { candidate.invalid = true; return candidate; }
                candidate.charge += charge;
            }
            for (auto& member : page.members) {
                if (member.name.size() > kMaxValueBytes || member.domain.size() > kMaxValueBytes) {
                    candidate.capacity = true; return candidate;
                }
                if (!ValidText(member.name, kMaxValueBytes, false) || !ValidText(member.domain, kMaxValueBytes) ||
                    member.name.find('\\') != std::string::npos || member.domain.find('\\') != std::string::npos) {
                    candidate.invalid = true; return candidate;
                }
                const size_t charge = 256 + 2 * (member.name.size() + member.domain.size() + 1);
                if (charge > kDomainBudget - candidate.charge) { candidate.capacity = true; return candidate; }
                const std::string key = member.domain + "\\" + member.name;
                if (!candidate.members.emplace(key, std::move(member)).second) { candidate.invalid = true; return candidate; }
                candidate.charge += charge;
            }
            if (page.status == Status::Complete) { candidate.result = Result::Complete; return candidate; }
            if (count == 0 || page.resumeHandle == resume || !handles.insert(page.resumeHandle).second) {
                candidate.invalid = true; return candidate;
            }
            resume = page.resumeHandle;
        }
        candidate.capacity = !m_stop.load();
        return candidate;
    }
    void PublishCoverage() {
        Coverage coverage;
        coverage.retained = m_configCharge;
        for (const auto& domain : m_domains) {
            if (domain.state == 1) ++coverage.complete;
            else if (domain.state == 2) ++coverage.missing;
            else if (domain.state == 3) ++coverage.failed;
            else ++coverage.pending;
            coverage.retained += domain.baseline.charge;
        }
        std::lock_guard<std::mutex> lock(m_coverageMutex); m_coverage = coverage;
    }
    void Submit(Event& event) {
        event.type = EDR_EVT_LOCAL_ACCOUNT;
        event.source = "local_account_monitor";
        FILETIME now = {}; GetSystemTimePreciseAsFileTime(&now);
        event.ts100ns = (static_cast<uint64_t>(now.dwHighDateTime) << 32) | now.dwLowDateTime;
        event.fields[field::kSource] = event.source;
        event.fields[field::kType] = "LOCAL_ACCOUNT";
        if (m_bus) m_health.RecordEventSubmitted(!m_bus->Push(event));
    }
    void EmitUser(const LocalAccountUser& user, const char* action) {
        Event event;
        event.fields[field::kAccountType] = "user";
        event.fields[field::kAccountName] = user.name;
        event.fields[field::kAccountAction] = action;
        if (!user.fullName.empty()) event.fields[field::kAccountFullName] = user.fullName;
        event.fields[field::kAccountEnabled] = user.enabled ? "true" : "false";
        Submit(event);
    }
    void EmitMember(const std::string& group, const LocalAccountMember& member, const char* action) {
        Event event;
        event.fields[field::kAccountType] = "group";
        event.fields[field::kGroupName] = group;
        event.fields[field::kGroupAction] = action;
        event.fields[field::kGroupMember] = member.name;
        if (!member.domain.empty()) event.fields[field::kGroupMemberDomain] = member.domain;
        Submit(event);
    }
    void Diff(const Domain& previous, const Candidate& current) {
        if (previous.group.empty()) {
            for (const auto& item : current.users) {
                auto old = previous.baseline.users.find(item.first);
                if (old == previous.baseline.users.end()) EmitUser(item.second, "added");
                else if (old->second.fullName != item.second.fullName || old->second.enabled != item.second.enabled)
                    EmitUser(item.second, "modified");
            }
            for (const auto& item : previous.baseline.users)
                if (!current.users.count(item.first)) EmitUser(item.second, "removed");
        } else {
            for (const auto& item : current.members)
                if (!previous.baseline.members.count(item.first)) EmitMember(previous.group, item.second, "added");
            for (const auto& item : previous.baseline.members)
                if (!current.members.count(item.first)) EmitMember(previous.group, item.second, "removed");
        }
    }
    void Run() noexcept {
        m_health.WorkerStarted();
        struct Stopped { CollectorRuntimeHealth& health; ~Stopped() { health.WorkerStopped(); } } stopped{m_health};
        try {
            size_t retained = m_configCharge;
            while (!m_stop.load()) {
                for (auto& domain : m_domains) {
                    if (m_stop.load()) break;
                    Candidate candidate = QueryDomain(domain.group);
                    if (m_stop.load()) break;
                    const size_t otherRetained = retained - domain.baseline.charge;
                    if (candidate.result == Result::Complete && candidate.charge > kRetainedBudget - otherRetained) {
                        candidate.result = Result::Failed; candidate.capacity = true;
                    }
                    if (candidate.result == Result::Complete) {
                        if (domain.seeded) Diff(domain, candidate);
                        retained = otherRetained + candidate.charge;
                        domain.baseline = std::move(candidate);
                        domain.seeded = true; domain.state = 1;
                        m_health.RecordSnapshotSuccess();
                    } else if (candidate.result == Result::Missing) {
                        domain.state = 2; m_missingObservations.fetch_add(1);
                    } else {
                        domain.state = 3; m_health.RecordSourceError();
                        if (candidate.capacity) m_capacityRejections.fetch_add(1);
                        if (candidate.invalid) { m_invalidSnapshots.fetch_add(1); m_health.RecordParseError(); }
                    }
                    PublishCoverage();
                }
                std::unique_lock<std::mutex> lock(m_waitMutex);
                m_wake.wait_for(lock, std::chrono::milliseconds(m_pollMs), [&] { return m_stop.load(); });
            }
        } catch (...) { m_workerFailed.store(true); m_health.RecordSourceError(); }
    }
    uint32_t m_pollMs;
    LocalAccountQuery m_query;
    std::vector<Domain> m_domains;
    size_t m_configCharge = 0;
    bool m_configValid = true;
    EventBus* m_bus = nullptr;
    std::thread m_thread;
    std::atomic<bool> m_stop{false}, m_explicitStop{false}, m_workerFailed{false};
    std::atomic<uint64_t> m_capacityRejections{0}, m_invalidSnapshots{0}, m_missingObservations{0};
    CollectorRuntimeHealth m_health;
    mutable std::mutex m_coverageMutex;
    Coverage m_coverage;
    std::mutex m_waitMutex;
    std::condition_variable m_wake;
};
ICollector* CreateLocalAccountCollector(uint32_t pollMs, const std::vector<std::string>& watchGroups) {
    return new LocalAccountCollector(pollMs, watchGroups, {});
}
ICollector* CreateLocalAccountCollector(uint32_t pollMs, const std::vector<std::string>& watchGroups,
                                       LocalAccountQuery query) {
    return new LocalAccountCollector(pollMs, watchGroups, std::move(query));
}
} // namespace edr
