/*
 * collector_local_account.h - Local user account / group membership monitor.
 *
 * Polls local users (NetUserEnum) and a configured set of local groups
 * (NetLocalGroupGetMembers) and emits LOCAL_ACCOUNT events when accounts
 * are added/removed/modified or group membership changes. Detects account
 * creation (T1136) and account manipulation (T1098) without relying on
 * the Windows Security log.
 */
#ifndef EDR_COLLECTOR_LOCAL_ACCOUNT_H
#define EDR_COLLECTOR_LOCAL_ACCOUNT_H

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace edr {

class ICollector;

struct LocalAccountUser {
    std::string name;
    std::string fullName;
    bool enabled = false;
};
struct LocalAccountMember {
    std::string name;
    std::string domain;
};

/* A narrow page-query seam: empty group means local users. MoreData pages
 * must advance resumeHandle; only a final Complete page commits a domain.
 * Missing is valid only for groups. Providers run on the worker thread;
 * exceptions represent a fatal worker failure, Failed is recoverable. */
enum class LocalAccountQueryStatus { Complete, MoreData, Missing, Failed };
struct LocalAccountPage {
    LocalAccountQueryStatus status = LocalAccountQueryStatus::Failed;
    uint64_t resumeHandle = 0;
    std::vector<LocalAccountUser> users;
    std::vector<LocalAccountMember> members;
};
using LocalAccountQuery =
    std::function<LocalAccountPage(const std::string& group, uint64_t resumeHandle)>;

ICollector* CreateLocalAccountCollector(
    uint32_t pollMs, const std::vector<std::string>& watchGroups);
ICollector* CreateLocalAccountCollector(
    uint32_t pollMs, const std::vector<std::string>& watchGroups,
    LocalAccountQuery query);

} // namespace edr

#endif /* EDR_COLLECTOR_LOCAL_ACCOUNT_H */
