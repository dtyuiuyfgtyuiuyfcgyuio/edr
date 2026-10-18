#pragma once
#ifndef EDR_HOST_ISOLATION_H
#define EDR_HOST_ISOLATION_H

#include <windows.h>

#include <atomic>
#include <cstdint>
#include <string>
#include <mutex>

namespace edr {

struct HostIsolationStatus {
    bool isolated = false;
    std::string managementIp;
    std::string allowedPorts;
    uint64_t isolatedSinceMs = 0;
    uint64_t elapsedMs = 0;
};

class HostIsolationController {
public:
    HostIsolationController();
    ~HostIsolationController();

    static bool ValidateIsolationParameters(const std::string& managementIp,
                                            const std::string& allowedPorts,
                                            std::string& error);

    /* Enter isolation mode: block all network traffic except management IP/ports.
     * Returns true on success, sets error message on failure. */
    bool EnableIsolation(const std::string& managementIp,
                        const std::string& allowedPorts,
                        std::string& error);

    /* Exit isolation mode and restore original firewall rules. */
    bool DisableIsolation(std::string& error);

    /* Check if currently in isolation mode. */
    bool Isolated() const { return m_isolated.load(); }

    /* Return a thread-safe snapshot of controller state. */
    HostIsolationStatus GetStatus() const;

    /* Get isolation status as JSON string for reporting. */
    std::string GetStatusJson() const;

private:
    /* Add a firewall rule to block all inbound/outbound except management. */
    bool AddBlockAllRules(const std::string& managementIp,
                          const std::string& allowedPorts,
                          std::string& error);

    /* Remove all isolation-related firewall rules. */
    bool RemoveIsolationRules(std::string& error);

    /* Execute netsh with validated arguments and capture output. */
    bool ExecuteNetsh(const std::string& arguments, std::string& output,
                      DWORD& errorCode);

    std::atomic<bool> m_isolated{false};
    mutable std::mutex m_mutex;
    std::string m_managementIp;
    std::string m_allowedPorts;
    uint64_t m_isolatedSinceMs = 0;
};

} // namespace edr

#endif /* EDR_HOST_ISOLATION_H */
