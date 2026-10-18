/*
 * driver_policy_publisher.h - Push the agent config to the EDR driver.
 *
 * Independent of iMonitor: opens "\\.\edrdrv" and issues
 * IOCTL_EDR_SET_POLICY with exactly one validated EDR_POLICY_V1 table.
 * Retries on startup/reconnect. Never claims BLOCK readiness on failure.
 */
#ifndef EDR_DRIVER_POLICY_PUBLISHER_H
#define EDR_DRIVER_POLICY_PUBLISHER_H

#include <cstdint>
#include <string>
#include <vector>

#include "config.h"

namespace edr {

/* Serialize + validate the policy table (pure; allocation-free table build
 * except the caller's buffer). Throws std::runtime_error when the config
 * cannot be expressed as a valid table (invalid path, IP, count overflow). */
struct DriverPolicyBuildResult {
    std::vector<uint8_t> bytes; /* EDR_POLICY_SIZE bytes, packed */
    std::string error;          /* empty on success */
};

DriverPolicyBuildResult BuildDriverPolicy(const Config& cfg,
                                          uint32_t generation);

/* Thin wrapper around CreateFileA + DeviceIoControl(IOCTL_EDR_SET_POLICY).
 * Returns true only when the driver accepted the table. */
bool PushDriverPolicy(const std::vector<uint8_t>& policy,
                      std::string& error);

/* Convenience: build (generation auto-increments per call) and push.
 * Returns true on success; on failure fills `error` with a description. */
bool PublishDriverPolicy(const Config& cfg, std::string& error);

} // namespace edr

#endif /* EDR_DRIVER_POLICY_PUBLISHER_H */
