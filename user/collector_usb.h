/*
 * collector_usb.h - USB storage device monitoring collector.
 *
 * Polls removable logical drives and emits USB_DEVICE events on insert /
 * removal. Detects removable media propagation (MITRE T1091) and the early
 * stage of exfiltration via USB storage.
 */
#ifndef EDR_COLLECTOR_USB_H
#define EDR_COLLECTOR_USB_H

#include <cstdint>
#include <array>
#include <functional>
#include <string>

namespace edr {

class ICollector;

enum class UsbDriveStatus { Failed, Missing, Present };

struct UsbDriveObservation {
    UsbDriveStatus status = UsbDriveStatus::Failed;
    bool metadataKnown = false;
    std::string serial;
    std::string volumeName;
    std::string fileSystem;
};

struct UsbSnapshot {
    bool driveSetChecked = false;
    std::array<UsbDriveObservation, 26> drives{};
};

using UsbCollectorQuery = std::function<UsbSnapshot()>;

ICollector* CreateUsbCollector(uint32_t pollMs, uint64_t dedupWindowMs);
ICollector* CreateUsbCollector(uint32_t pollMs, uint64_t dedupWindowMs,
                               UsbCollectorQuery query);

} // namespace edr

#endif /* EDR_COLLECTOR_USB_H */
