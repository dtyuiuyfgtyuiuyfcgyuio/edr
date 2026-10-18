/*
 * collector_usb.cpp - USB storage device monitoring collector.
 *
 * Each polling pass records a checked status for all 26 drive letters. Unknown
 * observations never erase a known baseline, and volume metadata is read once
 * per candidate only after stable mount identity checks.
 */
#include <windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <climits>
#include <cstdio>
#include <string>
#include <thread>
#include <utility>

#include "collector.h"
#include "collector_runtime_health.h"
#include "collector_usb.h"
#include "edr_event.h"

namespace edr {
namespace {

constexpr size_t kMaxFieldBytes = 4096;
constexpr uint32_t kMinPollMs = 50;
constexpr uint32_t kMaxPollMs = 60000;

bool IsValidUtf8Bounded(const std::string& input, bool allowEmpty = true) {
    if (input.size() > kMaxFieldBytes || (!allowEmpty && input.empty()) ||
        input.find('\0') != std::string::npos) return false;
    for (size_t i = 0; i < input.size();) {
        const unsigned char lead = static_cast<unsigned char>(input[i]);
        const size_t count = lead < 0x80 ? 1 :
            (lead >= 0xC2 && lead <= 0xDF ? 2 :
             lead >= 0xE0 && lead <= 0xEF ? 3 :
             lead >= 0xF0 && lead <= 0xF4 ? 4 : 0);
        if (count == 0 || i + count > input.size()) return false;
        for (size_t j = 1; j < count; ++j) {
            const unsigned char continuation = static_cast<unsigned char>(input[i + j]);
            if (continuation < 0x80 || continuation > 0xBF) return false;
        }
        if (count >= 3) {
            const unsigned char second = static_cast<unsigned char>(input[i + 1]);
            if ((lead == 0xE0 && second < 0xA0) ||
                (lead == 0xED && second >= 0xA0) ||
                (lead == 0xF0 && second < 0x90) ||
                (lead == 0xF4 && second >= 0x90)) return false;
        }
        i += count;
    }
    return true;
}

bool WideUtf8(const wchar_t* value, size_t capacity, std::string& output) {
    if (value == nullptr || capacity == 0) return false;
    const size_t chars = wcsnlen_s(value, capacity);
    if (chars >= capacity) return false;
    if (chars == 0) {
        output.clear();
        return true;
    }
    if (chars > static_cast<size_t>(INT_MAX)) return false;
    const int charCount = static_cast<int>(chars);
    const int bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value,
        charCount, nullptr, 0, nullptr, nullptr);
    if (bytes <= 0 || static_cast<size_t>(bytes) > kMaxFieldBytes) return false;
    std::string result(static_cast<size_t>(bytes), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, charCount,
            &result[0], bytes, nullptr, nullptr) != bytes) return false;
    output = std::move(result);
    return true;
}

std::wstring DriveRoot(size_t index) {
    return std::wstring(1, static_cast<wchar_t>(L'A' + index)) + L":\\";
}

std::wstring VolumeGuid(const std::wstring& root) {
    wchar_t name[MAX_PATH] = {};
    if (!GetVolumeNameForVolumeMountPointW(root.c_str(), name,
                                            static_cast<DWORD>(std::size(name))))
        return {};
    if (wcsnlen_s(name, std::size(name)) >= std::size(name)) return {};
    return name;
}

class CriticalErrorModeGuard {
public:
    CriticalErrorModeGuard() noexcept {
        DWORD previous = 0;
        if (!SetThreadErrorMode(SEM_FAILCRITICALERRORS, &previous)) return;
        m_previous = previous;
        if (previous != SEM_FAILCRITICALERRORS &&
            !SetThreadErrorMode(previous | SEM_FAILCRITICALERRORS, nullptr)) {
            SetThreadErrorMode(previous, nullptr);
            return;
        }
        m_active = true;
    }
    ~CriticalErrorModeGuard() {
        if (m_active) SetThreadErrorMode(m_previous, nullptr);
    }
    CriticalErrorModeGuard(const CriticalErrorModeGuard&) = delete;
    CriticalErrorModeGuard& operator=(const CriticalErrorModeGuard&) = delete;
    bool Active() const noexcept { return m_active; }
private:
    DWORD m_previous = 0;
    bool m_active = false;
};

UsbSnapshot QueryNativeUsbSnapshot() {
    UsbSnapshot result;
    const DWORD beforeMask = GetLogicalDrives();
    if (beforeMask == 0) return result;
    result.driveSetChecked = true;

    for (size_t i = 0; i < result.drives.size(); ++i) {
        UsbDriveObservation& observation = result.drives[i];
        const DWORD bit = (1u << i);
        if ((beforeMask & bit) == 0) {
            observation.status = UsbDriveStatus::Missing;
            continue;
        }

        const std::wstring root = DriveRoot(i);
        const UINT typeBefore = GetDriveTypeW(root.c_str());
        if (typeBefore == DRIVE_UNKNOWN || typeBefore == DRIVE_NO_ROOT_DIR) {
            observation.status = UsbDriveStatus::Failed;
            continue;
        }
        if (typeBefore != DRIVE_REMOVABLE) {
            observation.status = UsbDriveStatus::Missing;
            continue;
        }

        observation.status = UsbDriveStatus::Present;
        const std::wstring guidBefore = VolumeGuid(root);
        if (guidBefore.empty()) continue;

        wchar_t label[256] = {};
        wchar_t fileSystem[64] = {};
        DWORD serial = 0;
        DWORD maxComponentLength = 0;
        DWORD fileSystemFlags = 0;
        BOOL metadataRead = FALSE;
        {
            CriticalErrorModeGuard errorMode;
            if (errorMode.Active()) {
                metadataRead = GetVolumeInformationW(root.c_str(), label,
                    static_cast<DWORD>(std::size(label)), &serial, &maxComponentLength,
                    &fileSystemFlags, fileSystem,
                    static_cast<DWORD>(std::size(fileSystem)));
            }
        }

        /* A candidate is accepted only while the same volume remains mounted. */
        const DWORD afterMask = GetLogicalDrives();
        const UINT typeAfter = GetDriveTypeW(root.c_str());
        const std::wstring guidAfter = VolumeGuid(root);
        if (afterMask == 0 || (afterMask & bit) == 0 ||
            typeAfter != DRIVE_REMOVABLE || guidAfter.empty() ||
            guidBefore != guidAfter || !metadataRead) {
            continue;
        }

        std::string volumeName;
        std::string fileSystemText;
        if (!WideUtf8(label, std::size(label), volumeName) ||
            !WideUtf8(fileSystem, std::size(fileSystem), fileSystemText))
            continue;

        char serialText[9] = {};
        std::snprintf(serialText, sizeof(serialText), "%08lX",
                      static_cast<unsigned long>(serial));
        observation.serial = serialText;
        observation.volumeName = std::move(volumeName);
        observation.fileSystem = std::move(fileSystemText);
        observation.metadataKnown = true;
    }
    const DWORD afterMask = GetLogicalDrives();
    if (afterMask == 0 || afterMask != beforeMask)
        result.driveSetChecked = false;
    return result;
}

struct BaselineDrive {
    bool known = false;
    bool present = false;
    std::string serial;
    std::string volumeName;
    std::string fileSystem;
};

bool NormalizeObservation(UsbDriveObservation& drive) {
    switch (drive.status) {
    case UsbDriveStatus::Failed:
        return true;
    case UsbDriveStatus::Missing:
        return !drive.metadataKnown && drive.serial.empty() &&
               drive.volumeName.empty() && drive.fileSystem.empty();
    case UsbDriveStatus::Present:
        if (!drive.metadataKnown)
            return drive.serial.empty() && drive.volumeName.empty() &&
                   drive.fileSystem.empty();
        if (drive.serial.size() != 8 ||
            !IsValidUtf8Bounded(drive.serial, false) ||
            !IsValidUtf8Bounded(drive.volumeName) ||
            !IsValidUtf8Bounded(drive.fileSystem, false)) return false;
        for (char& ch : drive.serial) {
            if (ch >= 'a' && ch <= 'f') ch = static_cast<char>(ch - 'a' + 'A');
            if (!((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F')))
                return false;
        }
        return true;
    }
    return false;
}

} // namespace

class UsbCollector final : public ICollector {
public:
    UsbCollector(uint32_t pollMs, uint64_t dedupWindowMs, UsbCollectorQuery query)
        : m_pollMs(std::clamp(pollMs, kMinPollMs, kMaxPollMs)),
          m_query(query ? std::move(query) : UsbCollectorQuery(QueryNativeUsbSnapshot)) {
        /* Preserve the factory signature; state transitions are never time-suppressed. */
        (void)dedupWindowMs;
    }

    ~UsbCollector() override { Stop(); }

    bool Start(EventBus* bus) override {
        if (bus == nullptr) return false;
        if (m_thread.joinable()) {
            if (m_health.Snapshot().running) return true;
            m_thread.join();
        }
        m_baseline = {};
        m_pendingBaselines.store(m_baseline.size());
        m_currentFailed.store(0);
        m_metadataUnknown.store(0);
        m_driveSetChecked.store(false);
        m_bus = bus;
        m_stop.store(false);
        m_fatal.store(false);
        m_userStopped.store(false);
        m_health.ResetSourceState();
        m_health.WorkerStarted();
        try {
            m_thread = std::thread(&UsbCollector::Run, this);
        } catch (...) {
            m_health.RecordSourceError();
            m_health.WorkerStopped();
            m_fatal.store(true);
            MarkWholeSnapshotFailure();
            m_bus = nullptr;
            return false;
        }
        return true;
    }

    void Stop() override {
        m_stop.store(true);
        if (m_thread.joinable()) m_thread.join();
        m_bus = nullptr;
        m_userStopped.store(true);
        m_health.WorkerStopped();
        if (m_emitCount.load() != 0 || m_health.Snapshot().sourceErrors != 0) {
            const auto health = m_health.Snapshot();
            std::fprintf(stderr, "[edr-usb] emitted=%llu errors=%llu\n",
                static_cast<unsigned long long>(m_emitCount.load()),
                static_cast<unsigned long long>(health.sourceErrors));
        }
    }

    CollectorHealthSnapshot GetHealthSnapshot() const override {
        const char* stoppedState = m_fatal.load() && !m_userStopped.load()
            ? "source_error" : "stopped";
        CollectorHealthSnapshot sample = m_health.Snapshot(stoppedState);
        sample.counters["current_failed_drives"] = m_currentFailed.load();
        sample.counters["pending_drive_baselines"] = m_pendingBaselines.load();
        sample.counters["metadata_unknown_drives"] = m_metadataUnknown.load();
        sample.counters["drive_set_checked"] = m_driveSetChecked.load() ? 1u : 0u;
        return sample;
    }

private:
    void MarkWholeSnapshotFailure() noexcept {
        m_currentFailed.store(m_baseline.size());
        m_metadataUnknown.store(0);
        m_driveSetChecked.store(false);
    }

    static uint64_t Now100ns() {
        FILETIME ft = {};
        GetSystemTimePreciseAsFileTime(&ft);
        return (static_cast<uint64_t>(ft.dwHighDateTime) << 32) |
               ft.dwLowDateTime;
    }

    void Emit(size_t index, const BaselineDrive& drive, const char* action) {
        Event ev;
        ev.type = EDR_EVT_USB_DEVICE;
        ev.ts100ns = Now100ns();
        ev.source = "usb_monitor";
        ev.fields[field::kSource] = ev.source;
        ev.fields[field::kType] = "USB_DEVICE";
        ev.fields[field::kUsbAction] = action;
        ev.fields[field::kUsbDriveLetter] =
            std::string(1, static_cast<char>('A' + index)) + ":";
        if (!drive.serial.empty()) ev.fields[field::kUsbSerial] = drive.serial;
        if (!drive.volumeName.empty())
            ev.fields[field::kUsbDeviceName] = drive.volumeName;
        if (!drive.fileSystem.empty())
            ev.fields[field::kUsbFileSystem] = drive.fileSystem;
        ev.fields[field::kUsbDeviceType] = "storage";
        if (m_bus != nullptr) {
            const bool accepted = m_bus->Push(ev);
            m_health.RecordEventSubmitted(!accepted);
            if (accepted) m_emitCount.fetch_add(1);
        }
    }

    bool Apply(const UsbSnapshot& rawSnapshot) {
        UsbSnapshot snapshot = rawSnapshot;
        size_t currentFailed = 0;
        size_t metadataUnknown = 0;
        for (UsbDriveObservation& sample : snapshot.drives) {
            if (sample.status == UsbDriveStatus::Present && !sample.metadataKnown)
                ++metadataUnknown;
            if (!NormalizeObservation(sample)) {
                sample.status = UsbDriveStatus::Failed;
                ++currentFailed;
                continue;
            }
            if (sample.status == UsbDriveStatus::Failed) {
                ++currentFailed;
            } else if (!snapshot.driveSetChecked &&
                       sample.status == UsbDriveStatus::Missing) {
                ++currentFailed;
            }
        }

        for (size_t i = 0; i < snapshot.drives.size(); ++i) {
            const UsbDriveObservation& sample = snapshot.drives[i];
            if (sample.status == UsbDriveStatus::Failed) continue;
            /* An incomplete mask cannot prove that a bit-absent drive vanished. */
            if (!snapshot.driveSetChecked &&
                sample.status == UsbDriveStatus::Missing) continue;
            BaselineDrive& old = m_baseline[i];
            const bool nowPresent = sample.status == UsbDriveStatus::Present;
            if (!old.known) {
                old.known = true;
                old.present = nowPresent;
                if (nowPresent && sample.metadataKnown) {
                    old.serial = sample.serial;
                    old.volumeName = sample.volumeName;
                    old.fileSystem = sample.fileSystem;
                }
                continue;
            }

            if (old.present && !nowPresent) {
                Emit(i, old, "removed");
                old = {};
                old.known = true;
                continue;
            }
            if (!old.present && nowPresent) {
                BaselineDrive added;
                added.known = true;
                added.present = true;
                if (sample.metadataKnown) {
                    added.serial = sample.serial;
                    added.volumeName = sample.volumeName;
                    added.fileSystem = sample.fileSystem;
                }
                Emit(i, added, "added");
                old = std::move(added);
                continue;
            }
            if (!nowPresent) continue;

            const std::string serial = sample.metadataKnown ? sample.serial : "";
            if (!old.serial.empty() && !serial.empty() && old.serial != serial) {
                Emit(i, old, "removed");
                BaselineDrive added;
                added.known = true;
                added.present = true;
                added.serial = serial;
                added.volumeName = sample.volumeName;
                added.fileSystem = sample.fileSystem;
                Emit(i, added, "added");
                old = std::move(added);
                continue;
            }
            /* Unknown metadata never clears a previously reliable identity. */
            if (sample.metadataKnown) {
                if (old.serial.empty() && !serial.empty()) old.serial = serial;
                old.volumeName = sample.volumeName;
                old.fileSystem = sample.fileSystem;
            }
        }
        size_t pending = 0;
        for (const BaselineDrive& drive : m_baseline)
            if (!drive.known) ++pending;
        m_currentFailed.store(currentFailed);
        m_pendingBaselines.store(pending);
        m_metadataUnknown.store(metadataUnknown);
        m_driveSetChecked.store(snapshot.driveSetChecked);
        return !snapshot.driveSetChecked || currentFailed != 0 || metadataUnknown != 0;
    }

    void SleepUntilNextPoll() {
        uint32_t waited = 0;
        while (waited < m_pollMs && !m_stop.load()) {
            const uint32_t part = std::min<uint32_t>(25, m_pollMs - waited);
            Sleep(part);
            waited += part;
        }
    }

    void Run() noexcept {
        try {
            while (!m_stop.load()) {
                UsbSnapshot snapshot = m_query();
                if (m_stop.load()) break;
                const bool failed = Apply(snapshot);
                if (failed) m_health.RecordSourceError();
                else m_health.RecordSnapshotSuccess();
                SleepUntilNextPoll();
            }
        } catch (...) {
            m_health.RecordSourceError();
            m_fatal.store(true);
            MarkWholeSnapshotFailure();
        }
        m_health.WorkerStopped();
    }

    uint32_t m_pollMs;
    EventBus* m_bus = nullptr;
    UsbCollectorQuery m_query;
    std::thread m_thread;
    std::atomic<bool> m_stop{false};
    std::atomic<bool> m_fatal{false};
    std::atomic<bool> m_userStopped{false};
    std::atomic<uint64_t> m_emitCount{0};
    std::atomic<uint64_t> m_currentFailed{0};
    std::atomic<uint64_t> m_pendingBaselines{26};
    std::atomic<uint64_t> m_metadataUnknown{0};
    std::atomic<bool> m_driveSetChecked{false};
    CollectorRuntimeHealth m_health;
    std::array<BaselineDrive, 26> m_baseline{};
};

ICollector* CreateUsbCollector(uint32_t pollMs, uint64_t dedupWindowMs) {
    return new UsbCollector(pollMs, dedupWindowMs, {});
}

ICollector* CreateUsbCollector(uint32_t pollMs, uint64_t dedupWindowMs,
                               UsbCollectorQuery query) {
    return new UsbCollector(pollMs, dedupWindowMs, std::move(query));
}

} // namespace edr
