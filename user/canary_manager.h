/*
 * canary_manager.h - Canary (honeypot) file collector.
 *
 * Deploys decoy "canary" files at configured paths on Start() and watches
 * them while the agent runs. Legitimate software never touches a canary,
 * so ANY interaction is treated as attacker activity:
 *   - content/size/metadata change  -> fim_action=modified
 *   - file missing                  -> fim_action=removed
 *   - LastAccessTime advanced       -> fim_action=accessed (best effort;
 *                                      NTFS LastAccess updates may be
 *                                      disabled system-wide, in which case
 *                                      reads are not observable)
 *
 * Events are emitted as EDR_EVT_FILE_INTEGRITY with field "canary"="true"
 * so the downstream CanaryDetector can score them without confusing them
 * with ordinary FIM watch-file events.
 *
 * Thread-safety: one internal worker thread started by Start(); Stop()
 * joins it. Only the worker pushes events.
 */
#ifndef EDR_CANARY_MANAGER_H
#define EDR_CANARY_MANAGER_H

#include <atomic>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>

#include "collector.h"

namespace edr {

class EventBus;

class CanaryManager : public ICollector {
public:
    /* pollMs: watch interval; maxFileBytes: hash cap for tamper checks;
     * files: absolute canary paths (missing parents are reported once). */
    CanaryManager(uint32_t pollMs, uint64_t maxFileBytes,
                  std::vector<std::string> files);

    ~CanaryManager() override;

    bool Start(EventBus* bus) override;
    void Stop() override;

    size_t DeployedCount() const { return m_deployed.size(); }

private:
    struct Snapshot {
        bool present = false;
        uint64_t size = 0;
        uint64_t writeTime100ns = 0;
        uint64_t accessTime100ns = 0;
        std::string sha256; /* empty when not computed */
    };

    static bool Deploy(const std::string& utf8Path);
    Snapshot TakeSnapshot(const std::wstring& widePath);
    void Emit(const std::string& path, const char* action);
    void Run();

    uint32_t m_pollMs;
    uint64_t m_maxFileBytes;
    std::vector<std::string> m_files;
    std::vector<std::string> m_deployed;
    EventBus* m_bus = nullptr;
    std::thread m_thread;
    std::atomic<bool> m_stop{false};
};

ICollector* CreateCanaryCollector(uint32_t pollMs, uint64_t maxFileBytes,
                                  std::vector<std::string> files);

} // namespace edr

#endif /* EDR_CANARY_MANAGER_H */
