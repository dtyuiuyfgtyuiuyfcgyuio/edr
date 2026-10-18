/*
 * memory_scanner_detector.h - Memory scanner detector.
 *
 * Detects suspicious memory artifacts in processes:
 * - Executable memory regions not backed by mapped files (shellcode)
 * - RWX (Read-Write-Execute) memory regions
 * - PE headers in memory not matching on-disk image
 * - Hollowed process indicators (memory image differs from file)
 * - Injected PE modules without file backing
 *
 * This detector analyzes PROCESS_ACCESS, THREAD_CREATE, MEMORY_WRITE,
 * and IMAGE_LOAD events to identify memory-based attacks.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_MEMORY_SCANNER_DETECTOR_H
#define EDR_MEMORY_SCANNER_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class MemoryScannerDetector {
public:
    MemoryScannerDetector(bool enabled, uint32_t minScore,
                          uint32_t dedupWindowSeconds, size_t stateCapacity);

    void Enrich(Event& event);

    /* True only for event types Enrich inspects; lets the caller skip the
     * copy/enrich pipeline for unrelated types. */
    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_processStates.size(); }

private:
    struct MemoryRegion {
        uint64_t baseAddress = 0;
        uint64_t size = 0;
        uint32_t protection = 0;  // PAGE_*
        bool isMappedFile = false;
        bool hasPeHeader = false;
        std::string moduleName;
        uint64_t lastSeen100ns = 0;
    };

    struct ProcessState {
        uint32_t pid = 0;
        std::string imagePath;
        uint64_t startTime100ns = 0;
        uint64_t lastSeen100ns = 0;
        std::vector<MemoryRegion> suspiciousRegions;
        uint32_t score = 0;
        std::vector<std::string> reasons;
        bool alerted = false;
    };

    struct SuspiciousPattern {
        uint32_t weight;
        const char* description;
    };

    void AnalyzeProcessAccess(Event& event, ProcessState& state);
    void AnalyzeThreadCreate(Event& event, ProcessState& state);
    void AnalyzeMemoryWrite(Event& event, ProcessState& state);
    void AnalyzeImageLoad(Event& event, ProcessState& state);
    void AnalyzeProcessStart(Event& event);

    bool IsSuspiciousMemoryProtection(uint32_t protection) const;
    bool IsExecutableProtection(uint32_t protection) const;
    bool IsSuspiciousModule(const std::string& moduleName) const;
    bool IsSystemModule(const std::string& moduleName) const;
    bool DetectPeHeaderInMemory(const Event& event) const;
    bool DetectShellcodePattern(const Event& event) const;

    ProcessState& GetOrCreateState(uint32_t pid, const std::string& image,
                                    uint64_t startTime100ns);
    void PurgeExpired(uint64_t now100ns);
    void UpdateScore(ProcessState& state, uint32_t weight, const char* reason);
    void StampEvent(Event& event, const ProcessState& state);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;

    std::unordered_map<uint32_t, ProcessState> m_processStates;
};

} // namespace edr

#endif /* EDR_MEMORY_SCANNER_DETECTOR_H */
