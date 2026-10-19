#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace edr {
struct Event;

/*
 * process_tree_builder.h - Builds a process tree to enrich alert context.
 *
 * Tracks parent-child relationships and process metadata (image, timestamps)
 * for every observed process. Provides tree traversal (ancestors, children)
 * and JSON serialization for downstream alert correlation. Thread-safe via
 * an internal mutex; all public methods acquire the lock.
 */
class ProcessTreeBuilder {
public:
    /* Per-process record stored in the tree. */
    struct ProcessRecord {
        uint32_t pid = 0;
        uint32_t parentPid = 0;
        std::string image;
        uint64_t firstSeenMs = 0;
        uint64_t lastSeenMs = 0;
    };

    ProcessTreeBuilder() = default;
    ~ProcessTreeBuilder() = default;

    /* Non-copyable, non-movable (mutex). */
    ProcessTreeBuilder(const ProcessTreeBuilder&) = delete;
    ProcessTreeBuilder& operator=(const ProcessTreeBuilder&) = delete;

    /* Add or update a parent-child relationship.  If the child already
     * exists, only the lastSeenMs and image are refreshed; parentPid is
     * overwritten so the tree stays consistent across restarts. */
    void AddParentChild(uint32_t parentPid, uint32_t childPid,
                        const std::string& image);

    /* Observe dispatch metadata; tampering events supply no parent evidence
     * and must not replace established ancestry or invent a root process. */
    void Observe(const Event& event);

    /* Build a JSON representation of the process tree rooted at |pid|,
     * descending at most |maxDepth| levels.  Returns an empty JSON
     * object ("{}") when the pid is unknown. */
    std::string GetProcessTreeJson(uint32_t pid, uint32_t maxDepth = 5);

    /* Remove every record whose lastSeenMs is older than |nowMs - maxAgeMs|. */
    void PruneOldEntries(uint64_t nowMs, uint64_t maxAgeMs);

    /* Return true when a record for |pid| exists. */
    bool HasProcess(uint32_t pid);

    /* Return the ancestor chain (immediate parent first, root last) up to
     * |maxDepth| entries.  Returns an empty vector if |pid| is unknown. */
    std::vector<uint32_t> GetAncestors(uint32_t pid, uint32_t maxDepth = 10);

    /* Return the direct children of |pid| (unsorted). */
    std::vector<uint32_t> GetChildren(uint32_t pid);

private:
    /* Recursive helper for GetProcessTreeJson.  Caller must already hold
     * m_mutex. */
    void BuildNodeJsonLocked(uint32_t pid, uint32_t depth, uint32_t maxDepth,
                             std::string& out);

    mutable std::mutex m_mutex;
    std::unordered_map<uint32_t, ProcessRecord> m_processes;
};

} // namespace edr
