/*
 * lolbin_parent_child_detector.h - Office/browser/script-host to LOLBin
 * parent-child enrichment (T1059 / T1218 / T1566).
 *
 * A single PROCESS_START event is scored from parent image, child image,
 * and command-line boosters. No rolling state is kept. Events at or above
 * minScore are stamped with lolbin_score / lolbin_parent_class /
 * lolbin_child_class / lolbin_flags / lolbin_verdict.
 *
 * Heuristic: legitimate administration, software installers, and browser
 * helpers can score in the SUSPICIOUS band. Tune min_score or downgrade
 * the matching rules before production use.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_LOLBIN_PARENT_CHILD_DETECTOR_H
#define EDR_LOLBIN_PARENT_CHILD_DETECTOR_H

#include <cstdint>
#include <string>
#include <vector>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

struct LolbinScoreResult {
    uint32_t score = 0;                 /* 0..100, capped */
    std::string parentClass;            /* office/browser/adobe/... */
    std::string childClass;             /* powershell/cmd/script/lolbin/... */
    std::vector<std::string> flags;     /* LOLBIN_* reason tags */
};

/* Pure scoring helper for unit tests. Images may be full paths or
 * basenames; comparison is case-insensitive. */
LolbinScoreResult ScoreLolbinParentChild(const std::string& parentImage,
                                         const std::string& childImage,
                                         const std::string& commandLine);

/* Verdict for a score: "MALICIOUS" (>= 70), "SUSPICIOUS" (>= 50), or
 * empty below 50. */
const char* LolbinVerdict(uint32_t score);

class LolbinParentChildDetector {
public:
    LolbinParentChildDetector(bool enabled, uint32_t minScore);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

private:
    bool m_enabled;
    uint32_t m_minScore;
};

} // namespace edr

#endif /* EDR_LOLBIN_PARENT_CHILD_DETECTOR_H */
