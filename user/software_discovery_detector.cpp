/*
 * software_discovery_detector.cpp - Per-actor software discovery breadth
 * detector (T1518 / T1518.001). See software_discovery_detector.h for the
 * category model and rationale.
 */
#include "software_discovery_detector.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <initializer_list>
#include <vector>

namespace edr {
namespace {

constexpr size_t kActorKeyMax = 256;

std::string LowerAscii(const std::string& text) {
    std::string out = text;
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return out;
}

bool Contains(const std::string& haystack, const char* needle) {
    return haystack.find(needle) != std::string::npos;
}

bool ContainsAny(const std::string& haystack,
                 std::initializer_list<const char*> needles) {
    for (const char* needle : needles) {
        if (Contains(haystack, needle)) return true;
    }
    return false;
}

std::string FieldValue(const Event& event, const char* name) {
    auto found = event.fields.find(name);
    return found == event.fields.end() ? std::string() : found->second;
}

std::string BaseName(const std::string& value) {
    const size_t slash = value.find_last_of("\\/");
    return LowerAscii(slash == std::string::npos ? value
                                                 : value.substr(slash + 1));
}

bool LooksPrivileged(const std::string& lower) {
    return ContainsAny(lower, {"runas ", " /user:", "-verb runas",
                               "start-process -verb", "psexec", "/rl highest",
                               "schtasks /create"});
}

} // namespace

SoftwareDiscoveryDetector::SoftwareDiscoveryDetector(
    bool enabled, uint32_t minScore, uint32_t windowSeconds,
    uint32_t minCategories, uint32_t dedupWindowSeconds, size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_window100ns(static_cast<uint64_t>(windowSeconds) *
                    kFiletimeTicksPerSecond),
      m_minCategories(std::max<uint32_t>(2, minCategories)),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)) {}

/* static */
bool SoftwareDiscoveryDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT;
}

bool SoftwareDiscoveryDetector::Classify(
    const std::string& lower,
    std::unordered_set<std::string>* categories) const {
    /* --- Software inventory (T1518) -------------------------------- */
    if (ContainsAny(lower, {"wmic product get", "wmic.exe product get",
                            "win32_product", "get-wmiobject win32_product",
                            "get-ciminstance win32_product", "get-package",
                            "get-package -providername", "get-installedsoftware",
                            "software inventory"})) {
        categories->insert("software_inventory");
    }
    /* --- Security software discovery (T1518.001) -------------------- */
    /* Vendor names need a token boundary: bare "eset" nests inside
     * "reset" / "present", so the trailing space / .exe suffix is part
     * of the needle. */
    if (ContainsAny(lower,
                    {"securitycenter2", "get-mpcomputerstatus",
                     "get-mppreference", "sc query windefend",
                     "sc.exe query windefend", "sc query mpssvc",
                     "sc.exe query mpssvc", "get-service -name windefend",
                     "get-service windefend", "root/microsoft/windows/defender",
                     "avast", "kaspersky", "mcafee", "symantec", "eset ",
                     "eset.exe", "sophos", "trend micro", "norton",
                     "bitdefender"})) {
        categories->insert("security_products");
    }
    /* --- Installed application enumeration (T1518) ------------------ */
    if (ContainsAny(lower, {"currentversion\\uninstall", "currentversion/uninstall",
                            "\\uninstall\\*", "/uninstall", "get-childitem hklm",
                            "installed programs", "dir \"%programfiles%\"",
                            "dir \"%programfiles(x86)%\"", "dir \"%appdata%\"",
                            "get-childitem env:programfiles"})) {
        categories->insert("installed_apps");
    }
    return !categories->empty();
}

void SoftwareDiscoveryDetector::PurgeExpired(uint64_t now100ns) {
    for (auto it = m_actors.begin(); it != m_actors.end();) {
        ActorState& state = it->second;
        for (auto cat = state.categories.begin();
             cat != state.categories.end();) {
            if (now100ns >= cat->second && m_window100ns != 0 &&
                now100ns - cat->second > m_window100ns)
                cat = state.categories.erase(cat);
            else
                ++cat;
        }
        if (state.categories.empty()) {
            it = m_actors.erase(it);
        } else {
            /* lastSeen100ns drives capacity eviction below; keep it in step
             * with the surviving window so a stale actor is dropped first. */
            uint64_t newest = 0;
            for (const auto& entry : state.categories) {
                if (entry.second > newest) newest = entry.second;
            }
            state.lastSeen100ns = newest;
            ++it;
        }
    }
}

bool SoftwareDiscoveryDetector::Analyze(Event& event, Finding* out) {
    const std::string image = FieldValue(event, field::kImage);
    /* House contract: PROCESS_START carries kCommandLine; a script event body
     * lives only in kScriptBlockText. kImage is the last-resort fallback. */
    std::string text = FieldValue(event, field::kCommandLine);
    if (text.empty() && event.type == EDR_EVT_POWERSHELL_SCRIPT) {
        text = FieldValue(event, field::kScriptBlockText);
    }
    if (text.empty()) text = image;

    std::unordered_set<std::string> categories;
    const std::string lower = LowerAscii(text);
    if (!Classify(lower, &categories)) return false;

    /* The actor key is the executable basename plus the owning user: two
     * different users on the same box are two different investigators, and a
     * tool that re-spawns per query (reg.exe, powershell.exe) still
     * accumulates correctly because the category window lives on the actor,
     * not the process instance. */
    std::string actor = BaseName(image);
    if (actor.empty()) actor = "?";
    const std::string sid = FieldValue(event, field::kUserSid);
    const std::string user = FieldValue(event, field::kSubjectUserName);
    const std::string owner = !sid.empty() ? sid : user;
    if (!owner.empty()) {
        actor += "|";
        actor += LowerAscii(owner);
    }
    if (actor.size() > kActorKeyMax) actor.resize(kActorKeyMax);

    const uint64_t now = event.ts100ns;
    if (now == 0) return false; /* cannot window an untimed event */

    bool privileged = false;
    auto existing = m_actors.find(actor);
    if (existing != m_actors.end()) {
        /* Clamp out-of-order timestamps before they can poison the window. */
        if (existing->second.lastSeen100ns != 0 &&
            now < existing->second.lastSeen100ns)
            return false;
        privileged = existing->second.privileged;
    }

    /* Capacity: reset the whole map rather than silently growing without
     * bound. Census state is cheap to rebuild (a few events). Never hold a
     * reference across the clear(). */
    if (m_stateCapacity != 0 && m_actors.size() > m_stateCapacity) {
        std::fprintf(stderr,
                     "[edr-software-discovery] actor capacity %zu reached; "
                     "census state reset\n",
                     m_stateCapacity);
        m_actors.clear();
        existing = m_actors.end();
    }

    ActorState& state = m_actors[actor];
    state.lastSeen100ns = now;
    for (const std::string& category : categories) {
        state.categories[category] = now;
    }
    if (LooksPrivileged(lower)) state.privileged = true;

    PurgeExpired(now);

    const uint32_t count = static_cast<uint32_t>(state.categories.size());
    if (count < m_minCategories) return false;

    const bool grew = count > state.lastFlaggedCount;
    const bool cooled = state.lastStamp100ns == 0 ||
                        (now >= state.lastStamp100ns &&
                         now - state.lastStamp100ns >= m_dedupWindow100ns);
    if (!grew && !cooled) return false;

    std::vector<std::string> ordered;
    ordered.reserve(state.categories.size());
    for (const auto& entry : state.categories) ordered.push_back(entry.first);
    std::sort(ordered.begin(), ordered.end());

    std::string joined;
    for (const std::string& item : ordered) {
        if (!joined.empty()) joined += ",";
        joined += item;
    }

    const bool securityProducts =
        state.categories.find("security_products") != state.categories.end();

    out->categoryCount = count;
    out->categories = joined;
    out->privileged = state.privileged;
    out->securityProducts = securityProducts;
    /* Breadth is the signal. There are exactly three census categories
     * (software_inventory, security_products, installed_apps), so the ladder
     * has to be reachable within that bound: 2 categories scores 60 and a full
     * sweep scores 75. A privileged actor that also shows breadth adds 10,
     * hard-capped at 100. Security-product enumeration paired with breadth is
     * the strong T1518.001 case and is escalated to at least 70, or 90 when the
     * actor is privileged. */
    uint32_t score = 60u + (count - 2u) * 15u;
    if (score > 100u) score = 100u;
    if (state.privileged) score = std::min(100u, score + 10u);
    if (securityProducts && count >= m_minCategories) {
        score = std::max(score, state.privileged ? 90u : 70u);
    }
    out->score = score;
    out->signal =
        securityProducts
            ? (state.privileged
                   ? "privileged security software discovery across multiple categories"
                   : "security software discovery across multiple categories")
            : (state.privileged
                   ? "privileged software inventory across multiple categories"
                   : "software discovery across multiple inventory categories");

    state.lastFlaggedCount = count;
    state.lastStamp100ns = now;
    return true;
}

void SoftwareDiscoveryDetector::Stamp(Event& event,
                                      const Finding& finding) const {
    event.fields[field::kSoftwareDiscoveryScore] =
        std::to_string(finding.score);
    event.fields[field::kSoftwareDiscoveryVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kSoftwareDiscoverySignals] = finding.signal;
    event.fields[field::kSoftwareDiscoveryCategories] = finding.categories;
    event.fields[field::kSoftwareDiscoveryCategoryCount] =
        std::to_string(finding.categoryCount);
}

void SoftwareDiscoveryDetector::Enrich(Event& event) {
    if (!m_enabled) return;
    if (!Inspects(event.type)) return;

    Finding finding;
    if (!Analyze(event, &finding)) return;
    if (finding.score < m_minScore) return;
    Stamp(event, finding);
}

} // namespace edr