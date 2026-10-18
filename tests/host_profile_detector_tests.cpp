/*
 * host_profile_detector_tests.cpp - Unit tests for HostProfileDetector.
 *
 * The detector's contract is *breadth*: it must stay silent for any single
 * profile question and only stamp the event once an actor has asked at least
 * min_categories distinct questions inside the rolling window.
 */
#include "host_profile_detector_tests.h"

#include <windows.h>

#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "host_profile_detector.h"

namespace {

#define HPROF_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "host profile detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

edr::Event ProcessStart(uint64_t ts100ns, const char* commandLine,
                        const char* image = "C:\\Windows\\System32\\cmd.exe",
                        const char* user = nullptr) {
    edr::Event event;
    event.type = EDR_EVT_PROCESS_START;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "PROCESS_START";
    if (commandLine != nullptr)
        event.fields[edr::field::kCommandLine] = commandLine;
    if (image != nullptr) event.fields[edr::field::kImage] = image;
    if (user != nullptr) event.fields[edr::field::kSubjectUserName] = user;
    return event;
}

bool HasScore(const edr::Event& event) {
    return event.fields.find(edr::field::kHostProfileScore) !=
           event.fields.end();
}

uint32_t Score(const edr::Event& event) {
    return static_cast<uint32_t>(
        std::stoul(event.fields.at(edr::field::kHostProfileScore)));
}

constexpr uint64_t kSecond = 10000000ULL;

/* Defaults matching config.h so tests exercise the shipped tuning. */
edr::HostProfileDetector MakeDetector(bool enabled = true,
                                      uint32_t minScore = 55,
                                      uint32_t windowSeconds = 300,
                                      uint32_t minCategories = 3,
                                      uint32_t dedupSeconds = 300,
                                      size_t capacity = 1024) {
    return edr::HostProfileDetector(enabled, minScore, windowSeconds,
                                    minCategories, dedupSeconds, capacity);
}

} // namespace

void RunHostProfileDetectorTests() {
    std::fprintf(stderr, "[host_profile] TestDisabled\n");
    {
        auto detector = MakeDetector(false);
        auto event = ProcessStart(kSecond, "net user");
        detector.Enrich(event);
        HPROF_CHECK(!HasScore(event));
    }

    /* A single profile question -- however loudly repeated -- must never
     * alert. This is the property that keeps routine administration quiet. */
    std::fprintf(stderr, "[host_profile] SingleCategorySilent\n");
    {
        auto detector = MakeDetector();
        /* All seven land in the same "accounts" category. */
        const char* commands[] = {"net user",
                                  "net user administrator",
                                  "net accounts",
                                  "net.exe user /domain",
                                  "Get-LocalUser",
                                  "wmic useraccount get name",
                                  "dsquery user -limit 0"};
        for (const char* command : commands) {
            auto event = ProcessStart(10 * kSecond, command);
            detector.Enrich(event);
            HPROF_CHECK(!HasScore(event));
        }
        /* State is retained (one actor entry per image+user) but no alert was
         * ever written: breadth never reached the threshold. */
        HPROF_CHECK(detector.StateCount() == 1);
    }

    /* Conversely, seven *distinct* questions from one silent window do trip --
     * breadth, not volume, is the signal. */
    std::fprintf(stderr, "[host_profile] SevenCategoriesTripOnce\n");
    {
        auto detector = MakeDetector();
        const char* commands[] = {"tasklist /v", "sc query state= all",
                                  "reg query HKLM\\Software",
                                  "ipconfig /all", "systeminfo",
                                  "net localgroup administrators",
                                  "net user administrator"};
        edr::Event last;
        for (int i = 0; i < 7; ++i) {
            last = ProcessStart((10 + i) * kSecond, commands[i]);
            detector.Enrich(last);
        }
        HPROF_CHECK(HasScore(last));
        HPROF_CHECK(last.fields.at(edr::field::kHostProfileCategoryCount) ==
                    "7");
    }

    std::fprintf(stderr, "[host_profile] TwoCategoriesSilent\n");
    {
        auto detector = MakeDetector();
        auto first = ProcessStart(10 * kSecond, "tasklist");
        detector.Enrich(first);
        HPROF_CHECK(!HasScore(first));

        auto second = ProcessStart(11 * kSecond, "ipconfig /all");
        detector.Enrich(second);
        HPROF_CHECK(!HasScore(second));
    }

    /* The core trip: 3 distinct categories inside the window. */
    std::fprintf(stderr, "[host_profile] ThreeCategoriesTrips\n");
    {
        auto detector = MakeDetector();
        auto first = ProcessStart(10 * kSecond, "tasklist");
        detector.Enrich(first);
        HPROF_CHECK(!HasScore(first));

        auto second = ProcessStart(11 * kSecond, "ipconfig /all");
        detector.Enrich(second);
        HPROF_CHECK(!HasScore(second));

        auto third = ProcessStart(12 * kSecond, "net user");
        detector.Enrich(third);
        HPROF_CHECK(HasScore(third));
        /* 3 categories -> 55 + 12 = 67 (SUSPICIOUS band). */
        HPROF_CHECK(Score(third) == 67);
        HPROF_CHECK(third.fields.at(edr::field::kHostProfileVerdict) ==
                    "suspicious");
        HPROF_CHECK(third.fields.at(edr::field::kHostProfileCategoryCount) ==
                    "3");
        HPROF_CHECK(third.fields.at(edr::field::kHostProfileWindowSeconds) ==
                    "300");
        /* Categories are emitted sorted for stable rule matching. */
        HPROF_CHECK(third.fields.at(edr::field::kHostProfileCategories) ==
                    "accounts,netconfig,processes");
    }

    /* Each extra category adds 12 and pushes into the MALICIOUS band. */
    std::fprintf(stderr, "[host_profile] BreadthEscalatesToMalicious\n");
    {
        auto detector = MakeDetector();
        const char* commands[] = {"tasklist",         /* processes  */
                                  "ipconfig /all",    /* netconfig  */
                                  "net user",         /* accounts   */
                                  "reg query HKLM\\Software", /* registry */
                                  "systeminfo"};      /* systeminfo */
        edr::Event last;
        for (int i = 0; i < 5; ++i) {
            last = ProcessStart((10 + i) * kSecond, commands[i]);
            detector.Enrich(last);
        }
        HPROF_CHECK(HasScore(last));
        /* 5 categories -> 55 + 3*12 = 91 (>= 75 MALICIOUS). */
        HPROF_CHECK(Score(last) == 91);
        HPROF_CHECK(last.fields.at(edr::field::kHostProfileVerdict) ==
                    "malicious");
        HPROF_CHECK(last.fields.at(edr::field::kHostProfileCategoryCount) ==
                    "5");
    }

    std::fprintf(stderr, "[host_profile] ScoreCapAtHundred\n");
    {
        auto detector = MakeDetector();
        const char* commands[] = {"tasklist", "sc query", "reg query HKLM",
                                  "ipconfig /all", "systeminfo",
                                  "net localgroup", "net user"};
        edr::Event last;
        for (int i = 0; i < 7; ++i) {
            last = ProcessStart((10 + i) * kSecond, commands[i]);
            detector.Enrich(last);
        }
        HPROF_CHECK(HasScore(last));
        HPROF_CHECK(Score(last) == 100);
        HPROF_CHECK(last.fields.at(edr::field::kHostProfileCategoryCount) ==
                    "7");
    }

    /* Rolling window: categories age out, so a burst must be *recent*. */
    std::fprintf(stderr, "[host_profile] WindowDecay\n");
    {
        auto detector = MakeDetector(true, 55, 60, 3, 300, 1024);
        auto first = ProcessStart(10 * kSecond, "tasklist");
        detector.Enrich(first);
        auto second = ProcessStart(11 * kSecond, "ipconfig /all");
        detector.Enrich(second);

        /* 200s later the first two have expired; only 1 category remains. */
        auto third = ProcessStart(210 * kSecond, "net user");
        detector.Enrich(third);
        HPROF_CHECK(!HasScore(third));
    }

    /* Different users are different actors: two questions each never trips. */
    std::fprintf(stderr, "[host_profile] SeparateActorsByUser\n");
    {
        auto detector = MakeDetector();
        auto aliceOne = ProcessStart(10 * kSecond, "tasklist", nullptr,
                                     "CORP\\alice");
        detector.Enrich(aliceOne);
        auto bobOne = ProcessStart(11 * kSecond, "ipconfig /all", nullptr,
                                   "CORP\\bob");
        detector.Enrich(bobOne);
        auto aliceTwo = ProcessStart(12 * kSecond, "net localgroup",
                                     nullptr, "CORP\\alice");
        detector.Enrich(aliceTwo);
        HPROF_CHECK(!HasScore(aliceTwo));
        HPROF_CHECK(detector.StateCount() == 2);
    }

    /* A privileged execution path widens the score and is reported. */
    std::fprintf(stderr, "[host_profile] PrivilegedEscalation\n");
    {
        auto detector = MakeDetector();
        auto first = ProcessStart(10 * kSecond, "tasklist");
        detector.Enrich(first);
        auto second = ProcessStart(11 * kSecond,
                                   "\"C:\\Windows\\System32\\runas.exe\" "
                                   "/user:CORP\\admin cmd /c ipconfig /all");
        detector.Enrich(second);
        auto third = ProcessStart(12 * kSecond, "net user");
        detector.Enrich(third);
        HPROF_CHECK(HasScore(third));
        /* 3 categories -> 67, +10 for the privileged actor -> 77. */
        HPROF_CHECK(Score(third) == 77);
        HPROF_CHECK(third.fields.at(edr::field::kHostProfileVerdict) ==
                    "malicious");
        HPROF_CHECK(third.fields.at(edr::field::kHostProfilePrivileged) ==
                    "true");
        HPROF_CHECK(third.fields.at(edr::field::kHostProfileSignals) ==
                    "privileged host profiling across multiple categories");
    }

    /* Re-asking the same question must not manufacture breadth. */
    std::fprintf(stderr, "[host_profile] RepeatSameCategoryNoBreadth\n");
    {
        auto detector = MakeDetector();
        edr::Event last;
        for (int i = 0; i < 10; ++i) {
            last = ProcessStart((10 + i) * kSecond, "tasklist /v");
            detector.Enrich(last);
        }
        HPROF_CHECK(!HasScore(last));
    }

    std::fprintf(stderr, "[host_profile] DedupSuppressesFlood\n");
    {
        auto detector = MakeDetector(true, 55, 300, 3, 300, 1024);
        auto first = ProcessStart(10 * kSecond, "tasklist");
        detector.Enrich(first);
        auto second = ProcessStart(11 * kSecond, "ipconfig /all");
        detector.Enrich(second);
        auto third = ProcessStart(12 * kSecond, "net user");
        detector.Enrich(third);
        HPROF_CHECK(HasScore(third));
        HPROF_CHECK(third.fields.at(edr::field::kHostProfileCategoryCount) ==
                    "3");

        /* Re-asking an already-seen category does not widen the profile, so
         * the same breadth inside the dedup window stays suppressed. */
        auto fourth = ProcessStart(13 * kSecond, "ipconfig /all");
        detector.Enrich(fourth);
        HPROF_CHECK(!HasScore(fourth));

        /* A *wider* profile is new information -> not suppressed. */
        auto fifth = ProcessStart(14 * kSecond, "net localgroup");
        detector.Enrich(fifth);
        HPROF_CHECK(HasScore(fifth));
        HPROF_CHECK(fifth.fields.at(edr::field::kHostProfileCategoryCount) ==
                    "4");
    }

    std::fprintf(stderr, "[host_profile] MinScoreFiltersBaseline\n");
    {
        /* min_score above the 3-category score silences the trip. */
        auto detector = MakeDetector(true, 75, 300, 3, 300, 1024);
        auto first = ProcessStart(10 * kSecond, "tasklist");
        detector.Enrich(first);
        auto second = ProcessStart(11 * kSecond, "ipconfig /all");
        detector.Enrich(second);
        auto third = ProcessStart(12 * kSecond, "net user");
        detector.Enrich(third);
        HPROF_CHECK(!HasScore(third));
    }

    std::fprintf(stderr, "[host_profile] MinCategoriesRespected\n");
    {
        auto detector = MakeDetector(true, 55, 300, 5, 300, 1024);
        auto first = ProcessStart(10 * kSecond, "tasklist");
        detector.Enrich(first);
        auto second = ProcessStart(11 * kSecond, "ipconfig /all");
        detector.Enrich(second);
        auto third = ProcessStart(12 * kSecond, "net user");
        detector.Enrich(third);
        HPROF_CHECK(!HasScore(third));

        auto fourth = ProcessStart(13 * kSecond, "reg query HKLM");
        detector.Enrich(fourth);
        HPROF_CHECK(!HasScore(fourth));

        auto fifth = ProcessStart(14 * kSecond, "systeminfo");
        detector.Enrich(fifth);
        HPROF_CHECK(HasScore(fifth));
        HPROF_CHECK(fifth.fields.at(edr::field::kHostProfileCategoryCount) ==
                    "5");
    }

    std::fprintf(stderr, "[host_profile] IgnoresUnrelatedEvents\n");
    {
        auto detector = MakeDetector();
        edr::Event event;
        event.type = EDR_EVT_REG_WRITE;
        event.ts100ns = 10 * kSecond;
        event.fields[edr::field::kCommandLine] = "tasklist";
        detector.Enrich(event);
        HPROF_CHECK(!HasScore(event));
    }

    /* Events without a timestamp cannot be windowed; stay silent instead of
     * inventing a clock. */
    std::fprintf(stderr, "[host_profile] UntimedEventIgnored\n");
    {
        auto detector = MakeDetector();
        auto event = ProcessStart(0, "tasklist");
        detector.Enrich(event);
        HPROF_CHECK(!HasScore(event));
    }

    std::fprintf(stderr, "[host_profile] CapacityBounded\n");
    {
        auto detector = MakeDetector(true, 55, 300, 3, 300, 4);
        for (int i = 0; i < 32; ++i) {
            const std::string user = "CORP\\u" + std::to_string(i);
            auto event = ProcessStart((10 + i) * kSecond, "tasklist", nullptr,
                                      user.c_str());
            detector.Enrich(event);
        }
        HPROF_CHECK(detector.StateCount() <= 4);
    }

    std::fprintf(stderr, "[host_profile] InspectsOnlyProcessStart\n");
    {
        HPROF_CHECK(edr::HostProfileDetector::Inspects(EDR_EVT_PROCESS_START));
        HPROF_CHECK(!edr::HostProfileDetector::Inspects(EDR_EVT_REG_WRITE));
        HPROF_CHECK(
            !edr::HostProfileDetector::Inspects(EDR_EVT_POWERSHELL_SCRIPT));
    }

    std::fprintf(stderr, "[host_profile] all passed\n");
}
