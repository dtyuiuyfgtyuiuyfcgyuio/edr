#include <windows.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "behavior_baseline_detector.h"

namespace {

constexpr uint64_t kTicksPerSecond = 10000000ULL;
constexpr uint64_t kUnixEpoch100ns = 116444736000000000ULL;
std::string g_root;
int g_failures = 0;

void Require(bool condition, const char* expression, int line) {
    if (!condition) {
        throw std::runtime_error(std::string("line ") + std::to_string(line) +
                                 ": " + expression);
    }
}

void Record(bool condition, const std::string& expression,
            std::vector<std::string>& failures) {
    if (!condition) failures.push_back(expression);
}

void ThrowRecorded(const std::vector<std::string>& failures) {
    if (failures.empty()) return;
    std::string message;
    for (const std::string& failure : failures) {
        if (!message.empty()) message += "; ";
        message += failure;
    }
    throw std::runtime_error(message);
}

#define REQUIRE(expression) Require((expression), #expression, __LINE__)

uint64_t Now100ns() {
    FILETIME value = {};
    GetSystemTimePreciseAsFileTime(&value);
    return (static_cast<uint64_t>(value.dwHighDateTime) << 32) |
           value.dwLowDateTime;
}

uint64_t NowUnix() {
    return (Now100ns() - kUnixEpoch100ns) / kTicksPerSecond;
}

uint64_t AtOffset(int seconds) {
    const uint64_t now = Now100ns();
    if (seconds < 0) return now - static_cast<uint64_t>(-seconds) * kTicksPerSecond;
    return now + static_cast<uint64_t>(seconds) * kTicksPerSecond;
}

std::string Path(const std::string& name) { return g_root + "\\" + name; }

void Write(const std::string& path, const std::string& bytes) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) throw std::runtime_error("cannot create fixture: " + path);
    out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    if (!out) throw std::runtime_error("cannot write fixture: " + path);
}

std::string Read(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(in),
                       std::istreambuf_iterator<char>());
}

std::string ValidFile(const std::string& entries,
                      uint64_t savedAt = 0) {
    if (savedAt == 0) savedAt = NowUnix();
    return "{\"version\":1,\"saved_at_unix\":" +
           std::to_string(savedAt) + ",\"entries\":" + entries + "}";
}

edr::BehaviorBaselineDetector::Options Options(const std::string& path) {
    edr::BehaviorBaselineDetector::Options options;
    options.enabled = true;
    options.baselinePath = path;
    options.trainingSeconds = 3600;
    options.maxAgeDays = 30;
    options.minScore = 40;
    options.dedupSeconds = 0;
    return options;
}

edr::Event ProcessStart(const std::string& parent, const std::string& image,
                        uint64_t timestamp, const std::string& chain = {}) {
    edr::Event event;
    event.type = EDR_EVT_PROCESS_START;
    event.ts100ns = timestamp;
    event.fields[edr::field::kParentImage] = parent;
    event.fields[edr::field::kImage] = image;
    if (!chain.empty()) event.fields["chain_score"] = chain;
    return event;
}

void Test(const char* name, void (*body)()) {
    try {
        body();
        std::cout << "PASS " << name << "\n";
    } catch (const std::exception& error) {
        ++g_failures;
        std::cerr << "FAIL " << name << ": " << error.what() << "\n";
    }
}

void DisabledDoesNotLoadOrSave() {
    const std::string path = Path("disabled.json");
    const std::string before = ValidFile(
        "{\"parent.exe\":{\"children\":[\"old.exe\"],\"dirs\":[],"
        "\"endpoints\":[],\"first_seen_unix\":1,\"trained\":true}}",
        1);
    Write(path, before);
    auto options = Options(path);
    options.enabled = false;
    edr::BehaviorBaselineDetector detector(options);
    REQUIRE(detector.StateCount() == 0);
    REQUIRE(detector.LoadedEntries() == 0);
    REQUIRE(!detector.Save());
    REQUIRE(Read(path) == before);
}

void ExpiredBaselineClearsObservationsAndRetrains() {
    const std::string path = Path("expired-retrain.json");
    auto options = Options(path);
    options.maxAgeDays = 1;
    edr::BehaviorBaselineDetector detector(options);
    const uint64_t base = AtOffset(-2 * 86400);
    auto seed = ProcessStart("parent.exe", "old.exe", base);
    detector.Enrich(seed);
    auto freeze = ProcessStart("parent.exe", "old.exe",
                               base + 3601 * kTicksPerSecond);
    detector.Enrich(freeze);
    REQUIRE(detector.StateCount() == 1);
    auto event = ProcessStart("parent.exe", "new.exe", AtOffset(-1));
    detector.Enrich(event);
    REQUIRE(event.fields.find(edr::field::kBehaviorBaselineScore) ==
            event.fields.end());
    REQUIRE(detector.Save());
    const std::string saved = Read(path);
    REQUIRE(saved.find("old.exe") == std::string::npos);
    REQUIRE(saved.find("new.exe") != std::string::npos);
}

void OutOfOrderEventCannotCreateDeviationMark() {
    auto options = Options(Path("out-of-order.json"));
    options.trainingSeconds = 5;
    edr::BehaviorBaselineDetector detector(options);
    const uint64_t base = AtOffset(-30);
    auto seed = ProcessStart("parent.exe", "known.exe", base);
    detector.Enrich(seed);
    auto train = ProcessStart("parent.exe", "known.exe", base + 6 * kTicksPerSecond);
    detector.Enrich(train);
    auto stale = ProcessStart("parent.exe", "stale-new.exe",
                              base + 2 * kTicksPerSecond);
    detector.Enrich(stale);
    REQUIRE(stale.fields.find(edr::field::kBehaviorBaselineScore) ==
            stale.fields.end());
}

void PollutionSurvivesPersistence() {
    const std::string path = Path("pollution.json");
    auto options = Options(path);
    auto detector = edr::BehaviorBaselineDetector(options);
    const uint64_t base = AtOffset(-30);
    auto polluted = ProcessStart("parent.exe", "seed.exe", base, "90");
    detector.Enrich(polluted);
    REQUIRE(detector.Save());
    edr::BehaviorBaselineDetector reloaded(options);
    auto later = ProcessStart("parent.exe", "should-not-learn.exe",
                              base + kTicksPerSecond);
    reloaded.Enrich(later);
    REQUIRE(reloaded.Save());
    REQUIRE(Read(path).find("should-not-learn.exe") == std::string::npos);
}

void RestartRejectsOlderEventWithSubsecondPrecision() {
    const std::string path = Path("restart-order.json");
    auto options = Options(path);
    const uint64_t base = AtOffset(-30);
    const uint64_t latest = base + 20 * kTicksPerSecond + 1234;
    edr::BehaviorBaselineDetector detector(options);
    auto seed = ProcessStart("parent.exe", "seed.exe", base);
    auto learned = ProcessStart("parent.exe", "learned.exe", latest);
    detector.Enrich(seed);
    detector.Enrich(learned);
    REQUIRE(detector.Save());
    edr::BehaviorBaselineDetector reloaded(options);
    REQUIRE(reloaded.LoadedEntries() == 1);
    auto older = ProcessStart("parent.exe", "replayed-old.exe", latest - 1);
    reloaded.Enrich(older);
    REQUIRE(reloaded.Save());
    REQUIRE(Read(path).find("replayed-old.exe") == std::string::npos);
}

void FutureEventDoesNotPoisonLiveOrPersistedClock() {
    const std::string path = Path("future-event.json");
    edr::BehaviorBaselineDetector detector(Options(path));
    auto future = ProcessStart("parent.exe", "future.exe", AtOffset(86400));
    detector.Enrich(future);
    REQUIRE(detector.StateCount() == 0);
    auto current = ProcessStart("parent.exe", "current.exe", AtOffset(-1));
    detector.Enrich(current);
    REQUIRE(detector.Save());
    edr::BehaviorBaselineDetector reloaded(Options(path));
    REQUIRE(reloaded.LastError().empty());
    REQUIRE(reloaded.LoadedEntries() == 1);
    REQUIRE(Read(path).find("future.exe") == std::string::npos);
    REQUIRE(Read(path).find("current.exe") != std::string::npos);
}

void LegacyBaselineRejectsReplayWithinSavedSecond() {
    const std::string path = Path("legacy-order.json");
    const uint64_t savedAt = NowUnix() - 10;
    Write(path, ValidFile("{\"parent.exe\":{\"children\":[\"seed.exe\"],"
        "\"dirs\":[],\"endpoints\":[],\"first_seen_unix\":" +
        std::to_string(savedAt - 30) + ",\"trained\":false}}", savedAt));
    edr::BehaviorBaselineDetector detector(Options(path));
    REQUIRE(detector.LoadedEntries() == 1);
    auto replay = ProcessStart("parent.exe", "legacy-replayed.exe",
        kUnixEpoch100ns + savedAt * kTicksPerSecond + kTicksPerSecond / 2);
    detector.Enrich(replay);
    REQUIRE(detector.Save());
    REQUIRE(Read(path).find("legacy-replayed.exe") == std::string::npos);
}

void MalformedEntryFixturesAreRejectedAsWholeFiles() {
    const std::vector<std::string> badEntries = {
        "[]",
        "{\"parent.exe\":false}",
        "{\"parent.exe\":{\"children\":[\"ok.exe\",7],\"dirs\":[],"
            "\"endpoints\":[],\"first_seen_unix\":1,\"trained\":false}}",
        "{\"parent.exe\":{\"children\":[],\"dirs\":[],\"endpoints\":[],"
            "\"first_seen_unix\":-1,\"trained\":false}}",
        "{\"parent.exe\":{\"children\":[],\"dirs\":[],\"endpoints\":[],"
            "\"first_seen_unix\":18446744073709551616,\"trained\":false}}",
        "{\"good.exe\":{\"children\":[],\"dirs\":[],\"endpoints\":[],"
            "\"first_seen_unix\":" + std::to_string(NowUnix()) +
            ",\"trained\":true},\"bad.exe\":false}",
        "{\"parent.exe\":{\"children\":[],\"dirs\":[],\"endpoints\":[],"
            "\"first_seen_unix\":" + std::to_string(NowUnix() + 86400) +
            ",\"trained\":true}}",
    };
    std::vector<std::string> failures;
    for (size_t i = 0; i < badEntries.size(); ++i) {
        const std::string path = Path("malformed-" + std::to_string(i) + ".json");
        Write(path, ValidFile(badEntries[i]));
        edr::BehaviorBaselineDetector detector(Options(path));
        const std::string prefix = "fixture " + std::to_string(i) + ": ";
        Record(detector.StateCount() == 0, prefix + "whole file not rejected", failures);
        Record(detector.LoadedEntries() == 0, prefix + "loaded-entry count not zero", failures);
        Record(!detector.LastError().empty(), prefix + "LastError not set", failures);
    }
    ThrowRecorded(failures);
}

void ExpiredFileStartsWithNoLoadedEntries() {
    const std::string path = Path("expired-all.json");
    Write(path, ValidFile(
        "{\"one.exe\":{\"children\":[\"a.exe\"],\"dirs\":[],"
        "\"endpoints\":[],\"first_seen_unix\":1,\"trained\":true},"
        "\"two.exe\":{\"children\":[\"b.exe\"],\"dirs\":[],"
        "\"endpoints\":[],\"first_seen_unix\":1,\"trained\":true}}", 1));
    auto options = Options(path);
    options.maxAgeDays = 0;
    edr::BehaviorBaselineDetector detector(options);
    REQUIRE(detector.StateCount() == 0);
    REQUIRE(detector.LoadedEntries() == 0);
}

void ConcurrentSavesKeepCompleteBaselineAndForeignTemp() {
    const std::string path = Path("concurrent.json");
    const std::string foreignTemp = path + ".tmp";
    Write(foreignTemp, "preserve-foreign-temp");
    edr::BehaviorBaselineDetector first(Options(path));
    edr::BehaviorBaselineDetector second(Options(path));
    auto a = ProcessStart("first.exe", "child-a.exe", AtOffset(-10));
    auto b = ProcessStart("second.exe", "child-b.exe", AtOffset(-10));
    first.Enrich(a);
    second.Enrich(b);
    for (int i = 0; i < 20; ++i) {
        bool savedA = false;
        bool savedB = false;
        std::thread writerA([&] { savedA = first.Save(); });
        std::thread writerB([&] { savedB = second.Save(); });
        writerA.join();
        writerB.join();
        REQUIRE(savedA || savedB);
        edr::BehaviorBaselineDetector reloaded(Options(path));
        REQUIRE(reloaded.LastError().empty());
        REQUIRE(reloaded.LoadedEntries() == 1);
        const std::string saved = Read(path);
        REQUIRE((saved.find("child-a.exe") != std::string::npos) !=
                (saved.find("child-b.exe") != std::string::npos));
    }
    REQUIRE(Read(foreignTemp) == "preserve-foreign-temp");
}

void UnsafeKeysAndValuesAreNotPersisted() {
    const std::string path = Path("unsafe-values.json");
    auto options = Options(path);
    edr::BehaviorBaselineDetector detector(options);
    const std::string nul(1, '\0');
    edr::BehaviorBaselineDetector nulKeyDetector(Options(Path("nul-key.json")));
    auto nulKey = ProcessStart("bad" + nul + "key.exe", "child.exe", AtOffset(-3));
    nulKeyDetector.Enrich(nulKey);
    const bool nulKeyRejected = nulKeyDetector.StateCount() == 0;
    edr::BehaviorBaselineDetector longKeyDetector(Options(Path("long-key.json")));
    auto longKey = ProcessStart(std::string(300, 'k'), "child.exe", AtOffset(-2));
    longKeyDetector.Enrich(longKey);
    const bool longKeyRejected = longKeyDetector.StateCount() == 0;

    edr::Event longValue;
    longValue.type = EDR_EVT_FILE_CREATE;
    longValue.ts100ns = AtOffset(-1);
    longValue.fields[edr::field::kImage] = "writer.exe";
    longValue.fields[edr::field::kTargetPath] = "C:\\" + std::string(600, 'x') +
                                               "\\file.bin";
    detector.Enrich(longValue);

    edr::Event nulValue;
    nulValue.type = EDR_EVT_FILE_CREATE;
    nulValue.ts100ns = AtOffset(0);
    nulValue.fields[edr::field::kImage] = "writer.exe";
    nulValue.fields[edr::field::kTargetPath] = "C:\\safe" + nul + "hidden\\file.bin";
    detector.Enrich(nulValue);
    REQUIRE(detector.Save());
    const std::string saved = Read(path);
    std::vector<std::string> failures;
    Record(nulKeyRejected, "NUL key created state", failures);
    Record(longKeyRejected, "overlong key created state", failures);
    Record(saved.find(std::string(600, 'x')) == std::string::npos,
           "overlong value was persisted", failures);
    Record(saved.find("\\u0000") == std::string::npos,
           "NUL value was persisted", failures);
    Record(saved.find("safe") == std::string::npos,
           "NUL-containing value polluted stored observations", failures);
    ThrowRecorded(failures);
}

void FailedSavePreservesExistingTarget() {
    const std::string target = Path("target-directory");
    REQUIRE(CreateDirectoryA(target.c_str(), nullptr) != FALSE);
    const std::string marker = target + "\\keep.txt";
    Write(marker, "preserve-me");
    auto options = Options(target);
    edr::BehaviorBaselineDetector detector(options);
    REQUIRE(!detector.Save());
    REQUIRE(std::filesystem::is_directory(target));
    REQUIRE(Read(marker) == "preserve-me");
}

void SuccessfulSaveClearsPreviousError() {
    const std::string path = Path("recover-save.json");
    auto options = Options(path);
    edr::BehaviorBaselineDetector detector(options);
    REQUIRE(!detector.LastError().empty());
    REQUIRE(detector.Save());
    REQUIRE(detector.LastError().empty());
}

std::string CreateRoot() {
    char temp[MAX_PATH + 1] = {};
    const DWORD length = GetTempPathA(MAX_PATH, temp);
    if (length == 0 || length >= MAX_PATH)
        throw std::runtime_error("GetTempPathA failed");
    for (unsigned attempt = 0; attempt < 100; ++attempt) {
        const std::string candidate = std::string(temp) +
            "edr-baseline-edge-" + std::to_string(GetCurrentProcessId()) + "-" +
            std::to_string(GetTickCount64()) + "-" + std::to_string(attempt);
        if (CreateDirectoryA(candidate.c_str(), nullptr)) return candidate;
        if (GetLastError() != ERROR_ALREADY_EXISTS)
            throw std::runtime_error("cannot create private fixture namespace");
    }
    throw std::runtime_error("private fixture namespace collision limit reached");
}

} // namespace

int main() {
    try {
        g_root = CreateRoot();
    } catch (const std::exception& error) {
        std::cerr << "FAIL fixture namespace: " << error.what() << "\n";
        return 2;
    }

    Test("disabled skips load and save", DisabledDoesNotLoadOrSave);
    Test("expired baseline clears observations and retrains",
         ExpiredBaselineClearsObservationsAndRetrains);
    Test("out-of-order event cannot mark a deviation",
         OutOfOrderEventCannotCreateDeviationMark);
    Test("pollution survives persistence", PollutionSurvivesPersistence);
    Test("restart preserves event order to 100ns precision",
         RestartRejectsOlderEventWithSubsecondPrecision);
    Test("future events do not poison live or saved baseline",
         FutureEventDoesNotPoisonLiveOrPersistedClock);
    Test("legacy baseline rejects replay within its saved second",
         LegacyBaselineRejectsReplayWithinSavedSecond);
    Test("malformed entries reject the whole file",
         MalformedEntryFixturesAreRejectedAsWholeFiles);
    Test("expired file starts with fresh state", ExpiredFileStartsWithNoLoadedEntries);
    Test("unsafe keys and values are not persisted", UnsafeKeysAndValuesAreNotPersisted);
    Test("failed save preserves existing target", FailedSavePreservesExistingTarget);
    Test("successful save clears previous error", SuccessfulSaveClearsPreviousError);
    Test("concurrent saves keep valid baseline and foreign temp",
         ConcurrentSavesKeepCompleteBaselineAndForeignTemp);

    std::error_code cleanupError;
    std::filesystem::remove_all(g_root, cleanupError);
    if (cleanupError) {
        std::cerr << "FAIL fixture cleanup: " << cleanupError.message() << "\n";
        ++g_failures;
    }
    std::cout << "RESULT failures=" << g_failures << "\n";
    return g_failures == 0 ? 0 : 1;
}
