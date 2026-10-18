/*
 * dll_search_order_detector_tests.cpp - Unit tests for DllSearchOrderDetector (T1574.002).
 */
#include "dll_search_order_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "dll_search_order_detector.h"
#include "edr_event.h"
#include "event_bus.h"

namespace {

#define DS_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "dll search order detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

edr::Event FileEvent(uint64_t ts100ns, const char* path) {
    edr::Event event;
    event.type = EDR_EVT_FILE_CREATE;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "FILE_CREATE";
    event.fields[edr::field::kFilePath] = path;
    return event;
}

edr::Event ProcEvent(uint64_t ts100ns, const char* image,
                     const char* commandLine) {
    edr::Event event;
    event.type = EDR_EVT_PROCESS_START;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "PROCESS_START";
    event.fields[edr::field::kImage] = image;
    if (commandLine != nullptr)
        event.fields[edr::field::kCommandLine] = commandLine;
    return event;
}

edr::Event RegEvent(uint64_t ts100ns, const char* key, const char* value) {
    edr::Event event;
    event.type = EDR_EVT_REG_WRITE;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "REG_WRITE";
    event.fields[edr::field::kRegKey] = key;
    event.fields[edr::field::kRegValue] = value;
    return event;
}

std::string Score(const edr::Event& event) {
    auto it = event.fields.find(edr::field::kDllSearchOrderScore);
    return it == event.fields.end() ? "" : it->second;
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunDllSearchOrderDetectorTests() {
    std::fprintf(stderr, "[dll-search] TestDisabled\n");
    {
        edr::DllSearchOrderDetector detector(false, 55, 300, 1024);
        edr::Event event = FileEvent(1000 * kSecond,
            "C:\\Program Files\\App\\version.dll");
        detector.Enrich(event);
        DS_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[dll-search] TestAppDir\n");
    {
        edr::DllSearchOrderDetector detector(true, 55, 300, 1024);
        edr::Event event = FileEvent(1001 * kSecond,
            "C:\\Program Files\\MyApp\\version.dll");
        detector.Enrich(event);
        DS_CHECK(Score(event) == "85");
    }
    std::fprintf(stderr, "[dll-search] TestWritableDir\n");
    {
        edr::DllSearchOrderDetector detector(true, 55, 300, 1024);
        edr::Event event = FileEvent(1002 * kSecond,
            "C:\\Users\\bob\\AppData\\Local\\Temp\\winmm.dll");
        detector.Enrich(event);
        DS_CHECK(Score(event) == "80");
    }
    std::fprintf(stderr, "[dll-search] TestKnownDllsWritable\n");
    {
        edr::DllSearchOrderDetector detector(true, 55, 300, 1024);
        edr::Event event = RegEvent(1003 * kSecond,
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs",
            "C:\\Users\\Public\\advapi32.dll");
        detector.Enrich(event);
        DS_CHECK(Score(event) == "90");
    }
    std::fprintf(stderr, "[dll-search] TestSystem32Silent\n");
    {
        edr::DllSearchOrderDetector detector(true, 55, 300, 1024);
        edr::Event event = FileEvent(1004 * kSecond,
            "C:\\Windows\\System32\\version.dll");
        detector.Enrich(event);
        DS_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[dll-search] TestCommandCopy\n");
    {
        edr::DllSearchOrderDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(1005 * kSecond,
            "C:\\Windows\\System32\\cmd.exe",
            "copy C:\\Temp\\version.dll \"C:\\Program Files\\App\\version.dll\"");
        detector.Enrich(event);
        DS_CHECK(Score(event) == "85");
    }
    std::fprintf(stderr, "[dll-search] TestReadOnlySilent\n");
    {
        edr::DllSearchOrderDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(1006 * kSecond,
            "C:\\Windows\\System32\\reg.exe",
            "reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs\"");
        detector.Enrich(event);
        DS_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[dll-search] all passed\n");
}
