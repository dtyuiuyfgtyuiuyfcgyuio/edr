/*
 * dll_hijack_detector_tests.cpp - Unit tests for DllHijackDetector.
 */
#include "dll_hijack_detector_tests.h"

#include <cstdio>
#include <fstream>
#include <stdexcept>
#include <string>

#include "config.h"
#include "dll_hijack_detector.h"
#include "edr_event.h"
#include "event_bus.h"

using namespace edr;

namespace {

#define DL_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "dll hijack detector test failed at line " + std::to_string(line) +
            ": " + expression);
}

edr::Event ImageLoad(const std::string& path, const std::string& loadType,
                     uint32_t pid = 100) {
    edr::Event event;
    event.type = EDR_EVT_IMAGE_LOAD;
    event.pid = pid;
    event.fields[edr::field::kType] = "IMAGE_LOAD";
    event.fields[edr::field::kImageLoadType] = loadType;
    event.fields[edr::field::kImageLoaded] = path;
    return event;
}

bool HasField(const edr::Event& event, const char* name) {
    return event.fields.find(name) != event.fields.end();
}

void TestClassifier() {
    DL_CHECK(edr::ClassifyDllHijackPath(
        "C:\\Users\\Public\\Downloads\\version.dll").suspicious);
    DL_CHECK(edr::ClassifyDllHijackPath(
        "C:\\Windows\\System32\\version.dll").suspicious == false);
    DL_CHECK(edr::ClassifyDllHijackPath(
        "C:\\Program Files\\App\\version.dll").suspicious == false);
    DL_CHECK(edr::ClassifyDllHijackPath(
        "C:\\Users\\x\\AppData\\Local\\Temp\\dbghelp.dll").location == "temp");
}

void TestEnrich() {
    edr::DllHijackDetector detector(true);
    edr::Event event = ImageLoad(
        "C:\\Users\\Public\\Documents\\dwmapi.dll", "load");
    detector.Enrich(event);
    DL_CHECK(HasField(event, edr::field::kDllHijackScore));
    DL_CHECK(event.fields.at(edr::field::kDllHijackName) == "dwmapi.dll");
    DL_CHECK(event.fields.at(edr::field::kDllHijackLocation) == "public");
    DL_CHECK(event.fields.at(edr::field::kDllHijackVerdict) ==
             "dll_search_order_hijack");
}

void TestUnloadAndDisabled() {
    edr::DllHijackDetector detector(true);
    edr::Event unload = ImageLoad(
        "C:\\Users\\Public\\version.dll", "unload");
    detector.Enrich(unload);
    DL_CHECK(!HasField(unload, edr::field::kDllHijackScore));

    edr::DllHijackDetector disabled(false);
    edr::Event load = ImageLoad(
        "C:\\Users\\Public\\version.dll", "load");
    disabled.Enrich(load);
    DL_CHECK(!HasField(load, edr::field::kDllHijackScore));

    DL_CHECK(edr::DllHijackDetector::Inspects(EDR_EVT_IMAGE_LOAD));
    DL_CHECK(!edr::DllHijackDetector::Inspects(EDR_EVT_PROCESS_START));
}

void TestConfigStrictAtomic() {
    const char* path = "edr-native-dll-hijack-config.json";
    std::ofstream out(path, std::ios::binary);
    out << R"({"dll_hijack":{"enable":true}})";
    out.close();

    std::string error;
    edr::Config config;
    DL_CHECK(edr::LoadConfigFile(path, config, error));
    DL_CHECK(config.dllHijackEnable);

    std::ofstream bad(path, std::ios::binary);
    bad << R"({"dll_hijack":{"enable":true,"bogus":1}})";
    bad.close();
    edr::Config unchanged;
    DL_CHECK(!edr::LoadConfigFile(path, unchanged, error));
    DL_CHECK(!unchanged.dllHijackEnable);

    std::remove(path);
}

} // namespace

void RunDllHijackDetectorTests() {
    TestClassifier();
    TestEnrich();
    TestUnloadAndDisabled();
    TestConfigStrictAtomic();
}
