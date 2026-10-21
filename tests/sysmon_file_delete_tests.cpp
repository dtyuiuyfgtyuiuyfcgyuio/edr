#include <windows.h>
#include <winevt.h>

#include <cstdio>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "history_tamper_detector.h"
#include "process_tree_builder.h"
#include "rule_engine.h"
#include "sysmon_parser.h"

namespace {
int failures = 0;
#define CHECK(value) do { if (!(value)) { \
    std::fprintf(stderr, "line %d: %s\n", __LINE__, #value); ++failures; } } while (0)

std::wstring Xml(unsigned id, const std::wstring& pid = L"51",
                 const std::wstring& path = L"C:\\Users\\tester\\ConsoleHost_history.txt",
                 const std::wstring& image = L"C:\\Windows\\System32\\cmd.exe") {
    return L"<Event><System><EventID>" + std::to_wstring(id) +
        L"</EventID><TimeCreated SystemTime='2026-10-20T01:02:03.1234567Z'/>"
        L"<Execution ProcessID='777'/></System><EventData>"
        L"<Data Name='ProcessId'>" + pid + L"</Data>"
        L"<Data Name='ProcessGuid'>{12345678-1234-1234-1234-123456789abc}</Data>"
        L"<Data Name='Image'>" + image + L"</Data>"
        L"<Data Name='TargetFilename'>" + path + L"</Data>"
        L"<Data Name='User'>TEST\\tester</Data>"
        L"<Data Name='Hashes'>SHA256=0123456789abcdef</Data>"
        L"<Data Name='IsExecutable'>false</Data>" +
        (id == 23 ? L"<Data Name='Archived'>true</Data>" : L"") +
        L"</EventData></Event>";
}

std::string Field(const edr::Event& event, const char* key) {
    auto it = event.fields.find(key);
    return it == event.fields.end() ? "" : it->second;
}

void TestMappingAndRules(const char* rules) {
    edr::RuleEngine engine;
    engine.LoadFromFile(rules);
    CHECK(engine.RuleCount() > 0);
    edr::HistoryTamperDetector detector(true, 55, 300, 1024);
    for (const unsigned id : {23u, 26u}) {
        edr::Event event;
        const bool parsed = edr::ParseSysmonXml(Xml(id), event);
        CHECK(parsed);
        if (!parsed) continue;
        CHECK(event.type == EDR_EVT_FILE_DELETE);
        CHECK(Field(event, edr::field::kType) == "FILE_DELETE");
        CHECK(event.source == "sysmon" && event.pid == 51 && event.ppid == 0);
        CHECK(event.processStartTime100ns == 0);
        CHECK(event.processIdentity == "{12345678-1234-1234-1234-123456789abc}");
        CHECK(Field(event, edr::field::kFilePath) == "C:\\Users\\tester\\ConsoleHost_history.txt");
        CHECK(Field(event, edr::field::kFilePath) == Field(event, edr::field::kTargetPath));
        CHECK(Field(event, edr::field::kUserId) == "TEST\\tester");
        CHECK(Field(event, edr::field::kHashes) == "SHA256=0123456789abcdef");
        CHECK(Field(event, "sysmon_file_delete_is_executable") == "false");
        CHECK(Field(event, "sysmon_file_delete_archived") == (id == 23 ? "true" : ""));
        CHECK(Field(event, edr::field::kOperationType) == "FILE_DELETE");
        detector.Enrich(event);
        CHECK(Field(event, edr::field::kHistoryTamperScore) == "85");
        bool matched = false;
        engine.SetAlertCallback([&matched](const edr::Alert& alert) {
            if (alert.ruleId == "EDR-369") {
                matched = true;
                CHECK(alert.action == "alert");
            }
        });
        engine.OnEvent(event);
        CHECK(matched);
        engine.SetAlertCallback({});

        edr::Event ordinary;
        CHECK(edr::ParseSysmonXml(Xml(id, L"51", L"C:\\Temp\\ordinary.txt"), ordinary));
        detector.Enrich(ordinary);
        CHECK(Field(ordinary, edr::field::kHistoryTamperScore).empty());
    }
}

void TestInvalidAndOptionalFields() {
    for (unsigned id : {23u, 26u}) {
        for (const auto& pid : {L"", L"0", L"-1", L"4294967296", L"51x"}) {
            edr::Event event;
            CHECK(!edr::ParseSysmonXml(Xml(id, pid), event));
        }
        edr::Event event;
        CHECK(!edr::ParseSysmonXml(Xml(id, L"51", L""), event));
        CHECK(!edr::ParseSysmonXml(Xml(id, L"51", L"C:\\Temp\\file.txt", L""), event));
        auto xml = Xml(id);
        const auto begin = xml.find(L"<Data Name='IsExecutable'>");
        const auto end = xml.find(L"</Data>", begin) + 7;
        xml.erase(begin, end - begin);
        CHECK(edr::ParseSysmonXml(xml, event));
        CHECK(Field(event, "sysmon_file_delete_is_executable").empty());
    }
    edr::Event escaped;
    CHECK(edr::ParseSysmonXml(Xml(26, L"51", L"C:\\Temp\\a&amp;b.txt"), escaped));
    CHECK(Field(escaped, edr::field::kFilePath) == "C:\\Temp\\a&b.txt");
}

void TestAncestryIsNotInferred() {
    edr::ProcessTreeBuilder tree;
    tree.AddParentChild(10, 51, "C:\\known.exe");
    for (unsigned id : {23u, 26u}) {
        edr::Event event;
        if (!edr::ParseSysmonXml(Xml(id), event)) continue;
        tree.Observe(event);
        CHECK(tree.GetAncestors(51) == std::vector<uint32_t>{10});
        CHECK(tree.GetProcessTreeJson(51, 3).find("known.exe") != std::string::npos);
        event.pid = 52;
        tree.Observe(event);
        CHECK(!tree.HasProcess(52));
    }
}

void TestQueries() {
    for (unsigned mask = 0; mask < 16; ++mask) {
        const auto query = edr::SysmonSubscriptionQuery(
            (mask & 1) != 0, (mask & 2) != 0, (mask & 4) != 0, (mask & 8) != 0);
        CHECK(query.find(L"EventID=23") != std::wstring::npos);
        CHECK(query.find(L"EventID=26") != std::wstring::npos);
        EVT_HANDLE handle = EvtQuery(nullptr, L"Application", query.c_str(), EvtQueryChannelPath);
        CHECK(handle != nullptr);
        if (handle) EvtClose(handle);
    }
}
} // namespace

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    TestMappingAndRules(argv[1]);
    TestInvalidAndOptionalFields();
    TestAncestryIsNotInferred();
    TestQueries();
    if (failures) std::fprintf(stderr, "%d file deletion checks failed\n", failures);
    else std::puts("Sysmon file deletion contracts passed");
    return failures ? 1 : 0;
}
