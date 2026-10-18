/*
 * audit_chain_recovery_tests.cpp - fail-closed startup replay tests for the
 * native alert, incident, and response JSONL ledgers.
 *
 * The cases are kept in their own translation unit so the replay logic stays
 * focused. The native test target calls RunAuditChainRecoveryTests(); when
 * compiled alone this file still provides a small standalone main.
 */
#include "alerter.h"
#include "incident_store.h"
#include "response_server.h"

#include <windows.h>
#include <aclapi.h>
#include <sddl.h>

#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

namespace {

void Require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

std::string ReadFile(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    std::ostringstream bytes;
    bytes << input.rdbuf();
    return bytes.str();
}

void WriteFile(const std::string& path, const std::string& contents) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output << contents;
}

void ReplaceFirst(std::string& text, const std::string& from,
                  const std::string& to) {
    const size_t offset = text.find(from);
    Require(offset != std::string::npos, "test fixture field is missing");
    text.replace(offset, from.size(), to);
}

std::string TempPath(const char* prefix) {
    char directory[MAX_PATH] = {};
    Require(GetTempPathA(MAX_PATH, directory) != 0, "GetTempPathA failed");
    return std::string(directory) + prefix +
        std::to_string(GetCurrentProcessId()) + ".jsonl";
}

std::string FileDaclSddl(const std::string& path) {
    HANDLE file = CreateFileA(path.c_str(), READ_CONTROL,
                              FILE_SHARE_READ | FILE_SHARE_WRITE |
                                  FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                              nullptr);
    Require(file != INVALID_HANDLE_VALUE, "could not open fixture for DACL query");

    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    const DWORD status = GetSecurityInfo(file, SE_FILE_OBJECT,
                                         DACL_SECURITY_INFORMATION, nullptr,
                                         nullptr, &dacl, nullptr, &descriptor);
    CloseHandle(file);
    Require(status == ERROR_SUCCESS, "GetSecurityInfo failed for fixture");

    LPSTR sddl = nullptr;
    const BOOL converted = ConvertSecurityDescriptorToStringSecurityDescriptorA(
        descriptor, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &sddl, nullptr);
    LocalFree(descriptor);
    Require(converted != FALSE, "could not convert fixture DACL to SDDL");
    std::string result(sddl);
    LocalFree(sddl);
    return result;
}

std::string NormalizedFileDaclSddl(const std::string& path) {
    std::string sddl = FileDaclSddl(path);
    /* Windows may retain the auto-inherited control marker after P is set. */
    if (sddl.compare(0, 5, "D:PAI") == 0) {
        sddl.replace(0, 5, "D:P");
    }
    return sddl;
}

bool HasProtectedDacl(const std::string& path) {
    HANDLE file = CreateFileA(path.c_str(), READ_CONTROL,
                              FILE_SHARE_READ | FILE_SHARE_WRITE |
                                  FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                              nullptr);
    Require(file != INVALID_HANDLE_VALUE, "could not open fixture to inspect DACL flags");

    PSECURITY_DESCRIPTOR descriptor = nullptr;
    const DWORD status = GetSecurityInfo(file, SE_FILE_OBJECT,
                                         DACL_SECURITY_INFORMATION, nullptr,
                                         nullptr, nullptr, nullptr, &descriptor);
    CloseHandle(file);
    Require(status == ERROR_SUCCESS, "GetSecurityInfo failed for DACL flags");

    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    const BOOL inspected = GetSecurityDescriptorControl(descriptor, &control,
                                                        &revision);
    LocalFree(descriptor);
    Require(inspected != FALSE, "could not inspect DACL protection flag");
    return (control & SE_DACL_PROTECTED) != 0;
}

void RestoreInheritedFileDacl(const std::string& path) {
    const std::string contents = ReadFile(path);
    Require(DeleteFileA(path.c_str()) != FALSE,
            "could not recreate incident fixture with inherited DACL");
    WriteFile(path, contents);
    Require(ReadFile(path) == contents,
            "could not restore chain bytes to inherited-DACL fixture");
    Require(!HasProtectedDacl(path),
            "existing-file fixture still has a protected DACL");
    Require(NormalizedFileDaclSddl(path) != "D:P(A;;FA;;;OW)",
            "existing-file fixture unexpectedly retained the owner-only DACL");
}

edr::Incident MakeIncidentFixture() {
    edr::Incident incident;
    incident.id = "incident-acl-test";
    incident.host = "host";
    incident.severity = "high";
    incident.alertCount = 1;
    return incident;
}

void CreateIncidentHistory(const std::string& path) {
    DeleteFileA(path.c_str());
    edr::IncidentStore writer(path, false, 10);
    Require(writer.Open(), "incident history fixture open failed");
    writer.OnIncidentOpened(MakeIncidentFixture());
    Require(writer.RecordCount() == 1,
            "incident history fixture did not record its first entry");
    writer.Close();
}

void TestAlerterRejectsBrokenHistory() {
    const std::string path = TempPath("edr-alert-chain-");
    DeleteFileA(path.c_str());
    edr::Event event;
    event.type = 0;
    event.ts100ns = 1;
    event.pid = 7;
    edr::Alert alert;
    alert.ruleId = "EDR-chain-test";
    alert.severity = "high";
    alert.action = "alert";
    alert.event = &event;
    {
        edr::Alerter writer(path, false, false);
        Require(writer.Open(), "alerter fixture open failed");
        writer.OnAlert(alert);
    }
    std::string contents = ReadFile(path);
    ReplaceFirst(contents, "\"chain_seq\":1", "\"chain_seq\":2");
    WriteFile(path, contents);
    edr::Alerter broken(path, false, false);
    Require(!broken.Open(), "alerter accepted a sequence gap");
    DeleteFileA(path.c_str());
}

void TestIncidentStoreRejectsTruncatedTail() {
    const std::string path = TempPath("edr-incident-chain-");
    DeleteFileA(path.c_str());
    edr::Incident incident;
    incident.id = "incident-chain-test";
    incident.host = "host";
    incident.severity = "high";
    incident.alertCount = 1;
    {
        edr::IncidentStore writer(path, false, 10);
        Require(writer.Open(), "incident fixture open failed");
        writer.OnIncidentOpened(incident);
    }
    std::string contents = ReadFile(path);
    Require(!contents.empty(), "incident fixture is empty");
    contents.pop_back();
    WriteFile(path, contents);
    const std::string brokenContents = ReadFile(path);
    edr::IncidentStore broken(path, false, 10);
    Require(!broken.Open(), "incident store accepted an incomplete tail");
    broken.OnIncidentOpened(MakeIncidentFixture());
    broken.Close();
    broken.Close();
    Require(broken.RecordCount() == 0,
            "broken incident history changed the store record count");
    Require(ReadFile(path) == brokenContents,
            "incident store modified a truncated history after rejecting it");
    DeleteFileA(path.c_str());
}

void TestIncidentStoreProtectsNewAndExistingFile() {
    const std::string path = TempPath("edr-incident-acl-");
    DeleteFileA(path.c_str());

    std::string originalHistory;
    {
        edr::IncidentStore fresh(path, false, 10);
        Require(fresh.Open(), "incident store could not open a new file");
        Require(NormalizedFileDaclSddl(path) == "D:P(A;;FA;;;OW)",
                "new incident file does not have the exact protected owner-only DACL");
        fresh.OnIncidentOpened(MakeIncidentFixture());
        Require(fresh.RecordCount() == 1,
                "new incident file did not accept a write after ACL protection");
        fresh.Close();
    }

    originalHistory = ReadFile(path);
    Require(!originalHistory.empty() &&
                originalHistory.find("\"chain_seq\":1") != std::string::npos,
            "new incident file could not be read back as a chained record");

    RestoreInheritedFileDacl(path);
    {
        edr::IncidentStore existing(path, false, 10);
        Require(existing.Open(), "incident store could not open an existing valid chain");
        Require(NormalizedFileDaclSddl(path) == "D:P(A;;FA;;;OW)",
                "existing incident file was not converted to the exact protected owner-only DACL");
        existing.OnIncidentClosed(MakeIncidentFixture());
        Require(existing.RecordCount() == 1,
                "existing incident chain did not accept an append after ACL protection");
        existing.Close();
    }

    const std::string extendedHistory = ReadFile(path);
    Require(extendedHistory.size() > originalHistory.size() &&
                extendedHistory.compare(0, originalHistory.size(), originalHistory) == 0 &&
                extendedHistory.find("\"chain_seq\":2") != std::string::npos,
            "existing protected incident chain did not preserve and append its history");
    DeleteFileA(path.c_str());
}

void TestIncidentStoreAclFailurePreservesHistory() {
    const std::string validPath = TempPath("edr-incident-acl-failure-");
    CreateIncidentHistory(validPath);
    RestoreInheritedFileDacl(validPath);
    const std::string validHistory = ReadFile(validPath);
    Require(!validHistory.empty(), "ACL failure fixture history is empty");

    edr::IncidentStore unavailable(
        validPath, false, 10,
        [](HANDLE) { return false; });
    Require(!unavailable.Open(),
            "incident store opened with an unavailable file-protection function");
    unavailable.OnIncidentClosed(MakeIncidentFixture());
    unavailable.Close();
    unavailable.Close();
    Require(unavailable.RecordCount() == 0,
            "ACL failure counted a record that was not persisted");
    Require(ReadFile(validPath) == validHistory,
            "ACL failure appended to or changed an existing unprotected chain");
    DeleteFileA(validPath.c_str());

    const std::string newPath = TempPath("edr-incident-acl-new-failure-");
    DeleteFileA(newPath.c_str());
    edr::IncidentStore newUnavailable(
        newPath, false, 10,
        [](HANDLE) { return false; });
    Require(!newUnavailable.Open(),
            "new incident store opened when its protection function failed");
    newUnavailable.OnIncidentOpened(MakeIncidentFixture());
    newUnavailable.Close();
    newUnavailable.Close();
    Require(newUnavailable.RecordCount() == 0,
            "new-file ACL failure counted an unwritten incident");
    Require(ReadFile(newPath).empty(),
            "new-file ACL failure wrote incident bytes before protection succeeded");
    DeleteFileA(newPath.c_str());

    const std::string brokenPath = TempPath("edr-incident-acl-broken-");
    CreateIncidentHistory(brokenPath);
    std::string brokenHistory = ReadFile(brokenPath);
    Require(!brokenHistory.empty(), "broken-chain fixture history is empty");
    brokenHistory.pop_back();
    WriteFile(brokenPath, brokenHistory);
    const std::string rejectedHistory = ReadFile(brokenPath);

    edr::IncidentStore broken(brokenPath, false, 10);
    Require(!broken.Open(), "incident store accepted an incomplete tail");
    broken.OnIncidentOpened(MakeIncidentFixture());
    broken.Close();
    broken.Close();
    Require(broken.RecordCount() == 0,
            "truncated history counted an incident after Open failed");
    Require(ReadFile(brokenPath) == rejectedHistory,
            "truncated history changed after Open failed closed");
    DeleteFileA(brokenPath.c_str());
}

void TestResponseLedgerRejectsTamperedHash() {
    const std::string path = TempPath("edr-response-chain-");
    DeleteFileA(path.c_str());
    edr::ResponseRequest request;
    request.kind = edr::ResponseRequest::Kind::Terminate;
    request.requestId = "chain-test-1234-1234-123456789abc";
    request.timestamp = "134348719355421281";
    request.reason = "chain replay test";
    request.pid = 12345;
    request.createTime100ns = "123456789";
    {
        edr::ResponseAuditLedger writer;
        std::string error;
        Require(writer.Open(path, error), "response fixture open failed");
        Require(writer.AcceptDryRun(request, error), "response fixture write failed");
    }
    std::string contents = ReadFile(path);
    ReplaceFirst(contents, "\"chain_hash\":\"", "\"chain_hash\":\"0");
    WriteFile(path, contents);
    edr::ResponseAuditLedger broken;
    std::string error;
    Require(!broken.Open(path, error), "response ledger accepted a tampered hash");
    DeleteFileA(path.c_str());
}

} // namespace

void RunAuditChainRecoveryTests() {
    TestAlerterRejectsBrokenHistory();
    TestIncidentStoreRejectsTruncatedTail();
    TestIncidentStoreProtectsNewAndExistingFile();
    TestIncidentStoreAclFailurePreservesHistory();
    TestResponseLedgerRejectsTamperedHash();
}

#if !defined(EDR_NATIVE_TESTS)
int main() {
    try {
        RunAuditChainRecoveryTests();
        std::cout << "audit chain recovery tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << "\n";
        return 1;
    }
}
#endif
