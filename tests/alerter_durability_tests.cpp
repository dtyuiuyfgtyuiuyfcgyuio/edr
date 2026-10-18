/* Focused failure-injection tests for the alert ledger durability contract. */
#include "alerter_durability_tests.h"

#include <windows.h>
#include <aclapi.h>

#include <cstdio>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "alerter.h"
#include "edr_event.h"

namespace {

#define AD_CHECK(cond) Check((cond), #cond, __LINE__)

void Check(bool cond, const char* expr, int line) {
    if (!cond) {
        throw std::runtime_error("alerter durability test failed at line " +
                                 std::to_string(line) + ": " + expr);
    }
}

std::string TempLedgerPath(const char* tag) {
    char tempDir[MAX_PATH] = {};
    const DWORD n = GetTempPathA(MAX_PATH, tempDir);
    AD_CHECK(n > 0 && n < MAX_PATH);
    static unsigned counter = 0;
    std::string path = std::string(tempDir) + "alerter_durability_" + tag +
        "_" + std::to_string(GetCurrentProcessId()) + "_" +
        std::to_string(++counter) + ".jsonl";
    DeleteFileA(path.c_str());
    return path;
}

void RemoveQuietly(const std::string& path) { DeleteFileA(path.c_str()); }

void CheckOwnerOnlyProtectedAcl(const std::string& path) {
    HANDLE token = nullptr;
    AD_CHECK(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token));
    DWORD needed = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
    std::vector<unsigned char> userBuffer(needed);
    AD_CHECK(needed != 0 && GetTokenInformation(
        token, TokenUser, userBuffer.data(), needed, &needed));
    const PSID userSid = reinterpret_cast<TOKEN_USER*>(userBuffer.data())->User.Sid;

    const int wideLength = MultiByteToWideChar(CP_ACP, 0, path.c_str(), -1,
                                               nullptr, 0);
    AD_CHECK(wideLength > 0);
    std::vector<wchar_t> widePath(static_cast<size_t>(wideLength));
    AD_CHECK(MultiByteToWideChar(CP_ACP, 0, path.c_str(), -1,
                                 widePath.data(), wideLength) == wideLength);

    PSID ownerSid = nullptr;
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    DWORD rc = GetNamedSecurityInfoW(widePath.data(), SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &ownerSid, nullptr, &dacl, nullptr, &descriptor);
    AD_CHECK(rc == ERROR_SUCCESS && ownerSid != nullptr && dacl != nullptr);
    AD_CHECK(EqualSid(ownerSid, userSid));

    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    AD_CHECK(GetSecurityDescriptorControl(descriptor, &control, &revision));
    AD_CHECK((control & SE_DACL_PROTECTED) != 0);

    ACL_SIZE_INFORMATION aclInfo = {};
    AD_CHECK(GetAclInformation(dacl, &aclInfo, sizeof(aclInfo),
                               AclSizeInformation));
    AD_CHECK(aclInfo.AceCount == 1);
    void* ace = nullptr;
    AD_CHECK(GetAce(dacl, 0, &ace));
    auto* access = static_cast<ACCESS_ALLOWED_ACE*>(ace);
    AD_CHECK(access->Header.AceType == ACCESS_ALLOWED_ACE_TYPE);
    AD_CHECK(EqualSid(&access->SidStart, userSid));
    AD_CHECK((access->Mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS);

    LocalFree(descriptor);
    CloseHandle(token);
}

struct Fixture {
    edr::Event event;
    edr::Alert alert;

    Fixture() {
        event.type = EDR_EVT_PROCESS_START;
        event.ts100ns = 134000000000000000ULL;
        event.pid = 4242;
        event.source = "alerter-durability-test";
        alert.ruleId = "EDR-DURABILITY";
        alert.severity = "high";
        alert.action = "alert";
        alert.event = &event;
    }
};

} // namespace

void RunAlerterDurabilityTests() {
    /* Simulate a short append (some bytes reached storage) followed by a
     * flush error. Alerter must latch the failure because the tail may now
     * be malformed, leave the committed chain cursor unchanged, and never
     * tell the sink that this or a later alert was persisted. */
    const std::string partialPath = TempLedgerPath("partial");
    std::vector<std::string> attemptedLines;
    std::vector<std::string> sinkLines;
    edr::Alerter alerter(
        partialPath, false, false,
        [&](const std::string& line, std::string& error) {
            attemptedLines.push_back(line);
            std::ofstream partial(partialPath, std::ios::binary | std::ios::app);
            partial.write(line.data(), static_cast<std::streamsize>(line.size() / 2));
            partial.flush();
            error = "simulated short write: disk full";
            return false;
        });
    AD_CHECK(alerter.Open());
    alerter.SetSink([&](const std::string& line) { sinkLines.push_back(line); });

    Fixture failedAlert;
    alerter.OnAlert(failedAlert.alert);
    Fixture ignoredAlert;
    ignoredAlert.event.pid++;
    alerter.OnAlert(ignoredAlert.alert);

    const auto status = alerter.GetWriteStatus();
    AD_CHECK(attemptedLines.size() == 1);
    AD_CHECK(sinkLines.empty());
    AD_CHECK(!status.writable);
    AD_CHECK(status.writeFailures == 1);
    AD_CHECK(status.chainSequence == 0);
    AD_CHECK(status.lastError.find("disk full") != std::string::npos);
    alerter.Close();
    AD_CHECK(!alerter.Open()); /* the failed instance stays latched */
    {
        edr::Alerter restarted(partialPath, false, false);
        AD_CHECK(!restarted.Open()); /* a partial JSONL tail is never extended */
        AD_CHECK(!restarted.GetWriteStatus().writable);
    }
    RemoveQuietly(partialPath);

    /* The production file path must apply the same protected owner-only ACL
     * on both first creation and reopen of an existing ledger. */
    const std::string path = TempLedgerPath("acl");
    {
        edr::Alerter writer(path, false, false);
        AD_CHECK(writer.Open());
        CheckOwnerOnlyProtectedAcl(path);
        Fixture initialAlert;
        writer.OnAlert(initialAlert.alert);
        AD_CHECK(writer.GetWriteStatus().chainSequence == 1);
    }
    {
        edr::Alerter resumed(path, false, false);
        AD_CHECK(resumed.Open());
        CheckOwnerOnlyProtectedAcl(path);
        AD_CHECK(resumed.GetWriteStatus().chainSequence == 1);
        Fixture next;
        next.event.pid++;
        resumed.OnAlert(next.alert);
        AD_CHECK(resumed.GetWriteStatus().chainSequence == 2);
    }
    RemoveQuietly(path);

    /* Replay remains bounded for a corrupt oversized unterminated line. */
    const std::string oversizedPath = TempLedgerPath("oversized");
    {
        std::ofstream out(oversizedPath, std::ios::binary | std::ios::trunc);
        AD_CHECK(out.good());
        const std::string block(64 * 1024, 'x');
        for (size_t i = 0; i < 257; ++i) out.write(block.data(), block.size());
        out.flush();
        AD_CHECK(out.good());
    }
    {
        edr::Alerter oversized(oversizedPath, false, false);
        AD_CHECK(!oversized.Open());
        AD_CHECK(!oversized.GetWriteStatus().writable);
    }
    RemoveQuietly(oversizedPath);
}
