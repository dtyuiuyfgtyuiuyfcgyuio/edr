/*
 * response_stream_replay_tests.cpp - large-file full-history replay tests for
 * the native response audit ledger.
 */
#include "response_stream_replay_tests.h"

#include <windows.h>

#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

#include "response_server.h"

namespace {

#define SR_CHECK(condition) Check((condition), #condition, __LINE__)

constexpr size_t kLegacyRecordCount = 50001;
constexpr size_t kReplayRecentRecordCount = 50000;
constexpr size_t kReplayMiB = 1024 * 1024;

void Check(bool condition, const char* expression, int line) {
    if (!condition) {
        throw std::runtime_error("response stream replay test failed at line " +
            std::to_string(line) + ": " + expression);
    }
}

std::string TempPath(const char* prefix) {
    char directory[MAX_PATH] = {};
    SR_CHECK(GetTempPathA(MAX_PATH, directory) != 0);
    return std::string(directory) + prefix +
        std::to_string(GetCurrentProcessId()) + ".jsonl";
}

void RemoveIfPresent(const std::string& path) {
    DeleteFileA(path.c_str());
}

uint64_t FileSize(const std::string& path) {
    HANDLE file = CreateFileA(path.c_str(), FILE_READ_ATTRIBUTES,
                              FILE_SHARE_READ | FILE_SHARE_WRITE |
                                  FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                              nullptr);
    SR_CHECK(file != INVALID_HANDLE_VALUE);
    LARGE_INTEGER size = {};
    const BOOL sized = GetFileSizeEx(file, &size);
    CloseHandle(file);
    SR_CHECK(sized != FALSE && size.QuadPart >= 0);
    return static_cast<uint64_t>(size.QuadPart);
}

std::string ReadAll(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    SR_CHECK(input.is_open());
    std::string contents((std::istreambuf_iterator<char>(input)),
                         std::istreambuf_iterator<char>());
    SR_CHECK(!input.bad());
    return contents;
}

std::string LegacyRequestId(size_t index) {
    return "legacy-" + std::to_string(index) + "-123456789abc";
}

void WriteLegacyPrefix(const std::string& path, size_t recordCount,
                       size_t paddingBytes) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    SR_CHECK(output.is_open());
    const std::string padding(paddingBytes, 'x');
    for (size_t index = 1; index <= recordCount; ++index) {
        output << "{\"requestId\":\"" << LegacyRequestId(index)
               << "\",\"padding\":\"" << padding
               << "\"}\n";
    }
    output.close();
    SR_CHECK(output.good());
}

edr::ResponseActionRequest MakeAction(const std::string& requestId,
                                      const std::string& timestamp) {
    edr::ResponseActionRequest request;
    request.requestId = requestId;
    request.timestamp = timestamp;
    request.pid = 12345;
    request.createTime100ns = 123456789;
    return request;
}

std::vector<std::string> BuildPendingSuffix(const std::string& requestId,
                                           const std::string& timestamp) {
    const std::string builderPath = TempPath("edr-response-stream-seed-");
    RemoveIfPresent(builderPath);
    std::vector<std::string> lines;
    std::string error;
    {
        edr::ResponseAuditLedger builder(
            [&](HANDLE, const std::string& line) {
                lines.push_back(line);
                return true;
            });
        if (!builder.Open(builderPath, error)) {
            throw std::runtime_error("could not open chain-line fixture builder: " +
                                     error);
        }
        const auto request = MakeAction(requestId, timestamp);
        if (!builder.Attempt(request, error)) {
            throw std::runtime_error("could not make pending fixture record: " +
                                     error);
        }
        builder.Close();
    }
    RemoveIfPresent(builderPath);
    SR_CHECK(lines.size() == 1);
    return lines;
}

std::vector<std::string> BuildLargeSuffix(const std::string& firstId,
                                         const std::string& secondId,
                                         size_t largePayloadBytes) {
    const std::string builderPath = TempPath("edr-response-stream-seed-");
    RemoveIfPresent(builderPath);
    std::vector<std::string> lines;
    std::string error;
    {
        edr::ResponseAuditLedger builder(
            [&](HANDLE, const std::string& line) {
                lines.push_back(line);
                return true;
            });
        if (!builder.Open(builderPath, error)) {
            throw std::runtime_error("could not open chain-line fixture builder: " +
                                     error);
        }

        auto first = MakeAction(firstId, "134348719355421281");
        if (!builder.Attempt(first, error)) {
            throw std::runtime_error("could not make first chain fixture record: " +
                                     error);
        }
        edr::ResponseActionResult outcome;
        outcome.requestId = firstId;
        outcome.status.assign(largePayloadBytes, 's');
        if (!builder.Outcome(outcome, error)) {
            throw std::runtime_error("could not make large outcome fixture record: " +
                                     error);
        }
        auto second = MakeAction(secondId,
                                 std::string(largePayloadBytes, '7'));
        if (!builder.Attempt(second, error)) {
            throw std::runtime_error("could not make late pending fixture record: " +
                                     error);
        }
        builder.Close();
    }
    RemoveIfPresent(builderPath);
    SR_CHECK(lines.size() == 3);
    return lines;
}

void AppendLines(const std::string& path,
                 const std::vector<std::string>& lines) {
    std::ofstream output(path, std::ios::binary | std::ios::app);
    SR_CHECK(output.is_open());
    for (const auto& line : lines) output << line;
    output.close();
    SR_CHECK(output.good());
}

void MutateFirstChainHash(std::string& line) {
    const std::string field = "\"chain_hash\":\"";
    const size_t marker = line.find(field);
    SR_CHECK(marker != std::string::npos);
    const size_t value = marker + field.size();
    SR_CHECK(value < line.size());
    line[value] = line[value] == '0' ? '1' : '0';
}

void ReplaceFirstChainSequence(std::string& line, const std::string& sequence) {
    const std::string field = "\"chain_seq\":";
    const size_t marker = line.find(field);
    SR_CHECK(marker != std::string::npos);
    const size_t begin = marker + field.size();
    size_t end = begin;
    while (end < line.size() && line[end] >= '0' && line[end] <= '9') ++end;
    SR_CHECK(end > begin);
    line.replace(begin, end - begin, sequence);
}

void TestResponseAuditStreamsLargeLegacyPrefixAndLatePending() {
    const std::string path = TempPath("edr-response-stream-valid-");
    RemoveIfPresent(path);
    WriteLegacyPrefix(path, kLegacyRecordCount, 160);
    const std::string pendingId = "stream-pending-1234-1234-123456789abc";
    AppendLines(path, BuildPendingSuffix(pendingId, "134348719355421281"));
    SR_CHECK(FileSize(path) > 8 * kReplayMiB);

    edr::ResponseAuditLedger ledger;
    std::string error;
    if (!ledger.Open(path, error)) {
        throw std::runtime_error("large legacy response history failed to replay: " +
                                 error);
    }
    const size_t expiredCount = kLegacyRecordCount + 1 -
        kReplayRecentRecordCount;
    for (size_t index = 1; index <= expiredCount; ++index)
        SR_CHECK(!ledger.Contains(LegacyRequestId(index)));
    SR_CHECK(ledger.Contains(LegacyRequestId(expiredCount + 1)));
    SR_CHECK(ledger.Contains(LegacyRequestId(kLegacyRecordCount)));
    SR_CHECK(ledger.Contains(pendingId));
    const auto state = ledger.State();
    SR_CHECK(state.available && state.pending && !state.writable);

    auto blocked = MakeAction("blocked-after-pending-1234-123456789abc",
                              "134348719355421282");
    SR_CHECK(!ledger.Attempt(blocked, error));
    SR_CHECK(error == "prior attempt has no outcome");
    ledger.Close();
    RemoveIfPresent(path);
}

void TestResponseAuditRejectsTamperedEarlyChainBeyondEightMiB() {
    const std::string path = TempPath("edr-response-stream-tampered-");
    RemoveIfPresent(path);
    auto lines = BuildLargeSuffix(
        "stream-first-1234-123456789abc",
        "stream-late-1234-123456789abc", 4 * kReplayMiB + 64);
    MutateFirstChainHash(lines.front());
    AppendLines(path, lines);
    SR_CHECK(FileSize(path) > 8 * kReplayMiB);
    const std::string before = ReadAll(path);

    edr::ResponseAuditLedger ledger;
    std::string error;
    SR_CHECK(!ledger.Open(path, error));
    SR_CHECK(!ledger.State().available);
    SR_CHECK(ReadAll(path) == before);
    ledger.Close();
    RemoveIfPresent(path);
}

void TestResponseAuditRejectsOversizedRecord() {
    const std::string path = TempPath("edr-response-stream-oversized-");
    RemoveIfPresent(path);
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    SR_CHECK(output.is_open());
    output << "{\"requestId\":\"oversized-1234-123456789abc\",\"padding\":\""
           << std::string(8 * kReplayMiB + 1, 'x') << "\"}\n";
    output.close();
    SR_CHECK(output.good());
    const std::string before = ReadAll(path);

    edr::ResponseAuditLedger ledger;
    std::string error;
    SR_CHECK(!ledger.Open(path, error));
    SR_CHECK(!ledger.State().available);
    SR_CHECK(ReadAll(path) == before);
    ledger.Close();
    RemoveIfPresent(path);
}

void TestResponseAuditRejectsMalformedAndTruncatedStream() {
    const std::string malformedPath = TempPath("edr-response-stream-malformed-");
    RemoveIfPresent(malformedPath);
    {
        std::ofstream output(malformedPath, std::ios::binary | std::ios::trunc);
        SR_CHECK(output.is_open());
        output << "{\"requestId\":\"malformed-1234-123456789abc\"}\n"
                  "{\"record_type\":\n";
    }
    const std::string malformedBefore = ReadAll(malformedPath);
    edr::ResponseAuditLedger malformed;
    std::string error;
    SR_CHECK(!malformed.Open(malformedPath, error));
    SR_CHECK(ReadAll(malformedPath) == malformedBefore);
    malformed.Close();
    RemoveIfPresent(malformedPath);

    const std::string truncatedPath = TempPath("edr-response-stream-truncated-");
    RemoveIfPresent(truncatedPath);
    {
        std::ofstream output(truncatedPath, std::ios::binary | std::ios::trunc);
        SR_CHECK(output.is_open());
        output << "{\"requestId\":\"truncated-1234-123456789abc\"}";
    }
    const std::string truncatedBefore = ReadAll(truncatedPath);
    edr::ResponseAuditLedger truncated;
    SR_CHECK(!truncated.Open(truncatedPath, error));
    SR_CHECK(ReadAll(truncatedPath) == truncatedBefore);
    truncated.Close();
    RemoveIfPresent(truncatedPath);
}

void TestResponseAuditRejectsInvalidUtf8() {
    const std::string path = TempPath("edr-response-stream-invalid-utf8-");
    RemoveIfPresent(path);
    {
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        SR_CHECK(output.is_open());
        output << "{\"requestId\":\"invalid-utf8-1234-123456789abc\",\"padding\":\"";
        output.put(static_cast<char>(0xc3)); // Truncated UTF-8 two-byte sequence.
        output << "\"}\n";
    }
    const std::string before = ReadAll(path);

    edr::ResponseAuditLedger ledger;
    std::string error;
    SR_CHECK(!ledger.Open(path, error));
    SR_CHECK(!ledger.State().available);
    SR_CHECK(ReadAll(path) == before);
    ledger.Close();
    RemoveIfPresent(path);
}

void TestResponseAuditRejectsUnsafeChainSequence() {
    const std::vector<std::string> unsafeSequences = {
        "9007199254740992", // First integer that cannot be represented safely.
        "9007199254740993", // Rounds when parsed as a JSON double.
        "18446744073709551615", // UINT64_MAX rounds to 2^64 as a double.
        "18446744073709551616" // 2^64, outside uint64_t conversion range.
    };
    for (size_t index = 0; index < unsafeSequences.size(); ++index) {
        const std::string prefix = "edr-response-stream-unsafe-sequence-" +
                                   std::to_string(index) + "-";
        const std::string path = TempPath(prefix.c_str());
        RemoveIfPresent(path);
        auto lines = BuildPendingSuffix(
            "stream-unsafe-sequence-123456789abc", "134348719355421283");
        ReplaceFirstChainSequence(lines.front(), unsafeSequences[index]);
        AppendLines(path, lines);
        const std::string before = ReadAll(path);

        edr::ResponseAuditLedger ledger;
        std::string error;
        SR_CHECK(!ledger.Open(path, error));
        SR_CHECK(!ledger.State().available);
        SR_CHECK(ReadAll(path) == before);
        ledger.Close();
        RemoveIfPresent(path);
    }
}

} // namespace

void RunResponseStreamReplayTests() {
    TestResponseAuditRejectsInvalidUtf8();
    TestResponseAuditStreamsLargeLegacyPrefixAndLatePending();
    TestResponseAuditRejectsTamperedEarlyChainBeyondEightMiB();
    TestResponseAuditRejectsOversizedRecord();
    TestResponseAuditRejectsMalformedAndTruncatedStream();
    TestResponseAuditRejectsUnsafeChainSequence();
}
