/*
 * triage_pack_tests.cpp - Tests for the read-only triage pack export
 * (user/triage_pack.{h,cpp}, wired as `edr.exe --triage`).
 *
 * Covered contract points (see user/triage_pack.h):
 *   - dry-run collects/hashes but creates nothing on disk
 *   - manifest.json fields: kind/version/generated_utc(ISO-8601 UTC)/
 *     tail_lines/files[{name,sha256,bytes,lines,missing,status,reason,source_lines,omitted_lines}]
 *   - sha256 spot-checked against an independent test-local BCrypt
 *     implementation (not the production helper)
 *   - rules_summary.json carries {count, parse_ok, sha256 of the full file}
 *   - missing/unreadable inputs are graceful: manifest marks missing=true
 *   - tail trimming: more than N -> exactly N; fewer than N -> all;
 *     empty ledger -> empty tail file, still missing=false
 *   - final source line without a trailing newline is emitted
 *     newline-terminated
 *   - outDir that is non-empty (and holds no input file) is rejected;
 *     outDir == ledger directory is allowed (input basenames carve-out)
 *   - manifest written last is proxied by "manifest lists every content
 *     file, present or missing" (a real ordering race is not assertable)
 *   - tailLines range contract: 50/100001 rejected, 100000 accepted
 *   - 16 MiB overlong-line omission with manifest completeness
 *
 * Fixtures live under %TEMP% (tag + pid + counter), mirroring the house
 * temp-ledger pattern; every case cleans its directories up.
 */
#include "triage_pack_tests.h"

#include <windows.h>
#include <bcrypt.h>
#include <aclapi.h>
#include <sddl.h>
#include <winioctl.h>
#include <cstddef>

#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "json_lite.h"
#include "triage_pack.h"

namespace {

#define TP_CHECK(condition) TpCheck((condition), #condition, __LINE__)

void TpCheck(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error("triage pack test failed at line " +
                                 std::to_string(line) + ": " + expression);
}

/* ---- temp fixtures (tag + pid + counter, under %TEMP%) ---- */

unsigned g_tempCounter = 0;

std::string MakeTempDir(const char* tag) {
    char tempDir[MAX_PATH] = {};
    const DWORD n = GetTempPathA(MAX_PATH, tempDir);
    TP_CHECK(n > 0 && n < MAX_PATH);
    for (;;) {
        std::string dir = std::string(tempDir) + "edr_triage_" + tag + "_" +
                          std::to_string(GetCurrentProcessId()) + "_" +
                          std::to_string(++g_tempCounter);
        if (CreateDirectoryA(dir.c_str(), nullptr)) return dir;
        TP_CHECK(GetLastError() == ERROR_ALREADY_EXISTS); /* retry new name */
    }
}

void RemoveDirRecursive(const std::string& dir) {
    WIN32_FIND_DATAA fd{};
    HANDLE h = FindFirstFileA((dir + "\\*").c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            std::string name = fd.cFileName;
            if (name == "." || name == "..") continue;
            std::string full = dir + "\\" + name;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                RemoveDirRecursive(full);
            else
                DeleteFileA(full.c_str());
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
    RemoveDirectoryA(dir.c_str());
}

std::vector<std::string> ListDir(const std::string& dir) {
    std::vector<std::string> names;
    WIN32_FIND_DATAA fd{};
    HANDLE h = FindFirstFileA((dir + "\\*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return names;
    do {
        std::string name = fd.cFileName;
        if (name == "." || name == "..") continue;
        names.push_back(name);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    return names;
}

bool PathExists(const std::string& path) {
    return GetFileAttributesA(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}

/* ---- file helpers ---- */

void WriteTextFile(const std::string& path, const std::string& content) {
    HANDLE h = CreateFileA(path.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    TP_CHECK(h != INVALID_HANDLE_VALUE);
    DWORD written = 0;
    TP_CHECK(content.empty() ||
             (WriteFile(h, content.data(), (DWORD)content.size(), &written,
                        nullptr) &&
              written == content.size()));
    CloseHandle(h);
}

std::string ReadAllText(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    TP_CHECK(in.good());
    return std::string((std::istreambuf_iterator<char>(in)),
                       std::istreambuf_iterator<char>());
}

std::vector<std::string> ReadAllLines(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    TP_CHECK(in.good());
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        lines.push_back(line);
    }
    return lines;
}

/* Ledger content: "l1\nl2\n...l<count>" (+ trailing newline when asked). */
std::string MakeLedgerContent(int count, bool trailingNewline) {
    std::string content;
    for (int i = 1; i <= count; ++i) {
        content += "l" + std::to_string(i);
        content += (i == count && !trailingNewline) ? "" : "\n";
    }
    return content;
}

/* ---- independent test-local SHA-256 (BCrypt), for spot checks ---- */

std::string Sha256HexLocal(const std::string& text) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE h = nullptr;
    DWORD objLen = 0, ret = 0;
    std::vector<unsigned char> obj;
    unsigned char digest[32] = {};
    NTSTATUS st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM,
                                              nullptr, 0);
    if (st >= 0)
        st = BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen,
                               sizeof(objLen), &ret, 0);
    if (st >= 0) {
        obj.resize(objLen);
        st = BCryptCreateHash(alg, &h, obj.data(), objLen, nullptr, 0, 0);
    }
    if (st >= 0)
        st = BCryptHashData(h, (PUCHAR)text.data(), (ULONG)text.size(), 0);
    if (st >= 0) st = BCryptFinishHash(h, digest, sizeof(digest), 0);
    if (h) BCryptDestroyHash(h);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    TP_CHECK(st >= 0);
    static const char hex[] = "0123456789abcdef";
    std::string out(64, '0');
    for (size_t i = 0; i < 32; ++i) {
        out[i * 2] = hex[digest[i] >> 4];
        out[i * 2 + 1] = hex[digest[i] & 15];
    }
    return out;
}

/* ---- assertion helpers ---- */

bool IsLowerHex64(const std::string& s) {
    if (s.size() != 64) return false;
    for (char c : s) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

/* 2026-10-04T12:34:56Z shape check. */
bool LooksIso8601Utc(const std::string& s) {
    if (s.size() != 20) return false;
    const int digitIdx[] = {0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18};
    for (int i : digitIdx) {
        if (!std::isdigit((unsigned char)s[(size_t)i])) return false;
    }
    return s[4] == '-' && s[7] == '-' && s[10] == 'T' && s[13] == ':' &&
           s[16] == ':' && s[19] == 'Z';
}

const jsonlite::Value& FieldOf(const jsonlite::Value& obj, const char* key) {
    const jsonlite::Value* v = obj.find(key);
    TP_CHECK(v != nullptr);
    return *v;
}

struct Fixture {
    std::string dir;
    std::string configPath;
    std::string rulesPath;
    std::string alertsPath;
    std::string incidentsPath;
    std::string responseAuditPath;

    std::string MakeMissing(const char* name) const {
        return dir + "\\" + name; /* never created */
    }
};

Fixture MakeFullFixture(bool withConfig, bool withRules, bool withAlerts,
                        bool withIncidents, bool withResponse) {
    Fixture fx;
    fx.dir = MakeTempDir("fx");
    if (withConfig) {
        fx.configPath = fx.dir + "\\edr.config.json";
        WriteTextFile(fx.configPath, "{\"console\": true}\n");
    }
    if (withRules) {
        fx.rulesPath = fx.dir + "\\rules.json";
        WriteTextFile(fx.rulesPath,
                      "{\"rules\": [{\"id\": \"EDR-001\"}, "
                      "{\"id\": \"EDR-002\"}]}");
    }
    if (withAlerts) {
        fx.alertsPath = fx.dir + "\\alerts.jsonl";
        WriteTextFile(fx.alertsPath, MakeLedgerContent(3, true));
    }
    if (withIncidents) {
        fx.incidentsPath = fx.dir + "\\incidents.jsonl";
        WriteTextFile(fx.incidentsPath, MakeLedgerContent(2, true));
    }
    if (withResponse) {
        fx.responseAuditPath = fx.dir + "\\response-audit.jsonl";
        WriteTextFile(fx.responseAuditPath, MakeLedgerContent(5, true));
    }
    return fx;
}

edr::TriageOptions BaseOptions(const Fixture& fx, const std::string& outDir) {
    edr::TriageOptions opts;
    opts.configPath = fx.configPath;
    opts.rulesPath = fx.rulesPath;
    opts.alertsPath = fx.alertsPath;
    opts.incidentsPath = fx.incidentsPath;
    opts.responseAuditPath = fx.responseAuditPath;
    opts.outDir = outDir;
    return opts;
}

/* ---- cases ---- */

void TestDryRunWritesNothing() {
    std::fprintf(stderr, "[triage_pack] TestDryRunWritesNothing\n");
    Fixture fx = MakeFullFixture(true, false, true, false, false);
    std::string out = MakeTempDir("dry");
    RemoveDirectoryA(out.c_str()); /* must NOT come back */

    edr::TriageOptions opts = BaseOptions(fx, out);
    opts.rulesPath = fx.MakeMissing("rules.json");
    opts.incidentsPath = fx.MakeMissing("incidents.jsonl");
    std::string error;
    int rc = edr::WriteTriagePack(opts, /*dryRun=*/true, error);
    TP_CHECK(rc == 0);
    TP_CHECK(!PathExists(out)); /* dry-run must not create outDir */

    /* Source directory untouched: still exactly the fixture files. */
    TP_CHECK(ListDir(fx.dir).size() == 2); /* config + alerts fixture */
    RemoveDirRecursive(fx.dir);
}

void TestPackManifestFieldsComplete() {
    std::fprintf(stderr, "[triage_pack] TestPackManifestFieldsComplete\n");
    Fixture fx = MakeFullFixture(true, true, true, true, true);
    std::string out = MakeTempDir("full"); /* exists-and-empty is valid */

    std::string rulesContent = ReadAllText(fx.rulesPath);

    edr::TriageOptions opts = BaseOptions(fx, out);
    std::string error;
    int rc = edr::WriteTriagePack(opts, false, error);
    TP_CHECK(rc == 0);

    std::string manifestText = ReadAllText(out + "\\manifest.json");
    jsonlite::Value manifest = jsonlite::parse(manifestText);
    TP_CHECK(manifest.type == jsonlite::Type::Object);
    TP_CHECK(FieldOf(manifest, "kind").asString() == "edr-triage-pack");
    TP_CHECK(FieldOf(manifest, "version").asNumber() == 2);
    TP_CHECK(FieldOf(manifest, "config_redacted").asBool());
    TP_CHECK(LooksIso8601Utc(FieldOf(manifest, "generated_utc").asString()));
    TP_CHECK(FieldOf(manifest, "tail_lines").asNumber() == 1000);

    const jsonlite::Value& files = FieldOf(manifest, "files");
    TP_CHECK(files.type == jsonlite::Type::Array);
    TP_CHECK(files.array.size() == 5);
    const char* expected[] = {"config.json", "rules_summary.json",
                              "alerts.tail.jsonl", "incidents.tail.jsonl",
                              "response_audit.tail.jsonl"};
    for (size_t i = 0; i < 5; ++i) {
        const jsonlite::Value& e = files.array[i];
        TP_CHECK(FieldOf(e, "name").asString() == expected[i]);
        TP_CHECK(!FieldOf(e, "missing").asBool());
        TP_CHECK(IsLowerHex64(FieldOf(e, "sha256").asString()));
    }

    /* sha256 spot check (config.json) against the independent impl. */
    TP_CHECK(FieldOf(files.array[0], "sha256").asString() ==
             Sha256HexLocal(ReadAllText(out + "\\config.json")));
    TP_CHECK(FieldOf(files.array[0], "lines").asNumber() == 1);
    TP_CHECK(FieldOf(files.array[0], "bytes").asNumber() ==
             (double)ReadAllText(out + "\\config.json").size());

    /* rules_summary.json: count + sha256 over the full rules file, and the
     * manifest hashes the produced summary file itself. */
    std::string summaryText = ReadAllText(out + "\\rules_summary.json");
    jsonlite::Value summary = jsonlite::parse(summaryText);
    TP_CHECK(FieldOf(summary, "count").asNumber() == 2);
    TP_CHECK(FieldOf(summary, "parse_ok").asBool());
    TP_CHECK(FieldOf(summary, "sha256").asString() ==
             Sha256HexLocal(rulesContent));
    TP_CHECK(FieldOf(files.array[1], "sha256").asString() ==
             Sha256HexLocal(summaryText));

    /* Tail files carry the exact fixture lines. */
    std::vector<std::string> alertLines = ReadAllLines(out + "\\alerts.tail.jsonl");
    TP_CHECK(alertLines.size() == 3);
    TP_CHECK(alertLines[0] == "l1" && alertLines[2] == "l3");
    TP_CHECK(FieldOf(files.array[2], "lines").asNumber() == 3);
    TP_CHECK(FieldOf(files.array[4], "lines").asNumber() == 5);

    RemoveDirRecursive(fx.dir);
    RemoveDirRecursive(out);
}

void TestMissingFilesGraceful() {
    std::fprintf(stderr, "[triage_pack] TestMissingFilesGraceful\n");
    Fixture fx = MakeFullFixture(false, false, false, false, false);
    std::string out = MakeTempDir("missing");
    RemoveDirectoryA(out.c_str());

    edr::TriageOptions opts = BaseOptions(fx, out);
    std::string error;
    int rc = edr::WriteTriagePack(opts, false, error);
    TP_CHECK(rc == 0); /* missing inputs are not errors */

    jsonlite::Value manifest = jsonlite::parse(ReadAllText(out + "\\manifest.json"));
    const jsonlite::Value& files = FieldOf(manifest, "files");
    TP_CHECK(files.array.size() == 5);
    for (const jsonlite::Value& e : files.array) {
        TP_CHECK(FieldOf(e, "missing").asBool());
        TP_CHECK(FieldOf(e, "sha256").asString().empty());
        TP_CHECK(FieldOf(e, "bytes").asNumber() == 0);
        TP_CHECK(FieldOf(e, "lines").asNumber() == 0);
    }
    /* No content files for missing inputs: only the manifest exists. */
    std::vector<std::string> produced = ListDir(out);
    TP_CHECK(produced.size() == 1);
    TP_CHECK(produced[0] == "manifest.json");
    RemoveDirRecursive(fx.dir);
    RemoveDirRecursive(out);
}

void TestManifestListsAllContentFiles() {
    /* Proxy test for "manifest is written last": whatever the present/
     * missing mix, the final manifest names every content file. */
    std::fprintf(stderr, "[triage_pack] TestManifestListsAllContentFiles\n");
    Fixture fx = MakeFullFixture(true, false, true, false, false);
    std::string out = MakeTempDir("mixed");

    edr::TriageOptions opts = BaseOptions(fx, out);
    opts.rulesPath = fx.MakeMissing("rules.json");
    opts.incidentsPath = fx.MakeMissing("incidents.jsonl");
    opts.responseAuditPath = fx.MakeMissing("response-audit.jsonl");
    std::string error;
    int rc = edr::WriteTriagePack(opts, false, error);
    TP_CHECK(rc == 0);

    jsonlite::Value manifest = jsonlite::parse(ReadAllText(out + "\\manifest.json"));
    const jsonlite::Value& files = FieldOf(manifest, "files");
    TP_CHECK(files.array.size() == 5);
    TP_CHECK(!FieldOf(files.array[0], "missing").asBool()); /* config.json */
    TP_CHECK(!FieldOf(files.array[2], "missing").asBool()); /* alerts tail */
    for (size_t i : {1u, 3u, 4u}) TP_CHECK(FieldOf(files.array[i], "missing").asBool());

    std::vector<std::string> produced = ListDir(out);
    TP_CHECK(produced.size() == 3); /* config + alerts tail + manifest */
    RemoveDirRecursive(fx.dir);
    RemoveDirRecursive(out);
}

void TestTailTrimsToN() {
    std::fprintf(stderr, "[triage_pack] TestTailTrimsToN\n");
    Fixture fx = MakeFullFixture(false, false, true, false, false);
    std::string out = MakeTempDir("trim");

    WriteTextFile(fx.alertsPath, MakeLedgerContent(130, true));
    edr::TriageOptions opts = BaseOptions(fx, out);
    opts.tailLines = 100;
    std::string error;
    int rc = edr::WriteTriagePack(opts, false, error);
    TP_CHECK(rc == 0);

    std::vector<std::string> lines = ReadAllLines(out + "\\alerts.tail.jsonl");
    TP_CHECK(lines.size() == 100);
    TP_CHECK(lines.front() == "l31");  /* 130 - 100 -> starts at line 31 */
    TP_CHECK(lines.back() == "l130");
    jsonlite::Value manifest = jsonlite::parse(ReadAllText(out + "\\manifest.json"));
    TP_CHECK(FieldOf(manifest, "tail_lines").asNumber() == 100);
    TP_CHECK(FieldOf(FieldOf(manifest, "files").array[2], "lines").asNumber() == 100);
    RemoveDirRecursive(fx.dir);
    RemoveDirRecursive(out);
}

void TestTailKeepsAllWhenFewerThanN() {
    std::fprintf(stderr, "[triage_pack] TestTailKeepsAllWhenFewerThanN\n");
    Fixture fx = MakeFullFixture(false, false, true, true, false);
    std::string out = MakeTempDir("few");

    WriteTextFile(fx.alertsPath, MakeLedgerContent(40, true));
    WriteTextFile(fx.incidentsPath, ""); /* present but empty */
    edr::TriageOptions opts = BaseOptions(fx, out); /* tailLines = 1000 */
    std::string error;
    int rc = edr::WriteTriagePack(opts, false, error);
    TP_CHECK(rc == 0);

    std::vector<std::string> lines = ReadAllLines(out + "\\alerts.tail.jsonl");
    TP_CHECK(lines.size() == 40);
    TP_CHECK(lines.front() == "l1" && lines.back() == "l40");

    /* Empty ledger: tail file exists (empty), still not "missing". */
    std::string emptyTail = ReadAllText(out + "\\incidents.tail.jsonl");
    TP_CHECK(emptyTail.empty());
    jsonlite::Value manifest = jsonlite::parse(ReadAllText(out + "\\manifest.json"));
    const jsonlite::Value& inc = FieldOf(manifest, "files").array[3];
    TP_CHECK(!FieldOf(inc, "missing").asBool());
    TP_CHECK(FieldOf(inc, "lines").asNumber() == 0);
    RemoveDirRecursive(fx.dir);
    RemoveDirRecursive(out);
}

void TestLastLineNoTrailingNewline() {
    std::fprintf(stderr, "[triage_pack] TestLastLineNoTrailingNewline\n");
    Fixture fx = MakeFullFixture(false, false, true, false, false);
    std::string out = MakeTempDir("noeol");

    WriteTextFile(fx.alertsPath, MakeLedgerContent(3, /*trailingNewline=*/false));
    edr::TriageOptions opts = BaseOptions(fx, out);
    std::string error;
    int rc = edr::WriteTriagePack(opts, false, error);
    TP_CHECK(rc == 0);

    /* Emitted tail is newline-terminated, content preserved. */
    TP_CHECK(ReadAllText(out + "\\alerts.tail.jsonl") == "l1\nl2\nl3\n");
    jsonlite::Value manifest = jsonlite::parse(ReadAllText(out + "\\manifest.json"));
    TP_CHECK(FieldOf(FieldOf(manifest, "files").array[2], "lines").asNumber() == 3);
    RemoveDirRecursive(fx.dir);
    RemoveDirRecursive(out);
}

void TestOutDirNonEmptyRejected() {
    std::fprintf(stderr, "[triage_pack] TestOutDirNonEmptyRejected\n");
    Fixture fx = MakeFullFixture(true, false, true, false, false);
    std::string out = MakeTempDir("nonempty");
    WriteTextFile(out + "\\stray.txt", "do not clobber me");

    edr::TriageOptions opts = BaseOptions(fx, out);
    std::string error;
    int rc = edr::WriteTriagePack(opts, false, error);
    TP_CHECK(rc != 0);
    TP_CHECK(error.find("not empty") != std::string::npos);
    /* Nothing was written into the refused directory. */
    std::vector<std::string> produced = ListDir(out);
    TP_CHECK(produced.size() == 1);
    TP_CHECK(produced[0] == "stray.txt");
    RemoveDirRecursive(fx.dir);
    RemoveDirRecursive(out);
}

void TestLedgerDirAsOutDirAllowed() {
    std::fprintf(stderr, "[triage_pack] TestLedgerDirAsOutDirAllowed\n");
    Fixture fx = MakeFullFixture(false, false, true, false, false);
    std::string before = ReadAllText(fx.alertsPath);

    edr::TriageOptions opts = BaseOptions(fx, fx.dir); /* out == ledger dir */
    std::string error;
    int rc = edr::WriteTriagePack(opts, false, error);
    TP_CHECK(rc == 0);

    /* The source ledger is byte-identical; pack files joined it. */
    TP_CHECK(ReadAllText(fx.alertsPath) == before);
    std::vector<std::string> produced = ListDir(fx.dir);
    TP_CHECK(produced.size() == 3); /* alerts.jsonl + tail + manifest */
    bool hasManifest = false, hasTail = false;
    for (const std::string& name : produced) {
        if (name == "manifest.json") hasManifest = true;
        if (name == "alerts.tail.jsonl") hasTail = true;
    }
    TP_CHECK(hasManifest && hasTail);
    RemoveDirRecursive(fx.dir);
}

void TestOversizeLineOmitted() {
    std::fprintf(stderr, "[triage_pack] TestOversizeLineOmitted\n");
    Fixture fx = MakeFullFixture(false, false, true, false, false);
    std::string out = MakeTempDir("oversize");

    /* One 17 MiB line without a trailing newline, then a normal line. */
    std::string big(17ull * 1024ull * 1024ull, 'x');
    WriteTextFile(fx.alertsPath, big + "\n" + "ok");
    big.clear();

    edr::TriageOptions opts = BaseOptions(fx, out);
    std::string error;
    int rc = edr::WriteTriagePack(opts, false, error);
    TP_CHECK(rc == 0);

    std::string tail = ReadAllText(out + "\\alerts.tail.jsonl");
    TP_CHECK(tail == "ok\n"); /* no invalid JSON fragments */
    jsonlite::Value manifest = jsonlite::parse(ReadAllText(out + "\\manifest.json"));
    const auto& entry = FieldOf(manifest, "files").array[2];
    TP_CHECK(FieldOf(entry, "lines").asNumber() == 1);
    TP_CHECK(FieldOf(entry, "source_lines").asNumber() == 2);
    TP_CHECK(FieldOf(entry, "omitted_lines").asNumber() == 1);
    TP_CHECK(FieldOf(entry, "status").asString() == "partial");
    RemoveDirRecursive(fx.dir);
    RemoveDirRecursive(out);
}

void TestTailLinesRangeRejected() {
    std::fprintf(stderr, "[triage_pack] TestTailLinesRangeRejected\n");
    Fixture fx = MakeFullFixture(true, false, true, false, false);
    std::string out = MakeTempDir("range");

    edr::TriageOptions opts = BaseOptions(fx, out);
    opts.tailLines = 50; /* below the documented 100..100000 range */
    std::string error;
    int rc = edr::WriteTriagePack(opts, false, error);
    TP_CHECK(rc != 0);
    TP_CHECK(error.find("100..100000") != std::string::npos);
    TP_CHECK(ListDir(out).empty()); /* nothing staged before the check */

    opts.tailLines = 100001; /* above the range */
    rc = edr::WriteTriagePack(opts, false, error);
    TP_CHECK(rc != 0);
    TP_CHECK(ListDir(out).empty());
    RemoveDirRecursive(fx.dir);
    RemoveDirRecursive(out);
}

void TestTailMaxBoundary() {
    std::fprintf(stderr, "[triage_pack] TestTailMaxBoundary\n");
    Fixture fx = MakeFullFixture(false, false, true, false, false);
    std::string out = MakeTempDir("maxn");

    WriteTextFile(fx.alertsPath, MakeLedgerContent(100001, true));
    edr::TriageOptions opts = BaseOptions(fx, out);
    opts.tailLines = 100000; /* top of the range must be accepted */
    std::string error;
    int rc = edr::WriteTriagePack(opts, false, error);
    TP_CHECK(rc == 0);

    std::vector<std::string> lines = ReadAllLines(out + "\\alerts.tail.jsonl");
    TP_CHECK(lines.size() == 100000);
    TP_CHECK(lines.front() == "l2");
    TP_CHECK(lines.back() == "l100001");
    RemoveDirRecursive(fx.dir);
    RemoveDirRecursive(out);
}

void TestConfigSecretsRedacted() {
    Fixture fx = MakeFullFixture(true, false, false, false, false);
    std::string out = MakeTempDir("secrets");
    WriteTextFile(fx.configPath,
        "{\"reporter\":{\"enable\":true,\"api_key\":\"secret-key\","
        "\"url\":\"https://user:password@host/?token=secret-url\"},"
        "\"secret\":123456,\"future_option\":[\"secret-future\"]}");
    std::string error;
    TP_CHECK(edr::WriteTriagePack(BaseOptions(fx, out), false, error) == 0);
    const std::string content = ReadAllText(out + "\\config.json");
    TP_CHECK(content.find("secret-key") == std::string::npos);
    TP_CHECK(content.find("secret-url") == std::string::npos);
    TP_CHECK(content.find("secret-future") == std::string::npos);
    TP_CHECK(content.find("123456") == std::string::npos);
    TP_CHECK(FieldOf(FieldOf(jsonlite::parse(content), "reporter"), "enable").asBool());
    TP_CHECK(ReadAllText(fx.configPath).find("secret-key") != std::string::npos);
    RemoveDirRecursive(fx.dir);
    RemoveDirRecursive(out);
}

void TestInvalidConfigFailsClosed() {
    Fixture fx = MakeFullFixture(true, false, false, false, false);
    std::string out = MakeTempDir("invalid_config");
    WriteTextFile(fx.configPath, "{\"api_key\":\"secret-invalid\"");
    std::string error;
    TP_CHECK(edr::WriteTriagePack(BaseOptions(fx, out), false, error) != 0);
    TP_CHECK(error.find("secret-invalid") == std::string::npos);
    TP_CHECK(ListDir(out).empty());
    WriteTextFile(fx.configPath, std::string(65, '[') + "0" + std::string(65, ']'));
    TP_CHECK(edr::WriteTriagePack(BaseOptions(fx, out), false, error) != 0);
    TP_CHECK(ListDir(out).empty());
    RemoveDirRecursive(fx.dir);
    RemoveDirRecursive(out);
}

void TestExistingTempAndPackNotOverwritten() {
    Fixture fx = MakeFullFixture(true, false, false, false, false);
    const std::string out = MakeTempDir("collision");
    std::string error;
    for (const char* name : {"config.json.tmp", "CONFIG.JSON", "manifest.json.tmp"}) {
        const std::string path = out + "\\" + name;
        WriteTextFile(path, "preserve existing bytes");
        TP_CHECK(edr::WriteTriagePack(BaseOptions(fx, out), false, error) != 0);
        TP_CHECK(ReadAllText(path) == "preserve existing bytes");
        TP_CHECK(ListDir(out).size() == 1);
        TP_CHECK(DeleteFileA(path.c_str()));
    }
    RemoveDirRecursive(fx.dir);
    RemoveDirRecursive(out);
}

void TestOutputDaclProtectedAndRecursive() {
    Fixture fx = MakeFullFixture(true, false, false, false, false);
    std::string parent = MakeTempDir("protected");
    std::string out = parent + "\\new\\pack";
    std::string error;
    TP_CHECK(edr::WriteTriagePack(BaseOptions(fx, out), false, error) == 0);
    for (const std::string path : {out, out + "\\config.json", out + "\\manifest.json"}) {
        PACL dacl = nullptr;
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        TP_CHECK(GetNamedSecurityInfoA(const_cast<char*>(path.c_str()), SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION, nullptr, nullptr, &dacl, nullptr, &descriptor) == ERROR_SUCCESS);
        SECURITY_DESCRIPTOR_CONTROL control = 0;
        DWORD revision = 0;
        TP_CHECK(GetSecurityDescriptorControl(descriptor, &control, &revision));
        TP_CHECK((control & SE_DACL_PROTECTED) != 0);
        TP_CHECK(dacl != nullptr && dacl->AceCount == 1);
        void* ace = nullptr;
        TP_CHECK(GetAce(dacl, 0, &ace));
        TP_CHECK(static_cast<ACE_HEADER*>(ace)->AceType == ACCESS_ALLOWED_ACE_TYPE);
        PSID ownerRights = nullptr;
        TP_CHECK(ConvertStringSidToSidA("S-1-3-4", &ownerRights));
        TP_CHECK(EqualSid(&static_cast<ACCESS_ALLOWED_ACE*>(ace)->SidStart, ownerRights));
        LocalFree(ownerRights);
        LocalFree(descriptor);
    }
    RemoveDirRecursive(fx.dir);
    RemoveDirRecursive(parent);
}

void TestOversizeFinalLineDeclared() {
    Fixture fx = MakeFullFixture(false, false, true, false, false);
    std::string out = MakeTempDir("final_overlong");
    WriteTextFile(fx.alertsPath, std::string(16u * 1024u * 1024u + 1, 'a'));
    std::string error;
    TP_CHECK(edr::WriteTriagePack(BaseOptions(fx, out), false, error) == 0);
    TP_CHECK(ReadAllText(out + "\\alerts.tail.jsonl").empty());
    const auto manifest = jsonlite::parse(ReadAllText(out + "\\manifest.json"));
    const auto& entry = FieldOf(manifest, "files").array[2];
    TP_CHECK(FieldOf(entry, "source_lines").asNumber() == 1);
    TP_CHECK(FieldOf(entry, "omitted_lines").asNumber() == 1);
    TP_CHECK(FieldOf(entry, "reason").asString() == "overlong_lines_omitted");
    RemoveDirRecursive(fx.dir);
    RemoveDirRecursive(out);
}

void TestJunctionAncestorRejected() {
    Fixture fx = MakeFullFixture(true, false, false, false, false);
    std::string parent = MakeTempDir("junction_parent");
    std::string target = MakeTempDir("junction_target");
    std::string junction = parent + "\\redirect";
    TP_CHECK(CreateDirectoryA(junction.c_str(), nullptr));
    HANDLE handle = CreateFileA(junction.c_str(), GENERIC_WRITE, 0, nullptr,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    TP_CHECK(handle != INVALID_HANDLE_VALUE);
    std::wstring targetWide(target.begin(), target.end()); /* fixture path is ASCII */
    std::wstring substitute = L"\\??\\" + targetWide;
    struct MountPoint {
        DWORD tag;
        WORD dataLength;
        WORD reserved;
        WORD substituteOffset;
        WORD substituteLength;
        WORD printOffset;
        WORD printLength;
        wchar_t path[1];
    };
    const size_t substituteBytes = substitute.size() * sizeof(wchar_t);
    const size_t printBytes = targetWide.size() * sizeof(wchar_t);
    std::vector<unsigned char> data(offsetof(MountPoint, path) + substituteBytes +
        printBytes + 2 * sizeof(wchar_t));
    auto* mount = reinterpret_cast<MountPoint*>(data.data());
    mount->tag = IO_REPARSE_TAG_MOUNT_POINT;
    mount->dataLength = static_cast<WORD>(data.size() - 8);
    mount->substituteLength = static_cast<WORD>(substituteBytes);
    mount->printOffset = static_cast<WORD>(substituteBytes + sizeof(wchar_t));
    mount->printLength = static_cast<WORD>(printBytes);
    std::memcpy(mount->path, substitute.data(), substituteBytes);
    std::memcpy(reinterpret_cast<unsigned char*>(mount->path) + mount->printOffset,
        targetWide.data(), printBytes);
    DWORD bytes = 0;
    BOOL created = DeviceIoControl(handle, FSCTL_SET_REPARSE_POINT, data.data(),
        static_cast<DWORD>(data.size()), nullptr, 0, &bytes, nullptr);
    CloseHandle(handle);
    TP_CHECK(created);
    std::string error;
    TP_CHECK(edr::WriteTriagePack(BaseOptions(fx, junction + "\\pack"), false, error) != 0);
    TP_CHECK(ListDir(target).empty());
    TP_CHECK(RemoveDirectoryA(junction.c_str())); /* detach before recursive fixture cleanup */
    RemoveDirRecursive(parent);
    RemoveDirRecursive(target);
    RemoveDirRecursive(fx.dir);
}

void TestFailedExportRemovesOnlyCreatedFiles() {
    Fixture fx = MakeFullFixture(true, true, false, false, false);
    const std::string out = MakeTempDir("failed_export");
    HANDLE handle = CreateFileA(fx.rulesPath.c_str(), GENERIC_WRITE, 0, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    TP_CHECK(handle != INVALID_HANDLE_VALUE);
    LARGE_INTEGER size{};
    size.QuadPart = 64LL * 1024 * 1024 + 1;
    TP_CHECK(SetFilePointerEx(handle, size, nullptr, FILE_BEGIN));
    TP_CHECK(SetEndOfFile(handle));
    CloseHandle(handle);
    std::string error;
    TP_CHECK(edr::WriteTriagePack(BaseOptions(fx, out), false, error) != 0);
    TP_CHECK(ListDir(out).empty());
    TP_CHECK(ReadAllText(fx.configPath) == "{\"console\": true}\n");
    TP_CHECK(PathExists(fx.rulesPath));
    RemoveDirRecursive(fx.dir);
    RemoveDirRecursive(out);
}

void TestUnreadableLedgerDeclared() {
    Fixture fx = MakeFullFixture(false, false, true, false, false);
    const std::string out = MakeTempDir("unreadable");
    HANDLE handle = CreateFileA(fx.alertsPath.c_str(), GENERIC_READ, 0, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    TP_CHECK(handle != INVALID_HANDLE_VALUE);
    std::string error;
    const int result = edr::WriteTriagePack(BaseOptions(fx, out), false, error);
    CloseHandle(handle);
    TP_CHECK(result == 0);
    const auto manifest = jsonlite::parse(ReadAllText(out + "\\manifest.json"));
    const auto& entry = FieldOf(manifest, "files").array[2];
    TP_CHECK(FieldOf(entry, "missing").asBool());
    TP_CHECK(FieldOf(entry, "reason").asString() == "unreadable");
    TP_CHECK(FieldOf(entry, "status").asString() == "not_collected");
    TP_CHECK(!PathExists(out + "\\alerts.tail.jsonl"));
    RemoveDirRecursive(fx.dir);
    RemoveDirRecursive(out);
}

} /* namespace */

void RunTriagePackTests() {
    TestConfigSecretsRedacted();
    TestInvalidConfigFailsClosed();
    TestExistingTempAndPackNotOverwritten();
    TestOutputDaclProtectedAndRecursive();
    TestOversizeFinalLineDeclared();
    TestJunctionAncestorRejected();
    TestFailedExportRemovesOnlyCreatedFiles();
    TestUnreadableLedgerDeclared();
    TestDryRunWritesNothing();
    TestPackManifestFieldsComplete();
    TestMissingFilesGraceful();
    TestManifestListsAllContentFiles();
    TestTailTrimsToN();
    TestTailKeepsAllWhenFewerThanN();
    TestLastLineNoTrailingNewline();
    TestOutDirNonEmptyRejected();
    TestLedgerDirAsOutDirAllowed();
    TestOversizeLineOmitted();
    TestTailLinesRangeRejected();
    TestTailMaxBoundary();
    std::fprintf(stderr, "[triage_pack] all passed\n");
}

/* Standalone probe harness, compiled only for the single-TU verification
 * probe (cl /DTRIAGE_PACK_PROBE_MAIN); the production test target defines
 * no such macro and gets just RunTriagePackTests via the .h. */
#ifdef TRIAGE_PACK_PROBE_MAIN
int main(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--triage-pack") continue; /* suite-selection dash flag */
        if (arg == "-h" || arg == "--help") {
            std::fprintf(stderr, "usage: triage_pack_tests [--triage-pack]\n");
            return 0;
        }
        std::fprintf(stderr, "unknown argument: %s\n", arg.c_str());
        return 2;
    }
    std::fprintf(stderr, "[triage_pack] RunTriagePackTests\n");
    try {
        RunTriagePackTests();
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[triage_pack] FAILED: %s\n", e.what());
        return 1;
    }
    std::fprintf(stderr, "[triage_pack] all passed\n");
    return 0;
}
#endif /* TRIAGE_PACK_PROBE_MAIN */
