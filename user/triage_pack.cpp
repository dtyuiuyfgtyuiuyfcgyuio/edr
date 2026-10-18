/*
 * triage_pack.cpp - read-only forensic triage pack export.
 *
 * See triage_pack.h for the full contract. Implementation notes:
 *
 *  - SHA-256 uses BCrypt directly (same approach as user/alerter.cpp's
 *    Sha256Hex) but is an independent, self-contained implementation here;
 *    no private helper is shared across files.
 *  - Tail extraction does two passes over a snapshot bounded by the file
 *    size taken at open time ("先扫全文件行数再回拷尾部"): pass 1 counts
 *    lines and records the byte offset where the last |tailLines| lines
 *    begin (ring buffer of line-start offsets), pass 2 seeks there and
 *    streams the tail. Both passes stop at the open-time size, so records
 *    appended by a concurrent writer after open are excluded. A concurrent
 *    truncate/rotate between the passes is a documented best-effort limit.
 *  - Content files retain exclusive handles through flush and rename; manifest.json is written last, so a pack directory
 *    without manifest.json means "interrupted export, do not trust".
 *  - Every emitted tail line is newline-terminated and capped at 16 MiB
 *    per line (kMaxTailLineBytes, mirroring the alert ledger's per-line
 *    bound on write); overlong lines are omitted in full and declared
 *    in the manifest, never exported as damaged JSON fragments.
 */
#include "triage_pack.h"
#include "owner_only_sd.h"

#include <windows.h>
#include <bcrypt.h>
#include <sddl.h>

#include <cstdint>
#include <cstddef>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <io.h>
#include <set>
#include <string>
#include <vector>

#include "json_lite.h"

namespace edr {

namespace {

/* ---- contract constants (documented in triage_pack.h) ---- */

constexpr size_t kTailLinesMin = 100;
constexpr size_t kTailLinesMax = 100000;
/* Per-line cap for emitted tail lines (bytes). Mirrors alerter.cpp's
 * kMaxAlertLedgerLineBytes so a corrupt/hand-edited ledger cannot turn one
 * line into an unbounded copy. */
constexpr size_t kMaxTailLineBytes = 16u * 1024u * 1024u;
/* Whole-file read cap for verbatim/summary inputs (config, rules). These
 * are read into memory to be hashed/printed; a config or rules file beyond
 * 64 MiB is treated as an error instead of silently truncating evidence. */
constexpr uint64_t kMaxWholeFileBytes = 64ull * 1024ull * 1024ull;
/* Streaming chunk size for the ledger passes. */
constexpr DWORD kReadChunkBytes = 1u << 20;

const char* const kConfigName = "config.json";
const char* const kRulesName = "rules_summary.json";
const char* const kAlertsName = "alerts.tail.jsonl";
const char* const kIncidentsName = "incidents.tail.jsonl";
const char* const kResponseName = "response_audit.tail.jsonl";
const char* const kManifestName = "manifest.json";

/* ---- small string / path helpers ---- */

std::wstring Utf8ToWide(const std::string& utf8) {
    if (utf8.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(),
                                (int)utf8.size(), nullptr, 0);
    if (n <= 0) return std::wstring();
    std::wstring wide((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(),
                        (int)utf8.size(), &wide[0], n);
    return wide;
}

std::string WideToUtf8Local(const std::wstring& wide) {
    if (wide.empty()) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, wide.data(), (int)wide.size(),
                                nullptr, 0, nullptr, nullptr);
    if (n <= 0) return std::string();
    std::string utf8((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.data(), (int)wide.size(), &utf8[0],
                        n, nullptr, nullptr);
    return utf8;
}

/* Last path component after '/' or '\\' (empty for an empty path). */
std::string BasenameUtf8(const std::string& path) {
    size_t slash = path.find_last_of("/\\");
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

std::string LastErrorText(const char* what, unsigned long code) {
    return std::string(what) + " (GetLastError " + std::to_string(code) + ")";
}

/* ---- SHA-256 (BCrypt), independent implementation ---- */

class Sha256Stream {
public:
    Sha256Stream() {
        NTSTATUS st = BCryptOpenAlgorithmProvider(&m_alg, BCRYPT_SHA256_ALGORITHM,
                                                  nullptr, 0);
        if (st >= 0) {
            DWORD objLen = 0, ret = 0;
            st = BCryptGetProperty(m_alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen,
                                   sizeof(objLen), &ret, 0);
            if (st >= 0) {
                m_obj.resize(objLen);
                st = BCryptCreateHash(m_alg, &m_hash, m_obj.data(), objLen,
                                      nullptr, 0, 0);
            }
        }
        m_ok = (st >= 0);
    }
    ~Sha256Stream() {
        if (m_hash) BCryptDestroyHash(m_hash);
        if (m_alg) BCryptCloseAlgorithmProvider(m_alg, 0);
    }
    Sha256Stream(const Sha256Stream&) = delete;
    Sha256Stream& operator=(const Sha256Stream&) = delete;

    bool Ok() const { return m_ok; }

    void Update(const void* data, size_t len) {
        if (!m_ok || len == 0) return;
        const unsigned char* p = (const unsigned char*)data;
        while (len > 0) {
            ULONG step = (ULONG)(len < 0x40000000ull ? len : 0x40000000ull);
            if (BCryptHashData(m_hash, (PUCHAR)p, step, 0) < 0) {
                m_ok = false;
                return;
            }
            p += step;
            len -= step;
        }
    }

    /* Lowercase hex, or an empty string when hashing failed. */
    std::string FinishHex() {
        if (!m_ok) return std::string();
        unsigned char digest[32] = {};
        if (BCryptFinishHash(m_hash, digest, sizeof(digest), 0) < 0) {
            m_ok = false;
            return std::string();
        }
        static const char hex[] = "0123456789abcdef";
        std::string out(64, '0');
        for (size_t i = 0; i < 32; ++i) {
            out[i * 2] = hex[digest[i] >> 4];
            out[i * 2 + 1] = hex[digest[i] & 15];
        }
        return out;
    }

private:
    BCRYPT_ALG_HANDLE m_alg = nullptr;
    BCRYPT_HASH_HANDLE m_hash = nullptr;
    std::vector<unsigned char> m_obj;
    bool m_ok = false;
};

std::string Sha256HexBuffer(const std::string& content) {
    Sha256Stream sha;
    sha.Update(content.data(), content.size());
    return sha.FinishHex();
}

/* ---- file helpers ---- */

bool FileExists(const std::wstring& path) {
    DWORD attrs = GetFileAttributesW(path.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES;
}

/* Open a source file for reading while letting a running agent keep it
 * open for append (all sharing flags). */
HANDLE OpenReadShared(const std::wstring& path) {
    return CreateFileW(path.c_str(), GENERIC_READ,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
}

/* Read a whole file (config / rules) into memory, capped at
 * kMaxWholeFileBytes. Returns false on any failure. */
bool ReadWholeFileCapped(const std::wstring& path, std::string& contentOut,
                         std::string& error) {
    contentOut.clear();
    HANDLE h = OpenReadShared(path);
    if (h == INVALID_HANDLE_VALUE) {
        error = LastErrorText("cannot open file", GetLastError());
        return false;
    }
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(h, &size)) {
        error = LastErrorText("cannot stat file", GetLastError());
        CloseHandle(h);
        return false;
    }
    if (size.QuadPart < 0 || (uint64_t)size.QuadPart > kMaxWholeFileBytes) {
        error = "file exceeds the " + std::to_string(kMaxWholeFileBytes) +
                " byte whole-read cap: " + WideToUtf8Local(path);
        CloseHandle(h);
        return false;
    }
    std::vector<char> buf(kReadChunkBytes);
    uint64_t remaining = (uint64_t)size.QuadPart;
    while (remaining > 0) {
        DWORD want = (DWORD)(remaining < buf.size() ? remaining : buf.size());
        DWORD got = 0;
        if (!ReadFile(h, buf.data(), want, &got, nullptr) || got == 0) {
            error = LastErrorText("cannot read file", GetLastError());
            CloseHandle(h);
            return false;
        }
        contentOut.append(buf.data(), got);
        remaining -= got;
    }
    CloseHandle(h);
    return true;
}

/* 'a\nb' -> 2, 'a\nb\n' -> 2, '' -> 0. Same rule the tail emitter uses:
 * a trailing chunk without a newline still counts as one line. */
uint64_t LineCountForBuffer(const std::string& content) {
    if (content.empty()) return 0;
    uint64_t lines = 0;
    for (char c : content) {
        if (c == '\n') ++lines;
    }
    if (content.back() != '\n') ++lines;
    return lines;
}

std::vector<std::string> ListDirNames(const std::wstring& dir) {
    std::vector<std::string> names;
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW((dir + L"\\*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return names;
    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
            continue;
        names.push_back(WideToUtf8Local(fd.cFileName));
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return names;
}

FILE* OpenWriteTmp(const std::wstring& path) {
    std::string sdError;
    PSECURITY_DESCRIPTOR descriptor = CreateOwnerOnlyDescriptor(sdError);
    if (descriptor == nullptr)
        return nullptr;
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor, FALSE};
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE | DELETE, 0,
                           &attributes, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    LocalFree(descriptor);
    if (h == INVALID_HANDLE_VALUE) return nullptr;
    int fd = _open_osfhandle((intptr_t)h, 0);
    if (fd < 0) {
        CloseHandle(h);
        return nullptr;
    }
    FILE* f = _fdopen(fd, "wb");
    if (!f) _close(fd); /* also closes the handle */
    return f;
}

bool RenameTmpToFinal(FILE* file, const std::wstring& finalPath) {
    HANDLE handle = reinterpret_cast<HANDLE>(_get_osfhandle(_fileno(file)));
    if (std::fflush(file) != 0 || !FlushFileBuffers(handle)) return false;
    const size_t nameBytes = finalPath.size() * sizeof(wchar_t);
    std::vector<unsigned char> buffer(offsetof(FILE_RENAME_INFO, FileName) + nameBytes + sizeof(wchar_t));
    auto* rename = reinterpret_cast<FILE_RENAME_INFO*>(buffer.data());
    rename->ReplaceIfExists = FALSE;
    rename->FileNameLength = static_cast<DWORD>(nameBytes);
    std::memcpy(rename->FileName, finalPath.data(), nameBytes);
    return SetFileInformationByHandle(handle, FileRenameInfo, rename,
                                     static_cast<DWORD>(buffer.size())) != 0;
}

/* Preserve configuration structure and numeric switches without exporting
 * arbitrary string credentials, URL userinfo/query secrets or future fields. */
std::string RedactedJson(const jsonlite::Value& value, unsigned depth = 0) {
    if (depth > 64) throw std::runtime_error("configuration nesting exceeds export limit");
    switch (value.type) {
    case jsonlite::Type::Null: return "null";
    case jsonlite::Type::Bool: return value.boolean ? "true" : "false";
    case jsonlite::Type::Number: {
        if (!std::isfinite(value.number)) throw std::runtime_error("non-finite configuration number");
        char text[32]{};
        std::snprintf(text, sizeof(text), "%.17g", value.number);
        return text;
    }
    case jsonlite::Type::String: return "\"[REDACTED]\"";
    case jsonlite::Type::Array: {
        std::string out = "[";
        for (const auto& item : value.array) {
            if (out.size() > 1) out += ',';
            out += RedactedJson(item, depth + 1);
        }
        return out + ']';
    }
    case jsonlite::Type::Object: {
        std::string out = "{";
        for (const auto& item : value.object) {
            if (out.size() > 1) out += ',';
            std::string key;
            for (unsigned char c : item.first)
                if (std::isalnum(c)) key += static_cast<char>(std::tolower(c));
            const bool secret = key.find("secret") != std::string::npos ||
                key.find("password") != std::string::npos ||
                key.find("token") != std::string::npos ||
                key.find("credential") != std::string::npos ||
                key.find("key") != std::string::npos || key == "pin";
            out += '"' + jsonlite::escape(item.first) + "\":";
            out += secret ? "\"[REDACTED]\"" : RedactedJson(item.second, depth + 1);
        }
        return out + '}';
    }
    }
    throw std::runtime_error("unsupported configuration type");
}

/* ---- ISO-8601 UTC timestamp (YYYY-MM-DDTHH:MM:SSZ) ---- */

std::string Iso8601Utc() {
    SYSTEMTIME st{};
    GetSystemTime(&st);
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%04u-%02u-%02uT%02u:%02u:%02uZ",
                  (unsigned)st.wYear, (unsigned)st.wMonth,
                  (unsigned)st.wDay, (unsigned)st.wHour,
                  (unsigned)st.wMinute, (unsigned)st.wSecond);
    return buf;
}

/* ---- rules summary ---- */

/* rules.json top level is {"rules": [...]} (a bare array is accepted as a
 * legacy fallback). parse_ok=false covers corrupt files: the sha256 is
 * still recorded, the count is reported as 0 and the manifest consumer can
 * see the parse failed instead of silently trusting "0 rules". */
size_t CountRulesInRulesFile(const std::string& text, bool& parseOk) {
    parseOk = false;
    try {
        jsonlite::Value root = jsonlite::parse(text);
        if (root.type == jsonlite::Type::Object) {
            const jsonlite::Value* rules = root.find("rules");
            if (rules && rules->type == jsonlite::Type::Array) {
                parseOk = true;
                return rules->array.size();
            }
        } else if (root.type == jsonlite::Type::Array) {
            parseOk = true;
            return root.array.size();
        }
    } catch (...) {
        parseOk = false;
    }
    return 0;
}

/* ---- manifest ---- */

struct EntryMeta {
    std::string name;
    std::string sha256;
    uint64_t bytes = 0;
    uint64_t lines = 0;
    uint64_t sourceLines = 0; /* total lines in the source ledger (tails) */
    bool missing = true;
    uint64_t omittedLines = 0;
    std::string reason = "not_configured";
    /* 0 = verbatim copy, 1 = rules summary, 2 = tail */
    int kind = 0;
};

std::string BuildManifestJson(const std::vector<EntryMeta>& entries,
                              size_t tailLines) {
    std::string s;
    s += "{\n";
    s += "  \"kind\": \"edr-triage-pack\",\n";
    s += "  \"version\": 2,\n";
    s += "  \"config_redacted\": true,\n";
    s += "  \"scope\": \"per_file_snapshot_tail\",\n";
    s += "  \"generated_utc\": \"" + jsonlite::escape(Iso8601Utc()) + "\",\n";
    s += "  \"tail_lines\": " + std::to_string(tailLines) + ",\n";
    s += "  \"files\": [\n";
    for (size_t i = 0; i < entries.size(); ++i) {
        const EntryMeta& e = entries[i];
        s += "    {\"name\": \"" + jsonlite::escape(e.name) + "\"";
        s += ", \"sha256\": \"" + jsonlite::escape(e.sha256) + "\"";
        s += ", \"bytes\": " + std::to_string(e.bytes);
        s += ", \"lines\": " + std::to_string(e.lines);
        s += ", \"missing\": ";
        s += e.missing ? "true" : "false";
        s += ", \"source_lines\": " + std::to_string(e.sourceLines);
        s += ", \"omitted_lines\": " + std::to_string(e.omittedLines);
        s += ", \"reason\": \"" + jsonlite::escape(e.reason) + "\"";
        s += ", \"status\": \"";
        s += e.missing ? "not_collected" :
            (e.omittedLines || (e.kind == 2 && e.sourceLines > e.lines)) ? "partial" : "collected";
        s += "\"";
        s += "}";
        if (i + 1 < entries.size()) s += ",";
        s += "\n";
    }
    s += "  ]\n";
    s += "}\n";
    return s;
}

/* ---- output sink used by the tail emitter ---- */

struct EntryOut {
    bool dry = false;            /* dry-run: hash/count only, no file */
    FILE* file = nullptr;        /* .tmp stream when staging */
    Sha256Stream sha;
    uint64_t bytes = 0;
    uint64_t lines = 0;
    uint64_t omittedLines = 0;

    /* Emit one line; always newline-terminated. Callers have already
     * capped the line at kMaxTailLineBytes. */
    void EmitLine(const std::string& line) {
        size_t len = line.size() < kMaxTailLineBytes ? line.size()
                                                     : kMaxTailLineBytes;
        static const char kNewline = '\n';
        if (!dry && file) {
            if (len) std::fwrite(line.data(), 1, len, file);
            std::fwrite(&kNewline, 1, 1, file);
        }
        sha.Update(line.data(), len);
        sha.Update(&kNewline, 1);
        bytes += len + 1;
        ++lines;
    }

    void WriteBuffer(const std::string& content) {
        if (!dry && file) std::fwrite(content.data(), 1, content.size(), file);
        sha.Update(content.data(), content.size());
        bytes += content.size();
    }
};

/* ---- tail extraction ---- */

/* Pass 1: count lines of the snapshot and find where the last |tailLines|
 * lines start. The ring holds the start offsets of the last |tailLines|
 * lines; when the file has more than |tailLines| lines the ring is full and
 * ring[ringPos] is the start of line (total - tailLines). */
bool ScanLineCount(HANDLE h, uint64_t snapshotBytes, size_t tailLines,
                   uint64_t& totalOut, uint64_t& tailStartOut) {
    LARGE_INTEGER zero{};
    if (!SetFilePointerEx(h, zero, nullptr, FILE_BEGIN)) return false;
    std::vector<unsigned char> buf(kReadChunkBytes);
    std::vector<uint64_t> ring(tailLines, 0);
    size_t ringPos = 0, ringFill = 0;
    uint64_t total = 0, offset = 0, remaining = snapshotBytes;
    bool inLine = false;
    while (remaining > 0) {
        DWORD want = (DWORD)(remaining < buf.size() ? remaining : buf.size());
        DWORD got = 0;
        if (!ReadFile(h, buf.data(), want, &got, nullptr) || got == 0)
            return false;
        remaining -= got;
        for (DWORD i = 0; i < got; ++i, ++offset) {
            if (!inLine) {
                inLine = true;
                ring[ringPos] = offset;
                ringPos = (ringPos + 1) % ring.size();
                if (ringFill < ring.size()) ++ringFill;
            }
            if (buf[i] == '\n') {
                ++total;
                inLine = false;
            }
        }
    }
    if (inLine) ++total; /* final line without trailing newline */
    totalOut = total;
    /* total > tailLines implies at least tailLines lines started, so the
     * ring is full and ringPos points at its oldest entry. */
    tailStartOut = (total > (uint64_t)tailLines) ? ring[ringPos] : 0;
    return true;
}

/* Pass 2: stream lines from tailStart to the snapshot end into |out|.
 * Lines longer than kMaxTailLineBytes are omitted and counted explicitly. A final
 * source line without a trailing newline is emitted newline-terminated. */
bool StreamTail(HANDLE h, uint64_t snapshotBytes, uint64_t tailStart,
                EntryOut& out) {
    LARGE_INTEGER pos{};
    pos.QuadPart = (LONGLONG)tailStart;
    if (!SetFilePointerEx(h, pos, nullptr, FILE_BEGIN)) return false;
    std::vector<char> buf(kReadChunkBytes);
    std::string line;
    line.reserve(4096);
    uint64_t remaining = snapshotBytes - tailStart;
    bool overlong = false;
    while (remaining > 0) {
        DWORD want = (DWORD)(remaining < buf.size() ? remaining : buf.size());
        DWORD got = 0;
        if (!ReadFile(h, buf.data(), want, &got, nullptr) || got == 0)
            return false;
        remaining -= got;
        for (DWORD i = 0; i < got; ++i) {
            char c = buf[i];
            if (c == '\n') {
                if (overlong) ++out.omittedLines;
                else out.EmitLine(line);
                line.clear();
                overlong = false;
            } else if (line.size() < kMaxTailLineBytes) {
                line.push_back(c);
            } else {
                overlong = true;
            }
        }
    }
    if (overlong) ++out.omittedLines;
    else if (!line.empty()) out.EmitLine(line);
    return true;
}

/* ---- staging of one entry ---- */

struct Staging {
    bool dryRun = false;
    bool committed = false;
    std::wstring outDirWide;
    std::vector<FILE*> files;
    std::vector<HANDLE> directories;

    ~Staging() {
        if (!committed) Cleanup();
        for (FILE* file : files) std::fclose(file);
        for (HANDLE directory : directories) CloseHandle(directory);
    }

    bool BindDirectories(std::string& error) {
        /* Canonical local drive paths only. Pin each ancestor without delete
         * sharing, then inspect the opened object instead of a path precheck. */
        std::wstring requested = outDirWide;
        for (auto& c : requested) if (c == L'/') c = L'\\';
        if (requested.find(L'\0') != std::wstring::npos || requested.compare(0, 2, L"\\\\") == 0) {
            error = "triage: output requires a local drive directory";
            return false;
        }
        DWORD needed = GetFullPathNameW(requested.c_str(), 0, nullptr, nullptr);
        if (!needed) return false;
        std::vector<wchar_t> full(needed + 1);
        DWORD length = GetFullPathNameW(requested.c_str(), static_cast<DWORD>(full.size()), full.data(), nullptr);
        if (!length || length >= full.size()) return false;
        outDirWide.assign(full.data(), length);
        while (outDirWide.size() > 3 && outDirWide.back() == L'\\') outDirWide.pop_back();
        if (outDirWide.size() <= 3 || outDirWide[1] != L':' || outDirWide[2] != L'\\' ||
            outDirWide.find(L':', 2) != std::wstring::npos) {
            error = "triage: invalid local output directory";
            return false;
        }
        size_t end = 3;
        for (;;) {
            std::wstring path = outDirWide.substr(0, end);
            HANDLE directory = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
            if (directory == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_NOT_FOUND) {
                /* Pin the owner to the token user so the created directory
                 * matches the owner-pinned files written inside it. */
                std::string sdError;
                PSECURITY_DESCRIPTOR descriptor =
                    CreateOwnerPinnedDescriptor(L"D:P(A;OICI;FA;;;OW)",
                                                sdError);
                if (descriptor == nullptr) return false;
                SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor, FALSE};
                BOOL created = CreateDirectoryW(path.c_str(), &attributes);
                DWORD code = GetLastError();
                LocalFree(descriptor);
                if (!created && code != ERROR_ALREADY_EXISTS) {
                    error = LastErrorText("cannot create output directory", code);
                    return false;
                }
                directory = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
            }
            if (directory == INVALID_HANDLE_VALUE) {
                error = LastErrorText("cannot bind output directory", GetLastError());
                return false;
            }
            directories.push_back(directory);
            BY_HANDLE_FILE_INFORMATION info{};
            if (!GetFileInformationByHandle(directory, &info) ||
                !(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
                (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
                error = "triage: output ancestor is not an ordinary directory";
                return false;
            }
            if (end == outDirWide.size()) break;
            size_t next = outDirWide.find(L'\\', end == 3 ? end : end + 1);
            end = next == std::wstring::npos ? outDirWide.size() : next;
        }
        return true;
    }

    void Cleanup() {
        /* Delete exactly the objects we created, while their exclusive
         * handles still prevent name replacement. Never delete by path. */
        for (FILE* file : files) {
            FILE_DISPOSITION_INFO disposition{TRUE};
            SetFileInformationByHandle(reinterpret_cast<HANDLE>(_get_osfhandle(_fileno(file))),
                FileDispositionInfo, &disposition, sizeof(disposition));
            std::fclose(file);
        }
        files.clear();
    }
};

/* Produce one entry. Returns false (with |error|) on a hard failure that
 * must abort the export. Missing inputs just fill |meta| with missing=true. */
bool ProduceEntry(const TriageOptions& opts, const std::string& srcPath,
                  int kind, const char* outName, Staging& staging,
                  EntryMeta& meta, std::string& error) {
    meta.name = outName;
    meta.kind = kind;
    meta.missing = true;

    if (srcPath.empty()) return true; /* caller gave no path: missing */
    std::wstring srcWide = Utf8ToWide(srcPath);
    if (!FileExists(srcWide)) {
        const DWORD code = GetLastError();
        meta.reason = (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND)
            ? "not_found" : "unreadable";
        return true;
    }

    if (kind == 2) {
        /* --- tail of a JSONL ledger (streamed, two passes) --- */
        HANDLE h = OpenReadShared(srcWide);
        if (h == INVALID_HANDLE_VALUE) { meta.reason = "unreadable"; return true; }
        LARGE_INTEGER size{};
        if (!GetFileSizeEx(h, &size) || size.QuadPart < 0) {
            CloseHandle(h);
            error = LastErrorText("cannot stat ledger", GetLastError());
            return false;
        }
        uint64_t snapshotBytes = (uint64_t)size.QuadPart;
        uint64_t total = 0, tailStart = 0;
        if (!ScanLineCount(h, snapshotBytes, opts.tailLines, total, tailStart)) {
            CloseHandle(h);
            error = "cannot scan ledger lines: " + srcPath;
            return false;
        }
        meta.sourceLines = total;
        EntryOut out;
        out.dry = staging.dryRun;
        if (!staging.dryRun) {
            std::wstring tmp = staging.outDirWide + L"\\" + Utf8ToWide(outName) +
                               L".tmp";
            out.file = OpenWriteTmp(tmp);
            if (!out.file) {
                CloseHandle(h);
                error = LastErrorText("cannot create staging file", GetLastError());
                return false;
            }
            staging.files.push_back(out.file);
        }
        bool streamed = StreamTail(h, snapshotBytes, tailStart, out);
        if (out.file && (std::ferror(out.file) || std::fflush(out.file) != 0)) streamed = false;
        CloseHandle(h);
        if (!streamed) {
            error = "cannot copy ledger tail: " + srcPath;
            return false;
        }
        meta.sha256 = out.sha.FinishHex();
        meta.bytes = out.bytes;
        meta.lines = out.lines;
        meta.missing = false;
        meta.omittedLines = out.omittedLines;
        meta.reason = out.omittedLines ? "overlong_lines_omitted" :
            total > out.lines ? "tail_window" : "";
        if (meta.sha256.empty()) { error = "cannot hash ledger tail"; return false; }
        return true;
    }

    /* --- verbatim copy (config) / summary (rules): whole-file reads --- */
    std::string content;
    std::string readError;
    if (!ReadWholeFileCapped(srcWide, content, readError)) {
        /* Unreadable-in-principle inputs are reported as missing so a
         * permission problem on one input does not kill the pack; only
         * the >64MiB cap is a hard error because silently truncating
         * evidence would be worse. */
        if (readError.find("whole-read cap") == std::string::npos) {
            meta.reason = "unreadable";
            return true;
        }
        error = readError;
        return false;
    }

    if (kind == 0) {
        if (content.compare(0, 3, "\xEF\xBB\xBF") == 0) content.erase(0, 3);
        /* Invalid config must never fall back to a verbatim secret copy. */
        try {
            bool quoted = false, escaped = false;
            unsigned depth = 0;
            for (char c : content) {
                if (quoted) {
                    if (escaped) escaped = false;
                    else if (c == '\\') escaped = true;
                    else if (c == '"') quoted = false;
                } else if (c == '"') quoted = true;
                else if (c == '{' || c == '[') {
                    if (++depth > 64) throw std::runtime_error("configuration nesting exceeds export limit");
                } else if ((c == '}' || c == ']') && depth) --depth;
            }
            const auto value = jsonlite::parse(content);
            if (value.type != jsonlite::Type::Object) throw std::runtime_error("configuration must be an object");
            content = RedactedJson(value) + '\n';
        } catch (const std::exception&) {
            error = "triage: cannot safely redact configuration";
            return false;
        }
        meta.sha256 = Sha256HexBuffer(content);
        meta.bytes = content.size();
        meta.lines = LineCountForBuffer(content);
        meta.missing = false;
        meta.reason = "redacted";
    } else {
        /* rules_summary.json: {count, parse_ok, sha256 of the full file} */
        bool parseOk = false;
        size_t count = CountRulesInRulesFile(content, parseOk);
        std::string summary = "{\"count\": " + std::to_string(count) +
                              ", \"parse_ok\": " + (parseOk ? "true" : "false") +
                              ", \"sha256\": \"" + Sha256HexBuffer(content) +
                              "\"}\n";
        meta.sha256 = Sha256HexBuffer(summary);
        meta.bytes = summary.size();
        meta.lines = 1;
        meta.missing = false;
        meta.reason = "summary";
        content = summary; /* stage the summary, not the rules file */
    }

    if (meta.sha256.empty()) { error = "cannot hash pack entry"; return false; }
    if (!staging.dryRun) {
        std::wstring tmp = staging.outDirWide + L"\\" + Utf8ToWide(outName) +
                           L".tmp";
        FILE* f = OpenWriteTmp(tmp);
        if (!f) {
            error = LastErrorText("cannot create staging file", GetLastError());
            return false;
        }
        staging.files.push_back(f);
        size_t written = std::fwrite(content.data(), 1, content.size(), f);
        bool flushOk = (std::fflush(f) == 0);
        if (written != content.size() || !flushOk) {
            error = "short write while staging " + std::string(outName);
            return false;
        }
    }
    return true;
}

/* ---- outDir preparation ---- */

/* Output names are fixed by the pack layout. */
std::vector<std::string> OutputFileNames() {
    return {kConfigName, kRulesName, kAlertsName, kIncidentsName,
            kResponseName, kManifestName};
}

bool PrepareOutDir(const TriageOptions& opts,
                   const std::set<std::string>& inputBasenames,
                   std::wstring& dirWideOut, std::string& error) {
    if (dirWideOut.empty()) {
        error = "triage: outDir must be specified";
        return false;
    }
    DWORD attrs = GetFileAttributesW(dirWideOut.c_str());
    if (!(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        error = "triage: output path exists and is not a directory: " +
                opts.outDir;
        return false;
    }
    std::vector<std::string> outputs = OutputFileNames();
    for (const std::string& name : ListDirNames(dirWideOut)) {
        bool isOutput = false;
        for (const std::string& o : outputs) {
            if (_stricmp(name.c_str(), o.c_str()) == 0 ||
                _stricmp(name.c_str(), (o + ".tmp").c_str()) == 0) { isOutput = true; break; }
        }
        if (isOutput) {
            error = "triage: refusing to overwrite existing pack file '" +
                    name + "' in " + opts.outDir;
            return false;
        }
        if (inputBasenames.count(name)) continue; /* input ledgers live here */
        error = "triage: output directory exists and is not empty: " +
                opts.outDir + " (found '" + name + "')";
        return false;
    }
    return true;
}

/* ---- dry-run report ---- */

void PrintDryRun(const TriageOptions& opts,
                 const std::vector<EntryMeta>& entries) {
    std::printf("[triage] dry-run: no files written\n");
    std::printf("[triage] outDir: %s\n", opts.outDir.c_str());
    std::printf("[triage] tail_lines: %zu\n", opts.tailLines);
    for (const EntryMeta& e : entries) {
        if (e.missing) {
            std::printf("[triage] %s: missing (not collected)\n", e.name.c_str());
            continue;
        }
        if (e.kind == 2) {
            std::printf("[triage] %s: tail %llu/%llu lines, %llu bytes, "
                        "sha256=%s\n",
                        e.name.c_str(), (unsigned long long)e.lines,
                        (unsigned long long)e.sourceLines,
                        (unsigned long long)e.bytes, e.sha256.c_str());
        } else if (e.kind == 1) {
            std::printf("[triage] %s: summary, %llu bytes, sha256=%s\n",
                        e.name.c_str(), (unsigned long long)e.bytes,
                        e.sha256.c_str());
        } else {
            std::printf("[triage] %s: redacted config, %llu bytes, %llu lines, "
                        "sha256=%s\n",
                        e.name.c_str(), (unsigned long long)e.bytes,
                        (unsigned long long)e.lines, e.sha256.c_str());
        }
    }
    std::printf("[triage] manifest.json:\n%s",
                BuildManifestJson(entries, opts.tailLines).c_str());
    std::fflush(stdout);
}

} /* namespace */

int WriteTriagePack(const TriageOptions& opts, bool dryRun, std::string& error) {
    error.clear();

    if (opts.outDir.empty()) {
        error = "triage: outDir must be specified";
        return 1;
    }
    if (opts.tailLines < kTailLinesMin || opts.tailLines > kTailLinesMax) {
        error = "triage: tailLines out of range (100..100000): " +
                std::to_string(opts.tailLines);
        return 1;
    }

    /* Input basenames tolerated in an existing outDir (lets --out point at
     * the directory that already holds the ledgers). */
    std::set<std::string> inputBasenames;
    const std::string* inputs[] = {&opts.configPath, &opts.rulesPath,
                                   &opts.alertsPath, &opts.incidentsPath,
                                   &opts.responseAuditPath};
    for (const std::string* p : inputs) {
        if (!p->empty()) inputBasenames.insert(BasenameUtf8(*p));
    }

    Staging staging;
    staging.dryRun = dryRun;
    if (!dryRun) {
        staging.outDirWide = Utf8ToWide(opts.outDir);
        if (!staging.BindDirectories(error)) return 1;
        if (!PrepareOutDir(opts, inputBasenames, staging.outDirWide, error))
            return 1;
    } else {
        staging.outDirWide = Utf8ToWide(opts.outDir);
    }

    struct Plan {
        const char* name;
        const std::string* src;
        int kind; /* 0 copy, 1 rules summary, 2 tail */
    };
    const Plan plans[] = {
        {kConfigName, &opts.configPath, 0},
        {kRulesName, &opts.rulesPath, 1},
        {kAlertsName, &opts.alertsPath, 2},
        {kIncidentsName, &opts.incidentsPath, 2},
        {kResponseName, &opts.responseAuditPath, 2},
    };

    std::vector<EntryMeta> entries;
    for (const Plan& plan : plans) {
        EntryMeta meta;
        if (!ProduceEntry(opts, *plan.src, plan.kind, plan.name, staging, meta,
                          error)) {
            staging.Cleanup();
            return 1;
        }
        entries.push_back(meta);
        if (!dryRun && !meta.missing) {
            /* Stage -> rename immediately; manifest comes after the loop. */
            std::wstring finalPath = staging.outDirWide + L"\\" +
                                     Utf8ToWide(plan.name);
            if (!RenameTmpToFinal(staging.files.back(), finalPath)) {
                error = LastErrorText(
                    ("cannot finalize " + std::string(plan.name)).c_str(),
                    GetLastError());
                staging.Cleanup();
                return 1;
            }
        }
    }

    if (dryRun) {
        PrintDryRun(opts, entries);
        staging.committed = true;
        return 0;
    }

    /* manifest.json LAST: a pack directory without it is an interrupted
     * export (documented in triage_pack.h). */
    std::string manifest = BuildManifestJson(entries, opts.tailLines);
    std::wstring tmp = staging.outDirWide + L"\\manifest.json.tmp";
    FILE* f = OpenWriteTmp(tmp);
    if (!f) {
        error = LastErrorText("cannot create manifest staging file",
                              GetLastError());
        staging.Cleanup();
        return 1;
    }
    staging.files.push_back(f);
    size_t written = std::fwrite(manifest.data(), 1, manifest.size(), f);
    bool flushOk = (std::fflush(f) == 0);
    if (written != manifest.size() || !flushOk) {
        error = "short write while staging manifest.json";
        staging.Cleanup();
        return 1;
    }
    std::wstring finalPath = staging.outDirWide + L"\\manifest.json";
    if (!RenameTmpToFinal(f, finalPath)) {
        error = LastErrorText("cannot finalize manifest.json", GetLastError());
        staging.Cleanup();
        return 1;
    }
    staging.committed = true;
    return 0;
}

} // namespace edr
