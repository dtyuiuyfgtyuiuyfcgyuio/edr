#include "alerter.h"

#include <windows.h>
#include <aclapi.h>
#include <bcrypt.h>

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <fstream>
#include <limits>
#include <sstream>
#include <vector>

#include "config.h"
#include "json_lite.h"

namespace edr {

static constexpr size_t kMaxAlertLedgerLineBytes = 16u * 1024u * 1024u;

// ---------- hash-chain helpers (SHA-256 via BCrypt) ----------
static std::string Sha256Hex(const std::string& text) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE h = nullptr;
    DWORD objLen = 0, ret = 0;
    std::vector<unsigned char> obj;
    unsigned char digest[32] = {};
    NTSTATUS st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (st >= 0) st = BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &ret, 0);
    if (st >= 0) { obj.resize(objLen); st = BCryptCreateHash(alg, &h, obj.data(), objLen, nullptr, 0, 0); }
    if (st >= 0) st = BCryptHashData(h, (PUCHAR)text.data(), (ULONG)text.size(), 0);
    if (st >= 0) st = BCryptFinishHash(h, digest, sizeof(digest), 0);
    if (h) BCryptDestroyHash(h);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    if (st < 0) return std::string(64, '0');
    static const char hex[] = "0123456789abcdef";
    std::string out; out.resize(64);
    for (size_t i = 0; i < 32; ++i) { out[i*2]=hex[digest[i]>>4]; out[i*2+1]=hex[digest[i]&15]; }
    return out;
}
static std::string ChainHashFor(uint64_t seq, const std::string& prev, const std::string& payloadHash) {
    std::string canon = std::to_string(seq) + "|" + prev + "|" + payloadHash;
    return Sha256Hex(canon);
}
static std::string StableJson(const jsonlite::Value& v) {
    switch(v.type){
        case jsonlite::Type::Null: return "null";
        case jsonlite::Type::Bool: return v.boolean?"true":"false";
        case jsonlite::Type::Number: { double n=v.number; if(std::floor(n)==n) return std::to_string((long long)n); char buf[64]; std::snprintf(buf,sizeof(buf),"%.15g",n); return std::string(buf); }
        case jsonlite::Type::String: return "\""+jsonlite::escape(v.str)+"\"";
        case jsonlite::Type::Array: { std::string s="["; for(size_t i=0;i<v.array.size();++i){ if(i) s+=","; s+=StableJson(v.array[i]); } s+="]"; return s; }
        case jsonlite::Type::Object: { std::string s="{"; bool first=true; for(auto &kv: v.object){ if(!first) s+=","; first=false; s+="\""+jsonlite::escape(kv.first)+"\""+":"+StableJson(kv.second); } s+="}"; return s; }
    }
    return "null";
}
static bool IsHexDigest(const std::string& value) {
    if (value.size() != 64) return false;
    for (unsigned char ch : value) {
        if (!((ch >= '0' && ch <= '9') ||
              (ch >= 'a' && ch <= 'f') ||
              (ch >= 'A' && ch <= 'F'))) return false;
    }
    return true;
}

static bool ResumeChainFromFile(const std::string& path, uint64_t& seqOut,
                                std::string& prevOut) {
    seqOut = 0; prevOut = std::string(64, '0');
    std::ifstream in(path, std::ios::binary);
    if (!in) return true; /* Open() will create a missing ledger. */

    /* Validate every record before appending. The old tail-only recovery could
     * skip a forged prefix and continue from an attacker-controlled hash.
     * Unchained records are accepted only as a contiguous legacy prefix; once
     * a chain starts, every following record must carry and verify all fields. */
    std::string line;
    uint64_t expectedSeq = 1;
    std::string expectedPrev(64, '0');
    bool chained = false;
    while (std::getline(in, line)) {
        if (in.eof()) return false; /* deterministic partial final line */
        if (!line.empty() && line.back()=='\r') line.pop_back();
        if (line.empty()) return false;
        try {
            auto v = jsonlite::parse(line);
            if (v.type != jsonlite::Type::Object) return false;
            const auto* cs = v.find("chain_seq");
            const auto* cp = v.find("chain_prev");
            const auto* ch = v.find("chain_hash");
            const bool hasChain = cs || cp || ch;
            if (!hasChain) {
                if (chained) return false; /* mixed legacy/chained history */
                continue;
            }
            if (!cs || !cp || !ch ||
                cs->type != jsonlite::Type::Number ||
                cp->type != jsonlite::Type::String ||
                ch->type != jsonlite::Type::String ||
                !std::isfinite(cs->number) || std::floor(cs->number) != cs->number ||
                cs->number < 1.0 || cs->number > static_cast<double>(std::numeric_limits<uint64_t>::max()) ||
                cp->str != expectedPrev || !IsHexDigest(cp->str) || !IsHexDigest(ch->str)) {
                return false;
            }
            const uint64_t seq = static_cast<uint64_t>(cs->number);
            if (seq != expectedSeq) return false;
            const std::string chainHash = ch->str;
            v.object.erase("chain_seq");
            v.object.erase("chain_prev");
            v.object.erase("chain_hash");
            const std::string payloadHash = Sha256Hex(StableJson(v));
            if (ChainHashFor(seq, expectedPrev, payloadHash) != chainHash) return false;
            chained = true;
            expectedPrev = chainHash;
            if (expectedSeq == std::numeric_limits<uint64_t>::max()) return false;
            ++expectedSeq;
        } catch (...) {
            return false;
        }
    }
    if (in.bad()) return false;
    if (chained) {
        seqOut = expectedSeq - 1;
        prevOut = expectedPrev;
    }
    return true;
}

static bool ResumeChainFromHandle(HANDLE file, uint64_t& seqOut,
                                  std::string& prevOut) {
    seqOut = 0;
    prevOut = std::string(64, '0');
    LARGE_INTEGER beginning = {};
    if (!SetFilePointerEx(file, beginning, nullptr, FILE_BEGIN)) return false;

    uint64_t expectedSeq = 1;
    std::string expectedPrev(64, '0');
    bool chained = false;
    std::string pending;
    auto consumeLine = [&](std::string line) -> bool {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) return false;
        try {
            auto v = jsonlite::parse(line);
            if (v.type != jsonlite::Type::Object) return false;
            const auto* cs = v.find("chain_seq");
            const auto* cp = v.find("chain_prev");
            const auto* ch = v.find("chain_hash");
            const bool hasChain = cs || cp || ch;
            if (!hasChain) return !chained;
            if (!cs || !cp || !ch ||
                cs->type != jsonlite::Type::Number ||
                cp->type != jsonlite::Type::String ||
                ch->type != jsonlite::Type::String ||
                !std::isfinite(cs->number) || std::floor(cs->number) != cs->number ||
                cs->number < 1.0 ||
                cs->number > static_cast<double>(std::numeric_limits<uint64_t>::max()) ||
                cp->str != expectedPrev || !IsHexDigest(cp->str) ||
                !IsHexDigest(ch->str)) return false;
            const uint64_t seq = static_cast<uint64_t>(cs->number);
            if (seq != expectedSeq) return false;
            const std::string chainHash = ch->str;
            v.object.erase("chain_seq");
            v.object.erase("chain_prev");
            v.object.erase("chain_hash");
            if (ChainHashFor(seq, expectedPrev, Sha256Hex(StableJson(v))) != chainHash)
                return false;
            chained = true;
            expectedPrev = chainHash;
            if (expectedSeq == std::numeric_limits<uint64_t>::max()) return false;
            ++expectedSeq;
            return true;
        } catch (...) {
            return false;
        }
    };

    char block[64 * 1024];
    for (;;) {
        DWORD bytesRead = 0;
        if (!ReadFile(file, block, sizeof(block), &bytesRead, nullptr)) return false;
        if (bytesRead == 0) break;
        for (DWORD i = 0; i < bytesRead; ++i) {
            if (block[i] == '\n') {
                if (!consumeLine(std::move(pending))) return false;
                pending.clear();
            } else {
                pending.push_back(block[i]);
                if (pending.size() > kMaxAlertLedgerLineBytes) return false;
            }
        }
    }
    /* A trailing fragment is not a durable JSONL record and cannot be
     * safely extended. */
    if (!pending.empty()) return false;
    if (chained) {
        seqOut = expectedSeq - 1;
        prevOut = expectedPrev;
    }
    return true;
}

static HANDLE OpenProtectedAlertsLedger(const std::string& path,
                                        std::string& error) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        error = "OpenProcessToken failed while securing alert ledger";
        return INVALID_HANDLE_VALUE;
    }
    DWORD tokenBytes = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &tokenBytes);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || tokenBytes == 0) {
        CloseHandle(token);
        error = "could not query alert ledger owner identity";
        return INVALID_HANDLE_VALUE;
    }
    std::vector<unsigned char> tokenData(tokenBytes);
    if (!GetTokenInformation(token, TokenUser, tokenData.data(), tokenBytes,
                             &tokenBytes)) {
        CloseHandle(token);
        error = "could not read alert ledger owner identity";
        return INVALID_HANDLE_VALUE;
    }
    const PSID userSid = reinterpret_cast<TOKEN_USER*>(tokenData.data())->User.Sid;

    EXPLICIT_ACCESSW grant = {};
    grant.grfAccessPermissions = FILE_ALL_ACCESS;
    grant.grfAccessMode = SET_ACCESS;
    grant.grfInheritance = NO_INHERITANCE;
    BuildTrusteeWithSidW(&grant.Trustee, userSid);
    PACL dacl = nullptr;
    DWORD rc = SetEntriesInAclW(1, &grant, nullptr, &dacl);
    if (rc != ERROR_SUCCESS) {
        CloseHandle(token);
        error = "SetEntriesInAclW failed with error " + std::to_string(rc);
        return INVALID_HANDLE_VALUE;
    }

    std::wstring widePath = Utf8ToWide(path);
    if (widePath.empty()) {
        LocalFree(dacl);
        CloseHandle(token);
        error = "alert ledger path is not valid UTF-8";
        return INVALID_HANDLE_VALUE;
    }

    SECURITY_DESCRIPTOR securityDescriptor = {};
    BOOL descriptorOk = InitializeSecurityDescriptor(
        &securityDescriptor, SECURITY_DESCRIPTOR_REVISION) &&
        SetSecurityDescriptorOwner(&securityDescriptor, userSid, FALSE) &&
        SetSecurityDescriptorDacl(&securityDescriptor, TRUE, dacl, FALSE) &&
        SetSecurityDescriptorControl(&securityDescriptor,
            SE_DACL_PROTECTED, SE_DACL_PROTECTED);
    if (!descriptorOk) {
        LocalFree(dacl);
        CloseHandle(token);
        error = "could not prepare protected alert ledger security descriptor";
        return INVALID_HANDLE_VALUE;
    }
    SECURITY_ATTRIBUTES attributes = {};
    attributes.nLength = sizeof(attributes);
    attributes.lpSecurityDescriptor = &securityDescriptor;

    HANDLE file = CreateFileW(widePath.c_str(),
        GENERIC_READ | FILE_APPEND_DATA | READ_CONTROL | WRITE_DAC | WRITE_OWNER,
        FILE_SHARE_READ, &attributes, OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        const DWORD createError = GetLastError();
        LocalFree(dacl);
        CloseHandle(token);
        error = "CreateFileW for alert ledger failed with error " +
                std::to_string(createError);
        return INVALID_HANDLE_VALUE;
    }

    BY_HANDLE_FILE_INFORMATION fileInfo = {};
    if (!GetFileInformationByHandle(file, &fileInfo)) {
        const DWORD infoError = GetLastError();
        LocalFree(dacl);
        CloseHandle(file);
        CloseHandle(token);
        error = "could not inspect alert ledger handle (error " +
                std::to_string(infoError) + ")";
        return INVALID_HANDLE_VALUE;
    }
    if ((fileInfo.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT |
                                      FILE_ATTRIBUTE_DIRECTORY)) != 0) {
        LocalFree(dacl);
        CloseHandle(file);
        CloseHandle(token);
        error = "alert ledger must be a regular non-reparse file";
        return INVALID_HANDLE_VALUE;
    }

    rc = SetSecurityInfo(file, SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION |
            PROTECTED_DACL_SECURITY_INFORMATION,
        userSid, nullptr, dacl, nullptr);
    if (rc != ERROR_SUCCESS) {
        LocalFree(dacl);
        CloseHandle(file);
        CloseHandle(token);
        error = "SetSecurityInfo for alert ledger failed with error " +
                std::to_string(rc);
        return INVALID_HANDLE_VALUE;
    }

    LocalFree(dacl);
    PSID owner = nullptr;
    PACL actualDacl = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    rc = GetSecurityInfo(file, SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &owner, nullptr, &actualDacl, nullptr, &descriptor);
    bool verified = rc == ERROR_SUCCESS && owner != nullptr &&
                    actualDacl != nullptr && EqualSid(owner, userSid);
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    if (verified) {
        verified = GetSecurityDescriptorControl(descriptor, &control, &revision) &&
                   (control & SE_DACL_PROTECTED) != 0;
    }
    ACL_SIZE_INFORMATION aclInfo = {};
    if (verified) {
        verified = GetAclInformation(actualDacl, &aclInfo, sizeof(aclInfo),
                                     AclSizeInformation) &&
                   aclInfo.AceCount == 1;
    }
    void* ace = nullptr;
    if (verified) {
        verified = GetAce(actualDacl, 0, &ace) != FALSE && ace != nullptr;
    }
    if (verified) {
        const auto* allowed = static_cast<const ACCESS_ALLOWED_ACE*>(ace);
        verified = allowed->Header.AceType == ACCESS_ALLOWED_ACE_TYPE &&
                   EqualSid(const_cast<DWORD*>(&allowed->SidStart), userSid) &&
                   (allowed->Mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS;
    }
    if (descriptor) LocalFree(descriptor);
    CloseHandle(token);
    if (!verified) {
        CloseHandle(file);
        error = "alert ledger owner-only protected ACL verification failed";
        return INVALID_HANDLE_VALUE;
    }
    return file;
}

static std::string FileTimeToIso8601(uint64_t value) {
    FILETIME ft = {static_cast<DWORD>(value), static_cast<DWORD>(value >> 32)};
    SYSTEMTIME st = {};
    if (!FileTimeToSystemTime(&ft, &st)) return "1970-01-01T00:00:00.000Z";
    char result[32] = {};
    std::snprintf(result, sizeof(result), "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
                  st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute,
                  st.wSecond, st.wMilliseconds);
    return result;
}

static uint64_t EventFingerprint(const Event& event, bool redact) {
    uint64_t hash = 1469598103934665603ULL;
    auto add = [&](const std::string& value) {
        for (unsigned char ch : value) {
            hash ^= ch;
            hash *= 1099511628211ULL;
        }
    };
    add(event.source);
    add(std::to_string(event.type));
    add(std::to_string(event.ts100ns));
    add(std::to_string(event.pid));
    add(event.processIdentity);
    for (const auto& field : event.fields) {
        add(field.first);
        if (redact && field.first == field::kScriptBlockText) {
            add("[redacted]");
        } else if (redact && field.first == field::kCommandLine) {
            add(Alerter::Redact(field.second));
        } else {
            add(field.second);
        }
    }
    return hash;
}

std::string Alerter::Redact(const std::string& text) {
    /* Mask password/token-style assignments and -enc/-e encoded payloads. */
    static const char* keys[] = {
        "password", "passwd", "pwd", "token", "secret", "apikey", "api_key"
    };
    std::string out = text;

    for (const char* key : keys) {
        std::string lower;
        lower.reserve(out.size());
        for (char c : out) {
            lower.push_back((char)tolower((unsigned char)c));
        }
        size_t pos = 0;
        std::string needle = std::string(key) + "=";
        std::string needle2 = std::string(key) + ":";
        while (true) {
            size_t hit = lower.find(needle, pos);
            size_t skip = needle.size();
            if (hit == std::string::npos) {
                hit = lower.find(needle2, pos);
                skip = needle2.size();
            }
            if (hit == std::string::npos) {
                break;
            }
            size_t start = hit + skip;
            size_t end = start;
            while (end < out.size() && out[end] != ' ' && out[end] != '\t' &&
                   out[end] != '"' && out[end] != '\'') {
                end++;
            }
            out.replace(start, end - start, "***");
            lower.replace(start, end - start, "***");
            pos = start + 3;
        }
    }

    /* "-enc <blob>" / "-ec <blob>" style PowerShell payloads. */
    std::string lower;
    lower.reserve(out.size());
    for (char c : out) {
        lower.push_back((char)tolower((unsigned char)c));
    }
    size_t pos = 0;
    while ((pos = lower.find("-enc", pos)) != std::string::npos) {
        size_t p = pos + 4;
        while (p < lower.size() && (lower[p] == ' ' || lower[p] == '\t')) p++;
        size_t end = p;
        while (end < lower.size() && lower[end] != ' ' && lower[end] != '\t') end++;
        if (end > p) {
            out.replace(p, end - p, "***");
            lower.replace(p, end - p, "***");
        }
        pos = p + 3;
    }
    return out;
}

std::string AlertToJsonLine(const Alert& alert, bool redact) {
    const Event& ev = *alert.event;
    std::string line = "{\"rule\":\"";
    line += jsonlite::escape(alert.ruleId);
    line += "\",\"severity\":\"";
    line += jsonlite::escape(alert.severity);
    line += "\",\"action\":\"";
    line += jsonlite::escape(alert.action);
    line += "\",\"ts_100ns\":";
    line += std::to_string(ev.ts100ns);
    line += ",\"pid\":";
    line += std::to_string(ev.pid);
    line += ",\"type\":\"";
    line += EventTypeName(ev.type);
    line += "\",\"fields\":{";
    bool first = true;
    for (const auto& kv : ev.fields) {
        if (!first) {
            line += ",";
        }
        first = false;
        std::string value = kv.second;
        if (redact && kv.first == field::kScriptBlockText) {
            value = "[redacted]";
        } else if (redact && kv.first == field::kCommandLine) {
            value = Alerter::Redact(value);
        }
        line += "\"";
        line += jsonlite::escape(kv.first);
        line += "\":\"";
        line += jsonlite::escape(value);
        line += "\"";
    }
    line += "}";
    if (!alert.mitreAttack.empty()) {
        line += ",\"mitre_attack\":[";
        bool maFirst = true;
        for (const auto& entry : alert.mitreAttack) {
            if (!maFirst) line += ",";
            maFirst = false;
            line += "\"";
            line += jsonlite::escape(entry);
            line += "\"";
        }
        line += "]";
    }
    if (!alert.mitreTactic.empty()) {
        line += ",\"mitre_tactic\":[";
        bool mtFirst = true;
        for (const auto& entry : alert.mitreTactic) {
            if (!mtFirst) line += ",";
            mtFirst = false;
            line += "\"";
            line += jsonlite::escape(entry);
            line += "\"";
        }
        line += "]";
    }
    line += "}";
    return line;
}

std::string EventToJsonLine(const Event& ev, bool redact) {
    std::string line = "{\"eventId\":\"" +
        std::to_string(EventFingerprint(ev, redact));
    line += "\",\"type\":\"" + std::string(EventTypeName(ev.type));
    line += "\",\"timestamp\":\"" + FileTimeToIso8601(ev.ts100ns);
    line += "\",\"ts_100ns\":\"" + std::to_string(ev.ts100ns);
    line += "\",\"source\":\"" + jsonlite::escape(ev.source);
    line += "\",\"pid\":" + std::to_string(ev.pid);
    line += ",\"ppid\":" + std::to_string(ev.ppid);
    if (!ev.processIdentity.empty())
        line += ",\"process_guid\":\"" + jsonlite::escape(ev.processIdentity) + "\"";
    if (!ev.parentProcessIdentity.empty())
        line += ",\"parent_process_guid\":\"" + jsonlite::escape(ev.parentProcessIdentity) + "\"";
    if (ev.processStartTime100ns != 0)
        line += ",\"start_time\":\"" + std::to_string(ev.processStartTime100ns) + "\"";
    line += ",\"fields\":{";
    bool first = true;
    for (const auto& kv : ev.fields) {
        if (!first) line += ",";
        first = false;
        std::string value = kv.second;
        if (redact && kv.first == field::kScriptBlockText)
            value = "[redacted]";
        else if (redact && kv.first == field::kCommandLine)
            value = Alerter::Redact(value);
        line += "\"" + jsonlite::escape(kv.first) + "\":\"" +
                jsonlite::escape(value) + "\"";
    }
    line += "}}";
    return line;
}

Alerter::Alerter(std::string alertsPath, bool redact, bool useEventLog,
                 AppendFunction appendFunction)
    : m_path(std::move(alertsPath)), m_redact(redact),
      m_useEventLog(useEventLog), m_appendFunction(std::move(appendFunction)) {}

Alerter::~Alerter() {
    Close();
}

bool Alerter::ResumeChain() {
    if (m_appendFunction)
        return ResumeChainFromFile(m_path, m_chainSeq, m_chainPrev);
    return m_fileHandle != nullptr && ResumeChainFromHandle(
        static_cast<HANDLE>(m_fileHandle), m_chainSeq, m_chainPrev);
}

bool Alerter::Open() {
    if (m_opened || m_writeFailed) return false;
    if (!m_appendFunction) {
        std::string openError;
        HANDLE file = OpenProtectedAlertsLedger(m_path, openError);
        if (file == INVALID_HANDLE_VALUE) {
            m_writeFailed = true;
            m_lastWriteError = std::move(openError);
            return false;
        }
        m_fileHandle = file;
    }
    if (!ResumeChain()) {
        if (m_fileHandle != nullptr) {
            CloseHandle(static_cast<HANDLE>(m_fileHandle));
            m_fileHandle = nullptr;
        }
        m_writeFailed = true;
        m_lastWriteError = "alert ledger history validation failed";
        return false;
    }
    if (m_useEventLog) {
        HANDLE h = RegisterEventSourceW(nullptr, L"EDR-Agent");
        m_eventSource = (void*)h; /* may be NULL: not fatal */
    }
    m_opened = true;
    return true;
}

Alerter::WriteStatus Alerter::GetWriteStatus() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    WriteStatus status;
    status.writable = m_opened && !m_writeFailed;
    status.writeFailures = m_writeFailures;
    status.chainSequence = m_chainSeq;
    status.lastError = m_lastWriteError;
    return status;
}

void Alerter::SetSink(std::function<void(const std::string& alertJson)> sink) {
    m_sink = std::move(sink);
}

void Alerter::OnAlert(const Alert& alert) {
    std::string base = AlertToJsonLine(alert, m_redact);
    std::string line;
    bool persisted = false;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_opened && !m_writeFailed) {
            /* A partial prior append can leave a malformed JSONL tail. Never
             * extend that file or represent a later alert as persisted. */
        uint64_t seq = m_chainSeq + 1;
        std::string prev = m_chainPrev;
        std::string payloadHash;
        try{ auto pv=jsonlite::parse(base); payloadHash=Sha256Hex(StableJson(pv)); } catch(...){ payloadHash=Sha256Hex(base); }
        std::string ch = ChainHashFor(seq, prev, payloadHash);
        // inject chain fields before final '}'
        if (!base.empty() && base.back() == '}') {
            line = base.substr(0, base.size()-1) + ",\"chain_seq\":" + std::to_string(seq) + ",\"chain_prev\":\"" + prev + "\",\"chain_hash\":\"" + ch + "\"}";
        } else {
            line = base;
        }
        std::string appendError;
        bool appendOk = false;
        if (m_appendFunction) {
            try {
                appendOk = m_appendFunction(line, appendError);
            } catch (const std::exception& ex) {
                appendError = std::string("alert ledger append threw: ") + ex.what();
            } catch (...) {
                appendError = "alert ledger append threw an unknown exception";
            }
        } else if (m_fileHandle != nullptr) {
            std::string record = line + "\n";
            if (record.size() > MAXDWORD) {
                appendError = "alert ledger record exceeds the Windows write limit";
            } else {
                DWORD bytesWritten = 0;
                const DWORD bytesToWrite = static_cast<DWORD>(record.size());
                HANDLE file = static_cast<HANDLE>(m_fileHandle);
                if (!WriteFile(file, record.data(), bytesToWrite,
                               &bytesWritten, nullptr)) {
                    appendError = "alert ledger WriteFile failed with error " +
                                  std::to_string(GetLastError());
                } else if (bytesWritten != bytesToWrite) {
                    appendError = "alert ledger WriteFile completed a short write";
                } else if (!FlushFileBuffers(file)) {
                    appendError = "alert ledger FlushFileBuffers failed with error " +
                                  std::to_string(GetLastError());
                } else {
                    appendOk = true;
                }
            }
        } else {
            appendError = "alert ledger is not open";
        }
        if (appendOk) {
            /* Commit in-memory chain state only after append and flush have
             * both reported success. */
            m_chainSeq = seq;
            m_chainPrev = ch;
            persisted = true;
            m_lastWriteError.clear();
        } else {
            m_writeFailed = true;
            ++m_writeFailures;
            m_lastWriteError = appendError.empty()
                ? "alert ledger append failed" : std::move(appendError);
        }
        }
    }
    if (m_useEventLog && m_eventSource != nullptr) {
        WriteEventLog(line.empty() ? base : line, alert.severity); /* independent of file write */
    }
    /* Out-of-band sink (webhook): same persisted line, still outside the
     * file mutex so a slow sink cannot block the JSONL writer. Sink
     * failures are contained: the sink runs on the event consumer thread,
     * so a throw must not escape OnAlert; log once, count always. */
    if (persisted && m_sink) {
        try {
            m_sink(line.empty() ? base : line);
        } catch (...) {
            if (m_sinkFailures.fetch_add(1) == 0) {
                std::fprintf(stderr,
                             "[alerter] alert sink threw; further sink errors suppressed (still counted)\n");
            }
        }
    }
}

void Alerter::WriteEventLog(const std::string& line, const std::string& severity) {
    WORD type = EVENTLOG_INFORMATION_TYPE;
    if (severity == "high") {
        type = EVENTLOG_ERROR_TYPE;
    } else if (severity == "medium") {
        type = EVENTLOG_WARNING_TYPE;
    }
    std::wstring wide = Utf8ToWide(line);
    LPCWSTR strings[1] = { wide.c_str() };
    /* Failure is intentionally ignored (non-fatal, non-blocking). */
    ReportEventW((HANDLE)m_eventSource, type, 0, 1000, nullptr, 1, 0,
                 strings, nullptr);
}

void Alerter::Close() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_fileHandle != nullptr) {
        CloseHandle(static_cast<HANDLE>(m_fileHandle));
        m_fileHandle = nullptr;
    }
    m_opened = false;
    if (m_eventSource != nullptr) {
        DeregisterEventSource((HANDLE)m_eventSource);
        m_eventSource = nullptr;
    }
}

} // namespace edr
