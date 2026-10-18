/*
 * incident_store.cpp - Durable incident sink (incidents.jsonl).
 */
#include "incident_store.h"

#include <windows.h>
#include <aclapi.h>
#include <sddl.h>   /* ConvertStringSecurityDescriptorToSecurityDescriptorA */
#include <bcrypt.h>

#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <limits>
#include <sstream>
#include <string>

#include "alerter.h"   /* Alerter::Redact */
#include "owner_only_sd.h"
#include "json_lite.h"

namespace edr {

static std::string Sha256HexIS(const std::string& text) {
    BCRYPT_ALG_HANDLE alg=nullptr; BCRYPT_HASH_HANDLE h=nullptr; DWORD objLen=0,ret=0; std::vector<unsigned char> obj; unsigned char digest[32]={};
    NTSTATUS st=BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,nullptr,0);
    if(st>=0) st=BCryptGetProperty(alg,BCRYPT_OBJECT_LENGTH,(PUCHAR)&objLen,sizeof(objLen),&ret,0);
    if(st>=0){obj.resize(objLen); st=BCryptCreateHash(alg,&h,obj.data(),objLen,nullptr,0,0);}
    if(st>=0) st=BCryptHashData(h,(PUCHAR)text.data(),(ULONG)text.size(),0);
    if(st>=0) st=BCryptFinishHash(h,digest,sizeof(digest),0);
    if(h) BCryptDestroyHash(h); if(alg) BCryptCloseAlgorithmProvider(alg,0);
    if(st<0) return std::string(64,'0');
    static const char hex[]="0123456789abcdef"; std::string out; out.resize(64);
    for(size_t i=0;i<32;++i){out[i*2]=hex[digest[i]>>4]; out[i*2+1]=hex[digest[i]&15];}
    return out;
}
static std::string ChainHashIS(uint64_t seq,const std::string& prev,const std::string& payloadHash){
    return Sha256HexIS(std::to_string(seq)+"|"+prev+"|"+payloadHash);
}
static std::string StableJsonIS(const jsonlite::Value& v){
    switch(v.type){
        case jsonlite::Type::Null: return "null";
        case jsonlite::Type::Bool: return v.boolean?"true":"false";
        case jsonlite::Type::Number: { double n=v.number; if(std::floor(n)==n) return std::to_string((long long)n); char buf[64]; std::snprintf(buf,sizeof(buf),"%.15g",n); return std::string(buf); }
        case jsonlite::Type::String: return "\""+jsonlite::escape(v.str)+"\"";
        case jsonlite::Type::Array: { std::string s="["; for(size_t i=0;i<v.array.size();++i){ if(i) s+=","; s+=StableJsonIS(v.array[i]); } s+="]"; return s; }
        case jsonlite::Type::Object: { std::string s="{"; bool first=true; for(auto &kv: v.object){ if(!first) s+=","; first=false; s+="\""+jsonlite::escape(kv.first)+"\""+":"+StableJsonIS(kv.second); } s+="}"; return s; }
    }
    return "null";
}
static bool IsHexDigestIS(const std::string& value) {
    if (value.size() != 64) return false;
    for (unsigned char ch : value) {
        if (!((ch >= '0' && ch <= '9') ||
              (ch >= 'a' && ch <= 'f') ||
              (ch >= 'A' && ch <= 'F'))) return false;
    }
    return true;
}

static std::string WinErrorIS(const char* operation, DWORD error) {
    return std::string(operation) + " (win32=" + std::to_string(error) + ")";
}

static std::string NormalizeOwnerOnlyDaclSddlIS(const char* sddl) {
    std::string normalized = sddl ? sddl : "";
    /* NTFS can report SE_DACL_AUTO_INHERITED (AI) even when the DACL is
     * protected. It does not add an ACE or permit inheritance while P is set. */
    if (normalized.compare(0, 5, "D:PAI") == 0) {
        normalized.replace(0, 5, "D:P");
    }
    return normalized;
}

static bool ApplyOwnerOnlyDaclIS(HANDLE file, PACL expectedDacl,
                                 DWORD& failureCode, std::string& failureDetail) {
    if (file == INVALID_HANDLE_VALUE || expectedDacl == nullptr) {
        failureCode = ERROR_INVALID_PARAMETER;
        failureDetail = "missing handle or policy DACL";
        return false;
    }
    const SECURITY_INFORMATION securityInfo =
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
    failureCode = SetSecurityInfo(file, SE_FILE_OBJECT, securityInfo, nullptr,
                                  nullptr, expectedDacl, nullptr);
    if (failureCode != ERROR_SUCCESS) {
        failureDetail = "SetSecurityInfo failed";
        return false;
    }

    PACL actualDacl = nullptr;
    PSECURITY_DESCRIPTOR actualDescriptor = nullptr;
    const DWORD queryStatus = GetSecurityInfo(
        file, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr,
        &actualDacl, nullptr, &actualDescriptor);
    if (queryStatus != ERROR_SUCCESS) {
        failureCode = queryStatus;
        failureDetail = "GetSecurityInfo verification failed";
        if (actualDescriptor != nullptr) LocalFree(actualDescriptor);
        return false;
    }

    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    const BOOL controlRead = GetSecurityDescriptorControl(
        actualDescriptor, &control, &revision);
    LPSTR actualSddl = nullptr;
    const BOOL converted = ConvertSecurityDescriptorToStringSecurityDescriptorA(
        actualDescriptor, SDDL_REVISION_1, DACL_SECURITY_INFORMATION,
        &actualSddl, nullptr);
    const std::string normalizedSddl = converted != FALSE && actualSddl != nullptr
        ? NormalizeOwnerOnlyDaclSddlIS(actualSddl) : std::string();
    bool verified = controlRead != FALSE &&
        (control & SE_DACL_PROTECTED) != 0 && actualDacl != nullptr &&
        converted != FALSE && actualSddl != nullptr &&
        normalizedSddl == "D:P(A;;FA;;;OW)";
    if (!verified) {
        failureCode = converted == FALSE || controlRead == FALSE
            ? GetLastError() : ERROR_INVALID_ACL;
        failureDetail = "queried DACL did not match protected owner-only policy";
        if (actualSddl != nullptr) failureDetail += ": " + std::string(actualSddl);
    }
    if (actualSddl != nullptr) LocalFree(actualSddl);
    LocalFree(actualDescriptor);
    return verified;
}

static bool ResumeChainIS(const std::string& path, uint64_t& seqOut,
                          std::string& prevOut) {
    seqOut = 0; prevOut = std::string(64, '0');
    std::ifstream in(path, std::ios::binary);
    if (!in) return true;
    std::string line;
    uint64_t expectedSeq = 1;
    std::string expectedPrev(64, '0');
    bool chained = false;
    while (std::getline(in, line)) {
        if (in.eof()) return false;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) return false;
        try {
            auto v = jsonlite::parse(line);
            if (v.type != jsonlite::Type::Object) return false;
            const auto* cs = v.find("chain_seq");
            const auto* cp = v.find("chain_prev");
            const auto* ch = v.find("chain_hash");
            const bool hasChain = cs || cp || ch;
            if (!hasChain) {
                if (chained) return false;
                continue;
            }
            if (!cs || !cp || !ch ||
                cs->type != jsonlite::Type::Number ||
                cp->type != jsonlite::Type::String ||
                ch->type != jsonlite::Type::String ||
                !std::isfinite(cs->number) || std::floor(cs->number) != cs->number ||
                cs->number < 1.0 || cs->number > static_cast<double>(std::numeric_limits<uint64_t>::max()) ||
                cp->str != expectedPrev || !IsHexDigestIS(cp->str) || !IsHexDigestIS(ch->str)) {
                return false;
            }
            const uint64_t seq = static_cast<uint64_t>(cs->number);
            if (seq != expectedSeq) return false;
            const std::string chainHash = ch->str;
            v.object.erase("chain_seq");
            v.object.erase("chain_prev");
            v.object.erase("chain_hash");
            if (ChainHashIS(seq, expectedPrev, Sha256HexIS(StableJsonIS(v))) != chainHash) {
                return false;
            }
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

std::string IncidentRecordToJsonLine(const std::string& kind,
                                     const Incident& incident, bool redact) {
    /* IncidentToJson already returns a complete object literal, so the kind is
     * spliced in as the leading member rather than re-serialized. */
    std::string body = IncidentToJson(incident);
    if (body.size() < 2 || body[0] != '{') {
        /* Defensive: never emit a malformed line if IncidentToJson changes. */
        body = "{}";
    }
    std::string line = "{\"kind\":\"";
    line += jsonlite::escape(kind);
    line += "\",";
    line.append(body, 1, std::string::npos); /* skip the leading '{' */
    if (redact) {
        line = Alerter::Redact(line);
    }
    return line;
}

IncidentStore::IncidentStore(std::string path, bool redact, size_t maxRecords,
                            ProtectFileFn protectFile, AppendFn append)
    : m_path(std::move(path)),
      m_redact(redact),
      m_maxRecords(maxRecords == 0 ? 1 : maxRecords),
      m_protectFile(std::move(protectFile)),
      m_append(std::move(append)) {}

IncidentStore::~IncidentStore() {
    Close();
}

bool IncidentStore::OpenWithRestrictedAcl() {
#if defined(_WIN32)
    if (m_aclHandle != INVALID_HANDLE_VALUE) {
        m_lastError = "incident store file handle is already open";
        return false;
    }

    /* Apply the policy atomically for a new file and again through the open
     * handle for both new and existing files. The retained handle deliberately
     * omits FILE_SHARE_DELETE so the protected path cannot be swapped while
     * records are appended through that handle. */
    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = FALSE;

    /* SDDL: D:P  protected DACL, A  allow, FA full access, OW owner rights.
     * The owner is pinned to the token user so the elevated default
     * (Administrators) does not become the effective principal. */
    std::string sdError;
    PSECURITY_DESCRIPTOR sd = CreateOwnerOnlyDescriptor(sdError);
    if (sd == nullptr) {
        std::fprintf(stderr,
                     "[edr] incident store DACL descriptor conversion failed: %s\n",
                     sdError.c_str());
        m_lastError = WinErrorIS("incident store DACL descriptor conversion failed",
                                 ERROR_INVALID_SECURITY_DESCR);
        return false;
    }
    sa.lpSecurityDescriptor = sd;

    HANDLE h = CreateFileA(m_path.c_str(),
                           FILE_APPEND_DATA | READ_CONTROL | WRITE_DAC,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, &sa,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        const DWORD error = GetLastError();
        LocalFree(sd);
        std::fprintf(stderr,
                     "[edr] incident store protected file open/create failed (win32=%lu)\n",
                     static_cast<unsigned long>(error));
        m_lastError = WinErrorIS("incident store protected file open/create failed",
                                 error);
        return false;
    }

    PACL policyDacl = nullptr;
    BOOL daclPresent = FALSE;
    BOOL daclDefaulted = FALSE;
    const BOOL haveDacl = GetSecurityDescriptorDacl(
        sd, &daclPresent, &policyDacl, &daclDefaulted);
    bool protectedFile = false;
    DWORD protectError = ERROR_SUCCESS;
    std::string protectDetail;
    if (haveDacl != FALSE && daclPresent != FALSE && policyDacl != nullptr) {
        try {
            if (m_protectFile) {
                protectedFile = m_protectFile(h);
                if (!protectedFile) {
                    protectError = ERROR_ACCESS_DENIED;
                    protectDetail = "injected protection function returned false";
                }
            } else {
                protectedFile = ApplyOwnerOnlyDaclIS(
                    h, policyDacl, protectError, protectDetail);
            }
        } catch (...) {
            protectedFile = false;
            protectError = ERROR_UNHANDLED_EXCEPTION;
            protectDetail = "protection function threw an exception";
        }
    } else {
        protectError = haveDacl != FALSE ? ERROR_INVALID_ACL : GetLastError();
        protectDetail = "policy security descriptor has no usable DACL";
    }
    LocalFree(sd);

    if (!protectedFile) {
        CloseHandle(h);
        std::fprintf(stderr,
                     "[edr] incident store DACL protection failed: %s (win32=%lu)\n",
                     protectDetail.c_str(),
                     static_cast<unsigned long>(protectError));
        m_lastError = protectDetail + " (win32=" +
            std::to_string(protectError) + ")";
        return false;
    }
    m_aclHandle = h;
    return true;
#else
    return false;
#endif
}

void IncidentStore::CloseAclHandle() {
#if defined(_WIN32)
    if (m_aclHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(m_aclHandle);
        m_aclHandle = INVALID_HANDLE_VALUE;
    }
#endif
}

bool IncidentStore::ResumeChain(){ return ResumeChainIS(m_path,m_chainSeq,m_chainPrev); }

bool IncidentStore::Open() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!Enabled()) {
        m_lastError.clear();
        return true; /* nothing to do is not a failure */
    }
    if (m_writeFailed) {
        m_lastError = "incident store append failure remains latched; use a new instance after recovery";
        return false;
    }
    m_lastError.clear();
#if defined(_WIN32)
    if (m_aclHandle != INVALID_HANDLE_VALUE) {
        m_lastError = "incident store Open rejected while already open";
        std::fprintf(stderr,
                     "[edr] incident store Open rejected while already open\n");
        return false;
    }
    if (!OpenWithRestrictedAcl()) {
        if (m_lastError.empty())
            m_lastError = "incident store protected file open or DACL verification failed";
        return false;
    }
    if (!ResumeChain()) {
        m_lastError = "incident store history recovery failed; append refused";
        std::fprintf(stderr,
                     "[edr] incident store history recovery failed; append refused\n");
        CloseAclHandle();
        return false;
    }
#else
    if (m_file.is_open()) {
        m_lastError = "incident store Open rejected while already open";
        return false;
    }
    if (!ResumeChain()) {
        m_lastError = "incident store history recovery failed; append refused";
        std::fprintf(stderr,
                     "[edr] incident store history recovery failed; append refused\n");
        return false;
    }
    m_file.open(m_path, std::ios::app | std::ios::binary);
    if (!m_file.is_open()) {
        std::fprintf(stderr,
                     "[edr] incident store append stream open failed (win32=%lu)\n",
                     static_cast<unsigned long>(GetLastError()));
        m_lastError = "incident store append stream open failed";
        return false;
    }
#endif
    if (m_recordCount >= m_maxRecords)
        m_lastError = "per-instance incident record limit reached";
    return true;
}

void IncidentStore::Close() {
    std::lock_guard<std::mutex> lock(m_mutex);
#if defined(_WIN32)
    CloseAclHandle();
#else
    if (m_file.is_open()) {
        m_file.flush();
        m_file.close();
    }
#endif
}

void IncidentStore::OnIncidentOpened(const Incident& incident) {
    Write("open", incident);
}

void IncidentStore::OnIncidentClosed(const Incident& incident) {
    Write("incident", incident);
}

void IncidentStore::Write(const std::string& kind, const Incident& incident) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!Enabled()) {
        return;
    }
    if (m_writeFailed) {
        ++m_dropped;
        return;
    }
#if defined(_WIN32)
    const bool isOpen = m_aclHandle != INVALID_HANDLE_VALUE;
#else
    const bool isOpen = m_file.is_open();
#endif
    if (!isOpen) {
        ++m_dropped;
        if (m_lastError.empty()) m_lastError = "incident store is not open";
        return;
    }
    if (m_recordCount >= m_maxRecords) {
        m_truncated = true;
        ++m_dropped;
        if (m_lastError.empty())
            m_lastError = "per-instance incident record limit reached";
        if (!m_reportedTruncation) {
            m_reportedTruncation = true;
            std::fprintf(stderr,
                          "[edr] incident store reached its record ceiling "
                          "(%zu); further incidents are not persisted\n",
                          m_maxRecords);
        }
        return;
    }

    std::string base = IncidentRecordToJsonLine(kind, incident, m_redact);
    uint64_t seq = m_chainSeq + 1;
    std::string prev = m_chainPrev;
    std::string payloadHash; try{ auto pv=jsonlite::parse(base); payloadHash=Sha256HexIS(StableJsonIS(pv)); }catch(...){ payloadHash=Sha256HexIS(base); }
    std::string ch = ChainHashIS(seq, prev, payloadHash);
    std::string line;
    if (!base.empty() && base.back() == '}') {
        line = base.substr(0, base.size()-1) + ",\"chain_seq\":" + std::to_string(seq) + ",\"chain_prev\":\"" + prev + "\",\"chain_hash\":\"" + ch + "\"}";
    } else line = base;
    line.push_back('\n');

    bool appended = false;
    if (m_append) {
        SetLastError(ERROR_SUCCESS);
        try {
#if defined(_WIN32)
            appended = m_append(m_aclHandle, line);
#else
            appended = m_append(nullptr, line);
#endif
            if (!appended) {
                const DWORD error = GetLastError();
                m_lastError = error == ERROR_SUCCESS
                    ? "incident append callback returned false"
                    : WinErrorIS("incident append callback failed", error);
            }
        } catch (...) {
            m_lastError = "incident append callback threw an exception";
        }
    } else {
#if defined(_WIN32)
        if (line.size() > std::numeric_limits<DWORD>::max()) {
            m_lastError = "incident record exceeds the Windows append limit";
        } else {
            DWORD written = 0;
            if (!WriteFile(m_aclHandle, line.data(),
                           static_cast<DWORD>(line.size()), &written, nullptr)) {
                m_lastError = WinErrorIS("incident append WriteFile failed",
                                         GetLastError());
            } else if (written != line.size()) {
                m_lastError = WinErrorIS("incident append was incomplete",
                                         ERROR_WRITE_FAULT);
            } else if (!FlushFileBuffers(m_aclHandle)) {
                m_lastError = WinErrorIS("incident append flush failed",
                                         GetLastError());
            } else {
                appended = true;
            }
        }
#else
        m_file.write(line.data(), static_cast<std::streamsize>(line.size()));
        m_file.flush();
        if (m_file.good()) {
            appended = true;
        } else {
            m_lastError = "incident append stream write or flush failed";
        }
#endif
    }

    if (!appended) {
        ++m_writeFailures;
        ++m_dropped;
        m_writeFailed = true;
        if (m_lastError.empty()) m_lastError = "incident append failed";
        if (!m_reportedWriteFailure) {
            m_reportedWriteFailure = true;
            std::fprintf(stderr,
                         "[edr] incident store append failed; future writes are latched: %s\n",
                         m_lastError.c_str());
        }
        return;
    }
    ++m_recordCount;
    m_chainSeq = seq;
    m_chainPrev = ch;
    if (m_recordCount >= m_maxRecords)
        m_lastError = "per-instance incident record limit reached";
    else
        m_lastError.clear();
}

size_t IncidentStore::RecordCount() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_recordCount;
}

bool IncidentStore::Truncated() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_truncated;
}

IncidentStore::WriteStatus IncidentStore::GetWriteStatus() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    WriteStatus status;
    status.enabled = Enabled();
#if defined(_WIN32)
    status.open = m_aclHandle != INVALID_HANDLE_VALUE;
#else
    status.open = m_file.is_open();
#endif
    status.truncated = m_truncated;
    status.writeFailures = m_writeFailures;
    status.dropped = m_dropped;
    status.chainSequence = m_chainSeq;
    status.lastError = m_lastError;
    status.writable = status.enabled && status.open && !m_writeFailed &&
        !m_truncated && m_recordCount < m_maxRecords;
    return status;
}

} // namespace edr
