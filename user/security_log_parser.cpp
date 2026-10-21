#include "security_log_parser.h"

#include <windows.h>
#include <cstdio>
#include <initializer_list>
#include <limits>
#include <map>
#include <utility>

#include "config.h"
#include "edr_event.h"
#include "xml_util.h"

namespace edr {

using DataMap = std::map<std::wstring, std::wstring>;

static void Put(Event& event, const DataMap& data, const wchar_t* source,
                const char* target) {
    auto it = data.find(source);
    if (it != data.end() && !it->second.empty()) {
        event.fields[target] = WideToUtf8(it->second.c_str());
    }
}

static void PutFirst(Event& event, const DataMap& data,
                     std::initializer_list<const wchar_t*> sources,
                     const char* target) {
    for (const wchar_t* source : sources) {
        auto it = data.find(source);
        if (it != data.end() && !it->second.empty()) {
            event.fields[target] = WideToUtf8(it->second.c_str());
            return;
        }
    }
}

static void PutSubject(Event& event, const DataMap& data) {
    Put(event, data, L"SubjectUserName", field::kSubjectUserName);
    Put(event, data, L"SubjectDomainName", field::kSubjectDomainName);
    Put(event, data, L"SubjectUserSid", field::kSubjectUserSid);
}

/* Capture complete Task Scheduler XML as UTF-8 text, without parsing or
 * executing its embedded task document. The size contract is in UTF-8 bytes. */
static void PutTaskContent(Event& event, const DataMap& data,
                           const wchar_t* source) {
    const auto found = data.find(source);
    if (found == data.end() || found->second.empty()) {
        event.fields[field::kTaskContentStatus] = "missing";
        return;
    }
    const std::wstring& content = found->second;
    if (content.size() > static_cast<size_t>(std::numeric_limits<int>::max())) {
        event.fields[field::kTaskContentStatus] = "omitted_oversize";
        return;
    }
    const int wideLength = static_cast<int>(content.size());
    const int utf8Length = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, content.data(), wideLength,
        nullptr, 0, nullptr, nullptr);
    if (utf8Length == 0) {
        event.fields[field::kTaskContentStatus] = "invalid_encoding";
        return;
    }
    if (utf8Length > 32768) {
        event.fields[field::kTaskContentStatus] = "omitted_oversize";
        return;
    }
    std::string utf8(static_cast<size_t>(utf8Length), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, content.data(),
            wideLength, utf8.data(), utf8Length, nullptr, nullptr) != utf8Length) {
        event.fields[field::kTaskContentStatus] = "invalid_encoding";
        return;
    }
    event.fields[field::kTaskContent] = std::move(utf8);
    event.fields[field::kTaskContentStatus] = "captured";
}

/* EvtRender renders win:FILETIME as UTC xs:dateTime. Validate before using
 * the shared seven-digit converter: SystemTimeToFileTime can normalize a
 * date such as February 30. Retain 100ns precision, truncating finer digits. */
static bool ParseUtcFiletime(const std::wstring& text, uint64_t& out) {
    if (text.size() < 20 || text.size() > 30 || text[4] != L'-' ||
        text[7] != L'-' || text[10] != L'T' || text[13] != L':' ||
        text[16] != L':' || text.back() != L'Z') return false;
    auto number = [&](size_t offset, size_t count) {
        int result = 0;
        for (size_t i = offset; i < offset + count; ++i) {
            if (text[i] < L'0' || text[i] > L'9') return -1;
            result = result * 10 + static_cast<int>(text[i] - L'0');
        }
        return result;
    };
    const int year = number(0, 4), month = number(5, 2), day = number(8, 2);
    const int hour = number(11, 2), minute = number(14, 2), second = number(17, 2);
    if (year < 1601 || month < 1 || month > 12 || day < 1 || day > 31 ||
        hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 ||
        second > 59) return false;
    std::wstring fraction(7, L'0');
    if (text.size() != 20) {
        if (text[19] != L'.' || text.size() < 22) return false;
        const size_t digits = text.size() - 21;
        for (size_t i = 0; i < digits; ++i) {
            if (text[20 + i] < L'0' || text[20 + i] > L'9') return false;
            if (i < 7) fraction[i] = text[20 + i];
        }
    }
    SYSTEMTIME input{};
    input.wYear = static_cast<WORD>(year); input.wMonth = static_cast<WORD>(month);
    input.wDay = static_cast<WORD>(day); input.wHour = static_cast<WORD>(hour);
    input.wMinute = static_cast<WORD>(minute); input.wSecond = static_cast<WORD>(second);
    FILETIME ticks{};
    SYSTEMTIME actual{};
    if (!SystemTimeToFileTime(&input, &ticks) || !FileTimeToSystemTime(&ticks, &actual) ||
        actual.wYear != input.wYear || actual.wMonth != input.wMonth ||
        actual.wDay != input.wDay) return false;
    out = ParseSystemTime100ns(text.substr(0, 19) + L"." + fraction + L"Z");
    return true;
}

/* Numeric FILETIME is retained for previously accepted forwarded inputs. */
static bool ParseFiletimeText(const std::wstring& text, uint64_t& out) {
    if (text.empty()) return false;
    if (text.find(L'T') != std::wstring::npos) return ParseUtcFiletime(text, out);
    if (text.size() >= 2 && text[0] == L'0' &&
        (text[1] == L'x' || text[1] == L'X')) {
        const size_t start = 2;
        if (text.size() - start < 1 || text.size() - start > 16)
            return false;
        uint64_t value = 0;
        for (size_t i = start; i < text.size(); ++i) {
            const wchar_t ch = text[i];
            unsigned digit;
            if (ch >= L'0' && ch <= L'9')
                digit = static_cast<unsigned>(ch - L'0');
            else if (ch >= L'a' && ch <= L'f')
                digit = static_cast<unsigned>(ch - L'a') + 10;
            else if (ch >= L'A' && ch <= L'F')
                digit = static_cast<unsigned>(ch - L'A') + 10;
            else
                return false;
            value = (value << 4) | digit;
        }
        out = value;
        return true;
    }
    return ParseUnsigned(text, ~0ULL, out);
}

static void PutFiletimeValue(Event& event, const DataMap& data,
                             const wchar_t* source, const char* target) {
    auto it = data.find(source);
    if (it == data.end() || it->second.empty()) return;
    uint64_t value = 0;
    if (!ParseFiletimeText(it->second, value)) return;
    event.fields[target] = std::to_string(value);
}

static void PutAccountTarget(Event& event, const DataMap& data) {
    Put(event, data, L"TargetUserName", field::kTargetUser);
    Put(event, data, L"TargetDomainName", field::kTargetDomain);
    PutSubject(event, data);
    auto sidIt = data.find(L"TargetSid");
    if (sidIt != data.end() && !sidIt->second.empty())
        event.fields[field::kTargetUserSid] = WideToUtf8(sidIt->second.c_str());
}

bool ParseSecurityLogXml(const std::wstring& xml, Event& event) {
    uint64_t idValue = 0;
    std::wstring eventIdStr = ElementText(xml, L"<EventID");
    if (eventIdStr.empty() || !ParseUnsigned(eventIdStr, 65535, idValue))
        return false;
    unsigned int id = static_cast<unsigned int>(idValue);
    if (id != 4624 && id != 4625 && id != 4672 && id != 4720 && id != 4697 &&
        id != 1102 && id != 1100 && id != 4722 && id != 4723 && id != 4724 &&
        id != 4725 && id != 4726 && id != 4740 && id != 4769 && id != 4768 &&
        id != 4616 && id != 4728 && id != 4732 && id != 4756 && id != 4719 &&
        id != 1104 && id != 4698 && id != 4702)
        return false;

    uint64_t eventVersion = 0;
    const std::wstring version = ElementText(xml, L"<Version>");
    if (!version.empty()) ParseUnsigned(version, 255, eventVersion);

    event = Event{};
    DataMap data = EventData(xml);
    if (id == 4698 || id == 4702) {
        const auto taskName = data.find(L"TaskName");
        if (taskName == data.end() || taskName->second.empty()) return false;
    }
    event.source = "security_log";
    event.fields[field::kSource] = event.source;
    event.fields[field::kSecurityEventId] = std::to_string(id);

    switch (id) {
    case 4624: {
        event.type = EDR_EVT_LOGON;
        event.fields[field::kOperationType] = "LOGON";
        Put(event, data, L"TargetUserName", field::kTargetUser);
        Put(event, data, L"TargetDomainName", field::kTargetDomain);
        Put(event, data, L"TargetLogonId", field::kLogonId);
        Put(event, data, L"LogonType", field::kLogonType);
        Put(event, data, L"LogonProcessName", field::kLogonProcess);
        Put(event, data, L"AuthenticationPackageName", field::kAuthPackage);
        Put(event, data, L"WorkstationName", field::kSourceWorkstation);
        Put(event, data, L"IpAddress", field::kSrcIp);
        Put(event, data, L"ElevatedToken", field::kElevatedToken);
        PutSubject(event, data);
        {
            auto it = data.find(L"TargetUserSid");
            if (it != data.end() && !it->second.empty())
                event.fields[field::kTargetUserSid] = WideToUtf8(it->second.c_str());
        }
        break;
    }
    case 4625: {
        event.type = EDR_EVT_LOGON;
        event.fields[field::kOperationType] = "LOGON_FAILURE";
        Put(event, data, L"TargetUserName", field::kTargetUser);
        Put(event, data, L"TargetDomainName", field::kTargetDomain);
        Put(event, data, L"LogonType", field::kLogonType);
        Put(event, data, L"WorkstationName", field::kSourceWorkstation);
        Put(event, data, L"IpAddress", field::kSrcIp);
        Put(event, data, L"FailureReason", field::kFailureReason);
        PutSubject(event, data);
        {
            auto it = data.find(L"Status");
            uint32_t rawStatus = 0;
            if (it != data.end() && ParseHexFlexible(it->second, rawStatus)) {
                char buf[11] = {};
                std::snprintf(buf, sizeof(buf), "0x%08x", rawStatus);
                event.fields[field::kStatus] = buf;
            }
        }
        {
            auto it = data.find(L"SubStatus");
            uint32_t rawSubStatus = 0;
            if (it != data.end() && ParseHexFlexible(it->second, rawSubStatus)) {
                char buf[11] = {};
                std::snprintf(buf, sizeof(buf), "0x%08x", rawSubStatus);
                event.fields[field::kSubStatus] = buf;
            }
        }
        break;
    }
    case 4672: {
        event.type = EDR_EVT_LOGON;
        event.fields[field::kOperationType] = "LOGON_ELEVATED";
        // The session receiving these privileges is the native Subject.
        // This event is a session assignment, not process privilege use.
        Put(event, data, L"SubjectUserName", field::kTargetUser);
        Put(event, data, L"SubjectDomainName", field::kTargetDomain);
        Put(event, data, L"SubjectUserSid", field::kTargetUserSid);
        Put(event, data, L"SubjectLogonId", field::kLogonId);
        event.fields[field::kElevatedToken] = "true";
        PutSubject(event, data);
        auto privIt = data.find(L"PrivilegeList");
        if (privIt != data.end() && !privIt->second.empty()) {
            event.fields[field::kPrivileges] = WideToUtf8(privIt->second.c_str());
        }
        break;
    }
    case 4720: {
        event.type = EDR_EVT_ACCOUNT_CHANGE;
        event.fields[field::kOperationType] = "ACCOUNT_CREATE";
        Put(event, data, L"TargetUserName", field::kTargetUser);
        Put(event, data, L"TargetDomainName", field::kTargetDomain);
        Put(event, data, L"SamAccountName", field::kAccountName);
        Put(event, data, L"SubjectUserName", field::kSubjectUserName);
        Put(event, data, L"SubjectDomainName", field::kSubjectDomainName);
        Put(event, data, L"SubjectUserSid", field::kSubjectUserSid);
        Put(event, data, L"WorkstationName", field::kSourceWorkstation);
        auto sidIt = data.find(L"TargetSid");
        if (sidIt != data.end() && !sidIt->second.empty())
            event.fields[field::kTargetUserSid] = WideToUtf8(sidIt->second.c_str());
        break;
    }
    case 4722: {
        /* A user account was enabled. */
        event.type = EDR_EVT_ACCOUNT_CHANGE;
        event.fields[field::kOperationType] = "ACCOUNT_ENABLED";
        PutAccountTarget(event, data);
        break;
    }
    case 4723: {
        /* An attempt was made to change an account's password. */
        event.type = EDR_EVT_ACCOUNT_CHANGE;
        event.fields[field::kOperationType] = "ACCOUNT_PASSWORD_CHANGE";
        PutAccountTarget(event, data);
        break;
    }
    case 4724: {
        /* An attempt was made to reset an account's password. */
        event.type = EDR_EVT_ACCOUNT_CHANGE;
        event.fields[field::kOperationType] = "ACCOUNT_PASSWORD_RESET";
        PutAccountTarget(event, data);
        break;
    }
    case 4725: {
        /* A user account was disabled. */
        event.type = EDR_EVT_ACCOUNT_CHANGE;
        event.fields[field::kOperationType] = "ACCOUNT_DISABLED";
        PutAccountTarget(event, data);
        break;
    }
    case 4726: {
        /* A user account was deleted. */
        event.type = EDR_EVT_ACCOUNT_CHANGE;
        event.fields[field::kOperationType] = "ACCOUNT_DELETED";
        PutAccountTarget(event, data);
        break;
    }
    case 4740: {
        /* A user account was locked out; CallerComputerName identifies the
         * machine that triggered the lockout (brute-force indicator). */
        event.type = EDR_EVT_ACCOUNT_CHANGE;
        event.fields[field::kOperationType] = "ACCOUNT_LOCKED_OUT";
        PutAccountTarget(event, data);
        Put(event, data, L"CallerComputerName", field::kSourceWorkstation);
        break;
    }
    case 4769: {
        /* A Kerberos service ticket was requested (T1558.003). Standard 4769
         * XML uses TargetUserName/TargetDomainName, Status, and IpAddress.
         * Older rendered/forwarded forms are accepted only as fallbacks.
         * RC4-HMAC (0x17) is the offline-crackable shape targeted by
         * Kerberoasting. Normalized under LOGON so no new event type is needed. */
        event.type = EDR_EVT_LOGON;
        event.fields[field::kOperationType] = "TGS_REQUEST";
        PutFirst(event, data, {L"TargetUserName", L"AccountName"},
                 field::kTargetUser);
        PutFirst(event, data, {L"TargetDomainName", L"Realm"},
                 field::kTargetDomain);
        Put(event, data, L"ServiceName", field::kTgsServiceName);
        Put(event, data, L"ServiceSid", field::kTgsServiceSid);
        Put(event, data, L"TicketEncryptionType",
            field::kTgsTicketEncryptionType);
        PutFirst(event, data, {L"Status", L"FailureCode"},
                 field::kTgsFailureCode);
        PutFirst(event, data, {L"IpAddress", L"ClientAddress"},
                 field::kSrcIp);
        PutSubject(event, data);
        break;
    }
    case 4768: {
        /* A Kerberos TGT was requested (T1558.004). PreAuthType distinguishes
         * normal pre-authenticated requests (15 = PA-ENC-TIMESTAMP) from
         * requests against accounts that do not require pre-authentication
         * (0), the shape AS-REP roasting exploits. Normalized under LOGON. */
        event.type = EDR_EVT_LOGON;
        event.fields[field::kOperationType] = "TGT_REQUEST";
        PutFirst(event, data, {L"TargetUserName", L"AccountName"},
                 field::kTargetUser);
        PutFirst(event, data, {L"TargetDomainName", L"Realm"},
                 field::kTargetDomain);
        Put(event, data, L"PreAuthType", field::kPreAuthType);
        Put(event, data, L"IpAddress", field::kSrcIp);
        PutFirst(event, data, {L"Status", L"FailureCode"},
                 field::kStatus);
        Put(event, data, L"TicketEncryptionType",
            field::kTgsTicketEncryptionType);
        PutSubject(event, data);
        break;
    }
    case 4697: {
        event.type = EDR_EVT_SERVICE_INSTALL;
        event.fields[field::kOperationType] = "SERVICE_INSTALL";
        Put(event, data, L"ServiceName", field::kServiceName);
        Put(event, data, L"ServiceFileName", field::kServiceImagePath);
        Put(event, data, L"ServiceStartType", field::kServiceStartType);
        Put(event, data, L"ServiceAccount", field::kServiceAccount);
        PutSubject(event, data);
        break;
    }
    case 4698:
    case 4702: {
        event.type = EDR_EVT_TASK_SCHEDULER;
        event.fields[field::kOperationType] =
            id == 4698 ? "TASK_REGISTERED" : "TASK_UPDATED";
        Put(event, data, L"TaskName", field::kTaskName);
        PutSubject(event, data);
        Put(event, data, L"SubjectLogonId", field::kLogonId);
        PutTaskContent(event, data,
                       id == 4698 ? L"TaskContent" : L"TaskContentNew");
        if (eventVersion == 1) {
            Put(event, data, L"ClientProcessId", field::kTaskClientPid);
            Put(event, data, L"ParentProcessId", field::kTaskClientParentPid);
            Put(event, data, L"ClientProcessStartKey",
                field::kTaskClientStartKey);
            Put(event, data, L"RpcCallClientLocality",
                field::kTaskRpcLocality);
            Put(event, data, L"FQDN", field::kTaskClientFqdn);
        }
        break;
    }
    case 1102: {
        /* Audit log cleared (T1070.001). Produced by the EventLog service
         * itself; carries subject identity when available. */
        event.type = EDR_EVT_AUDIT_LOG;
        event.fields[field::kAuditLogEventId] = "1102";
        PutSubject(event, data);
        break;
    }
    case 1100: {
        /* Event log service shut down; no event-specific detail data. */
        event.type = EDR_EVT_AUDIT_LOG;
        event.fields[field::kAuditLogEventId] = "1100";
        break;
    }
    case 4616: {
        /* System time changed (temporal anti-analysis signal). */
        event.type = EDR_EVT_SYSTEM_TIME_CHANGE;
        event.fields[field::kOperationType] = "TIME_CHANGE";
        PutSubject(event, data);
        PutFiletimeValue(event, data, L"PreviousTime",
                         field::kTimeChangePrev100ns);
        PutFiletimeValue(event, data, L"NewTime",
                         field::kTimeChangeNew100ns);
        break;
    }
    case 4728:
    case 4732:
    case 4756: {
        /* Member added to a security-enabled global/local/universal group
         * (T1098 / T1078.002). TargetUserName is the GROUP; the member is
         * MemberName/MemberSid. */
        event.type = EDR_EVT_ACCOUNT_CHANGE;
        event.fields[field::kOperationType] = "GROUP_MEMBER_ADD";
        PutSubject(event, data);
        Put(event, data, L"MemberName", field::kTargetUser);
        Put(event, data, L"MemberSid", field::kTargetUserSid);
        Put(event, data, L"TargetUserName", field::kTargetGroupName);
        break;
    }
    case 4719: {
        /* System audit policy was changed (T1562.002-adjacent): attackers
         * quiet specific audit categories before acting. */
        event.type = EDR_EVT_AUDIT_LOG;
        event.fields[field::kOperationType] = "AUDIT_POLICY_CHANGED";
        event.fields[field::kAuditLogEventId] = "4719";
        PutSubject(event, data);
        Put(event, data, L"SubjectLogonId", field::kLogonId);
        Put(event, data, L"CategoryId", field::kAuditPolicyCategoryId);
        Put(event, data, L"SubcategoryId", field::kAuditPolicySubcategoryId);
        Put(event, data, L"SubcategoryGuid",
            field::kAuditPolicySubcategoryGuid);
        Put(event, data, L"AuditPolicyChanges", field::kAuditPolicyChanges);
        break;
    }
    case 1104: {
        /* The security log is now full: precursor to a clear or evidence of
         * unattended retention exhaustion. */
        event.type = EDR_EVT_AUDIT_LOG;
        event.fields[field::kOperationType] = "SECURITY_LOG_FULL";
        event.fields[field::kAuditLogEventId] = "1104";
        break;
    }
    default:
        return false;
    }

    event.fields[field::kType] = EventTypeName(event.type);

    std::wstring timestamp = SourceTimestamp(xml);
    if (!timestamp.empty()) {
        event.fields[field::kSourceTimestamp] = WideToUtf8(timestamp.c_str());
        event.ts100ns = ParseSystemTime100ns(timestamp);
    }
    if (event.ts100ns != 0) {
        event.fields[field::kTimestampProvenance] = "security_log_system_time";
    } else {
        FILETIME ft = {};
        GetSystemTimePreciseAsFileTime(&ft);
        event.ts100ns = (static_cast<uint64_t>(ft.dwHighDateTime) << 32) |
                        ft.dwLowDateTime;
        event.fields[field::kTimestampProvenance] = "collector_time_fallback";
    }
    return true;
}

} // namespace edr
