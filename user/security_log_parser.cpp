#include "security_log_parser.h"

#include <windows.h>
#include <cstdio>
#include <initializer_list>
#include <map>

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

/* Parse a FILETIME value as rendered by 4616 EventData: decimal digits or
 * hex with 0x prefix; accumulates uint64 with an overflow guard. */
static bool ParseFiletimeText(const std::wstring& text, uint64_t& out) {
    if (text.empty()) return false;
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
        id != 1104)
        return false;

    event = Event{};
    DataMap data = EventData(xml);
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
        Put(event, data, L"TargetUserName", field::kTargetUser);
        Put(event, data, L"TargetDomainName", field::kTargetDomain);
        Put(event, data, L"TargetLogonId", field::kLogonId);
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
        Put(event, data, L"ImagePath", field::kServiceImagePath);
        Put(event, data, L"ServiceStartType", field::kServiceStartType);
        Put(event, data, L"ServiceAccount", field::kServiceAccount);
        PutSubject(event, data);
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
        event.fields[field::kAuditLogEventId] = "4719";
        PutSubject(event, data);
        break;
    }
    case 1104: {
        /* The security log is now full: precursor to a clear or evidence of
         * unattended retention exhaustion. */
        event.type = EDR_EVT_AUDIT_LOG;
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