/*
 * privilege_log_parser.cpp - Parse Windows Security log XML for
 * privilege escalation events (4673, 4674, 4703).
 *
 * Event IDs handled:
 *   4673 - Sensitive privileges used (SeDebug, SeTcb, SeAudit, ...)
 *   4674 - Sensitive privileges used on an object
 *   4703 - Token rights adjusted (privileges enabled/disabled)
 *
 * Follows the same XML parsing pattern as security_log_parser.cpp.
 */
#include "privilege_log_parser.h"

#include <windows.h>
#include <map>
#include <cstdio>

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

static void PutSubject(Event& event, const DataMap& data) {
    Put(event, data, L"SubjectUserName", field::kSubjectUserName);
    Put(event, data, L"SubjectDomainName", field::kSubjectDomainName);
    Put(event, data, L"SubjectUserSid", field::kSubjectUserSid);
    Put(event, data, L"SubjectLogonId", field::kLogonId);
}

bool ParsePrivilegeLogXml(const std::wstring& xml, Event& event) {
    uint64_t idValue = 0;
    std::wstring eventIdStr = ElementText(xml, L"<EventID");
    if (eventIdStr.empty() || !ParseUnsigned(eventIdStr, 65535, idValue))
        return false;
    unsigned int id = static_cast<unsigned int>(idValue);
    if (id != 4673 && id != 4674 && id != 4703)
        return false;

    event = Event{};
    DataMap data = EventData(xml);
    event.source = "security_log";
    event.fields[field::kSource] = event.source;
    event.fields[field::kSecurityEventId] = std::to_string(id);
    event.type = EDR_EVT_PRIVILEGE;

    switch (id) {
    case 4673: {
        event.fields[field::kPrivilegeOperation] = "SENSITIVE_USED";
        event.fields[field::kOperationType] = "PRIVILEGE_USE";
        Put(event, data, L"ObjectServer", field::kObjectServer);
        Put(event, data, L"ObjectType", field::kObjectType);
        Put(event, data, L"PrivilegeList", field::kPrivilegeList);
        Put(event, data, L"ProcessId", field::kSourcePid);
        Put(event, data, L"ProcessName", field::kProcessName);
        PutSubject(event, data);
        break;
    }
    case 4674: {
        event.fields[field::kPrivilegeOperation] = "SENSITIVE_OBJECT";
        event.fields[field::kOperationType] = "PRIVILEGE_OBJECT_USE";
        Put(event, data, L"ObjectServer", field::kObjectServer);
        Put(event, data, L"ObjectType", field::kObjectType);
        Put(event, data, L"ObjectName", field::kObjectName);
        Put(event, data, L"HandleId", field::kHandleId);
        Put(event, data, L"AccessMask", field::kAccessMask);
        Put(event, data, L"PrivilegeList", field::kPrivilegeList);
        Put(event, data, L"ProcessId", field::kSourcePid);
        Put(event, data, L"ProcessName", field::kProcessName);
        PutSubject(event, data);
        break;
    }
    case 4703: {
        event.fields[field::kPrivilegeOperation] = "TOKEN_ADJUSTED";
        event.fields[field::kOperationType] = "TOKEN_RIGHTS_CHANGE";
        Put(event, data, L"PrivilegeList", field::kPrivilegeList);
        Put(event, data, L"ProcessId", field::kSourcePid);
        Put(event, data, L"ProcessName", field::kProcessName);
        PutSubject(event, data);
        break;
    }
    default:
        return false;
    }

    event.fields[field::kType] = EventTypeName(event.type);

    /* Parse ProcessId from decimal string for event.pid */
    auto pidIt = data.find(L"ProcessId");
    if (pidIt != data.end()) {
        uint64_t pid = 0;
        if (ParseUnsigned(pidIt->second, 0xFFFFFFFF, pid)) {
            event.pid = static_cast<uint32_t>(pid);
        }
    }

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
