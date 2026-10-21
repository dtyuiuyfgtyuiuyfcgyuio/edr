#include "defender_parser.h"

#include <windows.h>

#include <initializer_list>
#include <limits>
#include <map>

#include "config.h"
#include "edr_event.h"
#include "xml_util.h"

namespace edr {
namespace {

using DataMap = std::map<std::wstring, std::wstring>;

bool IsAsrEvent(unsigned int id) {
    return id == 1121 || id == 1122 || id == 1129;
}

bool IsCfaEvent(unsigned int id) {
    return id == 1123 || id == 1124 || id == 1127 || id == 1128;
}

void PutFirst(Event& event, const DataMap& data,
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

void PutExecutionPid(Event& event, const std::wstring& xml, bool providerOnly) {
    size_t execution = xml.find(L"<Execution");
    if (execution == std::wstring::npos) return;
    size_t end = xml.find(L'>', execution);
    if (end == std::wstring::npos) return;
    std::wstring value = Attribute(xml, execution, end, L"ProcessID");
    uint64_t pid = 0;
    if (ParseUnsigned(value, std::numeric_limits<uint32_t>::max(), pid)) {
        if (providerOnly) {
            event.fields[field::kDefenderProviderPid] = std::to_string(pid);
        } else {
            event.pid = static_cast<uint32_t>(pid);
            event.fields[field::kPid] = std::to_string(event.pid);
        }
    }
}

void PutTimestamp(Event& event, const std::wstring& xml) {
    std::wstring timestamp = SourceTimestamp(xml);
    if (!timestamp.empty()) {
        event.fields[field::kSourceTimestamp] = WideToUtf8(timestamp.c_str());
        event.ts100ns = ParseSystemTime100ns(timestamp);
    }
    if (event.ts100ns != 0) {
        event.fields[field::kTimestampProvenance] = "defender_system_time";
        return;
    }
    FILETIME now = {};
    GetSystemTimePreciseAsFileTime(&now);
    event.ts100ns = (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
                    now.dwLowDateTime;
    event.fields[field::kTimestampProvenance] = "collector_time_fallback";
}

} // namespace

const wchar_t* DefenderSubscriptionQuery() {
    return L"*[System[(EventID=1116 or EventID=1117 or EventID=5001 or "
           L"EventID=5007 or EventID=1121 or EventID=1122 or "
           L"EventID=1129 or EventID=1123 or EventID=1124 or "
           L"EventID=1127 or EventID=1128)]]";
}

bool ParseDefenderXml(const std::wstring& xml, Event& event) {
    uint64_t idValue = 0;
    std::wstring eventId = ElementText(xml, L"<EventID");
    if (!ParseUnsigned(eventId, 65535, idValue)) return false;
    unsigned int id = static_cast<unsigned int>(idValue);
    if (id != 1116 && id != 1117 && id != 5001 && id != 5007 &&
        !IsAsrEvent(id) && !IsCfaEvent(id))
        return false;

    event = Event{};
    event.type = EDR_EVT_DEFENDER;
    event.source = "defender_log";
    event.fields[field::kSource] = event.source;
    event.fields[field::kDefenderEventId] = std::to_string(id);

    switch (id) {
    case 1116:
        event.fields[field::kOperationType] = "MALWARE_DETECTED";
        break;
    case 1117:
        event.fields[field::kOperationType] = "ACTION_TAKEN";
        break;
    case 5001:
        event.fields[field::kOperationType] =
            "REALTIME_PROTECTION_DISABLED";
        break;
    case 5007:
        event.fields[field::kOperationType] = "CONFIG_CHANGED";
        break;
    case 1121:
        event.fields[field::kOperationType] = "ASR_BLOCKED";
        break;
    case 1122:
        event.fields[field::kOperationType] = "ASR_AUDITED";
        break;
    case 1129:
        event.fields[field::kOperationType] = "ASR_WARN_BYPASSED";
        break;
    case 1123:
        event.fields[field::kOperationType] = "CFA_BLOCKED";
        break;
    case 1124:
        event.fields[field::kOperationType] = "CFA_AUDITED";
        break;
    case 1127:
        event.fields[field::kOperationType] = "CFA_SECTOR_WRITE_BLOCKED";
        break;
    case 1128:
        event.fields[field::kOperationType] = "CFA_SECTOR_WRITE_AUDITED";
        break;
    default:
        return false;
    }

    DataMap data = EventData(xml);
    PutFirst(event, data, {L"Threat Name", L"ThreatName"},
             field::kThreatName);
    PutFirst(event, data, {L"Threat ID", L"ThreatID"}, field::kThreatId);
    PutFirst(event, data, {L"Severity Name", L"SeverityName"},
             field::kThreatSeverity);
    PutFirst(event, data, {L"Category Name", L"CategoryName"},
             field::kThreatCategory);
    PutFirst(event, data, {L"Path"}, field::kDetectionPath);
    PutFirst(event, data, {L"Detection User", L"DetectionUser"},
             field::kDetectionUser);
    PutFirst(event, data, {L"Process Name", L"ProcessName"},
             field::kProcessName);
    PutFirst(event, data, {L"Action Name", L"ActionName"},
             field::kDefenderAction);
    PutFirst(event, data, {L"Status Description", L"StatusDescription"},
             field::kDefenderStatus);
    PutFirst(event, data, {L"Old Value", L"OldValue"},
             field::kDefenderOldValue);
    PutFirst(event, data, {L"New Value", L"NewValue"},
             field::kDefenderNewValue);
    if (IsAsrEvent(id)) {
        PutFirst(event, data, {L"ID"}, field::kAsrRuleId);
    } else if (IsCfaEvent(id)) {
        PutFirst(event, data, {L"ID"}, field::kCfaDetectionId);
    }
    if (IsAsrEvent(id) || IsCfaEvent(id)) {
        PutFirst(event, data, {L"User", L"Detection User", L"DetectionUser"},
                 field::kDetectionUser);
    }

    event.fields[field::kType] = EventTypeName(event.type);
    PutExecutionPid(event, xml, IsAsrEvent(id) || IsCfaEvent(id));
    PutTimestamp(event, xml);
    return true;
}

} // namespace edr
