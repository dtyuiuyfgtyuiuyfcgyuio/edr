#include "wmi_parser.h"

#include <windows.h>
#include <cstdio>
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

static bool PutPid(Event& event, const DataMap& data, const wchar_t* name) {
    auto it = data.find(name);
    if (it == data.end() || it->second.empty()) return false;
    uint64_t pid = 0;
    if (!ParseUnsigned(it->second, 0xFFFFFFFF, pid)) return false;
    event.pid = static_cast<uint32_t>(pid);
    event.fields[field::kPid] = std::to_string(event.pid);
    return true;
}

static void PutHexResult(Event& event, const DataMap& data,
                        const wchar_t* name) {
    auto it = data.find(name);
    if (it == data.end()) return;
    uint32_t raw = 0;
    if (ParseHexFlexible(it->second, raw)) {
        char buf[11] = {};
        std::snprintf(buf, sizeof(buf), "0x%08x", raw);
        event.fields[field::kWmiResultCode] = buf;
    } else {
        event.fields[field::kWmiResultCode] = WideToUtf8(it->second.c_str());
    }
}

bool ParseWmiXml(const std::wstring& xml, Event& event) {
    uint64_t idValue = 0;
    std::wstring eventIdStr = ElementText(xml, L"<EventID");
    if (eventIdStr.empty() || !ParseUnsigned(eventIdStr, 65535, idValue))
        return false;
    unsigned int id = static_cast<unsigned int>(idValue);
    if (id != 5857 && id != 5858 && id != 5860 && id != 5859 && id != 5861)
        return false;

    event = Event{};
    DataMap data;
    if (!UserDataPairs(xml, data)) return false;
    event.source = "wmi";
    event.fields[field::kSource] = event.source;
    event.fields[field::kWmiEventId] = std::to_string(id);
    event.type = EDR_EVT_WMI_EVENT;

    switch (id) {
    case 5857: {
        event.fields[field::kOperationType] = "PROVIDER_LOAD";
        Put(event, data, L"ProviderName", field::kWmiProviderName);
        Put(event, data, L"ProviderPath", field::kWmiProviderPath);
        Put(event, data, L"HostProcess", field::kWmiHostProcess);
        PutHexResult(event, data, L"Code");
        PutPid(event, data, L"ProcessID");
        break;
    }
    case 5858: {
        event.fields[field::kOperationType] = "CLIENT_FAILURE";
        Put(event, data, L"ClientMachine", field::kWmiClientMachine);
        Put(event, data, L"User", field::kSubjectUserName);
        Put(event, data, L"Operation", field::kWmiOperation);
        PutHexResult(event, data, L"ResultCode");
        Put(event, data, L"PossibleCause", field::kWmiPossibleCause);
        PutPid(event, data, L"ClientProcessId");
        break;
    }
    case 5860: {
        event.fields[field::kOperationType] = "TEMPORARY_EVENT_SUBSCRIPTION";
        Put(event, data, L"NamespaceName", field::kWmiNamespace);
        Put(event, data, L"Query", field::kWmiQuery);
        Put(event, data, L"User", field::kSubjectUserName);
        Put(event, data, L"ClientMachine", field::kWmiClientMachine);
        Put(event, data, L"PossibleCause", field::kWmiPossibleCause);
        PutPid(event, data, L"Processid");
        break;
    }
    case 5859: {
        /* Permanent event subscription started (Operation_EssStarted):
         * the WMI filter that activates a permanent consumer. */
        event.fields[field::kOperationType] = "PERMANENT_EVENT_SUBSCRIPTION";
        Put(event, data, L"NamespaceName", field::kWmiNamespace);
        Put(event, data, L"Query", field::kWmiQuery);
        Put(event, data, L"User", field::kSubjectUserName);
        Put(event, data, L"Provider", field::kWmiProviderName);
        Put(event, data, L"PossibleCause", field::kWmiPossibleCause);
        PutPid(event, data, L"Processid");
        break;
    }
    case 5861: {
        /* Filter-to-consumer binding (Operation_ESStoConsumerBinding):
         * the association that links a permanent event filter to its
         * consumer. Real UserData element names are ESS (filter name) and
         * CONSUMER (consumer name/type, e.g. CommandLineEventConsumer="x").
         * No Processid in this event. */
        event.fields[field::kOperationType] = "FILTER_TO_CONSUMER_BINDING";
        Put(event, data, L"Namespace", field::kWmiNamespace);
        Put(event, data, L"ESS", field::kWmiOperation);
        Put(event, data, L"CONSUMER", field::kWmiProviderName);
        Put(event, data, L"PossibleCause", field::kWmiPossibleCause);
        break;
    }
    default:
        return false;
    }

    auto machine = event.fields.find(field::kWmiClientMachine);
    std::string identity = machine == event.fields.end() ? "local" : machine->second;
    if (event.pid != 0) identity += "/" + std::to_string(event.pid);
    event.processIdentity = "wmi/" + identity;

    event.fields[field::kType] = EventTypeName(event.type);

    std::wstring timestamp = SourceTimestamp(xml);
    if (!timestamp.empty()) {
        event.fields[field::kSourceTimestamp] = WideToUtf8(timestamp.c_str());
        event.ts100ns = ParseSystemTime100ns(timestamp);
    }
    if (event.ts100ns != 0) {
        event.fields[field::kTimestampProvenance] = "wmi_activity_system_time";
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
