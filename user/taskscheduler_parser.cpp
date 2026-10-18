#include "taskscheduler_parser.h"

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

bool ParseTaskSchedulerXml(const std::wstring& xml, Event& event) {
    uint64_t idValue = 0;
    std::wstring eventIdStr = ElementText(xml, L"<EventID");
    if (eventIdStr.empty() || !ParseUnsigned(eventIdStr, 65535, idValue))
        return false;
    unsigned int id = static_cast<unsigned int>(idValue);
    if (id != 106 && id != 140 && id != 141)
        return false;

    event = Event{};
    DataMap data = EventData(xml);
    event.type = EDR_EVT_TASK_SCHEDULER;
    event.source = "taskscheduler_log";
    event.fields[field::kSource] = event.source;
    event.fields[field::kTaskSchedulerEventId] = std::to_string(id);

    switch (id) {
    case 106:
        event.fields[field::kOperationType] = "TASK_REGISTERED";
        break;
    case 140:
        event.fields[field::kOperationType] = "TASK_UPDATED";
        break;
    case 141:
        event.fields[field::kOperationType] = "TASK_DELETED";
        break;
    default:
        return false;
    }

    Put(event, data, L"TaskName", field::kTaskName);
    {
        auto user = data.find(L"UserContext");
        if (user == data.end() || user->second.empty())
            user = data.find(L"UserName");
        if (user != data.end() && !user->second.empty())
            event.fields[field::kTaskUserContext] = WideToUtf8(user->second.c_str());
    }

    event.fields[field::kType] = EventTypeName(event.type);

    std::wstring timestamp = SourceTimestamp(xml);
    if (!timestamp.empty()) {
        event.fields[field::kSourceTimestamp] = WideToUtf8(timestamp.c_str());
        event.ts100ns = ParseSystemTime100ns(timestamp);
    }
    if (event.ts100ns != 0) {
        event.fields[field::kTimestampProvenance] = "taskscheduler_system_time";
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
