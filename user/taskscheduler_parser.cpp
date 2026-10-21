#include "taskscheduler_parser.h"

#include <windows.h>
#include <array>
#include <map>
#include <cstdio>
#include <limits>

#include "config.h"
#include "edr_event.h"
#include "xml_util.h"

namespace edr {

using DataMap = std::map<std::wstring, std::wstring>;

constexpr std::array<unsigned int, 9> kTaskSchedulerEventIds = {
    100, 102, 106, 140, 141, 200, 201, 202, 203
};

static void Put(Event& event, const DataMap& data, const wchar_t* source,
                const char* target) {
    auto it = data.find(source);
    if (it != data.end() && !it->second.empty()) {
        event.fields[target] = WideToUtf8(it->second.c_str());
    }
}

static bool IsStandardGuid(const std::wstring& value) {
    size_t first = 0;
    size_t length = value.size();
    if (length == 38 && value.front() == L'{' && value.back() == L'}') {
        first = 1;
        length = 36;
    } else if (length != 36) {
        return false;
    }
    for (size_t i = 0; i < length; ++i) {
        const wchar_t ch = value[first + i];
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (ch != L'-') return false;
        } else if (!((ch >= L'0' && ch <= L'9') ||
                     (ch >= L'a' && ch <= L'f') ||
                     (ch >= L'A' && ch <= L'F'))) {
            return false;
        }
    }
    return true;
}

static bool ValidateOptionalGuid(const DataMap& data, const wchar_t* name,
                                 const std::wstring** value) {
    auto found = data.find(name);
    if (found == data.end()) {
        *value = nullptr;
        return true;
    }
    if (!IsStandardGuid(found->second)) return false;
    *value = &found->second;
    return true;
}

static bool ValidateOptionalUInt32(const DataMap& data, const wchar_t* name,
                                   const std::wstring** value) {
    auto found = data.find(name);
    if (found == data.end()) {
        *value = nullptr;
        return true;
    }
    uint64_t parsed = 0;
    if (!ParseUnsigned(found->second, std::numeric_limits<uint32_t>::max(),
                       parsed))
        return false;
    *value = &found->second;
    return true;
}

static void PutSystemAttribute(Event& event, const std::wstring& xml,
                               const wchar_t* tag, const wchar_t* attribute,
                               const char* target) {
    const size_t start = xml.find(tag);
    if (start == std::wstring::npos) return;
    const size_t end = xml.find(L'>', start);
    if (end == std::wstring::npos) return;
    const std::wstring value = Attribute(xml, start, end, attribute);
    if (!value.empty()) event.fields[target] = WideToUtf8(value.c_str());
}

std::wstring BuildTaskSchedulerSubscriptionQuery() {
    std::wstring query = L"*[System[(";
    for (size_t i = 0; i < kTaskSchedulerEventIds.size(); ++i) {
        if (i != 0) query += L" or ";
        query += L"EventID=" + std::to_wstring(kTaskSchedulerEventIds[i]);
    }
    query += L")]]";
    return query;
}

bool ParseTaskSchedulerXml(const std::wstring& xml, Event& event) {
    uint64_t idValue = 0;
    std::wstring eventIdStr = ElementText(xml, L"<EventID");
    if (eventIdStr.empty() || !ParseUnsigned(eventIdStr, 65535, idValue))
        return false;
    unsigned int id = static_cast<unsigned int>(idValue);
    if (id != 106 && id != 140 && id != 141 &&
        id != 100 && id != 102 && id != 200 && id != 201 &&
        id != 202 && id != 203)
        return false;

    DataMap data = EventData(xml);
    const bool taskRuntimeEvent = id == 100 || id == 102;
    const bool actionEvent = id == 200 || id == 201 || id == 202 || id == 203;
    const std::wstring* taskInstanceId = nullptr;
    const std::wstring* taskActionName = nullptr;
    const std::wstring* taskResultCode = nullptr;
    const std::wstring* taskEnginePid = nullptr;
    const auto taskName = data.find(L"TaskName");
    if ((taskRuntimeEvent || actionEvent) &&
        (taskName == data.end() || taskName->second.empty()))
        return false;
    if (actionEvent) {
        const auto actionName = data.find(L"ActionName");
        if (actionName == data.end() || actionName->second.empty())
            return false;
        taskActionName = &actionName->second;
        if (!ValidateOptionalGuid(data, L"TaskInstanceId", &taskInstanceId) ||
            !ValidateOptionalUInt32(data, L"ResultCode",
                                    &taskResultCode) ||
            !ValidateOptionalUInt32(data, L"EnginePID",
                                    &taskEnginePid))
            return false;
    } else if (taskRuntimeEvent &&
               !ValidateOptionalGuid(data, L"InstanceId", &taskInstanceId)) {
        return false;
    }

    event = Event{};
    event.type = EDR_EVT_TASK_SCHEDULER;
    event.source = "taskscheduler_log";
    event.fields[field::kSource] = event.source;
    event.fields[field::kTaskSchedulerEventId] = std::to_string(id);

    switch (id) {
    case 100:
        event.fields[field::kOperationType] = "TASK_STARTED";
        break;
    case 102:
        event.fields[field::kOperationType] = "TASK_COMPLETED";
        break;
    case 106:
        event.fields[field::kOperationType] = "TASK_REGISTERED";
        break;
    case 140:
        event.fields[field::kOperationType] = "TASK_UPDATED";
        break;
    case 141:
        event.fields[field::kOperationType] = "TASK_DELETED";
        break;
    case 200:
        event.fields[field::kOperationType] = "TASK_ACTION_STARTED";
        break;
    case 201:
        event.fields[field::kOperationType] = "TASK_ACTION_COMPLETED";
        break;
    case 202:
        event.fields[field::kOperationType] = "TASK_ACTION_FAILED";
        break;
    case 203:
        event.fields[field::kOperationType] = "TASK_ACTION_START_FAILED";
        break;
    default:
        return false;
    }

    Put(event, data, L"TaskName", field::kTaskName);
    if (taskInstanceId != nullptr)
        event.fields[field::kTaskInstanceId] = WideToUtf8(taskInstanceId->c_str());
    if (taskActionName != nullptr)
        event.fields[field::kTaskActionName] = WideToUtf8(taskActionName->c_str());
    if (taskResultCode != nullptr)
        event.fields[field::kTaskResultCode] = WideToUtf8(taskResultCode->c_str());
    if (taskEnginePid != nullptr)
        event.fields[field::kTaskEnginePid] = WideToUtf8(taskEnginePid->c_str());
    PutSystemAttribute(event, xml, L"<Security", L"UserID",
                       field::kTaskEventUserSid);
    if (!actionEvent) {
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
