#include "rdp_parser.h"

#include <windows.h>

#include <limits>
#include <map>

#include "config.h"
#include "edr_event.h"
#include "xml_util.h"

namespace edr {
namespace {

using DataMap = std::map<std::wstring, std::wstring>;

void PutExecutionPid(Event& event, const std::wstring& xml) {
    size_t execution = xml.find(L"<Execution");
    if (execution == std::wstring::npos) return;
    size_t end = xml.find(L'>', execution);
    if (end == std::wstring::npos) return;
    std::wstring value = Attribute(xml, execution, end, L"ProcessID");
    uint64_t pid = 0;
    if (ParseUnsigned(value, std::numeric_limits<uint32_t>::max(), pid)) {
        event.pid = static_cast<uint32_t>(pid);
        event.fields[field::kPid] = std::to_string(event.pid);
    }
}

void PutTimestamp(Event& event, const std::wstring& xml) {
    std::wstring timestamp = SourceTimestamp(xml);
    if (!timestamp.empty()) {
        event.fields[field::kSourceTimestamp] = WideToUtf8(timestamp.c_str());
        event.ts100ns = ParseSystemTime100ns(timestamp);
    }
    if (event.ts100ns != 0) {
        event.fields[field::kTimestampProvenance] = "rdp_system_time";
        return;
    }
    FILETIME now = {};
    GetSystemTimePreciseAsFileTime(&now);
    event.ts100ns = (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
                    now.dwLowDateTime;
    event.fields[field::kTimestampProvenance] = "collector_time_fallback";
}

void SplitUser(Event& event, const std::string& combined) {
    if (combined.empty()) return;
    size_t slash = combined.find_last_of("\\/");
    if (slash == std::string::npos) {
        event.fields[field::kRdpUser] = combined;
        return;
    }
    if (slash > 0)
        event.fields[field::kRdpDomain] = combined.substr(0, slash);
    if (slash + 1 < combined.size())
        event.fields[field::kRdpUser] = combined.substr(slash + 1);
}

std::wstring UserDataParam(const std::wstring& xml, const wchar_t* name) {
    return ElementText(xml, std::wstring(L"<") + name);
}

const char* ActionForId(unsigned int id) {
    switch (id) {
    case 21: return "logon";
    case 23: return "logoff";
    case 24: return "disconnect";
    case 25: return "reconnect";
    case 1149: return "auth_success";
    default: return "";
    }
}

} // namespace

bool ParseRdpXml(const std::wstring& xml, Event& event) {
    uint64_t idValue = 0;
    std::wstring eventId = ElementText(xml, L"<EventID");
    if (!ParseUnsigned(eventId, 65535, idValue)) return false;
    unsigned int id = static_cast<unsigned int>(idValue);
    const char* action = ActionForId(id);
    if (action[0] == '\0') return false;

    event = Event{};
    event.type = EDR_EVT_RDP_SESSION;
    event.source = "rdp_log";
    event.fields[field::kSource] = event.source;
    event.fields[field::kRdpEventId] = std::to_string(id);
    event.fields[field::kRdpAction] = action;
    event.fields[field::kOperationType] = action;

    DataMap data = EventData(xml);
    auto put = [&](const wchar_t* name, const char* fieldName) {
        auto it = data.find(name);
        if (it != data.end() && !it->second.empty())
            event.fields[fieldName] = WideToUtf8(it->second.c_str());
    };
    put(L"User", field::kRdpUser);
    put(L"SessionID", field::kRdpSessionId);
    put(L"SessionId", field::kRdpSessionId);
    put(L"Address", field::kRdpSourceIp);
    put(L"ClientAddress", field::kRdpSourceIp);
    put(L"SessionName", field::kRdpSessionName);

    if (id == 1149) {
        std::wstring user = UserDataParam(xml, L"Param1");
        std::wstring domain = UserDataParam(xml, L"Param2");
        std::wstring address = UserDataParam(xml, L"Param3");
        if (!user.empty())
            event.fields[field::kRdpUser] = WideToUtf8(user.c_str());
        if (!domain.empty())
            event.fields[field::kRdpDomain] = WideToUtf8(domain.c_str());
        if (!address.empty())
            event.fields[field::kRdpSourceIp] = WideToUtf8(address.c_str());
    }

    auto userIt = event.fields.find(field::kRdpUser);
    if (userIt != event.fields.end() &&
        event.fields.find(field::kRdpDomain) == event.fields.end()) {
        SplitUser(event, userIt->second);
    }

    event.fields[field::kType] = EventTypeName(event.type);
    PutExecutionPid(event, xml);
    PutTimestamp(event, xml);
    return true;
}

} // namespace edr
