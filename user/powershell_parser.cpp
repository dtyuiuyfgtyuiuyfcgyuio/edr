#include "powershell_parser.h"

#include <windows.h>

#include <map>

#include "config.h"
#include "edr_event.h"
#include "xml_util.h"

namespace edr {

using DataMap = std::map<std::wstring, std::wstring>;

static void Put(Event& event, const DataMap& data, const wchar_t* source,
                const char* target) {
    auto it = data.find(source);
    if (it != data.end() && !it->second.empty())
        event.fields[target] = WideToUtf8(it->second.c_str());
}

static void PutSystemAttribute(Event& event, const std::wstring& xml,
                               const wchar_t* tag, const wchar_t* attribute,
                               const char* target) {
    size_t start = xml.find(tag);
    if (start == std::wstring::npos) return;
    size_t end = xml.find(L'>', start);
    if (end == std::wstring::npos) return;
    std::wstring value = Attribute(xml, start, end, attribute);
    if (!value.empty()) event.fields[target] = WideToUtf8(value.c_str());
}

bool ParsePowerShellXml(const std::wstring& xml, size_t maxScriptChars,
                        Event& event) {
    if (maxScriptChars == 0) return false;

    uint64_t id = 0;
    std::wstring eventId = ElementText(xml, L"<EventID");
    if (!ParseUnsigned(eventId, 65535, id) || id != 4104) return false;

    DataMap data = EventData(xml);
    auto text = data.find(L"ScriptBlockText");
    auto numberText = data.find(L"MessageNumber");
    auto totalText = data.find(L"MessageTotal");
    uint64_t messageNumber = 0, messageTotal = 0;
    if (text == data.end() || text->second.empty() ||
        numberText == data.end() || totalText == data.end() ||
        !ParseUnsigned(numberText->second, 65535, messageNumber) ||
        !ParseUnsigned(totalText->second, 65535, messageTotal) ||
        messageNumber == 0 || messageTotal == 0 ||
        messageNumber > messageTotal) {
        return false;
    }

    event = Event{};
    event.type = EDR_EVT_POWERSHELL_SCRIPT;
    event.source = "powershell_log";
    event.fields[field::kType] = EventTypeName(event.type);
    event.fields[field::kSource] = event.source;
    event.fields[field::kOperationType] = "SCRIPT_BLOCK";
    event.fields[field::kPowerShellEventId] = "4104";
    event.fields[field::kScriptMessageNumber] =
        std::to_string(messageNumber);
    event.fields[field::kScriptMessageTotal] = std::to_string(messageTotal);
    event.fields[field::kScriptBlockComplete] =
        messageTotal == 1 ? "true" : "false";

    std::wstring script = text->second;
    bool truncated = script.size() > maxScriptChars;
    if (truncated) {
        size_t length = maxScriptChars;
        if (length > 0 && length < script.size() &&
            script[length - 1] >= 0xD800 && script[length - 1] <= 0xDBFF &&
            script[length] >= 0xDC00 && script[length] <= 0xDFFF) {
            --length;
        }
        script.resize(length);
        event.flags |= EDR_FLAG_TRUNCATED;
    }
    event.fields[field::kScriptBlockText] = WideToUtf8(script.c_str(),
                                                        script.size());
    event.fields[field::kScriptBlockTruncated] = truncated ? "true" : "false";
    Put(event, data, L"ScriptBlockId", field::kScriptBlockId);
    Put(event, data, L"Path", field::kScriptPath);
    PutSystemAttribute(event, xml, L"<Security", L"UserID", field::kUserId);

    size_t execution = xml.find(L"<Execution");
    if (execution != std::wstring::npos) {
        size_t end = xml.find(L'>', execution);
        if (end != std::wstring::npos) {
            std::wstring processId = Attribute(xml, execution, end, L"ProcessID");
            uint64_t pid = 0;
            if (ParseUnsigned(processId, 0xFFFFFFFFULL, pid)) {
                event.pid = static_cast<uint32_t>(pid);
                event.fields[field::kPid] = std::to_string(pid);
            }
        }
    }

    std::wstring timestamp = SourceTimestamp(xml);
    if (!timestamp.empty()) {
        event.fields[field::kSourceTimestamp] = WideToUtf8(timestamp.c_str());
        event.ts100ns = ParseSystemTime100ns(timestamp);
    }
    if (event.ts100ns != 0) {
        event.fields[field::kTimestampProvenance] =
            "powershell_system_time";
    } else {
        FILETIME now = {};
        GetSystemTimePreciseAsFileTime(&now);
        event.ts100ns = (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
                        now.dwLowDateTime;
        event.fields[field::kTimestampProvenance] =
            "collector_time_fallback";
    }
    return true;
}

} // namespace edr
