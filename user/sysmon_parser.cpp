#include "sysmon_parser.h"

#include <windows.h>

#include <limits>
#include <map>
#include <cstdio>

#include "config.h"
#include "edr_event.h"
#include "process_access.h"
#include "xml_util.h"

namespace edr {

using DataMap = std::map<std::wstring, std::wstring>;

static std::string LowerAscii(std::string value) {
    for (char& ch : value) {
        if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch - 'A' + 'a');
    }
    return value;
}

static bool Number(const DataMap& data, const wchar_t* name, uint64_t maximum,
                   uint32_t& result, bool required = true) {
    auto it = data.find(name);
    if (it == data.end() || it->second.empty()) return !required;
    uint64_t parsed = 0;
    if (!ParseUnsigned(it->second, maximum, parsed)) return false;
    result = static_cast<uint32_t>(parsed);
    return true;
}

static void Put(Event& event, const DataMap& data, const wchar_t* source,
                const char* target) {
    auto it = data.find(source);
    if (it != data.end() && !it->second.empty()) {
        event.fields[target] = WideToUtf8(it->second.c_str());
    }
}

static void PutActor(Event& event, const DataMap& data) {
    Put(event, data, L"Image", field::kImage);
    Put(event, data, L"Image", field::kActorImage);
    Put(event, data, L"CommandLine", field::kCommandLine);
}

static bool SetPid(Event& event, const DataMap& data, bool required = true) {
    if (!Number(data, L"ProcessId", std::numeric_limits<uint32_t>::max(),
                event.pid, required)) return false;
    if (event.pid != 0 || required) event.fields[field::kPid] = std::to_string(event.pid);
    return !required || event.pid != 0;
}

static void SetIdentity(Event& event, const DataMap& data) {
    auto guid = data.find(L"ProcessGuid");
    if (guid != data.end() && !guid->second.empty()) {
        event.processIdentity = WideToUtf8(guid->second.c_str());
    }
}

/* Sysmon's process-create UtcTime is the process creation instant. Only map
 * it to FILETIME when all seven fractional digits are present; accepting the
 * common millisecond-only form would equate distinct sub-millisecond process
 * instances with the same rounded timestamp. Event System/TimeCreated is the
 * record timestamp and must never be used as a creation-time substitute. */
static uint64_t ExactSysmonProcessStartTime(const std::wstring& value) {
    if (value.size() == 28 && value[10] == L'T' && value[27] == L'Z')
        return ParseSystemTime100ns(value);
    if (value.size() != 27 || value[4] != L'-' || value[7] != L'-' ||
        value[10] != L' ' || value[13] != L':' || value[16] != L':' ||
        value[19] != L'.') return 0;

    auto digits = [&](size_t offset, size_t count) -> int {
        int result = 0;
        for (size_t i = 0; i < count; ++i) {
            const wchar_t ch = value[offset + i];
            if (ch < L'0' || ch > L'9') return -1;
            result = result * 10 + static_cast<int>(ch - L'0');
        }
        return result;
    };
    const int year = digits(0, 4), month = digits(5, 2), day = digits(8, 2);
    const int hour = digits(11, 2), minute = digits(14, 2);
    const int second = digits(17, 2), fraction = digits(20, 7);
    if (year < 0 || month < 0 || day < 0 || hour < 0 || minute < 0 ||
        second < 0 || fraction < 0) return 0;

    SYSTEMTIME st = {};
    st.wYear = static_cast<WORD>(year);
    st.wMonth = static_cast<WORD>(month);
    st.wDay = static_cast<WORD>(day);
    st.wHour = static_cast<WORD>(hour);
    st.wMinute = static_cast<WORD>(minute);
    st.wSecond = static_cast<WORD>(second);
    FILETIME ft = {};
    if (!SystemTimeToFileTime(&st, &ft)) return 0;
    return ((static_cast<uint64_t>(ft.dwHighDateTime) << 32) |
            ft.dwLowDateTime) + static_cast<uint64_t>(fraction);
}

static void PutDriverSignature(Event& event, const DataMap& data) {
    Put(event, data, L"Signature", field::kSignerSubject);

    std::string signedValue;
    auto signedIt = data.find(L"Signed");
    if (signedIt != data.end())
        signedValue = LowerAscii(WideToUtf8(signedIt->second.c_str()));

    std::string status;
    auto statusIt = data.find(L"SignatureStatus");
    if (statusIt != data.end())
        status = LowerAscii(WideToUtf8(statusIt->second.c_str()));

    if (signedValue == "false") {
        event.fields[field::kSignatureStatus] = "unsigned";
    } else if (status == "valid" ||
               (signedValue == "true" && status.empty())) {
        event.fields[field::kSignatureStatus] = "trusted";
    } else if (!status.empty()) {
        event.fields[field::kSignatureStatus] = "invalid";
    }
}

static bool PutPipeName(Event& event, const DataMap& data) {
    auto it = data.find(L"PipeName");
    if (it == data.end() || it->second.empty()) return false;

    std::string pipeName = WideToUtf8(it->second.c_str());
    std::string lower = LowerAscii(pipeName);
    const std::string prefixes[] = {
        "\\\\.\\pipe\\", "\\device\\namedpipe\\"
    };
    for (const std::string& prefix : prefixes) {
        if (lower.rfind(prefix, 0) == 0) {
            pipeName.erase(0, prefix.size());
            break;
        }
    }
    while (!pipeName.empty() &&
           (pipeName.front() == '\\' || pipeName.front() == '/')) {
        pipeName.erase(pipeName.begin());
    }
    if (pipeName.empty()) return false;
    event.fields[field::kPipeName] = pipeName;
    return true;
}

std::wstring SysmonSubscriptionQuery(bool imageLoad, bool processAccess,
                                    bool remoteThread, bool namedPipe) {
    std::wstring query =
        L"*[System[(EventID=1 or EventID=2 or EventID=3 or EventID=5 or EventID=6";
    if (imageLoad) query += L" or EventID=7";
    if (processAccess) query += L" or EventID=10";
    if (remoteThread) query += L" or EventID=8";
    if (namedPipe) query += L" or EventID=17 or EventID=18";
    query += L" or EventID=11 or EventID=12 or EventID=13 or "
             L"EventID=14 or EventID=22 or EventID=25)]]";
    return query;
}

static bool MapEvent(unsigned int id, const DataMap& data, Event& event) {
    switch (id) {
    case 1:
        event.type = EDR_EVT_PROCESS_START;
        if (!SetPid(event, data)) return false;
        if (!Number(data, L"ParentProcessId", std::numeric_limits<uint32_t>::max(),
                    event.ppid, false)) return false;
        if (event.ppid != 0) event.fields[field::kPpid] = std::to_string(event.ppid);
        PutActor(event, data);
        Put(event, data, L"ParentImage", field::kParentImage);
        {
            auto parentGuid = data.find(L"ParentProcessGuid");
            if (parentGuid != data.end())
                event.parentProcessIdentity = WideToUtf8(parentGuid->second.c_str());
        }
        break;
    case 2:
        event.type = EDR_EVT_FILE_INTEGRITY;
        if (!SetPid(event, data)) return false;
        PutActor(event, data);
        Put(event, data, L"TargetFilename", field::kFilePath);
        Put(event, data, L"TargetFilename", field::kTargetPath);
        Put(event, data, L"CreationUtcTime", field::kFileCreationTime);
        Put(event, data, L"PreviousCreationUtcTime",
            field::kFilePreviousCreationTime);
        Put(event, data, L"User", field::kUserId);
        if (event.fields.find(field::kTargetPath) == event.fields.end() ||
            event.fields.find(field::kFileCreationTime) == event.fields.end() ||
            event.fields.find(field::kFilePreviousCreationTime) ==
                event.fields.end()) return false;
        break;
    case 3: {
        event.type = EDR_EVT_NET_CONNECT;
        if (!SetPid(event, data)) return false;
        uint32_t sourcePort = 0, destinationPort = 0;
        if (!Number(data, L"SourcePort", 65535, sourcePort) ||
            !Number(data, L"DestinationPort", 65535, destinationPort)) return false;
        PutActor(event, data);
        Put(event, data, L"Protocol", field::kProtocol);
        Put(event, data, L"SourceIp", field::kSrcIp);
        Put(event, data, L"DestinationIp", field::kDstIp);
        event.fields[field::kSrcPort] = std::to_string(sourcePort);
        event.fields[field::kDstPort] = std::to_string(destinationPort);
        break;
    }
    case 5:
        event.type = EDR_EVT_PROCESS_STOP;
        if (!SetPid(event, data)) return false;
        PutActor(event, data);
        break;
    case 25: {
        event.type = EDR_EVT_PROCESS_TAMPERING;
        if (!SetPid(event, data)) return false;
        PutActor(event, data);
        if (event.fields.find(field::kImage) == event.fields.end()) return false;
        auto tamperingType = data.find(L"Type");
        if (tamperingType == data.end() || tamperingType->second.empty())
            return false;
        event.fields[field::kProcessTamperingType] =
            WideToUtf8(tamperingType->second.c_str());
        Put(event, data, L"User", field::kUserId);
        break;
    }
    case 6:
        event.type = EDR_EVT_IMAGE_LOAD;
        Put(event, data, L"ImageLoaded", field::kImageLoaded);
        Put(event, data, L"ImageLoaded", field::kTargetImage);
        Put(event, data, L"ImageLoaded", field::kTargetPath);
        Put(event, data, L"Hashes", field::kHashes);
        PutDriverSignature(event, data);
        event.fields[field::kImageLoadType] = "load";
        if (event.fields.find(field::kImageLoaded) == event.fields.end())
            return false;
        break;
    case 7:
        event.type = EDR_EVT_IMAGE_LOAD;
        if (!SetPid(event, data)) return false;
        PutActor(event, data);
        Put(event, data, L"ImageLoaded", field::kTargetImage);
        Put(event, data, L"ImageLoaded", field::kTargetPath);
        Put(event, data, L"Hashes", field::kHashes);
        if (event.fields.find(field::kTargetImage) == event.fields.end()) return false;
        break;
    case 8: {
        event.type = EDR_EVT_THREAD_CREATE;
        uint32_t sourcePid = 0, targetPid = 0, newThreadId = 0;
        if (!Number(data, L"SourceProcessId", std::numeric_limits<uint32_t>::max(),
                    sourcePid) || sourcePid == 0 ||
            !Number(data, L"TargetProcessId", std::numeric_limits<uint32_t>::max(),
                    targetPid) || targetPid == 0 ||
            !Number(data, L"NewThreadId", std::numeric_limits<uint32_t>::max(),
                    newThreadId) || newThreadId == 0) return false;
        event.pid = sourcePid;
        event.fields[field::kPid] = std::to_string(sourcePid);
        event.fields[field::kSourcePid] = std::to_string(sourcePid);
        event.fields[field::kTargetPid] = std::to_string(targetPid);
        event.fields[field::kThreadId] = std::to_string(newThreadId);
        Put(event, data, L"SourceImage", field::kImage);
        Put(event, data, L"SourceImage", field::kActorImage);
        Put(event, data, L"TargetImage", field::kTargetImage);
        Put(event, data, L"SourceProcessGUID", field::kSourceProcessGuid);
        Put(event, data, L"TargetProcessGUID", field::kTargetProcessGuid);
        auto sourceGuid = event.fields.find(field::kSourceProcessGuid);
        auto targetGuid = event.fields.find(field::kTargetProcessGuid);
        if (sourceGuid == event.fields.end() || targetGuid == event.fields.end())
            return false;
        sourceGuid->second = LowerAscii(sourceGuid->second);
        targetGuid->second = LowerAscii(targetGuid->second);
        event.processIdentity = sourceGuid->second;
        Put(event, data, L"StartAddress", field::kStartAddress);
        {
            auto module = data.find(L"StartModule");
            event.fields[field::kStartModule] =
                module != data.end() ? WideToUtf8(module->second.c_str()) : std::string();
            auto function = data.find(L"StartFunction");
            event.fields[field::kStartFunction] =
                function != data.end() ? WideToUtf8(function->second.c_str()) : std::string();
        }
        event.fields[field::kRemoteThread] =
            sourcePid != targetPid ? "true" : "false";
        break;
    }
    case 10: {
        event.type = EDR_EVT_PROCESS_ACCESS;
        uint32_t sourcePid = 0, targetPid = 0, grantedAccess = 0;
        if (!Number(data, L"SourceProcessId", std::numeric_limits<uint32_t>::max(),
                    sourcePid) || sourcePid == 0 ||
            !Number(data, L"TargetProcessId", std::numeric_limits<uint32_t>::max(),
                    targetPid) || targetPid == 0) return false;
        auto access = data.find(L"GrantedAccess");
        if (access == data.end() || !ParseHex32(access->second, grantedAccess))
            return false;
        event.pid = sourcePid;
        event.fields[field::kPid] = std::to_string(sourcePid);
        event.fields[field::kSourcePid] = std::to_string(sourcePid);
        event.fields[field::kTargetPid] = std::to_string(targetPid);
        Put(event, data, L"SourceImage", field::kImage);
        Put(event, data, L"SourceImage", field::kActorImage);
        Put(event, data, L"TargetImage", field::kTargetImage);
        if (event.fields.find(field::kImage) == event.fields.end() ||
            event.fields.find(field::kTargetImage) == event.fields.end()) return false;
        Put(event, data, L"SourceProcessGUID", field::kSourceProcessGuid);
        Put(event, data, L"TargetProcessGUID", field::kTargetProcessGuid);
        Put(event, data, L"CallTrace", field::kCallTrace);
        auto sourceGuid = event.fields.find(field::kSourceProcessGuid);
        auto targetGuid = event.fields.find(field::kTargetProcessGuid);
        if (sourceGuid == event.fields.end() || targetGuid == event.fields.end())
            return false;
        sourceGuid->second = LowerAscii(sourceGuid->second);
        targetGuid->second = LowerAscii(targetGuid->second);
        event.processIdentity = sourceGuid->second;
        ApplyProcessAccessFields(event, grantedAccess);
        bool crossProcess = sourcePid != targetPid;
        auto sourceGuidData = data.find(L"SourceProcessGUID");
        auto targetGuidData = data.find(L"TargetProcessGUID");
        if (sourceGuidData != data.end() && targetGuidData != data.end() &&
            !sourceGuidData->second.empty() && !targetGuidData->second.empty()) {
            crossProcess = _wcsicmp(sourceGuidData->second.c_str(),
                                    targetGuidData->second.c_str()) != 0;
        }
        event.fields[field::kCrossProcess] = crossProcess ? "true" : "false";
        break;
    }
    case 11:
        event.type = EDR_EVT_FILE_CREATE;
        if (!SetPid(event, data)) return false;
        PutActor(event, data);
        Put(event, data, L"TargetFilename", field::kFilePath);
        Put(event, data, L"TargetFilename", field::kTargetPath);
        if (event.fields.find(field::kTargetPath) == event.fields.end()) return false;
        break;
    case 12:
    case 13:
    case 14:
        event.type = EDR_EVT_REG_WRITE;
        if (!SetPid(event, data)) return false;
        PutActor(event, data);
        Put(event, data, L"EventType", field::kRegOperation);
        if (event.fields.find(field::kRegOperation) == event.fields.end()) return false;
        Put(event, data, L"TargetObject", field::kRegKey);
        Put(event, data, L"Details", field::kRegValue);
        Put(event, data, L"OldName", field::kRegOldTarget);
        Put(event, data, L"NewName", field::kRegNewTarget);
        Put(event, data, L"TargetObject", field::kTargetPath);
        if (event.fields.find(field::kRegKey) == event.fields.end()) return false;
        if (id == 14) {
            event.fields[field::kRegOldTarget] = event.fields[field::kRegKey];
            if (event.fields.find(field::kRegNewTarget) == event.fields.end()) return false;
        }
        break;
    case 17:
    case 18:
        event.type = EDR_EVT_NAMED_PIPE;
        if (!SetPid(event, data)) return false;
        PutActor(event, data);
        if (!PutPipeName(event, data)) return false;
        event.fields[field::kPipeOperation] =
            id == 17 ? "created" : "connected";
        break;
    case 22:
        event.type = EDR_EVT_DNS_QUERY;
        if (!SetPid(event, data)) return false;
        PutActor(event, data);
        Put(event, data, L"QueryName", field::kTargetHost);
        Put(event, data, L"QueryResults", field::kQueryResults);
        Put(event, data, L"QueryStatus", field::kQueryStatus);
        if (event.fields.find(field::kTargetHost) == event.fields.end()) return false;
        break;
    default:
        return false;
    }
    SetIdentity(event, data);
    return true;
}

bool ParseSysmonXml(const std::wstring& xml, Event& event) {
    uint64_t idValue = 0;
    if (!ParseUnsigned(ElementText(xml, L"<EventID"), 65535, idValue)) return false;
    unsigned int id = static_cast<unsigned int>(idValue);
    if (id != 1 && id != 2 && id != 3 && id != 5 && id != 6 && id != 7 &&
        id != 8 && id != 10 &&
        id != 11 && id != 12 && id != 13 && id != 14 &&
        id != 17 && id != 18 && id != 22 && id != 25) return false;

    event = Event{};
    DataMap data = EventData(xml);
    if (!MapEvent(id, data, event)) return false;
    if (id == 1) {
        auto utcTime = data.find(L"UtcTime");
        if (utcTime != data.end())
            event.processStartTime100ns =
                ExactSysmonProcessStartTime(utcTime->second);
    }
    event.source = "sysmon";
    event.fields[field::kSource] = event.source;
    event.fields[field::kType] = EventTypeName(event.type);
    event.fields[field::kSysmonEventId] = std::to_string(id);

    size_t eventId = xml.find(L"<EventID");
    size_t eventIdEnd = eventId == std::wstring::npos ? eventId : xml.find(L'>', eventId);
    if (eventIdEnd != std::wstring::npos) {
        std::wstring version = Attribute(xml, eventId, eventIdEnd, L"Version");
        if (version.empty()) version = ElementText(xml, L"<Version");
        if (!version.empty()) event.fields[field::kSysmonVersion] = WideToUtf8(version.c_str());
    }
    Put(event, data, L"RuleName", field::kSysmonRuleName);

    std::wstring timestamp = SourceTimestamp(xml);
    if (!timestamp.empty()) {
        event.fields[field::kSourceTimestamp] = WideToUtf8(timestamp.c_str());
        event.ts100ns = ParseSystemTime100ns(timestamp);
    }
    if (event.ts100ns != 0) {
        event.fields[field::kTimestampProvenance] = "sysmon_system_time";
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
