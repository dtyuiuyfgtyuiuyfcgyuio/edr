#include "dns_etw_parser.h"

#include <windows.h>
#include <algorithm>
#include <cmath>
#include <cstring>
#include <limits>

#include "edr_event.h"

namespace edr {
namespace {

bool ReadString(const DnsPropertyReader& read, const wchar_t* name,
                size_t maxChars, std::string& value, bool required = false) {
    std::vector<uint8_t> bytes;
    const auto status = read(name, bytes);
    if (status == DnsPropertyStatus::Missing) return !required;
    if (status != DnsPropertyStatus::Present ||
        bytes.size() < sizeof(wchar_t) || bytes.size() > kDnsMaxPropertyBytes ||
        bytes.size() % sizeof(wchar_t) != 0) return false;
    const size_t chars = bytes.size() / sizeof(wchar_t);
    if (chars - 1 > maxChars) return false;
    std::wstring wide(chars, L'\0');
    std::memcpy(wide.data(), bytes.data(), bytes.size());
    if (wide.back() != L'\0' || wide.find(L'\0') != chars - 1) return false;
    wide.pop_back();
    if (wide.empty()) return !required;
    const int length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
        wide.data(), static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
    if (length <= 0) return false;
    value.resize(static_cast<size_t>(length));
    return WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide.data(),
        static_cast<int>(wide.size()), value.data(), length, nullptr, nullptr) == length;
}

bool ReadUInt32(const DnsPropertyReader& read, const wchar_t* name,
                uint32_t& value, bool& present) {
    std::vector<uint8_t> bytes;
    const auto status = read(name, bytes);
    present = status == DnsPropertyStatus::Present;
    if (status == DnsPropertyStatus::Missing) return true;
    if (!present || bytes.size() != sizeof(value)) return false;
    std::memcpy(&value, bytes.data(), sizeof(value));
    return true;
}

std::string DnsType(uint32_t type) {
    switch (type) {
    case 1: return "A";
    case 2: return "NS";
    case 5: return "CNAME";
    case 6: return "SOA";
    case 12: return "PTR";
    case 15: return "MX";
    case 16: return "TXT";
    case 28: return "AAAA";
    case 33: return "SRV";
    case 255: return "ANY";
    default: return std::to_string(type);
    }
}

void EnrichQueryName(Event& event, std::string name) {
    unsigned counts[256] = {};
    int labels = 1, maxLabel = 0, label = 0;
    for (unsigned char ch : name) {
        if (ch >= 'A' && ch <= 'Z') ch += 'a' - 'A';
        ++counts[ch];
        if (ch == '.') { ++labels; maxLabel = std::max(maxLabel, label); label = 0; }
        else ++label;
    }
    double entropy = 0;
    for (const auto count : counts) {
        if (!count) continue;
        const double probability = static_cast<double>(count) / name.size();
        entropy -= probability * std::log2(probability);
    }
    event.fields[field::kDnsEntropy] = std::to_string(entropy);
    event.fields[field::kDnsSubdomainCount] = std::to_string(labels);
    event.fields[field::kDnsMaxLabelLength] = std::to_string(std::max(maxLabel, label));
}

} // namespace

bool ParseDnsEtwEvent(uint16_t id, uint8_t version, uint32_t providerPid,
                      uint64_t timestamp100ns, const DnsPropertyReader& read,
                      Event& event) {
    if (!read || (id != 3008 && id != 3009) ||
        (id == 3008 ? version != 0 : version > 2)) return false;
    try {
        Event parsed;
        parsed.type = EDR_EVT_DNS_QUERY;
        parsed.ts100ns = timestamp100ns;
        parsed.pid = providerPid;
        parsed.source = "dns_etw";
        parsed.fields[field::kSource] = parsed.source;
        parsed.fields[field::kType] = "DNS_QUERY";
        parsed.fields[field::kTimestampProvenance] = "etw_system_time";
        parsed.fields["dns_event_id"] = std::to_string(id);
        parsed.fields["dns_event_version"] = std::to_string(version);
        parsed.fields["dns_provider_pid"] = std::to_string(providerPid);
        parsed.fields["dns_pid_provenance"] = "event_header";
        parsed.fields["dns_phase"] = id == 3008 ? "completed" : "started";
        std::string name;
        if (!ReadString(read, L"QueryName", 1024, name, true)) return false;
        parsed.fields[field::kDnsQueryName] = name;

        if (id == 3008) {
            EnrichQueryName(parsed, name);
            uint32_t type = 0, status = 0;
            bool present = false;
            if (!ReadUInt32(read, L"QueryType", type, present)) return false;
            if (present && type) parsed.fields[field::kDnsQueryType] = DnsType(type);
            if (!ReadUInt32(read, L"QueryStatus", status, present)) return false;
            if (present) parsed.fields[field::kDnsQueryStatus] = std::to_string(status);
            std::string answers;
            if (!ReadString(read, L"QueryResults", 16384, answers)) return false;
            if (!answers.empty()) parsed.fields[field::kDnsAnswers] = answers;
        } else {
            parsed.disposition = EventDisposition::ReportOnly;
            std::string server, local;
            if (!ReadString(read, L"DNSServerAddress", 4096, server) ||
                !ReadString(read, L"LocalAddress", 4096, local)) return false;
            if (!server.empty()) parsed.fields[field::kDnsServerIp] = server;
            if (!local.empty()) parsed.fields[field::kSrcIp] = local;
            if (version >= 1) {
                uint32_t clientPid = 0;
                bool present = false;
                if (!ReadUInt32(read, L"ClientPID", clientPid, present) ||
                    clientPid == (std::numeric_limits<uint32_t>::max)()) return false;
                if (present && clientPid != 0) {
                    parsed.pid = clientPid;
                    parsed.fields[field::kSourcePid] = std::to_string(clientPid);
                    parsed.fields["dns_pid_provenance"] = "client_pid";
                }
            }
        }
        event = std::move(parsed);
        return true;
    } catch (...) {
        return false;
    }
}

} // namespace edr
