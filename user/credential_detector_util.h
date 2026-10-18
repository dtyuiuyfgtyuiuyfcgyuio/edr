/*
 * credential_detector_util.h - Internal bounded normalization helpers shared
 * by credential-correlation detectors. Not part of the public event API.
 */
#ifndef EDR_CREDENTIAL_DETECTOR_UTIL_H
#define EDR_CREDENTIAL_DETECTOR_UTIL_H

#include <winsock2.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

namespace edr::credential_detail {

constexpr size_t kMaxSourceIpChars = 64;
constexpr size_t kMaxDomainChars = 256;
constexpr size_t kMaxUserChars = 256;
constexpr size_t kMaxServiceChars = 512;

inline std::string LowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

inline bool TrimBounded(const std::string& input, size_t maximum,
                        std::string& output) {
    if (input.size() > maximum) return false;
    size_t first = 0;
    while (first < input.size() &&
           std::isspace(static_cast<unsigned char>(input[first])) != 0)
        ++first;
    size_t last = input.size();
    while (last > first &&
           std::isspace(static_cast<unsigned char>(input[last - 1])) != 0)
        --last;
    output.assign(input, first, last - first);
    if (output.empty()) return false;
    for (unsigned char value : output) {
        if (value < 0x20 || value == 0x7f) return false;
    }
    return true;
}

inline bool IsIpv4Rejected(const IN_ADDR& address) {
    const auto* bytes = reinterpret_cast<const unsigned char*>(&address.S_un.S_addr);
    return bytes[0] == 0 || bytes[0] == 127 || bytes[0] >= 224;
}

inline bool NormalizeSourceIp(const std::string& input, std::string& output) {
    std::string value;
    if (!TrimBounded(input, kMaxSourceIpChars, value) || value == "-")
        return false;

    IN_ADDR ipv4 = {};
    if (InetPtonA(AF_INET, value.c_str(), &ipv4) == 1) {
        if (IsIpv4Rejected(ipv4)) return false;
        char buffer[INET_ADDRSTRLEN] = {};
        if (InetNtopA(AF_INET, &ipv4, buffer, sizeof(buffer)) == nullptr)
            return false;
        output = buffer;
        return true;
    }

    IN6_ADDR ipv6 = {};
    if (InetPtonA(AF_INET6, value.c_str(), &ipv6) != 1) return false;
    const auto* bytes = reinterpret_cast<const unsigned char*>(&ipv6);
    bool unspecified = true;
    for (size_t i = 0; i < 16; ++i) unspecified = unspecified && bytes[i] == 0;
    bool loopback = true;
    for (size_t i = 0; i < 15; ++i) loopback = loopback && bytes[i] == 0;
    loopback = loopback && bytes[15] == 1;
    if (unspecified || loopback || bytes[0] == 0xff) return false;

    bool mapped = true;
    for (size_t i = 0; i < 10; ++i) mapped = mapped && bytes[i] == 0;
    mapped = mapped && bytes[10] == 0xff && bytes[11] == 0xff;
    if (mapped) {
        IN_ADDR mappedIpv4 = {};
        std::memcpy(&mappedIpv4, bytes + 12, sizeof(mappedIpv4));
        if (IsIpv4Rejected(mappedIpv4)) return false;
        char buffer[INET_ADDRSTRLEN] = {};
        if (InetNtopA(AF_INET, &mappedIpv4, buffer, sizeof(buffer)) == nullptr)
            return false;
        output = buffer;
        return true;
    }

    char buffer[INET6_ADDRSTRLEN] = {};
    if (InetNtopA(AF_INET6, &ipv6, buffer, sizeof(buffer)) == nullptr)
        return false;
    output = LowerAscii(buffer);
    return true;
}

inline uint64_t SaturatingAdd(uint64_t value, uint64_t amount) {
    constexpr uint64_t maximum = ~static_cast<uint64_t>(0);
    return amount > maximum - value ? maximum : value + amount;
}

} // namespace edr::credential_detail

#endif /* EDR_CREDENTIAL_DETECTOR_UTIL_H */
