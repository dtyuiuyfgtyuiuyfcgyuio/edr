#ifndef EDR_DNS_ETW_PARSER_H
#define EDR_DNS_ETW_PARSER_H

#include <cstdint>
#include <functional>
#include <vector>

#include "event_bus.h"

namespace edr {

enum class DnsPropertyStatus { Missing, Present, Invalid };
using DnsPropertyReader = std::function<DnsPropertyStatus(
    const wchar_t*, std::vector<uint8_t>&)>;
inline constexpr size_t kDnsMaxPropertyBytes = 64 * 1024;

/* Schema: Microsoft-Windows-DNS-Client 3008/v0 (completed), 3009/v0-v2
 * (network query started). The reader returns decoded TDH property bytes.
 * Starts are report-only so start+completion cannot count as two queries.
 * Output is changed only on success; malformed present fields fail closed. */
bool ParseDnsEtwEvent(uint16_t id, uint8_t version, uint32_t providerPid,
                      uint64_t timestamp100ns, const DnsPropertyReader& read,
                      Event& event);

} // namespace edr
#endif
