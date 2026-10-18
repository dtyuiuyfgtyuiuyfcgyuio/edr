#ifndef EDR_SECURITY_LOG_SUBSCRIPTION_H
#define EDR_SECURITY_LOG_SUBSCRIPTION_H

#include <array>
#include <cstdint>
#include <string>

namespace edr {

/* Keep the subscription contract reviewable and test it against every parser
 * ID. A parser-only event is otherwise invisible on the live collector path. */
inline constexpr std::array<uint16_t, 21> kSecurityLogEventIds = {
    1100, 1102, 1104, 4616, 4624, 4625, 4672, 4697, 4719, 4720, 4722,
    4723, 4724, 4725, 4726, 4728, 4732, 4740, 4756, 4768, 4769
};

inline const std::wstring& SecurityLogSubscriptionQuery() {
    static const std::wstring query = [] {
        // EvtSubscribe requires a structured query beyond 20 XPath expressions.
        // Keep each selector small as the supported ID list grows.
        std::wstring value = L"<QueryList><Query Id=\"0\" Path=\"Security\">";
        constexpr size_t idsPerSelector = 10;
        for (size_t first = 0; first < kSecurityLogEventIds.size(); first += idsPerSelector) {
            value += L"<Select Path=\"Security\">*[System[(";
            for (size_t i = first; i < first + idsPerSelector && i < kSecurityLogEventIds.size(); ++i) {
                if (i != first) value += L" or ";
                value += L"EventID=" + std::to_wstring(kSecurityLogEventIds[i]);
            }
            value += L")]]</Select>";
        }
        return value + L"</Query></QueryList>";
    }();
    return query;
}

} // namespace edr
#endif
