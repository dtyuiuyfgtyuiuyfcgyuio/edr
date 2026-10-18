/*
 * threat_intel_detector.cpp - See threat_intel_detector.h.
 *
 * Feed schema (JSON):
 * {
 *   "feed": "operator-name",            // optional, informational
 *   "indicators": [
 *     { "id": "TI-0001", "type": "sha256", "value": "<64 hex>",
 *       "confidence": "high", "source": "vendor-x",
 *       "threat": "FamilyName" }        // threat is optional
 *   ]
 * }
 *
 * "indicators" may also be given as a top-level array. Validation is strict:
 * an unusable indicator fails the whole load rather than being skipped, so a
 * typo in the feed cannot silently degrade detection to a no-op.
 *
 * Matching notes:
 *   - Domain indicators match the queried name exactly or as a parent
 *     suffix (`evil.example.com` matches `example.com`, but never
 *     `notexample.com`). Trailing dots from the DNS wire form are stripped.
 *   - ipv4/ipv6 match NET_CONNECT dst_ip exactly; ipv4_cidr/ipv6_cidr
 *     match all addresses within the normalized network prefix. Ranges and
 *     exact addresses share an evidence category, so overlapping ranges never
 *     earn a cross-type bonus. IPv4-mapped IPv6 remains in the IPv6 family.
 */
#include "threat_intel_detector.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <fstream>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "json_lite.h"

namespace edr {
namespace {

constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
constexpr size_t kMaxFeedBytes = 4u * 1024u * 1024u;

/* Hash exactly the bounded bytes that will be parsed, avoiding a second file
 * open and detecting edits even when the file's size and mtime are preserved. */
bool ReadFeed(const std::string& path, std::string& contents,
              std::string& fingerprint, std::string& error) {
    if (path.empty()) {
        error = "no threat intel feed path configured";
        return false;
    }
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        error = "cannot open threat intel feed: " + path;
        return false;
    }
    char buffer[8192];
    while (stream) {
        stream.read(buffer, sizeof(buffer));
        const size_t bytes = static_cast<size_t>(stream.gcount());
        if (bytes > kMaxFeedBytes - contents.size()) {
            error = "threat intel feed exceeds 4 MiB";
            return false;
        }
        contents.append(buffer, bytes);
    }
    if (stream.bad() || !stream.eof()) {
        error = "cannot read complete threat intel feed: " + path;
        return false;
    }

    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectBytes = 0, received = 0;
    std::vector<unsigned char> object;
    unsigned char digest[32] = {};
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (status >= 0) status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&objectBytes), sizeof(objectBytes), &received, 0);
    if (status >= 0) {
        object.resize(objectBytes);
        status = BCryptCreateHash(algorithm, &hash, object.data(), objectBytes,
                                   nullptr, 0, 0);
    }
    if (status >= 0) status = BCryptHashData(hash,
        reinterpret_cast<PUCHAR>(contents.data()),
        static_cast<ULONG>(contents.size()), 0);
    if (status >= 0) status = BCryptFinishHash(hash, digest, sizeof(digest), 0);
    if (hash != nullptr) BCryptDestroyHash(hash);
    if (algorithm != nullptr) BCryptCloseAlgorithmProvider(algorithm, 0);
    if (status < 0) {
        error = "cannot fingerprint threat intel feed";
        return false;
    }
    static const char hex[] = "0123456789abcdef";
    fingerprint.resize(64);
    for (size_t i = 0; i < sizeof(digest); ++i) {
        fingerprint[i * 2] = hex[digest[i] >> 4];
        fingerprint[i * 2 + 1] = hex[digest[i] & 15];
    }
    return true;
}

/* Base score per indicator type. A file hash or certificate thumbprint is a
 * near-conclusive match; a domain or address can be shared infrastructure, so
 * it scores lower on its own. */
constexpr int kScoreSha256 = 85;
constexpr int kScoreCertSha256 = 80;
constexpr int kScoreIpv4 = 65;
constexpr int kScoreIpv6 = 65;
constexpr int kScoreDomain = 60;

/* Added once when a single process matches indicators of more than one type,
 * e.g. an executable whose hash is known and that also resolves a known C2
 * domain. Breadth across independent surfaces is the strong signal here. */
constexpr int kCrossTypeBonus = 15;

std::string LowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

std::string Trim(const std::string& value) {
    size_t begin = 0;
    size_t end = value.size();
    while (begin < end &&
           std::isspace(static_cast<unsigned char>(value[begin])))
        ++begin;
    while (end > begin &&
           std::isspace(static_cast<unsigned char>(value[end - 1])))
        --end;
    return value.substr(begin, end - begin);
}

std::string FieldValue(const Event& event, const char* name) {
    auto found = event.fields.find(name);
    return found == event.fields.end() ? std::string() : found->second;
}

uint64_t EventTime(const Event& event) {
    if (event.ts100ns != 0) return event.ts100ns;
    FILETIME now = {};
    GetSystemTimePreciseAsFileTime(&now);
    return (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
           now.dwLowDateTime;
}

bool IsHex(const std::string& value, size_t length) {
    if (value.size() != length) return false;
    for (char c : value) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
    }
    return true;
}

bool IsValidIpv4(const std::string& value) {
    size_t begin = 0;
    for (int part = 0; part < 4; ++part) {
        size_t end = value.find('.', begin);
        if (part == 3) {
            if (end != std::string::npos) return false;
            end = value.size();
        } else if (end == std::string::npos) {
            return false;
        }
        const std::string token = value.substr(begin, end - begin);
        if (token.empty() || token.size() > 3) return false;
        for (char c : token) {
            if (!std::isdigit(static_cast<unsigned char>(c))) return false;
        }
        if (token.size() > 1 && token.front() == '0') return false;
        if (std::stoul(token) > 255) return false;
        if (part == 3) return true;
        begin = end + 1;
    }
    return false;
}

/* InetPton returns bytes in network order. Reject NUL before passing a C
 * string, and keep IPv4's existing strict dotted-decimal validation. */
bool ParseAddressBytes(const std::string& value, int family,
                       std::array<unsigned char, 16>& address) {
    if (value.empty() || value.find('\0') != std::string::npos) return false;
    if (family == AF_INET && !IsValidIpv4(value)) return false;
    return InetPtonA(family, value.c_str(), address.data()) == 1;
}

std::string PrefixKey(const std::array<unsigned char, 16>& address,
                      size_t byteCount, unsigned prefix) {
    std::string key(byteCount + 1, '\0');
    key[0] = static_cast<char>(prefix);
    const size_t wholeBytes = prefix / 8;
    for (size_t i = 0; i < wholeBytes; ++i)
        key[i + 1] = static_cast<char>(address[i]);
    const unsigned remaining = prefix % 8;
    if (remaining != 0)
        key[wholeBytes + 1] = static_cast<char>(
            address[wholeBytes] & (0xffu << (8 - remaining)));
    return key;
}

/* Normalize host bits away, so equivalent network spellings are duplicates.
 * A prefix is a plain decimal integer: no sign, padding, or trailing text. */
std::string ParseCidrKey(const std::string& raw, int family) {
    const std::string value = Trim(raw);
    const size_t slash = value.find('/');
    if (slash == std::string::npos || value.find('\0') != std::string::npos)
        return {};
    const std::string suffix = value.substr(slash + 1);
    if (suffix.empty() || suffix.size() > 3 ||
        (suffix.size() > 1 && suffix.front() == '0')) return {};
    unsigned prefix = 0;
    for (char c : suffix) {
        if (c < '0' || c > '9') return {};
        prefix = prefix * 10 + static_cast<unsigned>(c - '0');
    }
    const size_t byteCount = family == AF_INET ? 4u : 16u;
    if (prefix > byteCount * 8) return {};
    std::array<unsigned char, 16> address = {};
    if (!ParseAddressBytes(value.substr(0, slash), family, address)) return {};
    return PrefixKey(address, byteCount, prefix);
}

/* Parse IPv6 strictly and return its canonical spelling for exact indexing.
 * Reject embedded NUL explicitly because InetPtonA consumes a C string and
 * would otherwise accept a valid prefix before the terminator. */
std::string NormalizeIpv6(const std::string& raw) {
    const std::string value = Trim(raw);
    if (value.empty() || value.find('\0') != std::string::npos) return {};

    IN6_ADDR address = {};
    if (InetPtonA(AF_INET6, value.c_str(), &address) != 1) return {};

    char buffer[INET6_ADDRSTRLEN] = {};
    if (InetNtopA(AF_INET6, &address, buffer, sizeof(buffer)) == nullptr)
        return {};
    return LowerAscii(buffer);
}

/* Lowercase, strip the DNS wire trailing dot, and reject anything with
 * characters that cannot appear in a hostname. A malformed query name must
 * never be able to match an indicator by accident. */
std::string NormalizeDomain(const std::string& raw) {
    std::string value = LowerAscii(Trim(raw));
    while (!value.empty() && value.back() == '.') value.pop_back();
    if (value.empty()) return {};
    for (char c : value) {
        const unsigned char u = static_cast<unsigned char>(c);
        if (!std::isalnum(u) && c != '.' && c != '-' && c != '_') return {};
    }
    return value;
}

/* `host` matches `indicator` when identical, or when host is a subdomain of
 * it. The boundary check on the preceding character prevents
 * `notexample.com` from matching `example.com`. */
bool DomainMatches(const std::string& host, const std::string& indicator) {
    if (host == indicator) return true;
    if (host.size() <= indicator.size()) return false;
    if (host.compare(host.size() - indicator.size(), indicator.size(),
                     indicator) != 0)
        return false;
    return host[host.size() - indicator.size() - 1] == '.';
}

std::string Sha256Value(const Event& event) {
    const std::string direct = LowerAscii(Trim(FieldValue(event, field::kSha256)));
    if (IsHex(direct, 64)) return direct;
    const std::string hashes = LowerAscii(FieldValue(event, field::kHashes));
    size_t position = hashes.find("sha256=");
    if (position == std::string::npos) return {};
    position += 7;
    const std::string candidate = hashes.substr(position, 64);
    return IsHex(candidate, 64) ? candidate : std::string();
}

/* IMAGE_LOAD carries the mapped image's checksum separately from any hash
 * list, so both locations are consulted. */
std::string ImageHashValue(const Event& event) {
    const std::string direct = Sha256Value(event);
    if (!direct.empty()) return direct;
    const std::string checksum =
        LowerAscii(Trim(FieldValue(event, field::kImageChecksum)));
    return IsHex(checksum, 64) ? checksum : std::string();
}

const jsonlite::Value& Required(const jsonlite::Value& object,
                                const char* name, jsonlite::Type type) {
    const jsonlite::Value* value = object.find(name);
    if (value == nullptr || value->type != type)
        throw std::runtime_error(std::string("indicator field '") + name +
                                 "' is missing or has the wrong type");
    return *value;
}

void RequireExactKeys(const jsonlite::Value& object) {
    static const std::set<std::string> allowed = {
        "id", "type", "value", "confidence", "source", "threat"
    };
    for (const auto& item : object.object) {
        if (allowed.count(item.first) == 0)
            throw std::runtime_error("unknown indicator field '" +
                                     item.first + "'");
    }
}

std::string Join(const std::vector<std::string>& values) {
    std::string joined;
    for (size_t i = 0; i < values.size(); ++i) {
        if (i != 0) joined += ",";
        joined += values[i];
    }
    return joined;
}

template <typename Map>
void EvictOldest(Map& map, size_t capacity) {
    if (map.size() <= capacity) return;
    auto oldest = std::min_element(map.begin(), map.end(),
        [](const auto& left, const auto& right) {
            return left.second.lastSeen100ns < right.second.lastSeen100ns;
        });
    if (oldest != map.end()) map.erase(oldest);
}

std::string LowerIdentityAscii(std::string value) {
    for (char& ch : value) {
        if (ch >= 'A' && ch <= 'Z')
            ch = static_cast<char>(ch - 'A' + 'a');
    }
    return value;
}

bool IsBarePidIdentity(const std::string& identity) {
    const std::string lower = LowerIdentityAscii(identity);
    if (lower.rfind("pid:", 0) == 0) return true;
    if (lower.empty()) return false;
    for (unsigned char value : lower) {
        if (value < '0' || value > '9') return false;
    }
    return true;
}

void AppendKeyPart(std::string& key, const std::string& value) {
    key += std::to_string(value.size());
    key.push_back(':');
    key += value;
}

bool ProcessStateKey(const Event& event, std::string& key,
                     std::string& endpointId, bool& exactIdentity) {
    std::string kind;
    std::string identity;
    std::string source;
    endpointId = LowerIdentityAscii(FieldValue(event, field::kEndpointId));
    if (event.processStartTime100ns != 0) {
        exactIdentity = true;
        kind = "start-time";
        identity = std::to_string(event.processStartTime100ns);
    } else {
        exactIdentity = false;
        if (event.processIdentity.empty() ||
            IsBarePidIdentity(event.processIdentity))
            return false;
        source = event.source.empty()
            ? FieldValue(event, field::kSource)
            : event.source;
        if (source.empty()) return false;
        source = LowerIdentityAscii(source);
        kind = "opaque";
        identity = event.processIdentity;
    }

    key.clear();
    AppendKeyPart(key, "threat-intel-state-v1");
    AppendKeyPart(key, std::to_string(event.pid));
    AppendKeyPart(key, endpointId);
    AppendKeyPart(key, kind);
    AppendKeyPart(key, identity);
    AppendKeyPart(key, source);
    return true;
}

} // namespace

ThreatIntelDetector::ThreatIntelDetector(bool enabled, uint32_t minScore,
                                        uint32_t dedupWindowSeconds,
                                        size_t stateCapacity,
                                        uint32_t reloadPollSeconds)
    : m_enabled(enabled),
      m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)),
      m_reloadPollMs(static_cast<uint64_t>(reloadPollSeconds) * 1000ULL) {}

bool ThreatIntelDetector::LoadIndicators(const std::string& path,
                                         std::string& error) {
    error.clear();
    /* Retain the initial path so opt-in polling can recover after a missing
     * or invalid startup feed. A failed replacement cannot change active path. */
    if (m_feedPath.empty()) m_feedPath = path;
    m_lastReloadCheckMs = GetTickCount64();
    std::string contents, fingerprint;
    if (!ReadFeed(path, contents, fingerprint, error)) return false;
    if (!ApplyIndicators(contents, error)) {
        if (path == m_feedPath) {
            m_seenFingerprint = std::move(fingerprint);
            m_seenError = error;
        }
        return false;
    }
    m_feedPath = path;
    m_seenFingerprint = std::move(fingerprint);
    m_seenError.clear();
    m_reloadError.clear();
    return true;
}

bool ThreatIntelDetector::ReloadIndicatorsIfChanged(std::string& error) {
    error.clear();
    std::string contents, fingerprint;
    if (!ReadFeed(m_feedPath, contents, fingerprint, error)) return false;
    if (fingerprint == m_seenFingerprint) {
        error = m_seenError;
        return false;
    }
    const bool applied = ApplyIndicators(contents, error);
    m_seenFingerprint = std::move(fingerprint);
    m_seenError = error;
    return applied;
}

bool ThreatIntelDetector::ApplyIndicators(const std::string& contents,
                                          std::string& error) {
    try {
        const jsonlite::Value root = jsonlite::Parser(contents).parse();
        const jsonlite::Value* list = nullptr;
        std::string feedName;
        if (root.type == jsonlite::Type::Array) {
            list = &root;
        } else if (root.type == jsonlite::Type::Object) {
            list = root.find("indicators");
            const jsonlite::Value* feed = root.find("feed");
            if (feed != nullptr && feed->type == jsonlite::Type::String)
                feedName = feed->str;
        } else {
            throw std::runtime_error(
                "threat intel feed must be an object or an array");
        }
        if (list == nullptr || list->type != jsonlite::Type::Array)
            throw std::runtime_error(
                "threat intel feed has no 'indicators' array");
        if (list->array.empty())
            throw std::runtime_error("threat intel feed contains no indicators");

        std::vector<Indicator> loaded;
        std::set<std::string> uniqueIds;
        std::set<std::string> uniqueValues;
        loaded.reserve(list->array.size());

        for (const jsonlite::Value& entry : list->array) {
            if (entry.type != jsonlite::Type::Object)
                throw std::runtime_error(
                    "each indicator must be a JSON object");
            RequireExactKeys(entry);
            const std::string id =
                Required(entry, "id", jsonlite::Type::String).str;
            const std::string type =
                LowerAscii(Required(entry, "type", jsonlite::Type::String).str);
            const std::string rawValue =
                Required(entry, "value", jsonlite::Type::String).str;
            const std::string confidence =
                LowerAscii(Required(entry, "confidence",
                                    jsonlite::Type::String).str);
            const std::string source =
                Required(entry, "source", jsonlite::Type::String).str;
            const jsonlite::Value* threat = entry.find("threat");
            const std::string threatName =
                (threat != nullptr && threat->type == jsonlite::Type::String)
                    ? threat->str : std::string();

            if (id.empty() || !uniqueIds.insert(id).second)
                throw std::runtime_error(
                    "indicator ids must be non-empty and unique");
            if (confidence != "low" && confidence != "medium" &&
                confidence != "high")
                throw std::runtime_error(
                    "indicator confidence must be low, medium, or high");
            if (source.empty())
                throw std::runtime_error(
                    "indicator source must be non-empty");

            Indicator indicator;
            indicator.id = id;
            indicator.confidence = confidence;
            indicator.source = source;
            indicator.threat = threatName;

            if (type == "sha256") {
                const std::string value = LowerAscii(Trim(rawValue));
                if (!IsHex(value, 64))
                    throw std::runtime_error(
                        "sha256 indicator must contain 64 hex digits");
                indicator.type = IndicatorType::Sha256;
                indicator.value = value;
                indicator.baseScore = kScoreSha256;
            } else if (type == "cert_sha256") {
                const std::string value = LowerAscii(Trim(rawValue));
                if (!IsHex(value, 64))
                    throw std::runtime_error(
                        "cert_sha256 indicator must contain 64 hex digits");
                indicator.type = IndicatorType::CertificateSha256;
                indicator.value = value;
                indicator.baseScore = kScoreCertSha256;
            } else if (type == "domain") {
                const std::string value = NormalizeDomain(rawValue);
                if (value.empty() || value.find('.') == std::string::npos)
                    throw std::runtime_error("domain indicator is invalid");
                indicator.type = IndicatorType::Domain;
                indicator.value = value;
                indicator.baseScore = kScoreDomain;
            } else if (type == "ipv4") {
                const std::string value = LowerAscii(Trim(rawValue));
                if (!IsValidIpv4(value))
                    throw std::runtime_error("ipv4 indicator is invalid");
                indicator.type = IndicatorType::Ipv4;
                indicator.value = value;
                indicator.baseScore = kScoreIpv4;
            } else if (type == "ipv6") {
                const std::string value = NormalizeIpv6(rawValue);
                if (value.empty())
                    throw std::runtime_error("ipv6 indicator is invalid");
                indicator.type = IndicatorType::Ipv6;
                indicator.value = value;
                indicator.baseScore = kScoreIpv6;
            } else if (type == "ipv4_cidr" || type == "ipv6_cidr") {
                const bool ipv4 = type == "ipv4_cidr";
                indicator.value = ParseCidrKey(rawValue, ipv4 ? AF_INET : AF_INET6);
                if (indicator.value.empty())
                    throw std::runtime_error(type + " indicator is invalid");
                indicator.type = ipv4 ? IndicatorType::Ipv4 : IndicatorType::Ipv6;
                indicator.isCidr = true;
                indicator.baseScore = ipv4 ? kScoreIpv4 : kScoreIpv6;
            } else {
                throw std::runtime_error(
                    "unsupported indicator type '" + type + "'");
            }

            if (!uniqueValues.insert(type + ":" + indicator.value).second)
                throw std::runtime_error(
                    "duplicate indicator value for type " + type);
            loaded.push_back(std::move(indicator));
        }

        /* Build indices only after the whole feed validated, so a partial
         * load can never leave the detector half-armed. */
        std::unordered_map<std::string, const Indicator*> byHash, byDomain,
            byAddress, byCidr, byCert;
        for (const Indicator& indicator : loaded) {
            switch (indicator.type) {
            case IndicatorType::Sha256:
                byHash.emplace(indicator.value, &indicator);
                break;
            case IndicatorType::CertificateSha256:
                byCert.emplace(indicator.value, &indicator);
                break;
            case IndicatorType::Domain:
                byDomain.emplace(indicator.value, &indicator);
                break;
            case IndicatorType::Ipv4:
            case IndicatorType::Ipv6:
                if (indicator.isCidr)
                    byCidr.emplace(indicator.value, &indicator);
                else
                    byAddress.emplace(indicator.value, &indicator);
                break;
            }
        }
        /* No allocation after this point: publish owning storage and its
         * pointer indices together on the sole EventBus consumer thread. */
        m_indicators.swap(loaded);
        m_byHash.swap(byHash);
        m_byDomain.swap(byDomain);
        m_byAddress.swap(byAddress);
        m_byCidr.swap(byCidr);
        m_byCert.swap(byCert);
        m_feedName.swap(feedName);
        m_states.clear();
        return true;
    } catch (const std::exception& exception) {
        error = exception.what();
        return false;
    }
}

bool ThreatIntelDetector::Inspects(uint16_t type) {
    switch (type) {
    case EDR_EVT_PROCESS_START:
    case EDR_EVT_IMAGE_LOAD:
    case EDR_EVT_DNS_QUERY:
    case EDR_EVT_NET_CONNECT:
        return true;
    default:
        return false;
    }
}

void ThreatIntelDetector::PurgeExpired(uint64_t now100ns) {
    for (auto it = m_states.begin(); it != m_states.end();) {
        if (now100ns >= it->second.lastSeen100ns &&
            now100ns - it->second.lastSeen100ns > m_dedupWindow100ns)
            it = m_states.erase(it);
        else
            ++it;
    }
}

void ThreatIntelDetector::Enrich(Event& event) {
    if (!m_enabled || !Inspects(event.type)) return;
    const uint64_t nowMs = GetTickCount64();
    if (m_reloadPollMs != 0 &&
        nowMs - m_lastReloadCheckMs >= m_reloadPollMs) {
        m_lastReloadCheckMs = nowMs;
        const std::string previousError = m_reloadError;
        std::string error;
        if (ReloadIndicatorsIfChanged(error)) {
            std::fprintf(stderr, "[edr-intel] hot reload: %zu indicators from %s\n",
                m_indicators.size(), m_feedPath.c_str());
        } else if (!error.empty() && error != previousError) {
            std::fprintf(stderr,
                "[edr-intel] hot reload failed, keeping previous feed (%s): %s\n",
                m_feedPath.c_str(), error.c_str());
        }
        m_reloadError = error;
    }
    if (m_indicators.empty()) return;

    const uint64_t now = EventTime(event);
    PurgeExpired(now);
    if (event.pid == 0) return;

    /* Collect every indicator this event references. One event can legitimately
     * match several entries (e.g. a hash known by two feeds). */
    std::vector<const Indicator*> hits;
    switch (event.type) {
    case EDR_EVT_PROCESS_START: {
        const std::string hash = Sha256Value(event);
        if (!hash.empty()) {
            auto range = m_byHash.equal_range(hash);
            for (auto it = range.first; it != range.second; ++it)
                hits.push_back(it->second);
        }
        break;
    }
    case EDR_EVT_IMAGE_LOAD: {
        const std::string hash = ImageHashValue(event);
        if (!hash.empty()) {
            auto range = m_byHash.equal_range(hash);
            for (auto it = range.first; it != range.second; ++it)
                hits.push_back(it->second);
        }
        const std::string cert =
            LowerAscii(Trim(FieldValue(event, field::kSignerCertificateSha256)));
        if (IsHex(cert, 64)) {
            auto range = m_byCert.equal_range(cert);
            for (auto it = range.first; it != range.second; ++it)
                hits.push_back(it->second);
        }
        break;
    }
    case EDR_EVT_DNS_QUERY: {
        const std::string host =
            NormalizeDomain(FieldValue(event, field::kDnsQueryName));
        if (host.empty()) break;
        /* Walk the label suffixes so a parent-domain indicator catches any
         * subdomain without needing a wildcard syntax in the feed. */
        size_t position = 0;
        while (position < host.size()) {
            auto range = m_byDomain.equal_range(host.substr(position));
            for (auto it = range.first; it != range.second; ++it)
                hits.push_back(it->second);
            size_t dot = host.find('.', position);
            if (dot == std::string::npos) break;
            position = dot + 1;
        }
        break;
    }
    case EDR_EVT_NET_CONNECT: {
        const std::string rawIp = Trim(FieldValue(event, field::kDstIp));
        const std::string ip = rawIp.find(':') == std::string::npos
            ? LowerAscii(rawIp)
            : NormalizeIpv6(rawIp);
        if (ip.empty()) break;
        auto range = m_byAddress.equal_range(ip);
        for (auto it = range.first; it != range.second; ++it)
            hits.push_back(it->second);
        if (!m_byCidr.empty()) {
            const int family = rawIp.find(':') == std::string::npos ? AF_INET : AF_INET6;
            std::array<unsigned char, 16> address = {};
            if (!ParseAddressBytes(rawIp, family, address)) break;
            const size_t byteCount = family == AF_INET ? 4u : 16u;
            /* At most 33 IPv4 / 129 IPv6 lookups, even for large feeds.
             * Preserve all overlapping evidence, exact match first, then
             * increasingly specific prefixes, for stable alert attribution. */
            for (unsigned prefix = 0; prefix <= byteCount * 8; ++prefix) {
                const auto found = m_byCidr.find(PrefixKey(address, byteCount, prefix));
                if (found != m_byCidr.end()) hits.push_back(found->second);
            }
        }
        break;
    }
    default:
        return;
    }
    if (hits.empty()) return;

    std::string stateKey;
    std::string endpointId;
    bool exactIdentity = false;
    const bool retainState =
        ProcessStateKey(event, stateKey, endpointId, exactIdentity);
    ProcessState eventState;
    ProcessState* statePointer = &eventState;
    if (retainState) {
        const auto insertion = m_states.try_emplace(stateKey);
        statePointer = &insertion.first->second;
        if (exactIdentity && insertion.second) {
            for (auto it = m_states.begin(); it != m_states.end();) {
                if (it->first != stateKey && it->second.pid == event.pid &&
                    it->second.endpointId == endpointId)
                    it = m_states.erase(it);
                else
                    ++it;
            }
        }
        statePointer->pid = event.pid;
        statePointer->endpointId = endpointId;
    }
    ProcessState& state = *statePointer;
    state.lastSeen100ns = now;

    uint8_t typeMask = state.typeMask;
    int peak = state.peakScore;
    for (const Indicator* indicator : hits) {
        peak = std::max(peak, indicator->baseScore);
        typeMask |= static_cast<uint8_t>(1u << static_cast<unsigned>(indicator->type));
        const std::string typeName = [](IndicatorType type) {
            switch (type) {
            case IndicatorType::Sha256: return std::string("sha256");
            case IndicatorType::Domain: return std::string("domain");
            case IndicatorType::Ipv4: return std::string("ipv4");
            case IndicatorType::Ipv6: return std::string("ipv6");
            case IndicatorType::CertificateSha256:
                return std::string("cert_sha256");
            }
            return std::string("unknown");
        }(indicator->type);
        if (std::find(state.matchedIds.begin(), state.matchedIds.end(),
                      indicator->id) == state.matchedIds.end()) {
            state.matchedIds.push_back(indicator->id);
            state.matchedTypes.push_back(typeName);
            state.matchedSources.push_back(indicator->source);
            state.matchedConfidences.push_back(indicator->confidence);
        }
    }

    state.typeMask = typeMask;
    int distinctTypes = 0;
    for (int bit = 0; bit < 8; ++bit) {
        if (typeMask & (1u << bit)) ++distinctTypes;
    }
    int score = peak;
    if (distinctTypes > 1) score += kCrossTypeBonus * (distinctTypes - 1);
    score = std::min(100, score);
    state.peakScore = peak;

    /* Never write a verdict below the operator threshold; downstream rules
     * match a score band and a sub-threshold verdict would be misleading. */
    if (score < static_cast<int>(m_minScore)) {
        if (retainState) EvictOldest(m_states, m_stateCapacity);
        return;
    }

    event.fields[field::kThreatIntelScore] = std::to_string(score);
    event.fields[field::kThreatIntelVerdict] = score >= 75 ? "MALICIOUS"
                                                           : "SUSPICIOUS";
    event.fields[field::kThreatIntelSignals] = Join(state.matchedTypes);
    event.fields[field::kThreatIntelIocIds] = Join(state.matchedIds);
    event.fields[field::kThreatIntelIocTypes] = Join(state.matchedTypes);
    event.fields[field::kThreatIntelIocSources] = Join(state.matchedSources);
    event.fields[field::kThreatIntelIocConfidence] = Join(state.matchedConfidences);
    event.fields[field::kThreatIntelIocCount] =
        std::to_string(state.matchedIds.size());
    if (!m_feedName.empty())
        event.fields[field::kThreatIntelFeed] = m_feedName;
    if (retainState) EvictOldest(m_states, m_stateCapacity);
}

} // namespace edr
