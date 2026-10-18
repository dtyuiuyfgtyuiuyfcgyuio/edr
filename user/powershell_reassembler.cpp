#include "powershell_reassembler.h"

#include "edr_event.h"

#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace edr {
namespace {

bool ParseIndex(const Event& event, const char* name, uint32_t& result) {
    auto value = event.fields.find(name);
    if (value == event.fields.end() || value->second.empty()) return false;
    char* end = nullptr;
    const unsigned long parsed = std::strtoul(value->second.c_str(), &end, 10);
    if (*end != '\0' || parsed == 0 || parsed > UINT32_MAX) return false;
    result = static_cast<uint32_t>(parsed); return true;
}

std::string Sha256(const std::string& text) {
    BCRYPT_ALG_HANDLE algorithm = nullptr; BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectSize = 0, returned = 0; std::vector<unsigned char> object;
    std::array<unsigned char, 32> digest{};
    NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (status >= 0) status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectSize), sizeof(objectSize), &returned, 0);
    if (status >= 0) { object.resize(objectSize); status = BCryptCreateHash(algorithm, &hash, object.data(), objectSize, nullptr, 0, 0); }
    if (status >= 0) status = BCryptHashData(hash, reinterpret_cast<PUCHAR>(const_cast<char*>(text.data())), static_cast<ULONG>(text.size()), 0);
    if (status >= 0) status = BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0);
    if (hash) BCryptDestroyHash(hash); if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    if (status < 0) return {};
    static const char hex[] = "0123456789abcdef"; std::string result(64, '0');
    for (size_t i = 0; i < digest.size(); ++i) { result[i * 2] = hex[digest[i] >> 4]; result[i * 2 + 1] = hex[digest[i] & 15]; }
    return result;
}

void Scrub(std::string& text) { std::fill(text.begin(), text.end(), '\0'); text.clear(); }

} // namespace

class PowerShellReassembler::State {
    struct Digest { uint32_t length = 0; std::string sha256; };
    struct Part { Event event; Digest digest; };
    struct Block { uint32_t total = 0; uint64_t expiry = 0; uint64_t sequence = 0; std::map<uint32_t, Part> parts; };
    struct Tombstone { uint32_t total = 0; uint64_t expiry = 0; uint64_t sequence = 0; std::map<uint32_t, std::vector<Digest>> parts; };

public:
    State(PowerShellReassemblyConfig settings, Clock now, Hasher digest)
        : config(std::move(settings)), clock(std::move(now)), hasher(std::move(digest)) {}

    std::vector<Event> Accept(Event event, bool* exactTombstoneDuplicate) {
        if (exactTombstoneDuplicate != nullptr)
            *exactTombstoneDuplicate = false;
        std::lock_guard<std::mutex> lock(mutex); PurgeTombstones();
        uint32_t index = 0, total = 0; std::string key;
        if (!Eligible(event, index, total, key)) return {std::move(event)};
        event.disposition = EventDisposition::ReportOnly;
        const std::string text = event.fields[field::kScriptBlockText];
        const Digest digest{static_cast<uint32_t>(text.size()), DigestFor(text)};
        std::vector<Event> prior = ExpireBlocks();
        if (digest.sha256.empty()) return Terminal(std::move(event), prior, key, index, total, digest, "sha256_failed");

        auto tomb = tombstones.find(key);
        if (tomb != tombstones.end()) {
            auto old = tomb->second.parts.find(index);
            if (tomb->second.total == total && old != tomb->second.parts.end() && Matches(old->second, digest)) {
                if (exactTombstoneDuplicate != nullptr)
                    *exactTombstoneDuplicate = true;
                return OriginalFirst(std::move(event), prior);
            }
            return Terminal(std::move(event), prior, key, index, total, digest, "tombstone_mismatch");
        }

        auto block = blocks.find(key);
        if (block != blocks.end() && (block->second.total != total || !Compatible(block->second, event))) return Terminal(std::move(event), prior, key, index, total, digest, "invariant_metadata");
        if (block == blocks.end()) while (blocks.size() >= config.stateCapacity) prior.push_back(EvictOldest("state_capacity"));
        block = blocks.find(key);

        if (block != blocks.end()) {
            auto old = block->second.parts.find(index);
            if (old != block->second.parts.end()) {
                if (old->second.digest.length == digest.length && old->second.digest.sha256 == digest.sha256) return OriginalFirst(std::move(event), prior);
                return Terminal(std::move(event), prior, key, index, total, digest, "payload_conflict");
            }
        }

        const bool fragmentTruncated = (event.flags & EDR_FLAG_TRUNCATED) != 0 || event.fields[field::kScriptBlockTruncated] == "true";
        const size_t currentBytes = text.size();
        const size_t activeBytes = block == blocks.end() ? 0 : BlockBytes(block->second);
        if (currentBytes > config.maxAssembledBytes || activeBytes + currentBytes > config.maxAssembledBytes) return Terminal(std::move(event), prior, key, index, total, digest, fragmentTruncated ? "fragment_truncated" : "assembled_bytes_exceeded");
        while (bufferedBytes + currentBytes > config.maxBufferedBytes && !blocks.empty()) prior.push_back(EvictOldest("global_bytes"));
        if (bufferedBytes + currentBytes > config.maxBufferedBytes) return Terminal(std::move(event), prior, key, index, total, digest, fragmentTruncated ? "fragment_truncated" : "global_bytes");
        block = blocks.find(key);
        if (block == blocks.end()) { Block fresh; fresh.total = total; fresh.expiry = clock() + config.timeoutSeconds; fresh.sequence = ++sequence; block = blocks.emplace(key, std::move(fresh)).first; }
        if (fragmentTruncated) return Terminal(std::move(event), prior, key, index, total, digest, "fragment_truncated");

        block->second.parts[index] = {event, digest}; bufferedBytes += currentBytes;
        if (block->second.parts.size() != total) return OriginalFirst(std::move(event), prior);
        Event derived = Derived(block->second, nullptr, 0, "complete", "");
        AddTombstone(key, block->second); Erase(block); return OriginalDerivedFirst(std::move(event), std::move(derived), prior);
    }

    bool TryGetFragmentKey(const Event& event, std::string& key) const {
        uint32_t index = 0;
        uint32_t total = 0;
        return Eligible(event, index, total, key);
    }

    std::vector<Event> Flush(bool all) {
        std::lock_guard<std::mutex> lock(mutex); std::vector<Event> result;
        const uint64_t now = clock();
        for (auto it = blocks.begin(); it != blocks.end();) {
            if (!all && it->second.expiry > now) { ++it; continue; }
            result.push_back(Derived(it->second, nullptr, 0, "incomplete", all ? "shutdown" : "timeout")); AddTombstone(it->first, it->second); it = Erase(it);
        }
        PurgeTombstones(); return result;
    }

private:
    bool Eligible(const Event& event, uint32_t& index, uint32_t& total, std::string& key) const {
        auto user = event.fields.find(field::kUserId), block = event.fields.find(field::kScriptBlockId);
        if (!config.enabled || event.type != EDR_EVT_POWERSHELL_SCRIPT || event.source.empty() || event.pid == 0 || user == event.fields.end() || user->second.empty() || block == event.fields.end() || block->second.empty() || !ParseIndex(event, field::kScriptMessageNumber, index) || !ParseIndex(event, field::kScriptMessageTotal, total) || total == 1 || total > config.maxFragments || index > total) return false;
        key = event.source + "\n" + user->second + "\n" + std::to_string(event.pid) + "\n" + block->second; return true;
    }
    bool Compatible(const Block& state, const Event& event) const {
        if (state.parts.empty()) return true;
        const Event& first = state.parts.begin()->second.event;
        if (first.source != event.source || first.pid != event.pid) return false;
        for (const char* name : {field::kUserId, field::kScriptBlockId, field::kScriptPath}) {
            auto left = first.fields.find(name), right = event.fields.find(name);
            if ((left == first.fields.end()) != (right == event.fields.end()) || (left != first.fields.end() && left->second != right->second)) return false;
        }
        return true;
    }
    size_t BlockBytes(const Block& state) const { size_t bytes = 0; for (const auto& part : state.parts) bytes += part.second.event.fields.at(field::kScriptBlockText).size(); return bytes; }
    void AppendBounded(std::string& output, const std::string& input, bool& truncated) const {
        const size_t room = config.maxAssembledBytes - output.size();
        if (input.size() <= room) output += input; else { output.append(input, 0, room); truncated = true; }
    }
    Event Derived(const Block& state, const Event* current, uint32_t currentIndex, const char* status, const char* reason) const {
        auto base = state.parts.find(1); if (base == state.parts.end()) base = state.parts.begin();
        Event result = base != state.parts.end() ? base->second.event : *current;
        std::string text; uint32_t flags = 0; bool bounded = false;
        for (uint32_t index = 1; index <= state.total; ++index) {
            auto part = state.parts.find(index);
            if (part != state.parts.end()) { AppendBounded(text, part->second.event.fields.at(field::kScriptBlockText), bounded); flags |= part->second.event.flags; }
            else if (current != nullptr && index == currentIndex) { AppendBounded(text, current->fields.at(field::kScriptBlockText), bounded); flags |= current->flags; }
            else AppendBounded(text, "\n", bounded);
        }
        if (current != nullptr && state.parts.find(currentIndex) != state.parts.end()) { AppendBounded(text, "\n", bounded); AppendBounded(text, current->fields.at(field::kScriptBlockText), bounded); flags |= current->flags; }
        if (bounded) flags |= EDR_FLAG_TRUNCATED;
        result.flags = flags; result.fields[field::kScriptBlockText] = std::move(text);
        result.fields[field::kScriptBlockComplete] = std::string(status) == "complete" ? "true" : "false";
        result.fields[field::kScriptBlockTruncated] = (flags & EDR_FLAG_TRUNCATED) != 0 ? "true" : "false";
        result.fields[field::kScriptReassemblyStatus] = status; result.fields[field::kScriptReassemblyReason] = reason;
        result.fields[field::kScriptReassemblyCount] = std::to_string(state.parts.size() + (current != nullptr && state.parts.find(currentIndex) == state.parts.end() ? 1 : 0)); result.disposition = EventDisposition::ReportAndEvaluate;
        return result;
    }
    Event CurrentOnlyDerived(const Event& current, const char* reason) const {
        uint32_t index = 0, total = 1;
        ParseIndex(current, field::kScriptMessageNumber, index);
        ParseIndex(current, field::kScriptMessageTotal, total);
        Block empty; empty.total = total;
        return Derived(empty, &current, index, "incomplete", reason);
    }
    std::vector<Event> Terminal(Event current, std::vector<Event> prior, const std::string& key, uint32_t index, uint32_t total, const Digest& digest, const char* reason) {
        auto state = blocks.find(key); Event derived = state == blocks.end() ? CurrentOnlyDerived(current, reason) : Derived(state->second, &current, index, "incomplete", reason);
        if (tombstones.find(key) == tombstones.end()) AddTerminalTombstone(key, state == blocks.end() ? nullptr : &state->second, total, index, digest);
        if (state != blocks.end()) Erase(state);
        return OriginalDerivedFirst(std::move(current), std::move(derived), prior);
    }
    std::vector<Event> OriginalFirst(Event original, std::vector<Event> prior) { prior.insert(prior.begin(), std::move(original)); return prior; }
    std::vector<Event> OriginalDerivedFirst(Event original, Event derived, std::vector<Event> prior) { prior.insert(prior.begin(), std::move(derived)); prior.insert(prior.begin(), std::move(original)); return prior; }
    std::vector<Event> ExpireBlocks() { std::vector<Event> result; const uint64_t now = clock(); for (auto it = blocks.begin(); it != blocks.end();) { if (it->second.expiry > now) { ++it; continue; } result.push_back(Derived(it->second, nullptr, 0, "incomplete", "timeout")); AddTombstone(it->first, it->second); it = Erase(it); } return result; }
    Event EvictOldest(const char* reason) { auto oldest = blocks.begin(); for (auto it = blocks.begin(); it != blocks.end(); ++it) if (it->second.sequence < oldest->second.sequence) oldest = it; Event result = Derived(oldest->second, nullptr, 0, "incomplete", reason); AddTombstone(oldest->first, oldest->second); Erase(oldest); return result; }
    std::string DigestFor(const std::string& text) const { return hasher ? hasher(text) : Sha256(text); }
    bool Matches(const std::vector<Digest>& digests, const Digest& current) const { for (const Digest& digest : digests) if (digest.length == current.length && digest.sha256 == current.sha256) return true; return false; }
    void AddDigest(Tombstone& tomb, uint32_t index, const Digest& digest) { if (digest.sha256.empty()) return; std::vector<Digest>& values = tomb.parts[index]; if (!Matches(values, digest) && values.size() < 2) values.push_back(digest); }
    void StoreTombstone(const std::string& key, Tombstone tomb) { tombstones[key] = std::move(tomb); while (tombstones.size() > config.stateCapacity) { auto oldest = tombstones.begin(); for (auto it = tombstones.begin(); it != tombstones.end(); ++it) if (it->second.sequence < oldest->second.sequence) oldest = it; tombstones.erase(oldest); } }
    void AddTombstone(const std::string& key, const Block& state) { Tombstone tomb{state.total, clock() + config.timeoutSeconds, ++sequence, {}}; for (const auto& part : state.parts) AddDigest(tomb, part.first, part.second.digest); StoreTombstone(key, std::move(tomb)); }
    void AddTerminalTombstone(const std::string& key, const Block* state, uint32_t total, uint32_t index, const Digest& digest) { Tombstone tomb{total, clock() + config.timeoutSeconds, ++sequence, {}}; if (state != nullptr) for (const auto& part : state->parts) AddDigest(tomb, part.first, part.second.digest); AddDigest(tomb, index, digest); StoreTombstone(key, std::move(tomb)); }
    std::map<std::string, Block>::iterator Erase(std::map<std::string, Block>::iterator state) { for (auto& part : state->second.parts) { std::string& text = part.second.event.fields[field::kScriptBlockText]; bufferedBytes -= text.size(); Scrub(text); } return blocks.erase(state); }
    void PurgeTombstones() { const uint64_t now = clock(); for (auto it = tombstones.begin(); it != tombstones.end();) it = it->second.expiry <= now ? tombstones.erase(it) : std::next(it); }
    PowerShellReassemblyConfig config; Clock clock; Hasher hasher; std::mutex mutex; size_t bufferedBytes = 0; uint64_t sequence = 0; std::map<std::string, Block> blocks; std::map<std::string, Tombstone> tombstones;
};

PowerShellReassembler::PowerShellReassembler(PowerShellReassemblyConfig config, Clock clock, Hasher hasher) : m_state(std::make_unique<State>(std::move(config), std::move(clock), std::move(hasher))) {}
PowerShellReassembler::~PowerShellReassembler() = default;
std::vector<Event> PowerShellReassembler::Accept(Event event) {
    return m_state->Accept(std::move(event), nullptr);
}
std::vector<Event> PowerShellReassembler::Accept(
    Event event, bool* exactTombstoneDuplicate) {
    return m_state->Accept(std::move(event), exactTombstoneDuplicate);
}
bool PowerShellReassembler::TryGetFragmentKey(const Event& event,
                                               std::string& key) const {
    return m_state->TryGetFragmentKey(event, key);
}
std::vector<Event> PowerShellReassembler::FlushExpired() { return m_state->Flush(false); }
std::vector<Event> PowerShellReassembler::FlushAll() { return m_state->Flush(true); }

} // namespace edr
