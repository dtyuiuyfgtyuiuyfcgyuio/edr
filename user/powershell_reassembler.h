#ifndef EDR_POWERSHELL_REASSEMBLER_H
#define EDR_POWERSHELL_REASSEMBLER_H

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "event_bus.h"

namespace edr {

struct PowerShellReassemblyConfig {
    bool enabled = false;
    uint32_t maxFragments = 64;
    uint32_t maxAssembledBytes = 1024 * 1024;
    uint32_t stateCapacity = 256;
    uint32_t maxBufferedBytes = 32 * 1024 * 1024;
    uint32_t timeoutSeconds = 30;
};

class PowerShellReassembler {
public:
    using Clock = std::function<uint64_t()>;
    using Hasher = std::function<std::string(const std::string&)>;

    PowerShellReassembler(PowerShellReassemblyConfig config, Clock clock,
                          Hasher hasher = {});
    ~PowerShellReassembler();
    std::vector<Event> Accept(Event event);
    /* The optional result is true only when this event exactly matches an
     * unexpired same-key tombstone fragment. It lets durable consumers
     * acknowledge an already handled duplicate without treating changed or
     * incomplete input as consumed. */
    std::vector<Event> Accept(Event event, bool* exactTombstoneDuplicate);
    /* Uses the same immutable eligibility checks as Accept, including the
     * configured fragment bound, so callers can track replay groups without
     * drifting from reassembly policy. */
    bool TryGetFragmentKey(const Event& event, std::string& key) const;
    std::vector<Event> FlushExpired();
    std::vector<Event> FlushAll();

private:
    class State;
    std::unique_ptr<State> m_state;
};

} // namespace edr

#endif /* EDR_POWERSHELL_REASSEMBLER_H */
