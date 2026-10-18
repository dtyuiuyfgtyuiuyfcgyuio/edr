/*
 * driver_event_parser.h - Pure parser for driver wire events.
 *
 * Parses one EDR_EVENT_HEADER + TLV payload into a user-mode Event without
 * touching EventBus, the process API, or enrichment. No allocation beyond
 * the Event's own strings. Returns false when the block is malformed and
 * must be dropped.
 */
#ifndef EDR_DRIVER_EVENT_PARSER_H
#define EDR_DRIVER_EVENT_PARSER_H

#include <cstdint>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

/* Parse a single validated event (header already copied out; tlv points at
 * the TLV region of tlvLen bytes). Fills ev with the type/timestamp/pid and
 * all known TLV fields. Returns false on a structurally malformed TLV tail. */
bool ParseDriverEvent(const struct ::EDR_EVENT_HEADER& hdr,
                      const uint8_t* tlv, uint32_t tlvLen, Event& ev,
                      bool& malformed);

} // namespace edr

#endif /* EDR_DRIVER_EVENT_PARSER_H */