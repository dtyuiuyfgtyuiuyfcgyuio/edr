/*
 * collector_named_pipe.h - ETW named pipe monitoring collector.
 *
 * Subscribes to Microsoft-Windows-Kernel-File (GUID edd08927-9cc4-4e65-b970-c2560fb5c289)
 * and parses pipe create (event ID 17) and pipe connect (event ID 18) events.
 * Emits NAMED_PIPE events with pipe name and operation type.
 */
#ifndef EDR_COLLECTOR_NAMED_PIPE_H
#define EDR_COLLECTOR_NAMED_PIPE_H

#include <cstdint>
#include <string>

namespace edr {

class ICollector;

/* Parse the pipe name from an ETW payload. Returns the pipe name as UTF-8,
 * or empty string on failure. */
std::string ParsePipeName(const uint8_t* payload, uint32_t byteCount);

/* Create a named pipe ETW collector. Returns nullptr if unavailable. */
ICollector* CreateNamedPipeCollector();

} // namespace edr

#endif /* EDR_COLLECTOR_NAMED_PIPE_H */