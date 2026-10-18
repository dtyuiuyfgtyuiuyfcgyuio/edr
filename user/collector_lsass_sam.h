/*
 * collector_lsass_sam.h - LSASS/SAM credential access detector.
 *
 * Polls for processes holding open handles to lsass.exe with suspicious
 * access rights (PROCESS_VM_READ | PROCESS_QUERY_INFORMATION) and for
 * reads of the SAM/SECURITY hives. Emits PROCESS_READ events when a
 * non-system process accesses LSASS, and FILE_READ events when the SAM or
 * SECURITY hive is read. Detects credential dumping (MITRE T1003.001).
 */
#ifndef EDR_COLLECTOR_LsassSam_H
#define EDR_COLLECTOR_LsassSam_H

#include <cstdint>
#include <string>
#include <vector>

namespace edr {

class ICollector;

ICollector* CreateLsassSamCollector(uint32_t pollMs, uint32_t dedupMs);

} // namespace edr

#endif /* EDR_COLLECTOR_LsassSam_H */
