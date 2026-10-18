/*
 * pe_anomaly_scan.h - Static PE anomaly scanner (pure byte parser).
 *
 * Parses an in-memory PE image and scores static anomalies that
 * characteristically show up in packed, patched or injected binaries:
 *   - known packer section names (UPX0/UPX1, .vmp0/.vmp1, .themida, ...)
 *   - writable + executable (RWX) sections
 *   - virtual-only sections (SizeOfRawData == 0 with a nonzero VirtualSize)
 *   - nameless sections with content
 *   - high-entropy executable section data (packing / embedded shellcode)
 *   - zero or future compile timestamps
 *   - large overlay data past the last section
 *   - degenerate section counts
 *
 * The scanner is intentionally free of Win32 calls so tests can feed
 * synthetic buffers. Files are read by the caller (pe_anomaly_detector).
 */
#ifndef EDR_PE_ANOMALY_SCAN_H
#define EDR_PE_ANOMALY_SCAN_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace edr {

struct PeAnomalyFinding {
    bool valid = false;            /* parseable PE image */
    uint32_t score = 0;            /* 0..100 */
    std::vector<std::string> signals;
    std::string anomalousSections; /* comma list, empty when none */
};

/* Input restricted to little-endian PE32/PE32+ images as found on disk
 * (DOS header -> PE signature -> COFF -> optional header -> sections). */
PeAnomalyFinding ScanPeBuffer(const uint8_t* data, size_t length,
                              uint64_t nowUnixSeconds);

} // namespace edr

#endif /* EDR_PE_ANOMALY_SCAN_H */
