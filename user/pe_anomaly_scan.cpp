/*
 * pe_anomaly_scan.cpp - See pe_anomaly_scan.h.
 */
#include "pe_anomaly_scan.h"

#include <cmath>
#include <cctype>
#include <cstring>
#include <string>

namespace edr {
namespace {

constexpr uint32_t kImageScnMemRead = 0x40000000u;
constexpr uint32_t kImageScnMemWrite = 0x80000000u;
constexpr uint32_t kImageScnMemExecute = 0x20000000u;
constexpr uint32_t kImageScnCntUninitializedData = 0x00000080u;

bool PackerSectionName(const std::string& name) {
    std::string normalized = name;
    for (char& c : normalized)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    static const char* kNames[] = {
        "upx0", "upx1", "upx2", "upx3", ".aspack", ".adata", ".themida",
        ".vmp0", ".vmp1", ".petite", ".nsp0", ".nsp1", ".mpress1",
        ".mpress2", ".packed", ".enigma1", ".enigma2", ".y0da", ".boom",
    };
    for (const char* known : kNames)
        if (normalized == known) return true;
    return false;
}

/* Shannon entropy over at most the first sampleLimit bytes. */
double BufferedEntropy(const uint8_t* data, size_t length,
                       size_t sampleLimit) {
    size_t sample = length < sampleLimit ? length : sampleLimit;
    if (sample == 0) return 0.0;
    size_t counts[256] = {};
    for (size_t i = 0; i < sample; ++i) ++counts[data[i]];
    double entropy = 0.0;
    for (size_t i = 0; i < 256; ++i) {
        if (counts[i] == 0) continue;
        double p = static_cast<double>(counts[i]) / static_cast<double>(sample);
        entropy -= p * std::log2(p);
    }
    return entropy;
}

uint16_t ReadU16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0]) |
           (static_cast<uint16_t>(p[1]) << 8);
}

uint32_t ReadU32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

struct SectionView {
    std::string name;
    uint32_t virtualSize = 0;
    uint32_t rawSize = 0;
    uint32_t rawOffset = 0;
    uint32_t characteristics = 0;
};

void CapAdd(uint32_t& bucket, uint32_t amount, uint32_t cap) {
    uint32_t next = bucket + amount;
    bucket = next > cap ? cap : next;
}

} // namespace

PeAnomalyFinding ScanPeBuffer(const uint8_t* data, size_t length,
                              uint64_t nowUnixSeconds) {
    PeAnomalyFinding finding;
    /* DOS header: 'MZ' + e_lfanew at 0x3C. */
    if (length < 0x40 || data[0] != 'M' || data[1] != 'Z') return finding;
    uint32_t peOffset = ReadU32(data + 0x3C);
    if (peOffset < 0x40 || peOffset > length - 24) return finding;
    /* PE signature "PE\0\0" + COFF header (20 bytes). */
    if (peOffset + 24 > length || data[peOffset] != 'P' ||
        data[peOffset + 1] != 'E' || data[peOffset + 2] != 0 ||
        data[peOffset + 3] != 0)
        return finding;
    const uint8_t* coff = data + peOffset + 4;
    uint16_t sectionCount = ReadU16(coff + 2);
    uint32_t timestamp = ReadU32(coff + 4);
    uint16_t optionalSize = ReadU16(coff + 16);
    const uint8_t* optional = coff + 20;
    if (optionalSize > 0 &&
        static_cast<size_t>(optional - data) + optionalSize > length)
        return finding;
    size_t sectionsOffset = static_cast<size_t>(optional - data) +
                            optionalSize;
    if (static_cast<size_t>(optional - data) + optionalSize +
            static_cast<size_t>(sectionCount) * 40 >
        length)
        return finding;

    finding.valid = true;
    uint32_t packerScore = 0, structureScore = 0, miscScore = 0;

    if (sectionCount == 0) {
        finding.signals.push_back("zero sections");
        CapAdd(structureScore, 20, 60);
    } else if (sectionCount > 16) {
        finding.signals.push_back("unusual section count " +
                                  std::to_string(sectionCount));
        CapAdd(structureScore, 15, 60);
    }

    constexpr uint64_t kSecondsPerDay = 86400ULL;
    if (timestamp == 0) {
        finding.signals.push_back("zero compile timestamp");
        CapAdd(miscScore, 15, 60);
    } else if (nowUnixSeconds != 0 &&
               static_cast<uint64_t>(timestamp) >
                   nowUnixSeconds + 366ULL * kSecondsPerDay) {
        finding.signals.push_back("future compile timestamp");
        CapAdd(miscScore, 15, 60);
    }

    uint32_t endOfRaw = 0;
    for (uint16_t i = 0; i < sectionCount; ++i) {
        const uint8_t* raw = data + sectionsOffset + static_cast<size_t>(i) * 40;
        SectionView section;
        const char* nameBytes = reinterpret_cast<const char*>(raw);
        size_t nameLen = 0;
        while (nameLen < 8 && nameBytes[nameLen] != '\0') ++nameLen;
        section.name.assign(nameBytes, nameLen);
        section.virtualSize = ReadU32(raw + 8);
        section.rawSize = ReadU32(raw + 16);
        section.rawOffset = ReadU32(raw + 20);
        section.characteristics = ReadU32(raw + 36);

        const bool writable =
            (section.characteristics & kImageScnMemWrite) != 0;
        const bool executable =
            (section.characteristics & kImageScnMemExecute) != 0;
        const bool readable =
            (section.characteristics & kImageScnMemRead) != 0;

        if (PackerSectionName(section.name)) {
            finding.signals.push_back("packer section '" + section.name + "'");
            finding.anomalousSections += section.name + ",";
            CapAdd(packerScore, 30, 60);
        }
        if (nameLen == 0 && section.rawSize > 0) {
            finding.signals.push_back("nameless section with content");
            finding.anomalousSections += "<noname>,";
            CapAdd(structureScore, 20, 60);
        }
        if (writable && executable && readable) {
            finding.signals.push_back("writable+executable section '" +
                                      section.name + "'");
            finding.anomalousSections += section.name + ",";
            CapAdd(structureScore, 25, 60);
        }
        if (section.rawSize == 0 && section.virtualSize > 0 &&
            (section.characteristics & kImageScnCntUninitializedData) == 0) {
            finding.signals.push_back("virtual-only section '" +
                                      section.name + "'");
            finding.anomalousSections += section.name + ",";
            CapAdd(structureScore, 25, 60);
        }
        if (executable && section.rawSize > 0 &&
            section.rawOffset < length &&
            section.rawOffset + section.rawSize <= length) {
            double entropy =
                BufferedEntropy(data + section.rawOffset, section.rawSize,
                                64 * 1024);
            if (entropy > 7.6) {
                finding.signals.push_back(
                    "very high entropy executable section '" +
                    section.name + "'");
                finding.anomalousSections += section.name + ",";
                CapAdd(miscScore, 35, 60);
            } else if (entropy > 7.2) {
                finding.signals.push_back("high entropy executable section '" +
                                          section.name + "'");
                finding.anomalousSections += section.name + ",";
                CapAdd(miscScore, 25, 60);
            }
        }
        uint32_t sectionEnd =
            section.rawOffset > UINT32_MAX - section.rawSize
                ? UINT32_MAX
                : section.rawOffset + section.rawSize;
        if (sectionEnd > endOfRaw) endOfRaw = sectionEnd;
    }

    if (endOfRaw > 0 && length > endOfRaw + 4096) {
        finding.signals.push_back("overlay data " +
                                  std::to_string(length - endOfRaw) +
                                  " bytes");
        CapAdd(miscScore, 15, 60);
    }

    finding.score = packerScore + structureScore + miscScore;
    if (finding.score > 100) finding.score = 100;
    if (!finding.anomalousSections.empty() &&
        finding.anomalousSections.back() == ',')
        finding.anomalousSections.pop_back();
    return finding;
}

} // namespace edr
