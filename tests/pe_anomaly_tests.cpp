/*
 * pe_anomaly_tests.cpp - Unit tests for ScanPeBuffer + PeAnomalyDetector.
 */
#include "pe_anomaly_tests.h"

#include <windows.h>

#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

#include "edr_event.h"
#include "event_bus.h"
#include "pe_anomaly_detector.h"
#include "pe_anomaly_scan.h"

namespace {

#define PE_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error("pe anomaly test failed at line " +
                                 std::to_string(line) + ": " + expression);
}

constexpr uint32_t kImageScnMemRead = 0x40000000u;
constexpr uint32_t kImageScnMemWrite = 0x80000000u;
constexpr uint32_t kImageScnMemExecute = 0x20000000u;
constexpr uint32_t kImageScnCntUninitializedData = 0x00000080u;
constexpr uint32_t kImageScnCntCode = 0x00000020u;
constexpr uint64_t kNowUnix = 1756000000ULL; /* fixed "now" for tests */

void PutU16(std::vector<uint8_t>* buffer, size_t offset, uint16_t value) {
    (*buffer)[offset] = static_cast<uint8_t>(value & 0xFF);
    (*buffer)[offset + 1] = static_cast<uint8_t>(value >> 8);
}

void PutU32(std::vector<uint8_t>* buffer, size_t offset, uint32_t value) {
    (*buffer)[offset] = static_cast<uint8_t>(value & 0xFF);
    (*buffer)[offset + 1] = static_cast<uint8_t>((value >> 8) & 0xFF);
    (*buffer)[offset + 2] = static_cast<uint8_t>((value >> 16) & 0xFF);
    (*buffer)[offset + 3] = static_cast<uint8_t>((value >> 24) & 0xFF);
}

struct SectionSpec {
    const char* name;      /* nullptr = nameless */
    uint32_t virtualSize;
    uint32_t rawSize;
    uint32_t rawOffset;
    uint32_t characteristics;
    bool fillRandom;       /* fill raw data with pseudo-random bytes */
};

/* Build a little-endian PE32+ image with the given sections. */
std::vector<uint8_t> BuildPe(uint32_t timestamp,
                             const std::vector<SectionSpec>& sections,
                             size_t overlayBytes = 0) {
    size_t headersSize = 0x80 + 4 + 20 + 240 + sections.size() * 40;
    size_t maxRawEnd = 0;
    for (const SectionSpec& section : sections) {
        size_t end = static_cast<size_t>(section.rawOffset) +
                     section.rawSize;
        if (end > maxRawEnd) maxRawEnd = end;
    }
    size_t total = headersSize > maxRawEnd ? headersSize : maxRawEnd;
    total += overlayBytes;
    std::vector<uint8_t> buffer(total, 0);

    buffer[0] = 'M';
    buffer[1] = 'Z';
    PutU32(&buffer, 0x3C, 0x80);
    size_t pe = 0x80;
    buffer[pe] = 'P';
    buffer[pe + 1] = 'E';
    buffer[pe + 2] = 0;
    buffer[pe + 3] = 0;
    size_t coff = pe + 4;
    PutU16(&buffer, coff + 0, 0x8664);                 /* machine x64 */
    PutU16(&buffer, coff + 2,
           static_cast<uint16_t>(sections.size()));    /* section count */
    PutU32(&buffer, coff + 4, timestamp);              /* time stamp */
    PutU16(&buffer, coff + 16, 240);                   /* optional size */
    size_t optional = coff + 20;
    PutU16(&buffer, optional, 0x20B);                  /* PE32+ magic */
    size_t sectionTable = optional + 240;
    for (size_t i = 0; i < sections.size(); ++i) {
        const SectionSpec& spec = sections[i];
        size_t entry = sectionTable + i * 40;
        if (spec.name != nullptr) {
            size_t nameLen = std::strlen(spec.name);
            if (nameLen > 8) nameLen = 8;
            std::memcpy(&buffer[entry], spec.name, nameLen);
        }
        PutU32(&buffer, entry + 8, spec.virtualSize);
        PutU32(&buffer, entry + 12,
               0x1000 * static_cast<uint32_t>(i + 1)); /* virtual address */
        PutU32(&buffer, entry + 16, spec.rawSize);
        PutU32(&buffer, entry + 20, spec.rawOffset);
        PutU32(&buffer, entry + 36, spec.characteristics);
        if (spec.fillRandom && spec.rawSize > 0) {
            uint32_t seed = 0x9E3779B9u;
            for (uint32_t j = 0; j < spec.rawSize; ++j) {
                seed = seed * 1664525u + 1013904223u;
                if (spec.rawOffset + j < buffer.size())
                    buffer[spec.rawOffset + j] =
                        static_cast<uint8_t>(seed >> 24);
            }
        }
    }
    return buffer;
}

edr::Event FileEvent(uint16_t type, uint64_t ts100ns, const char* path) {
    edr::Event event;
    event.type = type;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] =
        type == EDR_EVT_FILE_CREATE ? "FILE_CREATE" : "FILE_RENAME";
    event.fields[edr::field::kFilePath] = path;
    return event;
}

std::string Score(const edr::Event& event) {
    auto it = event.fields.find(edr::field::kPeAnomalyScore);
    return it == event.fields.end() ? "" : it->second;
}

bool HasSignal(const edr::PeAnomalyFinding& finding, const char* needle) {
    for (const std::string& signal : finding.signals)
        if (signal.find(needle) != std::string::npos) return true;
    return false;
}

constexpr uint64_t kSecond = 10000000ULL;

/* Temp directory for detector file tests. */
std::string MakeTempDir() {
    char path[MAX_PATH];
    UINT len = GetTempPathA(MAX_PATH, path);
    if (len == 0 || len >= MAX_PATH) return "";
    std::string dir = std::string(path) + "edr_pe_anomaly_test";
    CreateDirectoryA(dir.c_str(), nullptr);
    return dir;
}

bool WriteTempFile(const std::string& dir, const char* name,
                   const std::vector<uint8_t>& bytes, std::string* outPath) {
    std::string full = dir + "\\" + name;
    HANDLE handle = CreateFileA(full.c_str(), GENERIC_WRITE, 0, nullptr,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    bool ok = WriteFile(handle, bytes.data(),
                        static_cast<DWORD>(bytes.size()), &written,
                        nullptr) &&
              written == bytes.size();
    CloseHandle(handle);
    if (ok) *outPath = full;
    return ok;
}

} // namespace

void RunPeAnomalyTests() {
    std::fprintf(stderr, "[pe-anomaly] TestCleanPeSilent\n");
    {
        std::vector<uint8_t> pe = BuildPe(
            1600000000u,
            {{".text", 0x200, 0x200, 0x400, kImageScnCntCode |
                                                   kImageScnMemExecute |
                                                   kImageScnMemRead, false}});
        edr::PeAnomalyFinding finding = edr::ScanPeBuffer(
            pe.data(), pe.size(), kNowUnix);
        PE_CHECK(finding.valid);
        PE_CHECK(finding.signals.empty());
        PE_CHECK(finding.score == 0);
    }

    std::fprintf(stderr, "[pe-anomaly] TestNonPeRejected\n");
    {
        const char* text = "this is not an executable";
        edr::PeAnomalyFinding finding = edr::ScanPeBuffer(
            reinterpret_cast<const uint8_t*>(text), std::strlen(text),
            kNowUnix);
        PE_CHECK(!finding.valid);
        PE_CHECK(finding.score == 0);
    }

    std::fprintf(stderr, "[pe-anomaly] TestPackedPeScores\n");
    {
        std::vector<uint8_t> pe = BuildPe(
            1600000000u,
            {/* UPX0: virtual-only RWX section */
             {"UPX0", 0x1000, 0, 0,
              kImageScnMemRead | kImageScnMemWrite | kImageScnMemExecute,
              false},
             /* UPX1: packed high-entropy payload (4096 random bytes so
              * the sample entropy ~7.95 clears the 7.6 band reliably) */
             {"UPX1", 0x1100, 0x1000, 0x400,
              kImageScnCntCode | kImageScnMemExecute | kImageScnMemRead,
              true}});
        edr::PeAnomalyFinding finding = edr::ScanPeBuffer(
            pe.data(), pe.size(), kNowUnix);
        PE_CHECK(finding.valid);
        PE_CHECK(HasSignal(finding, "packer section 'UPX0'"));
        PE_CHECK(HasSignal(finding, "virtual-only section 'UPX0'"));
        PE_CHECK(HasSignal(finding, "writable+executable section 'UPX0'"));
        PE_CHECK(HasSignal(finding, "entropy executable section 'UPX1'"));
        PE_CHECK(finding.score >= 75);
        PE_CHECK(finding.score <= 100);
        PE_CHECK(finding.anomalousSections.find("UPX0") !=
                 std::string::npos);
    }

    std::fprintf(stderr, "[pe-anomaly] TestWeakSignalsBelowBand\n");
    {
        /* Nameless section with content alone scores 20: valid finding,
         * but below the 55 alert band. */
        std::vector<uint8_t> pe = BuildPe(
            1600000000u,
            {{nullptr, 0x100, 0x100, 0x400, kImageScnCntCode |
                                                kImageScnMemRead, false}});
        edr::PeAnomalyFinding finding = edr::ScanPeBuffer(
            pe.data(), pe.size(), kNowUnix);
        PE_CHECK(finding.valid);
        PE_CHECK(HasSignal(finding, "nameless section"));
        PE_CHECK(finding.score == 20);
    }

    std::fprintf(stderr, "[pe-anomaly] TestTimestampAnomalies\n");
    {
        std::vector<uint8_t> zero = BuildPe(
            0u,
            {{".text", 0x100, 0x100, 0x400, kImageScnCntCode |
                                                kImageScnMemExecute |
                                                kImageScnMemRead, false}});
        edr::PeAnomalyFinding zeroFinding = edr::ScanPeBuffer(
            zero.data(), zero.size(), kNowUnix);
        PE_CHECK(HasSignal(zeroFinding, "zero compile timestamp"));
        PE_CHECK(zeroFinding.score == 15);

        std::vector<uint8_t> future = BuildPe(
            static_cast<uint32_t>(kNowUnix + 400ULL * 86400ULL),
            {{".text", 0x100, 0x100, 0x400, kImageScnCntCode |
                                                kImageScnMemExecute |
                                                kImageScnMemRead, false}});
        edr::PeAnomalyFinding futureFinding = edr::ScanPeBuffer(
            future.data(), future.size(), kNowUnix);
        PE_CHECK(HasSignal(futureFinding, "future compile timestamp"));
    }

    std::fprintf(stderr, "[pe-anomaly] TestOverlaySignal\n");
    {
        std::vector<uint8_t> pe = BuildPe(
            1600000000u,
            {{".text", 0x100, 0x100, 0x400, kImageScnCntCode |
                                                kImageScnMemExecute |
                                                kImageScnMemRead, false}},
            8192);
        edr::PeAnomalyFinding finding = edr::ScanPeBuffer(
            pe.data(), pe.size(), kNowUnix);
        PE_CHECK(HasSignal(finding, "overlay data"));
        PE_CHECK(finding.score == 15);
    }

    std::fprintf(stderr, "[pe-anomaly] TestDetectorDisabled\n");
    {
        edr::PeAnomalyDetector detector(false, 55, 300, 64, 4 * 1024 * 1024,
                                        {});
        std::string dir = MakeTempDir();
        PE_CHECK(!dir.empty());
        std::string path;
        std::vector<uint8_t> pe = BuildPe(
            1600000000u,
            {{"UPX0", 0x1000, 0, 0,
              kImageScnMemRead | kImageScnMemWrite | kImageScnMemExecute,
              false}});
        PE_CHECK(WriteTempFile(dir, "packed.exe", pe, &path));
        edr::Event event = FileEvent(EDR_EVT_FILE_CREATE, 1000,
                                     path.c_str());
        detector.Enrich(event);
        PE_CHECK(Score(event).empty());
    }

    std::fprintf(stderr, "[pe-anomaly] TestDetectorStampsPackedPe\n");
    {
        std::string dir = MakeTempDir();
        PE_CHECK(!dir.empty());
        std::string path;
        std::vector<uint8_t> pe = BuildPe(
            1600000000u,
            {{"UPX0", 0x1000, 0, 0,
              kImageScnMemRead | kImageScnMemWrite | kImageScnMemExecute,
              false},
             {"UPX1", 0x1100, 0x1000, 0x400,
              kImageScnCntCode | kImageScnMemExecute | kImageScnMemRead,
              true}});
        PE_CHECK(WriteTempFile(dir, "packed2.exe", pe, &path));
        edr::PeAnomalyDetector detector(true, 55, 300, 64, 4 * 1024 * 1024,
                                        {});
        edr::Event event = FileEvent(EDR_EVT_FILE_CREATE, 1000,
                                     path.c_str());
        detector.Enrich(event);
        PE_CHECK(!Score(event).empty());
        PE_CHECK(std::stoi(Score(event)) >= 75);

        /* Dedup: the same path inside the window is suppressed. */
        edr::Event repeat = FileEvent(EDR_EVT_FILE_CREATE, 2 * kSecond,
                                      path.c_str());
        detector.Enrich(repeat);
        PE_CHECK(Score(repeat).empty());
    }

    std::fprintf(stderr, "[pe-anomaly] TestDetectorSilentCases\n");
    {
        std::string dir = MakeTempDir();
        PE_CHECK(!dir.empty());

        /* Non-PE content with .exe extension stays silent. */
        std::string textPath;
        std::vector<uint8_t> textBytes = {'h', 'e', 'l', 'l', 'o'};
        PE_CHECK(WriteTempFile(dir, "text.exe", textBytes, &textPath));
        edr::PeAnomalyDetector detector(true, 55, 300, 64, 4 * 1024 * 1024,
                                        {});
        edr::Event textEvent = FileEvent(EDR_EVT_FILE_CREATE, 1000,
                                         textPath.c_str());
        detector.Enrich(textEvent);
        PE_CHECK(Score(textEvent).empty());

        /* PE content with a non-PE extension stays silent. */
        std::string txtPePath;
        std::vector<uint8_t> pe = BuildPe(
            1600000000u,
            {{"UPX0", 0x1000, 0, 0,
              kImageScnMemRead | kImageScnMemWrite | kImageScnMemExecute,
              false}});
        PE_CHECK(WriteTempFile(dir, "packed.txt", pe, &txtPePath));
        edr::Event txtEvent = FileEvent(EDR_EVT_FILE_CREATE, 1000,
                                        txtPePath.c_str());
        detector.Enrich(txtEvent);
        PE_CHECK(Score(txtEvent).empty());

        /* Clean PE below min_score stays silent. */
        std::string cleanPath;
        std::vector<uint8_t> clean = BuildPe(
            1600000000u,
            {{".text", 0x100, 0x100, 0x400, kImageScnCntCode |
                                                kImageScnMemExecute |
                                                kImageScnMemRead, false}});
        PE_CHECK(WriteTempFile(dir, "clean.dll", clean, &cleanPath));
        edr::Event cleanEvent = FileEvent(EDR_EVT_FILE_CREATE, 1000,
                                          cleanPath.c_str());
        detector.Enrich(cleanEvent);
        PE_CHECK(Score(cleanEvent).empty());
    }

    std::fprintf(stderr, "[pe-anomaly] TestScanDirsFilter\n");
    {
        std::string dir = MakeTempDir();
        PE_CHECK(!dir.empty());
        std::string path;
        std::vector<uint8_t> pe = BuildPe(
            1600000000u,
            {{"UPX0", 0x1000, 0, 0,
              kImageScnMemRead | kImageScnMemWrite | kImageScnMemExecute,
              false}});
        PE_CHECK(WriteTempFile(dir, "filtered.exe", pe, &path));

        /* Directory filter that does not match the temp dir suppresses. */
        edr::PeAnomalyDetector restricted(
            true, 55, 300, 64, 4 * 1024 * 1024,
            {"C:\\definitely-not-here"});
        edr::Event event = FileEvent(EDR_EVT_FILE_CREATE, 1000,
                                     path.c_str());
        restricted.Enrich(event);
        PE_CHECK(Score(event).empty());

        /* Matching directory prefix (case-insensitive) scans. */
        std::string loweredDir = dir;
        for (char& c : loweredDir)
            c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
        edr::PeAnomalyDetector allowed(true, 55, 300, 64, 4 * 1024 * 1024,
                                       {loweredDir});
        edr::Event allowedEvent = FileEvent(EDR_EVT_FILE_CREATE, 1000,
                                            path.c_str());
        allowed.Enrich(allowedEvent);
        PE_CHECK(!Score(allowedEvent).empty());
    }

    std::fprintf(stderr, "[pe-anomaly] all passed\n");
}
