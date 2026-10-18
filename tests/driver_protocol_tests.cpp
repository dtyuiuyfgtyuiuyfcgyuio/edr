/*
 * driver_protocol_tests.cpp - Wire-format, policy validation, and parser
 * protocol tests for the Phase B+C driver protocol.
 *
 * The policy validator under test (EdrPolicyValidate) is the exact pure-C
 * implementation the kernel driver links (driver/policy_validate.h), so a
 * green test here proves the kernel's whole-table rejection semantics.
 * Layout assertions are compile-time; malformed tables are runtime.
 */
#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "config.h"
#include "driver_event_parser.h"
#include "driver_policy_publisher.h"
#include "edr_event.h"
#include "edr_ioctl.h"
#include "edr_policy_engine.h"
#include "event_bus.h"
#include "policy_validate.h"
#include "response_policy.h"

namespace {

int gFailures = 0;

#define CHECK(cond)                                              \
    do {                                                         \
        if (!(cond)) {                                           \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__,  \
                         __LINE__, #cond);                       \
            gFailures++;                                         \
        }                                                        \
    } while (0)

/* ---- compile-time layout assertions (Phase B+C exact facts) ---- */

static_assert(sizeof(EDR_POLICY_FILE_RULE) == 516,
              "file rule must be 516 bytes");
static_assert(sizeof(EDR_POLICY_NET_RULE) == 8,
              "net rule must be 8 bytes");
static_assert(sizeof(EDR_POLICY_V1) == 17056,
              "policy table must be 17056 bytes");
static_assert(FIELD_OFFSET(EDR_POLICY_V1, file_rules) == 32,
              "file rules must start at offset 32");
static_assert(FIELD_OFFSET(EDR_POLICY_V1, net_rules) == 16544,
              "net rules must start at offset 16544");
static_assert(sizeof(EDR_EVENT_HEADER) == 36,
              "event header must be 36 bytes");
static_assert(sizeof(EDR_TLV_HEADER) == 4,
              "TLV header must be 4 bytes");
static_assert(EDR_ENABLE_KNOWN_MASK == 0x3fu,
              "KNOWN_MASK must be 0x3f (PROCESS|REGISTRY|FILE|NET|BLOCK|OBJECT_HANDLE)");
static_assert(EDR_EVT_BLOCK == 30u,
              "BLOCK event type must be 30 (24-29 taken by other collectors)");
static_assert(EDR_TAG_RULE_INDEX == 10u,
              "RULE_INDEX TLV tag must be 10 (1-9 taken)");
static_assert(EDR_MAX_FILE_RULES == 32u, "file rule cap");
static_assert(EDR_MAX_NET_RULES == 64u, "net rule cap");
static_assert(EDR_PATH_MAX_BYTES == 512u, "path byte cap");

/* ---- helpers ---- */

static void FillFileRule(EDR_POLICY_FILE_RULE* r, const wchar_t* prefix)
{
    size_t n = wcslen(prefix);
    memset(r, 0, sizeof(*r));
    r->length = (unsigned short)(n * sizeof(wchar_t));
    memcpy(r->path, prefix, n * sizeof(wchar_t));
}

static void FillNetRule(EDR_POLICY_NET_RULE* r, uint8_t a, uint8_t b,
                        uint8_t c, uint8_t d, uint16_t port)
{
    memset(r, 0, sizeof(*r));
    r->ip[0] = a; r->ip[1] = b; r->ip[2] = c; r->ip[3] = d;
    r->port = port;
}

static EDR_POLICY_V1 MakeValidPolicy(void)
{
    EDR_POLICY_V1 p;
    memset(&p, 0, sizeof(p));
    p.version = EDR_POLICY_VERSION;
    p.struct_size = sizeof(p);
    p.generation = 7;
    p.enable_mask = EDR_ENABLE_PROCESS | EDR_ENABLE_REGISTRY |
                    EDR_ENABLE_FILE | EDR_ENABLE_NET | EDR_ENABLE_BLOCK;
    p.file_rule_count = 1;
    p.net_rule_count = 1;
    FillFileRule(&p.file_rules[0], L"\\Device\\HarddiskVolume1\\Windows");
    FillNetRule(&p.net_rules[0], 203, 0, 113, 10, 443);
    return p;
}

/* ---- EdrPolicyValidate whole-table rejection ---- */

static void TestValidPolicyAccepted(void)
{
    EDR_POLICY_V1 p = MakeValidPolicy();
    CHECK(EdrPolicyValidate(&p, sizeof(p)) == 0);
}

static void TestSizeChecks(void)
{
    EDR_POLICY_V1 p = MakeValidPolicy();
    CHECK(EdrPolicyValidate(&p, sizeof(p) - 1) != 0);
    CHECK(EdrPolicyValidate(&p, sizeof(p) + 1) != 0);
    CHECK(EdrPolicyValidate(nullptr, sizeof(p)) != 0);
    CHECK(EdrPolicyValidate(&p, 0) != 0);
}

static void TestHeaderFieldRejects(void)
{
    EDR_POLICY_V1 p = MakeValidPolicy();
    p.version = 2;
    CHECK(EdrPolicyValidate(&p, sizeof(p)) != 0);

    p = MakeValidPolicy();
    p.struct_size = sizeof(p) - 1;
    CHECK(EdrPolicyValidate(&p, sizeof(p)) != 0);

    p = MakeValidPolicy();
    p.generation = 0;
    CHECK(EdrPolicyValidate(&p, sizeof(p)) != 0);

    p = MakeValidPolicy();
    p.enable_mask = 0x80u; /* unknown bit (0x20 is now EDR_ENABLE_OBJECT_HANDLE) */
    CHECK(EdrPolicyValidate(&p, sizeof(p)) != 0);

    p = MakeValidPolicy();
    p.enable_mask = 0x1Fu | 0x40u;
    CHECK(EdrPolicyValidate(&p, sizeof(p)) != 0);

    p = MakeValidPolicy();
    p.reserved[0] = 1;
    CHECK(EdrPolicyValidate(&p, sizeof(p)) != 0);

    p = MakeValidPolicy();
    p.reserved[1] = 0xDEADBEEF;
    CHECK(EdrPolicyValidate(&p, sizeof(p)) != 0);
}

static void TestFileRuleRejects(void)
{
    EDR_POLICY_V1 p;

    /* Reserved nonzero. */
    p = MakeValidPolicy();
    p.file_rules[0].reserved = 1;
    CHECK(EdrPolicyValidate(&p, sizeof(p)) != 0);

    /* Zero length. */
    p = MakeValidPolicy();
    p.file_rules[0].length = 0;
    CHECK(EdrPolicyValidate(&p, sizeof(p)) != 0);

    /* Odd byte length. */
    p = MakeValidPolicy();
    p.file_rules[0].length = 3;
    CHECK(EdrPolicyValidate(&p, sizeof(p)) != 0);

    /* Over-cap length. */
    p = MakeValidPolicy();
    p.file_rules[0].length = EDR_PATH_MAX_BYTES + 2;
    CHECK(EdrPolicyValidate(&p, sizeof(p)) != 0);

    /* Missing leading backslash. */
    p = MakeValidPolicy();
    p.file_rules[0].path[0] = L'C';
    CHECK(EdrPolicyValidate(&p, sizeof(p)) != 0);

    /* Embedded NUL inside the declared prefix. */
    p = MakeValidPolicy();
    p.file_rules[0].path[4] = L'\0';
    CHECK(EdrPolicyValidate(&p, sizeof(p)) != 0);

    /* Unpaired high surrogate at the end. */
    p = MakeValidPolicy();
    FillFileRule(&p.file_rules[0], L"\\x");
    p.file_rules[0].length = 6;
    p.file_rules[0].path[1] = (wchar_t)0xD800u;
    p.file_rules[0].path[2] = L'x';
    CHECK(EdrPolicyValidate(&p, sizeof(p)) != 0);

    /* Lone low surrogate. */
    p = MakeValidPolicy();
    FillFileRule(&p.file_rules[0], L"\\x");
    p.file_rules[0].length = 4;
    p.file_rules[0].path[1] = (wchar_t)0xDC00u;
    CHECK(EdrPolicyValidate(&p, sizeof(p)) != 0);

    /* Valid surrogate pair must pass (used in prefix). */
    p = MakeValidPolicy();
    FillFileRule(&p.file_rules[0], L"\\x\xD83D\xDCFF");
    CHECK(EdrPolicyValidate(&p, sizeof(p)) == 0);

    /* Bytes beyond the declared length must be zero: corrupt one tail byte
     * at offset 8 (past the 4-byte prefix "\x" plus the 4-byte header). */
    p = MakeValidPolicy();
    FillFileRule(&p.file_rules[0], L"\\x");
    p.file_rules[0].path[2] = (wchar_t)1;
    CHECK(EdrPolicyValidate(&p, sizeof(p)) != 0);

    /* Unused slot must be all zero. */
    p = MakeValidPolicy();
    p.file_rules[1].length = 4;
    p.file_rules[1].path[0] = L'\\';
    p.file_rules[1].path[1] = L'x';
    CHECK(EdrPolicyValidate(&p, sizeof(p)) != 0);

    /* Unused slot zero is fine. */
    p = MakeValidPolicy();
    CHECK(EdrPolicyValidate(&p, sizeof(p)) == 0);
}

static void TestDuplicateFileRules(void)
{
    EDR_POLICY_V1 p = MakeValidPolicy();
    p.file_rule_count = 2;
    p.file_rules[1] = p.file_rules[0]; /* exact duplicate */
    CHECK(EdrPolicyValidate(&p, sizeof(p)) != 0);

    /* Case-insensitive duplicate. */
    p = MakeValidPolicy();
    p.file_rule_count = 2;
    p.file_rules[1] = p.file_rules[0];
    p.file_rules[1].path[8] = L'W'; /* "windows" -> "Windows" only differs */
    FillFileRule(&p.file_rules[1], L"\\device\\harddiskvolume1\\windows");
    CHECK(EdrPolicyValidate(&p, sizeof(p)) != 0);

    /* Distinct prefixes pass. */
    p = MakeValidPolicy();
    p.file_rule_count = 2;
    FillFileRule(&p.file_rules[1], L"\\Device\\HarddiskVolume1\\Program");
    CHECK(EdrPolicyValidate(&p, sizeof(p)) == 0);
}

static void TestNetRuleRejects(void)
{
    EDR_POLICY_V1 p;

    /* Reserved nonzero. */
    p = MakeValidPolicy();
    p.net_rules[0].reserved = 1;
    CHECK(EdrPolicyValidate(&p, sizeof(p)) != 0);

    /* Unspecified 0.0.0.0. */
    p = MakeValidPolicy();
    FillNetRule(&p.net_rules[0], 0, 0, 0, 0, 80);
    CHECK(EdrPolicyValidate(&p, sizeof(p)) != 0);

    /* Loopback. */
    p = MakeValidPolicy();
    FillNetRule(&p.net_rules[0], 127, 0, 0, 1, 80);
    CHECK(EdrPolicyValidate(&p, sizeof(p)) != 0);

    /* Multicast. */
    p = MakeValidPolicy();
    FillNetRule(&p.net_rules[0], 224, 1, 1, 1, 80);
    CHECK(EdrPolicyValidate(&p, sizeof(p)) != 0);

    /* Limited broadcast. */
    p = MakeValidPolicy();
    FillNetRule(&p.net_rules[0], 255, 255, 255, 255, 80);
    CHECK(EdrPolicyValidate(&p, sizeof(p)) != 0);

    /* Private address is legal. */
    p = MakeValidPolicy();
    FillNetRule(&p.net_rules[0], 10, 1, 2, 3, 53);
    CHECK(EdrPolicyValidate(&p, sizeof(p)) == 0);

    /* Port 0 (any) is legal. */
    p = MakeValidPolicy();
    FillNetRule(&p.net_rules[0], 203, 0, 113, 9, 0);
    CHECK(EdrPolicyValidate(&p, sizeof(p)) == 0);

    /* Unused slot must be all zero. */
    p = MakeValidPolicy();
    FillNetRule(&p.net_rules[1], 1, 2, 3, 4, 80);
    CHECK(EdrPolicyValidate(&p, sizeof(p)) != 0);
}

static void TestDuplicateNetRules(void)
{
    EDR_POLICY_V1 p = MakeValidPolicy();
    p.net_rule_count = 2;
    p.net_rules[1] = p.net_rules[0];
    CHECK(EdrPolicyValidate(&p, sizeof(p)) != 0);

    /* Same IP, different port is legal. */
    p = MakeValidPolicy();
    p.net_rule_count = 2;
    p.net_rules[1] = p.net_rules[0];
    p.net_rules[1].port = 8443;
    CHECK(EdrPolicyValidate(&p, sizeof(p)) == 0);
}

/* ---- whole-table atomicity: one bad rule anywhere rejects all ---- */

static void TestWholeTableRejection(void)
{
    EDR_POLICY_V1 p = MakeValidPolicy();
    /* Corrupt the LAST net rule slot far away from the header. */
    FillNetRule(&p.net_rules[63], 1, 2, 3, 4, 80);
    CHECK(EdrPolicyValidate(&p, sizeof(p)) != 0);

    p = MakeValidPolicy();
    FillNetRule(&p.net_rules[63], 0, 0, 0, 0, 0); /* zero = unused, ok */
    CHECK(EdrPolicyValidate(&p, sizeof(p)) == 0);
}

/* ---- policy_validate.h must be includable and identical in C++ ---- */

static void TestPolicyVersionConstants(void)
{
    CHECK(EDR_POLICY_VERSION == 1u);
    CHECK(EDR_MAX_FILE_RULES == 32u);
    CHECK(EDR_MAX_NET_RULES == 64u);
    CHECK(EDR_PATH_MAX_BYTES == 512u);
}

/* ---- Kill-IOCTL response plane: code uniqueness and wire contract ---- */

static void TestKillProcessIoctlContract(void)
{
    /* The three IOCTL function codes must stay distinct: 0x800 fetch,
     * 0x801 policy, 0x802 kill. A collision would silently re-route one
     * plane's IRPs to another's handler. */
    const ULONG fetchCode = (ULONG)IOCTL_EDR_FETCH_EVENT;
    const ULONG policyCode = (ULONG)IOCTL_EDR_SET_POLICY;
    const ULONG killCode = (ULONG)IOCTL_EDR_KILL_PROCESS;
    CHECK(fetchCode != policyCode);
    CHECK(fetchCode != killCode);
    CHECK(policyCode != killCode);

    /* Function-code extraction: bits 2..13. Verify the kill IOCTL sits
     * at 0x802 exactly. */
    CHECK(((killCode >> 2) & 0xfff) == 0x802u);

    /* The kill IOCTL requires FILE_WRITE_ACCESS on the device handle:
     * the access field lives in bits 14..15 of the CTL_CODE. This is the
     * gate that keeps a read-only device opener from terminating
     * processes. */
    CHECK(((killCode >> 14) & 0x3) == FILE_WRITE_ACCESS);
    CHECK(((fetchCode >> 14) & 0x3) == FILE_ANY_ACCESS);

    /* METHOD_BUFFERED for all three: SystemBuffer carries the payload.
     * Method is bits 0..1. */
    CHECK((killCode & 0x3) == METHOD_BUFFERED);
    CHECK((policyCode & 0x3) == METHOD_BUFFERED);

    /* Exercise the exact decoder used by the kernel, regardless of HANDLE
     * width. Invalid frames must not modify the caller's output. */
    CHECK(sizeof(EDR_KILL_PROCESS_REQUEST) == 4);
    CHECK(offsetof(EDR_KILL_PROCESS_REQUEST, pid) == 0);
    CHECK(EDR_KILL_PROCESS_REQUEST_SIZE == 4);
    unsigned char bytes[9] = {0, 0x78, 0x56, 0x34, 0x12};
    UINT32 pid = 9;
    for (ULONG length : {0UL, 3UL, 5UL, 8UL}) {
        CHECK(!EdrDecodeKillProcessRequest(bytes + 1, length, &pid));
        CHECK(pid == 9);
    }
    CHECK(!EdrDecodeKillProcessRequest(nullptr, 4, &pid));
    CHECK(!EdrDecodeKillProcessRequest(bytes + 1, 4, nullptr));
    CHECK(EdrDecodeKillProcessRequest(bytes + 1, 4, &pid));
    CHECK(pid == 0x12345678);
    const EDR_KILL_PROCESS_REQUEST zero = {};
    pid = 9;
    CHECK(!EdrDecodeKillProcessRequest(&zero, 4, &pid));
    CHECK(pid == 9);
}

/* ---- ParseDriverEvent: BLOCK event round-trips the TLV fields ---- */

static void TestParseDriverBlockEvent(void)
{
    struct ::EDR_EVENT_HEADER hdr = {};
    hdr.magic = EDR_EVENT_MAGIC;
    hdr.version = EDR_EVENT_VERSION;
    hdr.type = EDR_EVT_BLOCK;
    hdr.ts_100ns = 0x12345678;
    hdr.pid = 4242;
    hdr.ppid = 777;
    hdr.flags = 0;
    const wchar_t path[] = L"\\Device\\HarddiskVolume1\\Windows\\System32\\evil.dll";
    const char ip[] = "198.51.100.9";
    const uint16_t port = 443;
    const uint32_t ruleIndex = 3;

    std::vector<uint8_t> tlv;
    auto push = [&tlv](unsigned short tag, const void* p, uint16_t n) {
        EDR_TLV_HEADER th;
        th.tag = tag;
        th.len = n;
        const uint8_t* q = static_cast<const uint8_t*>(p);
        tlv.insert(tlv.end(), reinterpret_cast<const uint8_t*>(&th),
                   reinterpret_cast<const uint8_t*>(&th) + sizeof(th));
        tlv.insert(tlv.end(), q, q + n);
    };
    push(EDR_TAG_FILE_PATH, path, (uint16_t)(sizeof(path) - sizeof(wchar_t)));
    push(EDR_TAG_DST_IP, ip, (uint16_t)(sizeof(ip) - 1));
    push(EDR_TAG_DST_PORT, &port, sizeof(port));
    push(EDR_TAG_RULE_INDEX, &ruleIndex, sizeof(ruleIndex));

    edr::Event ev;
    bool malformed = true;
    CHECK(edr::ParseDriverEvent(hdr, tlv.data(), (uint32_t)tlv.size(), ev,
                                malformed));
    CHECK(!malformed);
    CHECK(ev.type == EDR_EVT_BLOCK);
    CHECK(ev.pid == 4242);
    CHECK(ev.ppid == 777);
    CHECK(ev.fields.count(edr::field::kType) &&
          ev.fields[edr::field::kType] == "BLOCK");
    CHECK(ev.fields.count(edr::field::kRuleIndex) &&
          ev.fields[edr::field::kRuleIndex] == "3");
    CHECK(ev.fields.count(edr::field::kDstIp) &&
          ev.fields[edr::field::kDstIp] == "198.51.100.9");
    CHECK(ev.fields.count(edr::field::kDstPort) &&
          ev.fields[edr::field::kDstPort] == "443");
    CHECK(ev.fields.count(edr::field::kFilePath) &&
          ev.fields[edr::field::kFilePath].find("evil.dll") !=
              std::string::npos);

    /* truncated TLV tail must be rejected as malformed */
    hdr.length = (uint32_t)(sizeof(hdr) + tlv.size());
    CHECK(!edr::ParseDriverEvent(hdr, tlv.data(), (uint32_t)tlv.size() - 2,
                                 ev, malformed));
    CHECK(malformed);
}

/* ---- ParseDriverEvent: NET_CONNECT event round-trips the TLV fields ---- */

static void TestParseDriverNetConnectEvent(void)
{
    struct ::EDR_EVENT_HEADER hdr = {};
    hdr.magic = EDR_EVENT_MAGIC;
    hdr.version = EDR_EVENT_VERSION;
    hdr.type = EDR_EVT_NET_CONNECT;
    hdr.ts_100ns = 0x22334455;
    hdr.pid = 8080;
    hdr.ppid = 1;
    hdr.flags = 0;
    const char ip[] = "198.51.100.44";
    const uint16_t port = 8443;

    std::vector<uint8_t> tlv;
    auto push = [&tlv](unsigned short tag, const void* p, uint16_t n) {
        EDR_TLV_HEADER th;
        th.tag = tag;
        th.len = n;
        const uint8_t* q = static_cast<const uint8_t*>(p);
        tlv.insert(tlv.end(), reinterpret_cast<const uint8_t*>(&th),
                   reinterpret_cast<const uint8_t*>(&th) + sizeof(th));
        tlv.insert(tlv.end(), q, q + n);
    };
    push(EDR_TAG_DST_IP, ip, (uint16_t)(sizeof(ip) - 1));
    push(EDR_TAG_DST_PORT, &port, sizeof(port));

    edr::Event ev;
    bool malformed = true;
    CHECK(edr::ParseDriverEvent(hdr, tlv.data(), (uint32_t)tlv.size(), ev,
                                malformed));
    CHECK(!malformed);
    CHECK(ev.type == EDR_EVT_NET_CONNECT);
    CHECK(ev.pid == 8080);
    CHECK(ev.fields.count(edr::field::kType) &&
          ev.fields[edr::field::kType] == "NET_CONNECT");
    CHECK(ev.fields.count(edr::field::kDstIp) &&
          ev.fields[edr::field::kDstIp] == "198.51.100.44");
    CHECK(ev.fields.count(edr::field::kDstPort) &&
          ev.fields[edr::field::kDstPort] == "8443");
    /* No RULE_INDEX tag on a permitted-connect telemetry event. */
    CHECK(ev.fields.count(edr::field::kRuleIndex) == 0);
}

/* ---- BuildDriverPolicy: config -> packed table round-trip ---- */

static void TestBuildDriverPolicy(void)
{
    edr::Config cfg;
    cfg.driverEnableFile = true;
    cfg.driverEnableNet = true;
    cfg.driverEnableBlock = true;
    cfg.driverBlockFilePaths.push_back(std::string("\\Windows\\System32\\evil.dll"));
    edr::Config::DriverNetRule net;
    net.ip = "203.0.113.7";
    net.port = 8443;
    cfg.driverNetRules.push_back(net);
    net.ip = "198.51.100.6";
    net.port = 0; /* any port */
    cfg.driverNetRules.push_back(net);

    edr::DriverPolicyBuildResult built = edr::BuildDriverPolicy(cfg, 7u);
    CHECK(built.error.empty());
    CHECK(built.bytes.size() == EDR_POLICY_SIZE);
    const EDR_POLICY_V1* p = (const EDR_POLICY_V1*)built.bytes.data();
    CHECK(EdrPolicyEngineValidate(p) == 1);
    CHECK(p->generation == 7u);
    CHECK(p->file_rule_count == 1u);
    CHECK(p->net_rule_count == 2u);
    CHECK((p->enable_mask & EDR_ENABLE_FILE) != 0u);
    CHECK((p->enable_mask & EDR_ENABLE_NET) != 0u);
    CHECK((p->enable_mask & EDR_ENABLE_BLOCK) != 0u);
    CHECK((p->enable_mask & EDR_ENABLE_PROCESS) != 0u);
    CHECK((p->enable_mask & EDR_ENABLE_REGISTRY) != 0u);

    /* file rule 0 matches a path under the blocked NT prefix */
    std::wstring match = edr::Utf8ToWide("\\Windows\\System32\\evil.dll");
    CHECK(EdrPolicyEngineMatchFile(
              p, (const unsigned short*)match.data(),
              (unsigned long)(match.size() * sizeof(wchar_t))) == 1);
    std::wstring sibling = edr::Utf8ToWide("\\Windows\\System32\\other.dll");
    CHECK(EdrPolicyEngineMatchFile(
              p, (const unsigned short*)sibling.data(),
              (unsigned long)(sibling.size() * sizeof(wchar_t))) == 0);

    /* net rule 0 exact port; rule 1 is any-port */
    unsigned char ip[4] = {203, 0, 113, 7};
    CHECK(EdrPolicyEngineMatchNet(p, ip, 8443) == 1);
    CHECK(EdrPolicyEngineMatchNet(p, ip, 80) == 0);
    unsigned char ip2[4] = {198, 51, 100, 6};
    CHECK(EdrPolicyEngineMatchNet(p, ip2, 65535) == 1);
    unsigned char ip3[4] = {198, 51, 100, 9};
    CHECK(EdrPolicyEngineMatchNet(p, ip3, 8443) == 0);

    /* baby-step: a table with just PROCESS|REGISTRY boot defaults */
    edr::Config minimal;
    edr::DriverPolicyBuildResult m = edr::BuildDriverPolicy(minimal, 1u);
    CHECK(m.error.empty());
    CHECK(EdrPolicyEngineValidate((const EDR_POLICY_V1*)m.bytes.data()) == 1);

    /* rejected configs must never produce a table */
    edr::Config bad = cfg;
    bad.driverBlockFilePaths[0] = "Windows\\System32\\evil.dll"; /* no leading backslash */
    CHECK(!edr::BuildDriverPolicy(bad, 2u).error.empty());
    bad = cfg;
    bad.driverNetRules[0].ip = "255.255.255.255"; /* special address */
    CHECK(!edr::BuildDriverPolicy(bad, 2u).error.empty());
    CHECK(!edr::BuildDriverPolicy(cfg, 0u).error.empty());
}

} // namespace

int main()
{
    const char* protectedImages[] = {"System", "SYSTEM", "smss.exe", "CSRSS.EXE",
        "wininit.exe", "Winlogon.exe", "lsass.exe", "SERVICES.EXE",
        "lsaiso.exe", "Registry"};
    for (const char* image : protectedImages)
        CHECK(EdrIsProtectedResponseImage(image, std::strlen(image) + 1));
    CHECK(EdrIsProtectedResponseImage(nullptr, 15));
    CHECK(!EdrIsProtectedResponseImage("sample.exe", 11));
    CHECK(!EdrIsProtectedResponseImage("lsass.exe.fake", 14));
    const char boundedImage[15] = {'L','S','A','S','S','.','E','X','E','x','x','x','x','x','x'};
    CHECK(!EdrIsProtectedResponseImage(boundedImage, sizeof(boundedImage)));
    TestValidPolicyAccepted();
    TestSizeChecks();
    TestHeaderFieldRejects();
    TestFileRuleRejects();
    TestDuplicateFileRules();
    TestNetRuleRejects();
    TestDuplicateNetRules();
    TestWholeTableRejection();
    TestPolicyVersionConstants();
    TestKillProcessIoctlContract();
    TestParseDriverBlockEvent();
    TestParseDriverNetConnectEvent();
    TestBuildDriverPolicy();

    if (gFailures == 0) {
        std::printf("driver_protocol_tests: ALL PASS\n");
        return 0;
    }
    std::fprintf(stderr, "driver_protocol_tests: %d FAILURES\n", gFailures);
    return 1;
}
