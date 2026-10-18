/* Unit tests for the firewall, share-change, and local-account detectors. */
#include "new_rule_detectors_tests.h"

#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "firewall_rule_detector.h"
#include "local_account_detector.h"
#include "share_change_detector.h"

namespace {

#define NR_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error("new rule detector test failed at line " +
                                 std::to_string(line) + ": " + expression);
}

edr::Event Event(uint16_t type) {
    edr::Event event;
    event.type = type;
    return event;
}

void TestFirewallRdpRule() {
    edr::Event event = Event(EDR_EVT_FIREWALL_RULE);
    event.fields[edr::field::kFirewallAction] = "added";
    event.fields[edr::field::kFirewallDir] = "in";
    event.fields[edr::field::kFirewallRuleAction] = "allow";
    event.fields[edr::field::kFirewallLocalPort] = "3389";
    event.fields[edr::field::kFirewallProtocol] = "tcp";
    edr::FirewallRuleDetector detector;
    detector.Enrich(event);
    NR_CHECK(event.fields.at(edr::field::kFirewallRuleScore) == "50");
    NR_CHECK(event.fields.find(edr::field::kFirewallRuleVerdict) ==
             event.fields.end());
}

void TestFirewallSensitiveAnyRule() {
    edr::Event event = Event(EDR_EVT_FIREWALL_RULE);
    event.fields[edr::field::kFirewallAction] = "added";
    event.fields[edr::field::kFirewallDir] = "in";
    event.fields[edr::field::kFirewallRuleAction] = "allow";
    event.fields[edr::field::kFirewallProtocol] = "any";
    event.fields[edr::field::kFirewallApp] = "C:\\Windows\\System32\\powershell.exe";
    edr::FirewallRuleDetector detector;
    detector.Enrich(event);
    NR_CHECK(event.fields.at(edr::field::kFirewallRuleScore) == "65");
    NR_CHECK(event.fields.at(edr::field::kFirewallRuleVerdict) == "SUSPICIOUS");
}

void TestShareSensitiveHidden() {
    edr::Event event = Event(EDR_EVT_SHARE_CHANGE);
    event.fields[edr::field::kShareAction] = "added";
    event.fields[edr::field::kShareName] = "stage$";
    event.fields[edr::field::kSharePath] = "C:\\Users\\Public";
    event.fields[edr::field::kShareType] = "disk";
    edr::ShareChangeDetector detector;
    detector.Enrich(event);
    NR_CHECK(event.fields.at(edr::field::kShareChangeScore) == "75");
    NR_CHECK(event.fields.at(edr::field::kShareChangeVerdict) == "MALICIOUS");
}

void TestSharePrintIgnored() {
    edr::Event event = Event(EDR_EVT_SHARE_CHANGE);
    event.fields[edr::field::kShareAction] = "added";
    event.fields[edr::field::kShareType] = "print";
    edr::ShareChangeDetector detector;
    detector.Enrich(event);
    NR_CHECK(event.fields.find(edr::field::kShareChangeScore) ==
             event.fields.end());
}

void TestPrivilegedGroupAdd() {
    edr::Event event = Event(EDR_EVT_LOCAL_ACCOUNT);
    event.fields[edr::field::kAccountType] = "group";
    event.fields[edr::field::kGroupAction] = "added";
    event.fields[edr::field::kGroupName] = "Administrators";
    event.fields[edr::field::kGroupMember] = "svc_backup";
    edr::LocalAccountDetector detector;
    detector.Enrich(event);
    NR_CHECK(event.fields.at(edr::field::kLocalAccountScore) == "70");
    NR_CHECK(event.fields.at(edr::field::kLocalAccountVerdict) == "SUSPICIOUS");
}

void TestSuspiciousUserAdd() {
    edr::Event event = Event(EDR_EVT_LOCAL_ACCOUNT);
    event.fields[edr::field::kAccountType] = "user";
    event.fields[edr::field::kAccountAction] = "added";
    event.fields[edr::field::kAccountName] = "admin_backup";
    event.fields[edr::field::kAccountEnabled] = "true";
    edr::LocalAccountDetector detector;
    detector.Enrich(event);
    NR_CHECK(event.fields.at(edr::field::kLocalAccountScore) == "55");
    NR_CHECK(event.fields.at(edr::field::kLocalAccountVerdict) == "SUSPICIOUS");
}

void TestUninterestingEvents() {
    edr::Event firewall = Event(EDR_EVT_FIREWALL_RULE);
    firewall.fields[edr::field::kFirewallAction] = "added";
    firewall.fields[edr::field::kFirewallDir] = "out";
    firewall.fields[edr::field::kFirewallRuleAction] = "block";
    edr::FirewallRuleDetector firewallDetector;
    firewallDetector.Enrich(firewall);
    NR_CHECK(firewall.fields.find(edr::field::kFirewallRuleScore) ==
             firewall.fields.end());

    edr::Event other = Event(EDR_EVT_PROCESS_START);
    edr::LocalAccountDetector accountDetector;
    accountDetector.Enrich(other);
    NR_CHECK(other.fields.empty());
}

} // namespace

void RunNewRuleDetectorsTests() {
    TestFirewallRdpRule();
    TestFirewallSensitiveAnyRule();
    TestShareSensitiveHidden();
    TestSharePrintIgnored();
    TestPrivilegedGroupAdd();
    TestSuspiciousUserAdd();
    TestUninterestingEvents();
}
