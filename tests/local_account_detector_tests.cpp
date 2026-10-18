/*
 * local_account_detector_tests.cpp - Unit tests for LocalAccountDetector
 * (T1136.001 local account creation / T1098 account manipulation).
 *
 * The detector consumes LOCAL_ACCOUNT events from the local account
 * monitor collector and scores each change independently (no dedup
 * state). Verdict strings follow this detector family's uppercase house
 * style (MALICIOUS / SUSPICIOUS); scores below 55 stamp the score only.
 */
#include "local_account_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "local_account_detector.h"

namespace {

#define LA_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "local account detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

edr::Event UserEvent(const char* action, const char* name) {
    edr::Event event;
    event.type = EDR_EVT_LOCAL_ACCOUNT;
    event.ts100ns = 10000000ULL;
    event.fields[edr::field::kType] = "LOCAL_ACCOUNT";
    event.fields[edr::field::kAccountType] = "user";
    event.fields[edr::field::kAccountAction] = action;
    event.fields[edr::field::kAccountName] = name;
    return event;
}

edr::Event GroupEvent(const char* groupAction, const char* group,
                      const char* member) {
    edr::Event event;
    event.type = EDR_EVT_LOCAL_ACCOUNT;
    event.ts100ns = 10000000ULL;
    event.fields[edr::field::kType] = "LOCAL_ACCOUNT";
    event.fields[edr::field::kAccountType] = "group";
    event.fields[edr::field::kGroupAction] = groupAction;
    event.fields[edr::field::kGroupName] = group;
    event.fields[edr::field::kGroupMember] = member;
    return event;
}

std::string Score(const edr::Event& event) {
    auto it = event.fields.find(edr::field::kLocalAccountScore);
    return it == event.fields.end() ? "" : it->second;
}

std::string Verdict(const edr::Event& event) {
    auto it = event.fields.find(edr::field::kLocalAccountVerdict);
    return it == event.fields.end() ? "" : it->second;
}

std::string Signals(const edr::Event& event) {
    auto it = event.fields.find(edr::field::kLocalAccountSignals);
    return it == event.fields.end() ? "" : it->second;
}

bool Contains(const std::string& text, const char* needle) {
    return text.find(needle) != std::string::npos;
}

} // namespace

void RunLocalAccountDetectorTests() {
    std::fprintf(stderr, "[local-account] TestInspects\n");
    {
        LA_CHECK(edr::LocalAccountDetector::Inspects(EDR_EVT_LOCAL_ACCOUNT));
        LA_CHECK(!edr::LocalAccountDetector::Inspects(EDR_EVT_PROCESS_START));

        edr::LocalAccountDetector detector;
        edr::Event other;
        other.type = EDR_EVT_PROCESS_START;
        other.fields[edr::field::kType] = "PROCESS_START";
        detector.Enrich(other);
        LA_CHECK(Score(other).empty());
    }
    std::fprintf(stderr, "[local-account] TestSuspiciousUserAdded\n");
    {
        /* user added 25 + suspicious svc* prefix 30 = 55 SUSPICIOUS. */
        edr::LocalAccountDetector detector;
        edr::Event event = UserEvent("added", "svc_backdoor");
        detector.Enrich(event);
        LA_CHECK(Score(event) == "55");
        LA_CHECK(Verdict(event) == "SUSPICIOUS");
        LA_CHECK(Contains(Signals(event), "account_user_added"));
        LA_CHECK(Contains(Signals(event), "_suspicious_user"));
    }
    std::fprintf(stderr, "[local-account] TestAdminFullNameRaisesScore\n");
    {
        /* added 25 + suspicious name 30 + admin full name 10 = 65. */
        edr::LocalAccountDetector detector;
        edr::Event event = UserEvent("added", "svc_update");
        event.fields[edr::field::kAccountFullName] = "Admin Service Account";
        detector.Enrich(event);
        LA_CHECK(Score(event) == "65");
        LA_CHECK(Verdict(event) == "SUSPICIOUS");
    }
    std::fprintf(stderr, "[local-account] TestOrdinaryUserAddedLowSignal\n");
    {
        /* A normal new user scores 25 (score only, no verdict). */
        edr::LocalAccountDetector detector;
        edr::Event event = UserEvent("added", "jdoe");
        detector.Enrich(event);
        LA_CHECK(Score(event) == "25");
        LA_CHECK(Verdict(event).empty());
        LA_CHECK(Signals(event).empty());
    }
    std::fprintf(stderr, "[local-account] TestDisabledAccountReEnabled\n");
    {
        /* suspicious name 30 + enable-on-modify 25 = 55 SUSPICIOUS. */
        edr::LocalAccountDetector detector;
        edr::Event event = UserEvent("modified", "Administrator");
        event.fields[edr::field::kAccountEnabled] = "true";
        detector.Enrich(event);
        LA_CHECK(Score(event) == "55");
        LA_CHECK(Verdict(event) == "SUSPICIOUS");
        LA_CHECK(Contains(Signals(event), "account_user_modified"));
        LA_CHECK(Contains(Signals(event), "_enabled"));
    }
    std::fprintf(stderr, "[local-account] TestPrivilegedGroupMemberAdded\n");
    {
        /* group added 20 + privileged group 35 + suspicious member 15
         * = 70 SUSPICIOUS. */
        edr::LocalAccountDetector detector;
        edr::Event event = GroupEvent("added", "Administrators", "svc_ops");
        detector.Enrich(event);
        LA_CHECK(Score(event) == "70");
        LA_CHECK(Verdict(event) == "SUSPICIOUS");
        LA_CHECK(Contains(Signals(event), "account_group_added"));
        LA_CHECK(Contains(Signals(event), "_privileged_group"));
    }
    std::fprintf(stderr, "[local-account] TestOrdinaryGroupChurn\n");
    {
        /* Non-privileged group membership churn stays low signal (20). */
        edr::LocalAccountDetector detector;
        edr::Event event = GroupEvent("added", "Users", "jdoe");
        detector.Enrich(event);
        LA_CHECK(Score(event) == "20");
        LA_CHECK(Verdict(event).empty());
    }
    std::fprintf(stderr, "[local-account] all passed\n");
}
