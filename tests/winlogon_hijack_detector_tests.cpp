/*
 * winlogon_hijack_detector_tests.cpp - Unit tests for WinlogonHijackDetector (T1547.004).
 */
#include "winlogon_hijack_detector_tests.h"
#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>
#include "edr_event.h"
#include "event_bus.h"
#include "winlogon_hijack_detector.h"

namespace {
#define SR_CHECK(c) Check((c), #c, __LINE__)
void Check(bool c,const char* e,int l){ if(!c) throw std::runtime_error(std::string("CHECK failed at ")+std::to_string(l)+": "+e); }
edr::Event ProcEvent(uint64_t ts, const char* img, const char* cmd){
    edr::Event ev; ev.type=EDR_EVT_PROCESS_START; ev.ts100ns=ts; ev.fields[edr::field::kType]="PROCESS_START"; ev.fields[edr::field::kImage]=img; if(cmd) ev.fields[edr::field::kCommandLine]=cmd; return ev;
}
edr::Event RegDataEvent(uint64_t ts, const char* key, const char* data){
    edr::Event ev; ev.type=EDR_EVT_REG_WRITE; ev.ts100ns=ts; ev.fields[edr::field::kType]="REG_WRITE"; ev.fields[edr::field::kRegKey]=key; ev.fields[edr::field::kRegValue]=data; return ev;
}
edr::Event RegNameEvent(uint64_t ts, const char* key, const char* valName){
    edr::Event ev; ev.type=EDR_EVT_REG_WRITE; ev.ts100ns=ts; ev.fields[edr::field::kType]="REG_WRITE"; ev.fields[edr::field::kRegKey]=key; ev.fields[edr::field::kRegValue]=valName; return ev;
}
std::string Score(const edr::Event& e){
    auto it=e.fields.find(edr::field::kWinlogonHijackScore);
    return it==e.fields.end()?"":it->second;
}
constexpr uint64_t kSecond=10000000ULL;
}

void RunWinlogonHijackDetectorTests(){
    std::fprintf(stderr, "[winlogon-hijack] TestDisabled\n");
    {
        edr::WinlogonHijackDetector d(false,55,300,1024);
        auto ev=RegDataEvent(10000000ULL,"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit","C:\\Users\\Public\\evil.exe");
        d.Enrich(ev); SR_CHECK(Score(ev).empty());
    }
    std::fprintf(stderr, "[winlogon-hijack] TestWritable\n");
    {
        edr::WinlogonHijackDetector d(true,55,0,1024);
        auto ev=RegDataEvent(10000000ULL,"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit","C:\\Users\\Public\\evil.exe");
        d.Enrich(ev); SR_CHECK(Score(ev)=="90");
    }
    std::fprintf(stderr, "[winlogon-hijack] TestNonSystem\n");
    {
        edr::WinlogonHijackDetector d(true,55,0,1024);
        auto ev=RegDataEvent(10000000ULL,"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell","C:\\Tools\\evil.exe");
        d.Enrich(ev); SR_CHECK(Score(ev)=="85");
    }
    std::fprintf(stderr, "[winlogon-hijack] TestSystem32Silent\n");
    {
        edr::WinlogonHijackDetector d(true,55,0,1024);
        auto ev=RegDataEvent(10000000ULL,"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit","C:\\Windows\\System32\\userinit.exe");
        d.Enrich(ev); SR_CHECK(Score(ev).empty());
    }
    std::fprintf(stderr, "[winlogon-hijack] TestNameOnly\n");
    {
        edr::WinlogonHijackDetector d(true,55,0,1024);
        auto ev=RegNameEvent(10000000ULL,"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon","Userinit");
        d.Enrich(ev); SR_CHECK(Score(ev)=="75");
    }
    std::fprintf(stderr, "[winlogon-hijack] TestCommandPlane\n");
    {
        edr::WinlogonHijackDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,"C:\\Windows\\System32\\reg.exe","reg add HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon /v Userinit /d C:\\Users\\Public\\evil.exe /f");
        d.Enrich(ev); SR_CHECK(Score(ev)=="90");
    }
    std::fprintf(stderr, "[winlogon-hijack] TestReadOnlySilent\n");
    {
        edr::WinlogonHijackDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,"C:\\Windows\\System32\\reg.exe","reg query HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon /v Userinit");
        d.Enrich(ev); SR_CHECK(Score(ev).empty());
    }
    std::fprintf(stderr, "[winlogon-hijack] all passed\n");
}
