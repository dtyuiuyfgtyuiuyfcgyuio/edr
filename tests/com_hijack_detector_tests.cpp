/*
 * com_hijack_detector_tests.cpp - Unit tests for ComHijackDetector (T1546.015).
 */
#include "com_hijack_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "com_hijack_detector.h"

namespace {

#define SR_CHECK(c) Check((c), #c, __LINE__)
void Check(bool c, const char* e, int l){ if(!c) throw std::runtime_error(std::string("CHECK failed at ")+std::to_string(l)+": "+e); }

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
    auto it=e.fields.find(edr::field::kComHijackScore);
    return it==e.fields.end()?"":it->second;
}
constexpr uint64_t kSecond=10000000ULL;
}

void RunComHijackDetectorTests(){
    std::fprintf(stderr, "[com-hijack] TestDisabled\n");
    {
        edr::ComHijackDetector d(false,55,300,1024);
        auto ev=RegDataEvent(10000000ULL,"HKCU\\Software\\Classes\\CLSID\\{11111111-1111-1111-1111-111111111111}\\InprocServer32","C:\\Users\\Public\\evil.dll");
        d.Enrich(ev); SR_CHECK(Score(ev).empty());
    }
    std::fprintf(stderr, "[com-hijack] TestWritableDir\n");
    {
        edr::ComHijackDetector d(true,55,0,1024);
        auto ev=RegDataEvent(10000000ULL,"HKCU\\Software\\Classes\\CLSID\\{11111111-1111-1111-1111-111111111111}\\InprocServer32","C:\\Users\\Public\\evil.dll");
        d.Enrich(ev); SR_CHECK(Score(ev)=="90");
    }
    std::fprintf(stderr, "[com-hijack] TestNonSystem\n");
    {
        edr::ComHijackDetector d(true,55,0,1024);
        auto ev=RegDataEvent(10000000ULL,"HKCU\\Software\\Classes\\CLSID\\{22222222-2222-2222-2222-222222222222}\\InprocServer32","C:\\Tools\\evil.dll");
        d.Enrich(ev); SR_CHECK(Score(ev)=="85");
    }
    std::fprintf(stderr, "[com-hijack] TestSystem32Silent\n");
    {
        edr::ComHijackDetector d(true,55,0,1024);
        auto ev=RegDataEvent(10000000ULL,"HKCU\\Software\\Classes\\CLSID\\{33333333-3333-3333-3333-333333333333}\\InprocServer32","C:\\Windows\\System32\\legit.dll");
        d.Enrich(ev); SR_CHECK(Score(ev).empty());
    }
    std::fprintf(stderr, "[com-hijack] TestNameOnly\n");
    {
        edr::ComHijackDetector d(true,55,0,1024);
        auto ev=RegNameEvent(10000000ULL,"HKCU\\Software\\Classes\\CLSID\\{44444444-4444-4444-4444-444444444444}\\InprocServer32","");
        d.Enrich(ev); SR_CHECK(Score(ev)=="75");
    }
    std::fprintf(stderr, "[com-hijack] TestCommandPlane\n");
    {
        edr::ComHijackDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,"C:\\Windows\\System32\\reg.exe","reg add HKCU\\Software\\Classes\\CLSID\\{55555555-5555-5555-5555-555555555555}\\InprocServer32 /d C:\\Users\\Public\\evil.dll /f");
        d.Enrich(ev); SR_CHECK(Score(ev)=="90");
    }
    std::fprintf(stderr, "[com-hijack] TestReadOnlySilent\n");
    {
        edr::ComHijackDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,"C:\\Windows\\System32\\reg.exe","reg query HKCU\\Software\\Classes\\CLSID\\{66666666-6666-6666-6666-666666666666}\\InprocServer32");
        d.Enrich(ev); SR_CHECK(Score(ev).empty());
    }
    std::fprintf(stderr, "[com-hijack] TestMinScoreGate\n");
    {
        edr::ComHijackDetector d(true,90,0,1024);
        auto ev1=RegDataEvent(10000000ULL,"HKCU\\Software\\Classes\\CLSID\\{77777777-7777-7777-7777-777777777777}\\InprocServer32","C:\\Tools\\evil.dll");
        d.Enrich(ev1); SR_CHECK(Score(ev1).empty());
        auto ev2=RegDataEvent(20000000ULL,"HKCU\\Software\\Classes\\CLSID\\{88888888-8888-8888-8888-888888888888}\\InprocServer32","C:\\Users\\Public\\evil.dll");
        d.Enrich(ev2); SR_CHECK(Score(ev2)=="90");
    }
    std::fprintf(stderr, "[com-hijack] all passed\n");
}
