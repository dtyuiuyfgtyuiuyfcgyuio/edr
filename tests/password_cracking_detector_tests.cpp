/*
 * password_cracking_detector_tests.cpp - Unit tests for
 * PasswordCrackingDetector (T1110.002).
 */
#include "password_cracking_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "password_cracking_detector.h"

namespace {

#define CRACK_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "password cracking detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

edr::Event ProcEvent(uint64_t ts100ns, const char* image,
                     const char* command) {
    edr::Event event;
    event.type = EDR_EVT_PROCESS_START;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "PROCESS_START";
    event.fields[edr::field::kImage] = image;
    if (command != nullptr) {
        event.fields[edr::field::kCommandLine] = command;
    }
    return event;
}

bool HasScore(const edr::Event& event) {
    return event.fields.find(edr::field::kPasswordCrackScore) !=
           event.fields.end();
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunPasswordCrackingDetectorTests() {
    std::fprintf(stderr, "[password-crack] TestDisabled\n");
    {
        edr::PasswordCrackingDetector detector(false, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "hashcat.exe", "hashcat -m 1000 hashes.txt");
        detector.Enrich(event);
        CRACK_CHECK(!HasScore(event));
    }
    std::fprintf(stderr, "[password-crack] TestHashcat\n");
    {
        /* hashcat.exe -> 90 malicious. */
        edr::PasswordCrackingDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "hashcat.exe", "hashcat -m 1000 hashes.txt");
        detector.Enrich(event);
        CRACK_CHECK(HasScore(event));
        CRACK_CHECK(event.fields.at(edr::field::kPasswordCrackScore) == "90");
        CRACK_CHECK(event.fields.at(edr::field::kPasswordCrackVerdict) ==
                    "MALICIOUS");
        CRACK_CHECK(event.fields.at(edr::field::kPasswordCrackSignals) ==
                    "hashcat");
        CRACK_CHECK(event.fields.at(edr::field::kPasswordCrackTools) ==
                    "hashcat");
    }
    std::fprintf(stderr, "[password-crack] TestJohnTheRipper\n");
    {
        /* john --<mode> -> 85 malicious. */
        edr::PasswordCrackingDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "john.exe", "john --format=nt hashes.txt");
        detector.Enrich(event);
        CRACK_CHECK(event.fields.at(edr::field::kPasswordCrackScore) == "85");
        CRACK_CHECK(event.fields.at(edr::field::kPasswordCrackSignals) ==
                    "john_the_ripper");
    }
    std::fprintf(stderr, "[password-crack] TestOphcrack\n");
    {
        /* ophcrack.exe -> 80 malicious. */
        edr::PasswordCrackingDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "ophcrack.exe", "ophcrack -d tables");
        detector.Enrich(event);
        CRACK_CHECK(event.fields.at(edr::field::kPasswordCrackScore) == "80");
        CRACK_CHECK(event.fields.at(edr::field::kPasswordCrackSignals) ==
                    "ophcrack");
    }
    std::fprintf(stderr, "[password-crack] TestSamdump2\n");
    {
        /* samdump2 -> 75 malicious. */
        edr::PasswordCrackingDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "samdump2", "samdump2 system sam");
        detector.Enrich(event);
        CRACK_CHECK(event.fields.at(edr::field::kPasswordCrackScore) == "75");
        CRACK_CHECK(event.fields.at(edr::field::kPasswordCrackSignals) ==
                    "samdump2");
    }
    std::fprintf(stderr, "[password-crack] TestCainAbel\n");
    {
        /* cain.exe -> 75 malicious. */
        edr::PasswordCrackingDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "cain.exe", "cain.exe /crack");
        detector.Enrich(event);
        CRACK_CHECK(event.fields.at(edr::field::kPasswordCrackScore) == "75");
        CRACK_CHECK(event.fields.at(edr::field::kPasswordCrackSignals) ==
                    "cain_abel");
    }
    std::fprintf(stderr, "[password-crack] TestFcrackzip\n");
    {
        /* fcrackzip -> 60 suspicious. */
        edr::PasswordCrackingDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "fcrackzip.exe", "fcrackzip -u -D wordlist.zip");
        detector.Enrich(event);
        CRACK_CHECK(event.fields.at(edr::field::kPasswordCrackScore) == "60");
        CRACK_CHECK(event.fields.at(edr::field::kPasswordCrackVerdict) ==
                    "SUSPICIOUS");
        CRACK_CHECK(event.fields.at(edr::field::kPasswordCrackSignals) ==
                    "fcrackzip");
    }
    std::fprintf(stderr, "[password-crack] TestHashIdentifier\n");
    {
        /* hash-identifier -> 55 suspicious. */
        edr::PasswordCrackingDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "hash-identifier",
            "hash-identifier deadbeef");
        detector.Enrich(event);
        CRACK_CHECK(event.fields.at(edr::field::kPasswordCrackScore) == "55");
        CRACK_CHECK(event.fields.at(edr::field::kPasswordCrackVerdict) ==
                    "SUSPICIOUS");
        CRACK_CHECK(event.fields.at(edr::field::kPasswordCrackSignals) ==
                    "hash_identifier");
    }
    std::fprintf(stderr, "[password-crack] TestBenignSilent\n");
    {
        edr::PasswordCrackingDetector detector(true, 55, 300, 1024);
        edr::Event notepad = ProcEvent(
            1000 * kSecond, "notepad.exe", "notepad notes.txt");
        detector.Enrich(notepad);
        CRACK_CHECK(!HasScore(notepad));
    }
    std::fprintf(stderr, "[password-crack] TestDedupWindow\n");
    {
        edr::PasswordCrackingDetector detector(true, 55, 300, 1024);
        edr::Event first = ProcEvent(
            1000 * kSecond, "hashcat.exe", "hashcat -m 1000 hashes.txt");
        detector.Enrich(first);
        CRACK_CHECK(HasScore(first));
        edr::Event repeat = ProcEvent(
            1010 * kSecond, "hashcat.exe", "hashcat -m 1000 hashes.txt");
        detector.Enrich(repeat);
        CRACK_CHECK(!HasScore(repeat));
        edr::Event expired = ProcEvent(
            1000 * kSecond + 301 * kSecond, "hashcat.exe",
            "hashcat -m 1000 hashes.txt");
        detector.Enrich(expired);
        CRACK_CHECK(HasScore(expired));
    }
    std::fprintf(stderr, "[password-crack] TestInspects\n");
    {
        CRACK_CHECK(edr::PasswordCrackingDetector::Inspects(
            EDR_EVT_PROCESS_START));
        CRACK_CHECK(!edr::PasswordCrackingDetector::Inspects(
            EDR_EVT_REG_WRITE));
        CRACK_CHECK(!edr::PasswordCrackingDetector::Inspects(
            EDR_EVT_FILE_CREATE));
    }
    std::fprintf(stderr, "[password-crack] all passed\n");
}
