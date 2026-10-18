#include <windows.h>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include "config.h"

int main() {
    wchar_t directory[MAX_PATH] = {}, filename[MAX_PATH] = {};
    if (!GetTempPathW(MAX_PATH, directory) || !GetTempFileNameW(directory, L"edr", 0, filename)) return 1;
    const std::string file = edr::WideToUtf8(filename);
    try {
        for (const char* invalid : {
            R"({"reporter":{"enable":true,"url":""}})",
            R"({"reporter":{"enable":true,"url":"https://example.invalid/ingest#fragment"}})",
            R"({"reporter":{"enable":true,"url":"https://example.invalid/ingest\u0000other"}})",
            R"({"reporter":{"spool":true}})",
            R"({"reporter":{"spool":{"enable":"true"}}})",
            R"({"reporter":{"enable":true,"spool":{"enable":true}}})",
            R"({"reporter":{"spool":{"max_records":1001}}})",
            R"({"reporter":{"spool":{"max_bytes":0}}})",
            R"({"reporter":{"spool":{"max_item_bytes":0}}})",
            R"({"reporter":{"spool":{"unexpected":1}}})",
            R"({"reporter":{"enable":true,"url":"https://example.invalid/ingest","spool":{"enable":true,"directory":"C:\\spool\\alerts\u0000evil","event_directory":"C:\\spool\\events"}}})",
            R"({"reporter":{"enable":true,"url":"https://example.invalid/ingest","spool":{"enable":true,"directory":"C:\\spool\\alerts","event_directory":"c:/spool/alerts/../alerts"}}})",
            R"({"reporter":{"enable":true,"url":"https://example.invalid/ingest","spool":{"enable":true,"directory":"relative","event_directory":"C:\\spool\\events"}}})"
        }) {
            { std::ofstream output(file, std::ios::binary | std::ios::trunc); output << invalid; }
            edr::Config config;
            config.reporterUrl = "unchanged";
            std::string error;
            if (edr::LoadConfigFile(file, config, error) || config.reporterUrl != "unchanged")
                throw std::runtime_error("invalid spool configuration accepted or partially applied");
        }
        { std::ofstream output(file, std::ios::binary | std::ios::trunc);
          output << R"({"reporter":{"enable":true,"url":"https://example.invalid/ingest","spool":{"enable":true,"directory":"C:\\spool\\alerts","event_directory":"C:\\spool\\events","max_records":20,"max_bytes":1048576,"max_item_bytes":65536}}})"; }
        edr::Config config;
        std::string error;
        if (!edr::LoadConfigFile(file, config, error)) throw std::runtime_error(error);
        if (!config.reporterSpoolEnable || config.reporterSpoolMaxRecords != 20 ||
            config.reporterSpoolMaxBytes != 1048576 || config.reporterSpoolMaxItemBytes != 65536 ||
            config.reporterSpoolDirectory != "C:\\spool\\alerts" ||
            config.reporterEventSpoolDirectory != "C:\\spool\\events")
            throw std::runtime_error("valid spool options were not applied");
        DeleteFileW(filename);
        std::cout << "reporter spool configuration tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        DeleteFileW(filename);
        std::cerr << error.what() << '\n';
        return 1;
    }
}
