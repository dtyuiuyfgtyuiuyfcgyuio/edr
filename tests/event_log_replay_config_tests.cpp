#include <windows.h>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include "config.h"
int main() {
    wchar_t filename[MAX_PATH] = {}, temp[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, temp); GetTempFileNameW(temp, L"erb", 0, filename);
    const auto file = edr::WideToUtf8(filename);
    try {
        for (const char* bad : {
            R"({"event_log_replay":true})",
            R"({"event_log_replay":{"enable":1}})",
            R"({"event_log_replay":{"enable":true}})",
            R"({"event_log_replay":{"max_pending_records":8201}})",
            R"({"event_log_replay":{"unknown":true}})",
            R"({"event_log_replay":{"enable":true,"checkpoint_directory":"relative"}})",
            R"({"event_log_replay":{"enable":true,"checkpoint_directory":"C:\\check\u0000evil"}})"
        }) {
            { std::ofstream out(file, std::ios::binary | std::ios::trunc); out << bad; }
            edr::Config cfg; cfg.reporterUrl = "unchanged"; std::string error;
            if (edr::LoadConfigFile(file, cfg, error) || cfg.reporterUrl != "unchanged")
                throw std::runtime_error(std::string("invalid replay config accepted or partially applied: ") + bad);
        }
        { std::ofstream out(file, std::ios::binary | std::ios::trunc);
          out << R"({"event_log_replay":{"enable":true,"checkpoint_directory":"C:\\check","max_pending_records":32}})"; }
        edr::Config cfg; std::string error;
        if (!edr::LoadConfigFile(file, cfg, error) || !cfg.eventLogReplayEnable ||
            cfg.eventLogReplayCheckpointDirectory != "C:\\check" || cfg.eventLogReplayMaxPendingRecords != 32)
            throw std::runtime_error("replay config was not applied");
        DeleteFileW(filename); std::cout << "event log replay config passed\n"; return 0;
    } catch (const std::exception& error) {
        DeleteFileW(filename); std::cerr << error.what() << '\n'; return 1;
    }
}
