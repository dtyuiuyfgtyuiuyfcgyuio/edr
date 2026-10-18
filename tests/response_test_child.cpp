#include <windows.h>

#include <cwchar>
#include <string>

/* Modes:
 *   (no args)        : sleep forever. Used as the plain termination target.
 *   --spawn          : spawn one plain child (this same exe), then sleep
 *                      forever. Used to build a two-level tree so tree
 *                      termination can be integration-tested.
 */
int wmain(int argc, wchar_t** argv) {
    bool spawn = false;
    for (int i = 1; i < argc; ++i) {
        if (std::wcscmp(argv[i], L"--spawn") == 0) spawn = true;
    }
    if (spawn) {
        wchar_t self[MAX_PATH] = {};
        if (GetModuleFileNameW(nullptr, self, MAX_PATH) != 0) {
            std::wstring command = L"\"" + std::wstring(self) + L"\"";
            STARTUPINFOW startup = {sizeof(startup)};
            PROCESS_INFORMATION process = {};
            if (CreateProcessW(self, command.data(), nullptr, nullptr, FALSE, 0,
                               nullptr, nullptr, &startup, &process)) {
                CloseHandle(process.hThread);
                CloseHandle(process.hProcess);
            }
        }
    }
    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    char byte = 0;
    DWORD read = 0;
    if (input && input != INVALID_HANDLE_VALUE)
        ReadFile(input, &byte, 1, &read, nullptr);
    Sleep(INFINITE);
    return 0;
}
