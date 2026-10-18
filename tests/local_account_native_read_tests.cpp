/* Validate actual NetAPI conversion and allocation release with native fakes. */
#include <windows.h>
#include <lm.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
namespace {
int mode = 0, freed = 0;
NET_API_STATUS FillAccountBuffer(LPBYTE* out, LPDWORD read, LPDWORD total, bool group) {
    *out = static_cast<LPBYTE>(std::calloc(1, 1024));
    if (!*out) throw std::bad_alloc();
    *read = *total = 1;
    auto* name = reinterpret_cast<wchar_t*>(*out + 512);
    std::memcpy(name, group ? L"HOST\\user" : L"user", group ? 20 : 10);
    if (mode == 1) name = reinterpret_cast<wchar_t*>(*out + 1024);
    if (mode == 2) { name = reinterpret_cast<wchar_t*>(*out + 1022); *name = L'x'; }
    if (mode == 5) { name[0] = 0xd800; name[1] = 0; }
    if (group) reinterpret_cast<LOCALGROUP_MEMBERS_INFO_2*>(*out)->lgrmi2_domainandname = name;
    else reinterpret_cast<USER_INFO_2*>(*out)->usri2_name = name;
    return mode == 3 ? ERROR_ACCESS_DENIED : NERR_Success;
}
NET_API_STATUS WINAPI TestUsers(LPCWSTR, DWORD, DWORD, LPBYTE* out, DWORD,
                                LPDWORD read, LPDWORD total, LPDWORD) {
    return FillAccountBuffer(out, read, total, false);
}
NET_API_STATUS WINAPI TestMembers(LPCWSTR, LPCWSTR, DWORD, LPBYTE* out, DWORD,
                                  LPDWORD read, LPDWORD total, PDWORD_PTR) {
    return FillAccountBuffer(out, read, total, true);
}
NET_API_STATUS WINAPI TestSize(LPVOID, LPDWORD bytes) {
    if (mode == 6) throw std::runtime_error("size failure");
    *bytes = 1024;
    return mode == 4 ? ERROR_INVALID_DATA : NERR_Success;
}
NET_API_STATUS WINAPI TestFree(LPVOID p) { ++freed; std::free(p); return NERR_Success; }
}
#define NetUserEnum TestUsers
#define NetLocalGroupGetMembers TestMembers
#define NetApiBufferSize TestSize
#define NetApiBufferFree TestFree
#include "../user/collector_local_account.cpp"
#undef NetUserEnum
#undef NetLocalGroupGetMembers
#undef NetApiBufferSize
#undef NetApiBufferFree
int main() {
    for (bool group : {false, true}) {
        for (mode = 0; mode <= 6; ++mode) {
            const int before = freed;
            bool accepted = false, threw = false;
            try {
                const auto page = edr::QueryNativePage(group ? "Admins" : "", 0);
                accepted = page.status == edr::LocalAccountQueryStatus::Complete;
            } catch (const std::runtime_error&) { threw = true; }
            if (freed - before != 1 || threw != (mode == 6) || accepted != (mode == 0)) {
                std::fprintf(stderr, "native account failed: group=%d mode=%d accepted=%d threw=%d frees=%d\n",
                    group, mode, accepted, threw, freed - before);
                return 1;
            }
        }
    }
    std::puts("native account boundaries, strict text and release tests passed");
}
