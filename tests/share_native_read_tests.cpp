/* Exercise the production native reader with controlled NetAPI allocations. */
#include <windows.h>
#include <lmcons.h>
#include <lmerr.h>
#include <lmshare.h>
#include <lmapibuf.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>

namespace {
int mode = 0, frees = 0;
NET_API_STATUS WINAPI TestEnum(LMSTR, DWORD, LPBYTE* out, DWORD,
                               LPDWORD read, LPDWORD total, LPDWORD resume) {
    *out = static_cast<LPBYTE>(std::calloc(1, 512));
    if (!*out) throw std::bad_alloc();
    *read = *total = 1;
    *resume = 0;
    auto* row = reinterpret_cast<SHARE_INFO_502*>(*out);
    row->shi502_type = STYPE_DISKTREE;
    row->shi502_netname = reinterpret_cast<wchar_t*>(*out + 128);
    std::memcpy(row->shi502_netname, L"share", 12);
    if (mode == 1) row->shi502_netname = reinterpret_cast<wchar_t*>(*out + 512);
    if (mode == 2) {
        row->shi502_netname = reinterpret_cast<wchar_t*>(*out + 510);
        *row->shi502_netname = L'x';
    }
    if (mode == 5) { row->shi502_netname[0] = 0xd800; row->shi502_netname[1] = 0; }
    if (mode == 7) {
        row->shi502_netname[0] = 0xd83d;
        row->shi502_netname[1] = 0xdca9;
        row->shi502_netname[2] = 0;
    }
    if (mode == 8) *read = MAXDWORD;
    return mode == 3 ? ERROR_ACCESS_DENIED : NERR_Success;
}
NET_API_STATUS WINAPI TestSize(LPVOID, LPDWORD bytes) {
    if (mode == 6) throw std::runtime_error("size failure");
    *bytes = mode == 9 ? 1 : 512;
    return mode == 4 ? ERROR_INVALID_DATA : NERR_Success;
}
NET_API_STATUS WINAPI TestFree(LPVOID p) { ++frees; std::free(p); return NERR_Success; }
}
#define NetShareEnum TestEnum
#define NetApiBufferSize TestSize
#define NetApiBufferFree TestFree
#include "../user/collector_share.cpp"
#undef NetShareEnum
#undef NetApiBufferSize
#undef NetApiBufferFree

int main() {
    for (mode = 0; mode <= 9; ++mode) {
        const int before = frees;
        bool accepted = false, threw = false;
        try {
            const auto page = edr::ReadNativePage(0);
            accepted = page.status == ERROR_SUCCESS && page.shares.size() == 1;
            if (mode == 7 && accepted && page.shares[0].name != "\xf0\x9f\x92\xa9") return 1;
        } catch (const std::runtime_error&) { threw = true; }
        if (frees - before != 1 || threw != (mode == 6) ||
            accepted != (mode == 0 || mode == 7)) {
            std::fprintf(stderr, "native share reader failed: mode=%d accepted=%d threw=%d frees=%d\n",
                mode, accepted, threw, frees - before);
            return 1;
        }
    }
    std::puts("native share boundary and release tests passed");
}
