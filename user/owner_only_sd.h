/*
 * owner_only_sd.h - Security descriptors with the owner pinned to the token
 * user.
 *
 * The bare SDDL "D:P(A;;FA;;;OW)" leaves the object owner to the platform
 * default. For an elevated process that default is the Administrators group,
 * so a "current-owner-only" object would actually be owned by Administrators:
 * the spool, bookmark and quarantine paths all compare the object owner
 * against the current token user and would reject those objects on such a
 * host. Building the descriptor with the token user rendered into the owner
 * field keeps the owner-only policy deterministic on elevated, standard and
 * service (SYSTEM) contexts alike.
 *
 * Callers own the returned descriptor and must release it with LocalFree.
 */
#ifndef EDR_OWNER_ONLY_SD_H
#define EDR_OWNER_ONLY_SD_H

#include <windows.h>
#include <sddl.h>

#include <string>
#include <vector>

namespace edr {

/* DACL-only SDDL fragments the callers pair with the pinned owner. */
constexpr wchar_t kOwnerOnlyDaclSddl[] = L"D:P(A;;FA;;;OW)";
constexpr wchar_t kRestrictedDaclSddl[] =
    L"D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)";

/* Builds "O:<token-user-SID><daclSddl>" and converts it to a self-relative
 * security descriptor. Returns nullptr and sets error on any failure. */
inline PSECURITY_DESCRIPTOR CreateOwnerPinnedDescriptor(
    const wchar_t* daclSddl, std::string& error) {
    error.clear();
    if (daclSddl == nullptr) {
        error = "owner-pinned descriptor requires a DACL SDDL fragment";
        return nullptr;
    }
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        error = "could not open process token for owner-pinned descriptor";
        return nullptr;
    }
    DWORD needed = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
    if (needed == 0) {
        const DWORD code = GetLastError();
        CloseHandle(token);
        error = "could not size token user for owner-pinned descriptor";
        if (code != ERROR_INSUFFICIENT_BUFFER && code != ERROR_SUCCESS)
            error += " (win32=" + std::to_string(code) + ")";
        return nullptr;
    }
    std::vector<unsigned char> buffer(static_cast<size_t>(needed));
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (GetTokenInformation(token, TokenUser, buffer.data(), needed,
                            &needed)) {
        const auto* user =
            reinterpret_cast<const TOKEN_USER*>(buffer.data());
        LPWSTR sidText = nullptr;
        if (ConvertSidToStringSidW(user->User.Sid, &sidText)) {
            std::wstring sddl = L"O:";
            sddl += sidText;
            sddl += daclSddl;
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) {
                error = "could not convert owner-pinned SDDL";
                descriptor = nullptr;
            }
            LocalFree(sidText);
        } else {
            error = "could not render token user SID";
        }
    } else {
        error = "could not read token user for owner-pinned descriptor";
    }
    CloseHandle(token);
    return descriptor;
}

/* Convenience wrapper for the "D:P(A;;FA;;;OW)" policy. */
inline PSECURITY_DESCRIPTOR CreateOwnerOnlyDescriptor(std::string& error) {
    return CreateOwnerPinnedDescriptor(kOwnerOnlyDaclSddl, error);
}

} // namespace edr

#endif /* EDR_OWNER_ONLY_SD_H */
