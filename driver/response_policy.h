/* Pure bounded response policy shared by the driver and protocol tests. */
#ifndef EDR_RESPONSE_POLICY_H
#define EDR_RESPONSE_POLICY_H

static __inline unsigned char EdrResponseLowerAscii(unsigned char value) {
    return value >= 'A' && value <= 'Z' ? value + ('a' - 'A') : value;
}

static __inline int EdrIsProtectedResponseImage(const char* image,
                                               unsigned long imageBytes) {
    static const char* const denied[] = {
        "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
        "lsass.exe", "services.exe", "lsaiso.exe", "registry"
    };
    unsigned long i;
    if (image == 0 || imageBytes == 0) return 1;
    for (i = 0; i < sizeof(denied) / sizeof(denied[0]); ++i) {
        unsigned long j = 0;
        while (j < imageBytes && image[j] != '\0' && denied[i][j] != '\0' &&
               EdrResponseLowerAscii((unsigned char)image[j]) ==
                   (unsigned char)denied[i][j]) ++j;
        if (denied[i][j] == '\0' &&
            (j == imageBytes || image[j] == '\0')) return 1;
    }
    return 0;
}

#endif
