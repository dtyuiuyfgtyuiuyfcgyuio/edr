/*
 * policy_validate.h - Pure-C whole-table validation for EDR_POLICY_V1.
 *
 * This header is intentionally free of kernel dependencies so the exact
 * same validation can be unit-tested from user mode (driver_protocol_tests)
 * and called from the kernel policy singleton (policy.c). The function
 * validates the entire packed table and rejects it as a whole on the first
 * malformed field; no truncation, skipping, or repair is ever performed.
 *
 * Rules (PHASE_BC_PLAN.md "Protocol definitions and validation"):
 *   - exact input size, version, struct_size;
 *   - nonzero generation, enable_mask within KNOWN_MASK, counts in bounds;
 *   - all reserved/unused bytes zero;
 *   - file rules: even nonzero bounded length, no NUL, no unpaired UTF-16
 *     surrogate, leading backslash, case-insensitively unique prefixes;
 *   - net rules: display-order IPv4 excluding special addresses, port 0
 *     meaning any port, case-free uniqueness on (ip, port);
 *   - unused rule slots entirely zero.
 */
#ifndef EDR_POLICY_VALIDATE_H
#define EDR_POLICY_VALIDATE_H

#include <stddef.h>

#include "edr_ioctl.h"

#ifdef __cplusplus
extern "C" {
#endif

static int EdrPolicyValidate(const void* data, size_t size)
{
    const EDR_POLICY_V1* p;
    size_t i;

    if (data == NULL || size != sizeof(EDR_POLICY_V1)) {
        return -1;
    }
    p = (const EDR_POLICY_V1*)data;

    if (p->version != EDR_POLICY_VERSION ||
        p->struct_size != sizeof(EDR_POLICY_V1) ||
        p->generation == 0 ||
        (p->enable_mask & ~EDR_ENABLE_KNOWN_MASK) != 0 ||
        p->file_rule_count > EDR_MAX_FILE_RULES ||
        p->net_rule_count > EDR_MAX_NET_RULES ||
        p->reserved[0] != 0 || p->reserved[1] != 0) {
        return -1;
    }

    /* File rules: used slots validate, unused slots must be all zero. */
    for (i = 0; i < EDR_MAX_FILE_RULES; i++) {
        const EDR_POLICY_FILE_RULE* r = &p->file_rules[i];
        size_t j;

        if (i < p->file_rule_count) {
            size_t wchars;

            if (r->reserved != 0 ||
                r->length == 0 ||
                r->length > EDR_PATH_MAX_BYTES ||
                (r->length & (sizeof(unsigned short) - 1u)) != 0 ||
                r->path[0] != L'\\') {
                return -1;
            }
            wchars = r->length / sizeof(unsigned short);
            for (j = 0; j < wchars; j++) {
                unsigned int c = r->path[j];
                if (c == 0) {
                    return -1; /* no NUL inside the prefix */
                }
                if (c >= 0xD800u && c <= 0xDBFFu) {
                    unsigned int next = (j + 1 < wchars) ? r->path[j + 1] : 0;
                    if (next < 0xDC00u || next > 0xDFFFu) {
                        return -1; /* unpaired high surrogate */
                    }
                    j++;
                } else if (c >= 0xDC00u && c <= 0xDFFFu) {
                    return -1; /* lone low surrogate */
                }
            }
            /* Every byte beyond the declared prefix (offset 4 = length +
             * reserved fields, then `length` path bytes) must be zero. */
            for (j = sizeof(EDR_POLICY_FILE_RULE); j != 0; ) {
                j--;
                if (((const unsigned char*)r)[j] != 0 &&
                    j >= (size_t)r->length + 4u) {
                    return -1;
                }
            }
        } else {
            const unsigned char* raw = (const unsigned char*)r;
            for (j = 0; j < sizeof(EDR_POLICY_FILE_RULE); j++) {
                if (raw[j] != 0) {
                    return -1;
                }
            }
        }
    }

    /* Duplicate file prefixes are rejected (case-insensitive). */
    for (i = 0; i < p->file_rule_count; i++) {
        size_t j;
        for (j = i + 1; j < p->file_rule_count; j++) {
            const EDR_POLICY_FILE_RULE* a = &p->file_rules[i];
            const EDR_POLICY_FILE_RULE* b = &p->file_rules[j];
            size_t n = a->length / sizeof(unsigned short);
            size_t k;

            if (b->length != a->length) {
                continue;
            }
            for (k = 0; k < n; k++) {
                unsigned int x = a->path[k];
                unsigned int y = b->path[k];
                if (x >= L'a' && x <= L'z') x = x - L'a' + L'A';
                if (y >= L'a' && y <= L'z') y = y - L'a' + L'A';
                if (x != y) {
                    break;
                }
            }
            if (k == n) {
                return -1;
            }
        }
    }

    /* Net rules: used slots validate, unused slots must be all zero. */
    for (i = 0; i < EDR_MAX_NET_RULES; i++) {
        const EDR_POLICY_NET_RULE* r = &p->net_rules[i];
        unsigned int ip = ((unsigned int)r->ip[0] << 24) |
                          ((unsigned int)r->ip[1] << 16) |
                          ((unsigned int)r->ip[2] << 8) |
                          (unsigned int)r->ip[3];

        if (i < p->net_rule_count) {
            /* Exclude special addresses: unspecified, loopback, multicast,
             * and limited broadcast. Private ranges remain valid targets. */
            if (ip == 0x00000000u || ip == 0xFFFFFFFFu ||
                (ip & 0xFF000000u) == 0x7F000000u ||
                (ip & 0xF0000000u) == 0xE0000000u ||
                r->reserved != 0) {
                return -1;
            }
        } else if (r->ip[0] != 0 || r->ip[1] != 0 || r->ip[2] != 0 ||
                   r->ip[3] != 0 || r->port != 0 || r->reserved != 0) {
            return -1;
        }
    }

    /* Duplicate (ip, port) net rules are rejected. */
    for (i = 0; i < p->net_rule_count; i++) {
        size_t j;
        for (j = i + 1; j < p->net_rule_count; j++) {
            const EDR_POLICY_NET_RULE* a = &p->net_rules[i];
            const EDR_POLICY_NET_RULE* b = &p->net_rules[j];
            if (a->ip[0] == b->ip[0] && a->ip[1] == b->ip[1] &&
                a->ip[2] == b->ip[2] && a->ip[3] == b->ip[3] &&
                a->port == b->port) {
                return -1;
            }
        }
    }

    return 0;
}

#ifdef __cplusplus
}
#endif

#endif /* EDR_POLICY_VALIDATE_H */
