/*
 * edr_policy_engine.h - Pure, portable policy validation and bounded matching.
 *
 * Single source of truth for the EDR_POLICY_V1 wire-format rules. It is
 * compiled into the kernel driver by driver/policy.c (which owns the private
 * nonpaged double-snapshot singleton around it) AND into the user-mode
 * protocol tests, so both sides execute identical code. If the validation or
 * match semantics change, this header is the only place to change them.
 *
 * All functions are static, allocation-free, use only built-in 1/2/4-byte
 * types, and are safe to call at DISPATCH_LEVEL. Matching is bounded: at
 * most 32 rules x 256 UTF-16 units per file comparison and 64 fixed network
 * rule compares.
 *
 * Validation rejects the entire table on any single malformed field. The
 * caller must never truncate, skip, or partially repair a table.
 */
#ifndef EDR_POLICY_ENGINE_H
#define EDR_POLICY_ENGINE_H

#include "edr_ioctl.h"
#include "edr_event.h"

/* ASCII-a-z case folding only; non-ASCII code units compare as-is. This is
 * the documented bounded normalization for NT-path prefix matching. */
static unsigned int EdrPolicyEngineUpcase(unsigned int c)
{
    if (c >= (unsigned int)'a' && c <= (unsigned int)'z') {
        return c - (unsigned int)'a' + (unsigned int)'A';
    }
    return c;
}

/* Excluded IPv4 special addresses: 0.0.0.0, 255.255.255.255, and the
 * 224.0.0.0/3 multicast/reserved block (first octet >= 224). */
static int EdrPolicyEngineIpv4IsSpecial(const unsigned char ip[4])
{
    if (ip[0] == 0x00u && ip[1] == 0x00u && ip[2] == 0x00u && ip[3] == 0x00u) {
        return 1;
    }
    if (ip[0] == 0xffu && ip[1] == 0xffu && ip[2] == 0xffu && ip[3] == 0xffu) {
        return 1;
    }
    if (ip[0] >= 0xe0u) {
        return 1;
    }
    return 0;
}

/* Fill a policy table with the boot defaults: PROCESS|REGISTRY enabled,
 * rules empty, generation 1. */
static void EdrPolicyEngineInitialize(EDR_POLICY_V1* Policy)
{
    unsigned char* bytes;
    unsigned int i;

    if (Policy == NULL) {
        return;
    }
    bytes = (unsigned char*)Policy;
    for (i = 0; i < EDR_POLICY_SIZE; ++i) {
        bytes[i] = 0;
    }
    Policy->version = EDR_POLICY_VERSION;
    Policy->struct_size = EDR_POLICY_SIZE;
    Policy->generation = 1u;
    Policy->enable_mask = EDR_ENABLE_PROCESS | EDR_ENABLE_REGISTRY;
    Policy->file_rule_count = 0u;
    Policy->net_rule_count = 0u;
}

/* Validate the whole packed table. Returns 1 on success, 0 on any fault. */
static int EdrPolicyEngineValidate(const EDR_POLICY_V1* Policy)
{
    unsigned int i;
    unsigned int j;

    if (Policy == NULL) {
        return 0;
    }
    if (Policy->version != EDR_POLICY_VERSION) {
        return 0;
    }
    if (Policy->struct_size != EDR_POLICY_SIZE) {
        return 0;
    }
    if (Policy->generation == 0u) {
        return 0;
    }
    if ((Policy->enable_mask & ~EDR_ENABLE_KNOWN_MASK) != 0u) {
        return 0;
    }
    if (Policy->file_rule_count > EDR_MAX_FILE_RULES) {
        return 0;
    }
    if (Policy->net_rule_count > EDR_MAX_NET_RULES) {
        return 0;
    }
    if (Policy->reserved[0] != 0u || Policy->reserved[1] != 0u) {
        return 0;
    }

    for (i = 0; i < EDR_MAX_FILE_RULES; ++i) {
        const EDR_POLICY_FILE_RULE* fr = &Policy->file_rules[i];
        unsigned int word_units;

        if (i >= Policy->file_rule_count) {
            /* unused slot: the whole rule must be zero */
            const unsigned char* p = (const unsigned char*)fr;
            for (j = 0; j < EDR_POLICY_FILE_RULE_SIZE; ++j) {
                if (p[j] != 0u) {
                    return 0;
                }
            }
            continue;
        }
        if (fr->length == 0u || fr->length > EDR_PATH_MAX_BYTES) {
            return 0;
        }
        if ((fr->length & 1u) != 0u) {
            return 0; /* byte count must be even (UTF-16 units) */
        }
        if (fr->reserved != 0u) {
            return 0;
        }
        word_units = (unsigned int)fr->length / 2u;
        if (EdrPolicyEngineUpcase((unsigned int)fr->path[0]) !=
            (unsigned int)'\\') {
            return 0; /* normalized leading backslash */
        }
        for (j = 0; j < word_units; ++j) {
            unsigned int c = (unsigned int)fr->path[j];
            if (c == 0u) {
                return 0; /* no NUL inside the prefix */
            }
            if (c >= 0xD800u && c <= 0xDBFFu) { /* high surrogate */
                if (j + 1u >= word_units) {
                    return 0; /* unpaired trailing high */
                }
                if (!(fr->path[j + 1u] >= 0xDC00u &&
                      fr->path[j + 1u] <= 0xDFFFu)) {
                    return 0; /* high not followed by low */
                }
                ++j; /* consume the low half of the pair */
            } else if (c >= 0xDC00u && c <= 0xDFFFu) {
                return 0; /* low surrogate without a preceding high */
            }
        }
        /* every stored byte after the declared prefix must be zero */
        {
            const unsigned char* q = (const unsigned char*)fr->path;
            for (j = (unsigned int)fr->length; j < EDR_PATH_MAX_BYTES; ++j) {
                if (q[j] != 0u) {
                    return 0;
                }
            }
        }
    }

    for (i = 0; i < EDR_MAX_NET_RULES; ++i) {
        const EDR_POLICY_NET_RULE* nr = &Policy->net_rules[i];

        if (i >= Policy->net_rule_count) {
            const unsigned char* p = (const unsigned char*)nr;
            for (j = 0; j < EDR_POLICY_NET_RULE_SIZE; ++j) {
                if (p[j] != 0u) {
                    return 0;
                }
            }
            continue;
        }
        if (nr->reserved != 0u) {
            return 0;
        }
        if (EdrPolicyEngineIpv4IsSpecial(nr->ip)) {
            return 0;
        }
        /* port is any u16; 0 means "any port" */
    }

    /* duplicate file prefixes (case-insensitive) */
    for (i = 0; i < Policy->file_rule_count; ++i) {
        for (j = i + 1u; j < Policy->file_rule_count; ++j) {
            const EDR_POLICY_FILE_RULE* a = &Policy->file_rules[i];
            const EDR_POLICY_FILE_RULE* b = &Policy->file_rules[j];
            unsigned int k;
            unsigned int aunits = (unsigned int)a->length / 2u;
            unsigned int bunits = (unsigned int)b->length / 2u;

            if (aunits != bunits) {
                continue;
            }
            for (k = 0; k < aunits; ++k) {
                if (EdrPolicyEngineUpcase((unsigned int)a->path[k]) !=
                    EdrPolicyEngineUpcase((unsigned int)b->path[k])) {
                    break;
                }
            }
            if (k == aunits) {
                return 0;
            }
        }
    }

    /* duplicate network rules (identical ip + port) */
    for (i = 0; i < Policy->net_rule_count; ++i) {
        for (j = i + 1u; j < Policy->net_rule_count; ++j) {
            const EDR_POLICY_NET_RULE* a = &Policy->net_rules[i];
            const EDR_POLICY_NET_RULE* b = &Policy->net_rules[j];
            unsigned int k;

            for (k = 0; k < 4u; ++k) {
                if (a->ip[k] != b->ip[k]) {
                    break;
                }
            }
            if (k == 4u && a->port == b->port) {
                return 0;
            }
        }
    }

    return 1;
}

/* Case-insensitive bounded NT path prefix match against one rule table.
 * NtPathBytes is the byte length of NtPath (no NUL terminator required).
 * A prefix must land on a path-component boundary unless it ends the path. */
static int EdrPolicyEngineMatchFile(const EDR_POLICY_V1* Policy,
                                    const unsigned short* NtPath,
                                    unsigned long NtPathBytes)
{
    unsigned int i;
    unsigned int k;
    unsigned long path_units;

    if (Policy == NULL || NtPath == NULL) {
        return 0;
    }
    if (NtPathBytes == 0ul || (NtPathBytes & 1ul) != 0ul) {
        return 0;
    }
    path_units = NtPathBytes / 2ul;

    for (i = 0; i < Policy->file_rule_count; ++i) {
        const EDR_POLICY_FILE_RULE* fr = &Policy->file_rules[i];
        unsigned int rule_units = (unsigned int)fr->length / 2u;

        if (rule_units > path_units) {
            continue;
        }
        for (k = 0; k < rule_units; ++k) {
            if (EdrPolicyEngineUpcase((unsigned int)fr->path[k]) !=
                EdrPolicyEngineUpcase((unsigned int)NtPath[k])) {
                break;
            }
        }
        if (k == rule_units) {
            if (rule_units == path_units ||
                NtPath[rule_units] == (unsigned short)'\\') {
                return 1;
            }
        }
    }
    return 0;
}

/* IPv4 display-order + port match. port 0 in a rule means "any port". */
static int EdrPolicyEngineMatchNet(const EDR_POLICY_V1* Policy,
                                   const unsigned char* Address4,
                                   unsigned short Port)
{
    unsigned int i;

    if (Policy == NULL || Address4 == NULL) {
        return 0;
    }
    for (i = 0; i < Policy->net_rule_count; ++i) {
        const EDR_POLICY_NET_RULE* nr = &Policy->net_rules[i];

        if (nr->ip[0] != Address4[0] || nr->ip[1] != Address4[1] ||
            nr->ip[2] != Address4[2] || nr->ip[3] != Address4[3]) {
            continue;
        }
        if (nr->port == 0u || nr->port == Port) {
            return 1;
        }
    }
    return 0;
}

#endif /* EDR_POLICY_ENGINE_H */