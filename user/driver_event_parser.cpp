/*
 * driver_event_parser.cpp - Pure parser for driver wire events (M5: parse by
 * memcpy, never cast a wire byte pointer).
 */
#include "driver_event_parser.h"

#include <cstring>
#include <string>

#include "config.h"
#include "edr_event.h"

namespace edr {

bool ParseDriverEvent(const struct ::EDR_EVENT_HEADER& hdr,
                      const uint8_t* tlv, uint32_t tlvLen, Event& ev,
                      bool& malformed) {
    malformed = false;
    ev = Event();
    ev.type = hdr.type;
    ev.ts100ns = hdr.ts_100ns;
    ev.pid = hdr.pid;
    ev.ppid = hdr.ppid;
    ev.flags = hdr.flags;
    ev.source = "driver";
    ev.fields[field::kSource] = ev.source;
    ev.fields[field::kType] = EventTypeName(hdr.type);
    ev.fields[field::kPid] = std::to_string(hdr.pid);
    ev.fields[field::kPpid] = std::to_string(hdr.ppid);
    if (hdr.type == EDR_EVT_STATS) {
        ev.fields[field::kDroppedEvents] = std::to_string(hdr.reserved);
    }

    size_t off = 0;
    while (off + sizeof(EDR_TLV_HEADER) <= tlvLen) {
        EDR_TLV_HEADER th;
        std::memcpy(&th, tlv + off, sizeof(th));
        off += sizeof(th);
        if (off + th.len > tlvLen) {
            malformed = true;
            return false;
        }
        const uint8_t* value = tlv + off;
        const size_t units = th.len / 2; /* odd trailing byte is dropped */
        std::wstring wide(units, L'\0');
        if (units != 0) {
            std::memcpy(&wide[0], value, units * sizeof(wchar_t));
        }
        switch (th.tag) {
        case EDR_TAG_IMAGE:
            ev.fields[field::kImage] = WideToUtf8(wide.c_str(), wide.size());
            break;
        case EDR_TAG_COMMAND_LINE:
            ev.fields[field::kCommandLine] =
                WideToUtf8(wide.c_str(), wide.size());
            break;
        case EDR_TAG_PARENT_IMAGE:
            ev.fields[field::kParentImage] =
                WideToUtf8(wide.c_str(), wide.size());
            break;
        case EDR_TAG_FILE_PATH:
            ev.fields[field::kFilePath] =
                WideToUtf8(wide.c_str(), wide.size());
            break;
        case EDR_TAG_REG_KEY:
            ev.fields[field::kRegKey] = WideToUtf8(wide.c_str(), wide.size());
            break;
        case EDR_TAG_REG_VALUE:
            ev.fields[field::kRegValue] =
                WideToUtf8(wide.c_str(), wide.size());
            break;
        case EDR_TAG_SHA256:
            ev.fields[field::kSha256] =
                std::string((const char*)value, th.len);
            break;
        case EDR_TAG_DST_IP:
            ev.fields[field::kDstIp] =
                std::string((const char*)value, th.len);
            break;
        case EDR_TAG_DST_PORT: {
            uint16_t port = 0;
            if (th.len >= sizeof(port)) {
                std::memcpy(&port, value, sizeof(port));
            }
            ev.fields[field::kDstPort] = std::to_string(port);
            break;
        }
        case EDR_TAG_RULE_INDEX: {
            uint32_t rule = 0;
            if (th.len >= sizeof(rule)) {
                std::memcpy(&rule, value, sizeof(rule));
            }
            ev.fields[field::kRuleIndex] = std::to_string(rule);
            break;
        }
        case EDR_TAG_THREAD_ID: {
            uint32_t threadId = 0;
            if (th.len >= sizeof(threadId)) {
                std::memcpy(&threadId, value, sizeof(threadId));
            }
            ev.fields[field::kThreadId] = std::to_string(threadId);
            break;
        }
        case EDR_TAG_IMAGE_LOADED:
            ev.fields[field::kTargetImage] =
                WideToUtf8(wide.c_str(), wide.size());
            break;
        case EDR_TAG_TARGET_PID: {
            uint32_t pid = 0;
            if (th.len >= sizeof(pid)) {
                std::memcpy(&pid, value, sizeof(pid));
            }
            ev.fields[field::kTargetPid] = std::to_string(pid);
            break;
        }
        case EDR_TAG_ACCESS_MASK: {
            uint32_t mask = 0;
            if (th.len >= sizeof(mask)) {
                std::memcpy(&mask, value, sizeof(mask));
            }
            ev.fields[field::kAccessMask] = std::to_string(mask);
            break;
        }
        case EDR_TAG_OBJECT_TYPE: {
            uint8_t type = 0;
            if (th.len >= sizeof(type)) {
                std::memcpy(&type, value, sizeof(type));
            }
            ev.fields[field::kObjectType] = (type == 0) ? "process" : "thread";
            break;
        }
        case EDR_TAG_OLD_FILE_PATH:
            ev.fields[field::kOldFilePath] =
                WideToUtf8(wide.c_str(), wide.size());
            break;
        case EDR_TAG_REG_OPERATION: {
            uint8_t op = 0;
            if (th.len >= sizeof(op)) {
                std::memcpy(&op, value, sizeof(op));
            }
            ev.fields[field::kRegOperation] = (op == 0) ? "delete_value" : "delete_key";
            break;
        }
        default:
            break; /* forward compatibility: skip unknown tags */
        }
        off += th.len;
    }
    return true;
}

} // namespace edr