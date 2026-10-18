#ifndef EDR_XML_UTIL_H
#define EDR_XML_UTIL_H

#include <windows.h>

#include <cstdio>
#include <cwctype>
#include <limits>
#include <map>
#include <string>

namespace edr {

/* XML entity decoding. */
inline std::wstring DecodeXml(std::wstring value) {
    struct Entity { const wchar_t* encoded; const wchar_t* decoded; };
    const Entity entities[] = {
        {L"&amp;", L"&"}, {L"&lt;", L"<"}, {L"&gt;", L">"},
        {L"&quot;", L"\""}, {L"&apos;", L"'"}
    };
    for (const auto& entity : entities) {
        size_t pos = 0;
        while ((pos = value.find(entity.encoded, pos)) != std::wstring::npos) {
            value.replace(pos, wcslen(entity.encoded), entity.decoded);
            pos += wcslen(entity.decoded);
        }
    }
    return value;
}

/* Extract text content between an open tag and the next '<'. */
inline std::wstring ElementText(const std::wstring& xml,
                                const std::wstring& openTag) {
    size_t start = xml.find(openTag);
    if (start == std::wstring::npos) return {};
    start = xml.find(L'>', start);
    if (start == std::wstring::npos) return {};
    size_t end = xml.find(L'<', start + 1);
    if (end == std::wstring::npos) return {};
    return DecodeXml(xml.substr(start + 1, end - start - 1));
}

/* Extract an attribute value from a substring. */
inline std::wstring Attribute(const std::wstring& text, size_t start,
                              size_t end, const wchar_t* name) {
    std::wstring token(name);
    token += L"=";
    size_t pos = text.find(token, start);
    if (pos == std::wstring::npos || pos >= end) return {};
    pos += token.size();
    if (pos >= end || (text[pos] != L'\'' && text[pos] != L'\"')) return {};
    wchar_t delimiter = text[pos++];
    size_t valueEnd = text.find(delimiter, pos);
    if (valueEnd == std::wstring::npos || valueEnd > end) return {};
    return DecodeXml(text.substr(pos, valueEnd - pos));
}

/* Parse EventData <Data Name="..."> elements. */
inline std::map<std::wstring, std::wstring> EventData(const std::wstring& xml) {
    std::map<std::wstring, std::wstring> values;
    size_t pos = 0;
    while ((pos = xml.find(L"<Data ", pos)) != std::wstring::npos) {
        size_t tagEnd = xml.find(L'>', pos);
        if (tagEnd == std::wstring::npos) break;
        std::wstring name = Attribute(xml, pos, tagEnd, L"Name");
        size_t dataEnd = xml.find(L"</Data>", tagEnd + 1);
        if (dataEnd == std::wstring::npos) break;
        if (!name.empty()) {
            values[name] = DecodeXml(xml.substr(tagEnd + 1, dataEnd - tagEnd - 1));
        }
        pos = dataEnd + 7;
    }
    return values;
}

/* Parse unsigned decimal integer from a wide string. */
inline bool ParseUnsigned(const std::wstring& value, uint64_t maximum,
                          uint64_t& result) {
    if (value.empty()) return false;
    uint64_t number = 0;
    for (wchar_t ch : value) {
        if (ch < L'0' || ch > L'9') return false;
        uint64_t digit = static_cast<uint64_t>(ch - L'0');
        if (number > (maximum - digit) / 10) return false;
        number = number * 10 + digit;
    }
    result = number;
    return true;
}

/* Parse hex value with optional 0x/0X prefix (1-8 hex digits). */
inline bool ParseHexFlexible(const std::wstring& value, uint32_t& result) {
    size_t start = 0;
    if (value.size() >= 2 && value[0] == L'0' &&
        (value[1] == L'x' || value[1] == L'X')) {
        start = 2;
    }
    size_t digits = value.size() - start;
    if (digits < 1 || digits > 8) return false;
    uint32_t parsed = 0;
    for (size_t i = start; i < value.size(); ++i) {
        wchar_t ch = value[i];
        uint32_t digit = 0;
        if (ch >= L'0' && ch <= L'9') digit = static_cast<uint32_t>(ch - L'0');
        else if (ch >= L'a' && ch <= L'f') digit = static_cast<uint32_t>(ch - L'a' + 10);
        else if (ch >= L'A' && ch <= L'F') digit = static_cast<uint32_t>(ch - L'A' + 10);
        else return false;
        if (parsed > (std::numeric_limits<uint32_t>::max() - digit) / 16)
            return false;
        parsed = parsed * 16 + digit;
    }
    result = parsed;
    return true;
}

/* Hex with mandatory 0x/0X prefix (Sysmon-style). */
inline bool ParseHex32(const std::wstring& value, uint32_t& result) {
    if (value.size() < 3 || value.size() > 10 || value[0] != L'0' ||
        (value[1] != L'x' && value[1] != L'X')) return false;
    return ParseHexFlexible(value, result);
}

/* Extract <TimeCreated SystemTime='...'> value. */
inline std::wstring SourceTimestamp(const std::wstring& xml) {
    size_t timeCreated = xml.find(L"<TimeCreated");
    if (timeCreated == std::wstring::npos) return {};
    size_t end = xml.find(L'>', timeCreated);
    if (end == std::wstring::npos) return {};
    return Attribute(xml, timeCreated, end, L"SystemTime");
}

/* Convert ISO 8601 timestamp to FILETIME 100ns count. */
inline uint64_t ParseSystemTime100ns(const std::wstring& value) {
    if (value.size() != 28 || value[4] != L'-' || value[7] != L'-' ||
        value[10] != L'T' || value[13] != L':' || value[16] != L':' ||
        value[19] != L'.' || value[27] != L'Z') return 0;
    auto digits = [&](size_t offset, size_t count) -> int {
        int result = 0;
        for (size_t i = 0; i < count; ++i) {
            wchar_t ch = value[offset + i];
            if (ch < L'0' || ch > L'9') return -1;
            result = result * 10 + (ch - L'0');
        }
        return result;
    };
    SYSTEMTIME st = {};
    int year = digits(0, 4), month = digits(5, 2), day = digits(8, 2);
    int hour = digits(11, 2), minute = digits(14, 2), second = digits(17, 2);
    int fraction100ns = digits(20, 7);
    if (year < 0 || month < 0 || day < 0 || hour < 0 || minute < 0 ||
        second < 0 || fraction100ns < 0) return 0;
    st.wYear = static_cast<WORD>(year);
    st.wMonth = static_cast<WORD>(month);
    st.wDay = static_cast<WORD>(day);
    st.wHour = static_cast<WORD>(hour);
    st.wMinute = static_cast<WORD>(minute);
    st.wSecond = static_cast<WORD>(second);
    FILETIME ft = {};
    if (!SystemTimeToFileTime(&st, &ft)) return 0;
    return ((static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime) +
           static_cast<uint64_t>(fraction100ns);
}

/* Parse <TagName>value</TagName> pairs inside a <UserData> section.
 * Unlike EventData (which uses <Data Name="...">value</Data>),
 * WMI-Activity uses plain named tags. Returns all tag/value pairs
 * found within the first <UserData>...</UserData> block, skipping the
 * named wrapper element (e.g. <Operation_TemporaryEssStarted>). */
inline bool UserDataPairs(const std::wstring& xml,
                          std::map<std::wstring, std::wstring>& values) {
    values.clear();
    size_t udStart = xml.find(L"<UserData>");
    if (udStart == std::wstring::npos) return false;
    size_t udEnd = xml.find(L"</UserData>", udStart);
    if (udEnd == std::wstring::npos) return false;
    size_t pos = udStart + 10;
    while (pos < udEnd && iswspace(xml[pos])) ++pos;
    if (pos >= udEnd || xml[pos] != L'<') return false;
    size_t wrapperNameEnd = xml.find_first_of(L" \t>", pos + 1);
    if (wrapperNameEnd == std::wstring::npos || wrapperNameEnd >= udEnd)
        return false;
    std::wstring wrapperName = xml.substr(pos + 1, wrapperNameEnd - pos - 1);
    if (wrapperName.empty() || wrapperName[0] == L'/') return false;
    size_t wrapperEnd = xml.find(L'>', wrapperNameEnd);
    if (wrapperEnd == std::wstring::npos || wrapperEnd >= udEnd) return false;
    std::wstring wrapperClose = L"</" + wrapperName + L">";
    size_t wrapperCloseAt = xml.find(wrapperClose, wrapperEnd + 1);
    if (wrapperCloseAt == std::wstring::npos || wrapperCloseAt >= udEnd)
        return false;
    pos = wrapperEnd + 1;
    /* Parse <TagName>value</TagName> pairs */
    while (pos < wrapperCloseAt) {
        if (xml[pos] != L'<') { ++pos; continue; }
        size_t tagOpen = pos;
        size_t tagNameEnd = xml.find_first_of(L" \t>", tagOpen + 1);
        if (tagNameEnd == std::wstring::npos || tagNameEnd >= wrapperCloseAt)
            return false;
        size_t tagClose = xml.find(L'>', tagNameEnd);
        if (tagClose == std::wstring::npos || tagClose >= wrapperCloseAt)
            return false;
        /* Skip self-closing tags and the wrapper close tag */
        if (xml[tagClose - 1] == L'/') { pos = tagClose + 1; continue; }
        std::wstring tagName = xml.substr(tagOpen + 1, tagNameEnd - tagOpen - 1);
        if (tagName.empty() || tagName[0] == L'/') return false;
        std::wstring closingTag = L"</" + tagName + L">";
        size_t valueEnd = xml.find(closingTag, tagClose + 1);
        if (valueEnd == std::wstring::npos || valueEnd >= wrapperCloseAt)
            return false;
        std::wstring rawValue = xml.substr(tagClose + 1, valueEnd - tagClose - 1);
        if (rawValue.find(L'<') != std::wstring::npos) return false;
        std::wstring value = DecodeXml(std::move(rawValue));
        values[tagName] = value;
        pos = valueEnd + closingTag.size();
    }
    while (pos < wrapperCloseAt && iswspace(xml[pos])) ++pos;
    if (pos != wrapperCloseAt || values.empty()) return false;
    pos = wrapperCloseAt + wrapperClose.size();
    while (pos < udEnd && iswspace(xml[pos])) ++pos;
    return pos == udEnd;
}

} // namespace edr

#endif /* EDR_XML_UTIL_H */
