/*
 * json_lite.h - Minimal self-contained JSON subset (UTF-8): objects, arrays,
 * strings, numbers, booleans, null. Used only for the custom JSON rule
 * subset and the agent configuration. This is NOT a Sigma-compatible rules
 * engine and does not aim to be one.
 */
#ifndef EDR_JSON_LITE_H
#define EDR_JSON_LITE_H

#include <cctype>
#include <cstdint>
#include <cstdio>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace jsonlite {

enum class Type { Null, Bool, Number, String, Array, Object };

struct Value {
    Type type = Type::Null;
    bool boolean = false;
    double number = 0.0;
    std::string str;
    std::vector<Value> array;
    std::map<std::string, Value> object;

    static Value makeNull() { return Value(); }
    static Value makeBool(bool b) { Value v; v.type = Type::Bool; v.boolean = b; return v; }
    static Value makeNumber(double n) { Value v; v.type = Type::Number; v.number = n; return v; }
    static Value makeString(std::string s) { Value v; v.type = Type::String; v.str = std::move(s); return v; }
    static Value makeArray() { Value v; v.type = Type::Array; return v; }
    static Value makeObject() { Value v; v.type = Type::Object; return v; }

    const Value* find(const std::string& key) const {
        if (type != Type::Object) return nullptr;
        auto it = object.find(key);
        return it == object.end() ? nullptr : &it->second;
    }
    std::string asString(const std::string& def = "") const {
        return type == Type::String ? str : def;
    }
    double asNumber(double def = 0.0) const {
        return type == Type::Number ? number : def;
    }
    bool asBool(bool def = false) const {
        return type == Type::Bool ? boolean : def;
    }
};

class ParseError : public std::runtime_error {
public:
    explicit ParseError(const std::string& msg) : std::runtime_error(msg) {}
};

class Parser {
public:
    explicit Parser(const std::string& text) : m_text(text), m_pos(0) {}

    Value parse() {
        skipWs();
        Value v = parseValue();
        skipWs();
        if (m_pos != m_text.size()) {
            fail("trailing characters after JSON value");
        }
        return v;
    }

private:
    const std::string& m_text;
    size_t m_pos;

    [[noreturn]] void fail(const std::string& msg) const {
        throw ParseError("json parse error at offset " +
                         std::to_string(m_pos) + ": " + msg);
    }

    char peek() const {
        return m_pos < m_text.size() ? m_text[m_pos] : '\0';
    }
    char get() {
        if (m_pos >= m_text.size()) fail("unexpected end of input");
        return m_text[m_pos++];
    }
    void skipWs() {
        while (m_pos < m_text.size()) {
            char c = m_text[m_pos];
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
                m_pos++;
            } else {
                break;
            }
        }
    }
    void expect(char c) {
        if (get() != c) fail(std::string("expected '") + c + "'");
    }
    bool consume(const char* word) {
        size_t n = std::char_traits<char>::length(word);
        if (m_text.compare(m_pos, n, word) == 0) {
            m_pos += n;
            return true;
        }
        return false;
    }

    Value parseValue() {
        skipWs();
        char c = peek();
        switch (c) {
        case '{': return parseObject();
        case '[': return parseArray();
        case '"': return Value::makeString(parseString());
        case 't': if (consume("true")) return Value::makeBool(true); break;
        case 'f': if (consume("false")) return Value::makeBool(false); break;
        case 'n': if (consume("null")) return Value::makeNull(); break;
        default:
            if (c == '-' || (c >= '0' && c <= '9')) return parseNumber();
            break;
        }
        fail("unexpected character");
    }

    Value parseObject() {
        Value obj = Value::makeObject();
        expect('{');
        skipWs();
        if (peek() == '}') { m_pos++; return obj; }
        for (;;) {
            skipWs();
            std::string key = parseString();
            skipWs();
            expect(':');
            Value value = parseValue();
            if (!obj.object.emplace(std::move(key), std::move(value)).second) {
                fail("duplicate object key");
            }
            skipWs();
            char c = get();
            if (c == '}') return obj;
            if (c != ',') fail("expected ',' or '}' in object");
        }
    }

    Value parseArray() {
        Value arr = Value::makeArray();
        expect('[');
        skipWs();
        if (peek() == ']') { m_pos++; return arr; }
        for (;;) {
            arr.array.push_back(parseValue());
            skipWs();
            char c = get();
            if (c == ']') return arr;
            if (c != ',') fail("expected ',' or ']' in array");
        }
    }

    std::string parseString() {
        std::string out;
        expect('"');
        for (;;) {
            char c = get();
            if (c == '"') return out;
            if (c == '\\') {
                char e = get();
                switch (e) {
                case '"': out.push_back('"'); break;
                case '\\': out.push_back('\\'); break;
                case '/': out.push_back('/'); break;
                case 'b': out.push_back('\b'); break;
                case 'f': out.push_back('\f'); break;
                case 'n': out.push_back('\n'); break;
                case 'r': out.push_back('\r'); break;
                case 't': out.push_back('\t'); break;
                case 'u': appendUnicodeEscape(out); break;
                default: fail("invalid escape sequence");
                }
            } else {
                if (static_cast<unsigned char>(c) < 0x20)
                    fail("unescaped control character in string");
                out.push_back(c);
            }
        }
    }

    void appendUnicodeEscape(std::string& out) {
        unsigned int cp = parseHex4();
        if (cp >= 0xD800 && cp <= 0xDBFF) {
            /* surrogate pair */
            if (peek() == '\\') {
                m_pos++;
                if (get() != 'u') fail("expected low surrogate escape");
                unsigned int lo = parseHex4();
                if (lo >= 0xDC00 && lo <= 0xDFFF) {
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                } else {
                    fail("invalid low surrogate");
                }
            } else {
                fail("unpaired high surrogate");
            }
        } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
            fail("unpaired low surrogate");
        }
        /* encode UTF-8 */
        if (cp < 0x80) {
            out.push_back((char)cp);
        } else if (cp < 0x800) {
            out.push_back((char)(0xC0 | (cp >> 6)));
            out.push_back((char)(0x80 | (cp & 0x3F)));
        } else if (cp < 0x10000) {
            out.push_back((char)(0xE0 | (cp >> 12)));
            out.push_back((char)(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back((char)(0x80 | (cp & 0x3F)));
        } else {
            out.push_back((char)(0xF0 | (cp >> 18)));
            out.push_back((char)(0x80 | ((cp >> 12) & 0x3F)));
            out.push_back((char)(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back((char)(0x80 | (cp & 0x3F)));
        }
    }

    unsigned int parseHex4() {
        unsigned int v = 0;
        for (int i = 0; i < 4; i++) {
            char c = get();
            v <<= 4;
            if (c >= '0' && c <= '9') v |= (unsigned int)(c - '0');
            else if (c >= 'a' && c <= 'f') v |= (unsigned int)(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') v |= (unsigned int)(c - 'A' + 10);
            else fail("invalid hex digit");
        }
        return v;
    }

    Value parseNumber() {
        size_t start = m_pos;
        if (peek() == '-') m_pos++;
        if (peek() == '0') {
            m_pos++;
            if (std::isdigit((unsigned char)peek())) fail("leading zero in number");
        } else {
            if (!std::isdigit((unsigned char)peek())) fail("invalid number");
            while (std::isdigit((unsigned char)peek())) m_pos++;
        }
        if (peek() == '.') {
            m_pos++;
            if (!std::isdigit((unsigned char)peek())) fail("invalid fraction");
            while (std::isdigit((unsigned char)peek())) m_pos++;
        }
        if (peek() == 'e' || peek() == 'E') {
            m_pos++;
            if (peek() == '+' || peek() == '-') m_pos++;
            if (!std::isdigit((unsigned char)peek())) fail("invalid exponent");
            while (std::isdigit((unsigned char)peek())) m_pos++;
        }
        return Value::makeNumber(std::stod(m_text.substr(start, m_pos - start)));
    }
};

inline Value parse(const std::string& text) {
    return Parser(text).parse();
}

/* Escaping writer for flat string fields (used by alerter/reporter). */
inline std::string escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if ((unsigned char)c < 0x20) {
                char buf[8];
                std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                out += buf;
            } else {
                out.push_back(c);
            }
        }
    }
    return out;
}

} /* namespace jsonlite */

#endif /* EDR_JSON_LITE_H */
