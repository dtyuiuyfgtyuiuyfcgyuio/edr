/*
 * syslog_verify_receiver.js - UDP RFC 5424 test receiver for the EDR agent.
 *
 * Listens on 127.0.0.1:5514, validates each datagram against the RFC 5424
 * grammar emitted by user/syslog_forwarder.cpp, prints every message, and
 * exits 0 only when at least one message passed validation.
 *
 * The parser (parseSyslogDatagram) is a pure function exported for unit
 * tests (scripts/syslog_verify_receiver.test.js). Unlike the previous
 * single-regex approach it parses STRUCTURED-DATA precisely with escape
 * handling, so a MSG containing ']' (e.g. JSON arrays) is split correctly
 * instead of being swallowed by a greedy bracket match.
 *
 * Usage:  node scripts/syslog_verify_receiver.js [port] [idleTimeoutMs]
 * Tests:  node --test scripts/
 * Exit:   0 = >=1 valid message, 1 = none/invalid, 2 = bind failure.
 */
'use strict';

const dgram = require('node:dgram');

/* ---------------------- RFC 5424 parsing (pure) ---------------------- */

const NILVALUE = '-';
/* PRINTUSASCII = %d33-126: printable ASCII without space. */
const TIMESTAMP_RE =
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;
/* ABNF length limits (RFC 5424 section 6). */
const MAX_LEN = {
    timestamp: 32,
    hostname: 255,
    appName: 48,
    procid: 128,
    msgid: 32,
    sdId: 32,
    paramName: 32,
};

function fail(error, where) {
    return { ok: false, error, where };
}

function isPrintUsAscii(str) {
    for (let i = 0; i < str.length; i++) {
        const code = str.charCodeAt(i);
        if (code < 0x21 || code > 0x7e) return false;
    }
    return true;
}

/* ABNF-level range check (month 01-12, day 01-31, hour <=23, minute <=59,
 * second <=60 for leap seconds). */
function isValidTimestampRange(ts) {
    const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})/.exec(ts);
    if (!m) return false;
    const month = Number(m[2]);
    const day = Number(m[3]);
    const hour = Number(m[4]);
    const minute = Number(m[5]);
    const second = Number(m[6]);
    return month >= 1 && month <= 12 && day >= 1 && day <= 31 &&
        hour <= 23 && minute <= 59 && second <= 60;
}

function isValidTimestamp(ts) {
    return TIMESTAMP_RE.test(ts) && isValidTimestampRange(ts);
}

/* Read one SP-terminated header field starting at pos. */
function readHeaderField(text, pos, name, maxLength) {
    const sp = text.indexOf(' ', pos);
    if (sp === -1) return fail(`missing-${name}`, name);
    const value = text.slice(pos, sp);
    if (value === '') return fail(`empty-${name}`, name);
    if (value !== NILVALUE &&
        (!isPrintUsAscii(value) || value.length > maxLength)) {
        return fail(`invalid-${name}`, name);
    }
    return { ok: true, value, next: sp + 1 };
}

/* Parse one SD-ELEMENT: "[" SD-ID *(SP PARAM-NAME "=" DQUOTE PARAM-VALUE DQUOTE) "]" */
function parseSdElement(text, pos) {
    const start = pos;
    pos += 1; /* consume '[' */
    const idStart = pos;
    while (pos < text.length && text[pos] !== ' ' && text[pos] !== ']') pos++;
    const sdId = text.slice(idStart, pos);
    if (sdId === '' || sdId.length > MAX_LEN.sdId || !isPrintUsAscii(sdId)) {
        return fail('invalid-sd-id', 'structured-data');
    }
    const params = [];
    while (text[pos] === ' ') {
        pos += 1; /* SP before the param */
        const nameStart = pos;
        while (pos < text.length && text[pos] !== ' ' && text[pos] !== '=' &&
               text[pos] !== ']') {
            pos++;
        }
        const name = text.slice(nameStart, pos);
        if (name === '' || name.length > MAX_LEN.paramName ||
            !isPrintUsAscii(name)) {
            return fail('invalid-param-name', 'structured-data');
        }
        if (text[pos] !== '=') return fail('missing-param-equals', 'structured-data');
        pos += 1;
        if (text[pos] !== '"') return fail('missing-param-quote', 'structured-data');
        pos += 1;
        let value = '';
        let closed = false;
        while (pos < text.length) {
            const ch = text[pos];
            const code = ch.charCodeAt(0);
            if (ch === '\\') {
                /* Only ", \ and ] are escapable (RFC 5424 section 6.3.3). */
                const next = text[pos + 1];
                if (next === '"' || next === '\\' || next === ']') {
                    value += next;
                    pos += 2;
                    continue;
                }
                return fail('invalid-escape', 'structured-data');
            }
            if (code < 0x20 || code === 0x7f) {
                return fail('invalid-param-char', 'structured-data');
            }
            if (ch === ']') {
                return fail('unescaped-close-bracket', 'structured-data');
            }
            if (ch === '"') {
                closed = true;
                pos += 1;
                break;
            }
            value += ch;
            pos += 1;
        }
        if (!closed) return fail('unterminated-param-value', 'structured-data');
        params.push({ name, value });
    }
    if (text[pos] !== ']') return fail('unterminated-sd-element', 'structured-data');
    pos += 1;
    return { ok: true, value: text.slice(start, pos), sdId, params, next: pos };
}

/* STRUCTURED-DATA = NILVALUE / 1*SD-ELEMENT */
function parseStructuredData(text, pos) {
    if (text[pos] === '-') {
        return { ok: true, value: NILVALUE, elements: [], next: pos + 1 };
    }
    const start = pos;
    const elements = [];
    while (pos < text.length && text[pos] === '[') {
        const element = parseSdElement(text, pos);
        if (!element.ok) return element;
        elements.push({ sdId: element.sdId, params: element.params });
        pos = element.next;
    }
    if (elements.length === 0) {
        return fail('missing-structured-data', 'structured-data');
    }
    return { ok: true, value: text.slice(start, pos), elements, next: pos };
}

/*
 * Parse one complete RFC 5424 message.
 * Success: { ok:true, pri, facility, severity, version, timestamp, hostname,
 *            appName, procid, msgid, structuredData:'-', sdElements, msg }
 * Failure: { ok:false, error, where } with a stable error code for tests.
 */
function parseSyslogDatagram(text) {
    if (typeof text !== 'string') return fail('not-a-string', 'input');

    /* PRI = "<" 1*3DIGIT ">"; no leading zeros except "0" itself. */
    let m = /^<(\d{1,3})>/.exec(text);
    if (!m) return fail('missing-pri', 'pri');
    if (m[1] !== '0' && m[1][0] === '0') return fail('pri-leading-zero', 'pri');
    const pri = Number(m[1]);
    if (pri > 191) return fail('pri-out-of-range', 'pri');
    let pos = m[0].length;

    /* VERSION = NONZERO-DIGIT 1*DIGIT, followed by SP (or EOS). */
    m = /^(\d+)( |$)/.exec(text.slice(pos));
    if (!m) return fail('invalid-version', 'version');
    const versionText = m[1];
    if (versionText.length > 1 && versionText[0] === '0') {
        return fail('invalid-version', 'version');
    }
    if (Number(versionText) < 1) return fail('invalid-version', 'version');
    const version = Number(versionText);
    pos += versionText.length;
    if (text[pos] === ' ') pos += 1;

    /* HEADER fields: TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP */
    const timestampField = readHeaderField(text, pos, 'timestamp', MAX_LEN.timestamp);
    if (!timestampField.ok) return timestampField;
    if (timestampField.value !== NILVALUE &&
        !isValidTimestamp(timestampField.value)) {
        return fail('invalid-timestamp', 'timestamp');
    }
    pos = timestampField.next;

    const fields = {};
    /* Error codes use RFC 5424 field names (APP-NAME -> 'app-name'); the
     * result keys stay camelCase. */
    const fieldSpecs = [
        ['hostname', MAX_LEN.hostname, 'hostname'],
        ['appName', MAX_LEN.appName, 'app-name'],
        ['procid', MAX_LEN.procid, 'procid'],
        ['msgid', MAX_LEN.msgid, 'msgid'],
    ];
    for (const [name, maxLength, errorName] of fieldSpecs) {
        const field = readHeaderField(text, pos, errorName, maxLength);
        if (!field.ok) return field;
        fields[name] = field.value;
        pos = field.next;
    }

    /* STRUCTURED-DATA */
    const sd = parseStructuredData(text, pos);
    if (!sd.ok) return sd;
    pos = sd.next;

    /* Optional MSG: single SP separator, then any UTF-8 (incl. newlines). */
    let msg;
    if (pos < text.length) {
        if (text[pos] !== ' ') return fail('invalid-msg-separator', 'msg');
        msg = text.slice(pos + 1);
    }

    return {
        ok: true,
        pri,
        facility: Math.floor(pri / 8),
        severity: pri % 8,
        version,
        timestamp: timestampField.value,
        ...fields,
        structuredData: sd.value,
        sdElements: sd.elements,
        msg,
    };
}

module.exports = { parseSyslogDatagram };

/* ---------------------- CLI UDP receiver ---------------------- */

if (require.main === module) {
    const PORT = Number.parseInt(process.argv[2], 10) || 5514;
    const IDLE_MS = Number.parseInt(process.argv[3], 10) || 4000;
    const HARD_MS = 30000;

    let received = 0;
    let valid = 0;
    let invalid = 0;
    let idleTimer = null;

    const socket = dgram.createSocket('udp4');

    function finish(code, reason) {
        console.log(`--- summary: received=${received} valid=${valid} invalid=${invalid} (${reason}) ---`);
        try { socket.close(); } catch (_) { /* already closed */ }
        process.exit(code);
    }

    socket.on('error', error => {
        console.error(`bind failed on 127.0.0.1:${PORT}: ${error.message}`);
        process.exit(2);
    });

    socket.on('message', (buf, rinfo) => {
        received += 1;
        clearTimeout(idleTimer);
        idleTimer = setTimeout(() => finish(valid > 0 ? 0 : 1, 'idle'), IDLE_MS);

        const text = buf.toString('utf8');
        const parsed = parseSyslogDatagram(text);
        if (!parsed.ok) {
            invalid += 1;
            console.log(`[INVALID] from ${rinfo.address}:${rinfo.port} (${buf.length}B) ${parsed.where}: ${parsed.error}: ${text.slice(0, 200)}`);
            return;
        }
        valid += 1;
        console.log(`[OK] ${buf.length}B pri=${parsed.pri} (facility=${parsed.facility} sev=${parsed.severity}) ts=${parsed.timestamp} host=${parsed.hostname} app=${parsed.appName} msgid=${parsed.msgid}`);
        if (parsed.sdElements.length) {
            console.log(`     sd: ${parsed.sdElements.map(el => `${el.sdId}(${el.params.map(p => `${p.name}=${p.value}`).join(', ')})`).join(' ')}`);
        }
        if (parsed.msg !== undefined) {
            console.log(`     msg: ${parsed.msg.slice(0, 300)}`);
        }
    });

    socket.bind(PORT, '127.0.0.1', () => {
        console.log(`syslog_verify_receiver listening on udp://127.0.0.1:${PORT} (idle exit ${IDLE_MS}ms)`);
        idleTimer = setTimeout(() => finish(valid > 0 ? 0 : 1, 'no traffic'), IDLE_MS * 3);
        setTimeout(() => finish(valid > 0 ? 0 : 1, 'hard timeout'), HARD_MS);
    });
}
