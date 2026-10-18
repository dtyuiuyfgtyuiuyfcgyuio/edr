/*
 * syslog_verify_receiver.test.js - unit tests for the RFC 5424 header
 * parser exported by scripts/syslog_verify_receiver.js.
 *
 * Covers the ABNF boundary cases from RFC 5424 section 6: PRI range and
 * leading zeros, VERSION grammar, NILVALUE usage, field length limits and
 * character sets, timestamp shape and ranges, STRUCTURED-DATA escapes,
 * and MSG separator/absence rules.
 *
 * Run:  node --test scripts/
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { parseSyslogDatagram } = require('./syslog_verify_receiver.js');

/* Shorthand: expect success and return the parsed result. */
function ok(text) {
    const parsed = parseSyslogDatagram(text);
    assert.equal(parsed.ok, true, `expected ok for: ${JSON.stringify(text)}`);
    return parsed;
}

/* Shorthand: expect failure with the given error code. */
function bad(text, error) {
    const parsed = parseSyslogDatagram(text);
    assert.equal(parsed.ok, false, `expected failure for: ${JSON.stringify(text)}`);
    assert.equal(parsed.error, error,
        `expected error '${error}', got '${parsed.error}'`);
    return parsed;
}

/* Fixed header used by most tests: version 1, NILVALUE timestamp. */
const H = '<134>1 - - - - - ';

test('accepts the exact datagram emitted by the C++ agent (regression)', () => {
    const line = '<130>1 2026-08-17T03:53:21.012Z DESKTOP-BO8VKN0 edr-agent - EDR-099 '
        + '[edr@47400 severity="critical"] '
        + '{"rule":"EDR-099","severity":"critical","mitre_attack":["T1498","T1499"],"mitre_tactic":["Impact"]}';
    const parsed = ok(line);
    assert.equal(parsed.pri, 130);
    assert.equal(parsed.facility, 16);
    assert.equal(parsed.severity, 2);
    assert.equal(parsed.version, 1);
    assert.equal(parsed.timestamp, '2026-08-17T03:53:21.012Z');
    assert.equal(parsed.hostname, 'DESKTOP-BO8VKN0');
    assert.equal(parsed.appName, 'edr-agent');
    assert.equal(parsed.procid, '-');
    assert.equal(parsed.msgid, 'EDR-099');
    assert.deepEqual(parsed.sdElements,
        [{ sdId: 'edr@47400', params: [{ name: 'severity', value: 'critical' }] }]);
    assert.ok(parsed.msg.startsWith('{"rule":"EDR-099"'));
    assert.ok(parsed.msg.includes('["T1498","T1499"]'));
});

test('MSG containing and ending with "]" is not swallowed into STRUCTURED-DATA', () => {
    /* The old single-regex parser mis-split this shape (greedy bracket). */
    const parsed = ok('<131>1 - h a - m [x k="v"] arr=[1,2]');
    assert.equal(parsed.sdElements.length, 1);
    assert.equal(parsed.sdElements[0].sdId, 'x');
    assert.equal(parsed.msg, 'arr=[1,2]');
});

test('accepts all-NILVALUE minimal message', () => {
    const parsed = ok('<0>1 - - - - - -');
    assert.equal(parsed.pri, 0);
    assert.equal(parsed.facility, 0);
    assert.equal(parsed.severity, 0);
    assert.equal(parsed.timestamp, '-');
    assert.equal(parsed.hostname, '-');
    assert.equal(parsed.appName, '-');
    assert.equal(parsed.procid, '-');
    assert.equal(parsed.msgid, '-');
    assert.equal(parsed.structuredData, '-');
    assert.deepEqual(parsed.sdElements, []);
    assert.equal(parsed.msg, undefined);
});

test('accepts SD NILVALUE with MSG', () => {
    const parsed = ok('<191>1 - - - - msgid - hello world');
    assert.equal(parsed.pri, 191);
    assert.equal(parsed.facility, 23);
    assert.equal(parsed.severity, 7);
    assert.equal(parsed.msgid, 'msgid');
    assert.equal(parsed.msg, 'hello world');
});

test('MSG is absent, empty, or space-prefixed at the boundary', () => {
    /* No MSG at all: text ends right after SD. */
    assert.equal(ok('<134>1 - - - - - -').msg, undefined);
    /* Trailing SP with nothing after: MSG present but empty. */
    assert.equal(ok('<134>1 - - - - - [a] ').msg, '');
    /* Double SP: the second space belongs to MSG per single-SP separator. */
    assert.equal(ok('<134>1 - - - - - [a]  x').msg, ' x');
});

test('MSG may contain newlines and multi-byte UTF-8', () => {
    const parsed = ok('<134>1 - - - - - [a] café 🚨 line1\nline2\ttab');
    assert.equal(parsed.msg, 'café 🚨 line1\nline2\ttab');
});

test('PRI boundaries: 0 and 191 are valid, 192+ rejected', () => {
    assert.equal(ok('<0>1 - - - - - -').pri, 0);
    assert.equal(ok('<191>1 - - - - - -').pri, 191);
    bad('<192>1 - - - - - -', 'pri-out-of-range');
    bad('<999>1 - - - - - -', 'pri-out-of-range');
});

test('PRI rejects leading zeros per RFC 5424', () => {
    bad('<007>1 - - - - - -', 'pri-leading-zero');
    bad('<01>1 - - - - - -', 'pri-leading-zero');
});

test('PRI structural errors', () => {
    bad('134>1 - - - - - -', 'missing-pri');      /* no '<' */
    bad('<134 1 - - - - - -', 'missing-pri');     /* no '>' */
    bad('<>1 - - - - - -', 'missing-pri');        /* empty */
    bad('<1000>1 - - - - - -', 'missing-pri');    /* 4 digits: no '>' after 3 */
    bad('', 'missing-pri');
    bad('   ', 'missing-pri');
});

test('VERSION grammar: NONZERO-DIGIT 1*DIGIT', () => {
    assert.equal(ok('<134>2 - - - - - -').version, 2);   /* future version ok */
    assert.equal(ok('<134>10 - - - - - -').version, 10);
    bad('<134>0 - - - - - -', 'invalid-version');        /* zero */
    bad('<134>01 - - - - - -', 'invalid-version');       /* leading zero */
    bad('<134> - - - - - -', 'invalid-version');         /* missing */
    bad('<134>x1 - - - - - -', 'invalid-version');       /* non-digit */
});

test('VERSION running to end of input reports missing-timestamp next', () => {
    bad('<134>1', 'missing-timestamp');
});

test('field values must be non-empty (no double spaces)', () => {
    bad('<134>1  - - - - - -', 'empty-timestamp');
    bad('<134>1 -  - - - - -', 'empty-hostname');
    bad('<134>1 - -  - - - -', 'empty-app-name');
    bad('<134>1 - - -  - - -', 'empty-procid');
    bad('<134>1 - - - -  - -', 'empty-msgid');
});

test('header fields missing at end of input', () => {
    /* Truncated headers fail on the last field whose SP separator is gone:
     * N tokens after VERSION = ts, host, app-name, procid, msgid. */
    bad('<134>1 - - - -', 'missing-procid');   /* 4 tokens: procid un-terminated */
    bad('<134>1 - - -', 'missing-app-name');   /* 3 tokens: app-name un-terminated */
    bad('<134>1 - -', 'missing-hostname');     /* 2 tokens: hostname un-terminated */
    bad('<134>1 -', 'missing-timestamp');      /* 1 token: timestamp un-terminated */
    bad('<134>1 - - - - -', 'missing-msgid');  /* 5 tokens: msgid un-terminated */
});

test('field length limits from the ABNF', () => {
    const host = 'h'.repeat(255);
    const app = 'a'.repeat(48);
    const procid = 'p'.repeat(128);
    const msgid = 'm'.repeat(32);
    const parsed = ok(`<134>1 - ${host} ${app} ${procid} ${msgid} - x`);
    assert.equal(parsed.hostname, host);
    assert.equal(parsed.appName, app);
    assert.equal(parsed.procid, procid);
    assert.equal(parsed.msgid, msgid);

    bad(`<134>1 - ${'h'.repeat(256)} a p m - x`, 'invalid-hostname');
    bad(`<134>1 - h ${'a'.repeat(49)} p m - x`, 'invalid-app-name');
    bad(`<134>1 - h a ${'p'.repeat(129)} m - x`, 'invalid-procid');
    bad(`<134>1 - h a p ${'m'.repeat(33)} - x`, 'invalid-msgid');
});

test('header fields must be printable US-ASCII without space/control', () => {
    bad('<134>1 - host\ttab a p m - x', 'invalid-hostname');
    bad('<134>1 - host\nnl a p m - x', 'invalid-hostname');
    bad('<134>1 - h app\x01ctl p m - x', 'invalid-app-name');
    bad('<134>1 - h a p m\x7f - x', 'invalid-msgid');
});

test('timestamp shape and calendar ranges', () => {
    assert.equal(ok('<134>1 2026-08-17T03:53:21Z - - - - -').timestamp,
        '2026-08-17T03:53:21Z');
    assert.equal(ok('<134>1 2026-08-17T03:53:21.123456+08:00 - - - - -').timestamp,
        '2026-08-17T03:53:21.123456+08:00');
    /* Leap second is allowed by the ABNF (second <= 60). */
    ok('<134>1 2016-12-31T23:59:60Z - - - - -');
    /* Boundary date. */
    ok('<134>1 2026-12-31T23:59:59.999Z - - - - -');

    bad('<134>1 notatime - - - - -', 'invalid-timestamp');
    bad('<134>1 2026-13-01T00:00:00Z - - - - -', 'invalid-timestamp');   /* month 13 */
    bad('<134>1 2026-01-32T00:00:00Z - - - - -', 'invalid-timestamp');   /* day 32 */
    bad('<134>1 2026-01-01T24:00:00Z - - - - -', 'invalid-timestamp');   /* hour 24 */
    bad('<134>1 2026-01-01T00:60:00Z - - - - -', 'invalid-timestamp');   /* minute 60 */
    bad('<134>1 2026-01-01T00:00:61Z - - - - -', 'invalid-timestamp');   /* second 61 */
    bad('<134>1 2026-01-01T00:00:00 - - - - -', 'invalid-timestamp');    /* no zone */
    bad('<134>1 2026/01/01T00:00:00Z - - - - -', 'invalid-timestamp');   /* separators */
});

test('multiple SD-ELEMENTs parse with raw text preserved', () => {
    const parsed = ok('<134>1 - h a p m [x k="1"][y n="2" o="3"] tail');
    assert.deepEqual(parsed.sdElements, [
        { sdId: 'x', params: [{ name: 'k', value: '1' }] },
        { sdId: 'y', params: [{ name: 'n', value: '2' }, { name: 'o', value: '3' }] },
    ]);
    assert.equal(parsed.structuredData, '[x k="1"][y n="2" o="3"]');
    assert.equal(parsed.msg, 'tail');
});

test('SD-PARAM escapes: only \\", \\\\ and \\] are legal', () => {
    const parsed = ok('<134>1 - h a p m [x q="say \\"hi\\"" b="c:\\\\d" c="a\\]b"] after');
    assert.deepEqual(parsed.sdElements[0].params, [
        { name: 'q', value: 'say "hi"' },
        { name: 'b', value: 'c:\\d' },
        { name: 'c', value: 'a]b' },
    ]);
    assert.equal(parsed.msg, 'after');

    bad('<134>1 - h a p m [x k="a\\q"] t', 'invalid-escape');
    bad('<134>1 - h a p m [x k="a\\n"] t', 'invalid-escape');
});

test('SD structural errors', () => {
    bad('<134>1 - h a p m [x k="1"', 'unterminated-sd-element');
    bad('<134>1 - h a p m [x k="1" j', 'missing-param-equals'); /* param name with no '=' */
    bad('<134>1 - h a p m [x k=1]', 'missing-param-quote');
    bad('<134>1 - h a p m [x k="1', 'unterminated-param-value');
    bad('<134>1 - h a p m [x k="a]b"] t', 'unescaped-close-bracket');
    bad('<134>1 - h a p m [x k="a\tb"] t', 'invalid-param-char');
    bad('<134>1 - h a p m [ k="1"] t', 'invalid-sd-id');
    bad('<134>1 - h a p m [x ="v"] t', 'invalid-param-name');
    bad('<134>1 - h a p m [x k"v"] t', 'missing-param-equals');
});

test('STRUCTURED-DATA position must hold NILVALUE or an element', () => {
    bad('<134>1 - h a p m junk', 'missing-structured-data');
    bad('<134>1 - h a p m [a]x', 'invalid-msg-separator'); /* no SP before MSG */
});

test('rejects non-string input', () => {
    bad(null, 'not-a-string');
    bad(undefined, 'not-a-string');
    bad(1341, 'not-a-string');
});

test('PRI decomposition covers every severity for facility 16 (local0)', () => {
    /* Matches SeverityToSyslog in user/syslog_forwarder.cpp. */
    const expected = { critical: 2, high: 3, medium: 4, low: 5, info: 6 };
    for (const [name, sev] of Object.entries(expected)) {
        const pri = 16 * 8 + sev;
        const parsed = ok(`<${pri}>1 - - - - - -`);
        assert.equal(parsed.facility, 16, name);
        assert.equal(parsed.severity, sev, name);
    }
});
