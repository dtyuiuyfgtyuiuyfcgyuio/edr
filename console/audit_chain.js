'use strict';

const crypto = require('crypto');
const fs = require('fs');
const fsPromises = require('node:fs/promises');
const { TextDecoder } = require('node:util');
const { setImmediate: yieldToLoop } = require('node:timers/promises');

const ZERO_HASH = '0'.repeat(64);
const appendState = new Map();

// Canonical helpers
// chain_seq: positive safe integer, starting at 1 for each chain
// chain_prev: hex 64 (previous chain_hash or zeros for genesis)
// chain_hash: hex 64 = SHA256( seq + "|" + prevHash + "|" + payloadHash )
// payloadHash = SHA256(canonicalPayloadJson)
// canonicalPayloadJson = JSON.stringify(payloadStable) where payloadStable is the record
//                        without chain_* fields, with keys sorted recursively for determinism.
// This exact form is documented and shared with the C++ writer.

function sha256Hex(text) {
    return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

function stableStringify(value) {
    if (value === null || typeof value !== 'object') return JSON.stringify(value);
    if (Array.isArray(value)) return '[' + value.map(stableStringify).join(',') + ']';
    const keys = Object.keys(value).sort();
    return '{' + keys.map(k => JSON.stringify(k) + ':' + stableStringify(value[k])).join(',') + '}';
}

function chainHashFor(seq, prevHash, payloadHash) {
    const canonical = `${seq}|${prevHash}|${payloadHash}`;
    return sha256Hex(canonical);
}

function payloadHashFor(recordWithoutChain) {
    return sha256Hex(stableStringify(recordWithoutChain));
}

function stripChainFields(obj) {
    // A parsed JSON object may contain an own "__proto__" key. Copying it to
    // a plain object changes that object's prototype and silently drops the
    // key from the canonical payload, leaving it outside the chain hash.
    const out = Object.create(null);
    for (const [k, v] of Object.entries(obj)) {
        if (k === 'chain_seq' || k === 'chain_prev' || k === 'chain_hash') continue;
        out[k] = v;
    }
    return out;
}

function hasChainFields(obj) {
    return obj.chain_seq !== undefined || obj.chain_prev !== undefined || obj.chain_hash !== undefined;
}

function isRecordObject(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isValidHex64(s) {
    return typeof s === 'string' && /^[0-9a-f]{64}$/.test(s);
}

/**
 * Verify a JSONL string or file.
 * @param {string} input - either file path (if options.isPath) or raw JSONL text, or array of lines
 * @param {object} options
 * @returns {{valid:boolean, brokenAt:number|null, total:number, legacyPrefix:number, issues:string[]}}
 */
function verifyChain(input, options = {}) {
    let text;
    if (options.isPath) {
        if (!fs.existsSync(input)) {
            return { valid: true, brokenAt: null, total: 0, legacyPrefix: 0, issues: [] };
        }
        text = fs.readFileSync(input, 'utf8');
    } else if (Array.isArray(input)) {
        text = input.join('\n');
    } else {
        text = input || '';
    }

    // A JSONL file must end each committed record with a newline. A torn
    // append can leave parseable JSON, which must not be reported as intact.
    const incompleteTail = options.isPath && text.length > 0 && !text.endsWith('\n');
    const rawLines = text.split('\n');
    // Filter out trailing empty after final newline but keep internal empties as skipped
    const lines = [];
    for (const l of rawLines) {
        if (l === '' || l === '\r') continue;
        // trim \r
        const trimmed = l.endsWith('\r') ? l.slice(0, -1) : l;
        if (trimmed === '') continue;
        lines.push(trimmed);
    }

    const total = lines.length;
    if (total === 0) {
        return { valid: true, brokenAt: null, total: 0, legacyPrefix: 0, issues: [] };
    }

    let legacyPrefix = 0;
    let seenChain = false;
    for (let i = 0; i < lines.length; i++) {
        let obj;
        try { obj = JSON.parse(lines[i]); } catch (_) { break; }
        if (!isRecordObject(obj)) break;
        if (hasChainFields(obj)) { seenChain = true; break; }
        legacyPrefix++;
    }
    // If no chain at all, it's all legacy -> valid
    if (!seenChain && legacyPrefix === total && !incompleteTail) {
        return { valid: true, brokenAt: null, total, legacyPrefix: total, issues: [] };
    }

    const issues = [];
    let valid = true;
    let brokenAt = null;
    let expectedSeq = null;
    let expectedPrev = null;
    const seenSeqs = new Set();

    for (let idx = 0; idx < lines.length; idx++) {
        const lineNum = idx + 1;
        const raw = lines[idx];
        let obj;
        try {
            obj = JSON.parse(raw);
        } catch (_) {
            issues.push(`line ${lineNum}: malformed JSON`);
            if (valid) { valid = false; brokenAt = lineNum; }
            continue;
        }

        if (!isRecordObject(obj)) {
            issues.push(`line ${lineNum}: audit record must be an object`);
            if (valid) { valid = false; brokenAt = lineNum; }
            continue;
        }

        const isLegacy = idx < legacyPrefix;
        if (isLegacy) {
            // Legacy lines accepted, not verified
            continue;
        }

        // From here on, chain fields required
        if (!hasChainFields(obj)) {
            issues.push(`line ${lineNum}: missing chain fields after chain start`);
            if (valid) { valid = false; brokenAt = lineNum; }
            continue;
        }

        const seq = obj.chain_seq;
        const prev = obj.chain_prev;
        const hash = obj.chain_hash;

        // Validate field formats
        if (!Number.isSafeInteger(seq) || seq < 1) {
            issues.push(`line ${lineNum}: invalid chain_seq`);
            if (valid) { valid = false; brokenAt = lineNum; }
            continue;
        }
        if (!isValidHex64(prev)) {
            issues.push(`line ${lineNum}: invalid chain_prev`);
            if (valid) { valid = false; brokenAt = lineNum; }
            continue;
        }
        if (!isValidHex64(hash)) {
            issues.push(`line ${lineNum}: invalid chain_hash`);
            if (valid) { valid = false; brokenAt = lineNum; }
            continue;
        }

        if (seenSeqs.has(seq)) {
            issues.push(`line ${lineNum}: duplicate chain_seq ${seq}`);
            if (valid) { valid = false; brokenAt = lineNum; }
        }
        seenSeqs.add(seq);

        // Expected seq / prev checks
        if (expectedSeq === null) {
            // A legacy prefix does not participate in the chain. The first
            // chained record must still be its genesis entry.
            if (seq !== 1) {
                issues.push(`line ${lineNum}: chain_seq must start at 1 (got ${seq}; prefix trim detected)`);
                if (valid) { valid = false; brokenAt = lineNum; }
            }
            if (prev !== ZERO_HASH) {
                issues.push(`line ${lineNum}: chain_prev mismatch (expected ${ZERO_HASH})`);
                if (valid) { valid = false; brokenAt = lineNum; }
            }
            expectedSeq = seq + 1;
            expectedPrev = hash;
        } else {
            if (seq !== expectedSeq) {
                issues.push(`line ${lineNum}: chain_seq jump expected ${expectedSeq} got ${seq} (reorder/trim detected)`);
                if (valid) { valid = false; brokenAt = lineNum; }
                // Do not update expectedSeq to avoid cascade; keep checking prev mismatch as well
            }
            if (prev !== expectedPrev) {
                issues.push(`line ${lineNum}: chain_prev mismatch expected ${expectedPrev} got ${prev} (tamper/reorder)`);
                if (valid) { valid = false; brokenAt = lineNum; }
            }
            // Update for next only if not already broken? Still advance to allow further detection
            // Use current hash as next prev regardless of validity to catch chained breaks
            expectedSeq = seq + 1;
            // If seq was wrong, expectedSeq already advanced from actual seq; that's fine for further detection
            expectedPrev = hash;
        }

        // Verify chain_hash correctness
        const payload = stripChainFields(obj);
        const pHash = payloadHashFor(payload);
        const expectedHash = chainHashFor(seq, prev, pHash);
        if (expectedHash !== hash) {
            issues.push(`line ${lineNum}: chain_hash mismatch (byte tamper detected)`);
            if (valid) { valid = false; brokenAt = lineNum; }
        }
    }

    if (incompleteTail) {
        issues.push(`line ${total}: incomplete tail (missing newline)`);
        if (valid) { valid = false; brokenAt = total; }
    }

    if (issues.length && brokenAt === null) brokenAt = 1;
    if (!issues.length) {
        valid = true;
        brokenAt = null;
    } else {
        valid = false;
        if (brokenAt === null) brokenAt = legacyPrefix + 1;
    }

    return { valid, brokenAt, total, legacyPrefix, issues };
}

function verifyFile(filePath) {
    return verifyChain(filePath, { isPath: true });
}

function sameSnapshotStat(left, right) {
    return left.dev === right.dev && left.ino === right.ino &&
        left.size === right.size && left.mtimeNs === right.mtimeNs &&
        left.ctimeNs === right.ctimeNs;
}

function positiveLimit(value, fallback) {
    return Number.isSafeInteger(value) && value > 0 ? value : fallback;
}

function emptyStreamResult(status, extra = {}) {
    return {
        valid: status === 'missing', status, brokenAt: null, total: 0,
        legacyPrefix: 0, issues: [], issueCount: 0, issuesTruncated: false,
        scannedBytes: 0, ...extra,
    };
}

/* Verify one descriptor snapshot without holding its contents in memory.
 * `onRecord` runs for every syntactically valid JSON value; callers must not
 * publish callback state unless this result confirms a complete snapshot. */
async function verifyFileStream(filePath, options = {}) {
    const maxFileBytes = positiveLimit(options.maxFileBytes, 256 * 1024 * 1024);
    const maxRecordBytes = positiveLimit(options.maxRecordBytes, 64 * 1024);
    const maxRecords = positiveLimit(options.maxRecords, 200000);
    const maxIssues = Number.isSafeInteger(options.maxIssues) && options.maxIssues >= 0
        ? options.maxIssues : 64;
    const yieldEveryRecords = positiveLimit(options.yieldEveryRecords, 256);
    const highWaterMark = positiveLimit(options.highWaterMark, 64 * 1024);

    let descriptor;
    let stream;
    let before;
    let scannedBytes = 0;
    let total = 0;
    let legacyPrefix = 0;
    let legacyOpen = true;
    let expectedSeq = null;
    let expectedPrev = null;
    let valid = true;
    let brokenAt = null;
    let issueCount = 0;
    let issuesTruncated = false;
    const issues = [];
    const seenSeqs = new Set();
    const decoder = new TextDecoder('utf-8', { fatal: true });

    const addIssue = (line, message) => {
        issueCount += 1;
        if (issues.length < maxIssues) issues.push(`line ${line}: ${message}`);
        else issuesTruncated = true;
        valid = false;
        if (brokenAt === null) brokenAt = line;
    };

    const checkChainedRecord = (value, line) => {
        if (!hasChainFields(value)) {
            addIssue(line, 'missing chain fields after chain start');
            return;
        }
        const seq = value.chain_seq;
        const prev = value.chain_prev;
        const hash = value.chain_hash;
        if (!Number.isSafeInteger(seq) || seq < 1) {
            addIssue(line, 'invalid chain_seq');
            return;
        }
        if (!isValidHex64(prev)) {
            addIssue(line, 'invalid chain_prev');
            return;
        }
        if (!isValidHex64(hash)) {
            addIssue(line, 'invalid chain_hash');
            return;
        }

        if (seenSeqs.has(seq)) addIssue(line, `duplicate chain_seq ${seq}`);
        seenSeqs.add(seq);
        if (expectedSeq === null) {
            if (seq !== 1)
                addIssue(line, `chain_seq must start at 1 (got ${seq}; prefix trim detected)`);
            if (prev !== ZERO_HASH)
                addIssue(line, `chain_prev mismatch (expected ${ZERO_HASH})`);
        } else {
            if (seq !== expectedSeq)
                addIssue(line, `chain_seq jump expected ${expectedSeq} got ${seq} (reorder/trim detected)`);
            if (prev !== expectedPrev)
                addIssue(line, `chain_prev mismatch expected ${expectedPrev} got ${prev} (tamper/reorder)`);
        }
        expectedSeq = seq + 1;
        expectedPrev = hash;

        const expectedHash = chainHashFor(seq, prev,
            payloadHashFor(stripChainFields(value)));
        if (expectedHash !== hash)
            addIssue(line, 'chain_hash mismatch (byte tamper detected)');
    };

    const consumeRecord = (parts, byteLength) => {
        let bytes = Buffer.concat(parts, byteLength);
        if (bytes.length && bytes[bytes.length - 1] === 0x0d)
            bytes = bytes.subarray(0, bytes.length - 1);
        if (!bytes.length) return { ok: true, countable: false };
        if (total >= maxRecords) {
            total += 1; /* observed the first record outside the verified window */
            return { ok: false, limit: 'record_count' };
        }

        total += 1;
        let value;
        try {
            value = JSON.parse(decoder.decode(bytes));
        } catch (error) {
            if (error instanceof TypeError)
                addIssue(total, 'invalid UTF-8');
            else
                addIssue(total, 'malformed JSON');
            legacyOpen = false;
            return { ok: true, countable: true };
        }

        if (!isRecordObject(value)) {
            addIssue(total, 'audit record must be an object');
            legacyOpen = false;
        } else if (legacyOpen && !hasChainFields(value)) {
            legacyPrefix += 1;
        } else {
            legacyOpen = false;
            checkChainedRecord(value, total);
        }

        if (typeof options.onRecord === 'function') options.onRecord(value, total);
        return { ok: true, countable: true };
    };

    try {
        descriptor = await fsPromises.open(filePath, 'r');
        before = await descriptor.stat({ bigint: true });
        if (!before.isFile())
            return emptyStreamResult('unreadable', { reason: 'not_a_file' });

        if (before.size > BigInt(maxFileBytes)) {
            const stable = await descriptor.stat({ bigint: true });
            const named = await fsPromises.stat(filePath, { bigint: true });
            if (!sameSnapshotStat(before, stable) || !sameSnapshotStat(before, named))
                return emptyStreamResult('unreadable', {
                    reason: 'snapshot_changed', fileBytes: Number(before.size),
                });
            return emptyStreamResult('limit_exceeded', {
                limit: 'file_bytes', fileBytes: Number(before.size),
            });
        }

        const fileBytes = Number(before.size);
        if (fileBytes > 0) {
            stream = descriptor.createReadStream({
                start: 0,
                end: fileBytes - 1,
                autoClose: false,
                highWaterMark,
            });
            let lineParts = [];
            let lineBytes = 0;
            let lastByte = null;
            let stopLimit = null;
            let sinceYield = 0;

            const addLineBytes = (buffer, start, end) => {
                const length = end - start;
                if (!length) return true;
                lineBytes += length;
                if (lineBytes > maxRecordBytes) {
                    stopLimit = 'record_bytes';
                    return false;
                }
                lineParts.push(buffer.subarray(start, end));
                return true;
            };

            for await (const chunk of stream) {
                scannedBytes += chunk.length;
                lastByte = chunk[chunk.length - 1];
                /* Drain the captured range after a parsing limit so the
                 * descriptor stays open for the final snapshot check. */
                if (stopLimit) continue;
                let start = 0;
                while (start < chunk.length) {
                    const newline = chunk.indexOf(0x0a, start);
                    const end = newline < 0 ? chunk.length : newline;
                    if (!addLineBytes(chunk, start, end)) break;
                    if (newline < 0) break;

                    const consumed = consumeRecord(lineParts, lineBytes);
                    lineParts = [];
                    lineBytes = 0;
                    if (!consumed.ok) {
                        stopLimit = consumed.limit;
                        break;
                    }
                    if (consumed.countable) {
                        sinceYield += 1;
                        if (sinceYield >= yieldEveryRecords) {
                            sinceYield = 0;
                            await yieldToLoop();
                        }
                    }
                    start = newline + 1;
                }
            }

            if (!stopLimit && lineBytes > 0) {
                if (lineBytes > maxRecordBytes) stopLimit = 'record_bytes';
                else {
                    const consumed = consumeRecord(lineParts, lineBytes);
                    if (!consumed.ok) stopLimit = consumed.limit;
                    else if (consumed.countable) {
                        sinceYield += 1;
                        if (sinceYield >= yieldEveryRecords) await yieldToLoop();
                    }
                }
            }

            if (stopLimit) {
                const after = await descriptor.stat({ bigint: true });
                const named = await fsPromises.stat(filePath, { bigint: true });
                if (!sameSnapshotStat(before, after) || !sameSnapshotStat(before, named))
                    return emptyStreamResult('unreadable', {
                        reason: 'snapshot_changed', scannedBytes, fileBytes,
                    });
                return emptyStreamResult('limit_exceeded', {
                    limit: stopLimit, total, legacyPrefix, scannedBytes, fileBytes,
                });
            }

            if (scannedBytes !== fileBytes) {
                return emptyStreamResult('unreadable', {
                    reason: 'snapshot_changed', scannedBytes, fileBytes,
                });
            }
            if (lastByte !== 0x0a)
                addIssue(total || 1, 'incomplete tail (missing newline)');
        }

        const after = await descriptor.stat({ bigint: true });
        const named = await fsPromises.stat(filePath, { bigint: true });
        if (!sameSnapshotStat(before, after) || !sameSnapshotStat(before, named))
            return emptyStreamResult('unreadable', {
                reason: 'snapshot_changed', scannedBytes, fileBytes: Number(before.size),
            });

        if (!valid) {
            return {
                valid: false, status: 'broken', brokenAt, total, legacyPrefix,
                issues, issueCount, issuesTruncated, scannedBytes,
                fileBytes: Number(before.size),
            };
        }
        const status = total > 0 && legacyPrefix === total ? 'legacy'
            : legacyPrefix > 0 ? 'mixed' : 'verified';
        return {
            valid: true, status, brokenAt: null, total, legacyPrefix,
            issues, issueCount, issuesTruncated, scannedBytes,
            fileBytes: Number(before.size),
        };
    } catch (error) {
        if (error.code === 'ENOENT' && descriptor === undefined)
            return emptyStreamResult('missing');
        if (error.code === 'ENOENT')
            return emptyStreamResult('unreadable', {
                reason: 'snapshot_changed', scannedBytes,
            });
        return emptyStreamResult('unreadable', {
            reason: error.code || 'read_failed', scannedBytes,
        });
    } finally {
        if (stream && !stream.destroyed) stream.destroy();
        if (descriptor) {
            try { await descriptor.close(); } catch (_) { /* already closed */ }
        }
    }
}

function lastRecord(filePath, size) {
    if (!size) return null;
    const descriptor = fs.openSync(filePath, 'r');
    try {
        const count = Math.min(size, 1024 * 1024);
        const buffer = Buffer.alloc(count);
        fs.readSync(descriptor, buffer, 0, count, size - count);
        if (buffer[count - 1] !== 0x0a) throw new Error('audit file has an incomplete tail');
        const end = count - 1;
        const previous = buffer.lastIndexOf(0x0a, end - 1);
        if (previous < 0 && size > count) throw new Error('audit tail record is too large');
        const line = buffer.subarray(previous + 1, end).toString('utf8').replace(/\r$/, '');
        return JSON.parse(line);
    } finally {
        fs.closeSync(descriptor);
    }
}

/* Console audit entries use the same chain format as the native ledger.
 * Recheck the file if another process changed it; malformed or broken files
 * fail closed instead of appending an apparently valid continuation. */
function appendChainedRecord(filePath, payload) {
    if (!isRecordObject(payload) || hasChainFields(payload))
        throw new Error('audit payload must be an object without chain fields');
    const normalized = JSON.parse(JSON.stringify(payload));
    if (!isRecordObject(normalized) || hasChainFields(normalized))
        throw new Error('audit payload must serialize to an object without chain fields');
    const resolved = require('path').resolve(filePath);
    const descriptor = fs.openSync(resolved, 'a+', 0o600);
    try {
        const stat = fs.fstatSync(descriptor, { bigint: true });
        const size = Number(stat.size);
        if (!Number.isSafeInteger(size)) throw new Error('audit file is too large');
        let state = appendState.get(resolved);
        if (!state || state.size !== size || state.mtimeNs !== stat.mtimeNs || state.ino !== stat.ino) {
            const verification = verifyFile(resolved);
            if (!verification.valid) {
                if (verification.issues.some(issue => issue.includes('incomplete tail')))
                    throw new Error('audit file has an incomplete tail');
                throw new Error(`audit chain is broken at line ${verification.brokenAt}`);
            }
            const tail = lastRecord(resolved, size);
            if (verification.legacyPrefix === verification.total) {
                state = { size, seq: 0, prev: ZERO_HASH };
            } else {
                if (!tail || !Number.isSafeInteger(tail.chain_seq) || !isValidHex64(tail.chain_hash))
                    throw new Error('audit chain tail is invalid');
                state = { size, seq: tail.chain_seq, prev: tail.chain_hash };
            }
        }
        if (!Number.isSafeInteger(state.seq + 1)) throw new Error('audit chain sequence exhausted');
        const seq = state.seq + 1;
        const hash = chainHashFor(seq, state.prev, payloadHashFor(normalized));
        const line = `${JSON.stringify({ ...normalized, chain_seq: seq, chain_prev: state.prev, chain_hash: hash })}\n`;
        fs.writeFileSync(descriptor, line, 'utf8');
        fs.fsyncSync(descriptor);
        const written = fs.fstatSync(descriptor, { bigint: true });
        appendState.set(resolved, { size: Number(written.size), mtimeNs: written.mtimeNs,
            ino: written.ino, seq, prev: hash });
    } finally {
        fs.closeSync(descriptor);
    }
}

module.exports = {
    verifyChain,
    verifyFile,
    verifyFileStream,
    appendChainedRecord,
    sha256Hex,
    stableStringify,
    chainHashFor,
    payloadHashFor,
    ZERO_HASH,
};
