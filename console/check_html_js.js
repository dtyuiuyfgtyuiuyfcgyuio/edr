/* Lexical sanity check for the inline <script> blocks of public/index.html.
 *
 * Deliberately contains no dynamic code execution (no eval / new Function /
 * vm compile APIs) and no child processes. A single-pass scanner walks each
 * block tracking strings, template literals (including ${...} nesting),
 * comments and regex literals, and verifies bracket balance on the way.
 * It cannot replace a full parser, but it never runs page code. */
const fs = require('fs');
const path = require('path');

const REGEX_ALLOWED_AFTER = /[(,;=:[!&|?{}<>+\-*%^~<>]$/;
const REGEX_KEYWORDS = new Set(['return', 'typeof', 'instanceof', 'in', 'of',
    'new', 'delete', 'void', 'do', 'else', 'yield', 'await', 'case', 'throw']);

function scanBlock(code) {
    const stack = [];
    let prevSig = '';
    let prevWord = '';
    let word = '';
    const n = code.length;
    let i = 0;
    const closeExpected = { ')': '(', ']': '[', '}': '{' };
    while (i < n) {
        const inTemplateText = stack.length && stack[stack.length - 1] === '`';
        const ch = code[i];
        const next = code[i + 1];
        if (inTemplateText) {
            if (ch === '\\') { i += 2; continue; }
            if (ch === '`') { stack.pop(); prevSig = '`'; i += 1; continue; }
            if (ch === '$' && next === '{') { stack.push('{'); prevSig = ''; i += 2; continue; }
            i += 1;
            continue;
        }
        if (ch === '/' && next === '/') {
            while (i < n && code[i] !== '\n') i += 1;
            continue;
        }
        if (ch === '/' && next === '*') {
            i += 2;
            while (i < n && !(code[i] === '*' && code[i + 1] === '/')) i += 1;
            if (i >= n) throw new Error('unterminated block comment');
            i += 2;
            continue;
        }
        if (ch === '"' || ch === "'") {
            i += 1;
            let closed = false;
            while (i < n) {
                if (code[i] === '\\') { i += 2; continue; }
                if (code[i] === ch) { closed = true; i += 1; break; }
                if (code[i] === '\n') throw new Error('unterminated string literal');
                i += 1;
            }
            if (!closed) throw new Error('unterminated string literal');
            prevSig = ch;
            word = '';
            continue;
        }
        if (ch === '`') {
            stack.push('`');
            i += 1;
            continue;
        }
        if (ch === '/') {
            const regexAllowed = prevSig === '' || REGEX_ALLOWED_AFTER.test(prevSig) ||
                REGEX_KEYWORDS.has(prevWord);
            if (regexAllowed) {
                i += 1;
                let inClass = false;
                let closed = false;
                while (i < n) {
                    const r = code[i];
                    if (r === '\\') { i += 2; continue; }
                    if (r === '\n') break;
                    if (r === '[') inClass = true;
                    else if (r === ']') inClass = false;
                    else if (r === '/' && !inClass) { closed = true; i += 1; break; }
                    i += 1;
                }
                if (!closed) throw new Error('unterminated regex literal');
                while (i < n && /[a-z]/i.test(code[i])) i += 1;
                prevSig = ')';
                word = '';
                continue;
            }
            prevSig = '/';
            word = '';
            i += 1;
            continue;
        }
        if (ch === '(' || ch === '[' || ch === '{') {
            stack.push(ch);
            prevSig = ch;
            word = '';
            i += 1;
            continue;
        }
        if (ch === ')' || ch === ']' || ch === '}') {
            const open = stack.pop();
            if (open !== closeExpected[ch]) throw new Error(`unbalanced '${ch}'`);
            prevSig = ch;
            word = '';
            i += 1;
            continue;
        }
        if (/[A-Za-z0-9_$]/.test(ch)) {
            word += ch;
            if (i + 1 >= n || !/[A-Za-z0-9_$]/.test(code[i + 1])) {
                prevWord = word;
                word = '';
            }
        } else {
            word = '';
        }
        if (!/\s/.test(ch)) prevSig = ch;
        i += 1;
    }
    if (stack.length) {
        const open = stack[stack.length - 1];
        throw new Error(open === '`' ? 'unterminated template literal' : `unclosed '${open}'`);
    }
}

function main() {
    const htmlPath = path.join(__dirname, 'public', 'index.html');
    const html = fs.readFileSync(htmlPath, 'utf8');
    const blocks = html.match(/<script>([\s\S]*?)<\/script>/g) || [];
    let checked = 0;
    let failed = 0;
    for (const block of blocks) {
        if (block.includes('chart')) continue; /* vendor lib */
        const code = block.replace(/<\/?script>/g, '');
        try {
            scanBlock(code);
            checked += 1;
        } catch (e) {
            console.error('JS ERROR:', e.message);
            failed += 1;
            process.exitCode = 1;
        }
    }
    console.log(`checked ${checked} inline script block(s)${failed ? `, ${failed} failed` : ''}`);
}

if (require.main === module) main();

module.exports = { scanBlock };
