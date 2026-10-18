'use strict';

const path = require('path');

/* Resolve candidate under baseDir and refuse anything that escapes it.
 * Used by the console's ledger/evidence persistence so a caller that
 * forwards request-controlled strings can never point file I/O outside
 * the intended base directory. */
function resolveWithinBase(baseDir, candidate) {
    const base = path.resolve(baseDir);
    const target = path.resolve(base, candidate);
    const relative = path.relative(base, target);
    if (!relative || relative === '..' || relative.startsWith('..' + path.sep) || path.isAbsolute(relative)) {
        throw new Error('path escapes the base directory');
    }
    return target;
}

module.exports = { resolveWithinBase };
