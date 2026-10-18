'use strict';

class LedgerQueryBusyError extends Error {
    constructor() {
        super('ledger query capacity is busy');
        this.code = 'ledger_query_busy';
    }
}

/* Per-runtime admission only: no queue, result cache, or shared promises. */
function createQueryGate() {
    let active = 0;
    return {
        async run(operation) {
            if (active >= 2) throw new LedgerQueryBusyError();
            active += 1;
            try {
                return await operation();
            } finally {
                active -= 1;
            }
        },
    };
}

module.exports = { createQueryGate, LedgerQueryBusyError };
