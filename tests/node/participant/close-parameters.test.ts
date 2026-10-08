import { describe, expect, it } from 'vitest';

import { parseCloseParameters } from '#packages/sdk/src/participant/worker/close.js';

describe('close parameters', () => {
    it('carry the close time a request supplies', () => {
        expect(parseCloseParameters({})).toEqual({});
        expect(parseCloseParameters({ closeTime: 0 })).toEqual({
            closeTime: 0n,
        });
        expect(parseCloseParameters({ closeTime: 1_700_000_000_000 })).toEqual({
            closeTime: 1_700_000_000_000n,
        });
        expect(
            parseCloseParameters({ closeTime: Number.MAX_SAFE_INTEGER }),
        ).toEqual({ closeTime: BigInt(Number.MAX_SAFE_INTEGER) });
    });

    it('refuse malformed close times', () => {
        for (const parameters of [
            { closeTime: -1 },
            { closeTime: 1.5 },
            { closeTime: Number.NaN },
            { closeTime: null },
            { closeTime: '1700000000000' },
            { closeTime: Number.MAX_SAFE_INTEGER + 1 },
        ])
            expect(parseCloseParameters(parameters)).toBeUndefined();
    });
});
