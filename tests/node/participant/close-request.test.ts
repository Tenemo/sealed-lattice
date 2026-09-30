import { describe, expect, it } from 'vitest';

import { parseCloseRequest } from '#packages/sdk/src/participant/worker/close.js';
import { compileParticipantRuntimeProfile } from '#tests/participant-runtime-bounds-model.js';

const smallest = compileParticipantRuntimeProfile(3, 2);
const completion = compileParticipantRuntimeProfile(10, 10);

describe('close requests', () => {
    it('collect every other roster position when they name no ballots', () => {
        expect(parseCloseRequest(smallest, 0, {})).toEqual({
            deliver: [1, 2],
            announce: [],
        });
        expect(parseCloseRequest(completion, 4, {})).toEqual({
            deliver: [0, 1, 2, 3, 5, 6, 7, 8, 9],
            announce: [],
        });
        expect(
            parseCloseRequest(completion, 9, { closeTime: 1_700_000_000_000 }),
        ).toEqual({
            deliver: [0, 1, 2, 3, 4, 5, 6, 7, 8],
            announce: [],
            closeTime: 1_700_000_000_000n,
        });
    });

    it('collect only the ballots a request names', () => {
        expect(parseCloseRequest(completion, 4, { deliver: [] })).toEqual({
            deliver: [],
            announce: [],
        });
        expect(parseCloseRequest(completion, 4, { announce: [7, 2] })).toEqual({
            deliver: [],
            announce: [7, 2],
        });
        expect(
            parseCloseRequest(completion, 4, { deliver: [9, 0], announce: [] }),
        ).toEqual({ deliver: [9, 0], announce: [] });
    });

    it('refuse malformed positions and close times', () => {
        for (const parameters of [
            { deliver: 'every' },
            { deliver: [1, 1] },
            { deliver: [3] },
            { deliver: [-1] },
            { deliver: [1.5] },
            { announce: null },
            { announce: [0, '1'] },
            { closeTime: -1 },
            { closeTime: 1.5 },
            { closeTime: '1700000000000' },
            { closeTime: Number.MAX_SAFE_INTEGER + 1 },
        ])
            expect(parseCloseRequest(smallest, 0, parameters)).toBeUndefined();
    });
});
