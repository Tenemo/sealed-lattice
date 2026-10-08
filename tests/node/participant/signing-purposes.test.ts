import { describe, expect, it } from 'vitest';

import { unusedSigningPurposes } from '#packages/sdk/src/participant/worker/enrollment.js';
import { encodePreparationState } from '#packages/sdk/src/participant/worker/preparation-state.js';

// The unused-purpose mask at each generation a completed root can hold,
// written from the module's purpose positions (roster proposal 0, offer 1,
// selection proposal 2, selection endorsement 3, ballot 4, close intent 5,
// close response 6, close proposal 7, target 8, release 9) and the generation
// at which each signature completes.
const unusedByGeneration: Readonly<Record<number, number>> = {
    1: 0b11_1111_1111,
    2: 0b11_1111_1111,
    3: 0b11_1111_1110,
    12: 0b11_1111_0000,
    13: 0b11_1111_0000,
    14: 0b11_1111_0000,
    15: 0b11_1111_0000,
    17: 0b11_1110_0000,
    18: 0b11_1110_0000,
    19: 0b11_1100_0000,
    20: 0b11_1100_0000,
    21: 0b11_1000_0000,
    22: 0b11_0000_0000,
    23: 0b11_0000_0000,
    24: 0b10_0000_0000,
    25: 0b10_0000_0000,
    26: 0b10_0000_0000,
    27: 0b10_0000_0000,
    29: 0,
};
const signed = { body: new Uint8Array(4), signature: new Uint8Array(4) };

describe('restored signing purposes', () => {
    it('unlocks exactly the purposes whose signatures have not completed', () => {
        for (const [generation, expected] of Object.entries(unusedByGeneration))
            expect(unusedSigningPurposes(Number(generation), undefined)).toBe(
                expected,
            );
    });

    it('reads the preparation purposes from the preparation journal', () => {
        const later = 0b11_1111_0000;
        expect(unusedSigningPurposes(4, encodePreparationState({}))).toBe(
            later | 0b1110,
        );
        expect(
            unusedSigningPurposes(
                4,
                encodePreparationState({
                    selection: { stage: 'signed', ...signed },
                }),
            ),
        ).toBe(later | 0b1010);
        expect(
            unusedSigningPurposes(
                4,
                encodePreparationState({
                    selection: { stage: 'intent', body: signed.body },
                }),
            ),
        ).toBe(later | 0b1110);
    });

    it('refuses a preparation root without its journal', () => {
        expect(() => unusedSigningPurposes(4, undefined)).toThrow(
            'Missing preparation journal.',
        );
    });
});
