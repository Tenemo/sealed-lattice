import { describe, expect, it } from 'vitest';

import {
    calculateCandidateContentIdentity,
    serializeCandidateJson,
} from '#tools/ci/build-padded-tally-candidate-package.js';

describe('padded-tally candidate package identity', () => {
    it('is independent of enumeration order and binds paths and bytes', () => {
        const left = { path: 'a.bin', bytes: Uint8Array.of(1, 2, 3) };
        const right = { path: 'nested/b.bin', bytes: Uint8Array.of(4, 5) };
        const identity = calculateCandidateContentIdentity([left, right]);

        expect(calculateCandidateContentIdentity([right, left])).toBe(identity);
        expect(identity).toMatch(/^[0-9a-f]{128}$/u);
        expect(
            calculateCandidateContentIdentity([
                left,
                { ...right, path: 'nested/c.bin' },
            ]),
        ).not.toBe(identity);
        expect(
            calculateCandidateContentIdentity([
                left,
                { ...right, bytes: Uint8Array.of(4, 6) },
            ]),
        ).not.toBe(identity);
        expect(() =>
            calculateCandidateContentIdentity([left, { ...left }]),
        ).toThrow('Candidate content repeats a.bin.');
    });

    it('serializes candidate metadata with recursively sorted keys', () => {
        expect(
            new TextDecoder().decode(
                serializeCandidateJson({
                    z: 1,
                    a: { y: 2, b: 3 },
                    values: [{ d: 4, c: 5 }],
                }),
            ),
        ).toBe(
            [
                '{',
                '  "a": {',
                '    "b": 3,',
                '    "y": 2',
                '  },',
                '  "values": [',
                '    {',
                '      "c": 5,',
                '      "d": 4',
                '    }',
                '  ],',
                '  "z": 1',
                '}',
                '',
            ].join('\n'),
        );
    });
});
