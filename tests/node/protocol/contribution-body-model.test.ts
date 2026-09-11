import { describe, expect, it } from 'vitest';

import {
    compileContributionBodyCensus,
    contributionSenderPrefix,
    matchesContributionSenderPrefix,
} from '#tests/contribution-body-model.js';

describe('complete contribution body encoding', () => {
    it('matches the canonical domain and original key without granting body validity', () => {
        const key = Uint8Array.from(
                { length: 1952 },
                (_, index) => index % 251,
            ),
            label = contributionSenderPrefix(key);
        expect(label.subarray(0, 18)).toEqual(
            Buffer.from([
                1, 0, 1, 0, 5, 0, 0, 0, 2, 0, 38, 0, 0, 0, 34, 0, 0, 0,
            ]),
        );
        expect(label.subarray(18, 52).toString('ascii')).toBe(
            'sealed-lattice/setup-commitment/v1',
        );
        expect(label.subarray(52, 58)).toEqual(
            Buffer.from([1, 0, 160, 7, 0, 0]),
        );
        expect(label.subarray(58)).toEqual(Buffer.from(key));
        // Even the bare label passes this extraction predicate. It is not a
        // body, a contribution proof, or a public verification capability.
        expect(matchesContributionSenderPrefix(label, key)).toBe(true);
        expect(
            matchesContributionSenderPrefix(
                Buffer.concat([label, Buffer.from([255])]),
                key,
            ),
        ).toBe(true);
        expect(
            matchesContributionSenderPrefix(
                label.subarray(0, label.length - 1),
                key,
            ),
        ).toBe(false);
        for (const offset of [
            0,
            4,
            8,
            10,
            14,
            18,
            52,
            54,
            58,
            label.length - 1,
        ]) {
            const changed = label.slice();
            changed[offset] ^= 1;
            expect(matchesContributionSenderPrefix(changed, key)).toBe(false);
        }
        const other = key.slice();
        other[100] ^= 1;
        expect(matchesContributionSenderPrefix(label, other)).toBe(false);
        expect(() => contributionSenderPrefix(key.subarray(1))).toThrow(
            'key length',
        );
    });
    it('omits only fixed common polynomials and previously verified recipient keys', () => {
        const value = compileContributionBodyCensus();
        const excluded = new Set([
            42,
            73,
            ...Array.from({ length: 6 }, (_, gadget) => [
                7 * gadget,
                7 * gadget + 3,
                7 * gadget + 5,
            ]).flat(),
            ...Array.from({ length: 10 }, (_, recipient) => 43 + 3 * recipient),
        ]);
        expect(
            value.polynomials.map((polynomial) => polynomial.expandedIndex),
        ).toEqual(
            Array.from({ length: 75 }, (_, index) => index).filter(
                (index) => !excluded.has(index),
            ),
        );
        expect(value.polynomialPayloadBytes).toBe(198_991_872n);
        expect(value.maximumBodyBytes).toBeLessThan(256n * 1024n ** 2n);
        expect(value.maximumHashInputBytes).toBeLessThan(1n << 32n);
        expect(value.hashPrefixBytes).toBeLessThan(4096n);
        expect(value.minimumHashInputBytes).toBeLessThan(
            value.maximumHashInputBytes,
        );
        expect(value.minimumHashInputEnclosingBitExponent).toBe(
            value.maximumHashInputEnclosingBitExponent,
        );
        const upper = 1n << value.maximumHashInputEnclosingBitExponent;
        expect(8n * value.minimumHashInputBytes).toBeGreaterThan(upper / 2n);
        expect(8n * value.maximumHashInputBytes).toBeLessThanOrEqual(upper);
        expect(value.senderPrefixBytes).toBe(
            BigInt(contributionSenderPrefix(new Uint8Array(1952)).length),
        );
    });
});
