import { describe, expect, it } from 'vitest';

import {
    compileContributionBodyCensus,
    contributionSenderPrefix,
    matchesContributionSenderPrefix,
    contributionSaltPrefix,
} from '#tests/contribution-body-model.js';
import { completionProfile } from '#tests/supported-profile-model.js';

describe('complete contribution body encoding', () => {
    it('masks the complete sender and salt slice without selecting a body suffix', () => {
        const key = new Uint8Array(1952),
            salt = Uint8Array.from({ length: 64 }, (_, index) => index),
            sender = contributionSenderPrefix(key),
            prefix = contributionSaltPrefix(key, salt);
        expect(prefix.subarray(0, sender.length)).toEqual(sender);
        expect(prefix.subarray(sender.length, sender.length + 6)).toEqual(
            Buffer.from([1, 0, 64, 0, 0, 0]),
        );
        expect(prefix.subarray(sender.length + 6)).toEqual(Buffer.from(salt));
        expect(BigInt(prefix.length)).toBe(
            compileContributionBodyCensus(completionProfile())
                .senderSaltPrefixBytes,
        );
        expect(() => contributionSaltPrefix(key, salt.subarray(1))).toThrow(
            'salt length',
        );
    });
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
        const value = compileContributionBodyCensus(completionProfile());
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
    it('frames the complete owner-bound role in the body commitment input', () => {
        const value = compileContributionBodyCensus(completionProfile());
        const roleBytes =
            8n + 6n * 6n + (4n + 36n) + (4n + 128n) + 3n * 64n + 2n;
        const prefix =
            8n + 5n * 6n + 4n + 34n + 1952n + 64n + 4n + roleBytes + 4n;
        expect(value.hashPrefixBytes).toBe(prefix);
        expect(value.maximumHashInputBytes).toBe(
            prefix + value.maximumBodyBytes,
        );
        expect(value.minimumHashInputBytes).toBe(
            prefix +
                value.headerBytes +
                value.polynomialPayloadBytes +
                value.minimumProofBytes,
        );
        // The sender/salt prefix precedes the role and keeps its own grammar.
        expect(value.senderSaltPrefixBytes).toBe(
            BigInt(
                contributionSaltPrefix(new Uint8Array(1952), new Uint8Array(64))
                    .length,
            ),
        );
    });
});
