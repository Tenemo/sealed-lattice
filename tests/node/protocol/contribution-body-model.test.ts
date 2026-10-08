import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
    compileContributionBodyCensus,
    contributionBodyHashPrefix,
} from '#tests/contribution-body-model.js';
import { completionProfile } from '#tests/supported-profile-model.js';

describe('complete clear contribution body encoding', () => {
    it('frames one ordinary body identity without an independent whole-body salt', () => {
        for (const length of [0, 1, 76, 1024, 65536]) {
            const body = Buffer.alloc(length, 17);
            const prefix = contributionBodyHashPrefix(length);
            expect(prefix.subarray(0, 8)).toEqual(
                Buffer.from([1, 0, 1, 0, 2, 0, 0, 0]),
            );
            const domainLength = prefix.readUInt32LE(14);
            expect(
                prefix.subarray(18, 18 + domainLength).toString('ascii'),
            ).toBe('sealed-lattice/contribution-body/v1');
            expect(prefix.readUInt32LE(prefix.length - 8)).toBe(length + 4);
            expect(prefix.readUInt32LE(prefix.length - 4)).toBe(length);
            const whole = createHash('shake256', { outputLength: 64 })
                .update(prefix)
                .update(body)
                .digest();
            const streamed = createHash('shake256', {
                outputLength: 64,
            }).update(prefix);
            for (let offset = 0; offset < body.length; offset += 17)
                streamed.update(body.subarray(offset, offset + 17));
            expect(streamed.digest()).toEqual(whole);
            expect(BigInt(prefix.length)).toBe(
                compileContributionBodyCensus(completionProfile())
                    .hashPrefixBytes,
            );
        }
        for (const length of [-1, 1.5, Infinity, 0xffff_fffc])
            expect(() => contributionBodyHashPrefix(length)).toThrow('length');
    });

    it('carries only the FHE and encrypted-share polynomials and preserves the SCB2 source opening', () => {
        const value = compileContributionBodyCensus(completionProfile());
        const excluded = new Set([
            42,
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
            Array.from({ length: 73 }, (_, index) => index).filter(
                (index) => !excluded.has(index),
            ),
        );
        const headerBytes = 4n + 8n + 64n;
        const payloadBytes = 24n * 65536n * 109n + 20n * 65536n * 21n;
        const prefixBytes = 8n + 2n * 6n + 4n + 35n + 4n;
        // The full word proof's header is its shortest encoding.
        const minimumProofBytes = 4004n;
        expect(value.headerBytes).toBe(headerBytes);
        expect(value.sourceOpeningSaltBytes).toBe(64n);
        expect(value.polynomialPayloadBytes).toBe(payloadBytes);
        expect(value.minimumProofBytes).toBe(minimumProofBytes);
        expect(value.maximumBodyBytes).toBe(
            headerBytes + payloadBytes + value.maximumProofBytes,
        );
        expect(value.maximumBodyBytes).toBeLessThan(256n * 1024n ** 2n);
        expect(value.hashPrefixBytes).toBe(prefixBytes);
        expect(value.minimumHashInputBytes).toBe(
            prefixBytes + headerBytes + payloadBytes + minimumProofBytes,
        );
        expect(value.maximumHashInputBytes).toBe(
            prefixBytes + headerBytes + payloadBytes + value.maximumProofBytes,
        );
        expect(value.maximumHashInputBytes).toBeLessThan(1n << 32n);
        expect(value.setupContributorCount).toBe(4);
        expect(value.eligibleContributorCount).toBe(7);
        expect(value.maximumSelectedContributionBodies).toBe(
            4n * value.maximumBodyBytes,
        );
        expect(value.maximumEligibleOfferBodies).toBe(
            7n * value.maximumBodyBytes,
        );
    });
});
