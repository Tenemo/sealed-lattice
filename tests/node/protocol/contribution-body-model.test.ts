import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
    compileContributionBodyCensus,
    contributionBodyHashPrefix,
} from '#tests/contribution-body-model.js';
import {
    ascii,
    item,
    itemType,
    tuple,
    variable,
} from '#tests/node/protocol/reference/canonical-tuple.js';
import { completionProfile } from '#tests/supported-profile-model.js';

describe('complete contribution body encoding', () => {
    it('frames one ordinary body identity without an independent whole-body salt', () => {
        for (const length of [0, 1, 76, 1024, 65536]) {
            const body = Buffer.alloc(length, 17);
            const prefix = contributionBodyHashPrefix(length);
            expect(Buffer.concat([prefix, body])).toEqual(
                tuple([
                    ascii('sealed-lattice/contribution-body'),
                    item(itemType.rawBytes, variable(body)),
                ]),
            );
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

    it('carries only the FHE and encrypted-share polynomials and preserves the header source opening', () => {
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
        const headerBytes = 8n + 64n;
        const payloadBytes = 24n * 65536n * 109n + 20n * 65536n * 21n;
        const prefixBytes = 6n + 2n * 6n + 4n + 32n + 4n;
        // The full word proof's header is its shortest encoding.
        const minimumProofBytes = 3936n;
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
