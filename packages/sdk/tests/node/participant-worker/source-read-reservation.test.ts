import { describe, expect, it, vi } from 'vitest';

import type { PublicProfileContext } from '#packages/sdk/src/participant/worker/module/context.js';
import {
    fullOfferReadBytes,
    setupDownloadFits,
} from '#packages/sdk/src/participant/worker/stages/setup/setup-collection.js';

const downloaded = vi.hoisted(() => ({ bytes: 0 }));
vi.mock(
    '#packages/sdk/src/participant/worker/relay/relay.js',
    async (original) => ({
        ...(await original<
            typeof import('#packages/sdk/src/participant/worker/relay/relay.js')
        >()),
        relayDownloadedBytes: () => downloaded.bytes,
    }),
);
const chunkBytes = 1_048_576;
const context = (sourceCiphertextBytes: number) =>
    ({
        profile: {
            registration: { signatureBytes: 8642 },
            contribution: {
                polynomials: [{ bytes: 301 }, { bytes: 479 }],
                maximumProofBytes: 37,
                bodyHeaderBytes: 8,
                offerEnvelopeBytes: 99,
                sourceCiphertextBytes,
            },
        },
    }) as unknown as PublicProfileContext;
const otherReads = 301 + 479 + 37 + chunkBytes + 8 + 99 + 8642 + 2 * chunkBytes;

describe('source-range download reservation', () => {
    it.each([0, -1, Number.NaN, Number.POSITIVE_INFINITY, 1.5])(
        'refuses a malformed native source length %s',
        (bytes) => {
            expect(() => fullOfferReadBytes(context(bytes))).toThrow(
                'The source family has no canonical length.',
            );
        },
    );
    it.each([
        [1, 1],
        [chunkBytes / 2, 1],
        [chunkBytes - 1, 2],
        [chunkBytes, 1],
        [chunkBytes + 1, 2],
        [1_572_864, 2],
        [2 * chunkBytes - 1, 3],
        [2 * chunkBytes, 2],
        [2 * chunkBytes + 1, 3],
    ])(
        'reserves all complete transport chunks for a %s-byte source family',
        (bytes, chunks) => {
            expect(fullOfferReadBytes(context(bytes))).toBe(
                otherReads + chunks * chunkBytes,
            );
        },
    );

    it('charges the current source family before admitting a complete offer at the call budget', () => {
        // Four ciphertext polynomials, each with 65536 six-byte coefficients.
        // The complete source operand list also carries four common polynomials.
        const sourceBytes = 4 * 65_536 * 6;
        const required = fullOfferReadBytes(context(sourceBytes));
        const budget = (2 ** 31 * 15) / 16;
        downloaded.bytes = budget - otherReads;
        expect(setupDownloadFits(required)).toBe(false);
        downloaded.bytes = budget - required;
        expect(setupDownloadFits(required)).toBe(true);
        downloaded.bytes++;
        expect(setupDownloadFits(required)).toBe(false);
    });
});
