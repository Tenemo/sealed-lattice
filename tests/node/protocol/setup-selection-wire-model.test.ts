import { describe, expect, it } from 'vitest';

import {
    compileSetupSelectionWireCensus,
    encodeSetupCertificateModel,
    encodeSetupSelectionModel,
    setupSelectionIdentityModel,
} from '#tests/setup-selection-wire-model.js';

// FIPS 204 Table 2: an ML-DSA-65 signature has 3309 bytes.
const signatureBytes = 3309;
const roster = 'a2'.repeat(64);
const selected = (count: number) =>
    Array.from({ length: count }, (_, position) => ({
        position,
        bodyIdentity: (position + 1).toString(16).padStart(2, '0').repeat(64),
    }));
describe('clear setup wire census and semantic identity', () => {
    it.each([3, 4, 10, 20])(
        'counts canonical selection and exact certificate carriers at n=%i',
        (participants) => {
            const census = compileSetupSelectionWireCensus(participants);
            const entries = selected(census.selectedCount);
            const body = encodeSetupSelectionModel(
                participants,
                roster,
                entries,
            );
            expect(BigInt(body.length)).toBe(census.selectionBodyBytes);
            const signature = Buffer.alloc(signatureBytes, 17);
            const endorsements = Array.from(
                { length: census.quorum },
                (_, position) => ({ position, signature }),
            );
            const carrier = encodeSetupCertificateModel(
                participants,
                roster,
                entries,
                signature,
                endorsements,
            );
            expect(carrier.subarray(0, 4).toString('ascii')).toBe('SSC1');
            expect(carrier.readUInt32LE(4)).toBe(body.length);
            expect(carrier.subarray(8, 8 + body.length)).toEqual(body);
            expect(BigInt(carrier.length)).toBe(census.certificateBytes);
            expect(carrier.length).toBe(
                4 +
                    4 +
                    body.length +
                    signatureBytes +
                    census.quorum * (2 + signatureBytes),
            );
            expect(census.endorsementPacketBytes).toBe(
                2n + 64n + BigInt(signatureBytes),
            );
            expect(census.offerPacketBytes).toBe(
                4n + census.offerEnvelopeBytes + BigInt(signatureBytes),
            );
            expect(census.signedSelectionPacketBytes).toBe(
                4n + BigInt(body.length) + BigInt(signatureBytes),
            );
        },
    );
    it('keeps the setup identity independent of valid quorum subsets and signature bytes', () => {
        const entries = selected(2);
        const carriers = [
            [0, 1, 2],
            [1, 2, 3],
        ].map((positions, variant) =>
            encodeSetupCertificateModel(
                4,
                roster,
                entries,
                Buffer.alloc(signatureBytes, variant),
                positions.map((position) => ({
                    position,
                    signature: Buffer.alloc(signatureBytes, position + variant),
                })),
            ),
        );
        expect(carriers[0]).not.toEqual(carriers[1]);
        const bodyLength = carriers[0].readUInt32LE(4);
        expect(carriers[0].subarray(8, 8 + bodyLength)).toEqual(
            carriers[1].subarray(8, 8 + bodyLength),
        );
        const identity = setupSelectionIdentityModel(4, roster, entries);
        expect(identity).not.toBe(
            setupSelectionIdentityModel(4, 'a3'.repeat(64), entries),
        );
        expect(identity).not.toBe(
            setupSelectionIdentityModel(4, roster, [
                entries[0],
                { ...entries[1], bodyIdentity: 'ff'.repeat(64) },
            ]),
        );
    });
    it('refuses duplicate, unsorted, missing, out-of-range or overcomplete inventories', () => {
        const entries = selected(2);
        for (const bad of [
            [entries[0]],
            [entries[0], entries[0]],
            [...entries].reverse(),
            [entries[0], { ...entries[1], position: 3 }],
        ])
            expect(() => encodeSetupSelectionModel(4, roster, bad)).toThrow(
                'inventory',
            );
        const signature = Buffer.alloc(signatureBytes);
        for (const positions of [
            [0, 1],
            [0, 1, 1],
            [1, 0, 2],
            [0, 1, 4],
            [0, 1, 2, 3],
        ])
            expect(() =>
                encodeSetupCertificateModel(
                    4,
                    roster,
                    entries,
                    signature,
                    positions.map((position) => ({ position, signature })),
                ),
            ).toThrow('carrier');
        expect(() =>
            encodeSetupCertificateModel(
                4,
                roster,
                entries,
                signature.subarray(1),
                [0, 1, 2].map((position) => ({ position, signature })),
            ),
        ).toThrow('carrier');
    });
});
