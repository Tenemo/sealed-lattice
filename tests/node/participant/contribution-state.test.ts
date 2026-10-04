import { describe, expect, it } from 'vitest';

import { bodyHeader } from '#packages/sdk/src/participant/worker/contribution-proof.js';
import {
    decodeContributionState,
    encodeContributionState,
} from '#packages/sdk/src/participant/worker/contribution.js';
import type { ContributionState } from '#packages/sdk/src/participant/worker/contribution.js';
import { compileParticipantRuntimeProfile } from '#tests/participant-runtime-bounds-model.js';

const profile = compileParticipantRuntimeProfile(3, 2);
const bounds = profile.contribution;
const recordBytes = 1_048_576;
const proofObject = bounds.expandedPolynomials + 1;
const slots = Array.from(
    { length: Math.ceil(bounds.maximumProofBytes / recordBytes) },
    (_unused, index) => ({
        object: proofObject,
        offset: index * recordBytes,
        length: Math.min(
            recordBytes,
            bounds.maximumProofBytes - index * recordBytes,
        ),
    }),
);
const record = (
    location: Readonly<{ object: number; offset: number; length: number }>,
    index: number,
) => {
    const key = new Uint8Array(32);
    new DataView(key.buffer).setUint32(0, index + 1, true);
    return { ...location, key, hash: new Uint8Array(64).fill(index % 251) };
};
// These synthetic references exercise the private codec, not any public
// proof or participant capability. The slot oracle comes from the independent
// runtime model and the record format's fixed one-mebibyte width.
const completed = (length: number, generation = 7): ContributionState => {
    const signingLengths = [
        bounds.confirmationBodyBytes,
        profile.registration.signatureBytes,
        profile.root.setupInventoryBytes,
        bounds.openingBodyBytes,
        profile.registration.signatureBytes,
    ];
    const signingCount =
        generation === 7
            ? 0
            : generation === 8
              ? 1
              : generation === 9
                ? 2
                : generation === 10
                  ? 4
                  : 5;
    return {
        position: 0,
        salt: new Uint8Array(bounds.saltBytes),
        header: bodyHeader(bounds, length),
        publicRecords: [...bounds.publicRecords, ...slots].map(record),
        privateRecords: [],
        signingRecords: signingLengths
            .slice(0, signingCount)
            .map((bytes, index) =>
                record(
                    {
                        object: proofObject + 1 + index,
                        offset: 0,
                        length: bytes,
                    },
                    bounds.publicRecords.length + slots.length + index,
                ),
            ),
        seed: new Uint8Array(),
        coins: new Uint8Array(generation === 8 || generation === 10 ? 32 : 0),
    };
};

describe('contribution state framing', () => {
    it('retains one fixed-width SCB1 length and the same completed slot inventory', () => {
        for (const generation of [7, 8, 9, 10, 11, 12, 29]) {
            let encodedLength: number | undefined;
            for (const length of [
                bounds.minimumProofBytes,
                recordBytes - 1,
                recordBytes,
                recordBytes + 1,
                bounds.maximumProofBytes,
            ]) {
                const state = completed(length, generation);
                const encoded = encodeContributionState(state, profile);
                expect(new TextDecoder().decode(encoded.subarray(0, 4))).toBe(
                    'PCS3',
                );
                const decoded = decodeContributionState(
                    encoded,
                    generation,
                    profile,
                );
                expect(decoded).toEqual(state);
                expect(decoded.header.length).toBe(12);
                expect(
                    new DataView(decoded.header.buffer).getBigUint64(4, true),
                ).toBe(BigInt(length));
                expect(
                    decoded.publicRecords
                        .slice(bounds.publicRecords.length)
                        .map(({ object, offset, length: bytes }) => ({
                            object,
                            offset,
                            length: bytes,
                        })),
                ).toEqual(slots);
                encodedLength ??= encoded.length;
                expect(encoded.length).toBe(encodedLength);
                expect(encoded.length).toBeLessThanOrEqual(
                    bounds.maximumStateBytes,
                );
            }
        }
    });

    it('refuses missing, extra, shortened and displaced planned proof records', () => {
        const state = completed(bounds.minimumProofBytes);
        const last = state.publicRecords.length - 1;
        for (const records of [
            state.publicRecords.slice(0, last),
            [...state.publicRecords, state.publicRecords[last]],
            state.publicRecords.map((value, index) =>
                index === last ? { ...value, length: value.length - 1 } : value,
            ),
            state.publicRecords.map((value, index) =>
                index === last ? { ...value, offset: value.offset + 1 } : value,
            ),
        ])
            expect(() =>
                decodeContributionState(
                    encodeContributionState(
                        { ...state, publicRecords: records },
                        profile,
                    ),
                    7,
                    profile,
                ),
            ).toThrow();
    });

    it('refuses malformed body framing and any original variable-size format', () => {
        const state = completed(bounds.minimumProofBytes);
        for (const header of [
            new Uint8Array(),
            new Uint8Array(12),
            ...[
                BigInt(bounds.minimumProofBytes - 1),
                BigInt(bounds.maximumProofBytes + 1),
                (1n << 64n) - 1n,
            ].map((length) => {
                const value = state.header.slice();
                new DataView(value.buffer).setBigUint64(4, length, true);
                return value;
            }),
        ])
            expect(() =>
                decodeContributionState(
                    encodeContributionState({ ...state, header }, profile),
                    7,
                    profile,
                ),
            ).toThrow();
        const previous = encodeContributionState(state, profile);
        previous[3] = '2'.charCodeAt(0);
        expect(() => decodeContributionState(previous, 7, profile)).toThrow();
    });
});
