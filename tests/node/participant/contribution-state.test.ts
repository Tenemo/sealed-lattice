import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
    decodeContributionState,
    encodeContributionState,
} from '#packages/sdk/src/participant/worker/stages/contribution/contribution.js';
import type { ContributionState } from '#packages/sdk/src/participant/worker/stages/contribution/contribution.js';
import { compileParticipantRuntimeProfile } from '#tests/participant-runtime-bounds-model.js';

// The SHA-256 digest of stored bytes, which pins their exact format.
const storedDigest = (bytes: Uint8Array) =>
    createHash('sha256').update(bytes).digest('hex');

const profile = compileParticipantRuntimeProfile(4, 2);
const bounds = profile.contribution;
const recordBytes = 1_048_576;
const fixtureHeader = (length: number) => {
    const header = new Uint8Array(76).fill(43);
    header.set(new TextEncoder().encode('SCB2'));
    new DataView(header.buffer).setBigUint64(4, BigInt(length), true);
    return header;
};
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

// These are references and opaque checkpoint headers for codec checks.
// They create no authenticated storage, contribution or proof capability.
const stateAt = (
    phase: number,
    proofLength = bounds.minimumProofBytes,
    position = 2,
): ContributionState => ({
    phase,
    position,
    header:
        phase === 4
            ? new Uint8Array()
            : phase <= 6
              ? Uint8Array.of(70, 80, 67, 52, 17, 29)
              : fixtureHeader(proofLength),
    publicRecords:
        phase === 4
            ? []
            : [...bounds.publicRecords, ...(phase >= 7 ? slots : [])].map(
                  record,
              ),
    privateRecords:
        phase === 5 || phase === 6
            ? bounds.checkpointLengths.map((_length, index) => ({
                  key: new Uint8Array(32).fill(index % 251),
                  hash: new Uint8Array(64).fill((index + 1) % 251),
              }))
            : [],
    signingRecords: [
        bounds.offerEnvelopeBytes,
        profile.registration.signatureBytes,
    ]
        .slice(0, phase === 8 ? 1 : phase === 9 ? 2 : 0)
        .map((length, index) =>
            record(
                { object: proofObject + 1 + index, offset: 0, length },
                bounds.publicRecords.length + slots.length + index,
            ),
        ),
    seed: new Uint8Array(phase === 4 || phase === 6 ? 64 : 0).fill(61),
});
const decode = (state: ContributionState) =>
    decodeContributionState(encodeContributionState(state), profile);

describe('independent contribution state framing', () => {
    it('admits every own phase for eligible pool members beyond the selected count', () => {
        expect(profile.setupContributorCount).toBe(2);
        expect(profile.eligibleContributorCount).toBe(3);
        for (const phase of [4, 5, 6, 7, 8, 9]) {
            for (const position of [0, 1, 2]) {
                const state = stateAt(
                    phase,
                    bounds.minimumProofBytes,
                    position,
                );
                const bytes = encodeContributionState(state);
                expect(new TextDecoder().decode(bytes.subarray(0, 4))).toBe(
                    'PCS5',
                );
                expect(decodeContributionState(bytes, profile)).toEqual(state);
                expect(bytes.length).toBeLessThanOrEqual(
                    bounds.maximumStateBytes,
                );
            }
            expect(() =>
                decode(stateAt(phase, bounds.minimumProofBytes, 3)),
            ).toThrow();
        }
    });

    it('retains the same maximum proof slot inventory for varied logical lengths', () => {
        for (const phase of [7, 8, 9]) {
            let encodedLength: number | undefined;
            for (const length of [
                bounds.minimumProofBytes,
                recordBytes - 1,
                recordBytes,
                recordBytes + 1,
                bounds.maximumProofBytes,
            ]) {
                const state = stateAt(phase, length);
                const encoded = encodeContributionState(state);
                const decoded = decodeContributionState(encoded, profile);
                expect(decoded).toEqual(state);
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
            }
        }
    });

    it('rejects phase substitution instead of reviving or discarding private work', () => {
        for (const phase of [4, 5, 6, 7, 8, 9]) {
            const encoded = encodeContributionState(stateAt(phase));
            for (const changedPhase of [0, 3, 4, 5, 6, 7, 8, 9, 10, 255]) {
                if (changedPhase === phase) continue;
                const changed = encoded.slice();
                changed[4] = changedPhase;
                expect(() =>
                    decodeContributionState(changed, profile),
                ).toThrow();
            }
            expect(() =>
                decodeContributionState(
                    encoded.subarray(0, encoded.length - 1),
                    profile,
                ),
            ).toThrow();
            expect(() =>
                decodeContributionState(
                    new Uint8Array([...encoded, 0]),
                    profile,
                ),
            ).toThrow();
        }
    });

    it('rejects missing, extra, shortened and displaced body or proof records', () => {
        for (const phase of [5, 6, 7, 8, 9]) {
            const state = stateAt(phase);
            const last = state.publicRecords.length - 1;
            for (const records of [
                state.publicRecords.slice(0, last),
                [...state.publicRecords, state.publicRecords[last]],
                state.publicRecords.map((value, index) =>
                    index === last
                        ? { ...value, length: value.length - 1 }
                        : value,
                ),
                state.publicRecords.map((value, index) =>
                    index === last
                        ? { ...value, offset: value.offset + 1 }
                        : value,
                ),
                state.publicRecords.map((value, index) =>
                    index === 0
                        ? { ...value, object: value.object + 1 }
                        : value,
                ),
            ])
                expect(() =>
                    decode({ ...state, publicRecords: records }),
                ).toThrow();
        }
        for (const phase of [5, 6]) {
            const state = stateAt(phase);
            expect(() =>
                decode({
                    ...state,
                    privateRecords: state.privateRecords.slice(1),
                }),
            ).toThrow();
            expect(() =>
                decode({
                    ...state,
                    privateRecords: [
                        ...state.privateRecords,
                        state.privateRecords[0],
                    ],
                }),
            ).toThrow();
        }
    });

    it('rejects wrong seed and offer record shapes at their actual phases', () => {
        for (const phase of [4, 5, 6, 7, 8, 9]) {
            const state = stateAt(phase);
            for (const seed of [new Uint8Array(63), new Uint8Array(65)])
                expect(() => decode({ ...state, seed })).toThrow();
        }
        for (const phase of [8, 9]) {
            const state = stateAt(phase);
            for (const signingRecords of [
                state.signingRecords.slice(1),
                [...state.signingRecords, state.signingRecords[0]],
                state.signingRecords.map((value, index) =>
                    index === 0
                        ? { ...value, length: value.length + 1 }
                        : value,
                ),
                state.signingRecords.map((value, index) =>
                    index === 0
                        ? { ...value, object: value.object + 1 }
                        : value,
                ),
            ])
                expect(() => decode({ ...state, signingRecords })).toThrow();
        }
    });

    it('refuses malformed SCB2 framing and obsolete contribution formats', () => {
        const state = stateAt(7);
        for (const header of [
            new Uint8Array(),
            new Uint8Array(12),
            ...[
                BigInt(bounds.minimumProofBytes - 1),
                BigInt(bounds.maximumProofBytes + 1),
                (1n << 64n) - 1n,
            ].map((length) => {
                const changed = state.header.slice();
                new DataView(changed.buffer).setBigUint64(4, length, true);
                return changed;
            }),
        ])
            expect(() => decode({ ...state, header })).toThrow();
        for (const marker of ['PCS2', 'PCS3', 'PRC1']) {
            const previous = encodeContributionState(state);
            previous.set(new TextEncoder().encode(marker));
            expect(() => decodeContributionState(previous, profile)).toThrow();
        }
    });

    it('pins the bytes every own phase stores', () => {
        expect(
            [4, 5, 6, 7, 8, 9].map((phase) =>
                storedDigest(encodeContributionState(stateAt(phase))),
            ),
        ).toEqual([
            '474f222d0459cb981f8dbf8eba3358894c193350521df6ccab9076775b20dea0',
            '97ec1590ccd4ddebfdd9fb8571d7b37d31e35ea2db6a0c0da62441d43f41e6d8',
            '4b3d365b16756cf4234edf2d3487cb6ccede06ca9a1e09b2f622ce33de4236ae',
            'cf1a91bb116a30d03177ad2d06036ed589d6f5b2f10a84a47fbb01ee2789db37',
            '051e7b8c8ddc6fc9dcdab984320f406089131b814c7197cb687e2a604a02eece',
            'a65d601ae2067e22fd0cced38b3942201e15ce7b356d28dfea48c7284ab2d1fa',
        ]);
    });
});
