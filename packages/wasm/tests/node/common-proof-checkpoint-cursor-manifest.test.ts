import { describe, expect, it } from 'vitest';

import {
    CommonProofCheckpointCursorManifestError,
    decodeCommonProofCheckpointCursorManifest,
    isAssignedRuntimeCheckpointRandomUse,
} from '#packages/wasm/src/index';

const cursorManifestMagic = Uint8Array.of(
    0x53,
    0x4c,
    0x43,
    0x50,
    0x43,
    0x4d,
    0x30,
    0x33,
);
const familySchemaIdentifier = 0x1211;

type CursorRunFixture = Readonly<{
    coordinateCount: number;
    overrideCoordinateOffsets?: readonly number[];
    purposeClass: number;
}>;

const identityFreeManifest = (): Uint8Array<ArrayBuffer> => {
    const bytes = new Uint8Array(19);
    bytes.set(cursorManifestMagic);
    new DataView(bytes.buffer).setUint16(8, 3, true);
    return bytes;
};

const identityManifest = (
    input: {
        derivationBindingHash?: Uint8Array;
        familySchemaIdentifier?: number;
        runs?: readonly CursorRunFixture[];
        streamAttemptIdentifier?: Uint8Array;
    } = {},
): Uint8Array<ArrayBuffer> => {
    const runs = input.runs ?? [];
    const streamAttemptIdentifier =
        input.streamAttemptIdentifier ?? new Uint8Array(32).fill(0x67);
    const derivationBindingHash =
        input.derivationBindingHash ?? new Uint8Array(64).fill(0x42);
    if (derivationBindingHash.byteLength !== 64) {
        throw new TypeError(
            'The test derivation binding hash must contain exactly 64 bytes.',
        );
    }
    if (streamAttemptIdentifier.byteLength !== 32) {
        throw new TypeError(
            'The test stream attempt identifier must contain exactly 32 bytes.',
        );
    }
    const overrideCount = runs.reduce(
        (count, run) => count + (run.overrideCoordinateOffsets?.length ?? 0),
        0,
    );
    const bytes = new Uint8Array(
        19 + 98 + runs.length * 24 + overrideCount * 14,
    );
    bytes.set(cursorManifestMagic);
    const view = new DataView(bytes.buffer);
    view.setUint16(8, 3, true);
    bytes[10] = 1;
    view.setUint32(11, runs.length, true);
    view.setUint32(
        15,
        runs.reduce((count, run) => count + run.coordinateCount, 0),
        true,
    );
    view.setUint16(
        19,
        input.familySchemaIdentifier ?? familySchemaIdentifier,
        true,
    );
    bytes.set(derivationBindingHash, 21);
    bytes.set(streamAttemptIdentifier, 85);
    let offset = 117;
    for (const [runIndex, run] of runs.entries()) {
        if (run.coordinateCount < 1) {
            throw new TypeError(
                'A test cursor run must contain one coordinate.',
            );
        }
        const overrides = run.overrideCoordinateOffsets ?? [];
        view.setUint16(offset, run.purposeClass, true);
        view.setUint32(offset + 2, 0, true);
        view.setUint32(offset + 6, run.coordinateCount - 1, true);
        view.setBigUint64(offset + 10, BigInt(runIndex + 1), true);
        view.setUint16(offset + 18, 0, true);
        view.setUint32(offset + 20, overrides.length, true);
        offset += 24;
        for (const [overrideIndex, coordinateOffset] of overrides.entries()) {
            view.setUint32(offset, coordinateOffset, true);
            view.setBigUint64(
                offset + 4,
                BigInt((runIndex + 1) * 10 + overrideIndex),
                true,
            );
            view.setUint16(offset + 12, overrideIndex + 1, true);
            offset += 14;
        }
    }
    return bytes;
};

describe('common-proof checkpoint cursor manifest', () => {
    it('decodes the exact identity-free representation', () => {
        const decoded = decodeCommonProofCheckpointCursorManifest(
            identityFreeManifest(),
        );

        expect(decoded).toEqual({
            hasPrivateRandomnessIdentity: false,
            orderedPurposeClasses: [],
        });
        expect(Object.isFrozen(decoded)).toBe(true);
        expect(Object.isFrozen(decoded.orderedPurposeClasses)).toBe(true);
    });

    it('decodes and copies the complete identity before its first cursor', () => {
        const derivationBindingHash = new Uint8Array(64).fill(0x72);
        const streamAttemptIdentifier = new Uint8Array(32).fill(0x71);
        const manifest = identityManifest({
            derivationBindingHash,
            streamAttemptIdentifier,
        });
        const decoded = decodeCommonProofCheckpointCursorManifest(manifest);
        manifest.fill(0);

        expect(decoded.hasPrivateRandomnessIdentity).toBe(true);
        if (!decoded.hasPrivateRandomnessIdentity) {
            throw new Error(
                'The identity-bearing fixture decoded incorrectly.',
            );
        }
        expect(decoded.derivationBindingHash).toEqual(derivationBindingHash);
        expect(decoded.familySchemaIdentifier).toBe(familySchemaIdentifier);
        expect(decoded.orderedPurposeClasses).toEqual([]);
        expect(decoded.privateRandomnessStreamAttemptIdentifier).toEqual(
            streamAttemptIdentifier,
        );
    });

    it('accepts every public-witness family before and after its construction-hiding cursor materializes', () => {
        for (const publicOnlyFamilySchemaIdentifier of [
            0x1213, 0x1215, 0x1218,
        ]) {
            const derivationBindingHash = new Uint8Array(64).fill(
                publicOnlyFamilySchemaIdentifier & 0xff,
            );
            const streamAttemptIdentifier = new Uint8Array(32).fill(
                (publicOnlyFamilySchemaIdentifier + 1) & 0xff,
            );
            for (const runs of [
                [],
                [{ coordinateCount: 1, purposeClass: 4 }],
            ] as const) {
                const manifest = identityManifest({
                    derivationBindingHash,
                    familySchemaIdentifier: publicOnlyFamilySchemaIdentifier,
                    runs,
                    streamAttemptIdentifier,
                });
                const decoded =
                    decodeCommonProofCheckpointCursorManifest(manifest);
                manifest.fill(0);

                expect(decoded).toMatchObject({
                    familySchemaIdentifier: publicOnlyFamilySchemaIdentifier,
                    hasPrivateRandomnessIdentity: true,
                    orderedPurposeClasses: runs.length === 0 ? [] : [4],
                });
                if (!decoded.hasPrivateRandomnessIdentity) {
                    throw new Error(
                        'The public-witness identity fixture decoded incorrectly.',
                    );
                }
                expect(decoded.derivationBindingHash).toEqual(
                    derivationBindingHash,
                );
                expect(
                    decoded.privateRandomnessStreamAttemptIdentifier,
                ).toEqual(streamAttemptIdentifier);
            }
        }
    });

    it('rejects truly unassigned families and forbidden public-witness cursor purposes', () => {
        expect(() =>
            decodeCommonProofCheckpointCursorManifest(
                identityManifest({ familySchemaIdentifier: 0x1210 }),
            ),
        ).toThrow('unassigned family');

        for (const publicOnlyFamilySchemaIdentifier of [
            0x1213, 0x1215, 0x1218,
        ]) {
            expect(() =>
                decodeCommonProofCheckpointCursorManifest(
                    identityManifest({
                        familySchemaIdentifier:
                            publicOnlyFamilySchemaIdentifier,
                        runs: [{ coordinateCount: 1, purposeClass: 1 }],
                    }),
                ),
            ).toThrow('malformed');
        }
    });

    it('rejects non-integer and out-of-range random-use assignments', () => {
        const invalidUnsigned16Values = [
            Number.NaN,
            Number.NEGATIVE_INFINITY,
            Number.POSITIVE_INFINITY,
            -1,
            0,
            0.5,
            0x1_0000,
        ];

        for (const invalidFamily of invalidUnsigned16Values) {
            expect(isAssignedRuntimeCheckpointRandomUse(invalidFamily, 1)).toBe(
                false,
            );
        }
        for (const invalidPurpose of invalidUnsigned16Values) {
            expect(
                isAssignedRuntimeCheckpointRandomUse(0x2120, invalidPurpose),
            ).toBe(false);
        }
        for (const publicOnlyFamilySchemaIdentifier of [
            0x1213, 0x1215, 0x1218,
        ]) {
            expect(
                isAssignedRuntimeCheckpointRandomUse(
                    publicOnlyFamilySchemaIdentifier,
                    4,
                ),
            ).toBe(true);
            for (const forbiddenPurpose of [1, 2, 3, 0xfffe]) {
                expect(
                    isAssignedRuntimeCheckpointRandomUse(
                        publicOnlyFamilySchemaIdentifier,
                        forbiddenPurpose,
                    ),
                ).toBe(false);
            }
        }
        expect(isAssignedRuntimeCheckpointRandomUse(0x1211, 0xfffe)).toBe(true);
    });

    it('decodes ordered live cursor purposes with sparse state overrides', () => {
        const decoded = decodeCommonProofCheckpointCursorManifest(
            identityManifest({
                runs: [
                    {
                        coordinateCount: 4,
                        overrideCoordinateOffsets: [1, 3],
                        purposeClass: 1,
                    },
                    { coordinateCount: 2, purposeClass: 3 },
                    { coordinateCount: 1, purposeClass: 0xfffe },
                ],
            }),
        );

        expect(decoded.hasPrivateRandomnessIdentity).toBe(true);
        if (!decoded.hasPrivateRandomnessIdentity) {
            throw new Error(
                'The identity-bearing fixture decoded incorrectly.',
            );
        }
        expect(decoded.orderedPurposeClasses).toEqual([1, 3, 0xfffe]);
    });

    it('rejects malformed identities, run order, counts, overrides, and trailing bytes', () => {
        const wrongMagic = identityManifest();
        wrongMagic[0] ^= 0xff;
        const wrongVersion = identityManifest();
        new DataView(wrongVersion.buffer).setUint16(8, 2, true);
        const identityFreeTrailing = new Uint8Array(20);
        identityFreeTrailing.set(identityFreeManifest());
        const unsortedRuns = identityManifest({
            runs: [
                { coordinateCount: 1, purposeClass: 3 },
                { coordinateCount: 1, purposeClass: 1 },
            ],
        });
        const unassignedPurpose = identityManifest({
            runs: [{ coordinateCount: 1, purposeClass: 5 }],
        });
        const wrongLogicalCount = identityManifest({
            runs: [{ coordinateCount: 2, purposeClass: 1 }],
        });
        new DataView(wrongLogicalCount.buffer).setUint32(15, 1, true);
        const duplicateOverride = identityManifest({
            runs: [
                {
                    coordinateCount: 3,
                    overrideCoordinateOffsets: [1, 1],
                    purposeClass: 1,
                },
            ],
        });
        const impossibleBufferedOffset = identityManifest({
            runs: [{ coordinateCount: 1, purposeClass: 1 }],
        });
        new DataView(impossibleBufferedOffset.buffer).setUint16(
            117 + 18,
            513,
            true,
        );
        const redundantOverride = identityManifest({
            runs: [
                {
                    coordinateCount: 2,
                    overrideCoordinateOffsets: [1],
                    purposeClass: 1,
                },
            ],
        });
        const redundantOverrideView = new DataView(redundantOverride.buffer);
        redundantOverrideView.setBigUint64(117 + 24 + 4, 1n, true);
        redundantOverrideView.setUint16(117 + 24 + 12, 0, true);
        const trailing = new Uint8Array(identityManifest().byteLength + 1);
        trailing.set(identityManifest());

        for (const manifest of [
            new Uint8Array(),
            wrongMagic,
            wrongVersion,
            identityFreeTrailing,
            unsortedRuns,
            unassignedPurpose,
            wrongLogicalCount,
            duplicateOverride,
            impossibleBufferedOffset,
            redundantOverride,
            trailing,
        ]) {
            expect(() =>
                decodeCommonProofCheckpointCursorManifest(manifest),
            ).toThrow(CommonProofCheckpointCursorManifestError);
        }
    });
});
