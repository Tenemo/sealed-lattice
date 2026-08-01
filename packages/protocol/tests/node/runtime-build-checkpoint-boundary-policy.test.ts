import type { RuntimeBuildManifest } from '@sealed-lattice/wasm';
import { describe, expect, it } from 'vitest';

import { createResetSafeCommonProofCursorManifest } from '#packages/wasm/tests/node/common-proof-worker-runtime/kernel-fixtures';
import { activateRuntimeBuildAuthorityBindingFixture } from '#packages/wasm/tests/support/runtime-build-authority-binding-fixture';
import {
    createRuntimeBuildCheckpointBoundaryPolicy,
    RuntimeBuildCheckpointBoundaryPolicyError,
    type CheckpointBoundary,
    type ExpectedCheckpointBoundary,
    type RuntimeBuildCheckpointBoundaryBinding,
} from '@sealed-lattice/protocol';

type RuntimeOperationProfile =
    RuntimeBuildManifest['operationProfiles'][number];
type CheckpointBoundaryProfile =
    RuntimeOperationProfile['safeBoundaries'][number];

const proofRandomnessFamily = 0x1217;
const operationKind = proofRandomnessFamily;
const publicOnlyProofFamilies = Object.freeze([0x1213, 0x1215, 0x1218]);
const otherOperationKind = 0x1205;
const stateSchemaIdentifier = 0x010c;
const stateStreamDomain =
    'sealed-lattice/common-proof/generation-checkpoint-state/v1';
const checkpointLineageIdentifier = new Uint8Array(32).fill(0x41);
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
const stableAttemptBindingHash = new Uint8Array(64).fill(0x52);
const generationCursorManifestPrefixByteLength = 88;

const generationCursorManifest = (
    privateCoinCursorManifest: Uint8Array,
): Uint8Array<ArrayBuffer> => {
    const bytes = new Uint8Array(
        generationCursorManifestPrefixByteLength +
            privateCoinCursorManifest.byteLength,
    );
    bytes.set(Uint8Array.of(0x53, 0x4c, 0x43, 0x47, 0x43, 0x4d, 0x30, 0x31));
    const view = new DataView(bytes.buffer);
    view.setUint16(8, 1, true);
    view.setUint32(12, bytes.byteLength, true);
    view.setUint32(16, privateCoinCursorManifest.byteLength, true);
    bytes.set(
        privateCoinCursorManifest,
        generationCursorManifestPrefixByteLength,
    );
    return bytes;
};

const deterministicCursorManifest = (): Uint8Array<ArrayBuffer> => {
    const privateCoinCursorManifest = new Uint8Array(19);
    privateCoinCursorManifest.set(cursorManifestMagic);
    new DataView(privateCoinCursorManifest.buffer).setUint16(8, 3, true);
    return generationCursorManifest(privateCoinCursorManifest);
};

const privateCursorManifest = (input: {
    derivationBindingHash?: Uint8Array;
    family?: number;
    orderedPurposes: readonly number[];
    streamAttemptIdentifier: Uint8Array;
}): Uint8Array<ArrayBuffer> => {
    const derivationBindingHash =
        input.derivationBindingHash ?? stableAttemptBindingHash;
    if (derivationBindingHash.byteLength !== 64) {
        throw new TypeError(
            'The test derivation binding hash must contain exactly 64 bytes.',
        );
    }
    if (input.streamAttemptIdentifier.byteLength !== 32) {
        throw new TypeError(
            'The test stream attempt identifier must be exact.',
        );
    }
    const prefixByteLength = 19;
    const identityByteLength = 98;
    const runByteLength = 24;
    const bytes = new Uint8Array(
        prefixByteLength +
            identityByteLength +
            input.orderedPurposes.length * runByteLength,
    );
    bytes.set(cursorManifestMagic);
    const view = new DataView(bytes.buffer);
    view.setUint16(8, 3, true);
    bytes[10] = 1;
    view.setUint32(11, input.orderedPurposes.length, true);
    view.setUint32(15, input.orderedPurposes.length, true);
    view.setUint16(19, input.family ?? proofRandomnessFamily, true);
    bytes.set(derivationBindingHash, 21);
    bytes.set(input.streamAttemptIdentifier, 85);
    let offset = prefixByteLength + identityByteLength;
    for (const [purposeIndex, purpose] of input.orderedPurposes.entries()) {
        view.setUint16(offset, purpose, true);
        view.setUint32(offset + 2, 0, true);
        view.setUint32(offset + 6, 0, true);
        view.setBigUint64(offset + 10, BigInt(purposeIndex + 1), true);
        view.setUint16(offset + 18, 0, true);
        view.setUint32(offset + 20, 0, true);
        offset += runByteLength;
    }
    return generationCursorManifest(bytes);
};

const boundaryProfile = (
    orderedPurposes: readonly number[] = [],
    schemaIdentifier = stateSchemaIdentifier,
): CheckpointBoundaryProfile =>
    Object.freeze({
        orderedRandomUses: Object.freeze(
            orderedPurposes.map((purpose) =>
                Object.freeze({
                    family: proofRandomnessFamily,
                    purpose,
                }),
            ),
        ),
        stateSchemaIdentifier: schemaIdentifier,
    });

const operationProfile = (
    selectedOperationKind: number,
    safeBoundaries: readonly CheckpointBoundaryProfile[],
): RuntimeOperationProfile =>
    Object.freeze({
        operationKind: selectedOperationKind,
        safeBoundaries: Object.freeze(safeBoundaries),
    });

const manifestForOperationProfiles = (
    operationProfiles: readonly RuntimeOperationProfile[],
): RuntimeBuildManifest =>
    Object.freeze({
        operationProfiles: Object.freeze([...operationProfiles]),
        orderedAssets: Object.freeze([]),
        orderedSuiteArtifactPaths: Object.freeze([]),
        protocolVersion: 1,
        releaseIdentifier: 'checkpoint-policy-test',
        suiteIdentifier: new Uint8Array(64),
        suiteRecordPath: '/suite.canonical',
    });

const exactBinding = (
    safeBoundaryOrdinal = 0,
    schemaIdentifier = stateSchemaIdentifier,
    domain = stateStreamDomain,
): RuntimeBuildCheckpointBoundaryBinding =>
    Object.freeze({
        safeBoundaryOrdinal,
        stateSchemaIdentifier: schemaIdentifier,
        stateStreamDomain: domain,
    });

const createBoundary = (
    input: {
        cursorManifestBytes?: Uint8Array;
        operationKind?: number;
        orderedSourceDigests?: readonly Uint8Array[];
        safeBoundaryOrdinal?: number;
        stateStreamDomain?: string;
        streamAttemptIdentifier?: Uint8Array;
    } = {},
): CheckpointBoundary =>
    Object.freeze({
        operationKind: input.operationKind ?? operationKind,
        orderedSourceDigests:
            input.orderedSourceDigests ??
            Object.freeze([
                stableAttemptBindingHash.slice(),
                stableAttemptBindingHash.slice(),
                new Uint8Array(64).fill(0x43),
            ]),
        privateRandomCursorManifestBytes:
            input.cursorManifestBytes ?? deterministicCursorManifest(),
        ...(input.streamAttemptIdentifier === undefined
            ? {}
            : {
                  privateRandomnessStreamAttemptIdentifier:
                      input.streamAttemptIdentifier,
              }),
        safeBoundaryOrdinal: input.safeBoundaryOrdinal ?? 0,
        stateStreamDescriptorBytes: Uint8Array.of(0x91),
        stateStreamDomain: input.stateStreamDomain ?? stateStreamDomain,
    });

const withoutStateDescriptor = (
    boundary: CheckpointBoundary,
): ExpectedCheckpointBoundary => ({
    operationKind: boundary.operationKind,
    orderedSourceDigests: boundary.orderedSourceDigests,
    privateRandomCursorManifestBytes: boundary.privateRandomCursorManifestBytes,
    ...(boundary.privateRandomnessStreamAttemptIdentifier === undefined
        ? {}
        : {
              privateRandomnessStreamAttemptIdentifier:
                  boundary.privateRandomnessStreamAttemptIdentifier,
          }),
    safeBoundaryOrdinal: boundary.safeBoundaryOrdinal,
    stateStreamDomain: boundary.stateStreamDomain,
});

const validatePublication = (
    policy: ReturnType<typeof createRuntimeBuildCheckpointBoundaryPolicy>,
    boundary: CheckpointBoundary,
    previousBoundary?: CheckpointBoundary,
): void | Promise<void> =>
    policy.validatePublication({
        boundary,
        checkpointLineageIdentifier,
        ...(previousBoundary === undefined ? {} : { previousBoundary }),
    });

const validateResume = (
    policy: ReturnType<typeof createRuntimeBuildCheckpointBoundaryPolicy>,
    boundary: CheckpointBoundary,
): void | Promise<void> =>
    policy.validateResume({
        checkpointLineageIdentifier,
        expectedBoundary: withoutStateDescriptor(boundary),
    });

describe('runtime build checkpoint boundary policy', () => {
    it('accepts only the manifest-selected deterministic boundary and its canonical stream domain', () => {
        const policy = createRuntimeBuildCheckpointBoundaryPolicy({
            operationKind,
            orderedBoundaryBindings: Object.freeze([exactBinding()]),
            runtimeBuildManifest: manifestForOperationProfiles([
                operationProfile(otherOperationKind, [boundaryProfile()]),
                operationProfile(operationKind, [boundaryProfile()]),
            ]),
        });
        const boundary = createBoundary();

        expect(() => validatePublication(policy, boundary)).not.toThrow();
        expect(() => validateResume(policy, boundary)).not.toThrow();
        expect(Object.isFrozen(policy)).toBe(true);
    });

    it('accepts an identity-bearing zero-purpose boundary for every public-only proof family', () => {
        for (const publicOnlyProofFamily of publicOnlyProofFamilies) {
            const policy = createRuntimeBuildCheckpointBoundaryPolicy({
                operationKind: publicOnlyProofFamily,
                orderedBoundaryBindings: Object.freeze([exactBinding()]),
                runtimeBuildManifest: manifestForOperationProfiles([
                    operationProfile(publicOnlyProofFamily, [
                        boundaryProfile(),
                    ]),
                ]),
            });
            const streamAttemptIdentifier = new Uint8Array(32).fill(
                publicOnlyProofFamily & 0xff,
            );
            const boundary = createBoundary({
                cursorManifestBytes: privateCursorManifest({
                    family: publicOnlyProofFamily,
                    orderedPurposes: [],
                    streamAttemptIdentifier,
                }),
                operationKind: publicOnlyProofFamily,
                streamAttemptIdentifier,
            });

            expect(() => validatePublication(policy, boundary)).not.toThrow();
            expect(() => validateResume(policy, boundary)).not.toThrow();
        }

        const publicOnlyProofFamily = publicOnlyProofFamilies[0] ?? 0x1213;
        expect(() =>
            createRuntimeBuildCheckpointBoundaryPolicy({
                operationKind: publicOnlyProofFamily,
                orderedBoundaryBindings: Object.freeze([exactBinding()]),
                runtimeBuildManifest: manifestForOperationProfiles([
                    operationProfile(publicOnlyProofFamily, [
                        boundaryProfile([1]),
                    ]),
                ]),
            }),
        ).toThrow('Public-only runtime operation');
    });

    it('refuses mutated public-only family, purpose, attempt, and derivation bindings', () => {
        const publicOnlyProofFamily = publicOnlyProofFamilies[0] ?? 0x1213;
        const policy = createRuntimeBuildCheckpointBoundaryPolicy({
            operationKind: publicOnlyProofFamily,
            orderedBoundaryBindings: Object.freeze([exactBinding()]),
            runtimeBuildManifest: manifestForOperationProfiles([
                operationProfile(publicOnlyProofFamily, [boundaryProfile()]),
            ]),
        });
        const streamAttemptIdentifier = new Uint8Array(32).fill(0x64);
        const exactCursorManifest = privateCursorManifest({
            family: publicOnlyProofFamily,
            orderedPurposes: [],
            streamAttemptIdentifier,
        });

        expect(() =>
            validatePublication(
                policy,
                createBoundary({
                    operationKind: publicOnlyProofFamily,
                    streamAttemptIdentifier,
                }),
            ),
        ).toThrow('public-only');
        expect(() =>
            validateResume(
                policy,
                createBoundary({
                    cursorManifestBytes: privateCursorManifest({
                        family: publicOnlyProofFamilies[1] ?? 0x1215,
                        orderedPurposes: [],
                        streamAttemptIdentifier,
                    }),
                    operationKind: publicOnlyProofFamily,
                    streamAttemptIdentifier,
                }),
            ),
        ).toThrow('public-only');
        expect(() =>
            validatePublication(
                policy,
                createBoundary({
                    cursorManifestBytes: privateCursorManifest({
                        family: publicOnlyProofFamily,
                        orderedPurposes: [1],
                        streamAttemptIdentifier,
                    }),
                    operationKind: publicOnlyProofFamily,
                    streamAttemptIdentifier,
                }),
            ),
        ).toThrow(RuntimeBuildCheckpointBoundaryPolicyError);
        expect(() =>
            validateResume(
                policy,
                createBoundary({
                    cursorManifestBytes: exactCursorManifest,
                    operationKind: publicOnlyProofFamily,
                }),
            ),
        ).toThrow('stream-attempt identifier');

        const wrongAttemptIdentifier = streamAttemptIdentifier.slice();
        wrongAttemptIdentifier[0] ^= 0xff;
        expect(() =>
            validatePublication(
                policy,
                createBoundary({
                    cursorManifestBytes: exactCursorManifest,
                    operationKind: publicOnlyProofFamily,
                    streamAttemptIdentifier: wrongAttemptIdentifier,
                }),
            ),
        ).toThrow('stream-attempt identifier');

        const wrongDerivationBindingHash = stableAttemptBindingHash.slice();
        wrongDerivationBindingHash[63] ^= 0xff;
        for (const orderedSourceDigests of [
            Object.freeze([
                wrongDerivationBindingHash,
                stableAttemptBindingHash.slice(),
            ]),
            Object.freeze([
                stableAttemptBindingHash.slice(),
                wrongDerivationBindingHash,
            ]),
            Object.freeze([
                new Uint8Array(63),
                stableAttemptBindingHash.slice(),
            ]),
            Object.freeze([
                stableAttemptBindingHash.slice(),
                new Uint8Array(63),
            ]),
        ]) {
            const malformedBoundary = createBoundary({
                cursorManifestBytes: exactCursorManifest,
                operationKind: publicOnlyProofFamily,
                orderedSourceDigests,
                streamAttemptIdentifier,
            });
            expect(() => validateResume(policy, malformedBoundary)).toThrow(
                'derivation identities',
            );
            expect(() =>
                validatePublication(policy, malformedBoundary),
            ).toThrow('derivation identities');
        }
    });

    it('fails closed when the authenticated preflight manifest omits the selected proof family', async () => {
        const { activation } =
            await activateRuntimeBuildAuthorityBindingFixture();

        expect(() =>
            createRuntimeBuildCheckpointBoundaryPolicy({
                operationKind,
                orderedBoundaryBindings: Object.freeze([exactBinding()]),
                runtimeBuildManifest: activation.manifest,
            }),
        ).toThrowError(RuntimeBuildCheckpointBoundaryPolicyError);
        expect(() =>
            createRuntimeBuildCheckpointBoundaryPolicy({
                operationKind: 1,
                orderedBoundaryBindings: Object.freeze([exactBinding()]),
                runtimeBuildManifest: manifestForOperationProfiles([
                    operationProfile(operationKind, [boundaryProfile()]),
                ]),
            }),
        ).toThrow('Runtime operation 1 has no checkpoint profile');
    });

    it('binds the cursor family and attempt while restricting materialized purposes to the profile', () => {
        const orderedPurposes = Object.freeze([1, 3, 0xfffe]);
        const policy = createRuntimeBuildCheckpointBoundaryPolicy({
            operationKind,
            orderedBoundaryBindings: Object.freeze([exactBinding()]),
            runtimeBuildManifest: manifestForOperationProfiles([
                operationProfile(operationKind, [
                    boundaryProfile(orderedPurposes),
                ]),
            ]),
        });
        const streamAttemptIdentifier = new Uint8Array(32).fill(0x63);
        const boundary = createBoundary({
            cursorManifestBytes: privateCursorManifest({
                orderedPurposes,
                streamAttemptIdentifier,
            }),
            streamAttemptIdentifier,
        });

        expect(() => validatePublication(policy, boundary)).not.toThrow();
        expect(() => validateResume(policy, boundary)).not.toThrow();

        const wrongAttemptIdentifier = streamAttemptIdentifier.slice();
        wrongAttemptIdentifier[31] ^= 0xff;
        expect(() =>
            validatePublication(
                policy,
                createBoundary({
                    cursorManifestBytes:
                        boundary.privateRandomCursorManifestBytes,
                    streamAttemptIdentifier: wrongAttemptIdentifier,
                }),
            ),
        ).toThrow('stream-attempt identifier');
        expect(() =>
            validateResume(
                policy,
                createBoundary({
                    cursorManifestBytes: privateCursorManifest({
                        family: 0x1212,
                        orderedPurposes,
                        streamAttemptIdentifier,
                    }),
                    streamAttemptIdentifier,
                }),
            ),
        ).toThrow('random-use profile');
        expect(() =>
            validatePublication(
                policy,
                createBoundary({
                    cursorManifestBytes: privateCursorManifest({
                        orderedPurposes: [1, 2, 0xfffe],
                        streamAttemptIdentifier,
                    }),
                    streamAttemptIdentifier,
                }),
            ),
        ).toThrow('random-use profile');

        const wrongDerivationBindingHash = stableAttemptBindingHash.slice();
        wrongDerivationBindingHash[0] ^= 0xff;
        for (const orderedSourceDigests of [
            Object.freeze([
                wrongDerivationBindingHash,
                stableAttemptBindingHash.slice(),
            ]),
            Object.freeze([
                stableAttemptBindingHash.slice(),
                wrongDerivationBindingHash,
            ]),
        ]) {
            expect(() =>
                validateResume(
                    policy,
                    createBoundary({
                        cursorManifestBytes:
                            boundary.privateRandomCursorManifestBytes,
                        orderedSourceDigests,
                        streamAttemptIdentifier,
                    }),
                ),
            ).toThrow('derivation identities');
        }
    });

    it('accepts reset-safe identity before cursor use and non-prefix materialized subsets', () => {
        const orderedPurposes = Object.freeze([1, 3, 0xfffe]);
        const policy = createRuntimeBuildCheckpointBoundaryPolicy({
            operationKind,
            orderedBoundaryBindings: Object.freeze([exactBinding()]),
            runtimeBuildManifest: manifestForOperationProfiles([
                operationProfile(operationKind, [
                    boundaryProfile(orderedPurposes),
                ]),
            ]),
        });
        const streamAttemptIdentifier = new Uint8Array(32).fill(0x48);
        const resetSafeBoundary = createBoundary({
            cursorManifestBytes: createResetSafeCommonProofCursorManifest(
                streamAttemptIdentifier,
                stableAttemptBindingHash,
            ),
            streamAttemptIdentifier,
        });
        const materializedSubsetBoundary = createBoundary({
            cursorManifestBytes: privateCursorManifest({
                orderedPurposes: [3, 0xfffe],
                streamAttemptIdentifier,
            }),
            streamAttemptIdentifier,
        });

        expect(() =>
            validatePublication(policy, resetSafeBoundary),
        ).not.toThrow();
        expect(() => validateResume(policy, resetSafeBoundary)).not.toThrow();
        expect(() =>
            validatePublication(policy, materializedSubsetBoundary),
        ).not.toThrow();

        expect(() => validateResume(policy, createBoundary())).toThrow(
            'random-use profile',
        );
        expect(() =>
            validateResume(
                policy,
                createBoundary({
                    cursorManifestBytes: privateCursorManifest({
                        family: 0x1212,
                        orderedPurposes: [],
                        streamAttemptIdentifier,
                    }),
                    streamAttemptIdentifier,
                }),
            ),
        ).toThrow('random-use profile');
        const wrongAttemptIdentifier = streamAttemptIdentifier.slice();
        wrongAttemptIdentifier[0] ^= 0xff;
        expect(() =>
            validateResume(
                policy,
                createBoundary({
                    cursorManifestBytes:
                        resetSafeBoundary.privateRandomCursorManifestBytes,
                    streamAttemptIdentifier: wrongAttemptIdentifier,
                }),
            ),
        ).toThrow('stream-attempt identifier');
    });

    it('refuses wrong operations, unknown ordinals, wrong domains, and invalid previous boundaries', () => {
        const policy = createRuntimeBuildCheckpointBoundaryPolicy({
            operationKind,
            orderedBoundaryBindings: Object.freeze([exactBinding()]),
            runtimeBuildManifest: manifestForOperationProfiles([
                operationProfile(operationKind, [boundaryProfile()]),
            ]),
        });
        const exactBoundary = createBoundary();

        expect(() =>
            validatePublication(
                policy,
                createBoundary({ operationKind: operationKind + 1 }),
            ),
        ).toThrow(`instead of ${operationKind}`);
        expect(() =>
            validateResume(policy, createBoundary({ safeBoundaryOrdinal: 1 })),
        ).toThrow('does not assign checkpoint boundary 1');
        expect(() =>
            validatePublication(
                policy,
                createBoundary({ stateStreamDomain: `${stateStreamDomain}-x` }),
            ),
        ).toThrow('wrong state stream domain');
        expect(() =>
            validatePublication(
                policy,
                exactBoundary,
                createBoundary({ operationKind: operationKind + 1 }),
            ),
        ).toThrow(`instead of ${operationKind}`);
    });

    it('refuses private cursor material at a deterministic boundary', () => {
        const policy = createRuntimeBuildCheckpointBoundaryPolicy({
            operationKind,
            orderedBoundaryBindings: Object.freeze([exactBinding()]),
            runtimeBuildManifest: manifestForOperationProfiles([
                operationProfile(operationKind, [boundaryProfile()]),
            ]),
        });
        const streamAttemptIdentifier = new Uint8Array(32).fill(0x77);

        expect(() =>
            validatePublication(
                policy,
                createBoundary({
                    cursorManifestBytes: privateCursorManifest({
                        orderedPurposes: [1],
                        streamAttemptIdentifier,
                    }),
                    streamAttemptIdentifier,
                }),
            ),
        ).toThrow('deterministic checkpoint boundary');
    });

    it('requires one exact contiguous schema-and-domain binding for every manifest boundary', () => {
        const selectedProfile = operationProfile(operationKind, [
            boundaryProfile([], stateSchemaIdentifier),
            boundaryProfile([], stateSchemaIdentifier + 1),
        ]);
        const exactBindings = Object.freeze([
            exactBinding(0, stateSchemaIdentifier),
            exactBinding(1, stateSchemaIdentifier + 1),
        ]);
        expect(() =>
            createRuntimeBuildCheckpointBoundaryPolicy({
                operationKind,
                orderedBoundaryBindings: exactBindings,
                runtimeBuildManifest: manifestForOperationProfiles([
                    selectedProfile,
                ]),
            }),
        ).not.toThrow();

        for (const orderedBoundaryBindings of [
            [exactBindings[0]],
            [
                exactBinding(0, stateSchemaIdentifier),
                exactBinding(0, stateSchemaIdentifier + 1),
            ],
            [
                exactBinding(0, stateSchemaIdentifier),
                exactBinding(1, stateSchemaIdentifier + 2),
            ],
            [
                exactBinding(0, stateSchemaIdentifier),
                {
                    safeBoundaryOrdinal: 1,
                    stateSchemaIdentifier: stateSchemaIdentifier + 1,
                },
            ],
        ] as const) {
            expect(() =>
                createRuntimeBuildCheckpointBoundaryPolicy({
                    operationKind,
                    orderedBoundaryBindings:
                        orderedBoundaryBindings as readonly RuntimeBuildCheckpointBoundaryBinding[],
                    runtimeBuildManifest: manifestForOperationProfiles([
                        selectedProfile,
                    ]),
                }),
            ).toThrow(RuntimeBuildCheckpointBoundaryPolicyError);
        }
    });

    it('refuses missing, duplicate, unsorted, and malformed operation profiles', () => {
        const exactProfile = operationProfile(operationKind, [
            boundaryProfile(),
        ]);
        const invalidProfileSets = [
            [],
            [operationProfile(otherOperationKind, [boundaryProfile()])],
            [exactProfile, exactProfile],
            [
                exactProfile,
                operationProfile(otherOperationKind, [boundaryProfile()]),
            ],
            [operationProfile(operationKind, [boundaryProfile([3, 1])])],
            [operationProfile(operationKind, [boundaryProfile([4])])],
        ] as const;

        for (const operationProfiles of invalidProfileSets) {
            expect(() =>
                createRuntimeBuildCheckpointBoundaryPolicy({
                    operationKind,
                    orderedBoundaryBindings: Object.freeze([exactBinding()]),
                    runtimeBuildManifest:
                        manifestForOperationProfiles(operationProfiles),
                }),
            ).toThrow(RuntimeBuildCheckpointBoundaryPolicyError);
        }
    });

    it('copies the selected manifest profile and supplied domain binding', () => {
        const mutableRandomUses = [
            { family: proofRandomnessFamily, purpose: 1 },
        ];
        const mutableProfile = {
            operationKind,
            safeBoundaries: [
                {
                    orderedRandomUses: mutableRandomUses,
                    stateSchemaIdentifier,
                },
            ],
        };
        const mutableBinding = {
            safeBoundaryOrdinal: 0,
            stateSchemaIdentifier,
            stateStreamDomain,
        };
        const policy = createRuntimeBuildCheckpointBoundaryPolicy({
            operationKind,
            orderedBoundaryBindings: [mutableBinding],
            runtimeBuildManifest: manifestForOperationProfiles([
                mutableProfile,
            ]),
        });
        mutableRandomUses[0] = {
            family: proofRandomnessFamily,
            purpose: 3,
        };
        mutableProfile.safeBoundaries[0] = {
            orderedRandomUses: [],
            stateSchemaIdentifier: stateSchemaIdentifier + 1,
        };
        mutableBinding.stateStreamDomain = `${stateStreamDomain}-mutated`;
        const streamAttemptIdentifier = new Uint8Array(32).fill(0x29);

        expect(() =>
            validatePublication(
                policy,
                createBoundary({
                    cursorManifestBytes: privateCursorManifest({
                        orderedPurposes: [1],
                        streamAttemptIdentifier,
                    }),
                    streamAttemptIdentifier,
                }),
            ),
        ).not.toThrow();
    });

    it('rejects malformed cursor run order, counts, and trailing bytes', () => {
        const streamAttemptIdentifier = new Uint8Array(32).fill(0x35);
        const policy = createRuntimeBuildCheckpointBoundaryPolicy({
            operationKind,
            orderedBoundaryBindings: Object.freeze([exactBinding()]),
            runtimeBuildManifest: manifestForOperationProfiles([
                operationProfile(operationKind, [boundaryProfile([1, 3])]),
            ]),
        });
        const unsorted = privateCursorManifest({
            orderedPurposes: [3, 1],
            streamAttemptIdentifier,
        });
        const wrongCount = privateCursorManifest({
            orderedPurposes: [1, 3],
            streamAttemptIdentifier,
        });
        new DataView(wrongCount.buffer).setUint32(
            generationCursorManifestPrefixByteLength + 15,
            9,
            true,
        );
        const trailing = new Uint8Array(wrongCount.byteLength + 1);
        trailing.set(
            privateCursorManifest({
                orderedPurposes: [1, 3],
                streamAttemptIdentifier,
            }),
        );
        const trailingView = new DataView(trailing.buffer);
        trailingView.setUint32(12, trailing.byteLength, true);
        trailingView.setUint32(
            16,
            trailing.byteLength - generationCursorManifestPrefixByteLength,
            true,
        );

        for (const cursorManifestBytes of [unsorted, wrongCount, trailing]) {
            expect(() =>
                validateResume(
                    policy,
                    createBoundary({
                        cursorManifestBytes,
                        streamAttemptIdentifier,
                    }),
                ),
            ).toThrow(RuntimeBuildCheckpointBoundaryPolicyError);
        }
    });
});
