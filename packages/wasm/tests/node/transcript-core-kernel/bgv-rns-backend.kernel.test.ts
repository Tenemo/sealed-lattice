import { describe, expect, it } from 'vitest';

import {
    loadTranscriptCoreKernel,
    TranscriptCoreKernelCommandError,
} from '#packages/wasm/src/index';

type BgvProfileRejected = {
    readonly ok: false;
    readonly unresolvedReason: 'BGVProfileRejected';
    readonly statusLabels: readonly string[];
    readonly refusedObjects: readonly {
        readonly code: 'BGVProfileRejected';
        readonly reasonCode: string;
        readonly message: string;
    }[];
};

const expectBgvProfileRejected = (
    value: unknown,
    reasonCode?: string,
): BgvProfileRejected => {
    expect(value).toMatchObject({
        ok: false,
        unresolvedReason: 'BGVProfileRejected',
    });
    const rejection = value as BgvProfileRejected;
    expect(rejection.statusLabels).toContain('BGVProfileRejected');
    expect(
        rejection.refusedObjects.some(
            (refusedObject) => refusedObject.code === 'BGVProfileRejected',
        ),
    ).toBe(true);
    if (reasonCode !== undefined) {
        expect(rejection.refusedObjects[0]?.reasonCode).toBe(reasonCode);
    }

    return rejection;
};

const expectKernelCommandError = (
    command: () => unknown,
    code: TranscriptCoreKernelCommandError['code'],
    messagePattern: RegExp,
): void => {
    try {
        command();
        throw new Error('Expected a transcript-core kernel command error.');
    } catch (error) {
        expect(error).toBeInstanceOf(TranscriptCoreKernelCommandError);
        const commandError = error as TranscriptCoreKernelCommandError;
        expect(commandError.code).toBe(code);
        expect(commandError.message).toMatch(messagePattern);
    }
};

const stableBgvHashVectors = {
    profileHash:
        '4a2efbb3218fcbde79d396688ebd4bf5f5ed7300f23316e6900aa0cb7dd0057bccc3892df183a6a4f628cc26c8163cf9b226e37f54519216067be5efd5ca743e',
    batchEncoderHash:
        'b76e6b5f37b480032f9f1770f854f6102483f737c0c3d7740ee9f837141648e55ce6b502649661ebd0284e0870a70ea6d8a9370e1afd3e130f62f6ef90885e0c',
    batchLayoutBindingHash:
        '2bdddaf7eba3787d244cb6622e252b6ee9391a8d3aa22a23fa9e46a777d036a7d8852e38f664dec7fd50e2308bec608f896cbd3b3ae925844bc77f673330baab',
    encodedAggregateLayoutHash:
        '5326486ddf587930a12be856d2c79cf255c4d74aa0ab36c140f0882d90ad5a5bfb84785ac57143eb520e202afcb7101e409f8f77361f29f32001972ed869ad36',
    topKEvaluatorInputLayoutHash:
        'f6b51420ef079f4553dc3383ec4d7a3db6ca0951b8f6d99ae6c60b42d058739ebeb66e0d95a0697c3891e798b910054781b925a7ce7601b128922cef50ad5640',
    canonicalCiphertextConventionHash:
        'f12e731e1096504c1ade1fb25422d610888e44bcc1936234b160774f2e60e83dc8bd9d9b3ff43ddb6195b5ea6baec08544088e562f86b439a252de76c20d3bc8',
    allowedEvaluatorOpsHash:
        'ca576ed087e0fbddd7e82bb439610a4e3c3c761bce521363a2ed7d6fbc1c836dbf97c42fa0acb645007452f52365ba27ca42d8382ea582ab27b23ddf38b30498',
    securityEstimatorInputHash:
        '4bce752346f1caf9652f456f27645da0a19ff8c9cf5376eef941d9cb4411e22fa4c2f8eaf8707df98b7a48318ef3987ba85e656143e71587d68e16edfdb2f428',
    encodedPlaintextRoot:
        '58c345519637224053f85635ecd8493f74a42bc6b44fcd889571bf73e44ea0534de25677efec1b2efff76f64d17735debb527c787db0b8057a59458e004bfb3c',
    encodedPlaintextHash:
        '02dd5e48be07c2bc343db89c7566f907b0bc319b56feb4ea0d6fa9a40a9f65829346a2ea08a576342c8dccce1a098e31f553c60726b1a76c1a77ae4a57cf426e',
    ciphertextRoot:
        'ea667f7e46ffa85907186697546c29f810e32559acf366bd7fe646be10638a0e6b6d4946fc7a3cade59e468ac65b12cc5115c8ed89f4d1111bd92a7a2b4dd0b6',
    ciphertextHash:
        '63844b4aa643a6e261ddc4d9acf28c2cb6836a50079ce34aa9a18296505b83eda7c14686e212c728d3fd877bbfa2f2c41a33f58817fc328c66ff738f460472ba',
    baseConversionSourceRoot:
        '84e9322792461a7bfaf4026c23edeed8ec836c6cae265ad7dfdb3402fa78a0f2aac858db22395c30b5154d46528fc0b989b44866a6bce536fb4fc8a863a45416',
    baseConversionConvertedRoot:
        '4f5642198725dddac839c179cc88138f8617d84b564e5b974d193c1d6003a599714c6ce4b7992dfec7bd03b1b4966e8e71dbc992930b1991ad5a72bac27a6672',
} as const;

describe('BGV-RNS backend kernel commands', () => {
    it('describes the BGV-RNS profile and operation boundary', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const profile = kernel.describeBgvRnsProfile();
        const operationRegistry = kernel.describeBgvOperationRegistry() as {
            readonly registry: {
                readonly allowedOperations: readonly string[];
                readonly forbiddenOperations: readonly string[];
            };
            readonly allowedEvaluatorOpsHash: string;
        };

        expect(profile.profile).toMatchObject({
            profileId: 'sealed-lattice-bgv-rns-v1',
            polynomialDegree: 32_768,
            plaintextModulus: 65_537,
            dataPrimeBitLength: 47,
            dataLevels: 16,
            extendedLevels: 17,
        });
        expect(profile.profile.dataPrimes).toHaveLength(16);
        expect(profile.profileHash).toBe(stableBgvHashVectors.profileHash);
        expect(profile.batchEncoderHash).toBe(
            stableBgvHashVectors.batchEncoderHash,
        );
        expect(profile.batchLayoutBindingHash).toBe(
            stableBgvHashVectors.batchLayoutBindingHash,
        );
        expect(profile.encodedAggregateLayoutHash).toBe(
            stableBgvHashVectors.encodedAggregateLayoutHash,
        );
        expect(profile.topKEvaluatorInputLayoutHash).toBe(
            stableBgvHashVectors.topKEvaluatorInputLayoutHash,
        );
        expect(profile.canonicalCiphertextConventionHash).toBe(
            stableBgvHashVectors.canonicalCiphertextConventionHash,
        );
        expect(profile.allowedEvaluatorOpsHash).toBe(
            stableBgvHashVectors.allowedEvaluatorOpsHash,
        );
        expect(profile.securityEstimatorInputHash).toBe(
            stableBgvHashVectors.securityEstimatorInputHash,
        );
        expect(profile.batchLayoutBinding).toMatchObject({
            layoutKind: 'EncryptedAggregateInputEncodedScoreLayout-v1',
            coordinateOrder:
                'score-share-then-one-hot-score-buckets-per-option',
            oneHotBucketOrder: 'ascending-score-1-through-10',
            scoreBucketCount: 10,
            scalarOnlyAggregateLayout: false,
        });
        expect(operationRegistry.allowedEvaluatorOpsHash).toBe(
            stableBgvHashVectors.allowedEvaluatorOpsHash,
        );
        expect(operationRegistry.registry.allowedOperations).toContain(
            'homomorphicAggregateShareAddition',
        );
        expect(operationRegistry.registry.forbiddenOperations).toContain(
            'scalarDegree360Comparator',
        );
        expect(operationRegistry).not.toHaveProperty(
            'forbiddenOperationRejectionFixtures',
        );
    });

    it('encodes aggregate-share EncryptedAggregateInput slots and validates roots byte-identically', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const profile = kernel.describeBgvRnsProfile();
        const encodedResult = kernel.encodeBgvBatchPlaintext({
            slots: [0, 1, 65_536, 17, 99],
            level: 0,
            layoutBinding: profile.batchLayoutBinding,
            includeCanonicalBytesHex: true,
        });

        expect(encodedResult).not.toMatchObject({ ok: false });
        const encoded = encodedResult as Exclude<
            typeof encodedResult,
            BgvProfileRejected
        >;
        expect(encoded.validation.ok).toBe(true);
        expect(encoded.canonicalBytesHex).toMatch(/^[a-f0-9]+$/u);
        expect(encoded.plaintextRoot).toBe(
            stableBgvHashVectors.encodedPlaintextRoot,
        );
        expect(encoded.canonicalBytesHash512).toBe(
            stableBgvHashVectors.encodedPlaintextHash,
        );
        expect(encoded.canonicalByteLength).toBe(90_441);
        expect(encoded.batchLayoutBindingHash).toBe(
            profile.batchLayoutBindingHash,
        );
        expect(encoded.statusLabels).toContain(
            'EncryptedAggregateInputLayoutBound',
        );
        expect(encoded.sampledSlots).toEqual(
            expect.arrayContaining([
                { position: 0, value: 0 },
                { position: 1, value: 1 },
                { position: 2, value: 65_536 },
            ]),
        );

        const validated = kernel.validateBgvPlaintextObject({
            canonicalBytesHex: encoded.canonicalBytesHex ?? '',
            expectedPlaintextRoot: encoded.plaintextRoot,
        });
        const analyzed = kernel.analyzeBgvCanonicalObject({
            canonicalBytesHex: encoded.canonicalBytesHex ?? '',
        }) as {
            readonly objectKind: string;
            readonly coefficientCount: number;
        };

        expect(validated).toMatchObject({
            ok: true,
            objectKind: 'plaintext',
            plaintextRoot: encoded.plaintextRoot,
            canonicalBytesHash512: encoded.canonicalBytesHash512,
        });
        expect(analyzed).toMatchObject({
            objectKind: 'plaintext',
            coefficientCount: 32_768,
        });
        expectKernelCommandError(
            () =>
                kernel.validateBgvPlaintextObject({
                    canonicalBytesHex: encoded.canonicalBytesHex ?? '',
                    expectedPlaintextRoot: '0'.repeat(128),
                }),
            'ProfileComponentMismatch',
            /plaintext root/u,
        );
        const layoutHashHex = Buffer.from(
            profile.encryptedAggregateInputLayoutHash,
            'utf8',
        ).toString('hex');
        const wrongLayoutCanonicalBytesHex = (
            encoded.canonicalBytesHex ?? ''
        ).replace(
            layoutHashHex,
            Buffer.from('0'.repeat(128), 'utf8').toString('hex'),
        );
        expectKernelCommandError(
            () =>
                kernel.validateBgvPlaintextObject({
                    canonicalBytesHex: wrongLayoutCanonicalBytesHex,
                }),
            'ProfileComponentMismatch',
            /layout/u,
        );

        const layoutMutations: readonly Record<string, unknown>[] = [
            {
                ...(profile.batchLayoutBinding as Record<string, unknown>),
                coordinateOrder: 'one-hot-score-buckets-then-score-share',
            },
            {
                ...(profile.batchLayoutBinding as Record<string, unknown>),
                oneHotBucketOrder: 'descending-score-10-through-1',
            },
            {
                ...(profile.batchLayoutBinding as Record<string, unknown>),
                scoreBucketCount: 9,
            },
            {
                ...(profile.batchLayoutBinding as Record<string, unknown>),
                ballotScoreEncodingProfileHash: '0'.repeat(128),
            },
            {
                ...(profile.batchLayoutBinding as Record<string, unknown>),
                encodedAggregateLayoutHash: '0'.repeat(128),
            },
            {
                ...(profile.batchLayoutBinding as Record<string, unknown>),
                scalarOnlyAggregateLayout: true,
            },
        ];
        for (const layoutBinding of layoutMutations) {
            expectKernelCommandError(
                () =>
                    kernel.encodeBgvBatchPlaintext({
                        slots: [1, 2, 3],
                        level: 0,
                        layoutBinding,
                    }),
                'ProfileComponentMismatch',
                /layout binding/u,
            );
        }
    });

    it('rejects evaluator operations outside the selected registry', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(
            kernel.validateBgvEvaluatorOperation({
                operation: 'homomorphicAggregateShareAddition',
            }),
        ).toMatchObject({
            ok: true,
            acceptedOperation: 'homomorphicAggregateShareAddition',
        });
        expectBgvProfileRejected(
            kernel.validateBgvEvaluatorOperation({
                operation: 'scalarDegree360Comparator',
            }),
            'ForbiddenEvaluatorOperation',
        );
        expectBgvProfileRejected(
            kernel.validateBgvEvaluatorOperation({
                operation: 'uncertifiedScoreBitDerivationOperation',
            }),
            'ForbiddenEvaluatorOperation',
        );
        expectBgvProfileRejected(
            kernel.validateBgvEvaluatorOperation({
                operation: 'adHocEncryptedComparator',
            }),
            'UncertifiedEvaluatorOperation',
        );
    });

    it('validates ciphertext convention fixtures without claiming encryption evidence', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const fixtureResult = kernel.generateBgvCiphertextConventionFixture({
            leftSlots: [1, 2, 3],
            rightSlots: [4, 5, 6],
            includeCanonicalBytesHex: true,
        });
        expect(fixtureResult).not.toMatchObject({ ok: false });
        const fixture = fixtureResult as Exclude<
            typeof fixtureResult,
            BgvProfileRejected
        >;

        expect(fixture.statusLabels).toContain('NotEncryptionEvidence');
        expect(fixture.ciphertextRoot).toBe(
            stableBgvHashVectors.ciphertextRoot,
        );
        expect(fixture.canonicalBytesHash512).toBe(
            stableBgvHashVectors.ciphertextHash,
        );
        expect(fixture.canonicalByteLength).toBe(180_781);
        expect(fixture.validation).toMatchObject({
            ok: true,
            objectKind: 'ciphertext',
            ciphertextRoot: fixture.ciphertextRoot,
        });
        expect(
            kernel.validateBgvCiphertextObject({
                canonicalBytesHex: fixture.canonicalBytesHex ?? '',
                expectedCiphertextRoot: fixture.ciphertextRoot,
            }),
        ).toMatchObject({
            ok: true,
            objectKind: 'ciphertext',
            ciphertextRoot: fixture.ciphertextRoot,
        });
    });

    it('keeps base conversion and oracle material inside the BGV boundary', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const baseConversionResult = kernel.generateBgvBaseConversionFixture({
            slots: [7, 8, 9, 65_536],
        });
        expect(baseConversionResult).not.toMatchObject({ ok: false });
        const baseConversion = baseConversionResult as Exclude<
            typeof baseConversionResult,
            BgvProfileRejected
        >;
        const oracleRejection = kernel.rejectBgvReferenceOracleArtifact({
            artifact: {
                artifactKind: 'lattigo-development-oracle-vector',
                protocolEvidence: false,
            },
        });

        expect(baseConversion).toMatchObject({
            convertedBasisId: 'sealed-lattice-bgv-rns-extended-basis-v1',
            convertedModulusCount: 2,
        });
        expect(baseConversion.sourcePlaintextRoot).toBe(
            stableBgvHashVectors.baseConversionSourceRoot,
        );
        expect(baseConversion.convertedPlaintextRoot).toBe(
            stableBgvHashVectors.baseConversionConvertedRoot,
        );
        expect(baseConversion.statusLabels).toContain(
            'GenericKeySwitchSurfaceNotExported',
        );
        expect(oracleRejection).toMatchObject({
            ok: false,
            acceptedAsProtocolEvidence: false,
        });
        expect(oracleRejection.statusLabels).toEqual(
            expect.arrayContaining([
                'ReferenceOracleRejected',
                'LattigoSerializationRejected',
                'RuntimeOracleDependencyRejected',
            ]),
        );
    });
});
