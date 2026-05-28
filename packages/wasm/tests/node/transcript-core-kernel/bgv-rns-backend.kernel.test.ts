import { describe, expect, it } from 'vitest';

import {
    loadTranscriptCoreKernel,
    TranscriptCoreKernelCommandError,
} from '../../../src/index';

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
        'a4174e452575ce1e5a879a7c21c0d30c00fd05547a276f630cf5d5f5cb25810870715436230bc4db244209bdd75794c3b59f5d4b2435052a8eac00041fd137f5',
    batchLayoutBindingHash:
        '3bb25a676dc61ef33169966d56979638fc95efa887339506919d0c1ba64ec881c96d98453a7f2cc1d31b5eca7ce8b132022a12d3b58a1fe22c4355beaee58d6e',
    encodedAggregateLayoutHash:
        '4148f281d5a2bee306e19b55b2f74b8dff3454c4aa647873fa146819cbc163604772ef84cb6499296fa64a6402c197028d6c3cb852c85537bce3d3388656f49c',
    topKEvaluatorInputLayoutHash:
        '6247fcd31bfc8f451440ab8523b120ceb6a2f75b18477a1b7d947076b7f302dd65eb6a9e5d18be2e475572fefa46c7db3f48ec5827c84469bae410ac6226c85f',
    canonicalCiphertextConventionHash:
        'f12e731e1096504c1ade1fb25422d610888e44bcc1936234b160774f2e60e83dc8bd9d9b3ff43ddb6195b5ea6baec08544088e562f86b439a252de76c20d3bc8',
    allowedEvaluatorOpsHash:
        'b0cd268f310023b6341b730d146d0376721fc67ac5a7a9aaef468047cc0bbb8c9f5bbd333aaf0d3d2dbbe558705148731e7d40bd23d04dedd619f6b41873696f',
    securityEstimatorInputHash:
        '4bce752346f1caf9652f456f27645da0a19ff8c9cf5376eef941d9cb4411e22fa4c2f8eaf8707df98b7a48318ef3987ba85e656143e71587d68e16edfdb2f428',
    encodedPlaintextRoot:
        '92cf108ea1bf78bf8b4acff606df99b2b5d342fe8caac81f1dbc3eaa166b31bf61b2453d57630109422b14e9cbdf8cf327ce56793cb676a10888c5f6c1c12edd',
    encodedPlaintextHash:
        'd77e7936e25849fa95ac455dd4b1e2502b9f502491d0657c41035b0c91aa625762f77bdd6e24c236417eeab50d7afdeea376cabf1d737df587de3932b9fc641e',
    ciphertextRoot:
        '656a13bf2071f4def2cc2de14c41bea2c866c5c78eeedd64074a85c43caf5011eca8d78241f9e0705070d66bc9fb6dceb55cabf5f5fc2dcfa9c7e235284cc87f',
    ciphertextHash:
        '842135a9284e37b74a4ad6ab7c350449d1126efa3d15a68b1004d8b481adb40e790bd6b0cbc266b6d138ce297d6e9b6c6333900603ab3d5775a76882729159ed',
    baseConversionSourceRoot:
        '170b5c709ce3230aa0f731a4973ccb2fb3e1620fc9c8b60c57406b2443c51c69dcc3e97f2134de9af53f1f2735ed618033b89d4cdcadd7d641ad00848c35ba06',
    baseConversionConvertedRoot:
        'f3c721f6e0cf872460caf3b4d52bb7aaabea964d0f1977639f17ae43fa4812a657fbe82f51216c1470a56b9cbf3823ca9dd787f8a10199260b09ee6600118c80',
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
