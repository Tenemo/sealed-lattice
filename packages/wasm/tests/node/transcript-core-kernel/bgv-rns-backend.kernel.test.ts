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

const expectProtocolHash = (value: string, label: string): void => {
    expect(value, label).toMatch(/^[a-f0-9]{128}$/u);
};

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
        const batchLayoutBinding = profile.batchLayoutBinding as {
            readonly directAggregateLayoutHash: string;
            readonly encryptedBallotAggregateLayoutHash: string;
            readonly directComparisonProfileHash: string;
        };
        const directBallotEncoderMatrix = profile.directBallotEncoderMatrix as {
            readonly basisVectorHashes: readonly {
                readonly optionIndex: number;
                readonly sourceSlotIndex: number;
                readonly basisVectorHash: string;
            }[];
        };

        expect(profile.profile).toMatchObject({
            profileId: 'sealed-lattice-bgv-rns-v1',
            polynomialDegree: 32_768,
            plaintextModulus: 65_537,
            dataPrimeBitLength: 47,
            dataLevels: 17,
            extendedLevels: 18,
        });
        expect(profile.profile.dataPrimes).toHaveLength(17);
        for (const [label, value] of [
            ['profileHash', profile.profileHash],
            ['batchEncoderHash', profile.batchEncoderHash],
            ['batchLayoutBindingHash', profile.batchLayoutBindingHash],
            [
                'ballotScoreEncodingProfileHash',
                profile.ballotScoreEncodingProfileHash,
            ],
            ['encryptedBallotLayoutHash', profile.encryptedBallotLayoutHash],
            [
                'directBallotReservedSlotRuleHash',
                profile.directBallotReservedSlotRuleHash,
            ],
            [
                'directBallotEncoderMatrixRoot',
                profile.directBallotEncoderMatrixRoot,
            ],
            ['directAggregateLayoutHash', profile.directAggregateLayoutHash],
            [
                'directComparisonProfileHash',
                profile.directComparisonProfileHash,
            ],
            [
                'canonicalCiphertextConventionHash',
                profile.canonicalCiphertextConventionHash,
            ],
            ['allowedEvaluatorOpsHash', profile.allowedEvaluatorOpsHash],
            ['securityEstimatorInputHash', profile.securityEstimatorInputHash],
        ] as const) {
            expectProtocolHash(value, label);
        }
        expect(profile.batchLayoutBinding).toMatchObject({
            layoutKind: 'DirectEncryptedBallotAggregateLayout-v1',
            coordinateOrder:
                'encrypted-score-then-one-hot-score-buckets-per-option',
            oneHotBucketOrder: 'ascending-score-1-through-10',
            scoreBucketCount: 10,
            scalarOnlyAggregateLayout: false,
        });
        expect(profile.directBallotReservedSlotRule).toMatchObject({
            objectType: 'DirectBallotReservedSlotRule',
            objectVersion: 1,
            optionCount: 20,
            scoreSlotCount: 20,
            reservedSlotStartInclusive: 20,
            reservedSlotEndExclusive: 32_768,
            reservedSlotCount: 32_748,
            plaintextModulus: 65_537,
            polynomialDegree: 32_768,
        });
        expect(profile.directBallotEncoderMatrix).toMatchObject({
            objectType: 'DirectBallotEncoderMatrix',
            objectVersion: 1,
            encoderId: 'BGVBatchEncode_65537-v1',
            profileHash: profile.profileHash,
            reservedSlotRuleHash: profile.directBallotReservedSlotRuleHash,
            optionCount: 20,
            scoreSlotCount: 20,
            plaintextModulus: 65_537,
            polynomialDegree: 32_768,
        });
        expect(directBallotEncoderMatrix.basisVectorHashes).toHaveLength(20);
        expect(directBallotEncoderMatrix.basisVectorHashes[0]).toMatchObject({
            optionIndex: 0,
            sourceSlotIndex: 0,
        });
        expectProtocolHash(
            directBallotEncoderMatrix.basisVectorHashes[0]?.basisVectorHash ??
                '',
            'first direct ballot encoder basis vector hash',
        );
        expect(operationRegistry.allowedEvaluatorOpsHash).toBe(
            profile.allowedEvaluatorOpsHash,
        );
        expect(batchLayoutBinding.directAggregateLayoutHash).toBe(
            profile.directAggregateLayoutHash,
        );
        expect(batchLayoutBinding.directComparisonProfileHash).toBe(
            profile.directComparisonProfileHash,
        );
        expect(batchLayoutBinding.encryptedBallotAggregateLayoutHash).toBe(
            profile.encryptedBallotAggregateLayoutHash,
        );
        expect(operationRegistry.registry.allowedOperations).toContain(
            'homomorphicEncryptedBallotAggregation',
        );
        expect(operationRegistry.registry.forbiddenOperations).toContain(
            'scalarDegree360Comparator',
        );
        expect(operationRegistry).not.toHaveProperty(
            'forbiddenOperationRejectionFixtures',
        );
    });

    it('encodes direct encrypted ballot aggregate slots and validates roots byte-identically', async () => {
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
        expectProtocolHash(encoded.plaintextRoot, 'encoded plaintext root');
        expectProtocolHash(
            encoded.canonicalBytesHash512,
            'encoded plaintext canonical bytes hash',
        );
        expect(encoded.canonicalByteLength).toBe(90_441);
        expect(encoded.batchLayoutBindingHash).toBe(
            profile.batchLayoutBindingHash,
        );
        expect(encoded.statusLabels).toContain(
            'DirectEncryptedBallotAggregateLayoutBound',
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
            profile.encryptedBallotAggregateLayoutHash,
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
                directAggregateLayoutHash: '0'.repeat(128),
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
                operation: 'homomorphicEncryptedBallotAggregation',
            }),
        ).toMatchObject({
            ok: true,
            acceptedOperation: 'homomorphicEncryptedBallotAggregation',
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
            'UncertifiedEvaluatorOperation',
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
        expectProtocolHash(fixture.ciphertextRoot, 'ciphertext root');
        expectProtocolHash(
            fixture.canonicalBytesHash512,
            'ciphertext canonical bytes hash',
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
        expectProtocolHash(
            baseConversion.sourcePlaintextRoot,
            'base conversion source plaintext root',
        );
        expectProtocolHash(
            baseConversion.convertedPlaintextRoot,
            'base conversion converted plaintext root',
        );
        expect(baseConversion.convertedPlaintextRoot).not.toBe(
            baseConversion.sourcePlaintextRoot,
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
