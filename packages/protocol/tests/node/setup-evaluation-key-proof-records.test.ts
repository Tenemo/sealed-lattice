import { deriveCanonicalObjectHash, hash512Hex } from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import { deriveCollectiveBgvSetupContextHash } from '#packages/protocol/src/setup/common-fields';
import {
    createBinaryChunkedEvaluationKeyShareMaterialTransport,
    createGaloisKeyShareBatches,
    createRelinearizationKeyShareRounds,
    createTrusteeEvaluationKeyProofs,
    evaluationKeyShareComponentVectorRoot,
    type EvaluationKeyProofCommonInput,
    type EvaluationKeyShareComponentMaterialChunkSource,
    type EvaluationKeyShareComponentMaterialWriter,
    type EvaluationKeyShareMaterial,
    type EvaluationKeyTrusteeReference,
    type GaloisKeyShareBatchContribution,
    type RelinearizationRoundOneContribution,
    type RelinearizationRoundTwoContribution,
    type TrusteeEvaluationKeyProofGenerator,
    type TrusteeEvaluationKeyWitnessInput,
} from '#packages/protocol/src/setup/evaluation-key-proof-records';
import { evaluationKeyShareComponentMaterialReferenceRoot } from '#packages/protocol/src/setup/evaluation-key-proof-records/encoding';
import type {
    EvaluatorKeySchedule,
    RequiredGaloisKeyScheduleEntry,
} from '#packages/protocol/src/setup/evaluator-key-schedule';
import type { VssSameSecretBridgeStatementSet } from '#packages/protocol/src/setup/vss-commitments';
import {
    makeSetupContext,
    makeSetupFixtureHash,
} from '#tests/support/setup-fixtures';

type JsonRecord = Record<string, unknown>;
type TrusteeEvaluationKeyProofGeneratorInput =
    Parameters<TrusteeEvaluationKeyProofGenerator>[0];
type RelinearizationKeyShareRoundsInput = Parameters<
    typeof createRelinearizationKeyShareRounds
>[0];
type GaloisKeyShareBatchesInput = Parameters<
    typeof createGaloisKeyShareBatches
>[0];
type TrusteeEvaluationKeyProofsInput = Parameters<
    typeof createTrusteeEvaluationKeyProofs
>[0];
type EvaluationKeyShareMaterialTransportInput = Parameters<
    typeof createBinaryChunkedEvaluationKeyShareMaterialTransport
>[0];
type EvaluationKeyShareComponentMaterialTransportInput =
    EvaluationKeyShareMaterialTransportInput['relinearizationRoundOneContributions'][number]['shareMaterial'];
type SourceRelinearizationContribution =
    EvaluationKeyShareMaterialTransportInput['relinearizationRoundOneContributions'][number];

const qSharePrimes = [
    140_737_487_306_753, 140_737_486_716_929, 140_737_486_520_321,
] as const;
const participantCount = 2;
const scheduledLevel = 1;
const ringDegree = 8;
const digitCount = scheduledLevel + 1;
const canonicalChunkByteLength = 1_048_576;

const fixtureHash = makeSetupFixtureHash('setup-evaluation-key-proof-records');

const canonicalStreamDescriptor = (
    totalByteLength: bigint,
    chunkHashBytes: readonly number[],
    fullObjectHashByte = 0x42,
): Uint8Array => {
    const descriptorBytes = new Uint8Array(104 + 64 * chunkHashBytes.length);
    const view = new DataView(descriptorBytes.buffer);
    view.setUint16(0, 0x1800, true);
    view.setUint16(2, 1, true);
    view.setUint32(4, 3, true);

    let byteOffset = 8;
    view.setUint16(byteOffset, 0x05, true);
    view.setUint32(byteOffset + 2, 8, true);
    view.setBigUint64(byteOffset + 6, totalByteLength, true);
    byteOffset += 14;

    view.setUint16(byteOffset, 0x0e, true);
    view.setUint32(byteOffset + 2, 6 + 64 * chunkHashBytes.length, true);
    view.setUint16(byteOffset + 6, 0x06, true);
    view.setUint32(byteOffset + 8, chunkHashBytes.length, true);
    byteOffset += 12;
    for (const chunkHashByte of chunkHashBytes) {
        descriptorBytes.fill(chunkHashByte, byteOffset, byteOffset + 64);
        byteOffset += 64;
    }

    view.setUint16(byteOffset, 0x06, true);
    view.setUint32(byteOffset + 2, 64, true);
    descriptorBytes.fill(fullObjectHashByte, byteOffset + 6, byteOffset + 70);

    return descriptorBytes;
};

const setupContext = makeSetupContext(fixtureHash, participantCount);
const setupContextHash = deriveCollectiveBgvSetupContextHash(setupContext);

const requiredGaloisKeySchedule = [
    {
        rotation: 3,
        level: scheduledLevel,
    },
    {
        rotation: 7,
        level: scheduledLevel,
    },
] as const satisfies readonly RequiredGaloisKeyScheduleEntry[];

const evaluatorKeySchedule = (): EvaluatorKeySchedule => {
    const scheduleWithoutRoot = {
        objectType: 'EvaluatorKeySchedule',
        setupContextHash,
        publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
        publicKeyShareSetRoot: fixtureHash('public-key-share-set'),
        relinearizationLevelSchedule: [{ level: scheduledLevel }],
        requiredGaloisKeySchedule,
    } as const satisfies Omit<EvaluatorKeySchedule, 'evaluatorKeyScheduleRoot'>;

    return {
        ...scheduleWithoutRoot,
        evaluatorKeyScheduleRoot:
            deriveCanonicalObjectHash(scheduleWithoutRoot),
    } satisfies EvaluatorKeySchedule;
};

const trusteeReferences = (): readonly EvaluationKeyTrusteeReference[] =>
    Array.from(
        { length: participantCount },
        (_unused, trusteeRosterPosition) => ({
            trusteeIdentity: `trustee-${String(trusteeRosterPosition)}`,
            trusteeRosterPosition,
        }),
    );

const trusteeIdentityAtPosition = (trusteeRosterPosition: number): string =>
    `trustee-${String(trusteeRosterPosition)}`;

const relinearizationKeySwitchSeed = (
    schedule: EvaluatorKeySchedule,
    round: 'round-one' | 'round-two',
    level: number,
): string =>
    deriveCanonicalObjectHash({
        objectType: 'RelinearizationKeySwitchPublicSampleSeed',
        publicMatrixSeedHash: schedule.publicMatrixSeedHash,
        evaluatorKeyScheduleRoot: schedule.evaluatorKeyScheduleRoot,
        round,
        level,
    });

const galoisKeySwitchSeed = (
    schedule: EvaluatorKeySchedule,
    rotation: number,
    level: number,
): string =>
    deriveCanonicalObjectHash({
        objectType: 'GaloisKeySwitchPublicSampleSeed',
        publicMatrixSeedHash: schedule.publicMatrixSeedHash,
        evaluatorKeyScheduleRoot: schedule.evaluatorKeyScheduleRoot,
        rotation,
        level,
    });

const coefficientsToLittleEndianHex = (
    coefficients: readonly number[],
): string =>
    coefficients
        .map((coefficient) => {
            let remainingValue = BigInt(coefficient);
            let hex = '';
            for (let byteIndex = 0; byteIndex < 8; byteIndex += 1) {
                hex += (remainingValue & 0xffn).toString(16).padStart(2, '0');
                remainingValue >>= 8n;
            }

            return hex;
        })
        .join('');

// Deterministic small canonical residues, distinct per share label so every
// share carries different public component vectors.
const componentCoefficients = (
    label: string,
    digitIndex: number,
    rnsLimbIndex: number,
): number[] =>
    Array.from({ length: ringDegree }, (_unused, coefficientIndex) => {
        let labelWeight = 0;
        for (
            let characterIndex = 0;
            characterIndex < label.length;
            characterIndex += 1
        ) {
            labelWeight =
                (labelWeight * 31 + label.charCodeAt(characterIndex)) % 9973;
        }

        return (
            (labelWeight * 7919 +
                digitIndex * 1013 +
                rnsLimbIndex * 211 +
                coefficientIndex * 17 +
                1) %
            65521
        );
    });

const componentVectorEntries = (label: string): JsonRecord[] => {
    const entries: JsonRecord[] = [];
    for (let digitIndex = 0; digitIndex < digitCount; digitIndex += 1) {
        for (
            let rnsLimbIndex = 0;
            rnsLimbIndex < digitCount;
            rnsLimbIndex += 1
        ) {
            const coefficients = componentCoefficients(
                label,
                digitIndex,
                rnsLimbIndex,
            );
            entries.push({
                digitIndex,
                rnsLimbIndex,
                rnsPrime: qSharePrimes[rnsLimbIndex],
                coefficientsLeHex: coefficientsToLittleEndianHex(coefficients),
            });
        }
    }

    return entries;
};

const expectedRoundOneAggregateDiagonal = (): number[][] =>
    Array.from({ length: digitCount }, (_unusedDigit, digitIndex) =>
        Array.from(
            { length: ringDegree },
            (_unusedCoefficient, coefficientIndex) =>
                (componentCoefficients('round-one-0', digitIndex, digitIndex)[
                    coefficientIndex
                ] +
                    componentCoefficients(
                        'round-one-1',
                        digitIndex,
                        digitIndex,
                    )[coefficientIndex]) %
                qSharePrimes[digitIndex],
        ),
    );

const expectedStatementKeyBindings = (
    schedule: EvaluatorKeySchedule,
): readonly (readonly [string, number | null, string, string])[] => [
    ...(['round-one', 'round-two'] as const).map(
        (round) =>
            [
                `relinearization-${round}`,
                null,
                'relinearization',
                relinearizationKeySwitchSeed(schedule, round, scheduledLevel),
            ] as const,
    ),
    ...requiredGaloisKeySchedule.map(
        (scheduleEntry) =>
            [
                'galois-rotation',
                scheduleEntry.rotation,
                `galois-${String(scheduleEntry.rotation)}`,
                galoisKeySwitchSeed(
                    schedule,
                    scheduleEntry.rotation,
                    scheduleEntry.level,
                ),
            ] as const,
    ),
];

const componentMaterialTransportInput = (
    proofFamily: 'relinearization-key-share' | 'galois-key-share',
    keySwitchDomain: string,
    keySwitchSeedHex: string,
    label: string,
): EvaluationKeyShareComponentMaterialTransportInput => {
    const entries = componentVectorEntries(label);

    return {
        keySwitchDomain,
        keySwitchSeedHex,
        ringDegree,
        keySwitchComponentVectorRoot: evaluationKeyShareComponentVectorRoot(
            proofFamily,
            keySwitchDomain,
            keySwitchSeedHex,
            scheduledLevel,
            ringDegree,
            entries,
        ),
        keySwitchComponentVectors: entries,
    };
};

const transportedShareMaterial = (
    proofFamily: 'relinearization-key-share' | 'galois-key-share',
    sourceMaterial: EvaluationKeyShareComponentMaterialTransportInput,
    trusteeIdentity: string,
    trusteeRosterPosition: number,
    level: number,
): EvaluationKeyShareMaterial => ({
    keySwitchDomain: sourceMaterial.keySwitchDomain,
    keySwitchSeedHex: sourceMaterial.keySwitchSeedHex,
    ringDegree: sourceMaterial.ringDegree,
    keySwitchComponentVectorRoot: sourceMaterial.keySwitchComponentVectorRoot,
    keySwitchMaterialEncoding: 'binary-chunked-key-switch-component-vectors',
    keySwitchComponentMaterialRoot:
        evaluationKeyShareComponentMaterialReferenceRoot(
            proofFamily,
            sourceMaterial,
            trusteeIdentity,
            trusteeRosterPosition,
            level,
        ),
});

const sourceRelinearizationContributions = (
    schedule: EvaluatorKeySchedule,
    round: 'round-one' | 'round-two',
): SourceRelinearizationContribution[] =>
    Array.from(
        { length: participantCount },
        (_unused, trusteeRosterPosition) => ({
            trusteeRosterPosition,
            level: scheduledLevel,
            shareMaterial: componentMaterialTransportInput(
                'relinearization-key-share',
                'relinearization',
                relinearizationKeySwitchSeed(schedule, round, scheduledLevel),
                `${round}-${String(trusteeRosterPosition)}`,
            ),
        }),
    );

const transportedRelinearizationContributions = (
    contributions: readonly SourceRelinearizationContribution[],
): RelinearizationRoundOneContribution[] =>
    contributions.map((contribution) => ({
        ...contribution,
        shareMaterial: transportedShareMaterial(
            'relinearization-key-share',
            contribution.shareMaterial,
            trusteeIdentityAtPosition(contribution.trusteeRosterPosition),
            contribution.trusteeRosterPosition,
            contribution.level,
        ),
    }));

type EvaluationKeyFixture = Readonly<{
    schedule: EvaluatorKeySchedule;
    commonInput: EvaluationKeyProofCommonInput;
    roundOneContributions: RelinearizationRoundOneContribution[];
    roundTwoContributions: RelinearizationRoundTwoContribution[];
    batchContributions: GaloisKeyShareBatchContribution[];
    sourceRoundOneContributions: EvaluationKeyShareMaterialTransportInput['relinearizationRoundOneContributions'];
    sourceRoundTwoContributions: EvaluationKeyShareMaterialTransportInput['relinearizationRoundTwoContributions'];
    sourceBatchContributions: EvaluationKeyShareMaterialTransportInput['galoisKeyShareBatchContributions'];
}>;

const evaluationKeyFixture = (): EvaluationKeyFixture => {
    const schedule = evaluatorKeySchedule();
    const commonInput = {
        setupContext,
        qSharePrimes,
        participantCount,
        evaluatorKeySchedule: schedule,
        publicKeyShareSuccinctProofSetRoot: fixtureHash(
            'public-key-share-lnp-proof-set',
        ),
        trusteeReferences: trusteeReferences(),
    } satisfies EvaluationKeyProofCommonInput;
    const sourceRoundOneContributions = sourceRelinearizationContributions(
        schedule,
        'round-one',
    );
    const sourceRoundTwoContributions = sourceRelinearizationContributions(
        schedule,
        'round-two',
    );
    const sourceBatchContributions = Array.from(
        { length: participantCount },
        (_unused, trusteeRosterPosition) => ({
            trusteeRosterPosition,
            galoisKeyShares: requiredGaloisKeySchedule.map((scheduleEntry) => {
                const shareMaterial = componentMaterialTransportInput(
                    'galois-key-share',
                    `galois-${String(scheduleEntry.rotation)}`,
                    galoisKeySwitchSeed(
                        schedule,
                        scheduleEntry.rotation,
                        scheduleEntry.level,
                    ),
                    `galois-${String(scheduleEntry.rotation)}-${String(trusteeRosterPosition)}`,
                );

                return {
                    rotation: scheduleEntry.rotation,
                    level: scheduleEntry.level,
                    shareMaterial,
                };
            }),
        }),
    );
    const roundOneContributions = transportedRelinearizationContributions(
        sourceRoundOneContributions,
    );
    const roundTwoContributions = transportedRelinearizationContributions(
        sourceRoundTwoContributions,
    );
    const batchContributions = sourceBatchContributions.map(
        (batchContribution) => ({
            ...batchContribution,
            galoisKeyShares: batchContribution.galoisKeyShares.map(
                (contribution) => ({
                    ...contribution,
                    shareMaterial: transportedShareMaterial(
                        'galois-key-share',
                        contribution.shareMaterial,
                        trusteeIdentityAtPosition(
                            batchContribution.trusteeRosterPosition,
                        ),
                        batchContribution.trusteeRosterPosition,
                        contribution.level,
                    ),
                }),
            ),
        }),
    );

    return {
        schedule,
        commonInput,
        roundOneContributions,
        roundTwoContributions,
        batchContributions,
        sourceRoundOneContributions,
        sourceRoundTwoContributions,
        sourceBatchContributions,
    };
};

const trusteeEvaluationKeyProofBytesHash = (proofBytesHex: string): string => {
    const bytes = Uint8Array.from(
        Array.from({ length: proofBytesHex.length / 2 }, (_unused, byteIndex) =>
            Number.parseInt(
                proofBytesHex.slice(byteIndex * 2, byteIndex * 2 + 2),
                16,
            ),
        ),
    );

    return hash512Hex(
        'sealed-lattice/setup/trustee-evaluation-key/proof-bytes',
        [bytes],
    );
};

const statementKeyCount = 2 + requiredGaloisKeySchedule.length;

const stubProofBytesHex = (trusteeRosterPosition: number): string =>
    `00112233445566${trusteeRosterPosition.toString(16).padStart(2, '0')}`;

const stubGenerator = (
    capturedInputs: TrusteeEvaluationKeyProofGeneratorInput[],
): TrusteeEvaluationKeyProofGenerator => {
    return (input) => {
        capturedInputs.push(input);
        const proofBytesHex = stubProofBytesHex(
            input.context.trusteeRosterPosition,
        );
        const statementHash = fixtureHash(
            `statement-${String(input.context.trusteeRosterPosition)}`,
        );
        const proofBytesHash =
            trusteeEvaluationKeyProofBytesHash(proofBytesHex);
        const proofMaterialRoot = deriveCanonicalObjectHash({
            objectType: 'SetupProofMaterialReference',
            proofFamily: 'trustee-evaluation-key',
            proofBytesHash,
        });

        return Promise.resolve({
            statementHash,
            proofBytesHash,
            proofMaterialRoot,
            canonicalMaterial: {
                descriptorBytes: canonicalStreamDescriptor(
                    BigInt(proofBytesHex.length / 2),
                    [0x51 + input.context.trusteeRosterPosition],
                    0x61 + input.context.trusteeRosterPosition,
                ),
            },
        });
    };
};

const componentMaterialStore = (): Readonly<{
    chunks(materialRoot: string): readonly ArrayBuffer[] | undefined;
    sources(): readonly EvaluationKeyShareComponentMaterialChunkSource[];
    writer: EvaluationKeyShareComponentMaterialWriter;
}> => {
    const storedMaterial = new Map<string, readonly ArrayBuffer[]>();
    const writer: EvaluationKeyShareComponentMaterialWriter = async (input) => {
        const chunkCount = Math.ceil(
            input.totalByteLength / canonicalChunkByteLength,
        );
        const chunks: ArrayBuffer[] = [];
        for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex += 1) {
            const consumedByteLength = chunkIndex * canonicalChunkByteLength;
            const expectedByteLength = Math.min(
                canonicalChunkByteLength,
                input.totalByteLength - consumedByteLength,
            );
            const chunk = await input.pullChunk({
                chunkIndex,
                expectedByteLength,
            });
            if (chunk?.byteLength !== expectedByteLength) {
                throw new Error('The component material source was truncated.');
            }
            chunks.push(chunk.slice(0));
        }
        if (
            (await input.pullChunk({
                chunkIndex: chunkCount,
                expectedByteLength: 0,
            })) !== undefined
        ) {
            throw new Error(
                'The component material source had trailing bytes.',
            );
        }
        storedMaterial.set(input.keySwitchComponentMaterialRoot, chunks);
        const rootByte = Number.parseInt(
            input.keySwitchComponentMaterialRoot.slice(0, 2),
            16,
        );
        return canonicalStreamDescriptor(
            BigInt(input.totalByteLength),
            Array.from(
                { length: chunkCount },
                (_unused, chunkIndex) => (rootByte + chunkIndex) & 0xff,
            ),
            rootByte ^ 0xff,
        );
    };

    return {
        chunks: (materialRoot) => storedMaterial.get(materialRoot),
        writer,
        sources: () =>
            [...storedMaterial].map(([materialRoot, chunks]) => ({
                keySwitchComponentMaterialRoot: materialRoot,
                pullChunk: ({ chunkIndex, expectedByteLength }) => {
                    const chunk = chunks[chunkIndex];
                    if (chunk === undefined) {
                        return Promise.resolve(undefined);
                    }
                    if (chunk.byteLength !== expectedByteLength) {
                        throw new Error(
                            'The requested component chunk length is invalid.',
                        );
                    }
                    return Promise.resolve(chunk.slice(0));
                },
            })),
    };
};

const trusteeWitnesses = (): TrusteeEvaluationKeyWitnessInput[] =>
    Array.from(
        { length: participantCount },
        (_unused, trusteeRosterPosition) => ({
            trusteeRosterPosition,
            secretCoefficients: Array.from({ length: ringDegree }, () => 1),
            errorCoefficientsByKey: Array.from(
                { length: statementKeyCount },
                () =>
                    Array.from({ length: digitCount }, () =>
                        Array.from({ length: ringDegree }, () => 1),
                    ),
            ),
            negativeIndicatorCoefficients: Array.from(
                { length: ringDegree },
                () => 0,
            ),
            openingRandomnessByLimb: Array.from(
                { length: qSharePrimes.length },
                () => [Array.from({ length: ringDegree }, () => 1)],
            ),
        }),
    );

const sameSecretBridgeStatementSet = (): VssSameSecretBridgeStatementSet => {
    const statementRecords = trusteeReferences().map((trusteeReference) => {
        const sourceConstantCoefficientCommitments = qSharePrimes.map(
            (rnsPrime, rnsLimbIndex) => {
                const commitment = {
                    objectType: 'SetupCommitment',
                    sourceRnsLimbIndex: rnsLimbIndex,
                    sourceMessageModulus: rnsPrime,
                    shamirCoefficientIndex: 0,
                    ringDegree,
                    commitmentLimbs: [],
                } as const;

                return {
                    rnsLimbIndex,
                    rnsPrime,
                    commitment,
                } as const;
            },
        );
        const statementWithoutRoot = {
            objectType: 'VssSameSecretBridgeStatement',
            setupContextHash,
            publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
            ringDegree,
            ...trusteeReference,
            sourceConstantCoefficientCommitments,
        } as const;

        return {
            ...statementWithoutRoot,
            sameSecretBridgeStatementRoot:
                deriveCanonicalObjectHash(statementWithoutRoot),
        };
    });
    return {
        objectType: 'VssSameSecretBridgeStatementSet',
        setupContextHash,
        publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
        ringDegree,
        participantCount,
        qShareRnsLimbCount: qSharePrimes.length,
        thresholdDegree: participantCount,
        coefficientCommitmentRoot: fixtureHash('coefficient-commitment-set'),
        vssCoefficientCommitmentRoot: fixtureHash(
            'vss-coefficient-commitment-set',
        ),
        statementRecords,
    };
};

const sameSecretBridgeStatementSetWithWrongSourceLimb =
    (): VssSameSecretBridgeStatementSet => {
        const statementSet = sameSecretBridgeStatementSet();
        return {
            ...statementSet,
            statementRecords: statementSet.statementRecords.map(
                (statement, statementIndex) => ({
                    ...statement,
                    sourceConstantCoefficientCommitments:
                        statement.sourceConstantCoefficientCommitments.map(
                            (sourceCommitment, sourceLimbIndex) =>
                                statementIndex === 0 && sourceLimbIndex === 0
                                    ? {
                                          ...sourceCommitment,
                                          rnsPrime: qSharePrimes[1],
                                      }
                                    : sourceCommitment,
                        ),
                }),
            ),
        };
    };

type BuiltRoundsAndBatches = Readonly<{
    relinearizationKeyShareRounds: ReturnType<
        typeof createRelinearizationKeyShareRounds
    >;
    galoisKeyShareBatches: ReturnType<typeof createGaloisKeyShareBatches>;
}>;

const relinearizationKeyShareRoundsInput = (
    fixture: EvaluationKeyFixture,
    overrides: Partial<RelinearizationKeyShareRoundsInput> = {},
): RelinearizationKeyShareRoundsInput => ({
    ...fixture.commonInput,
    roundOneContributions: fixture.roundOneContributions,
    roundTwoContributions: fixture.roundTwoContributions,
    ...overrides,
});

const galoisKeyShareBatchesInput = (
    fixture: EvaluationKeyFixture,
    overrides: Partial<GaloisKeyShareBatchesInput> = {},
): GaloisKeyShareBatchesInput => ({
    ...fixture.commonInput,
    batchContributions: fixture.batchContributions,
    ...overrides,
});

const replaceFirstArrayEntry = <Item>(
    entries: readonly Item[],
    replacement: Item,
): Item[] => [replacement, ...entries.slice(1)];

const relinearizationInputWithFirstMaterialMutation = (
    fixture: EvaluationKeyFixture,
    materialMutation: Partial<EvaluationKeyShareMaterial>,
): RelinearizationKeyShareRoundsInput => {
    const firstContribution = fixture.roundOneContributions[0];
    return relinearizationKeyShareRoundsInput(fixture, {
        roundOneContributions: replaceFirstArrayEntry(
            fixture.roundOneContributions,
            {
                ...firstContribution,
                shareMaterial: {
                    ...firstContribution.shareMaterial,
                    ...materialMutation,
                },
            },
        ),
    });
};

const galoisInputWithFirstMaterialMutation = (
    fixture: EvaluationKeyFixture,
    materialMutation: Partial<EvaluationKeyShareMaterial>,
): GaloisKeyShareBatchesInput => {
    const firstBatch = fixture.batchContributions[0];
    const firstShare = firstBatch.galoisKeyShares[0];
    return galoisKeyShareBatchesInput(fixture, {
        batchContributions: replaceFirstArrayEntry(fixture.batchContributions, {
            ...firstBatch,
            galoisKeyShares: replaceFirstArrayEntry(
                firstBatch.galoisKeyShares,
                {
                    ...firstShare,
                    shareMaterial: {
                        ...firstShare.shareMaterial,
                        ...materialMutation,
                    },
                },
            ),
        }),
    });
};

const trusteeEvaluationKeyProofsInput = async (
    fixture: EvaluationKeyFixture,
    overrides: Partial<TrusteeEvaluationKeyProofsInput> = {},
): Promise<TrusteeEvaluationKeyProofsInput> => {
    const materialStore = componentMaterialStore();
    const componentTransport =
        await createBinaryChunkedEvaluationKeyShareMaterialTransport(
            evaluationKeyShareMaterialTransportInput(
                fixture,
                materialStore.writer,
            ),
        );
    const relinearizationKeyShareRounds = createRelinearizationKeyShareRounds({
        ...fixture.commonInput,
        roundOneContributions:
            componentTransport.relinearizationRoundOneContributions,
        roundTwoContributions:
            componentTransport.relinearizationRoundTwoContributions,
    });
    const galoisKeyShareBatches = createGaloisKeyShareBatches({
        ...fixture.commonInput,
        batchContributions: componentTransport.galoisKeyShareBatchContributions,
    });

    return {
        ...fixture.commonInput,
        relinearizationKeyShareRounds,
        galoisKeyShareBatches,
        trusteeWitnesses: trusteeWitnesses(),
        sameSecretBridgeStatementSet: sameSecretBridgeStatementSet(),
        trusteeEvaluationKeyProofGenerator: stubGenerator([]),
        transportedEvaluationKeyShareComponentMaterial:
            componentTransport.transportedEvaluationKeyShareComponentMaterial,
        evaluationKeyShareComponentMaterialChunkSources:
            materialStore.sources(),
        ...overrides,
    };
};

const evaluationKeyShareMaterialTransportInput = (
    fixture: EvaluationKeyFixture,
    writer: EvaluationKeyShareComponentMaterialWriter,
    overrides: Partial<EvaluationKeyShareMaterialTransportInput> = {},
): EvaluationKeyShareMaterialTransportInput => ({
    trusteeReferences: fixture.commonInput.trusteeReferences,
    relinearizationRoundOneContributions: fixture.sourceRoundOneContributions,
    relinearizationRoundTwoContributions: fixture.sourceRoundTwoContributions,
    galoisKeyShareBatchContributions: fixture.sourceBatchContributions,
    writeEvaluationKeyShareComponentMaterial: writer,
    ...overrides,
});

const builtTrusteeProofs = async (
    fixture: EvaluationKeyFixture,
    capturedInputs: TrusteeEvaluationKeyProofGeneratorInput[] = [],
): Promise<
    BuiltRoundsAndBatches &
        Awaited<ReturnType<typeof createTrusteeEvaluationKeyProofs>>
> => {
    const proofInput = await trusteeEvaluationKeyProofsInput(fixture, {
        trusteeEvaluationKeyProofGenerator: stubGenerator(capturedInputs),
    });
    const trusteeProofMaterialTransport =
        await createTrusteeEvaluationKeyProofs(proofInput);

    return {
        relinearizationKeyShareRounds: proofInput.relinearizationKeyShareRounds,
        galoisKeyShareBatches: proofInput.galoisKeyShareBatches,
        ...trusteeProofMaterialTransport,
    };
};

type EvaluationKeyRejectionCase<Input> = Readonly<{
    name: string;
    createInput(fixture: EvaluationKeyFixture): Input | Promise<Input>;
    expectedMessage: string;
}>;

const relinearizationKeyShareRoundsRejectionCases = [
    {
        name: 'rejects a key-switch seed outside the shared scheduled sample',
        createInput: (fixture) =>
            relinearizationInputWithFirstMaterialMutation(fixture, {
                keySwitchSeedHex: fixtureHash('wrong-seed'),
            }),
        expectedMessage:
            'keySwitchSeedHex must be shared by scheduled relinearization level and round',
    },
    {
        name: 'rejects a malformed transported component material root',
        createInput: (fixture) =>
            relinearizationInputWithFirstMaterialMutation(fixture, {
                keySwitchComponentMaterialRoot: 'not-a-hash',
            }),
        expectedMessage:
            'keySwitchComponentMaterialRoot must be a protocol hash',
    },
    {
        name: 'rejects missing scheduled contributions',
        createInput: (fixture) =>
            relinearizationKeyShareRoundsInput(fixture, {
                roundOneContributions: fixture.roundOneContributions.slice(1),
            }),
        expectedMessage:
            'roundOneContributions is missing a scheduled trustee and level',
    },
    {
        name: 'rejects duplicate scheduled contributions',
        createInput: (fixture) =>
            relinearizationKeyShareRoundsInput(fixture, {
                roundOneContributions: [
                    ...fixture.roundOneContributions,
                    fixture.roundOneContributions[0],
                ],
            }),
        expectedMessage:
            'roundOneContributions must not repeat a trustee and level',
    },
    {
        name: 'rejects an evaluator key schedule outside the setup context',
        createInput: (fixture) =>
            relinearizationKeyShareRoundsInput(fixture, {
                setupContext: {
                    ...setupContext,
                    setupEpoch: 'setup-epoch-2',
                },
            }),
        expectedMessage:
            'evaluatorKeySchedule.setupContextHash must match the authoritative setup context.',
    },
] satisfies readonly EvaluationKeyRejectionCase<RelinearizationKeyShareRoundsInput>[];

const galoisKeyShareBatchesRejectionCases = [
    {
        name: 'rejects shares outside the frozen Galois key schedule order',
        createInput: (fixture) =>
            galoisKeyShareBatchesInput(fixture, {
                batchContributions: [
                    {
                        trusteeRosterPosition: 0,
                        galoisKeyShares: [
                            ...fixture.batchContributions[0].galoisKeyShares,
                        ].reverse(),
                    },
                    fixture.batchContributions[1],
                ],
            }),
        expectedMessage:
            'galoisKeyShares must follow the frozen Galois key schedule',
    },
    {
        name: 'rejects a Galois key-switch domain outside the scheduled rotation',
        createInput: (fixture) =>
            galoisInputWithFirstMaterialMutation(fixture, {
                keySwitchDomain: 'galois-9',
            }),
        expectedMessage:
            'keySwitchDomain must match the scheduled Galois rotation',
    },
    {
        name: 'rejects missing trustee batches',
        createInput: (fixture) =>
            galoisKeyShareBatchesInput(fixture, {
                batchContributions: fixture.batchContributions.slice(0, 1),
            }),
        expectedMessage:
            'batchContributions must contain one batch per participant',
    },
] satisfies readonly EvaluationKeyRejectionCase<GaloisKeyShareBatchesInput>[];

const trusteeEvaluationKeyProofsRejectionCases = [
    {
        name: 'rejects missing participant witnesses',
        createInput: (fixture) =>
            trusteeEvaluationKeyProofsInput(fixture, {
                trusteeWitnesses: trusteeWitnesses().slice(0, 1),
            }),
        expectedMessage:
            'trusteeWitnesses must contain one witness per participant',
    },
    {
        name: 'rejects incomplete statement-key witness coverage',
        createInput: (fixture) => {
            const completeWitnesses = trusteeWitnesses();

            return trusteeEvaluationKeyProofsInput(fixture, {
                trusteeWitnesses: [
                    {
                        ...completeWitnesses[0],
                        errorCoefficientsByKey:
                            completeWitnesses[0].errorCoefficientsByKey.slice(
                                0,
                                1,
                            ),
                    },
                    completeWitnesses[1],
                ],
            });
        },
        expectedMessage:
            'trusteeWitnesses.errorCoefficientsByKey must contain one error vector set per statement key',
    },
    {
        name: 'rejects a bridge carrier with a mismatched public matrix seed',
        createInput: (fixture) => {
            const statementSet = sameSecretBridgeStatementSet();

            return trusteeEvaluationKeyProofsInput(fixture, {
                sameSecretBridgeStatementSet: {
                    ...statementSet,
                    publicMatrixSeedHash: fixtureHash(
                        'other-public-matrix-seed',
                    ),
                },
            });
        },
        expectedMessage:
            'sameSecretBridgeStatementSet.publicMatrixSeedHash must match evaluatorKeySchedule.publicMatrixSeedHash',
    },
    {
        name: 'rejects a bridge carrier missing participant statements',
        createInput: (fixture) => {
            const statementSet = sameSecretBridgeStatementSet();

            return trusteeEvaluationKeyProofsInput(fixture, {
                sameSecretBridgeStatementSet: {
                    ...statementSet,
                    statementRecords: statementSet.statementRecords.slice(1),
                },
            });
        },
        expectedMessage:
            'sameSecretBridgeStatementSet must contain one statement per participant',
    },
    {
        name: 'rejects a bridge carrier with a non-canonical source-limb body',
        createInput: (fixture) =>
            trusteeEvaluationKeyProofsInput(fixture, {
                sameSecretBridgeStatementSet:
                    sameSecretBridgeStatementSetWithWrongSourceLimb(),
            }),
        expectedMessage:
            'sameSecretBridgeStatementSet source constant commitments must carry canonical source-limb bodies in order',
    },
    {
        name: 'rejects rounds that do not bind the accepted evaluation-key roots',
        createInput: (fixture) =>
            trusteeEvaluationKeyProofsInput(fixture, {
                publicKeyShareSuccinctProofSetRoot: fixtureHash(
                    'other-public-key-share-proof-set',
                ),
            }),
        expectedMessage:
            'relinearizationKeyShareRounds must match the accepted evaluation-key binding',
    },
] satisfies readonly EvaluationKeyRejectionCase<TrusteeEvaluationKeyProofsInput>[];

const evaluationKeyShareMaterialTransportRejectionCases = [
    {
        name: 'rejects contributions for unknown trustee roster positions',
        createOverrides: (fixture: EvaluationKeyFixture) => ({
            relinearizationRoundOneContributions: [
                {
                    ...fixture.sourceRoundOneContributions[0],
                    trusteeRosterPosition: 7,
                },
            ],
            relinearizationRoundTwoContributions: [],
            galoisKeyShareBatchContributions: [],
        }),
        expectedMessage:
            'references a trustee roster position without a trustee reference',
    },
    {
        name: 'rejects duplicate component material roots',
        createOverrides: (fixture: EvaluationKeyFixture) => ({
            relinearizationRoundOneContributions: [
                fixture.sourceRoundOneContributions[0],
                fixture.sourceRoundOneContributions[0],
            ],
            relinearizationRoundTwoContributions: [],
            galoisKeyShareBatchContributions: [],
        }),
        expectedMessage:
            'transported evaluation-key component material contains duplicate roots',
    },
] as const;

const expectedRelinearizationRecords = (
    contributions: readonly RelinearizationRoundOneContribution[],
    objectType:
        | 'RelinearizationKeyShareRoundOne'
        | 'RelinearizationKeyShareRoundTwo',
): unknown[] =>
    contributions.map(
        (contribution, trusteeRosterPosition) =>
            expect.objectContaining({
                objectType,
                trusteeIdentity: trusteeIdentityAtPosition(
                    trusteeRosterPosition,
                ),
                trusteeRosterPosition,
                level: scheduledLevel,
                keySwitchComponentVectorRoot:
                    contribution.shareMaterial.keySwitchComponentVectorRoot,
            }) as unknown,
    );

const expectedGaloisBatches = (fixture: EvaluationKeyFixture): unknown[] =>
    fixture.batchContributions.map(
        (batchContribution, trusteeRosterPosition) =>
            expect.objectContaining({
                objectType: 'GaloisKeyShareBatch',
                trusteeRosterPosition,
                galoisKeyShareMaterialRecords:
                    batchContribution.galoisKeyShares.map(
                        (contribution, scheduleIndex) =>
                            expect.objectContaining({
                                objectType: 'GaloisKeyShareMaterial',
                                rotation:
                                    requiredGaloisKeySchedule[scheduleIndex]
                                        .rotation,
                                level: requiredGaloisKeySchedule[scheduleIndex]
                                    .level,
                                keySwitchComponentVectorRoot:
                                    contribution.shareMaterial
                                        .keySwitchComponentVectorRoot,
                            }) as unknown,
                    ),
            }) as unknown,
    );

describe('createRelinearizationKeyShareRounds', () => {
    it('creates scheduled round records with bound component material', () => {
        const fixture = evaluationKeyFixture();
        const rounds = createRelinearizationKeyShareRounds(
            relinearizationKeyShareRoundsInput(fixture),
        );

        expect(rounds.objectType).toBe('RelinearizationKeyShareRounds');
        expect(rounds.publicKeyShareSetRoot).toBe(
            fixture.schedule.publicKeyShareSetRoot,
        );
        expect(rounds.roundOneRecords).toEqual(
            expectedRelinearizationRecords(
                fixture.roundOneContributions,
                'RelinearizationKeyShareRoundOne',
            ),
        );
        expect(rounds.roundTwoRecords).toEqual(
            expectedRelinearizationRecords(
                fixture.roundTwoContributions,
                'RelinearizationKeyShareRoundTwo',
            ),
        );
    });

    it.each(relinearizationKeyShareRoundsRejectionCases)(
        '$name',
        ({ createInput, expectedMessage }) => {
            expect(() =>
                createRelinearizationKeyShareRounds(
                    createInput(evaluationKeyFixture()),
                ),
            ).toThrow(expectedMessage);
        },
    );
});

describe('createGaloisKeyShareBatches', () => {
    it('creates trustee batches with scheduled bound material records', () => {
        const fixture = evaluationKeyFixture();
        const batches = createGaloisKeyShareBatches(
            galoisKeyShareBatchesInput(fixture),
        );

        expect(batches).toEqual(expectedGaloisBatches(fixture));
    });

    it.each(galoisKeyShareBatchesRejectionCases)(
        '$name',
        ({ createInput, expectedMessage }) => {
            expect(() =>
                createGaloisKeyShareBatches(
                    createInput(evaluationKeyFixture()),
                ),
            ).toThrow(expectedMessage);
        },
    );
});

describe('createTrusteeEvaluationKeyProofs', () => {
    it('builds one statement per trustee in frozen key order with recomputed public aggregates', async () => {
        const fixture = evaluationKeyFixture();
        const capturedInputs: TrusteeEvaluationKeyProofGeneratorInput[] = [];
        const {
            trusteeEvaluationKeyProofs,
            transportedEvaluationKeyShareProofMaterial,
        } = await builtTrusteeProofs(fixture, capturedInputs);
        const bridgeStatementSet = sameSecretBridgeStatementSet();

        expect(capturedInputs).toHaveLength(participantCount);
        capturedInputs.forEach((generatorInput, trusteeRosterPosition) => {
            const sourceConstantCommitment =
                bridgeStatementSet.statementRecords[trusteeRosterPosition]
                    ?.sourceConstantCoefficientCommitments[0]?.commitment;
            expect(generatorInput).toMatchObject({
                context: {
                    trusteeRosterPosition,
                    setupContextHash,
                    evaluatorKeyScheduleRoot:
                        fixture.schedule.evaluatorKeyScheduleRoot,
                    sourceConstantCoefficientCommitmentRoot:
                        deriveCanonicalObjectHash(sourceConstantCommitment),
                },
                ringDegree,
                sameSecretLinkage: {
                    publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
                    commitments: [sourceConstantCommitment],
                },
            });
            expect(
                generatorInput.keys.map((statementKey) => [
                    statementKey.proofFamily,
                    statementKey.rotation ?? null,
                    statementKey.keySwitchDomain,
                    statementKey.keySwitchSeedHex,
                ]),
            ).toEqual(expectedStatementKeyBindings(fixture.schedule));
            const roundOneKey = generatorInput.keys[0];
            expect(
                roundOneKey.componentMaterialBytesHex.startsWith(
                    `534c454b434d563101000000000000000800000000000000${coefficientsToLittleEndianHex(
                        componentCoefficients(
                            `round-one-${String(trusteeRosterPosition)}`,
                            0,
                            0,
                        ),
                    )}`,
                ),
            ).toBe(true);
            const roundTwoKey = generatorInput.keys[1];
            expect(roundTwoKey.roundOneAggregateDiagonal).toEqual(
                expectedRoundOneAggregateDiagonal(),
            );
            expect(generatorInput.keys[0].roundOneAggregateDiagonal).toBe(
                undefined,
            );
            expect(generatorInput.errorCoefficientsByKey).toHaveLength(
                statementKeyCount,
            );
        });

        expect(trusteeEvaluationKeyProofs.proofRecords).toHaveLength(
            participantCount,
        );
        expect(trusteeEvaluationKeyProofs).toMatchObject({
            objectType: 'TrusteeEvaluationKeyProofSet',
            proofRecords: Array.from(
                { length: participantCount },
                (_unused, trusteeRosterPosition) =>
                    expect.objectContaining({
                        objectType: 'TrusteeEvaluationKeyProof',
                        trusteeRosterPosition,
                        statementHash: fixtureHash(
                            `statement-${String(trusteeRosterPosition)}`,
                        ),
                        proofBytesHash: trusteeEvaluationKeyProofBytesHash(
                            stubProofBytesHex(trusteeRosterPosition),
                        ),
                    }) as unknown,
            ),
        });
        expect(
            transportedEvaluationKeyShareProofMaterial.proofMaterials.map(
                (material) => material.proofMaterialRoot,
            ),
        ).toEqual(
            trusteeEvaluationKeyProofs.proofRecords.map(
                (record) => record.proofMaterialRoot,
            ),
        );
    });

    it.each(trusteeEvaluationKeyProofsRejectionCases)(
        '$name',
        async ({ createInput, expectedMessage }) => {
            await expect(
                createTrusteeEvaluationKeyProofs(
                    await createInput(evaluationKeyFixture()),
                ),
            ).rejects.toThrow(expectedMessage);
        },
    );

    it('rejects tampered transported component bytes during aggregate recomputation', async () => {
        const fixture = evaluationKeyFixture();
        const validInput = await trusteeEvaluationKeyProofsInput(fixture);
        const [firstSource, ...remainingSources] =
            validInput.evaluationKeyShareComponentMaterialChunkSources;
        if (firstSource === undefined) {
            throw new Error('The fixture must carry component material.');
        }
        await expect(
            createTrusteeEvaluationKeyProofs({
                ...validInput,
                evaluationKeyShareComponentMaterialChunkSources: [
                    {
                        ...firstSource,
                        pullChunk: async (input) => {
                            const chunk = await firstSource.pullChunk(input);
                            if (chunk === undefined || input.chunkIndex !== 0) {
                                return chunk;
                            }
                            const tamperedChunk = chunk.slice(0);
                            new Uint8Array(tamperedChunk)[0] ^= 0xff;
                            return tamperedChunk;
                        },
                    },
                    ...remainingSources,
                ],
            }),
        ).rejects.toThrow('wrong format marker');
    });
});

describe('trustee evaluation-key canonical proof material', () => {
    it('returns semantic proof records and descriptor-authenticated binary sidecars together', async () => {
        const fixture = evaluationKeyFixture();
        const transport = await builtTrusteeProofs(fixture);

        expect(
            transport.transportedEvaluationKeyShareProofMaterial.proofMaterials,
        ).toEqual(
            transport.trusteeEvaluationKeyProofs.proofRecords.map(
                (proofRecord) =>
                    expect.objectContaining({
                        objectType:
                            'SetupTransportedEvaluationKeyShareProofMaterial',
                        descriptorBytes: canonicalStreamDescriptor(
                            BigInt(
                                stubProofBytesHex(
                                    proofRecord.trusteeRosterPosition,
                                ).length / 2,
                            ),
                            [0x51 + proofRecord.trusteeRosterPosition],
                            0x61 + proofRecord.trusteeRosterPosition,
                        ),
                        proofMaterialRoot: proofRecord.proofMaterialRoot,
                    }) as unknown,
            ),
        );
    });

    it('rejects a generated material root that does not bind the proof family and hash', async () => {
        const fixture = evaluationKeyFixture();
        const validGenerator = stubGenerator([]);
        await expect(
            createTrusteeEvaluationKeyProofs(
                await trusteeEvaluationKeyProofsInput(fixture, {
                    trusteeEvaluationKeyProofGenerator: async (input) => ({
                        ...(await validGenerator(input)),
                        proofMaterialRoot: fixtureHash('wrong-material-root'),
                    }),
                }),
            ),
        ).rejects.toThrow(
            'proofMaterialRoot must bind the proof family and proof hash',
        );
    });
});

describe('createBinaryChunkedEvaluationKeyShareMaterialTransport', () => {
    it('writes source component vectors into canonical streams for every contribution', async () => {
        const fixture = evaluationKeyFixture();
        const materialStore = componentMaterialStore();
        const transport =
            await createBinaryChunkedEvaluationKeyShareMaterialTransport(
                evaluationKeyShareMaterialTransportInput(
                    fixture,
                    materialStore.writer,
                ),
            );
        const expectedComponentMaterialCount =
            participantCount * (2 + requiredGaloisKeySchedule.length);
        expect(
            transport.transportedEvaluationKeyShareComponentMaterial
                .componentMaterials,
        ).toHaveLength(expectedComponentMaterialCount);
        for (const contribution of [
            ...transport.relinearizationRoundOneContributions,
            ...transport.relinearizationRoundTwoContributions,
            ...transport.galoisKeyShareBatchContributions.flatMap(
                (batchContribution) => batchContribution.galoisKeyShares,
            ),
        ]) {
            expect(contribution.shareMaterial.keySwitchMaterialEncoding).toBe(
                'binary-chunked-key-switch-component-vectors',
            );
        }
        const sourceByRoot = new Map(
            materialStore
                .sources()
                .map((source) => [
                    source.keySwitchComponentMaterialRoot,
                    source,
                ]),
        );
        expect(sourceByRoot.size).toBe(expectedComponentMaterialCount);
        for (const componentMaterial of transport
            .transportedEvaluationKeyShareComponentMaterial
            .componentMaterials) {
            const material = componentMaterial;
            expect(material.objectType).toBe(
                'SetupTransportedEvaluationKeyShareComponentMaterial',
            );
            const keySwitchComponentMaterialRoot =
                material.keySwitchComponentMaterialRoot as string;
            const source = sourceByRoot.get(keySwitchComponentMaterialRoot);
            expect(source).toBeDefined();
            const chunks =
                materialStore.chunks(keySwitchComponentMaterialRoot) ?? [];
            expect(chunks).toHaveLength(1);
            expect([...new Uint8Array(chunks[0]).slice(0, 8)]).toEqual([
                0x53, 0x4c, 0x45, 0x4b, 0x43, 0x4d, 0x56, 0x31,
            ]);
        }
        const roundOneRoots = new Set(
            transport.relinearizationRoundOneContributions.map(
                (contribution) =>
                    (contribution.shareMaterial as JsonRecord)
                        .keySwitchComponentMaterialRoot,
            ),
        );
        expect(roundOneRoots.size).toBe(participantCount);
    });

    it.each(evaluationKeyShareMaterialTransportRejectionCases)(
        '$name',
        async ({ createOverrides, expectedMessage }) => {
            const fixture = evaluationKeyFixture();
            const materialStore = componentMaterialStore();
            await expect(
                createBinaryChunkedEvaluationKeyShareMaterialTransport(
                    evaluationKeyShareMaterialTransportInput(
                        fixture,
                        materialStore.writer,
                        createOverrides(fixture),
                    ),
                ),
            ).rejects.toThrow(expectedMessage);
        },
    );
});
