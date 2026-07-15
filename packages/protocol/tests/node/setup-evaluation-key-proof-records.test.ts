import { deriveCanonicalObjectHash, hash512Hex } from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import { deriveCollectiveBgvSetupContextHash } from '#packages/protocol/src/setup/common-fields';
import {
    createBinaryChunkedEvaluationKeyShareMaterialTransport,
    createGaloisKeyShareBatches,
    createRelinearizationKeyShareRounds,
    createTrusteeEvaluationKeyProofs,
    type EvaluationKeyProofCommonInput,
    type EvaluationKeyShareComponentMaterialStream,
    type EvaluationKeyShareComponentMaterialWriter,
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
import { canonicalStreamDescriptorFixture } from '#tests/support/canonical-stream-descriptor-fixture';
import {
    makeSetupContext,
    makeSetupFixtureHash,
} from '#tests/support/setup-fixtures';

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
type SourceRelinearizationContribution =
    EvaluationKeyShareMaterialTransportInput['relinearizationRoundOneContributions'][number];
type EvaluationKeyShareComponentVectors =
    SourceRelinearizationContribution['keySwitchComponentVectorsLittleEndianHexByDigitAndLimb'];

const qSharePrimes = [
    140_737_487_306_753, 140_737_486_716_929, 140_737_486_520_321,
] as const;
const participantCount = 2;
const scheduledLevel = 1;
const ringDegree = 8;
const digitCount = scheduledLevel + 1;
const canonicalChunkByteLength = 1_048_576;

const fixtureHash = makeSetupFixtureHash('setup-evaluation-key-proof-records');

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
    return {
        objectType: 'EvaluatorKeySchedule',
        setupContextHash,
        publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
        publicKeyShareSetRoot: fixtureHash('public-key-share-set'),
        relinearizationLevelSchedule: [{ level: scheduledLevel }],
        requiredGaloisKeySchedule,
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
        evaluatorKeyScheduleRoot: deriveCanonicalObjectHash(schedule),
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
        evaluatorKeyScheduleRoot: deriveCanonicalObjectHash(schedule),
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

const componentVectorEntries = (label: string): string[] => {
    const entries: string[] = [];
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
            entries.push(coefficientsToLittleEndianHex(coefficients));
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

const expectedStatementKeyOrder: readonly (readonly [string, number | null])[] =
    [
        ...(['round-one', 'round-two'] as const).map(
            (round) => [`relinearization-${round}`, null] as const,
        ),
        ...requiredGaloisKeySchedule.map(
            (scheduleEntry) =>
                ['galois-rotation', scheduleEntry.rotation] as const,
        ),
    ];

const componentMaterialTransportInput = (
    label: string,
): EvaluationKeyShareComponentVectors => componentVectorEntries(label);

const componentVectorRoot = (
    proofFamily: 'relinearization-key-share' | 'galois-key-share',
    keySwitchDomain: string,
    keySwitchSeedHex: string,
    level: number,
    componentVectorsLittleEndianHexByDigitAndLimb: EvaluationKeyShareComponentVectors,
): string => {
    return deriveCanonicalObjectHash({
        objectType: 'EvaluationKeyShareComponentVectorSet',
        proofFamily,
        keySwitchDomain,
        keySwitchSeedHex,
        level,
        ringDegree,
        componentVectorsLittleEndianHexByDigitAndLimb,
    });
};

const transportedShareMaterialRoot = (
    proofFamily: 'relinearization-key-share' | 'galois-key-share',
    componentVectorsLittleEndianHexByDigitAndLimb: EvaluationKeyShareComponentVectors,
    keySwitchDomain: string,
    keySwitchSeedHex: string,
    trusteeIdentity: string,
    trusteeRosterPosition: number,
    level: number,
): string => {
    const keySwitchComponentVectorRoot = componentVectorRoot(
        proofFamily,
        keySwitchDomain,
        keySwitchSeedHex,
        level,
        componentVectorsLittleEndianHexByDigitAndLimb,
    );

    return evaluationKeyShareComponentMaterialReferenceRoot(
        proofFamily,
        ringDegree,
        keySwitchComponentVectorRoot,
        keySwitchDomain,
        keySwitchSeedHex,
        trusteeIdentity,
        trusteeRosterPosition,
        level,
    );
};

const sourceRelinearizationContributions = (
    round: 'round-one' | 'round-two',
): SourceRelinearizationContribution[] =>
    Array.from(
        { length: participantCount },
        (_unused, trusteeRosterPosition) => ({
            trusteeRosterPosition,
            level: scheduledLevel,
            keySwitchComponentVectorsLittleEndianHexByDigitAndLimb:
                componentMaterialTransportInput(
                    `${round}-${String(trusteeRosterPosition)}`,
                ),
        }),
    );

const transportedRelinearizationContributions = (
    contributions: readonly SourceRelinearizationContribution[],
    schedule: EvaluatorKeySchedule,
    round: 'round-one' | 'round-two',
): RelinearizationRoundOneContribution[] =>
    contributions.map((contribution) => ({
        trusteeRosterPosition: contribution.trusteeRosterPosition,
        level: contribution.level,
        keySwitchComponentMaterialRoot: transportedShareMaterialRoot(
            'relinearization-key-share',
            contribution.keySwitchComponentVectorsLittleEndianHexByDigitAndLimb,
            'relinearization',
            relinearizationKeySwitchSeed(schedule, round, contribution.level),
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
        evaluatorKeySchedule: schedule,
        trusteeReferences: trusteeReferences(),
    } satisfies EvaluationKeyProofCommonInput;
    const sourceRoundOneContributions =
        sourceRelinearizationContributions('round-one');
    const sourceRoundTwoContributions =
        sourceRelinearizationContributions('round-two');
    const sourceBatchContributions = Array.from(
        { length: participantCount },
        (_unused, trusteeRosterPosition) => ({
            trusteeRosterPosition,
            galoisKeyShares: requiredGaloisKeySchedule.map((scheduleEntry) => {
                const componentVectorsLittleEndianHexByDigitAndLimb =
                    componentMaterialTransportInput(
                        `galois-${String(scheduleEntry.rotation)}-${String(trusteeRosterPosition)}`,
                    );

                return {
                    rotation: scheduleEntry.rotation,
                    level: scheduleEntry.level,
                    keySwitchComponentVectorsLittleEndianHexByDigitAndLimb:
                        componentVectorsLittleEndianHexByDigitAndLimb,
                };
            }),
        }),
    );
    const roundOneContributions = transportedRelinearizationContributions(
        sourceRoundOneContributions,
        schedule,
        'round-one',
    );
    const roundTwoContributions = transportedRelinearizationContributions(
        sourceRoundTwoContributions,
        schedule,
        'round-two',
    );
    const batchContributions = sourceBatchContributions.map(
        (batchContribution) => ({
            ...batchContribution,
            galoisKeyShares: batchContribution.galoisKeyShares.map(
                (contribution) => ({
                    rotation: contribution.rotation,
                    level: contribution.level,
                    keySwitchComponentMaterialRoot:
                        transportedShareMaterialRoot(
                            'galois-key-share',
                            contribution.keySwitchComponentVectorsLittleEndianHexByDigitAndLimb,
                            `galois-${String(contribution.rotation)}`,
                            galoisKeySwitchSeed(
                                schedule,
                                contribution.rotation,
                                contribution.level,
                            ),
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
        const proofBytesHash =
            trusteeEvaluationKeyProofBytesHash(proofBytesHex);

        return Promise.resolve({
            proofBytesHash,
            proofMaterialStream: {
                descriptorBytes: canonicalStreamDescriptorFixture(
                    proofBytesHex.length / 2,
                    0x51 + input.context.trusteeRosterPosition,
                ),
                pullChunk: ({ chunkIndex, expectedByteLength }) =>
                    Promise.resolve(
                        chunkIndex === 0 &&
                            expectedByteLength === proofBytesHex.length / 2
                            ? Uint8Array.from(
                                  Array.from(
                                      { length: proofBytesHex.length / 2 },
                                      (_unused, byteIndex) =>
                                          Number.parseInt(
                                              proofBytesHex.slice(
                                                  byteIndex * 2,
                                                  byteIndex * 2 + 2,
                                              ),
                                              16,
                                          ),
                                  ),
                              ).buffer
                            : undefined,
                    ),
            },
        });
    };
};

const componentMaterialStore = (): Readonly<{
    chunks(materialRoot: string): readonly ArrayBuffer[] | undefined;
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
        const pullChunk: EvaluationKeyShareComponentMaterialStream['pullChunk'] =
            ({ chunkIndex, expectedByteLength }) => {
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
            };
        return {
            descriptorBytes: canonicalStreamDescriptorFixture(
                input.totalByteLength,
                rootByte,
            ),
            pullChunk,
        };
    };

    return {
        chunks: (materialRoot) => storedMaterial.get(materialRoot),
        writer,
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
            openingRandomnessByLimb: Array.from(
                { length: qSharePrimes.length },
                () => [Array.from({ length: ringDegree }, () => 1)],
            ),
        }),
    );

const sameSecretBridgeStatementSet = (): VssSameSecretBridgeStatementSet => {
    const statementRecords = trusteeReferences().map(() => {
        const sourceConstantCoefficientCommitments = qSharePrimes.map(
            (_unusedRnsPrime, rnsLimbIndex) =>
                ({
                    objectType: 'SetupCommitment',
                    sourceRnsLimbIndex: rnsLimbIndex,
                    shamirCoefficientIndex: 0,
                    ringDegree,
                    commitmentLimbs: [],
                }) as const,
        );
        const statementRecord = {
            objectType: 'VssSameSecretBridgeStatement',
            sourceConstantCoefficientCommitments,
        } as const;

        return statementRecord;
    });
    return {
        objectType: 'VssSameSecretBridgeStatementSet',
        setupContextHash,
        publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
        ringDegree,
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
                                          sourceRnsLimbIndex: 1,
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
    materialMutation: Partial<RelinearizationRoundOneContribution>,
): RelinearizationKeyShareRoundsInput => {
    const firstContribution = fixture.roundOneContributions[0];
    return relinearizationKeyShareRoundsInput(fixture, {
        roundOneContributions: replaceFirstArrayEntry(
            fixture.roundOneContributions,
            {
                ...firstContribution,
                ...materialMutation,
            },
        ),
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
        evaluationKeyShareComponentMaterialStreams:
            componentTransport.evaluationKeyShareComponentMaterialStreams,
        ...overrides,
    };
};

const evaluationKeyShareMaterialTransportInput = (
    fixture: EvaluationKeyFixture,
    writer: EvaluationKeyShareComponentMaterialWriter,
    overrides: Partial<EvaluationKeyShareMaterialTransportInput> = {},
): EvaluationKeyShareMaterialTransportInput => ({
    trusteeReferences: fixture.commonInput.trusteeReferences,
    qSharePrimes,
    ringDegree,
    evaluatorKeySchedule: fixture.schedule,
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
] satisfies readonly EvaluationKeyRejectionCase<TrusteeEvaluationKeyProofsInput>[];

const evaluationKeyShareMaterialTransportRejectionCases = [
    {
        name: 'rejects an invalid construction ring degree',
        createOverrides: (_fixture: EvaluationKeyFixture) => ({
            ringDegree: 0,
        }),
        expectedMessage: 'ringDegree must be a positive safe integer',
    },
    {
        name: 'rejects an empty Q_share basis',
        createOverrides: (_fixture: EvaluationKeyFixture) => ({
            qSharePrimes: [],
        }),
        expectedMessage: 'qSharePrimes must contain at least one RNS prime',
    },
    {
        name: 'rejects invalid Q_share primes',
        createOverrides: (_fixture: EvaluationKeyFixture) => ({
            qSharePrimes: [0],
        }),
        expectedMessage: 'qSharePrimes.0 must be a positive safe integer',
    },
    {
        name: 'rejects scheduled levels outside the Q_share basis',
        createOverrides: (_fixture: EvaluationKeyFixture) => ({
            qSharePrimes: [qSharePrimes[0]],
        }),
        expectedMessage:
            'evaluation-key component material level is outside the Q_share basis',
    },
    {
        name: 'rejects coefficients outside the prime derived from vector position',
        createOverrides: (fixture: EvaluationKeyFixture) => {
            const firstContribution = fixture.sourceRoundOneContributions[0];
            const nonCanonicalFirstVector = coefficientsToLittleEndianHex(
                Array.from({ length: ringDegree }, () => qSharePrimes[0]),
            );

            return {
                relinearizationRoundOneContributions: replaceFirstArrayEntry(
                    fixture.sourceRoundOneContributions,
                    {
                        ...firstContribution,
                        keySwitchComponentVectorsLittleEndianHexByDigitAndLimb:
                            replaceFirstArrayEntry(
                                firstContribution.keySwitchComponentVectorsLittleEndianHexByDigitAndLimb,
                                nonCanonicalFirstVector,
                            ),
                    },
                ),
            };
        },
        expectedMessage:
            'evaluation-key component material coefficients must be canonical residues',
    },
    {
        name: 'rejects contributions for unknown trustee roster positions',
        createOverrides: (fixture: EvaluationKeyFixture) => ({
            relinearizationRoundOneContributions: replaceFirstArrayEntry(
                fixture.sourceRoundOneContributions,
                {
                    ...fixture.sourceRoundOneContributions[0],
                    trusteeRosterPosition: 7,
                },
            ),
        }),
        expectedMessage:
            'references a trustee roster position without a trustee reference',
    },
] as const;

const expectedRelinearizationRoots = (
    contributions: readonly RelinearizationRoundOneContribution[],
): string[] =>
    contributions.map(
        (contribution) => contribution.keySwitchComponentMaterialRoot,
    );

const expectedGaloisBatches = (fixture: EvaluationKeyFixture): unknown[] =>
    fixture.batchContributions.map(
        (batchContribution) =>
            expect.objectContaining({
                objectType: 'GaloisKeyShareBatch',
                keySwitchComponentMaterialRoots:
                    batchContribution.galoisKeyShares.map(
                        (contribution) =>
                            contribution.keySwitchComponentMaterialRoot,
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
        expect(rounds.roundOneKeySwitchComponentMaterialRoots).toEqual(
            expectedRelinearizationRoots(fixture.roundOneContributions),
        );
        expect(rounds.roundTwoKeySwitchComponentMaterialRoots).toEqual(
            expectedRelinearizationRoots(fixture.roundTwoContributions),
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
                    ?.sourceConstantCoefficientCommitments[0];
            expect(generatorInput).toMatchObject({
                context: {
                    trusteeRosterPosition,
                    setupContextHash,
                    evaluatorKeyScheduleRoot: deriveCanonicalObjectHash(
                        fixture.schedule,
                    ),
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
                ]),
            ).toEqual(expectedStatementKeyOrder);
            const roundOneKey = generatorInput.keys[0];
            expect(
                roundOneKey.componentMaterialBytesHex.startsWith(
                    `534c454b434d5632${coefficientsToLittleEndianHex(
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

        expect(trusteeEvaluationKeyProofs.proofBytesHashes).toHaveLength(
            participantCount,
        );
        expect(trusteeEvaluationKeyProofs).toMatchObject({
            objectType: 'TrusteeEvaluationKeyProofSet',
            proofBytesHashes: Array.from(
                { length: participantCount },
                (_unused, trusteeRosterPosition) =>
                    trusteeEvaluationKeyProofBytesHash(
                        stubProofBytesHex(trusteeRosterPosition),
                    ),
            ),
        });
        expect(
            transportedEvaluationKeyShareProofMaterial.proofMaterialStreams,
        ).toHaveLength(trusteeEvaluationKeyProofs.proofBytesHashes.length);
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
        const [firstStream, ...remainingStreams] =
            validInput.evaluationKeyShareComponentMaterialStreams;
        if (firstStream === undefined) {
            throw new Error('The fixture must carry component material.');
        }
        await expect(
            createTrusteeEvaluationKeyProofs({
                ...validInput,
                evaluationKeyShareComponentMaterialStreams: [
                    {
                        ...firstStream,
                        pullChunk: async (input) => {
                            const chunk = await firstStream.pullChunk(input);
                            if (chunk === undefined || input.chunkIndex !== 0) {
                                return chunk;
                            }
                            const tamperedChunk = chunk.slice(0);
                            new Uint8Array(tamperedChunk)[0] ^= 0xff;
                            return tamperedChunk;
                        },
                    },
                    ...remainingStreams,
                ],
            }),
        ).rejects.toThrow('wrong format marker');
    });
});

describe('trustee evaluation-key canonical proof material', () => {
    it('returns proof references and canonical proof streams together', async () => {
        const fixture = evaluationKeyFixture();
        const transport = await builtTrusteeProofs(fixture);

        const proofMaterialStreams =
            transport.transportedEvaluationKeyShareProofMaterial
                .proofMaterialStreams;
        expect(proofMaterialStreams).toHaveLength(participantCount);
        proofMaterialStreams.forEach((stream, trusteeRosterPosition) => {
            expect(stream.descriptorBytes).toEqual(
                canonicalStreamDescriptorFixture(
                    stubProofBytesHex(trusteeRosterPosition).length / 2,
                    0x51 + trusteeRosterPosition,
                ),
            );
            expect(typeof stream.pullChunk).toBe('function');
        });
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
            transport.evaluationKeyShareComponentMaterialStreams,
        ).toHaveLength(expectedComponentMaterialCount);
        const sourceMaterial =
            fixture.sourceRoundOneContributions[0]
                .keySwitchComponentVectorsLittleEndianHexByDigitAndLimb;
        const keySwitchSeedHex = relinearizationKeySwitchSeed(
            fixture.schedule,
            'round-one',
            scheduledLevel,
        );
        const keySwitchComponentVectorRoot = componentVectorRoot(
            'relinearization-key-share',
            'relinearization',
            keySwitchSeedHex,
            scheduledLevel,
            sourceMaterial,
        );
        expect(
            transport.relinearizationRoundOneContributions[0]
                .keySwitchComponentMaterialRoot,
        ).toBe(
            evaluationKeyShareComponentMaterialReferenceRoot(
                'relinearization-key-share',
                ringDegree,
                keySwitchComponentVectorRoot,
                'relinearization',
                keySwitchSeedHex,
                trusteeIdentityAtPosition(0),
                0,
                scheduledLevel,
            ),
        );
        const rootsInCanonicalOrder = [
            ...transport.relinearizationRoundOneContributions.map(
                ({ keySwitchComponentMaterialRoot }) =>
                    keySwitchComponentMaterialRoot,
            ),
            ...transport.relinearizationRoundTwoContributions.map(
                ({ keySwitchComponentMaterialRoot }) =>
                    keySwitchComponentMaterialRoot,
            ),
            ...transport.galoisKeyShareBatchContributions.flatMap(
                ({ galoisKeyShares }) =>
                    galoisKeyShares.map(
                        ({ keySwitchComponentMaterialRoot }) =>
                            keySwitchComponentMaterialRoot,
                    ),
            ),
        ];
        expect(new Set(rootsInCanonicalOrder).size).toBe(
            expectedComponentMaterialCount,
        );
        for (const [
            streamIndex,
            componentMaterialStream,
        ] of transport.evaluationKeyShareComponentMaterialStreams.entries()) {
            const keySwitchComponentMaterialRoot =
                rootsInCanonicalOrder[streamIndex];
            expect(keySwitchComponentMaterialRoot).toBeDefined();
            const chunks =
                materialStore.chunks(keySwitchComponentMaterialRoot) ?? [];
            expect(chunks).toHaveLength(1);
            expect(componentMaterialStream.descriptorBytes).toEqual(
                canonicalStreamDescriptorFixture(
                    chunks[0].byteLength,
                    Number.parseInt(
                        keySwitchComponentMaterialRoot.slice(0, 2),
                        16,
                    ),
                ),
            );
            expect([...new Uint8Array(chunks[0]).slice(0, 8)]).toEqual([
                0x53, 0x4c, 0x45, 0x4b, 0x43, 0x4d, 0x56, 0x32,
            ]);
        }
        const roundOneRoots = new Set(
            transport.relinearizationRoundOneContributions.map(
                (contribution) => contribution.keySwitchComponentMaterialRoot,
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
