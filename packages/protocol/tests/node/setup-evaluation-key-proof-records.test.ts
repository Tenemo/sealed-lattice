import { deriveCanonicalObjectHash, hash512Hex } from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import {
    createBinaryChunkedEvaluationKeyShareMaterialTransport,
    createBinaryChunkedPublicEvaluationKeyMaterialTransport,
    createGaloisKeyShareBatches,
    createPublicEvaluationKeySet,
    createRelinearizationKeyShareRounds,
    createTrusteeEvaluationKeyProofs,
    evaluationKeyShareComponentVectorHash,
    evaluationKeyShareComponentVectorRoot,
    trusteeEvaluationKeyProofFamily,
    type EvaluationKeyProofCommonInput,
    type EvaluationKeyShareComponentMaterialChunkSource,
    type EvaluationKeyShareComponentMaterialWriter,
    type EvaluationKeyShareMaterial,
    type EvaluationKeyTrusteeReference,
    type GaloisKeyShareBatchContribution,
    type RelinearizationRoundOneContribution,
    type RelinearizationRoundTwoContribution,
    type PublicEvaluationKeyMaterialWriter,
    type TrusteeEvaluationKeyProofGenerator,
    type TrusteeEvaluationKeyWitnessInput,
} from '#packages/protocol/src/setup/evaluation-key-proof-records';
import {
    createRequiredGaloisSet,
    type EvaluatorKeySchedule,
    type RequiredGaloisKeyScheduleEntry,
} from '#packages/protocol/src/setup/evaluator-key-schedule';
import {
    createSetupPackageVerificationInput,
    type SetupPackage,
    type SetupPackageVerificationInputSource,
} from '#packages/protocol/src/setup/setup-package-assembly';
import type { VssSameSecretBridgeStatementSet } from '#packages/protocol/src/setup/vss-commitments';
import {
    makeSetupContext,
    makeSetupFixtureHash,
} from '#tests/support/setup-fixtures';

type JsonRecord = Record<string, unknown>;
type DescriptorBackedProofMaterialSet = Readonly<{
    objectType: string;
    proofFamily: string;
    proofMaterials: readonly Readonly<{
        objectType: string;
        proofFamily: string;
        proofMaterialRoot: string;
        descriptorBytes: Uint8Array;
    }>[];
}>;
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
type PublicEvaluationKeyMaterialTransportInput = Parameters<
    typeof createBinaryChunkedPublicEvaluationKeyMaterialTransport
>[0];

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

const setupContext = makeSetupContext(fixtureHash);

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
    const requiredGaloisSetHash = deriveCanonicalObjectHash(
        createRequiredGaloisSet(qSharePrimes.length, requiredGaloisKeySchedule),
    );
    const scheduleWithoutRoot = {
        objectType: 'EvaluatorKeySchedule',
        ...setupContext,
        publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
        relinearizationCrpRoot: fixtureHash('relinearization-crp'),
        galoisKeyCrpRoot: fixtureHash('galois-key-crp'),
        publicKeyShareSetRoot: fixtureHash('public-key-share-set'),
        publicKeyShareProofSetRoot: fixtureHash('public-key-share-proof-set'),
        relinearizationLevelSchedule: [{ level: scheduledLevel }],
        requiredGaloisKeySchedule,
        requiredGaloisSetHash,
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

const relinearizationKeySwitchSeed = (
    schedule: EvaluatorKeySchedule,
    round: 'round-one' | 'round-two',
    level: number,
): string =>
    deriveCanonicalObjectHash({
        objectType: 'RelinearizationKeySwitchPublicSampleSeed',
        proofFamily: 'relinearization-key-share',
        evaluatorKeyScheduleRoot: schedule.evaluatorKeyScheduleRoot,
        relinearizationCrpRoot: schedule.relinearizationCrpRoot,
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
        proofFamily: 'galois-key-share',
        evaluatorKeyScheduleRoot: schedule.evaluatorKeyScheduleRoot,
        galoisKeyCrpRoot: schedule.galoisKeyCrpRoot,
        requiredGaloisSetHash: schedule.requiredGaloisSetHash,
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
                coefficientVectorHash512:
                    evaluationKeyShareComponentVectorHash(coefficients),
                coefficientsLeHex: coefficientsToLittleEndianHex(coefficients),
            });
        }
    }

    return entries;
};

const embeddedShareMaterial = (
    proofFamily: 'relinearization-key-share' | 'galois-key-share',
    keySwitchDomain: string,
    keySwitchSeedHex: string,
    label: string,
): EvaluationKeyShareMaterial => {
    const entries = componentVectorEntries(label);

    return {
        keySwitchMaterialEncoding: 'embedded-full-key-switch-component-vectors',
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

type EvaluationKeyFixture = Readonly<{
    schedule: EvaluatorKeySchedule;
    commonInput: EvaluationKeyProofCommonInput;
    roundOneContributions: RelinearizationRoundOneContribution[];
    roundTwoContributions: RelinearizationRoundTwoContribution[];
    batchContributions: GaloisKeyShareBatchContribution[];
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
    const roundOneContributions = Array.from(
        { length: participantCount },
        (_unused, trusteeRosterPosition) => {
            const shareMaterial = embeddedShareMaterial(
                'relinearization-key-share',
                'relinearization',
                relinearizationKeySwitchSeed(
                    schedule,
                    'round-one',
                    scheduledLevel,
                ),
                `round-one-${String(trusteeRosterPosition)}`,
            );

            return {
                trusteeRosterPosition,
                level: scheduledLevel,
                roundOneShareRoot: shareMaterial.keySwitchComponentVectorRoot,
                shareMaterial,
            };
        },
    );
    const roundTwoContributions = Array.from(
        { length: participantCount },
        (_unused, trusteeRosterPosition) => {
            const shareMaterial = embeddedShareMaterial(
                'relinearization-key-share',
                'relinearization',
                relinearizationKeySwitchSeed(
                    schedule,
                    'round-two',
                    scheduledLevel,
                ),
                `round-two-${String(trusteeRosterPosition)}`,
            );

            return {
                trusteeRosterPosition,
                level: scheduledLevel,
                roundTwoShareRoot: shareMaterial.keySwitchComponentVectorRoot,
                shareMaterial,
            };
        },
    );
    const batchContributions = Array.from(
        { length: participantCount },
        (_unused, trusteeRosterPosition) => ({
            trusteeRosterPosition,
            galoisKeyShares: requiredGaloisKeySchedule.map((scheduleEntry) => {
                const shareMaterial = embeddedShareMaterial(
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
                    galoisKeyShareRoot:
                        shareMaterial.keySwitchComponentVectorRoot,
                    shareMaterial,
                };
            }),
        }),
    );

    return {
        schedule,
        commonInput,
        roundOneContributions,
        roundTwoContributions,
        batchContributions,
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
            objectType: 'TrusteeEvaluationKeyProofMaterialReference',
            proofFamily: trusteeEvaluationKeyProofFamily,
            trusteeIdentity: input.context.trusteeIdentity,
            trusteeRosterPosition: input.context.trusteeRosterPosition,
            statementHash,
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
                    shamirCoefficientIndex: 0,
                    commitment,
                } as const;
            },
        );
        const statementWithoutRoot = {
            objectType: 'VssSameSecretBridgeStatement',
            proofFamily: 'same-secret-bridge',
            ...setupContext,
            publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
            ringDegree,
            ...trusteeReference,
            sourceConstantCoefficientCommitments,
            targetConstantCoefficientCommitmentRoots: [],
            targetConstantCoefficientCommitments: [],
        } as const;

        return {
            ...statementWithoutRoot,
            sameSecretBridgeStatementRoot:
                deriveCanonicalObjectHash(statementWithoutRoot),
        };
    });
    const statementSetWithoutRoot = {
        objectType: 'VssSameSecretBridgeStatementSet',
        proofFamily: 'same-secret-bridge',
        ...setupContext,
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
    } as const;

    return {
        ...statementSetWithoutRoot,
        sameSecretBridgeStatementSetRoot: deriveCanonicalObjectHash(
            statementSetWithoutRoot,
        ),
    };
};

const sameSecretBridgeStatementSetWithWrongSourceLimb =
    (): VssSameSecretBridgeStatementSet => {
        const statementSet = sameSecretBridgeStatementSet();
        const firstStatement = statementSet.statementRecords[0];
        const firstSourceCommitment =
            firstStatement?.sourceConstantCoefficientCommitments[0];
        if (
            firstStatement === undefined ||
            firstSourceCommitment === undefined
        ) {
            throw new Error('Bridge fixture must carry the first source limb.');
        }

        return {
            ...statementSet,
            statementRecords: [
                {
                    ...firstStatement,
                    sourceConstantCoefficientCommitments: [
                        {
                            ...firstSourceCommitment,
                            rnsPrime: qSharePrimes[1],
                        },
                        ...firstStatement.sourceConstantCoefficientCommitments.slice(
                            1,
                        ),
                    ],
                },
                statementSet.statementRecords[1],
            ],
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

const builtRoundsAndBatches = (
    fixture: EvaluationKeyFixture,
): BuiltRoundsAndBatches => {
    const relinearizationKeyShareRounds = createRelinearizationKeyShareRounds(
        relinearizationKeyShareRoundsInput(fixture),
    );
    const galoisKeyShareBatches = createGaloisKeyShareBatches(
        galoisKeyShareBatchesInput(fixture),
    );

    return { relinearizationKeyShareRounds, galoisKeyShareBatches };
};

const trusteeEvaluationKeyProofsInput = (
    fixture: EvaluationKeyFixture,
    overrides: Partial<TrusteeEvaluationKeyProofsInput> = {},
): TrusteeEvaluationKeyProofsInput => ({
    ...fixture.commonInput,
    ...builtRoundsAndBatches(fixture),
    trusteeWitnesses: trusteeWitnesses(),
    sameSecretBridgeStatementSet: sameSecretBridgeStatementSet(),
    trusteeEvaluationKeyProofGenerator: stubGenerator([]),
    ...overrides,
});

const evaluationKeyShareMaterialTransportInput = (
    fixture: EvaluationKeyFixture,
    writer: EvaluationKeyShareComponentMaterialWriter,
    overrides: Partial<EvaluationKeyShareMaterialTransportInput> = {},
): EvaluationKeyShareMaterialTransportInput => ({
    trusteeReferences: fixture.commonInput.trusteeReferences,
    relinearizationRoundOneContributions: fixture.roundOneContributions,
    relinearizationRoundTwoContributions: fixture.roundTwoContributions,
    galoisKeyShareBatchContributions: fixture.batchContributions,
    writeEvaluationKeyShareComponentMaterial: writer,
    ...overrides,
});

const publicEvaluationKeyMaterialTransportInput = (
    fixture: EvaluationKeyFixture,
    writer: PublicEvaluationKeyMaterialWriter,
    overrides: Partial<PublicEvaluationKeyMaterialTransportInput> = {},
): PublicEvaluationKeyMaterialTransportInput => ({
    ...fixture.commonInput,
    ...builtRoundsAndBatches(fixture),
    writePublicEvaluationKeyMaterial: writer,
    ...overrides,
});

const builtTrusteeProofs = async (
    fixture: EvaluationKeyFixture,
    capturedInputs: TrusteeEvaluationKeyProofGeneratorInput[] = [],
): Promise<
    BuiltRoundsAndBatches &
        Awaited<ReturnType<typeof createTrusteeEvaluationKeyProofs>>
> => {
    const { relinearizationKeyShareRounds, galoisKeyShareBatches } =
        builtRoundsAndBatches(fixture);
    const trusteeProofMaterialTransport =
        await createTrusteeEvaluationKeyProofs(
            trusteeEvaluationKeyProofsInput(fixture, {
                relinearizationKeyShareRounds,
                galoisKeyShareBatches,
                trusteeEvaluationKeyProofGenerator:
                    stubGenerator(capturedInputs),
            }),
        );

    return {
        relinearizationKeyShareRounds,
        galoisKeyShareBatches,
        ...trusteeProofMaterialTransport,
    };
};

type EvaluationKeyRejectionCase<Input> = Readonly<{
    name: string;
    createInput(fixture: EvaluationKeyFixture): Input;
    expectedMessage: string;
}>;

const relinearizationKeyShareRoundsRejectionCases = [
    {
        name: 'rejects a key-switch seed outside the shared scheduled sample',
        createInput: (fixture) => {
            const tamperedMaterial = embeddedShareMaterial(
                'relinearization-key-share',
                'relinearization',
                fixtureHash('wrong-seed'),
                'round-one-0',
            );

            return relinearizationKeyShareRoundsInput(fixture, {
                roundOneContributions: [
                    {
                        ...fixture.roundOneContributions[0],
                        roundOneShareRoot:
                            tamperedMaterial.keySwitchComponentVectorRoot,
                        shareMaterial: tamperedMaterial,
                    },
                    fixture.roundOneContributions[1],
                ],
            });
        },
        expectedMessage:
            'keySwitchSeedHex must be shared by scheduled relinearization level and round',
    },
    {
        name: 'rejects a component vector root that does not match the share root',
        createInput: (fixture) =>
            relinearizationKeyShareRoundsInput(fixture, {
                roundOneContributions: [
                    {
                        ...fixture.roundOneContributions[0],
                        roundOneShareRoot: fixtureHash('substituted-share'),
                    },
                    fixture.roundOneContributions[1],
                ],
            }),
        expectedMessage:
            'keySwitchComponentVectorRoot must match the share root',
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
            'evaluatorKeySchedule.setupEpoch must match setupContext.',
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
        createInput: (fixture) => {
            const wrongDomainMaterial = embeddedShareMaterial(
                'galois-key-share',
                'galois-9',
                galoisKeySwitchSeed(fixture.schedule, 3, scheduledLevel),
                'galois-3-0',
            );

            return galoisKeyShareBatchesInput(fixture, {
                batchContributions: [
                    {
                        trusteeRosterPosition: 0,
                        galoisKeyShares: [
                            {
                                rotation: 3,
                                level: scheduledLevel,
                                galoisKeyShareRoot:
                                    wrongDomainMaterial.keySwitchComponentVectorRoot,
                                shareMaterial: wrongDomainMaterial,
                            },
                            fixture.batchContributions[0].galoisKeyShares[1],
                        ],
                    },
                    fixture.batchContributions[1],
                ],
            });
        },
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

describe('createRelinearizationKeyShareRounds', () => {
    it('creates root-bound slim round records with verifier-recomputable aggregate roots', () => {
        const fixture = evaluationKeyFixture();
        const rounds = createRelinearizationKeyShareRounds(
            relinearizationKeyShareRoundsInput(fixture),
        );

        expect(rounds.objectType).toBe('RelinearizationKeyShareRounds');
        expect(rounds.publicKeyShareSetRoot).toBe(
            fixture.schedule.publicKeyShareSetRoot,
        );
        expect(rounds.roundOneRecords).toHaveLength(participantCount);
        expect(rounds.roundTwoRecords).toHaveLength(participantCount);
        for (const record of rounds.roundOneRecords) {
            expect(record.objectType).toBe('RelinearizationKeyShareRoundOne');
            expect(record.setupEpoch).toBe(setupContext.setupEpoch);
            expect(record.keySwitchComponentVectorRoot).toBe(
                record.roundOneShareRoot,
            );
            const recordWithoutRoot = { ...record } as JsonRecord;
            delete recordWithoutRoot.roundOneRecordRoot;
            expect(record.roundOneRecordRoot).toBe(
                deriveCanonicalObjectHash(recordWithoutRoot),
            );
        }
        for (const record of rounds.roundTwoRecords) {
            expect(record.objectType).toBe('RelinearizationKeyShareRoundTwo');
            expect(record.roundOneAggregateRoot).toBe(
                rounds.roundOneAggregateRoots[0].roundOneAggregateRoot,
            );
            const matchingRoundOne = rounds.roundOneRecords.find(
                (roundOneRecord) =>
                    roundOneRecord.trusteeRosterPosition ===
                    record.trusteeRosterPosition,
            );
            expect(record.roundOneRecordRoot).toBe(
                matchingRoundOne?.roundOneRecordRoot,
            );
            expect(record.roundOneShareRoot).toBe(
                matchingRoundOne?.roundOneShareRoot,
            );
        }
        const expectedRoundOneAggregateRoot = deriveCanonicalObjectHash({
            objectType: 'RelinearizationRoundOneAggregate',
            evaluatorKeyScheduleRoot: fixture.schedule.evaluatorKeyScheduleRoot,
            level: scheduledLevel,
            roundOneRecordRoots: rounds.roundOneRecords.map((record) => ({
                trusteeIdentity: record.trusteeIdentity,
                trusteeRosterPosition: record.trusteeRosterPosition,
                roundOneRecordRoot: record.roundOneRecordRoot,
            })),
        });
        expect(rounds.roundOneAggregateRoots).toEqual([
            {
                level: scheduledLevel,
                roundOneAggregateRoot: expectedRoundOneAggregateRoot,
            },
        ]);
        const expectedRoundTwoAggregateRoot = deriveCanonicalObjectHash({
            objectType: 'RelinearizationRoundTwoAggregate',
            evaluatorKeyScheduleRoot: fixture.schedule.evaluatorKeyScheduleRoot,
            level: scheduledLevel,
            roundOneAggregateRoot: expectedRoundOneAggregateRoot,
            roundTwoRecordRoots: rounds.roundTwoRecords.map((record) => ({
                trusteeIdentity: record.trusteeIdentity,
                trusteeRosterPosition: record.trusteeRosterPosition,
                roundTwoRecordRoot: record.roundTwoRecordRoot,
            })),
        });
        expect(rounds.roundTwoAggregateRoots).toEqual([
            {
                level: scheduledLevel,
                roundTwoAggregateRoot: expectedRoundTwoAggregateRoot,
            },
        ]);
        const roundsWithoutRoot = { ...rounds } as JsonRecord;
        delete roundsWithoutRoot.relinearizationKeyShareRoundsRoot;
        expect(rounds.relinearizationKeyShareRoundsRoot).toBe(
            deriveCanonicalObjectHash(roundsWithoutRoot),
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
    it('creates root-bound batches with scheduled material records', () => {
        const fixture = evaluationKeyFixture();
        const batches = createGaloisKeyShareBatches(
            galoisKeyShareBatchesInput(fixture),
        );

        expect(batches).toHaveLength(participantCount);
        batches.forEach((batch, batchIndex) => {
            expect(batch.objectType).toBe('GaloisKeyShareBatch');
            expect(batch.trusteeRosterPosition).toBe(batchIndex);
            expect(batch.galoisKeyShareMaterialRecords).toHaveLength(
                requiredGaloisKeySchedule.length,
            );
            batch.galoisKeyShareMaterialRecords.forEach(
                (materialRecord, scheduleIndex) => {
                    expect(materialRecord.objectType).toBe(
                        'GaloisKeyShareMaterial',
                    );
                    expect(materialRecord.rotation).toBe(
                        requiredGaloisKeySchedule[scheduleIndex].rotation,
                    );
                    expect(materialRecord.trusteeIdentity).toBe(
                        batch.trusteeIdentity,
                    );
                    expect(materialRecord.keySwitchComponentVectorRoot).toBe(
                        materialRecord.galoisKeyShareRoot,
                    );
                },
            );
            const batchWithoutRoot = { ...batch } as JsonRecord;
            delete batchWithoutRoot.galoisKeyShareBatchRoot;
            expect(batch.galoisKeyShareBatchRoot).toBe(
                deriveCanonicalObjectHash(batchWithoutRoot),
            );
        });
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
            relinearizationKeyShareRounds,
        } = await builtTrusteeProofs(fixture, capturedInputs);
        const bridgeStatementSet = sameSecretBridgeStatementSet();

        expect(capturedInputs).toHaveLength(participantCount);
        capturedInputs.forEach((generatorInput, trusteeRosterPosition) => {
            expect(generatorInput.context.trusteeRosterPosition).toBe(
                trusteeRosterPosition,
            );
            expect(generatorInput.context.setupEpoch).toBe(
                setupContext.setupEpoch,
            );
            expect(generatorInput.ringDegree).toBe(ringDegree);
            expect(
                generatorInput.keys.map((statementKey) => [
                    statementKey.proofFamily,
                    statementKey.rotation ?? null,
                ]),
            ).toEqual([
                ['relinearization-round-one', null],
                ['relinearization-round-two', null],
                ['galois-rotation', 3],
                ['galois-rotation', 7],
            ]);
            const roundOneKey = generatorInput.keys[0];
            expect(roundOneKey.componentBByDigit).toHaveLength(digitCount);
            expect(roundOneKey.componentBByDigit[0][0]).toEqual(
                componentCoefficients(
                    `round-one-${String(trusteeRosterPosition)}`,
                    0,
                    0,
                ),
            );
            const roundTwoKey = generatorInput.keys[1];
            const expectedAggregateDiagonal = Array.from(
                { length: digitCount },
                (_unusedDigit, digitIndex) =>
                    Array.from(
                        { length: ringDegree },
                        (_unusedCoefficient, coefficientIndex) =>
                            (componentCoefficients(
                                'round-one-0',
                                digitIndex,
                                digitIndex,
                            )[coefficientIndex] +
                                componentCoefficients(
                                    'round-one-1',
                                    digitIndex,
                                    digitIndex,
                                )[coefficientIndex]) %
                            qSharePrimes[digitIndex],
                    ),
            );
            expect(roundTwoKey.roundOneAggregateDiagonal).toEqual(
                expectedAggregateDiagonal,
            );
            expect(generatorInput.keys[0].roundOneAggregateDiagonal).toBe(
                undefined,
            );
            expect(generatorInput.sameSecretLinkage.publicMatrixSeedHash).toBe(
                fixtureHash('public-matrix-seed'),
            );
            const sourceConstantCommitment =
                bridgeStatementSet.statementRecords[trusteeRosterPosition]
                    ?.sourceConstantCoefficientCommitments[0]?.commitment;
            expect(generatorInput.sameSecretLinkage.commitments).toEqual([
                sourceConstantCommitment,
            ]);
            const expectedSourceConstantCommitmentRoot =
                deriveCanonicalObjectHash(sourceConstantCommitment);
            expect(
                generatorInput.context.sourceConstantCoefficientCommitmentRoot,
            ).toBe(expectedSourceConstantCommitmentRoot);
            expect(generatorInput.errorCoefficientsByKey).toHaveLength(
                statementKeyCount,
            );
        });

        expect(trusteeEvaluationKeyProofs.objectType).toBe(
            'TrusteeEvaluationKeyProofSet',
        );
        expect(
            trusteeEvaluationKeyProofs.relinearizationKeyShareRoundsRoot,
        ).toBe(relinearizationKeyShareRounds.relinearizationKeyShareRoundsRoot);
        expect(trusteeEvaluationKeyProofs.proofRecords).toHaveLength(
            participantCount,
        );
        trusteeEvaluationKeyProofs.proofRecords.forEach(
            (proofRecord, trusteeRosterPosition) => {
                expect(proofRecord.objectType).toBe(
                    'TrusteeEvaluationKeyProof',
                );
                expect(proofRecord.trusteeRosterPosition).toBe(
                    trusteeRosterPosition,
                );
                expect(proofRecord.statementHash).toBe(
                    fixtureHash(`statement-${String(trusteeRosterPosition)}`),
                );
                const proofBytesHex = stubProofBytesHex(trusteeRosterPosition);
                expect(proofRecord.proofBytesHash).toBe(
                    trusteeEvaluationKeyProofBytesHash(proofBytesHex),
                );
                expect(
                    transportedEvaluationKeyShareProofMaterial.proofMaterials[
                        trusteeRosterPosition
                    ]?.proofMaterialRoot,
                ).toBe(proofRecord.proofMaterialRoot);
                const recordWithoutRoot = { ...proofRecord } as JsonRecord;
                delete recordWithoutRoot.trusteeEvaluationKeyProofRoot;
                expect(proofRecord.trusteeEvaluationKeyProofRoot).toBe(
                    deriveCanonicalObjectHash(recordWithoutRoot),
                );
            },
        );
        const proofSetWithoutRoot = {
            ...trusteeEvaluationKeyProofs,
        } as JsonRecord;
        delete proofSetWithoutRoot.trusteeEvaluationKeyProofSetRoot;
        expect(
            trusteeEvaluationKeyProofs.trusteeEvaluationKeyProofSetRoot,
        ).toBe(deriveCanonicalObjectHash(proofSetWithoutRoot));
    });

    it.each(trusteeEvaluationKeyProofsRejectionCases)(
        '$name',
        async ({ createInput, expectedMessage }) => {
            await expect(
                createTrusteeEvaluationKeyProofs(
                    createInput(evaluationKeyFixture()),
                ),
            ).rejects.toThrow(expectedMessage);
        },
    );

    it('rejects tampered embedded component coefficient hashes during aggregate recomputation', async () => {
        const fixture = evaluationKeyFixture();
        const validInput = trusteeEvaluationKeyProofsInput(fixture);
        const tamperedRounds = JSON.parse(
            JSON.stringify(validInput.relinearizationKeyShareRounds),
        ) as typeof validInput.relinearizationKeyShareRounds;
        const tamperedRecord = tamperedRounds.roundOneRecords[0] as unknown as {
            keySwitchComponentVectors: { coefficientVectorHash512: string }[];
        };
        tamperedRecord.keySwitchComponentVectors[0].coefficientVectorHash512 =
            fixtureHash('tampered-coefficient-hash');
        await expect(
            createTrusteeEvaluationKeyProofs({
                ...validInput,
                relinearizationKeyShareRounds: tamperedRounds,
            }),
        ).rejects.toThrow('coefficient hash does not match coefficientsLeHex');
    });
});

describe('trustee evaluation-key canonical proof material', () => {
    it('returns semantic proof records and descriptor-authenticated binary sidecars together', async () => {
        const fixture = evaluationKeyFixture();
        const transport = await builtTrusteeProofs(fixture);

        expect(
            transport.transportedEvaluationKeyShareProofMaterial.proofFamily,
        ).toBe(trusteeEvaluationKeyProofFamily);
        expect(
            transport.transportedEvaluationKeyShareProofMaterial.proofMaterials,
        ).toHaveLength(participantCount);
        transport.trusteeEvaluationKeyProofs.proofRecords.forEach(
            (proofRecord, recordIndex) => {
                const transportedMaterial =
                    transport.transportedEvaluationKeyShareProofMaterial
                        .proofMaterials[recordIndex];
                expect(transportedMaterial.objectType).toBe(
                    'SetupTransportedEvaluationKeyShareProofMaterial',
                );
                expect(transportedMaterial.proofFamily).toBe(
                    trusteeEvaluationKeyProofFamily,
                );
                expect(transportedMaterial.descriptorBytes).toEqual(
                    canonicalStreamDescriptor(
                        BigInt(
                            stubProofBytesHex(proofRecord.trusteeRosterPosition)
                                .length / 2,
                        ),
                        [0x51 + proofRecord.trusteeRosterPosition],
                        0x61 + proofRecord.trusteeRosterPosition,
                    ),
                );
                expect(transportedMaterial.proofMaterialRoot).toBe(
                    proofRecord.proofMaterialRoot,
                );
            },
        );
    });

    it('rejects a generated material root that does not bind the proof identity and hash', async () => {
        const fixture = evaluationKeyFixture();
        const validGenerator = stubGenerator([]);
        await expect(
            createTrusteeEvaluationKeyProofs(
                trusteeEvaluationKeyProofsInput(fixture, {
                    trusteeEvaluationKeyProofGenerator: async (input) => ({
                        ...(await validGenerator(input)),
                        proofMaterialRoot: fixtureHash('wrong-material-root'),
                    }),
                }),
            ),
        ).rejects.toThrow(
            'proofMaterialRoot must bind the trustee proof identity',
        );
    });
});

describe('setup package transport references', () => {
    const descriptorBytes = canonicalStreamDescriptor(1n, [0x41], 0x42);
    const publicKeyMaterialRoot = fixtureHash(
        'normalized-public-key-share-material-set',
    );
    const publicKeyProofRoot = fixtureHash(
        'normalized-public-key-proof-material',
    );
    const vssShareLinkageProofRoot = fixtureHash(
        'normalized-vss-share-linkage-proof-material',
    );
    const sameSecretBridgeProofRoot = fixtureHash(
        'normalized-same-secret-bridge-proof-material',
    );
    const evaluationKeyProofRoot = fixtureHash(
        'normalized-evaluation-key-proof-material',
    );
    const componentRoot = fixtureHash('normalized-component-material');
    const publicEvaluationKeyRoot = fixtureHash(
        'normalized-public-evaluation-key-material',
    );

    const descriptorBackedProofMaterialSet = (
        proofMaterialSetObjectType: string,
        proofMaterialObjectType: string,
        proofFamily: string,
        proofMaterialRoot: string,
    ): DescriptorBackedProofMaterialSet => ({
        objectType: proofMaterialSetObjectType,
        proofFamily,
        proofMaterials: [
            {
                objectType: proofMaterialObjectType,
                proofFamily,
                proofMaterialRoot,
                descriptorBytes: descriptorBytes.slice(),
            },
        ],
    });

    const descriptorBackedCompanionTemplate = {
        transportedPublicKeyShareMaterial: {
            objectType: 'SetupTransportedPublicKeyShareMaterial',
            publicKeyShareMaterialSetRoot: publicKeyMaterialRoot,
            descriptorBytes: descriptorBytes.slice(),
        },
        transportedPublicKeyShareProofMaterial:
            descriptorBackedProofMaterialSet(
                'SetupTransportedPublicKeyShareProofMaterialSet',
                'SetupTransportedPublicKeyShareProofMaterial',
                'public-key-share',
                publicKeyProofRoot,
            ),
        transportedEvaluationKeyShareProofMaterial:
            descriptorBackedProofMaterialSet(
                'SetupTransportedEvaluationKeyShareProofMaterialSet',
                'SetupTransportedEvaluationKeyShareProofMaterial',
                trusteeEvaluationKeyProofFamily,
                evaluationKeyProofRoot,
            ),
        transportedVssShareLinkageProofMaterial:
            descriptorBackedProofMaterialSet(
                'SetupTransportedVssShareLinkageProofMaterialSet',
                'SetupTransportedVssShareLinkageProofMaterial',
                'vss-share-linkage',
                vssShareLinkageProofRoot,
            ),
        transportedSameSecretBridgeProofMaterial:
            descriptorBackedProofMaterialSet(
                'SetupTransportedSameSecretBridgeProofMaterialSet',
                'SetupTransportedSameSecretBridgeProofMaterial',
                'same-secret-bridge',
                sameSecretBridgeProofRoot,
            ),
        transportedEvaluationKeyShareComponentMaterial: {
            objectType:
                'SetupTransportedEvaluationKeyShareComponentMaterialSet',
            componentMaterials: [
                {
                    objectType:
                        'SetupTransportedEvaluationKeyShareComponentMaterial',
                    keySwitchComponentMaterialRoot: componentRoot,
                    descriptorBytes: descriptorBytes.slice(),
                },
            ],
        },
        transportedPublicEvaluationKeyMaterial: {
            objectType: 'SetupTransportedPublicEvaluationKeyMaterialSet',
            publicEvaluationKeyMaterials: [
                {
                    objectType: 'SetupTransportedPublicEvaluationKeyMaterial',
                    publicEvaluationKeyMaterialRoot: publicEvaluationKeyRoot,
                    descriptorBytes: descriptorBytes.slice(),
                },
            ],
        },
    };

    const descriptorBackedCompanions =
        (): typeof descriptorBackedCompanionTemplate =>
            structuredClone(descriptorBackedCompanionTemplate);

    const descriptorBackedSetupPackageVerificationInput = (
        companions: typeof descriptorBackedCompanionTemplate,
    ): SetupPackageVerificationInputSource =>
        ({
            setupPackage: {
                objectType: 'SetupPackage',
            } as SetupPackage,
            expectedManifestHash: fixtureHash('expected-manifest'),
            expectedRosterHash: fixtureHash('expected-roster'),
            ...companions,
        }) as unknown as SetupPackageVerificationInputSource;

    it('preserves the semantic material references used by the kernel', () => {
        const companions = descriptorBackedCompanions();
        const verificationInput = createSetupPackageVerificationInput(
            descriptorBackedSetupPackageVerificationInput(companions),
        );
        const publicKeyMaterial =
            verificationInput.transportedPublicKeyShareMaterial as JsonRecord;
        expect(publicKeyMaterial).toMatchObject({
            objectType: 'SetupTransportedPublicKeyShareMaterial',
            publicKeyShareMaterialSetRoot: publicKeyMaterialRoot,
        });

        expect(
            (
                verificationInput.transportedPublicKeyShareProofMaterial as JsonRecord
            ).proofMaterials,
        ).toEqual([
            expect.objectContaining({
                objectType: 'SetupTransportedPublicKeyShareProofMaterial',
                proofFamily: 'public-key-share',
                proofMaterialRoot: publicKeyProofRoot,
            }),
        ]);
        expect(
            (
                verificationInput.transportedEvaluationKeyShareComponentMaterial as JsonRecord
            ).componentMaterials,
        ).toEqual([
            expect.objectContaining({
                objectType:
                    'SetupTransportedEvaluationKeyShareComponentMaterial',
                keySwitchComponentMaterialRoot: componentRoot,
            }),
        ]);
        expect(
            (
                verificationInput.transportedPublicEvaluationKeyMaterial as JsonRecord
            ).publicEvaluationKeyMaterials,
        ).toEqual([
            expect.objectContaining({
                objectType: 'SetupTransportedPublicEvaluationKeyMaterial',
                publicEvaluationKeyMaterialRoot: publicEvaluationKeyRoot,
            }),
        ]);

        const evaluationKeyProofMaterials = (
            verificationInput.transportedEvaluationKeyShareProofMaterial as JsonRecord
        ).proofMaterials as readonly JsonRecord[];
        expect(evaluationKeyProofMaterials[0]).toMatchObject({
            objectType: 'SetupTransportedEvaluationKeyShareProofMaterial',
            proofFamily: trusteeEvaluationKeyProofFamily,
            proofMaterialRoot: evaluationKeyProofRoot,
        });

        for (const [
            proofSet,
            expectedObjectType,
            expectedProofFamily,
            expectedProofMaterialRoot,
        ] of [
            [
                verificationInput.transportedVssShareLinkageProofMaterial,
                'SetupTransportedVssShareLinkageProofMaterial',
                'vss-share-linkage',
                vssShareLinkageProofRoot,
            ],
            [
                verificationInput.transportedSameSecretBridgeProofMaterial,
                'SetupTransportedSameSecretBridgeProofMaterial',
                'same-secret-bridge',
                sameSecretBridgeProofRoot,
            ],
        ] as const) {
            const proofMaterials = (proofSet as JsonRecord)
                .proofMaterials as readonly JsonRecord[];
            expect(proofMaterials[0]).toMatchObject({
                objectType: expectedObjectType,
                proofFamily: expectedProofFamily,
                proofMaterialRoot: expectedProofMaterialRoot,
            });
        }
    });
});

describe('createBinaryChunkedEvaluationKeyShareMaterialTransport', () => {
    it('moves embedded component vectors into canonical streams for every contribution', async () => {
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
            expect(material.ringDegree).toBe(ringDegree);
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

    it('rejects contributions for unknown trustee roster positions', async () => {
        const fixture = evaluationKeyFixture();
        const materialStore = componentMaterialStore();
        await expect(
            createBinaryChunkedEvaluationKeyShareMaterialTransport(
                evaluationKeyShareMaterialTransportInput(
                    fixture,
                    materialStore.writer,
                    {
                        relinearizationRoundOneContributions: [
                            {
                                ...fixture.roundOneContributions[0],
                                trusteeRosterPosition: 7,
                            },
                        ],
                        relinearizationRoundTwoContributions: [],
                        galoisKeyShareBatchContributions: [],
                    },
                ),
            ),
        ).rejects.toThrow(
            'references a trustee roster position without a trustee reference',
        );
    });

    it('rejects duplicate component material roots', async () => {
        const fixture = evaluationKeyFixture();
        const materialStore = componentMaterialStore();
        await expect(
            createBinaryChunkedEvaluationKeyShareMaterialTransport(
                evaluationKeyShareMaterialTransportInput(
                    fixture,
                    materialStore.writer,
                    {
                        relinearizationRoundOneContributions: [
                            fixture.roundOneContributions[0],
                            fixture.roundOneContributions[0],
                        ],
                        relinearizationRoundTwoContributions: [],
                        galoisKeyShareBatchContributions: [],
                    },
                ),
            ),
        ).rejects.toThrow(
            'transported evaluation-key component material contains duplicate roots',
        );
    });
});

describe('createPublicEvaluationKeySet', () => {
    it('derives relinearization and Galois key roots from the verified records', () => {
        const fixture = evaluationKeyFixture();
        const { relinearizationKeyShareRounds, galoisKeyShareBatches } =
            builtRoundsAndBatches(fixture);
        const evaluationKeys = createPublicEvaluationKeySet({
            ...fixture.commonInput,
            relinearizationKeyShareRounds,
            galoisKeyShareBatches,
        });

        expect(evaluationKeys.objectType).toBe('PublicEvaluationKeySet');
        expect(evaluationKeys.relinearizationKeyRoots).toHaveLength(1);
        const relinearizationKeyRoot =
            evaluationKeys.relinearizationKeyRoots[0];
        expect(relinearizationKeyRoot.level).toBe(scheduledLevel);
        expect(relinearizationKeyRoot.roundOneAggregateRoot).toBe(
            relinearizationKeyShareRounds.roundOneAggregateRoots[0]
                .roundOneAggregateRoot,
        );
        expect(evaluationKeys.galoisKeyRoots).toHaveLength(
            requiredGaloisKeySchedule.length,
        );
        evaluationKeys.galoisKeyRoots.forEach(
            (galoisKeyRoot, scheduleIndex) => {
                expect(galoisKeyRoot.rotation).toBe(
                    requiredGaloisKeySchedule[scheduleIndex].rotation,
                );
                expect(galoisKeyRoot.contributingShareRoots).toHaveLength(
                    participantCount,
                );
                galoisKeyRoot.contributingShareRoots.forEach(
                    (contributingShareRoot, trusteeRosterPosition) => {
                        expect(
                            contributingShareRoot.trusteeRosterPosition,
                        ).toBe(trusteeRosterPosition);
                    },
                );
            },
        );
        const evaluationKeysWithoutHash = { ...evaluationKeys } as JsonRecord;
        delete evaluationKeysWithoutHash.evaluationKeySetHash;
        expect(evaluationKeys.evaluationKeySetHash).toBe(
            deriveCanonicalObjectHash(evaluationKeysWithoutHash),
        );
    });

    it('rejects Galois batches outside the accepted evaluation-key binding', () => {
        const fixture = evaluationKeyFixture();
        const { relinearizationKeyShareRounds, galoisKeyShareBatches } =
            builtRoundsAndBatches(fixture);
        const tamperedBatch = {
            ...galoisKeyShareBatches[0],
            publicKeyShareSuccinctProofSetRoot: fixtureHash('other-proof-set'),
        };
        expect(() =>
            createPublicEvaluationKeySet({
                ...fixture.commonInput,
                relinearizationKeyShareRounds,
                galoisKeyShareBatches: [
                    tamperedBatch,
                    galoisKeyShareBatches[1],
                ],
            }),
        ).toThrow(
            'galoisKeyShareBatches must match the accepted evaluation-key binding',
        );
    });
});

describe('createBinaryChunkedPublicEvaluationKeyMaterialTransport', () => {
    const publicEvaluationKeyMaterialStore = (): Readonly<{
        bytes(materialRoot: string): Uint8Array;
        writer: PublicEvaluationKeyMaterialWriter;
    }> => {
        const storedChunks = new Map<string, readonly ArrayBuffer[]>();
        const writer: PublicEvaluationKeyMaterialWriter = async (input) => {
            const chunkCount = Math.ceil(
                input.totalByteLength / canonicalChunkByteLength,
            );
            const chunks: ArrayBuffer[] = [];
            for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex += 1) {
                const expectedByteLength = Math.min(
                    canonicalChunkByteLength,
                    input.totalByteLength -
                        chunkIndex * canonicalChunkByteLength,
                );
                const chunk = await input.pullChunk({
                    chunkIndex,
                    expectedByteLength,
                });
                if (chunk?.byteLength !== expectedByteLength) {
                    throw new Error(
                        'The public evaluation-key material source was truncated.',
                    );
                }
                chunks.push(chunk.slice(0));
            }
            const repeatedFirstChunk = await input.pullChunk({
                chunkIndex: 0,
                expectedByteLength: Math.min(
                    canonicalChunkByteLength,
                    input.totalByteLength,
                ),
            });
            if (repeatedFirstChunk?.byteLength !== chunks[0]?.byteLength) {
                throw new Error(
                    'The public evaluation-key material source is not repeatable.',
                );
            }
            storedChunks.set(input.publicEvaluationKeyMaterialRoot, chunks);
            const rootByte = Number.parseInt(
                input.publicEvaluationKeyMaterialRoot.slice(0, 2),
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
            bytes: (materialRoot) => {
                const chunks = storedChunks.get(materialRoot);
                if (chunks === undefined) {
                    throw new Error(
                        'The public evaluation-key material was not stored.',
                    );
                }
                const byteLength = chunks.reduce(
                    (total, chunk) => total + chunk.byteLength,
                    0,
                );
                const bytes = new Uint8Array(byteLength);
                let byteOffset = 0;
                for (const chunk of chunks) {
                    bytes.set(new Uint8Array(chunk), byteOffset);
                    byteOffset += chunk.byteLength;
                }
                return bytes;
            },
            writer,
        };
    };

    it('binds a canonical manifest with share material roots and chunked transport', async () => {
        const fixture = evaluationKeyFixture();
        const materialStore = publicEvaluationKeyMaterialStore();
        const { relinearizationKeyShareRounds, galoisKeyShareBatches } =
            builtRoundsAndBatches(fixture);
        const transport =
            await createBinaryChunkedPublicEvaluationKeyMaterialTransport(
                publicEvaluationKeyMaterialTransportInput(
                    fixture,
                    materialStore.writer,
                    {
                        relinearizationKeyShareRounds,
                        galoisKeyShareBatches,
                    },
                ),
            );

        const transportedMaterial =
            transport.transportedPublicEvaluationKeyMaterial
                .publicEvaluationKeyMaterials[0];
        expect(transportedMaterial.evaluationKeySetHash).toBe(
            transport.evaluationKeys.evaluationKeySetHash,
        );
        expect(transportedMaterial.descriptorBytes.byteLength).toBeGreaterThan(
            0,
        );
        const materialBytes = materialStore.bytes(
            transportedMaterial.publicEvaluationKeyMaterialRoot,
        );
        // SLEKPMV1 magic prefix before the canonical JSON manifest bytes.
        expect(Buffer.from(materialBytes.subarray(0, 8)).toString('hex')).toBe(
            '534c454b504d5631',
        );
        const manifestJson = Buffer.from(materialBytes.subarray(8)).toString(
            'utf8',
        );
        const manifest = JSON.parse(manifestJson) as JsonRecord;
        expect(manifest.objectType).toBe('PublicEvaluationKeyMaterialManifest');
        const relinearizationShareMaterialRoots =
            manifest.relinearizationShareMaterialRoots as readonly JsonRecord[];
        expect(relinearizationShareMaterialRoots).toHaveLength(
            participantCount * 2,
        );
        expect(relinearizationShareMaterialRoots[0].round).toBe('round-one');
        const galoisShareMaterialRoots =
            manifest.galoisShareMaterialRoots as readonly JsonRecord[];
        expect(galoisShareMaterialRoots).toHaveLength(
            participantCount * requiredGaloisKeySchedule.length,
        );
    });

    it('rejects undeclared transported component material for embedded records', async () => {
        const fixture = evaluationKeyFixture();
        const materialStore = publicEvaluationKeyMaterialStore();
        const { relinearizationKeyShareRounds, galoisKeyShareBatches } =
            builtRoundsAndBatches(fixture);
        await expect(
            createBinaryChunkedPublicEvaluationKeyMaterialTransport(
                publicEvaluationKeyMaterialTransportInput(
                    fixture,
                    materialStore.writer,
                    {
                        relinearizationKeyShareRounds,
                        galoisKeyShareBatches,
                        transportedEvaluationKeyShareComponentMaterial: {
                            objectType:
                                'SetupTransportedEvaluationKeyShareComponentMaterialSet',
                            componentMaterials: [
                                {
                                    keySwitchComponentMaterialRoot:
                                        fixtureHash('x'),
                                },
                            ],
                        },
                    },
                ),
            ),
        ).rejects.toThrow(
            'transportedEvaluationKeyShareComponentMaterial must not be supplied when evaluation-key records do not use binary component material',
        );
    });

    it('requires component material coverage for streamed records', async () => {
        const fixture = evaluationKeyFixture();
        const materialStore = componentMaterialStore();
        const publicMaterialStore = publicEvaluationKeyMaterialStore();
        const shareTransport =
            await createBinaryChunkedEvaluationKeyShareMaterialTransport(
                evaluationKeyShareMaterialTransportInput(
                    fixture,
                    materialStore.writer,
                ),
            );
        const rounds = createRelinearizationKeyShareRounds(
            relinearizationKeyShareRoundsInput(fixture, {
                roundOneContributions:
                    shareTransport.relinearizationRoundOneContributions,
                roundTwoContributions:
                    shareTransport.relinearizationRoundTwoContributions,
            }),
        );
        const batches = createGaloisKeyShareBatches(
            galoisKeyShareBatchesInput(fixture, {
                batchContributions:
                    shareTransport.galoisKeyShareBatchContributions,
            }),
        );
        await expect(
            createBinaryChunkedPublicEvaluationKeyMaterialTransport(
                publicEvaluationKeyMaterialTransportInput(
                    fixture,
                    publicMaterialStore.writer,
                    {
                        relinearizationKeyShareRounds: rounds,
                        galoisKeyShareBatches: batches,
                    },
                ),
            ),
        ).rejects.toThrow(
            'transportedEvaluationKeyShareComponentMaterial is required for binary evaluation-key component material',
        );
        const transport =
            await createBinaryChunkedPublicEvaluationKeyMaterialTransport(
                publicEvaluationKeyMaterialTransportInput(
                    fixture,
                    publicMaterialStore.writer,
                    {
                        relinearizationKeyShareRounds: rounds,
                        galoisKeyShareBatches: batches,
                        transportedEvaluationKeyShareComponentMaterial:
                            shareTransport.transportedEvaluationKeyShareComponentMaterial,
                    },
                ),
            );
        const manifest = JSON.parse(
            Buffer.from(
                publicMaterialStore
                    .bytes(
                        transport.transportedPublicEvaluationKeyMaterial
                            .publicEvaluationKeyMaterials[0]
                            .publicEvaluationKeyMaterialRoot,
                    )
                    .subarray(8),
            ).toString('utf8'),
        ) as JsonRecord;
        const relinearizationShareMaterialRoots =
            manifest.relinearizationShareMaterialRoots as readonly JsonRecord[];
        expect(
            relinearizationShareMaterialRoots[0].keySwitchComponentMaterialRoot,
        ).not.toBe(null);
    });
});
