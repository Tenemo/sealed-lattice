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
    transportTrusteeEvaluationKeyProofSet,
    trusteeEvaluationKeyProofFamily,
    type EvaluationKeyProofCommonInput,
    type EvaluationKeyShareMaterial,
    type GaloisKeyShareBatchContribution,
    type RelinearizationRoundOneContribution,
    type RelinearizationRoundTwoContribution,
    type SameSecretProofReference,
    type TrusteeEvaluationKeyProofGenerator,
    type TrusteeEvaluationKeyWitnessInput,
    type TrusteeSameSecretBridgeAnchorInput,
} from '#packages/protocol/src/setup/evaluation-key-proof-records';
import {
    createRequiredGaloisSet,
    type EvaluatorKeySchedule,
    type RequiredGaloisKeyScheduleEntry,
} from '#packages/protocol/src/setup/evaluator-key-schedule';
import {
    makeSetupContext,
    makeSetupFixtureHash,
} from '#tests/support/setup-fixtures';

type JsonRecord = Record<string, unknown>;
type TrusteeEvaluationKeyProofGeneratorInput =
    Parameters<TrusteeEvaluationKeyProofGenerator>[0];

const qSharePrimes = [
    140_737_487_306_753, 140_737_486_716_929, 140_737_486_520_321,
] as const;
const participantCount = 2;
const scheduledLevel = 1;
const ringDegree = 8;
const digitCount = scheduledLevel + 1;

const fixtureHash = makeSetupFixtureHash('setup-evaluation-key-proof-records');

const setupContext = makeSetupContext(fixtureHash);

const requiredGaloisKeySchedule = [
    {
        rotation: 3,
        level: scheduledLevel,
        purpose: 'direct-score-packing-basis',
        proofFamily: 'galois-key-share',
    },
    {
        rotation: 7,
        level: scheduledLevel,
        purpose: 'packed-rank-return-basis',
        proofFamily: 'galois-key-share',
    },
] as const satisfies readonly RequiredGaloisKeyScheduleEntry[];

const evaluatorKeySchedule = (): EvaluatorKeySchedule => {
    const requiredGaloisSetHash = deriveCanonicalObjectHash(
        createRequiredGaloisSet(qSharePrimes.length, requiredGaloisKeySchedule),
    );
    const scheduleWithoutRoot = {
        objectType: 'EvaluatorKeySchedule',
        ...setupContext,
        participantCount,
        rnsLimbCount: qSharePrimes.length,
        publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
        relinearizationCrpRoot: fixtureHash('relinearization-crp'),
        galoisKeyCrpRoot: fixtureHash('galois-key-crp'),
        sameSecretConsistencyRoot: fixtureHash('same-secret-consistency'),
        publicKeyShareSetRoot: fixtureHash('public-key-share-set'),
        publicKeyShareProofSetRoot: fixtureHash('public-key-share-proof-set'),
        relinearizationLevelSchedule: [
            {
                level: scheduledLevel,
                proofFamily: 'relinearization-key-share',
                keyShareRounds: ['round-one', 'round-two'],
            },
        ],
        requiredGaloisKeySchedule,
        requiredGaloisSetHash,
    } as const satisfies Omit<EvaluatorKeySchedule, 'evaluatorKeyScheduleRoot'>;

    return {
        ...scheduleWithoutRoot,
        evaluatorKeyScheduleRoot:
            deriveCanonicalObjectHash(scheduleWithoutRoot),
    } satisfies EvaluatorKeySchedule;
};

const sameSecretProofReferences = (): readonly SameSecretProofReference[] =>
    Array.from(
        { length: participantCount },
        (_unused, trusteeRosterPosition) => ({
            trusteeIdentity: `trustee-${String(trusteeRosterPosition)}`,
            trusteeRosterPosition,
            sameSecretStatementRoot: fixtureHash(
                `same-secret-statement-${String(trusteeRosterPosition)}`,
            ),
            trusteeSecretCommitmentRoot: fixtureHash(
                `trustee-secret-commitment-${String(trusteeRosterPosition)}`,
            ),
            sameSecretProofRoot: fixtureHash(
                `same-secret-proof-${String(trusteeRosterPosition)}`,
            ),
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
        keySwitchSampleScope: 'shared-by-scheduled-level-and-round',
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
        keySwitchSampleScope: 'shared-by-scheduled-rotation-and-level',
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
                component: 'b',
                coefficientByteLength: ringDegree * 8,
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
        sameSecretProofSetRoot: fixtureHash('same-secret-proof-set'),
        sameSecretProofFamilyBindingRoot: fixtureHash(
            'same-secret-proof-family-binding',
        ),
        publicKeyShareSuccinctProofSetRoot: fixtureHash(
            'public-key-share-lnp-proof-set',
        ),
        sameSecretProofReferences: sameSecretProofReferences(),
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
        'sealed-lattice/setup/trustee-evaluation-key/proof-bytes-v1',
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

        return {
            operation: 'generateTrusteeEvaluationKeyProof',
            statementHash: fixtureHash(
                `statement-${String(input.context.trusteeRosterPosition)}`,
            ),
            limbCount: qSharePrimes.length,
            proofByteLength: proofBytesHex.length / 2,
            proofBytesHex,
        };
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

const sameSecretBridgeAnchors = (): TrusteeSameSecretBridgeAnchorInput[] =>
    Array.from(
        { length: participantCount },
        (_unused, trusteeRosterPosition) => ({
            trusteeRosterPosition,
            publicMatrixSeedHash: fixtureHash('bridge-public-matrix-seed'),
            targetBasisHash: fixtureHash('bridge-target-basis'),
            targetRnsPrimes: [17],
            targetConstantCommitmentRoots: [
                fixtureHash(
                    `bridge-target-root-${String(trusteeRosterPosition)}`,
                ),
            ],
            targetConstantCommitments: [
                {
                    objectType: 'VssPublicCommitmentFixture',
                    trusteeRosterPosition,
                },
            ],
        }),
    );

type BuiltRoundsAndBatches = Readonly<{
    relinearizationKeyShareRounds: ReturnType<
        typeof createRelinearizationKeyShareRounds
    >;
    galoisKeyShareBatches: ReturnType<typeof createGaloisKeyShareBatches>;
}>;

const builtRoundsAndBatches = (
    fixture: EvaluationKeyFixture,
): BuiltRoundsAndBatches => {
    const relinearizationKeyShareRounds = createRelinearizationKeyShareRounds({
        ...fixture.commonInput,
        roundOneContributions: fixture.roundOneContributions,
        roundTwoContributions: fixture.roundTwoContributions,
    });
    const galoisKeyShareBatches = createGaloisKeyShareBatches({
        ...fixture.commonInput,
        batchContributions: fixture.batchContributions,
    });

    return { relinearizationKeyShareRounds, galoisKeyShareBatches };
};

const builtTrusteeProofs = (
    fixture: EvaluationKeyFixture,
    capturedInputs: TrusteeEvaluationKeyProofGeneratorInput[] = [],
): BuiltRoundsAndBatches &
    Readonly<{
        trusteeEvaluationKeyProofs: ReturnType<
            typeof createTrusteeEvaluationKeyProofs
        >;
    }> => {
    const { relinearizationKeyShareRounds, galoisKeyShareBatches } =
        builtRoundsAndBatches(fixture);
    const trusteeEvaluationKeyProofs = createTrusteeEvaluationKeyProofs({
        ...fixture.commonInput,
        relinearizationKeyShareRounds,
        galoisKeyShareBatches,
        keySwitchDecompositionHash: fixtureHash('key-switch-decomposition'),
        trusteeWitnesses: trusteeWitnesses(),
        sameSecretBridgeAnchors: sameSecretBridgeAnchors(),
        trusteeEvaluationKeyProofGenerator: stubGenerator(capturedInputs),
    });

    return {
        relinearizationKeyShareRounds,
        galoisKeyShareBatches,
        trusteeEvaluationKeyProofs,
    };
};

describe('createRelinearizationKeyShareRounds', () => {
    it('creates root-bound slim round records with verifier-recomputable aggregate roots', () => {
        const fixture = evaluationKeyFixture();
        const rounds = createRelinearizationKeyShareRounds({
            ...fixture.commonInput,
            roundOneContributions: fixture.roundOneContributions,
            roundTwoContributions: fixture.roundTwoContributions,
        });

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

    it('rejects a key-switch seed outside the shared scheduled sample', () => {
        const fixture = evaluationKeyFixture();
        const tamperedMaterial = embeddedShareMaterial(
            'relinearization-key-share',
            'relinearization',
            fixtureHash('wrong-seed'),
            'round-one-0',
        );
        expect(() =>
            createRelinearizationKeyShareRounds({
                ...fixture.commonInput,
                roundOneContributions: [
                    {
                        ...fixture.roundOneContributions[0],
                        roundOneShareRoot:
                            tamperedMaterial.keySwitchComponentVectorRoot,
                        shareMaterial: tamperedMaterial,
                    },
                    fixture.roundOneContributions[1],
                ],
                roundTwoContributions: fixture.roundTwoContributions,
            }),
        ).toThrow(
            'keySwitchSeedHex must be shared by scheduled relinearization level and round',
        );
    });

    it('rejects a component vector root that does not match the share root', () => {
        const fixture = evaluationKeyFixture();
        expect(() =>
            createRelinearizationKeyShareRounds({
                ...fixture.commonInput,
                roundOneContributions: [
                    {
                        ...fixture.roundOneContributions[0],
                        roundOneShareRoot: fixtureHash('substituted-share'),
                    },
                    fixture.roundOneContributions[1],
                ],
                roundTwoContributions: fixture.roundTwoContributions,
            }),
        ).toThrow('keySwitchComponentVectorRoot must match the share root');
    });

    it('rejects missing and duplicate scheduled contributions', () => {
        const fixture = evaluationKeyFixture();
        expect(() =>
            createRelinearizationKeyShareRounds({
                ...fixture.commonInput,
                roundOneContributions: fixture.roundOneContributions.slice(1),
                roundTwoContributions: fixture.roundTwoContributions,
            }),
        ).toThrow(
            'roundOneContributions is missing a scheduled trustee and level',
        );
        expect(() =>
            createRelinearizationKeyShareRounds({
                ...fixture.commonInput,
                roundOneContributions: [
                    ...fixture.roundOneContributions,
                    fixture.roundOneContributions[0],
                ],
                roundTwoContributions: fixture.roundTwoContributions,
            }),
        ).toThrow('roundOneContributions must not repeat a trustee and level');
    });

    it('rejects an evaluator key schedule outside the setup context', () => {
        const fixture = evaluationKeyFixture();
        expect(() =>
            createRelinearizationKeyShareRounds({
                ...fixture.commonInput,
                setupContext: {
                    ...setupContext,
                    setupEpoch: 'setup-epoch-2',
                },
                roundOneContributions: fixture.roundOneContributions,
                roundTwoContributions: fixture.roundTwoContributions,
            }),
        ).toThrow('evaluatorKeySchedule.setupEpoch must match setupContext.');
    });
});

describe('createGaloisKeyShareBatches', () => {
    it('creates root-bound batches with scheduled material records', () => {
        const fixture = evaluationKeyFixture();
        const batches = createGaloisKeyShareBatches({
            ...fixture.commonInput,
            batchContributions: fixture.batchContributions,
        });

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

    it('rejects shares outside the frozen Galois key schedule order', () => {
        const fixture = evaluationKeyFixture();
        expect(() =>
            createGaloisKeyShareBatches({
                ...fixture.commonInput,
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
        ).toThrow('galoisKeyShares must follow the frozen Galois key schedule');
    });

    it('rejects a Galois key-switch domain outside the scheduled rotation', () => {
        const fixture = evaluationKeyFixture();
        const schedule = fixture.schedule;
        const wrongDomainMaterial = embeddedShareMaterial(
            'galois-key-share',
            'galois-9',
            galoisKeySwitchSeed(schedule, 3, scheduledLevel),
            'galois-3-0',
        );
        expect(() =>
            createGaloisKeyShareBatches({
                ...fixture.commonInput,
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
            }),
        ).toThrow('keySwitchDomain must match the scheduled Galois rotation');
    });

    it('rejects missing trustee batches', () => {
        const fixture = evaluationKeyFixture();
        expect(() =>
            createGaloisKeyShareBatches({
                ...fixture.commonInput,
                batchContributions: fixture.batchContributions.slice(0, 1),
            }),
        ).toThrow('batchContributions must contain one batch per participant');
    });
});

describe('createTrusteeEvaluationKeyProofs', () => {
    it('builds one statement per trustee in frozen key order with recomputed public aggregates', () => {
        const fixture = evaluationKeyFixture();
        const capturedInputs: TrusteeEvaluationKeyProofGeneratorInput[] = [];
        const { trusteeEvaluationKeyProofs, relinearizationKeyShareRounds } =
            builtTrusteeProofs(fixture, capturedInputs);

        expect(capturedInputs).toHaveLength(participantCount);
        capturedInputs.forEach((generatorInput, trusteeRosterPosition) => {
            expect(generatorInput.context.trusteeRosterPosition).toBe(
                trusteeRosterPosition,
            );
            expect(generatorInput.context.setupEpoch).toBe(
                setupContext.setupEpoch,
            );
            expect(generatorInput.context.keySwitchDecompositionHash).toBe(
                fixtureHash('key-switch-decomposition'),
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
            expect(generatorInput.sameSecretBridge.publicMatrixSeedHash).toBe(
                fixtureHash('bridge-public-matrix-seed'),
            );
            expect(generatorInput.sameSecretBridge.sourceTrusteeIdentity).toBe(
                generatorInput.context.trusteeIdentity,
            );
            expect(
                generatorInput.sameSecretBridge.sourceTrusteeRosterPosition,
            ).toBe(generatorInput.context.trusteeRosterPosition);
            expect(generatorInput.errorCoefficientsByKey).toHaveLength(
                statementKeyCount,
            );
        });

        expect(trusteeEvaluationKeyProofs.objectType).toBe(
            'TrusteeEvaluationKeyProofSet',
        );
        expect(trusteeEvaluationKeyProofs.proofFamily).toBe(
            trusteeEvaluationKeyProofFamily,
        );
        expect(trusteeEvaluationKeyProofs.keySwitchDecompositionHash).toBe(
            fixtureHash('key-switch-decomposition'),
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
                expect(proofRecord).toHaveProperty(
                    'proofBytesHex',
                    proofBytesHex,
                );
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

    it('rejects witnesses that do not cover every statement key or participant', () => {
        const fixture = evaluationKeyFixture();
        const { relinearizationKeyShareRounds, galoisKeyShareBatches } =
            builtRoundsAndBatches(fixture);
        const completeWitnesses = trusteeWitnesses();
        expect(() =>
            createTrusteeEvaluationKeyProofs({
                ...fixture.commonInput,
                relinearizationKeyShareRounds,
                galoisKeyShareBatches,
                keySwitchDecompositionHash: fixtureHash(
                    'key-switch-decomposition',
                ),
                trusteeWitnesses: completeWitnesses.slice(0, 1),
                sameSecretBridgeAnchors: sameSecretBridgeAnchors(),
                trusteeEvaluationKeyProofGenerator: stubGenerator([]),
            }),
        ).toThrow('trusteeWitnesses must contain one witness per participant');
        expect(() =>
            createTrusteeEvaluationKeyProofs({
                ...fixture.commonInput,
                relinearizationKeyShareRounds,
                galoisKeyShareBatches,
                keySwitchDecompositionHash: fixtureHash(
                    'key-switch-decomposition',
                ),
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
                sameSecretBridgeAnchors: sameSecretBridgeAnchors(),
                trusteeEvaluationKeyProofGenerator: stubGenerator([]),
            }),
        ).toThrow(
            'trusteeWitnesses.errorCoefficientsByKey must contain one error vector set per statement key',
        );
    });

    it('rejects rounds that do not bind the accepted evaluation-key roots', () => {
        const fixture = evaluationKeyFixture();
        const { relinearizationKeyShareRounds, galoisKeyShareBatches } =
            builtRoundsAndBatches(fixture);
        expect(() =>
            createTrusteeEvaluationKeyProofs({
                ...fixture.commonInput,
                sameSecretProofSetRoot: fixtureHash('other-proof-set'),
                relinearizationKeyShareRounds,
                galoisKeyShareBatches,
                keySwitchDecompositionHash: fixtureHash(
                    'key-switch-decomposition',
                ),
                trusteeWitnesses: trusteeWitnesses(),
                sameSecretBridgeAnchors: sameSecretBridgeAnchors(),
                trusteeEvaluationKeyProofGenerator: stubGenerator([]),
            }),
        ).toThrow(
            'relinearizationKeyShareRounds must match the accepted evaluation-key binding',
        );
    });

    it('rejects tampered embedded component coefficient hashes during aggregate recomputation', () => {
        const fixture = evaluationKeyFixture();
        const { relinearizationKeyShareRounds, galoisKeyShareBatches } =
            builtRoundsAndBatches(fixture);
        const tamperedRounds = JSON.parse(
            JSON.stringify(relinearizationKeyShareRounds),
        ) as typeof relinearizationKeyShareRounds;
        const tamperedRecord = tamperedRounds.roundOneRecords[0] as unknown as {
            keySwitchComponentVectors: { coefficientVectorHash512: string }[];
        };
        tamperedRecord.keySwitchComponentVectors[0].coefficientVectorHash512 =
            fixtureHash('tampered-coefficient-hash');
        expect(() =>
            createTrusteeEvaluationKeyProofs({
                ...fixture.commonInput,
                relinearizationKeyShareRounds: tamperedRounds,
                galoisKeyShareBatches,
                keySwitchDecompositionHash: fixtureHash(
                    'key-switch-decomposition',
                ),
                trusteeWitnesses: trusteeWitnesses(),
                sameSecretBridgeAnchors: sameSecretBridgeAnchors(),
                trusteeEvaluationKeyProofGenerator: stubGenerator([]),
            }),
        ).toThrow('coefficient hash does not match coefficientsLeHex');
    });
});

describe('transportTrusteeEvaluationKeyProofSet', () => {
    it('moves proof bytes into chunked transport and rebinds record and set roots', () => {
        const fixture = evaluationKeyFixture();
        const { trusteeEvaluationKeyProofs } = builtTrusteeProofs(fixture);
        const transport = transportTrusteeEvaluationKeyProofSet(
            trusteeEvaluationKeyProofs,
        );

        expect(
            transport.transportedEvaluationKeyShareProofMaterial.proofFamily,
        ).toBe(trusteeEvaluationKeyProofFamily);
        expect(
            transport.transportedEvaluationKeyShareProofMaterial.proofMaterials,
        ).toHaveLength(participantCount);
        transport.trusteeEvaluationKeyProofs.proofRecords.forEach(
            (proofRecord, recordIndex) => {
                const recordFields = proofRecord as JsonRecord;
                expect(recordFields.proofBytesEncoding).toBe(
                    'binary-chunked-proof-bytes',
                );
                expect(recordFields.proofChunkCount).toBe(1);
                const transportedMaterial =
                    transport.transportedEvaluationKeyShareProofMaterial
                        .proofMaterials[recordIndex];
                expect(transportedMaterial.objectType).toBe(
                    'SetupTransportedEvaluationKeyShareProofMaterial',
                );
                expect(transportedMaterial.proofFamily).toBe(
                    trusteeEvaluationKeyProofFamily,
                );
                expect(transportedMaterial.proofMaterialRoot).toBe(
                    recordFields.proofMaterialRoot,
                );
                const chunks = transportedMaterial.chunks as readonly {
                    chunkIndex: number;
                    bytesHex: string;
                }[];
                expect(chunks).toHaveLength(1);
                expect(chunks[0].bytesHex).toBe(
                    stubProofBytesHex(proofRecord.trusteeRosterPosition),
                );
                expect(recordFields.proofTotalByteLength).toBe(
                    chunks[0].bytesHex.length / 2,
                );
                const recordWithoutRoot = { ...proofRecord } as JsonRecord;
                delete recordWithoutRoot.trusteeEvaluationKeyProofRoot;
                expect(proofRecord.trusteeEvaluationKeyProofRoot).toBe(
                    deriveCanonicalObjectHash(recordWithoutRoot),
                );
            },
        );
        const proofSetWithoutRoot = {
            ...transport.trusteeEvaluationKeyProofs,
        } as JsonRecord;
        delete proofSetWithoutRoot.trusteeEvaluationKeyProofSetRoot;
        expect(
            transport.trusteeEvaluationKeyProofs
                .trusteeEvaluationKeyProofSetRoot,
        ).toBe(deriveCanonicalObjectHash(proofSetWithoutRoot));
        expect(
            transport.trusteeEvaluationKeyProofs
                .trusteeEvaluationKeyProofSetRoot,
        ).not.toBe(trusteeEvaluationKeyProofs.trusteeEvaluationKeyProofSetRoot);
    });

    it('rejects proof bytes that do not match the recorded proof bytes hash', () => {
        const fixture = evaluationKeyFixture();
        const { trusteeEvaluationKeyProofs } = builtTrusteeProofs(fixture);
        const tamperedProofSet = JSON.parse(
            JSON.stringify(trusteeEvaluationKeyProofs),
        ) as typeof trusteeEvaluationKeyProofs;
        (
            tamperedProofSet.proofRecords[0] as unknown as JsonRecord
        ).proofBytesHex = 'ffeeddcc';
        expect(() =>
            transportTrusteeEvaluationKeyProofSet(tamperedProofSet),
        ).toThrow(
            'proofRecords.proofBytesHash must match proofBytesHex before transport',
        );
    });
});

describe('createBinaryChunkedEvaluationKeyShareMaterialTransport', () => {
    it('moves embedded component vectors into chunked transport for every contribution', () => {
        const fixture = evaluationKeyFixture();
        const transport =
            createBinaryChunkedEvaluationKeyShareMaterialTransport({
                sameSecretProofReferences:
                    fixture.commonInput.sameSecretProofReferences,
                relinearizationRoundOneContributions:
                    fixture.roundOneContributions,
                relinearizationRoundTwoContributions:
                    fixture.roundTwoContributions,
                galoisKeyShareBatchContributions: fixture.batchContributions,
            });
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
        for (const componentMaterial of transport
            .transportedEvaluationKeyShareComponentMaterial
            .componentMaterials) {
            const material = componentMaterial;
            expect(material.objectType).toBe(
                'SetupTransportedEvaluationKeyShareComponentMaterial',
            );
            expect(material.digitCount).toBe(digitCount);
            expect(material.rnsLimbCount).toBe(digitCount);
            expect(material.ringDegree).toBe(ringDegree);
            const chunks = material.chunks as readonly {
                chunkIndex: number;
                bytesHex: string;
            }[];
            expect(chunks.length).toBeGreaterThan(0);
            expect(chunks[0].bytesHex.startsWith('534c454b434d5631')).toBe(
                true,
            );
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

    it('keeps the chunked contributions buildable into the same record containers', () => {
        const fixture = evaluationKeyFixture();
        const transport =
            createBinaryChunkedEvaluationKeyShareMaterialTransport({
                sameSecretProofReferences:
                    fixture.commonInput.sameSecretProofReferences,
                relinearizationRoundOneContributions:
                    fixture.roundOneContributions,
                relinearizationRoundTwoContributions:
                    fixture.roundTwoContributions,
                galoisKeyShareBatchContributions: fixture.batchContributions,
            });
        const rounds = createRelinearizationKeyShareRounds({
            ...fixture.commonInput,
            roundOneContributions:
                transport.relinearizationRoundOneContributions,
            roundTwoContributions:
                transport.relinearizationRoundTwoContributions,
        });
        const batches = createGaloisKeyShareBatches({
            ...fixture.commonInput,
            batchContributions: transport.galoisKeyShareBatchContributions,
        });
        const capturedInputs: TrusteeEvaluationKeyProofGeneratorInput[] = [];
        const trusteeEvaluationKeyProofs = createTrusteeEvaluationKeyProofs({
            ...fixture.commonInput,
            relinearizationKeyShareRounds: rounds,
            galoisKeyShareBatches: batches,
            keySwitchDecompositionHash: fixtureHash('key-switch-decomposition'),
            trusteeWitnesses: trusteeWitnesses(),
            sameSecretBridgeAnchors: sameSecretBridgeAnchors(),
            trusteeEvaluationKeyProofGenerator: stubGenerator(capturedInputs),
            transportedEvaluationKeyShareComponentMaterial:
                transport.transportedEvaluationKeyShareComponentMaterial,
        });

        expect(trusteeEvaluationKeyProofs.proofRecords).toHaveLength(
            participantCount,
        );
        // The decoded chunked material must reproduce the same component
        // coefficients the embedded path supplies.
        expect(capturedInputs[0].keys[0].componentBByDigit[0][0]).toEqual(
            componentCoefficients('round-one-0', 0, 0),
        );
    });

    it('rejects contributions for unknown trustee roster positions', () => {
        const fixture = evaluationKeyFixture();
        expect(() =>
            createBinaryChunkedEvaluationKeyShareMaterialTransport({
                sameSecretProofReferences:
                    fixture.commonInput.sameSecretProofReferences,
                relinearizationRoundOneContributions: [
                    {
                        ...fixture.roundOneContributions[0],
                        trusteeRosterPosition: 7,
                    },
                ],
                relinearizationRoundTwoContributions: [],
                galoisKeyShareBatchContributions: [],
            }),
        ).toThrow(
            'references a trustee roster position without a same-secret proof reference',
        );
    });

    it('rejects duplicate component material roots', () => {
        const fixture = evaluationKeyFixture();
        expect(() =>
            createBinaryChunkedEvaluationKeyShareMaterialTransport({
                sameSecretProofReferences:
                    fixture.commonInput.sameSecretProofReferences,
                relinearizationRoundOneContributions: [
                    fixture.roundOneContributions[0],
                    fixture.roundOneContributions[0],
                ],
                relinearizationRoundTwoContributions: [],
                galoisKeyShareBatchContributions: [],
            }),
        ).toThrow(
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
    it('binds a canonical manifest with share material roots and chunked transport', () => {
        const fixture = evaluationKeyFixture();
        const { relinearizationKeyShareRounds, galoisKeyShareBatches } =
            builtRoundsAndBatches(fixture);
        const transport =
            createBinaryChunkedPublicEvaluationKeyMaterialTransport({
                ...fixture.commonInput,
                relinearizationKeyShareRounds,
                galoisKeyShareBatches,
            });

        expect(transport.evaluationKeys.publicEvaluationKeyMaterialRoot).toBe(
            transport.publicEvaluationKeyMaterialReference
                .publicEvaluationKeyMaterialRoot,
        );
        const transportedMaterial =
            transport.transportedPublicEvaluationKeyMaterial
                .publicEvaluationKeyMaterials[0];
        expect(transportedMaterial.evaluationKeySetHash).toBe(
            transport.evaluationKeys.evaluationKeySetHash,
        );
        const materialBytesHex = transportedMaterial.chunks
            .map((chunk) => chunk.bytesHex)
            .join('');
        // SLEKPMV1 magic prefix before the canonical JSON manifest bytes.
        expect(materialBytesHex.startsWith('534c454b504d5631')).toBe(true);
        const manifestJson = Buffer.from(
            materialBytesHex.slice('534c454b504d5631'.length),
            'hex',
        ).toString('utf8');
        const manifest = JSON.parse(manifestJson) as JsonRecord;
        expect(manifest.objectType).toBe('PublicEvaluationKeyMaterialManifest');
        const relinearizationShareMaterialRoots =
            manifest.relinearizationShareMaterialRoots as readonly JsonRecord[];
        expect(relinearizationShareMaterialRoots).toHaveLength(
            participantCount * 2,
        );
        expect(relinearizationShareMaterialRoots[0].round).toBe('round-one');
        expect(
            relinearizationShareMaterialRoots[0].keySwitchComponentMaterialRoot,
        ).toBe(null);
        const galoisShareMaterialRoots =
            manifest.galoisShareMaterialRoots as readonly JsonRecord[];
        expect(galoisShareMaterialRoots).toHaveLength(
            participantCount * requiredGaloisKeySchedule.length,
        );
    });

    it('rejects undeclared transported component material for embedded records', () => {
        const fixture = evaluationKeyFixture();
        const { relinearizationKeyShareRounds, galoisKeyShareBatches } =
            builtRoundsAndBatches(fixture);
        expect(() =>
            createBinaryChunkedPublicEvaluationKeyMaterialTransport({
                ...fixture.commonInput,
                relinearizationKeyShareRounds,
                galoisKeyShareBatches,
                transportedEvaluationKeyShareComponentMaterial: {
                    objectType:
                        'SetupTransportedEvaluationKeyShareComponentMaterialSet',
                    componentMaterials: [
                        { keySwitchComponentMaterialRoot: fixtureHash('x') },
                    ],
                },
            }),
        ).toThrow(
            'transportedEvaluationKeyShareComponentMaterial must not be supplied when evaluation-key records do not use binary component material',
        );
    });

    it('requires component material coverage for chunked records', () => {
        const fixture = evaluationKeyFixture();
        const shareTransport =
            createBinaryChunkedEvaluationKeyShareMaterialTransport({
                sameSecretProofReferences:
                    fixture.commonInput.sameSecretProofReferences,
                relinearizationRoundOneContributions:
                    fixture.roundOneContributions,
                relinearizationRoundTwoContributions:
                    fixture.roundTwoContributions,
                galoisKeyShareBatchContributions: fixture.batchContributions,
            });
        const rounds = createRelinearizationKeyShareRounds({
            ...fixture.commonInput,
            roundOneContributions:
                shareTransport.relinearizationRoundOneContributions,
            roundTwoContributions:
                shareTransport.relinearizationRoundTwoContributions,
        });
        const batches = createGaloisKeyShareBatches({
            ...fixture.commonInput,
            batchContributions: shareTransport.galoisKeyShareBatchContributions,
        });
        expect(() =>
            createBinaryChunkedPublicEvaluationKeyMaterialTransport({
                ...fixture.commonInput,
                relinearizationKeyShareRounds: rounds,
                galoisKeyShareBatches: batches,
            }),
        ).toThrow(
            'transportedEvaluationKeyShareComponentMaterial is required for binary evaluation-key component material',
        );
        const transport =
            createBinaryChunkedPublicEvaluationKeyMaterialTransport({
                ...fixture.commonInput,
                relinearizationKeyShareRounds: rounds,
                galoisKeyShareBatches: batches,
                transportedEvaluationKeyShareComponentMaterial:
                    shareTransport.transportedEvaluationKeyShareComponentMaterial,
            });
        const manifest = JSON.parse(
            Buffer.from(
                transport.transportedPublicEvaluationKeyMaterial.publicEvaluationKeyMaterials[0].chunks[0].bytesHex.slice(
                    '534c454b504d5631'.length,
                ),
                'hex',
            ).toString('utf8'),
        ) as JsonRecord;
        const relinearizationShareMaterialRoots =
            manifest.relinearizationShareMaterialRoots as readonly JsonRecord[];
        expect(
            relinearizationShareMaterialRoots[0].keySwitchComponentMaterialRoot,
        ).not.toBe(null);
    });
});
