import { deriveProtocolHash } from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import {
    createGaloisKeyShareBatches,
    createPublicEvaluationKeySet,
    createRelinearizationKeyShareRounds,
    galoisProofModelStatus,
    galoisProofVerificationStatus,
    relinearizationProofModelStatus,
    relinearizationProofVerificationStatus,
    type EvaluationKeyProofCommonInput,
    type EvaluationKeyShareProofGenerator,
    type GaloisKeyShareBatchContribution,
    type GaloisKeyShareProofGeneration,
    type GaloisKeyShareProofMaterial,
    type RelinearizationKeyShareProofGeneration,
    type RelinearizationKeyShareProofMaterial,
    type RelinearizationRoundOneContribution,
    type RelinearizationRoundTwoContribution,
    type SameSecretProofReference,
} from '#packages/protocol/src/setup/evaluation-key-proof-records';
import {
    createRequiredGaloisSet,
    type EvaluatorKeySchedule,
    type RequiredGaloisKeyScheduleEntry,
} from '#packages/protocol/src/setup/evaluator-key-schedule';
import { setupProofProfileId } from '#packages/protocol/src/setup/same-secret-consistency-records';
import type { CollectiveBgvSetupContext } from '#packages/protocol/src/setup/vss-share-verification-records';

type TransportedRelinearizationKeyShareProofMaterial = Extract<
    RelinearizationKeyShareProofMaterial,
    {
        readonly keySwitchMaterialEncoding: 'binary-chunked-key-switch-component-vectors';
    }
>;
type EvaluationKeyShareProofGeneratorInput =
    Parameters<EvaluationKeyShareProofGenerator>[0];

const qSharePrimes = [
    140_737_487_306_753, 140_737_486_716_929, 140_737_486_520_321,
] as const;
const participantCount = 2;

const fixtureHash = (label: string): string =>
    deriveProtocolHash('ActionContextHash', {
        fixture: 'setup-evaluation-key-proof-records',
        label,
    });

const setupContext = {
    ceremonyId: 'ceremony-1',
    manifestHash: fixtureHash('manifest'),
    rosterHash: fixtureHash('roster'),
    setupProfileHash: fixtureHash('setup-profile'),
    qShareHash: fixtureHash('q-share'),
    carryAwareVssShareRelationProfileHash: fixtureHash(
        'carry-aware-vss-share-relation-profile',
    ),
    commitmentProfileHash: fixtureHash('commitment-profile'),
    setupEpoch: 'setup-epoch-1',
} satisfies CollectiveBgvSetupContext;

const requiredGaloisKeySchedule = [
    {
        rotation: 3,
        level: 1,
        purpose: 'direct-score-packing-basis',
        proofFamily: 'galois-key-share',
    },
    {
        rotation: 7,
        level: 1,
        purpose: 'packed-rank-return-basis',
        proofFamily: 'galois-key-share',
    },
] as const satisfies readonly RequiredGaloisKeyScheduleEntry[];

const evaluatorKeySchedule = (): EvaluatorKeySchedule => {
    const requiredGaloisSetHash = deriveProtocolHash(
        'RequiredGaloisSetHash',
        createRequiredGaloisSet(qSharePrimes.length, requiredGaloisKeySchedule),
    );
    const scheduleWithoutRoot = {
        objectType: 'EvaluatorKeySchedule',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId,
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
                level: 1,
                proofFamily: 'relinearization-key-share',
                keyShareRounds: ['round-one', 'round-two'],
            },
        ],
        requiredGaloisKeySchedule,
        requiredGaloisSetHash,
        genericKeySwitchPolicy: 'refused-unless-explicitly-required',
        genericKeySwitchProofStatus: 'not-required-for-first-profile',
        scheduleBindingStatus:
            'relinearization-and-galois-proof-verifiers-bound-by-accepted-setup-proof-accounting',
    } as const satisfies Omit<EvaluatorKeySchedule, 'evaluatorKeyScheduleRoot'>;

    return {
        ...scheduleWithoutRoot,
        evaluatorKeyScheduleRoot: deriveProtocolHash(
            'EvaluatorKeyScheduleRoot',
            scheduleWithoutRoot,
        ),
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
    round: 'round-one' | 'round-two',
    level: number,
): string => {
    const schedule = evaluatorKeySchedule();

    return deriveProtocolHash('RelinearizationKeyShareSeed', {
        objectType: 'RelinearizationKeySwitchPublicSampleSeed',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId,
        proofFamily: 'relinearization-key-share',
        keySwitchSampleScope: 'shared-by-scheduled-level-and-round',
        evaluatorKeyScheduleRoot: schedule.evaluatorKeyScheduleRoot,
        relinearizationCrpRoot: schedule.relinearizationCrpRoot,
        round,
        level,
    });
};

const galoisKeySwitchSeed = (rotation: number, level: number): string => {
    const schedule = evaluatorKeySchedule();

    return deriveProtocolHash('GaloisKeyShareSeed', {
        objectType: 'GaloisKeySwitchPublicSampleSeed',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId,
        proofFamily: 'galois-key-share',
        keySwitchSampleScope: 'shared-by-scheduled-rotation-and-level',
        evaluatorKeyScheduleRoot: schedule.evaluatorKeyScheduleRoot,
        galoisKeyCrpRoot: schedule.galoisKeyCrpRoot,
        requiredGaloisSetHash: schedule.requiredGaloisSetHash,
        rotation,
        level,
    });
};

const relinearizationProofMaterial = (
    shareRoot: string,
    label: string,
    round: 'round-one' | 'round-two',
    level: number,
): RelinearizationKeyShareProofMaterial => ({
    proofProfileId: 'sealed-lattice-relinearization-key-share-proof-lnp-v1',
    setupProofBinding: {
        objectType: 'SetupProofBindingFixture',
        label,
    },
    keySwitchMaterialEncoding: 'embedded-full-key-switch-component-vectors',
    keySwitchDomain: 'relinearization',
    keySwitchSeedHex: relinearizationKeySwitchSeed(round, level),
    ringDegree: 8,
    keySwitchComponentVectorRoot: shareRoot,
    keySwitchComponentVectors: [
        {
            component: 'b',
            digitIndex: 0,
            vectorHash: fixtureHash(`component-vector-${label}`),
        },
    ],
    relinearizationKeyShareTboxParameterProfileHash: fixtureHash(
        `relinearization-tbox-${label}`,
    ),
    statementHash: fixtureHash(`statement-${label}`),
    relationCommitmentHash: fixtureHash(`relation-commitment-${label}`),
    tboxCommitmentPrefixHash: fixtureHash(`tbox-commitment-${label}`),
    challenge: 17,
    proofSizeBytes: 4,
    proofBytesHash: fixtureHash(`proof-bytes-${label}`),
    proofBytesHex: '00112233',
});

const transportedRelinearizationProofMaterial = (
    shareRoot: string,
    label: string,
    round: 'round-one' | 'round-two',
    level: number,
): TransportedRelinearizationKeyShareProofMaterial => ({
    proofProfileId: 'sealed-lattice-relinearization-key-share-proof-lnp-v1',
    setupProofBinding: {
        objectType: 'SetupProofBindingFixture',
        label,
    },
    keySwitchMaterialEncoding: 'binary-chunked-key-switch-component-vectors',
    keySwitchDomain: 'relinearization',
    keySwitchSeedHex: relinearizationKeySwitchSeed(round, level),
    ringDegree: 8,
    keySwitchComponentVectorRoot: shareRoot,
    keySwitchComponentMaterialRoot: fixtureHash(
        `component-material-root-${label}`,
    ),
    keySwitchComponentChunkSizeBytes: 1_048_576,
    keySwitchComponentChunkCount: 1,
    keySwitchComponentTotalByteLength: 128,
    keySwitchComponentFullObjectHash: fixtureHash(
        `component-material-full-object-${label}`,
    ),
    keySwitchComponentChunkRoot: fixtureHash(
        `component-material-chunk-root-${label}`,
    ),
    keySwitchComponentChunkHashes: [
        fixtureHash(`component-material-chunk-${label}`),
    ],
    relinearizationKeyShareTboxParameterProfileHash: fixtureHash(
        `relinearization-tbox-${label}`,
    ),
    statementHash: fixtureHash(`statement-${label}`),
    relationCommitmentHash: fixtureHash(`relation-commitment-${label}`),
    tboxCommitmentPrefixHash: fixtureHash(`tbox-commitment-${label}`),
    challenge: 17,
    proofSizeBytes: 4,
    proofBytesHash: fixtureHash(`proof-bytes-${label}`),
    proofBytesHex: '00112233',
});

const relinearizationProofGeneration = (
    shareRoot: string,
    label: string,
    round: 'round-one' | 'round-two',
    level: number,
    roundOneAggregateSourceCoefficientsByDigit?: readonly (readonly number[])[],
): RelinearizationKeyShareProofGeneration => ({
    proofProfileId: 'sealed-lattice-relinearization-key-share-proof-lnp-v1',
    setupProofBinding: {
        objectType: 'SetupProofBindingFixture',
        label,
    },
    keySwitchMaterialEncoding: 'embedded-full-key-switch-component-vectors',
    keySwitchDomain: 'relinearization',
    keySwitchSeedHex: relinearizationKeySwitchSeed(round, level),
    ringDegree: 8,
    keySwitchComponentVectorRoot: shareRoot,
    keySwitchComponentVectors: [
        {
            component: 'b',
            digitIndex: 0,
            vectorHash: fixtureHash(
                `generated-relinearization-component-vector-${label}`,
            ),
        },
    ],
    constantCommitments: [
        {
            objectType: 'SetupCommitmentFixture',
            label,
        },
    ],
    secretCoefficients: [-1, 0, 1, -1, 0, 1, -1, 0],
    openingRandomnessByLimb: [
        [
            [0, 1, 0, -1, 0, 1, 0, -1],
            [1, 0, -1, 0, 1, 0, -1, 0],
        ],
    ],
    errorCoefficientsByDigit: [[0, 1, -1, 2, -2, 0, 1, -1]],
    relinearizationKeyShareTboxParameterProfileHash: fixtureHash(
        `generated-relinearization-tbox-${label}`,
    ),
    relinearizationSourceCoefficientsByDigit: [[1, 0, -1, 1, 0, -1, 1, 0]],
    ...(roundOneAggregateSourceCoefficientsByDigit === undefined
        ? {}
        : { roundOneAggregateSourceCoefficientsByDigit }),
    proofRandomnessSource: 'development-deterministic-fixture',
    proofRandomnessSeedHex: fixtureHash(
        `generated-relinearization-proof-randomness-${label}`,
    ),
});

const galoisProofMaterial = (
    shareRoot: string,
    label: string,
    rotation: number,
    level: number,
): GaloisKeyShareProofMaterial => ({
    proofProfileId: 'sealed-lattice-galois-key-share-proof-lnp-v1',
    setupProofBinding: {
        objectType: 'SetupProofBindingFixture',
        label,
    },
    keySwitchMaterialEncoding: 'embedded-full-key-switch-component-vectors',
    keySwitchDomain: `galois-${String(rotation)}`,
    keySwitchSeedHex: galoisKeySwitchSeed(rotation, level),
    ringDegree: 8,
    keySwitchComponentVectorRoot: shareRoot,
    keySwitchComponentVectors: [
        {
            component: 'b',
            digitIndex: 0,
            vectorHash: fixtureHash(`galois-component-vector-${label}`),
        },
    ],
    galoisKeyShareTboxParameterProfileHash: fixtureHash(`galois-tbox-${label}`),
    statementHash: fixtureHash(`galois-statement-${label}`),
    relationCommitmentHash: fixtureHash(`galois-relation-commitment-${label}`),
    tboxCommitmentPrefixHash: fixtureHash(`galois-tbox-commitment-${label}`),
    challenge: 19,
    proofSizeBytes: 4,
    proofBytesHash: fixtureHash(`galois-proof-bytes-${label}`),
    proofBytesHex: '44556677',
});

const galoisProofGeneration = (
    shareRoot: string,
    label: string,
    rotation: number,
    level: number,
): GaloisKeyShareProofGeneration => ({
    proofProfileId: 'sealed-lattice-galois-key-share-proof-lnp-v1',
    setupProofBinding: {
        objectType: 'SetupProofBindingFixture',
        label,
    },
    keySwitchMaterialEncoding: 'embedded-full-key-switch-component-vectors',
    keySwitchDomain: `galois-${String(rotation)}`,
    keySwitchSeedHex: galoisKeySwitchSeed(rotation, level),
    ringDegree: 8,
    keySwitchComponentVectorRoot: shareRoot,
    keySwitchComponentVectors: [
        {
            component: 'b',
            digitIndex: 0,
            vectorHash: fixtureHash(
                `generated-galois-component-vector-${label}`,
            ),
        },
    ],
    constantCommitments: [
        {
            objectType: 'SetupCommitmentFixture',
            label,
        },
    ],
    secretCoefficients: [-1, 0, 1, -1, 0, 1, -1, 0],
    openingRandomnessByLimb: [
        [
            [0, 1, 0, -1, 0, 1, 0, -1],
            [1, 0, -1, 0, 1, 0, -1, 0],
        ],
    ],
    errorCoefficientsByDigit: [[0, 1, -1, 2, -2, 0, 1, -1]],
    galoisKeyShareTboxParameterProfileHash: fixtureHash(
        `generated-galois-tbox-${label}`,
    ),
    proofRandomnessSource: 'development-deterministic-fixture',
    proofRandomnessSeedHex: fixtureHash(`generated-proof-randomness-${label}`),
});

const roundOneContributions =
    (): readonly RelinearizationRoundOneContribution[] =>
        sameSecretProofReferences().map((reference) => ({
            trusteeRosterPosition: reference.trusteeRosterPosition,
            level: 1,
            roundOneShareRoot: fixtureHash(
                `round-one-share-${String(reference.trusteeRosterPosition)}`,
            ),
            proofMaterial: relinearizationProofMaterial(
                fixtureHash(
                    `round-one-share-${String(reference.trusteeRosterPosition)}`,
                ),
                `round-one-${String(reference.trusteeRosterPosition)}`,
                'round-one',
                1,
            ),
        }));

const roundTwoContributions =
    (): readonly RelinearizationRoundTwoContribution[] =>
        sameSecretProofReferences().map((reference) => ({
            trusteeRosterPosition: reference.trusteeRosterPosition,
            level: 1,
            roundTwoShareRoot: fixtureHash(
                `round-two-share-${String(reference.trusteeRosterPosition)}`,
            ),
            proofMaterial: relinearizationProofMaterial(
                fixtureHash(
                    `round-two-share-${String(reference.trusteeRosterPosition)}`,
                ),
                `round-two-${String(reference.trusteeRosterPosition)}`,
                'round-two',
                1,
            ),
        }));

const transportedRoundOneContributions =
    (): readonly RelinearizationRoundOneContribution[] =>
        sameSecretProofReferences().map((reference) => {
            const roundOneShareRoot = fixtureHash(
                `transported-round-one-share-${String(reference.trusteeRosterPosition)}`,
            );

            return {
                trusteeRosterPosition: reference.trusteeRosterPosition,
                level: 1,
                roundOneShareRoot,
                proofMaterial: transportedRelinearizationProofMaterial(
                    roundOneShareRoot,
                    `transported-round-one-${String(reference.trusteeRosterPosition)}`,
                    'round-one',
                    1,
                ),
            };
        });

const transportedRoundTwoContributions =
    (): readonly RelinearizationRoundTwoContribution[] =>
        sameSecretProofReferences().map((reference) => {
            const roundTwoShareRoot = fixtureHash(
                `transported-round-two-share-${String(reference.trusteeRosterPosition)}`,
            );

            return {
                trusteeRosterPosition: reference.trusteeRosterPosition,
                level: 1,
                roundTwoShareRoot,
                proofMaterial: transportedRelinearizationProofMaterial(
                    roundTwoShareRoot,
                    `transported-round-two-${String(reference.trusteeRosterPosition)}`,
                    'round-two',
                    1,
                ),
            };
        });

const generatedRoundOneContributions =
    (): readonly RelinearizationRoundOneContribution[] =>
        sameSecretProofReferences().map((reference) => {
            const roundOneShareRoot = fixtureHash(
                `generated-round-one-share-${String(reference.trusteeRosterPosition)}`,
            );

            return {
                trusteeRosterPosition: reference.trusteeRosterPosition,
                level: 1,
                roundOneShareRoot,
                proofGeneration: relinearizationProofGeneration(
                    roundOneShareRoot,
                    `generated-round-one-${String(reference.trusteeRosterPosition)}`,
                    'round-one',
                    1,
                ),
            };
        });

const generatedRoundTwoContributions =
    (): readonly RelinearizationRoundTwoContribution[] =>
        sameSecretProofReferences().map((reference) => {
            const roundTwoShareRoot = fixtureHash(
                `generated-round-two-share-${String(reference.trusteeRosterPosition)}`,
            );

            return {
                trusteeRosterPosition: reference.trusteeRosterPosition,
                level: 1,
                roundTwoShareRoot,
                proofGeneration: relinearizationProofGeneration(
                    roundTwoShareRoot,
                    `generated-round-two-${String(reference.trusteeRosterPosition)}`,
                    'round-two',
                    1,
                    [[0, 1, 1, 0, -1, -1, 0, 1]],
                ),
            };
        });

const galoisBatchContributions =
    (): readonly GaloisKeyShareBatchContribution[] =>
        sameSecretProofReferences().map((reference) => ({
            trusteeRosterPosition: reference.trusteeRosterPosition,
            galoisKeyShareProofs: requiredGaloisKeySchedule.map(
                (scheduleEntry) => {
                    const galoisKeyShareRoot = fixtureHash(
                        `galois-share-${String(
                            reference.trusteeRosterPosition,
                        )}-${String(scheduleEntry.rotation)}`,
                    );

                    return {
                        rotation: scheduleEntry.rotation,
                        level: scheduleEntry.level,
                        galoisKeyShareRoot,
                        proofMaterial: galoisProofMaterial(
                            galoisKeyShareRoot,
                            `${String(
                                reference.trusteeRosterPosition,
                            )}-${String(scheduleEntry.rotation)}`,
                            scheduleEntry.rotation,
                            scheduleEntry.level,
                        ),
                    };
                },
            ),
        }));

const generatedGaloisBatchContributions =
    (): readonly GaloisKeyShareBatchContribution[] =>
        sameSecretProofReferences().map((reference) => ({
            trusteeRosterPosition: reference.trusteeRosterPosition,
            galoisKeyShareProofs: requiredGaloisKeySchedule.map(
                (scheduleEntry) => {
                    const galoisKeyShareRoot = fixtureHash(
                        `generated-galois-share-${String(reference.trusteeRosterPosition)}-${String(scheduleEntry.rotation)}`,
                    );

                    return {
                        rotation: scheduleEntry.rotation,
                        level: scheduleEntry.level,
                        galoisKeyShareRoot,
                        proofGeneration: galoisProofGeneration(
                            galoisKeyShareRoot,
                            `generated-galois-${String(reference.trusteeRosterPosition)}-${String(scheduleEntry.rotation)}`,
                            scheduleEntry.rotation,
                            scheduleEntry.level,
                        ),
                    };
                },
            ),
        }));

const commonInput = (): EvaluationKeyProofCommonInput => ({
    setupContext,
    qSharePrimes,
    participantCount,
    evaluatorKeySchedule: evaluatorKeySchedule(),
    sameSecretProofSetRoot: fixtureHash('same-secret-proof-set'),
    sameSecretProofFamilyBindingRoot: fixtureHash(
        'same-secret-proof-family-binding',
    ),
    publicKeyShareLnpProofSetRoot: fixtureHash(
        'public-key-share-lnp-proof-set',
    ),
    sameSecretProofReferences: sameSecretProofReferences(),
});

describe('evaluation-key proof record builders', () => {
    it('creates deterministic root-bound relinearization proof containers', () => {
        const rounds = createRelinearizationKeyShareRounds({
            ...commonInput(),
            roundOneContributions: roundOneContributions(),
            roundTwoContributions: roundTwoContributions(),
        });
        const { relinearizationKeyShareRoundsRoot, ...roundsWithoutRoot } =
            rounds;
        const { roundOneRecordRoot, ...roundOneWithoutRoot } =
            rounds.roundOneRecords[0];
        const { roundTwoRecordRoot, ...roundTwoWithoutRoot } =
            rounds.roundTwoRecords[0];
        const { roundOneProofRoot, ...roundOneWithoutProofRoot } =
            roundOneWithoutRoot;
        const { roundTwoProofRoot, ...roundTwoWithoutProofRoot } =
            roundTwoWithoutRoot;

        expect(roundOneProofRoot).toBe(
            deriveProtocolHash(
                'RelinearizationKeyShareProofRoot',
                roundOneWithoutProofRoot,
            ),
        );
        expect(roundTwoProofRoot).toBe(
            deriveProtocolHash(
                'RelinearizationKeyShareProofRoot',
                roundTwoWithoutProofRoot,
            ),
        );
        expect(roundOneRecordRoot).toBe(
            deriveProtocolHash(
                'RelinearizationRoundOneRecordRoot',
                roundOneWithoutRoot,
            ),
        );
        expect(roundTwoRecordRoot).toBe(
            deriveProtocolHash(
                'RelinearizationRoundTwoRecordRoot',
                roundTwoWithoutRoot,
            ),
        );
        expect(rounds.roundOneRecords[0].sameSecretProofFamilyBindingRoot).toBe(
            commonInput().sameSecretProofFamilyBindingRoot,
        );
        expect(rounds.roundTwoRecords[0].roundOneAggregateRoot).toBe(
            rounds.roundOneAggregateRoots[0].roundOneAggregateRoot,
        );
        expect(rounds.roundTwoRecords[0].roundOneSourceSquareBindingRoot).toBe(
            rounds.roundOneRecords[0].sourceSquareBindingRoot,
        );
        expect(
            rounds.roundTwoRecords[0].roundOneSourceSquareAggregateRoot,
        ).toBe(
            rounds.roundOneAggregateRoots[0].roundOneSourceSquareAggregateRoot,
        );
        expect(relinearizationKeyShareRoundsRoot).toBe(
            deriveProtocolHash(
                'RelinearizationKeyShareRoundsRoot',
                roundsWithoutRoot,
            ),
        );
    });

    it('creates relinearization records with transported component material references', () => {
        const rounds = createRelinearizationKeyShareRounds({
            ...commonInput(),
            roundOneContributions: transportedRoundOneContributions(),
            roundTwoContributions: transportedRoundTwoContributions(),
        });

        expect(rounds.roundOneRecords[0].keySwitchMaterialEncoding).toBe(
            'binary-chunked-key-switch-component-vectors',
        );
        expect('keySwitchComponentVectors' in rounds.roundOneRecords[0]).toBe(
            false,
        );
        expect(rounds.roundOneRecords[0].keySwitchComponentMaterialRoot).toBe(
            fixtureHash('component-material-root-transported-round-one-0'),
        );
    });

    it('generates relinearization proof material through the supplied proof generator', () => {
        const generatorInputs: EvaluationKeyShareProofGeneratorInput[] = [];
        const proofGenerator: EvaluationKeyShareProofGenerator = (input) => {
            const callNumber = generatorInputs.length;
            const relinearizationTboxParameterProfileHash =
                input.proofRecord
                    .relinearizationKeyShareTboxParameterProfileHash;
            generatorInputs.push(input);

            expect(input.proofFamily).toBe('relinearization-key-share');
            expect(input.publicMatrixSeedHash).toBe(
                evaluatorKeySchedule().publicMatrixSeedHash,
            );
            expect(
                input.relinearizationSourceCoefficientsByDigit,
            ).toBeDefined();
            expect(input.proofRecord).not.toHaveProperty('proofBytesHash');
            expect(input.proofRecord).not.toHaveProperty(
                'sourceSquareBindingRoot',
            );
            expect(input.proofRecord).not.toHaveProperty('roundOneProofRoot');
            expect(input.proofRecord).not.toHaveProperty('roundTwoProofRoot');
            expect(input.sameSecretStatementRecord).toMatchObject({
                objectType: 'SameSecretConsistencyStatement',
                trusteeRosterPosition: input.proofRecord.trusteeRosterPosition,
            });
            expect(typeof relinearizationTboxParameterProfileHash).toBe(
                'string',
            );

            return {
                ok: true,
                operation: 'generateEvaluationKeyShareLnpProof',
                setupProofProfileId,
                proofFamily: 'relinearization-key-share',
                proofVerificationStatus: relinearizationProofVerificationStatus,
                proofModelStatus: relinearizationProofModelStatus,
                relinearizationKeyShareTboxParameterProfileHash:
                    relinearizationTboxParameterProfileHash as string,
                statementHash: fixtureHash(
                    `generated-relinearization-statement-${String(callNumber)}`,
                ),
                relationCommitmentHash: fixtureHash(
                    `generated-relinearization-relation-${String(callNumber)}`,
                ),
                tboxCommitmentPrefixHash: fixtureHash(
                    `generated-relinearization-tbox-prefix-${String(callNumber)}`,
                ),
                challenge: 29 + callNumber,
                proofSizeBytes: 4,
                proofBytesHash: fixtureHash(
                    `generated-relinearization-proof-bytes-${String(callNumber)}`,
                ),
                proofBytesHex: 'aabbccdd',
                proofRandomness: {
                    source: input.proofRandomnessSource ?? 'fresh-csprng',
                    seedBytes: 64,
                    retention: 'test-only fixture',
                },
            };
        };
        const rounds = createRelinearizationKeyShareRounds({
            ...commonInput(),
            roundOneContributions: generatedRoundOneContributions(),
            roundTwoContributions: generatedRoundTwoContributions(),
            evaluationKeyShareProofGenerator: proofGenerator,
        });
        const { roundOneRecordRoot, ...roundOneWithoutRecordRoot } =
            rounds.roundOneRecords[0];
        const { roundOneProofRoot, ...roundOneWithoutProofRoot } =
            roundOneWithoutRecordRoot;

        expect(generatorInputs).toHaveLength(participantCount * 2);
        expect(
            generatorInputs.map((input) => input.proofRecord.objectType),
        ).toEqual([
            'RelinearizationKeyShareRoundOne',
            'RelinearizationKeyShareRoundOne',
            'RelinearizationKeyShareRoundTwo',
            'RelinearizationKeyShareRoundTwo',
        ]);
        expect(rounds.roundOneRecords[0].proofBytesHex).toBe('aabbccdd');
        expect(rounds.roundOneRecords[0].statementHash).toBe(
            fixtureHash('generated-relinearization-statement-0'),
        );
        expect(rounds.roundTwoRecords[0].statementHash).toBe(
            fixtureHash('generated-relinearization-statement-2'),
        );
        expect(roundOneProofRoot).toBe(
            deriveProtocolHash(
                'RelinearizationKeyShareProofRoot',
                roundOneWithoutProofRoot,
            ),
        );
        expect(roundOneRecordRoot).toBe(
            deriveProtocolHash(
                'RelinearizationRoundOneRecordRoot',
                roundOneWithoutRecordRoot,
            ),
        );
    });

    it('rejects missing and duplicate relinearization contributions', () => {
        const input = {
            ...commonInput(),
            roundOneContributions: roundOneContributions(),
            roundTwoContributions: roundTwoContributions(),
        };

        expect(() =>
            createRelinearizationKeyShareRounds({
                ...input,
                roundTwoContributions: input.roundTwoContributions.slice(1),
            }),
        ).toThrow(/missing a scheduled trustee and level/u);
        expect(() =>
            createRelinearizationKeyShareRounds({
                ...input,
                roundOneContributions: [
                    ...input.roundOneContributions,
                    input.roundOneContributions[0],
                ],
            }),
        ).toThrow(/must not repeat/u);
        expect(() =>
            createRelinearizationKeyShareRounds({
                ...input,
                sameSecretProofFamilyBindingRoot: 'not-a-hash',
            }),
        ).toThrow(/protocol hash/u);
        expect(() =>
            createRelinearizationKeyShareRounds({
                ...input,
                roundOneContributions: [
                    {
                        ...input.roundOneContributions[0],
                        proofMaterial: {
                            ...transportedRelinearizationProofMaterial(
                                input.roundOneContributions[0]
                                    .roundOneShareRoot,
                                'bad-transported-component',
                                'round-one',
                                input.roundOneContributions[0].level,
                            ),
                            keySwitchComponentChunkHashes: [],
                        },
                    },
                    ...input.roundOneContributions.slice(1),
                ],
            }),
        ).toThrow(/keySwitchComponentChunkHashes must match/u);
    });

    it('creates deterministic root-bound Galois proof batches', () => {
        const batches = createGaloisKeyShareBatches({
            ...commonInput(),
            batchContributions: galoisBatchContributions(),
        });
        const { galoisKeyShareBatchRoot, ...batchWithoutRoot } = batches[0];
        const { galoisKeyShareProofRoot, ...proofWithoutRoot } =
            batches[0].galoisKeyShareProofs[0];

        expect(batches).toHaveLength(participantCount);
        expect(galoisKeyShareProofRoot).toBe(
            deriveProtocolHash('GaloisKeyShareProofRoot', proofWithoutRoot),
        );
        expect(batchWithoutRoot.galoisKeyBatchProofRoot).toBe(
            deriveProtocolHash('GaloisKeyBatchProofRoot', {
                objectType: 'GaloisKeyBatchProofAggregate',
                objectVersion: 1,
                setupProfileId: 'CollectiveBgvSetup-v1',
                setupProofProfileId,
                proofFamily: 'galois-key-share',
                evaluatorKeyScheduleRoot:
                    commonInput().evaluatorKeySchedule.evaluatorKeyScheduleRoot,
                requiredGaloisSetHash:
                    commonInput().evaluatorKeySchedule.requiredGaloisSetHash,
                trusteeRosterPosition: 0,
                proofRoots: batchWithoutRoot.galoisKeyShareProofs.map(
                    (proof) => ({
                        rotation: proof.rotation,
                        level: proof.level,
                        galoisKeyShareProofRoot: proof.galoisKeyShareProofRoot,
                    }),
                ),
            }),
        );
        expect(batches[0].sameSecretProofFamilyBindingRoot).toBe(
            commonInput().sameSecretProofFamilyBindingRoot,
        );
        expect(galoisKeyShareBatchRoot).toBe(
            deriveProtocolHash('GaloisKeyShareBatchRoot', batchWithoutRoot),
        );
    });

    it('generates Galois proof material through the supplied proof generator', () => {
        const generatorInputs: EvaluationKeyShareProofGeneratorInput[] = [];
        const proofGenerator: EvaluationKeyShareProofGenerator = (input) => {
            const callNumber = generatorInputs.length;
            const galoisTboxParameterProfileHash =
                input.proofRecord.galoisKeyShareTboxParameterProfileHash;
            generatorInputs.push(input);

            expect(input.proofFamily).toBe('galois-key-share');
            expect(input.publicMatrixSeedHash).toBe(
                evaluatorKeySchedule().publicMatrixSeedHash,
            );
            expect(
                input.relinearizationSourceCoefficientsByDigit,
            ).toBeUndefined();
            expect(input.proofRecord).not.toHaveProperty('proofBytesHash');
            expect(input.proofRecord).not.toHaveProperty(
                'galoisKeyShareProofRoot',
            );
            expect(input.sameSecretStatementRecord).toMatchObject({
                objectType: 'SameSecretConsistencyStatement',
                trusteeRosterPosition: input.proofRecord.trusteeRosterPosition,
            });
            expect(typeof galoisTboxParameterProfileHash).toBe('string');

            return {
                ok: true,
                operation: 'generateEvaluationKeyShareLnpProof',
                setupProofProfileId,
                proofFamily: 'galois-key-share',
                proofVerificationStatus: galoisProofVerificationStatus,
                proofModelStatus: galoisProofModelStatus,
                galoisKeyShareTboxParameterProfileHash:
                    galoisTboxParameterProfileHash as string,
                statementHash: fixtureHash(
                    `generated-galois-statement-${String(callNumber)}`,
                ),
                relationCommitmentHash: fixtureHash(
                    `generated-galois-relation-${String(callNumber)}`,
                ),
                tboxCommitmentPrefixHash: fixtureHash(
                    `generated-galois-tbox-prefix-${String(callNumber)}`,
                ),
                challenge: 41 + callNumber,
                proofSizeBytes: 4,
                proofBytesHash: fixtureHash(
                    `generated-galois-proof-bytes-${String(callNumber)}`,
                ),
                proofBytesHex: 'ccddeeaa',
                proofRandomness: {
                    source: input.proofRandomnessSource ?? 'fresh-csprng',
                    seedBytes: 64,
                    retention: 'test-only fixture',
                },
            };
        };
        const batches = createGaloisKeyShareBatches({
            ...commonInput(),
            batchContributions: generatedGaloisBatchContributions(),
            evaluationKeyShareProofGenerator: proofGenerator,
        });
        const { galoisKeyShareProofRoot, ...proofWithoutRoot } =
            batches[0].galoisKeyShareProofs[0];

        expect(generatorInputs).toHaveLength(
            participantCount * requiredGaloisKeySchedule.length,
        );
        expect(
            generatorInputs.map((input) => input.proofRecord.objectType),
        ).toEqual([
            'GaloisKeyShareProof',
            'GaloisKeyShareProof',
            'GaloisKeyShareProof',
            'GaloisKeyShareProof',
        ]);
        expect(batches[0].galoisKeyShareProofs[0].proofBytesHex).toBe(
            'ccddeeaa',
        );
        expect(batches[0].galoisKeyShareProofs[0].statementHash).toBe(
            fixtureHash('generated-galois-statement-0'),
        );
        expect(galoisKeyShareProofRoot).toBe(
            deriveProtocolHash('GaloisKeyShareProofRoot', proofWithoutRoot),
        );
    });

    it('rejects Galois schedule drift and missing trustee batches', () => {
        const batchContributions = galoisBatchContributions();
        const [firstContribution, secondContribution] = batchContributions;
        const [firstShareProof, secondShareProof] =
            firstContribution.galoisKeyShareProofs;

        expect(() =>
            createGaloisKeyShareBatches({
                ...commonInput(),
                batchContributions: [
                    {
                        ...firstContribution,
                        galoisKeyShareProofs: [
                            secondShareProof,
                            firstShareProof,
                        ],
                    },
                    secondContribution,
                ],
            }),
        ).toThrow(/frozen Galois key schedule/u);
        expect(() =>
            createGaloisKeyShareBatches({
                ...commonInput(),
                batchContributions: [firstContribution],
            }),
        ).toThrow(/one batch per participant/u);
    });

    it('creates deterministic public evaluation-key assembly roots', () => {
        const input = commonInput();
        const relinearizationKeyShareRounds =
            createRelinearizationKeyShareRounds({
                ...input,
                roundOneContributions: roundOneContributions(),
                roundTwoContributions: roundTwoContributions(),
            });
        const galoisKeyShareBatches = createGaloisKeyShareBatches({
            ...input,
            batchContributions: galoisBatchContributions(),
        });
        const evaluationKeys = createPublicEvaluationKeySet({
            ...input,
            relinearizationKeyShareRounds,
            galoisKeyShareBatches,
        });
        const { evaluationKeySetHash, ...evaluationKeysWithoutHash } =
            evaluationKeys;

        expect(evaluationKeys.objectType).toBe('PublicEvaluationKeySet');
        expect(evaluationKeys.relinearizationKeyRoots).toHaveLength(
            input.evaluatorKeySchedule.relinearizationLevelSchedule.length,
        );
        expect(evaluationKeys.galoisKeyRoots).toHaveLength(
            input.evaluatorKeySchedule.requiredGaloisKeySchedule.length,
        );
        expect(evaluationKeys.genericKeySwitchKeyRoots).toEqual([]);
        expect(evaluationKeys.rawKeyBytesEmbedded).toBe(false);
        expect(evaluationKeys.verifierGeneratedKeyMaterial).toBe(false);
        const {
            relinearizationKeyRoot,
            ...firstRelinearizationKeyRootPayload
        } = evaluationKeys.relinearizationKeyRoots[0];
        expect(relinearizationKeyRoot).toBe(
            deriveProtocolHash('RelinearizationKeyRoot', {
                objectType: 'RelinearizationKeyAggregate',
                objectVersion: 1,
                setupProfileId: evaluationKeys.setupProfileId,
                setupProofProfileId: evaluationKeys.setupProofProfileId,
                assemblyStatus: evaluationKeys.assemblyStatus,
                materialEncoding: evaluationKeys.materialEncoding,
                materialSource: evaluationKeys.materialSource,
                evaluatorKeyScheduleRoot:
                    evaluationKeys.evaluatorKeyScheduleRoot,
                sameSecretProofFamilyBindingRoot:
                    evaluationKeys.sameSecretProofFamilyBindingRoot,
                publicKeyShareLnpProofSetRoot:
                    evaluationKeys.publicKeyShareLnpProofSetRoot,
                relinearizationKeyShareRoundsRoot:
                    evaluationKeys.relinearizationKeyShareRoundsRoot,
                ...firstRelinearizationKeyRootPayload,
            }),
        );
        const { galoisKeyRoot, ...firstGaloisKeyRootPayload } =
            evaluationKeys.galoisKeyRoots[0];
        expect(galoisKeyRoot).toBe(
            deriveProtocolHash('RotationKeyRoot', {
                objectType: 'GaloisKeyAggregate',
                objectVersion: 1,
                setupProfileId: evaluationKeys.setupProfileId,
                setupProofProfileId: evaluationKeys.setupProofProfileId,
                assemblyStatus: evaluationKeys.assemblyStatus,
                materialEncoding: evaluationKeys.materialEncoding,
                materialSource: evaluationKeys.materialSource,
                evaluatorKeyScheduleRoot:
                    evaluationKeys.evaluatorKeyScheduleRoot,
                sameSecretProofFamilyBindingRoot:
                    evaluationKeys.sameSecretProofFamilyBindingRoot,
                publicKeyShareLnpProofSetRoot:
                    evaluationKeys.publicKeyShareLnpProofSetRoot,
                galoisKeyCrpRoot: input.evaluatorKeySchedule.galoisKeyCrpRoot,
                requiredGaloisSetHash: evaluationKeys.requiredGaloisSetHash,
                ...firstGaloisKeyRootPayload,
            }),
        );
        expect(evaluationKeySetHash).toBe(
            deriveProtocolHash(
                'EvaluationKeySetHash',
                evaluationKeysWithoutHash,
            ),
        );
    });

    it('rejects public evaluation-key assembly with missing scheduled Galois proof material', () => {
        const input = commonInput();
        const relinearizationKeyShareRounds =
            createRelinearizationKeyShareRounds({
                ...input,
                roundOneContributions: roundOneContributions(),
                roundTwoContributions: roundTwoContributions(),
            });
        const galoisKeyShareBatches = createGaloisKeyShareBatches({
            ...input,
            batchContributions: galoisBatchContributions(),
        });
        const mutatedGaloisKeyShareBatches = [
            {
                ...galoisKeyShareBatches[0],
                galoisKeyShareProofs:
                    galoisKeyShareBatches[0].galoisKeyShareProofs.slice(0, 1),
            },
            galoisKeyShareBatches[1],
        ];

        expect(() =>
            createPublicEvaluationKeySet({
                ...input,
                relinearizationKeyShareRounds,
                galoisKeyShareBatches: mutatedGaloisKeyShareBatches,
            }),
        ).toThrow(/missing a scheduled proof record/u);
    });
});
