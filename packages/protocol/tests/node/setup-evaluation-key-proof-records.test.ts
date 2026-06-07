import { deriveProtocolHash } from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import {
    createGaloisKeyShareBatches,
    createPublicEvaluationKeySet,
    createRelinearizationKeyShareRounds,
    type EvaluationKeyProofCommonInput,
    type GaloisKeyShareBatchContribution,
    type GaloisKeyShareProofMaterial,
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

const qSharePrimes = [140_737_487_306_753, 140_737_486_716_929] as const;
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
            'relinearization-and-galois-proof-verifiers-pending',
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

const relinearizationProofMaterial = (
    shareRoot: string,
    label: string,
): RelinearizationKeyShareProofMaterial => ({
    proofProfileId: 'sealed-lattice-relinearization-key-share-proof-lnp-v1',
    setupProofBinding: {
        objectType: 'SetupProofBindingFixture',
        label,
    },
    keySwitchMaterialEncoding: 'embedded-full-key-switch-component-vectors',
    keySwitchDomain: `relinearization-${label}`,
    keySwitchSeedHex: 'ab'.repeat(32),
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

const galoisProofMaterial = (
    shareRoot: string,
    label: string,
): GaloisKeyShareProofMaterial => ({
    proofProfileId: 'sealed-lattice-galois-key-share-proof-lnp-v1',
    setupProofBinding: {
        objectType: 'SetupProofBindingFixture',
        label,
    },
    keySwitchMaterialEncoding: 'embedded-full-key-switch-component-vectors',
    keySwitchDomain: `galois-${label}`,
    keySwitchSeedHex: 'cd'.repeat(32),
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
            ),
        }));

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
        expect(
            evaluationKeys.relinearizationKeyRoots[0].relinearizationKeyRoot,
        ).toBe(
            deriveProtocolHash('RelinearizationKeyRoot', {
                objectType: 'RelinearizationKeyAggregate',
                objectVersion: 1,
                setupProfileId: 'CollectiveBgvSetup-v1',
                setupProofProfileId,
                assemblyStatus:
                    'assembled-from-review-gated-proof-bearing-shares',
                materialEncoding:
                    'root-bound-public-key-switch-component-roots',
                materialSource:
                    'verified-relinearization-and-galois-proof-records',
                evaluatorKeyScheduleRoot:
                    input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
                sameSecretProofFamilyBindingRoot:
                    input.sameSecretProofFamilyBindingRoot,
                publicKeyShareLnpProofSetRoot:
                    input.publicKeyShareLnpProofSetRoot,
                relinearizationKeyShareRoundsRoot:
                    relinearizationKeyShareRounds.relinearizationKeyShareRoundsRoot,
                level: 1,
                decompositionDigitCount: 2,
                rnsLimbCount: 2,
                roundOneAggregateRoot:
                    relinearizationKeyShareRounds.roundOneAggregateRoots[0]
                        .roundOneAggregateRoot,
                roundOneSourceSquareAggregateRoot:
                    relinearizationKeyShareRounds.roundOneAggregateRoots[0]
                        .roundOneSourceSquareAggregateRoot,
                roundTwoAggregateRoot:
                    relinearizationKeyShareRounds.roundTwoAggregateRoots[0]
                        .roundTwoAggregateRoot,
                roundTwoSourceSquareAggregateRoot:
                    relinearizationKeyShareRounds.roundTwoAggregateRoots[0]
                        .roundTwoSourceSquareAggregateRoot,
            }),
        );
        expect(evaluationKeys.galoisKeyRoots[0].galoisKeyRoot).toBe(
            deriveProtocolHash('RotationKeyRoot', {
                objectType: 'GaloisKeyAggregate',
                objectVersion: 1,
                setupProfileId: 'CollectiveBgvSetup-v1',
                setupProofProfileId,
                assemblyStatus:
                    'assembled-from-review-gated-proof-bearing-shares',
                materialEncoding:
                    'root-bound-public-key-switch-component-roots',
                materialSource:
                    'verified-relinearization-and-galois-proof-records',
                evaluatorKeyScheduleRoot:
                    input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
                sameSecretProofFamilyBindingRoot:
                    input.sameSecretProofFamilyBindingRoot,
                publicKeyShareLnpProofSetRoot:
                    input.publicKeyShareLnpProofSetRoot,
                galoisKeyCrpRoot: input.evaluatorKeySchedule.galoisKeyCrpRoot,
                requiredGaloisSetHash:
                    input.evaluatorKeySchedule.requiredGaloisSetHash,
                rotation: requiredGaloisKeySchedule[0].rotation,
                level: requiredGaloisKeySchedule[0].level,
                decompositionDigitCount: 2,
                rnsLimbCount: 2,
                contributingShareRoots:
                    evaluationKeys.galoisKeyRoots[0].contributingShareRoots,
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
