import { deriveProtocolHash } from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import {
    createGaloisKeyShareBatches,
    createRelinearizationKeyShareRounds,
    type EvaluationKeyProofCommonInput,
    type GaloisKeyShareBatchContribution,
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

const roundOneContributions =
    (): readonly RelinearizationRoundOneContribution[] =>
        sameSecretProofReferences().map((reference) => ({
            trusteeRosterPosition: reference.trusteeRosterPosition,
            level: 1,
            roundOneShareRoot: fixtureHash(
                `round-one-share-${String(reference.trusteeRosterPosition)}`,
            ),
            roundOneProofRoot: fixtureHash(
                `round-one-proof-${String(reference.trusteeRosterPosition)}`,
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
            roundTwoProofRoot: fixtureHash(
                `round-two-proof-${String(reference.trusteeRosterPosition)}`,
            ),
        }));

const galoisBatchContributions =
    (): readonly GaloisKeyShareBatchContribution[] =>
        sameSecretProofReferences().map((reference) => ({
            trusteeRosterPosition: reference.trusteeRosterPosition,
            galoisKeyShareRoots: requiredGaloisKeySchedule.map(
                (scheduleEntry) => ({
                    rotation: scheduleEntry.rotation,
                    level: scheduleEntry.level,
                    galoisKeyShareRoot: fixtureHash(
                        `galois-share-${String(
                            reference.trusteeRosterPosition,
                        )}-${String(scheduleEntry.rotation)}`,
                    ),
                }),
            ),
            galoisKeyBatchProofRoot: fixtureHash(
                `galois-proof-${String(reference.trusteeRosterPosition)}`,
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

        expect(batches).toHaveLength(participantCount);
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
        const [firstShareRoot, secondShareRoot] =
            firstContribution.galoisKeyShareRoots;

        expect(() =>
            createGaloisKeyShareBatches({
                ...commonInput(),
                batchContributions: [
                    {
                        ...firstContribution,
                        galoisKeyShareRoots: [secondShareRoot, firstShareRoot],
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
});
