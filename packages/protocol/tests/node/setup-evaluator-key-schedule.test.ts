import { deriveProtocolHash } from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import {
    acceptedBgvSetupQSharePrimes,
    createEvaluatorKeySchedule,
    createPublicKeyShareProofSet,
    createPublicKeyShareSet,
    createRequiredGaloisSet,
    createSameSecretConsistencyStatementSet,
    createVssCoefficientCommitmentBundle,
    createVssSourceTrusteeCoefficientOpeningState,
    type PublicKeyShareContributionInput,
    type PublicKeyShareProofSet,
    type PublicKeyShareSet,
    type RequiredGaloisKeyScheduleEntry,
    type SameSecretConsistencyStatementSet,
} from '#packages/protocol/src/index';
import { selectedEvaluatorWorkingLevel } from '#packages/protocol/src/setup/evaluator-key-schedule';
import { setupCommitmentComputer } from '#tests/support/setup-commitment-computer';
import {
    makeSetupContext,
    makeSetupFixtureHash,
    makeVssOpeningRandomBytes,
} from '#tests/support/setup-fixtures';

// The frozen evaluator working level requires the full accepted Q_share basis.
const qSharePrimes = acceptedBgvSetupQSharePrimes;
const ringDegree = 8;
const participantCount = 2;
const thresholdDegree = 2;

const fixtureHash = makeSetupFixtureHash('setup-evaluator-key-schedule');

const deterministicRandomBytes = makeVssOpeningRandomBytes(
    'setup-evaluator-key-schedule',
);

const setupContext = makeSetupContext(fixtureHash);

const sameSecretConsistency = (): SameSecretConsistencyStatementSet => {
    const vssCoefficientCommitments = createVssCoefficientCommitmentBundle({
        setupContext,
        publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
        setupCommitmentComputer,
        qSharePrimes,
        ringDegree,
        participantCount,
        thresholdDegree,
        sourceTrusteeOpeningStates: Array.from(
            { length: participantCount },
            (_unused, sourceTrusteeRosterPosition) =>
                createVssSourceTrusteeCoefficientOpeningState({
                    sourceTrusteeIdentity: `trustee-${String(sourceTrusteeRosterPosition)}`,
                    sourceTrusteeRosterPosition,
                    participantCount,
                    qSharePrimes,
                    ringDegree,
                    thresholdDegree,
                    randomBytes: deterministicRandomBytes(
                        `trustee-${String(sourceTrusteeRosterPosition)}`,
                    ),
                }),
        ),
    }).commitmentSet;

    return createSameSecretConsistencyStatementSet({
        setupContext,
        qSharePrimes,
        participantCount,
        thresholdDegree,
        vssCoefficientCommitments,
    });
};

const shareContribution = (
    trusteeRosterPosition: number,
): PublicKeyShareContributionInput => ({
    trusteeIdentity: `trustee-${String(trusteeRosterPosition)}`,
    trusteeRosterPosition,
    shareCoefficientVectorHash512ByLimb: qSharePrimes.map(
        (rnsPrime, rnsLimbIndex) => ({
            rnsLimbIndex,
            rnsPrime,
            component: 'b_i',
            coefficientVectorHash512: fixtureHash(
                `share-coefficient-${String(trusteeRosterPosition)}-${String(
                    rnsLimbIndex,
                )}`,
            ),
        }),
    ),
});

const publicKeyShareObjects = (
    sameSecretStatements: SameSecretConsistencyStatementSet,
): {
    readonly publicKeyShares: PublicKeyShareSet;
    readonly publicKeyShareProofs: PublicKeyShareProofSet;
} => {
    const publicKeyShares = createPublicKeyShareSet({
        setupContext,
        qSharePrimes,
        participantCount,
        publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
        publicKeyCrpRoot: fixtureHash('public-key-crp'),
        publicAPolynomialRoot: fixtureHash('public-a-polynomial'),
        sameSecretConsistency: sameSecretStatements,
        shareContributions: [shareContribution(0), shareContribution(1)],
    });

    return {
        publicKeyShares,
        publicKeyShareProofs: createPublicKeyShareProofSet({
            setupContext,
            qSharePrimes,
            participantCount,
            publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
            publicKeyCrpRoot: fixtureHash('public-key-crp'),
            publicAPolynomialRoot: fixtureHash('public-a-polynomial'),
            sameSecretConsistency: sameSecretStatements,
            publicKeyShares,
        }),
    };
};

const requiredGaloisKeySchedule = [
    {
        rotation: 7,
        level: 1,
        purpose: 'packed-rank-return-basis',
        proofFamily: 'galois-key-share',
    },
    {
        rotation: 3,
        level: 1,
        purpose: 'direct-score-packing-basis',
        proofFamily: 'galois-key-share',
    },
] as const satisfies readonly RequiredGaloisKeyScheduleEntry[];

describe('evaluator key schedule builder', () => {
    it('creates a deterministic root-bound first-profile schedule', () => {
        const sameSecretStatements = sameSecretConsistency();
        const { publicKeyShares, publicKeyShareProofs } =
            publicKeyShareObjects(sameSecretStatements);
        const evaluatorKeySchedule = createEvaluatorKeySchedule({
            setupContext,
            qSharePrimes,
            participantCount,
            publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
            relinearizationCrpRoot: fixtureHash('relinearization-crp'),
            galoisKeyCrpRoot: fixtureHash('galois-key-crp'),
            sameSecretConsistency: sameSecretStatements,
            publicKeyShares,
            publicKeyShareProofs,
            requiredGaloisKeySchedule,
        });
        const { evaluatorKeyScheduleRoot, ...scheduleWithoutRoot } =
            evaluatorKeySchedule;

        expect(
            evaluatorKeySchedule.requiredGaloisKeySchedule.map(
                (entry) => entry.rotation,
            ),
        ).toEqual([3, 7]);
        expect(evaluatorKeySchedule.relinearizationLevelSchedule).toEqual([
            {
                level: selectedEvaluatorWorkingLevel,
                proofFamily: 'relinearization-key-share',
                keyShareRounds: ['round-one', 'round-two'],
            },
        ]);
        expect(evaluatorKeySchedule.requiredGaloisSetHash).toBe(
            deriveProtocolHash(
                'RequiredGaloisSetHash',
                createRequiredGaloisSet(
                    qSharePrimes.length,
                    requiredGaloisKeySchedule,
                ),
            ),
        );
        expect(evaluatorKeyScheduleRoot).toBe(
            deriveProtocolHash('EvaluatorKeyScheduleRoot', scheduleWithoutRoot),
        );
    });

    it('rejects malformed schedule inputs', () => {
        const sameSecretStatements = sameSecretConsistency();
        const { publicKeyShares, publicKeyShareProofs } =
            publicKeyShareObjects(sameSecretStatements);
        const validInput = {
            setupContext,
            qSharePrimes,
            participantCount,
            publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
            relinearizationCrpRoot: fixtureHash('relinearization-crp'),
            galoisKeyCrpRoot: fixtureHash('galois-key-crp'),
            sameSecretConsistency: sameSecretStatements,
            publicKeyShares,
            publicKeyShareProofs,
            requiredGaloisKeySchedule,
        } as const;

        expect(() =>
            createEvaluatorKeySchedule({
                ...validInput,
                requiredGaloisKeySchedule: [
                    requiredGaloisKeySchedule[0],
                    requiredGaloisKeySchedule[0],
                ],
            }),
        ).toThrow(/must not repeat/u);
        expect(() =>
            createEvaluatorKeySchedule({
                ...validInput,
                publicKeyShareProofs: {
                    ...publicKeyShareProofs,
                    publicKeyShareSetRoot: fixtureHash(
                        'wrong-public-key-share-set',
                    ),
                },
            }),
        ).toThrow(/accepted same-secret and share-set roots/u);
    });
});
