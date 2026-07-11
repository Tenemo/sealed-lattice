import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import {
    acceptedBgvSetupQSharePrimes,
    createEvaluatorKeySchedule,
    createPublicKeyShareProofSet,
    createPublicKeyShareSet,
    createRequiredGaloisSet,
    type PublicKeyShareContributionInput,
    type PublicKeyShareProofSet,
    type PublicKeyShareSet,
    type RequiredGaloisKeyScheduleEntry,
} from '#packages/protocol/src/index';
import { selectedEvaluatorWorkingLevel } from '#packages/protocol/src/setup/evaluator-key-schedule';
import {
    makeSetupContext,
    makeSetupFixtureHash,
} from '#tests/support/setup-fixtures';

// The frozen evaluator working level requires the full accepted Q_share basis.
const qSharePrimes = acceptedBgvSetupQSharePrimes;
const participantCount = 2;

const fixtureHash = makeSetupFixtureHash('setup-evaluator-key-schedule');

const setupContext = makeSetupContext(fixtureHash);

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

const publicKeyShareObjects = (): {
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
    it('creates a deterministic root-bound first-parameters schedule', () => {
        const { publicKeyShares, publicKeyShareProofs } =
            publicKeyShareObjects();
        const evaluatorKeySchedule = createEvaluatorKeySchedule({
            setupContext,
            qSharePrimes,
            participantCount,
            publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
            relinearizationCrpRoot: fixtureHash('relinearization-crp'),
            galoisKeyCrpRoot: fixtureHash('galois-key-crp'),
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
            deriveCanonicalObjectHash(
                createRequiredGaloisSet(
                    qSharePrimes.length,
                    requiredGaloisKeySchedule,
                ),
            ),
        );
        expect(evaluatorKeyScheduleRoot).toBe(
            deriveCanonicalObjectHash(scheduleWithoutRoot),
        );
    });

    it('rejects malformed schedule inputs', () => {
        const { publicKeyShares, publicKeyShareProofs } =
            publicKeyShareObjects();
        const validInput = {
            setupContext,
            qSharePrimes,
            participantCount,
            publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
            relinearizationCrpRoot: fixtureHash('relinearization-crp'),
            galoisKeyCrpRoot: fixtureHash('galois-key-crp'),
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
        ).toThrow(/accepted share-set root/u);
    });
});
