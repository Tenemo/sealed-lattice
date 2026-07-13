import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import {
    acceptedBgvSetupQSharePrimes,
    createEvaluatorKeySchedule,
    createPublicKeyShareSet,
    type PublicKeyShareContributionInput,
    type PublicKeyShareSet,
    type RequiredGaloisKeyScheduleEntry,
} from '#packages/protocol/src/index';
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
        (_unusedRnsPrime, rnsLimbIndex) => ({
            coefficientVectorHash512: fixtureHash(
                `share-coefficient-${String(trusteeRosterPosition)}-${String(
                    rnsLimbIndex,
                )}`,
            ),
        }),
    ),
});

const publicKeySharesFixture = (): PublicKeyShareSet =>
    createPublicKeyShareSet({
        setupContext,
        qSharePrimes,
        participantCount,
        publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
        publicKeyCrpRoot: fixtureHash('public-key-crp'),
        publicAPolynomialRoot: fixtureHash('public-a-polynomial'),
        shareContributions: [shareContribution(0), shareContribution(1)],
    });

const requiredGaloisKeySchedule = [
    {
        rotation: 7,
        level: 1,
    },
    {
        rotation: 3,
        level: 1,
    },
] as const satisfies readonly RequiredGaloisKeyScheduleEntry[];

describe('evaluator key schedule builder', () => {
    it('creates a deterministic root-bound foundation schedule', () => {
        const publicKeyShares = publicKeySharesFixture();
        const evaluatorKeySchedule = createEvaluatorKeySchedule({
            setupContext,
            qSharePrimes,
            participantCount,
            publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
            relinearizationCrpRoot: fixtureHash('relinearization-crp'),
            galoisKeyCrpRoot: fixtureHash('galois-key-crp'),
            publicKeyShares,
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
            { level: 16 },
        ]);
        expect(evaluatorKeySchedule.requiredGaloisSetHash).toBe(
            deriveCanonicalObjectHash({
                objectType: 'RequiredGaloisSet',
                rnsLimbCount: qSharePrimes.length,
                entries: evaluatorKeySchedule.requiredGaloisKeySchedule,
            }),
        );
        expect(evaluatorKeyScheduleRoot).toBe(
            deriveCanonicalObjectHash(scheduleWithoutRoot),
        );
    });

    it('rejects malformed schedule inputs', () => {
        const publicKeyShares = publicKeySharesFixture();
        const validInput = {
            setupContext,
            qSharePrimes,
            participantCount,
            publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
            relinearizationCrpRoot: fixtureHash('relinearization-crp'),
            galoisKeyCrpRoot: fixtureHash('galois-key-crp'),
            publicKeyShares,
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
    });
});
