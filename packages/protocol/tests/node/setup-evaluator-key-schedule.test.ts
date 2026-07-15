import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import {
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
const qSharePrimes = [
    140_700_980_543_489, 140_546_359_361_537, 140_507_704_066_049,
    140_417_508_376_577, 140_396_033_212_417, 140_383_148_113_921,
    140_365_967_982_593, 140_280_067_325_953, 140_061_020_651_521,
    139_992_300_126_209, 139_880_629_272_577, 139_764_663_386_113,
    139_708_827_959_297, 139_670_172_663_809, 139_541_321_678_849,
    139_451_125_989_377, 139_399_585_595_393,
] as const;
const participantCount = 2;

const fixtureHash = makeSetupFixtureHash('setup-evaluator-key-schedule');

const setupContext = makeSetupContext(fixtureHash, participantCount);
const setupContextHash = deriveCanonicalObjectHash({
    objectType: 'CollectiveBgvSetupContext',
    ...setupContext,
});

const shareContribution = (
    trusteeRosterPosition: number,
): PublicKeyShareContributionInput => ({
    trusteeRosterPosition,
    shareCoefficientVectorHashesByLimb: qSharePrimes.map(
        (_unusedRnsPrime, rnsLimbIndex) =>
            fixtureHash(
                `share-coefficient-${String(trusteeRosterPosition)}-${String(
                    rnsLimbIndex,
                )}`,
            ),
    ),
});

const publicKeySharesFixture = (): PublicKeyShareSet =>
    createPublicKeyShareSet({
        setupContext,
        qSharePrimes,
        publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
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
    it('creates a deterministic normalized foundation schedule', () => {
        const publicKeyShares = publicKeySharesFixture();
        const evaluatorKeySchedule = createEvaluatorKeySchedule({
            setupContext,
            qSharePrimes,
            publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
            publicKeyShares,
            requiredGaloisKeySchedule,
        });
        expect(
            evaluatorKeySchedule.requiredGaloisKeySchedule.map(
                (entry) => entry.rotation,
            ),
        ).toEqual([3, 7]);
        expect(evaluatorKeySchedule.relinearizationLevelSchedule).toEqual([
            { level: 16 },
        ]);
        expect(evaluatorKeySchedule.setupContextHash).toBe(setupContextHash);
        expect(evaluatorKeySchedule.objectType).toBe('EvaluatorKeySchedule');
    });

    it('rejects malformed schedule inputs', () => {
        const publicKeyShares = publicKeySharesFixture();
        const validInput = {
            setupContext,
            qSharePrimes,
            publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
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
