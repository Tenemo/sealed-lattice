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
    140_737_487_306_753, 140_737_486_716_929, 140_737_486_520_321,
    140_737_485_864_961, 140_737_484_685_313, 140_737_483_898_881,
    140_737_482_981_377, 140_737_481_801_729, 140_737_481_342_977,
    140_737_480_949_761, 140_737_480_359_937, 140_737_479_639_041,
    140_737_476_100_097, 140_737_472_299_009, 140_737_471_971_329,
    140_737_471_774_721, 140_737_471_578_113,
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
