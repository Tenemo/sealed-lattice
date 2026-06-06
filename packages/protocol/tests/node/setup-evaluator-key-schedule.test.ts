import { deriveProtocolHash } from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import {
    createEvaluatorKeySchedule,
    createPublicKeyShareProofSet,
    createPublicKeyShareSet,
    createRequiredGaloisSet,
    createSameSecretConsistencyStatementSet,
    createVssCoefficientCommitmentBundle,
    createVssDealerCoefficientOpeningState,
    type CollectiveBgvSetupContext,
    type PublicKeyShareContributionInput,
    type PublicKeyShareProofSet,
    type PublicKeyShareSet,
    type RequiredGaloisKeyScheduleEntry,
    type SameSecretConsistencyStatementSet,
    type VssOpeningRandomByteSource,
} from '#packages/protocol/src/index';

const qSharePrimes = [140_737_487_306_753, 140_737_486_716_929] as const;
const ringDegree = 8;
const participantCount = 2;
const thresholdDegree = 2;

const fixtureHash = (label: string): string =>
    deriveProtocolHash('ActionContextHash', {
        fixture: 'setup-evaluator-key-schedule',
        label,
    });

const deterministicRandomBytes = (
    seedLabel: string,
): VssOpeningRandomByteSource => {
    const textEncoder = new TextEncoder();
    let blockIndex = 0;
    let bufferedBytes = new Uint8Array(0);
    let bufferedOffset = 0;

    return (byteLength) => {
        const outputBytes = new Uint8Array(byteLength);
        let outputOffset = 0;
        while (outputOffset < byteLength) {
            if (bufferedOffset >= bufferedBytes.byteLength) {
                bufferedBytes = textEncoder.encode(
                    deriveProtocolHash('ActionContextHash', {
                        fixture: 'setup-evaluator-key-schedule',
                        seedLabel,
                        blockIndex,
                    }),
                );
                bufferedOffset = 0;
                blockIndex += 1;
            }
            const copyLength = Math.min(
                byteLength - outputOffset,
                bufferedBytes.byteLength - bufferedOffset,
            );
            outputBytes.set(
                bufferedBytes.subarray(
                    bufferedOffset,
                    bufferedOffset + copyLength,
                ),
                outputOffset,
            );
            bufferedOffset += copyLength;
            outputOffset += copyLength;
        }

        return outputBytes;
    };
};

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

const sameSecretConsistency = (): SameSecretConsistencyStatementSet => {
    const vssCoefficientCommitments = createVssCoefficientCommitmentBundle({
        setupContext,
        publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
        qSharePrimes,
        ringDegree,
        participantCount,
        thresholdDegree,
        dealerOpeningStates: Array.from(
            { length: participantCount },
            (_unused, dealerRosterPosition) =>
                createVssDealerCoefficientOpeningState({
                    dealerIdentity: `trustee-${String(dealerRosterPosition)}`,
                    dealerRosterPosition,
                    participantCount,
                    qSharePrimes,
                    ringDegree,
                    thresholdDegree,
                    randomBytes: deterministicRandomBytes(
                        `trustee-${String(dealerRosterPosition)}`,
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
                level: 1,
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
