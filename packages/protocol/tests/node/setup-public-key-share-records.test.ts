import { deriveProtocolHash } from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import {
    createPublicKeyShareProofSet,
    createPublicKeyShareSet,
    createSameSecretConsistencyStatementSet,
    createVssCoefficientCommitmentBundle,
    createVssDealerCoefficientOpeningState,
    type CollectiveBgvSetupContext,
    type PublicKeyShareContributionInput,
    type PublicKeyShareSet,
    type SameSecretConsistencyStatementSet,
    type VssOpeningRandomByteSource,
} from '#packages/protocol/src/index';

const qSharePrimes = [140_737_487_306_753, 140_737_486_716_929] as const;
const ringDegree = 8;
const participantCount = 2;
const thresholdDegree = 2;

const fixtureHash = (label: string): string =>
    deriveProtocolHash('ActionContextHash', {
        fixture: 'setup-public-key-share-records',
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
                        fixture: 'setup-public-key-share-records',
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

const createShareSet = (
    sameSecretStatements: SameSecretConsistencyStatementSet,
): PublicKeyShareSet =>
    createPublicKeyShareSet({
        setupContext,
        qSharePrimes,
        participantCount,
        publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
        publicKeyCrpRoot: fixtureHash('public-key-crp'),
        publicAPolynomialRoot: fixtureHash('public-a-polynomial'),
        sameSecretConsistency: sameSecretStatements,
        shareContributions: [shareContribution(1), shareContribution(0)],
    });

describe('public-key share statement builders', () => {
    it('creates deterministic root-bound public-key share and proof statement sets', () => {
        const sameSecretStatements = sameSecretConsistency();
        const publicKeyShares = createShareSet(sameSecretStatements);
        const publicKeyShareProofs = createPublicKeyShareProofSet({
            setupContext,
            qSharePrimes,
            participantCount,
            publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
            publicKeyCrpRoot: fixtureHash('public-key-crp'),
            publicAPolynomialRoot: fixtureHash('public-a-polynomial'),
            sameSecretConsistency: sameSecretStatements,
            publicKeyShares,
        });
        const { publicKeyShareSetRoot, ...shareSetWithoutRoot } =
            publicKeyShares;
        const { publicKeyShareProofSetRoot, ...proofSetWithoutRoot } =
            publicKeyShareProofs;
        const firstShareRecord = publicKeyShares.shareRecords[0];
        const firstProofRecord = publicKeyShareProofs.proofRecords[0];
        if (firstShareRecord === undefined || firstProofRecord === undefined) {
            throw new Error('fixture public-key share record is missing');
        }
        const { publicKeyShareRoot, ...shareRecordWithoutRoot } =
            firstShareRecord;
        const { publicKeyShareProofRoot, ...proofRecordWithoutRoot } =
            firstProofRecord;

        expect(
            publicKeyShares.shareRecords.map(
                (record) => record.trusteeRosterPosition,
            ),
        ).toEqual([0, 1]);
        expect(firstShareRecord.sameSecretStatementRoot).toBe(
            sameSecretStatements.statementRecords[0]?.sameSecretStatementRoot,
        );
        expect(publicKeyShareRoot).toBe(
            deriveProtocolHash('PublicKeyShareRoot', shareRecordWithoutRoot),
        );
        expect(publicKeyShareSetRoot).toBe(
            deriveProtocolHash('PublicKeyShareRoot', shareSetWithoutRoot),
        );
        expect(firstProofRecord.publicKeyShareRoot).toBe(publicKeyShareRoot);
        expect(publicKeyShareProofRoot).toBe(
            deriveProtocolHash(
                'PublicKeyShareProofRoot',
                proofRecordWithoutRoot,
            ),
        );
        expect(publicKeyShareProofSetRoot).toBe(
            deriveProtocolHash('PublicKeyShareProofRoot', proofSetWithoutRoot),
        );
    });

    it('rejects malformed public-key share statement inputs', () => {
        const sameSecretStatements = sameSecretConsistency();
        const publicKeyShares = createShareSet(sameSecretStatements);

        expect(() =>
            createPublicKeyShareSet({
                setupContext,
                qSharePrimes,
                participantCount,
                publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
                publicKeyCrpRoot: fixtureHash('public-key-crp'),
                publicAPolynomialRoot: fixtureHash('public-a-polynomial'),
                sameSecretConsistency: sameSecretStatements,
                shareContributions: [
                    {
                        ...shareContribution(0),
                        shareCoefficientVectorHash512ByLimb:
                            shareContribution(
                                0,
                            ).shareCoefficientVectorHash512ByLimb.slice(1),
                    },
                    shareContribution(1),
                ],
            }),
        ).toThrow(/one entry for every Q_share limb/u);
        expect(() =>
            createPublicKeyShareSet({
                setupContext,
                qSharePrimes,
                participantCount,
                publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
                publicKeyCrpRoot: fixtureHash('public-key-crp'),
                publicAPolynomialRoot: fixtureHash('public-a-polynomial'),
                sameSecretConsistency: sameSecretStatements,
                shareContributions: [
                    {
                        ...shareContribution(0),
                        trusteeIdentity: 'wrong-trustee',
                    },
                    shareContribution(1),
                ],
            }),
        ).toThrow(/trusteeIdentity/u);
        expect(() =>
            createPublicKeyShareProofSet({
                setupContext,
                qSharePrimes,
                participantCount,
                publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
                publicKeyCrpRoot: fixtureHash('wrong-public-key-crp'),
                publicAPolynomialRoot: fixtureHash('public-a-polynomial'),
                sameSecretConsistency: sameSecretStatements,
                publicKeyShares,
            }),
        ).toThrow(/same common randomness/u);
    });
});
