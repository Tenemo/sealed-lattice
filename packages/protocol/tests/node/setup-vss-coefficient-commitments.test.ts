import { deriveProtocolHash } from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import {
    computeSetupCommitmentFromOpening,
    createVssDealerCoefficientOpeningState,
    createVssDealerCoefficientCommitmentContribution,
    createVssCoefficientCommitmentBundle,
    setupCommitmentRandomnessWidth,
    setupCommitmentRootPayload,
    type CollectiveBgvSetupContext,
    type VssCoefficientOpeningInput,
    type VssDealerCoefficientOpeningState,
    type VssOpeningRandomByteSource,
} from '#packages/protocol/src/index';

const qSharePrimes = [140_737_487_306_753, 140_737_486_716_929] as const;
const ringDegree = 8;
const participantCount = 2;
const thresholdDegree = 2;

const fixtureHash = (label: string): string =>
    deriveProtocolHash('ActionContextHash', {
        fixture: 'setup-vss-coefficient-commitments',
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
                const blockHex = deriveProtocolHash('ActionContextHash', {
                    fixture: 'setup-vss-coefficient-commitments',
                    seedLabel,
                    blockIndex,
                });
                bufferedBytes = textEncoder.encode(blockHex);
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

const coefficientMessage = (
    dealerRosterPosition: number,
    rnsLimbIndex: number,
    shamirCoefficientIndex: number,
    rnsPrime: number,
): number[] =>
    Array.from({ length: ringDegree }, (_unused, coefficientIndex) => {
        const value =
            (dealerRosterPosition + 1) * 19 +
            (rnsLimbIndex + 1) * 7 +
            (shamirCoefficientIndex + 1) * 5 +
            coefficientIndex;

        return value % rnsPrime;
    });

const randomnessByColumn = (
    dealerRosterPosition: number,
    rnsLimbIndex: number,
    shamirCoefficientIndex: number,
): number[][] =>
    Array.from({ length: 5 }, (_unusedColumn, randomnessColumnIndex) =>
        Array.from({ length: ringDegree }, (_unused, coefficientIndex) => {
            const selector =
                (dealerRosterPosition +
                    rnsLimbIndex +
                    shamirCoefficientIndex +
                    randomnessColumnIndex +
                    coefficientIndex) %
                3;

            return selector === 0 ? -1 : selector === 1 ? 0 : 1;
        }),
    );

const opening = (
    dealerRosterPosition: number,
    rnsPrime: number,
    rnsLimbIndex: number,
    shamirCoefficientIndex: number,
): VssCoefficientOpeningInput => ({
    rnsLimbIndex,
    rnsPrime,
    shamirCoefficientIndex,
    coefficientMessage: coefficientMessage(
        dealerRosterPosition,
        rnsLimbIndex,
        shamirCoefficientIndex,
        rnsPrime,
    ),
    randomnessByColumn: randomnessByColumn(
        dealerRosterPosition,
        rnsLimbIndex,
        shamirCoefficientIndex,
    ),
});

const dealerOpeningState = (
    dealerRosterPosition: number,
): VssDealerCoefficientOpeningState => ({
    dealerIdentity: `trustee-${String(dealerRosterPosition)}`,
    dealerRosterPosition,
    coefficientOpenings: qSharePrimes.flatMap((rnsPrime, rnsLimbIndex) =>
        Array.from({ length: thresholdDegree }, (_unused, coefficientIndex) =>
            opening(
                dealerRosterPosition,
                rnsPrime,
                rnsLimbIndex,
                coefficientIndex,
            ),
        ),
    ),
});

const requiredOpening = (
    dealerState: VssDealerCoefficientOpeningState,
    openingIndex: number,
): VssCoefficientOpeningInput => {
    const openingState = dealerState.coefficientOpenings[openingIndex];
    if (openingState === undefined) {
        throw new Error('fixture opening is missing');
    }

    return openingState;
};

const requiredRandomnessColumn = (
    openingState: VssCoefficientOpeningInput,
    randomnessColumnIndex: number,
): readonly number[] => {
    const randomnessColumn =
        openingState.randomnessByColumn[randomnessColumnIndex];
    if (randomnessColumn === undefined) {
        throw new Error('fixture randomness column is missing');
    }

    return randomnessColumn;
};

const requiredOpeningByCoordinate = (
    dealerState: VssDealerCoefficientOpeningState,
    rnsLimbIndex: number,
    shamirCoefficientIndex: number,
): VssCoefficientOpeningInput => {
    const openingState = dealerState.coefficientOpenings.find(
        (candidateOpening) =>
            candidateOpening.rnsLimbIndex === rnsLimbIndex &&
            candidateOpening.shamirCoefficientIndex === shamirCoefficientIndex,
    );
    if (openingState === undefined) {
        throw new Error('fixture opening coordinate is missing');
    }

    return openingState;
};

const decodeShortSecretResidues = (
    openingState: VssCoefficientOpeningInput,
): readonly (-1 | 0 | 1)[] =>
    openingState.coefficientMessage.map((coefficient) => {
        if (coefficient === 0) {
            return 0;
        }
        if (coefficient === 1) {
            return 1;
        }
        if (coefficient === openingState.rnsPrime - 1) {
            return -1;
        }
        throw new Error(
            'constant Shamir coefficient is not a centered ternary residue',
        );
    });

describe('VSS coefficient commitment builders', () => {
    it('generates local openings with one short secret shared across RNS limbs', () => {
        const generatedDealerState = createVssDealerCoefficientOpeningState({
            dealerIdentity: 'trustee-0',
            dealerRosterPosition: 0,
            participantCount,
            qSharePrimes,
            ringDegree,
            thresholdDegree,
            randomBytes: deterministicRandomBytes('trustee-0'),
        });
        const constantSecretForFirstLimb = decodeShortSecretResidues(
            requiredOpeningByCoordinate(generatedDealerState, 0, 0),
        );
        const constantSecretForSecondLimb = decodeShortSecretResidues(
            requiredOpeningByCoordinate(generatedDealerState, 1, 0),
        );
        const nonConstantOpening = requiredOpeningByCoordinate(
            generatedDealerState,
            0,
            1,
        );
        const firstRandomnessColumn = requiredRandomnessColumn(
            requiredOpeningByCoordinate(generatedDealerState, 0, 0),
            0,
        );
        const contribution = createVssDealerCoefficientCommitmentContribution({
            setupContext,
            publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
            qSharePrimes,
            ringDegree,
            participantCount,
            thresholdDegree,
            dealerOpeningState: generatedDealerState,
        });

        expect(generatedDealerState.coefficientOpenings).toHaveLength(
            qSharePrimes.length * thresholdDegree,
        );
        expect(constantSecretForSecondLimb).toEqual(constantSecretForFirstLimb);
        expect(
            nonConstantOpening.coefficientMessage.every(
                (coefficient) =>
                    coefficient >= 0 &&
                    coefficient < nonConstantOpening.rnsPrime,
            ),
        ).toBe(true);
        expect(
            requiredOpeningByCoordinate(generatedDealerState, 0, 0)
                .randomnessByColumn,
        ).toHaveLength(setupCommitmentRandomnessWidth);
        expect(
            firstRandomnessColumn.every(
                (coefficient) =>
                    coefficient === -1 ||
                    coefficient === 0 ||
                    coefficient === 1,
            ),
        ).toBe(true);
        expect(
            contribution.privateOpeningMaterial.coefficientOpenings[0]
                ?.commitmentRoot,
        ).toMatch(/^[0-9a-f]{128}$/u);
    });

    it('creates deterministic root-bound commitment material from local openings', () => {
        const bundle = createVssCoefficientCommitmentBundle({
            setupContext,
            publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
            qSharePrimes,
            ringDegree,
            participantCount,
            thresholdDegree,
            dealerOpeningStates: [dealerOpeningState(1), dealerOpeningState(0)],
        });
        const { vssCoefficientCommitmentRoot, ...commitmentSetWithoutRoot } =
            bundle.commitmentSet;
        const {
            vssCoefficientCommitmentMaterialRoot,
            ...materialSetWithoutRoot
        } = bundle.materialSet;
        const firstMaterialRecord =
            bundle.materialSet.coefficientCommitments[0];
        const firstOpening = requiredOpening(dealerOpeningState(0), 0);
        const firstDealerContribution =
            createVssDealerCoefficientCommitmentContribution({
                setupContext,
                publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
                qSharePrimes,
                ringDegree,
                participantCount,
                thresholdDegree,
                dealerOpeningState: dealerOpeningState(0),
            });

        expect(
            bundle.commitmentSet.dealerRecords.map(
                (record) => record.dealerRosterPosition,
            ),
        ).toEqual([0, 1]);
        expect(bundle.materialSet.materialRecordCount).toBe(
            participantCount * qSharePrimes.length * thresholdDegree,
        );
        expect(vssCoefficientCommitmentRoot).toBe(
            deriveProtocolHash(
                'VssCoefficientCommitmentRoot',
                commitmentSetWithoutRoot,
            ),
        );
        expect(vssCoefficientCommitmentMaterialRoot).toBe(
            deriveProtocolHash(
                'VssCoefficientCommitmentMaterialRoot',
                materialSetWithoutRoot,
            ),
        );
        expect(firstMaterialRecord?.commitmentRoot).toBe(
            deriveProtocolHash(
                'SetupCommitmentRoot',
                setupCommitmentRootPayload(
                    computeSetupCommitmentFromOpening({
                        publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
                        qSharePrimes,
                        sourceRnsLimbIndex: firstOpening.rnsLimbIndex,
                        sourceMessageModulus: firstOpening.rnsPrime,
                        shamirCoefficientIndex:
                            firstOpening.shamirCoefficientIndex,
                        messageCoefficients: firstOpening.coefficientMessage,
                        randomnessByColumn: firstOpening.randomnessByColumn,
                        ringDegree,
                    }),
                ),
            ),
        );
        expect(
            bundle.privateOpeningMaterialByDealer[0]?.coefficientOpenings[0]
                ?.commitmentRoot,
        ).toBe(firstMaterialRecord?.commitmentRoot);
        expect(firstDealerContribution.dealerRecord).toEqual(
            bundle.commitmentSet.dealerRecords[0],
        );
        expect(firstDealerContribution.materialRecords).toEqual(
            bundle.materialSet.coefficientCommitments.slice(
                0,
                qSharePrimes.length * thresholdDegree,
            ),
        );
        expect(
            bundle.commitmentSet.dealerRecords[0]?.coefficientCommitments[0]
                ?.coefficientVectorHash512,
        ).toMatch(/^[0-9a-f]{128}$/u);
    });

    it('rejects malformed local opening state before root publication', () => {
        const firstDealer = dealerOpeningState(0);
        const secondDealer = dealerOpeningState(1);

        expect(() =>
            createVssCoefficientCommitmentBundle({
                setupContext,
                publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
                qSharePrimes,
                ringDegree,
                participantCount,
                thresholdDegree,
                dealerOpeningStates: [firstDealer],
            }),
        ).toThrow(/every accepted participant/u);
        expect(() =>
            createVssCoefficientCommitmentBundle({
                setupContext,
                publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
                qSharePrimes,
                ringDegree,
                participantCount,
                thresholdDegree,
                dealerOpeningStates: [
                    {
                        ...firstDealer,
                        coefficientOpenings: [
                            requiredOpening(firstDealer, 0),
                            requiredOpening(firstDealer, 0),
                            ...firstDealer.coefficientOpenings.slice(2),
                        ],
                    },
                    secondDealer,
                ],
            }),
        ).toThrow(/distinct limb\/coefficient coordinates/u);
        expect(() =>
            createVssCoefficientCommitmentBundle({
                setupContext,
                publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
                qSharePrimes,
                ringDegree,
                participantCount,
                thresholdDegree,
                dealerOpeningStates: [
                    {
                        ...firstDealer,
                        coefficientOpenings: [
                            {
                                ...requiredOpening(firstDealer, 0),
                                coefficientMessage: [
                                    qSharePrimes[0],
                                    ...requiredOpening(
                                        firstDealer,
                                        0,
                                    ).coefficientMessage.slice(1),
                                ],
                            },
                            ...firstDealer.coefficientOpenings.slice(1),
                        ],
                    },
                    secondDealer,
                ],
            }),
        ).toThrow(/residue below the declared modulus/u);
        expect(() =>
            createVssCoefficientCommitmentBundle({
                setupContext,
                publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
                qSharePrimes,
                ringDegree,
                participantCount,
                thresholdDegree,
                dealerOpeningStates: [
                    {
                        ...firstDealer,
                        coefficientOpenings: [
                            {
                                ...requiredOpening(firstDealer, 0),
                                randomnessByColumn: [
                                    [
                                        2,
                                        ...requiredRandomnessColumn(
                                            requiredOpening(firstDealer, 0),
                                            0,
                                        ).slice(1),
                                    ],
                                    ...requiredOpening(
                                        firstDealer,
                                        0,
                                    ).randomnessByColumn.slice(1),
                                ],
                            },
                            ...firstDealer.coefficientOpenings.slice(1),
                        ],
                    },
                    secondDealer,
                ],
            }),
        ).toThrow(/centered ternary/u);
        expect(() =>
            createVssDealerCoefficientOpeningState({
                dealerIdentity: 'trustee-2',
                dealerRosterPosition: 2,
                participantCount,
                qSharePrimes,
                ringDegree,
                thresholdDegree,
                randomBytes: deterministicRandomBytes('trustee-2'),
            }),
        ).toThrow(/inside the accepted participant count/u);
        expect(() =>
            createVssDealerCoefficientOpeningState({
                dealerIdentity: 'trustee-0',
                dealerRosterPosition: 0,
                participantCount,
                qSharePrimes: [],
                ringDegree,
                thresholdDegree,
                randomBytes: deterministicRandomBytes('trustee-0'),
            }),
        ).toThrow(/at least one RNS prime/u);
        expect(() =>
            createVssDealerCoefficientOpeningState({
                dealerIdentity: 'trustee-0',
                dealerRosterPosition: 0,
                participantCount,
                qSharePrimes,
                ringDegree,
                thresholdDegree,
                randomBytes: (byteLength) =>
                    new Uint8Array(Math.max(0, byteLength - 1)),
            }),
        ).toThrow(/exactly the requested byte length/u);
    });
});
