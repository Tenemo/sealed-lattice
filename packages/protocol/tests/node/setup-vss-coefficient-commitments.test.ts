import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import {
    createVssSourceTrusteeCoefficientOpeningState,
    createVssSourceTrusteeCoefficientOpeningStateProvider,
    createVssSourceTrusteeCoefficientCommitmentContribution,
    createVssCoefficientCommitmentBundle,
    setupCommitmentRandomnessWidth,
    type VssCoefficientOpeningInput,
    type VssSourceTrusteeCoefficientOpeningState,
} from '#packages/protocol/src/index';
import {
    createVssPublicCoefficientCommitmentSet,
    createVssSameSecretBridgeStatementSet,
    type VssCommittedMaterialCommitmentComputer,
} from '#packages/protocol/src/setup/vss-commitments';
import { setupCommitmentComputer } from '#tests/support/setup-commitment-computer';
import {
    makeSetupContext,
    makeSetupFixtureHash,
    makeVssOpeningRandomBytes,
} from '#tests/support/setup-fixtures';

const qSharePrimes = [
    140_737_487_306_753, 140_737_486_716_929, 140_737_486_520_321,
] as const;
const ringDegree = 8;
const participantCount = 2;
const thresholdDegree = 2;

const fixtureHash = makeSetupFixtureHash('setup-vss-coefficient-commitments');

const deterministicRandomBytes = makeVssOpeningRandomBytes(
    'setup-vss-coefficient-commitments',
);

const setupContext = makeSetupContext(fixtureHash);

const committedMaterialComputer: VssCommittedMaterialCommitmentComputer = (
    input,
) => {
    const commitmentContextHash = deriveCanonicalObjectHash(
        input.commitmentContext,
    );
    const commitment = {
        objectType: 'VssCommittedMaterialCommitment',
        commitmentRole: input.commitmentRole,
        commitmentContextHash,
        rnsLimbIndex: input.rnsLimbIndex,
        rnsPrime: input.rnsPrime,
        ringDegree: input.ringDegree,
        materialColumnMaskDegree: 1,
        commitmentFields: [],
    } as const;

    return {
        commitment,
        commitmentRoot: deriveCanonicalObjectHash(commitment),
        openingRoot: deriveCanonicalObjectHash({
            objectType: 'VssCommittedMaterialOpening',
            commitmentContextHash,
            materialSeedHex: input.materialSeedHex,
        }),
        commitmentContextHash,
    };
};

const coefficientMessage = (
    sourceTrusteeRosterPosition: number,
    rnsLimbIndex: number,
    shamirCoefficientIndex: number,
    rnsPrime: number,
): number[] =>
    Array.from({ length: ringDegree }, (_unused, coefficientIndex) => {
        const value =
            (sourceTrusteeRosterPosition + 1) * 19 +
            (rnsLimbIndex + 1) * 7 +
            (shamirCoefficientIndex + 1) * 5 +
            coefficientIndex;

        return value % rnsPrime;
    });

const randomnessByColumn = (
    sourceTrusteeRosterPosition: number,
    rnsLimbIndex: number,
    shamirCoefficientIndex: number,
): number[][] =>
    Array.from({ length: 5 }, (_unusedColumn, randomnessColumnIndex) =>
        Array.from({ length: ringDegree }, (_unused, coefficientIndex) => {
            const selector =
                (sourceTrusteeRosterPosition +
                    rnsLimbIndex +
                    shamirCoefficientIndex +
                    randomnessColumnIndex +
                    coefficientIndex) %
                3;

            return selector === 0 ? -1 : selector === 1 ? 0 : 1;
        }),
    );

const opening = (
    sourceTrusteeRosterPosition: number,
    rnsPrime: number,
    rnsLimbIndex: number,
    shamirCoefficientIndex: number,
): VssCoefficientOpeningInput => ({
    rnsLimbIndex,
    rnsPrime,
    shamirCoefficientIndex,
    coefficientMessage: coefficientMessage(
        sourceTrusteeRosterPosition,
        rnsLimbIndex,
        shamirCoefficientIndex,
        rnsPrime,
    ),
    randomnessByColumn: randomnessByColumn(
        sourceTrusteeRosterPosition,
        rnsLimbIndex,
        shamirCoefficientIndex,
    ),
});

const sourceTrusteeOpeningState = (
    sourceTrusteeRosterPosition: number,
): VssSourceTrusteeCoefficientOpeningState => ({
    sourceTrusteeIdentity: `trustee-${String(sourceTrusteeRosterPosition)}`,
    sourceTrusteeRosterPosition,
    coefficientOpenings: qSharePrimes.flatMap((rnsPrime, rnsLimbIndex) =>
        Array.from({ length: thresholdDegree }, (_unused, coefficientIndex) =>
            opening(
                sourceTrusteeRosterPosition,
                rnsPrime,
                rnsLimbIndex,
                coefficientIndex,
            ),
        ),
    ),
});

const requiredOpening = (
    sourceTrusteeState: VssSourceTrusteeCoefficientOpeningState,
    openingIndex: number,
): VssCoefficientOpeningInput => {
    const openingState = sourceTrusteeState.coefficientOpenings[openingIndex];
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
    sourceTrusteeState: VssSourceTrusteeCoefficientOpeningState,
    rnsLimbIndex: number,
    shamirCoefficientIndex: number,
): VssCoefficientOpeningInput => {
    const openingState = sourceTrusteeState.coefficientOpenings.find(
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
        const generatedSourceTrusteeState =
            createVssSourceTrusteeCoefficientOpeningState({
                sourceTrusteeIdentity: 'trustee-0',
                sourceTrusteeRosterPosition: 0,
                participantCount,
                qSharePrimes,
                ringDegree,
                thresholdDegree,
                randomBytes: deterministicRandomBytes('trustee-0'),
            });
        const constantSecretForFirstLimb = decodeShortSecretResidues(
            requiredOpeningByCoordinate(generatedSourceTrusteeState, 0, 0),
        );
        const constantSecretForSecondLimb = decodeShortSecretResidues(
            requiredOpeningByCoordinate(generatedSourceTrusteeState, 1, 0),
        );
        const nonConstantOpening = requiredOpeningByCoordinate(
            generatedSourceTrusteeState,
            0,
            1,
        );
        const firstRandomnessColumn = requiredRandomnessColumn(
            requiredOpeningByCoordinate(generatedSourceTrusteeState, 0, 0),
            0,
        );
        const contribution =
            createVssSourceTrusteeCoefficientCommitmentContribution({
                setupContext,
                publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
                setupCommitmentComputer,
                qSharePrimes,
                ringDegree,
                participantCount,
                thresholdDegree,
                sourceTrusteeOpeningState: generatedSourceTrusteeState,
            });

        expect(generatedSourceTrusteeState.coefficientOpenings).toHaveLength(
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
            requiredOpeningByCoordinate(generatedSourceTrusteeState, 0, 0)
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

    it('loads deterministic source openings through a provider and rejects non-contiguous rosters', () => {
        const sourceTrusteeReferences = [
            {
                sourceTrusteeIdentity: 'trustee-0',
                sourceTrusteeRosterPosition: 0,
            },
            {
                sourceTrusteeIdentity: 'trustee-1',
                sourceTrusteeRosterPosition: 1,
            },
        ] as const;
        const sourceTrusteeOpeningStateProvider =
            createVssSourceTrusteeCoefficientOpeningStateProvider({
                sourceTrustees: sourceTrusteeReferences,
                participantCount,
                qSharePrimes,
                ringDegree,
                thresholdDegree,
                randomBytesForSourceTrustee: (sourceTrusteeReference) =>
                    deterministicRandomBytes(
                        `provider-${sourceTrusteeReference.sourceTrusteeIdentity}`,
                    ),
            });

        expect(
            sourceTrusteeOpeningStateProvider.loadSourceTrusteeOpeningState(
                sourceTrusteeReferences[0],
            ),
        ).toEqual(
            sourceTrusteeOpeningStateProvider.loadSourceTrusteeOpeningState(
                sourceTrusteeReferences[0],
            ),
        );

        expect(() =>
            createVssSourceTrusteeCoefficientOpeningStateProvider({
                sourceTrustees: [
                    sourceTrusteeReferences[0],
                    sourceTrusteeReferences[0],
                ],
                participantCount,
                qSharePrimes,
                ringDegree,
                thresholdDegree,
                randomBytesForSourceTrustee: () =>
                    deterministicRandomBytes('duplicate-source'),
            }),
        ).toThrow(/contiguous from zero/u);
    });

    it('creates deterministic root-bound commitment material from local openings', () => {
        const bundle = createVssCoefficientCommitmentBundle({
            setupContext,
            publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
            setupCommitmentComputer,
            qSharePrimes,
            ringDegree,
            participantCount,
            thresholdDegree,
            sourceTrusteeOpeningStates: [
                sourceTrusteeOpeningState(1),
                sourceTrusteeOpeningState(0),
            ],
        });
        const { vssCoefficientCommitmentRoot, ...commitmentSetWithoutRoot } =
            bundle.commitmentSet;
        const {
            vssCoefficientCommitmentMaterialRoot,
            ...materialSetWithoutRoot
        } = bundle.materialSet;
        const firstMaterialRecord =
            bundle.materialSet.coefficientCommitments[0];
        const firstOpening = requiredOpening(sourceTrusteeOpeningState(0), 0);
        const firstSourceTrusteeContribution =
            createVssSourceTrusteeCoefficientCommitmentContribution({
                setupContext,
                publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
                setupCommitmentComputer,
                qSharePrimes,
                ringDegree,
                participantCount,
                thresholdDegree,
                sourceTrusteeOpeningState: sourceTrusteeOpeningState(0),
            });

        expect(
            bundle.commitmentSet.sourceTrusteeRecords.map(
                (record) => record.sourceTrusteeRosterPosition,
            ),
        ).toEqual([0, 1]);
        expect(bundle.materialSet.materialRecordCount).toBe(
            participantCount * qSharePrimes.length * thresholdDegree,
        );
        expect(vssCoefficientCommitmentRoot).toBe(
            deriveCanonicalObjectHash(commitmentSetWithoutRoot),
        );
        expect(vssCoefficientCommitmentMaterialRoot).toBe(
            deriveCanonicalObjectHash(materialSetWithoutRoot),
        );
        expect(firstMaterialRecord?.commitmentRoot).toBe(
            setupCommitmentComputer({
                publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
                sourceRnsLimbIndex: firstOpening.rnsLimbIndex,
                sourceMessageModulus: firstOpening.rnsPrime,
                shamirCoefficientIndex: firstOpening.shamirCoefficientIndex,
                messageCoefficients: firstOpening.coefficientMessage,
                randomnessByColumn: firstOpening.randomnessByColumn,
                ringDegree,
            }).commitmentRoot,
        );
        expect(
            bundle.privateOpeningMaterialBySourceTrustee[0]
                ?.coefficientOpenings[0]?.commitmentRoot,
        ).toBe(firstMaterialRecord?.commitmentRoot);
        expect(firstSourceTrusteeContribution.sourceTrusteeRecord).toEqual(
            bundle.commitmentSet.sourceTrusteeRecords[0],
        );
        expect(firstSourceTrusteeContribution.materialRecords).toEqual(
            bundle.materialSet.coefficientCommitments.slice(
                0,
                qSharePrimes.length * thresholdDegree,
            ),
        );
    });

    it('builds the bridge carrier only from matching canonical source material', () => {
        const publicMatrixSeedHash = fixtureHash('public-matrix-seed');
        const sourceBundle = createVssCoefficientCommitmentBundle({
            setupContext,
            publicMatrixSeedHash,
            setupCommitmentComputer,
            qSharePrimes,
            ringDegree,
            participantCount,
            thresholdDegree,
            sourceTrusteeOpeningStates: [
                sourceTrusteeOpeningState(0),
                sourceTrusteeOpeningState(1),
            ],
        });
        const targetCommitmentBundle = createVssPublicCoefficientCommitmentSet({
            setupContext,
            publicMatrixSeedHash,
            participantCount,
            qSharePrimes,
            ringDegree,
            thresholdDegree,
            sourceTrusteeOpeningStates: [
                sourceTrusteeOpeningState(0),
                sourceTrusteeOpeningState(1),
            ],
            committedMaterialSeed: ({
                sourceTrusteeRosterPosition,
                rnsLimbIndex,
                shamirCoefficientIndex,
            }) =>
                fixtureHash(
                    `target-${String(sourceTrusteeRosterPosition)}-${String(rnsLimbIndex)}-${String(shamirCoefficientIndex)}`,
                ),
            computeVssCommittedMaterialCommitment: committedMaterialComputer,
        });
        const buildStatementSet = (
            sourceCoefficientCommitmentSet = sourceBundle.commitmentSet,
            sourceCoefficientCommitmentMaterialSet = sourceBundle.materialSet,
        ): ReturnType<typeof createVssSameSecretBridgeStatementSet> =>
            createVssSameSecretBridgeStatementSet({
                setupContext,
                publicMatrixSeedHash,
                coefficientCommitmentSet:
                    targetCommitmentBundle.coefficientCommitmentSet,
                sourceCoefficientCommitmentSet,
                sourceCoefficientCommitmentMaterialSet,
            });

        const statementSet = buildStatementSet();
        expect(
            statementSet.statementRecords.map((statementRecord) =>
                statementRecord.sourceConstantCoefficientCommitments.map(
                    (sourceCommitment) =>
                        sourceCommitment.commitment.sourceRnsLimbIndex,
                ),
            ),
        ).toEqual([
            [0, 1, 2],
            [0, 1, 2],
        ]);

        expect(() =>
            buildStatementSet({
                ...sourceBundle.commitmentSet,
                ceremonyId: 'other-ceremony',
            }),
        ).toThrow(/match the canonical source commitment set/u);
        expect(() =>
            buildStatementSet(sourceBundle.commitmentSet, {
                ...sourceBundle.materialSet,
                rnsLimbCount: qSharePrimes.length - 1,
            }),
        ).toThrow(/match the canonical source commitment set/u);

        const [firstMaterialRecord, ...remainingMaterialRecords] =
            sourceBundle.materialSet.coefficientCommitments;
        if (firstMaterialRecord === undefined) {
            throw new Error('bridge carrier fixture material is missing');
        }
        expect(() =>
            buildStatementSet(sourceBundle.commitmentSet, {
                ...sourceBundle.materialSet,
                coefficientCommitments: [
                    {
                        ...firstMaterialRecord,
                        commitment: {
                            ...firstMaterialRecord.commitment,
                            sourceRnsLimbIndex: 1,
                        },
                    },
                    ...remainingMaterialRecords,
                ],
            }),
        ).toThrow(/canonical public coordinates and roots/u);
    });

    it('rejects malformed local opening state before root publication', () => {
        const firstSourceTrustee = sourceTrusteeOpeningState(0);
        const secondSourceTrustee = sourceTrusteeOpeningState(1);

        expect(() =>
            createVssCoefficientCommitmentBundle({
                setupContext,
                publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
                setupCommitmentComputer,
                qSharePrimes,
                ringDegree,
                participantCount,
                thresholdDegree,
                sourceTrusteeOpeningStates: [firstSourceTrustee],
            }),
        ).toThrow(/every accepted participant/u);
        expect(() =>
            createVssCoefficientCommitmentBundle({
                setupContext,
                publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
                setupCommitmentComputer,
                qSharePrimes,
                ringDegree,
                participantCount,
                thresholdDegree,
                sourceTrusteeOpeningStates: [
                    {
                        ...firstSourceTrustee,
                        coefficientOpenings: [
                            requiredOpening(firstSourceTrustee, 0),
                            requiredOpening(firstSourceTrustee, 0),
                            ...firstSourceTrustee.coefficientOpenings.slice(2),
                        ],
                    },
                    secondSourceTrustee,
                ],
            }),
        ).toThrow(/distinct limb\/coefficient coordinates/u);
        expect(() =>
            createVssCoefficientCommitmentBundle({
                setupContext,
                publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
                setupCommitmentComputer,
                qSharePrimes,
                ringDegree,
                participantCount,
                thresholdDegree,
                sourceTrusteeOpeningStates: [
                    {
                        ...firstSourceTrustee,
                        coefficientOpenings: [
                            {
                                ...requiredOpening(firstSourceTrustee, 0),
                                coefficientMessage: [
                                    qSharePrimes[0],
                                    ...requiredOpening(
                                        firstSourceTrustee,
                                        0,
                                    ).coefficientMessage.slice(1),
                                ],
                            },
                            ...firstSourceTrustee.coefficientOpenings.slice(1),
                        ],
                    },
                    secondSourceTrustee,
                ],
            }),
        ).toThrow(/residue below the declared modulus/u);
        expect(() =>
            createVssCoefficientCommitmentBundle({
                setupContext,
                publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
                setupCommitmentComputer,
                qSharePrimes,
                ringDegree,
                participantCount,
                thresholdDegree,
                sourceTrusteeOpeningStates: [
                    {
                        ...firstSourceTrustee,
                        coefficientOpenings: [
                            {
                                ...requiredOpening(firstSourceTrustee, 0),
                                randomnessByColumn: [
                                    [
                                        2,
                                        ...requiredRandomnessColumn(
                                            requiredOpening(
                                                firstSourceTrustee,
                                                0,
                                            ),
                                            0,
                                        ).slice(1),
                                    ],
                                    ...requiredOpening(
                                        firstSourceTrustee,
                                        0,
                                    ).randomnessByColumn.slice(1),
                                ],
                            },
                            ...firstSourceTrustee.coefficientOpenings.slice(1),
                        ],
                    },
                    secondSourceTrustee,
                ],
            }),
        ).toThrow(/centered ternary/u);
        expect(() =>
            createVssSourceTrusteeCoefficientOpeningState({
                sourceTrusteeIdentity: 'trustee-2',
                sourceTrusteeRosterPosition: 2,
                participantCount,
                qSharePrimes,
                ringDegree,
                thresholdDegree,
                randomBytes: deterministicRandomBytes('trustee-2'),
            }),
        ).toThrow(/inside the accepted participant count/u);
        expect(() =>
            createVssSourceTrusteeCoefficientOpeningState({
                sourceTrusteeIdentity: 'trustee-0',
                sourceTrusteeRosterPosition: 0,
                participantCount,
                qSharePrimes: [],
                ringDegree,
                thresholdDegree,
                randomBytes: deterministicRandomBytes('trustee-0'),
            }),
        ).toThrow(/at least one RNS prime/u);
        expect(() =>
            createVssSourceTrusteeCoefficientOpeningState({
                sourceTrusteeIdentity: 'trustee-0',
                sourceTrusteeRosterPosition: 0,
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
