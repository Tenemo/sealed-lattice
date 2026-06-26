import { deriveProtocolHash } from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import {
    aggregateCompactVssThresholdShareCommitments,
    compactVssCommitmentMeasurement,
    compactVssMatrixExpansionProfile,
    compactVssParameterCertificateInputBinding,
    compactVssCommitmentProfileId,
    compactVssShareLinkageAggregateThresholdRule,
    compactVssShareLinkageCommonKeyRule,
    compactVssShareLinkageProofFamily,
    compactVssShareLinkageProofBatchingRule,
    compactVssShareLinkageShamirEvaluationRule,
    compactVssProjectionWeight,
    compactVssEncodedCommitmentByteLength,
    combineCompactVssCommitments,
    createCompactVssCoefficientCommitmentSet,
    createCompactVssRecipientShareCommitmentBundle,
    createCompactVssShareLinkageStatement,
    createCompactVssShareLinkageProofMaterialSet,
    computeCompactVssCommitmentFromOpening,
    decodeCompactVssCommitmentBody,
    decodeCompactVssTernaryRandomnessColumnsHex,
    encodeCompactVssTernaryRandomnessColumnsHex,
    encodeCompactVssCommitmentBody,
    verifyCompactVssAggregateThresholdCommitmentSet,
    verifyCompactVssRecipientShareCommitmentSet,
    verifyCompactVssShareLinkageStatement,
    verifyCompactVssShareLinkageProofMaterialSet,
    verifyCompactVssCommitmentOpening,
    verifyCompactVssAggregateOpeningCredential,
    type CompactVssAggregateThresholdCommitmentSet,
    type CompactVssCommitmentBodyMetadata,
    type CompactVssCommitmentValue,
    type CompactVssCommitmentOpeningInput,
    type CompactVssAggregateThresholdOpeningCredential,
    type CompactVssRecipientShareOpeningCredential,
    type CompactVssShareLinkageProofMaterialInput,
} from '#packages/protocol/src/setup/compact-vss-commitments.js';
import { acceptedBgvSetupQSharePrimes } from '#packages/protocol/src/setup/vss-coefficient-commitments.js';
import type { VssSourceTrusteeCoefficientOpeningState } from '#packages/protocol/src/setup/vss-coefficient-commitments.js';

type MutableCompactVssProofMaterialSetBytes = {
    readonly proofMaterials: {
        readonly proofRecords: {
            proofBytesHex: string;
        }[];
    }[];
};

const publicMatrixSeedHash = deriveProtocolHash('SetupPublicMatrixSeedHash', {
    fixture: 'compact-vss-commitments',
    label: 'public-matrix-seed',
});

const setupContext = {
    ceremonyId: 'compact-vss-test',
    manifestHash: deriveProtocolHash('ActionContextHash', {
        fixture: 'compact-vss',
        label: 'manifest',
    }),
    rosterHash: deriveProtocolHash('ActionContextHash', {
        fixture: 'compact-vss',
        label: 'roster',
    }),
    setupProfileHash: deriveProtocolHash('ActionContextHash', {
        fixture: 'compact-vss',
        label: 'setup-profile',
    }),
    qShareHash: deriveProtocolHash('ActionContextHash', {
        fixture: 'compact-vss',
        label: 'q-share',
    }),
    carryAwareVssShareRelationProfileHash: deriveProtocolHash(
        'ActionContextHash',
        {
            fixture: 'compact-vss',
            label: 'relation-profile',
        },
    ),
    commitmentProfileHash: deriveProtocolHash('ActionContextHash', {
        fixture: 'compact-vss',
        label: 'commitment-profile',
    }),
    setupEpoch: 'compact-vss-epoch',
};

const opening = (
    label: string,
    messageCoefficients: readonly number[],
    randomnessOffset: number,
): CompactVssCommitmentOpeningInput => ({
    commitmentRole: 'recipient-share',
    commitmentContext: {
        objectType: 'CompactVssRecipientShareCommitmentContext',
        objectVersion: 1,
        sourceTrusteeIdentity: `source-${label}`,
        recipientIdentity: 'recipient-0',
    },
    publicMatrixSeedHash,
    rnsLimbIndex: 0,
    rnsPrime: 65_537,
    ringDegree: messageCoefficients.length,
    messageCoefficients,
    randomnessByColumn: [
        messageCoefficients.map(
            (_unused, coefficientIndex) =>
                ((coefficientIndex + randomnessOffset) % 3) - 1,
        ),
        messageCoefficients.map(
            (_unused, coefficientIndex) =>
                ((coefficientIndex + randomnessOffset + 1) % 3) - 1,
        ),
    ],
});

const aggregateOpening = (
    leftOpening: CompactVssCommitmentOpeningInput,
    rightOpening: CompactVssCommitmentOpeningInput,
    rightScalar: number,
): CompactVssCommitmentOpeningInput => ({
    ...leftOpening,
    commitmentRole: 'aggregate-threshold-share',
    commitmentContext: {
        objectType: 'CompactVssAggregateThresholdShareCommitmentContext',
        objectVersion: 1,
        recipientIdentity: 'recipient-0',
    },
    messageCoefficients: leftOpening.messageCoefficients.map(
        (leftCoefficient, coefficientIndex) =>
            (leftCoefficient +
                rightScalar *
                    (rightOpening.messageCoefficients[coefficientIndex] ?? 0)) %
            leftOpening.rnsPrime,
    ),
    randomnessByColumn: leftOpening.randomnessByColumn.map(
        (leftColumn, columnIndex) =>
            leftColumn.map(
                (leftCoefficient, coefficientIndex) =>
                    leftCoefficient +
                    rightScalar *
                        (rightOpening.randomnessByColumn[columnIndex]?.[
                            coefficientIndex
                        ] ?? 0),
            ),
    ),
});

const residue = (value: bigint, modulus: number): number => {
    const modulusWide = BigInt(modulus);
    const residueValue = value % modulusWide;

    return Number(
        residueValue < 0n ? residueValue + modulusWide : residueValue,
    );
};

const writeTestLittleEndianU64 = (
    bytes: Uint8Array,
    offset: number,
    value: number,
): void => {
    let remainingValue = BigInt(value);
    for (let byteIndex = 0; byteIndex < 8; byteIndex += 1) {
        bytes[offset + byteIndex] = Number(remainingValue & 0xffn);
        remainingValue >>= 8n;
    }
};

const expectedPrivateVssShareValues = (input: {
    readonly sourceTrusteeOpeningState: VssSourceTrusteeCoefficientOpeningState;
    readonly recipientRosterPosition: number;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly ringDegree: number;
    readonly thresholdDegree: number;
}): readonly number[] => {
    const coefficientOpeningsByShamirIndex = new Map(
        input.sourceTrusteeOpeningState.coefficientOpenings
            .filter(
                (coefficientOpening) =>
                    coefficientOpening.rnsLimbIndex === input.rnsLimbIndex &&
                    coefficientOpening.rnsPrime === input.rnsPrime,
            )
            .map((coefficientOpening) => [
                coefficientOpening.shamirCoefficientIndex,
                coefficientOpening,
            ]),
    );
    const recipientTrusteePoint = BigInt(input.recipientRosterPosition + 1);

    return Array.from(
        { length: input.ringDegree },
        (_unused, coefficientPosition) => {
            let recipientPointPower = 1n;
            let unreducedShareValue = 0n;
            for (
                let shamirCoefficientIndex = 0;
                shamirCoefficientIndex < input.thresholdDegree;
                shamirCoefficientIndex += 1
            ) {
                const coefficientOpening = coefficientOpeningsByShamirIndex.get(
                    shamirCoefficientIndex,
                );
                if (coefficientOpening === undefined) {
                    throw new Error(
                        'compact VSS test fixture is missing a coefficient opening.',
                    );
                }
                const coefficientValue =
                    coefficientOpening.coefficientMessage[coefficientPosition];
                if (coefficientValue === undefined) {
                    throw new Error(
                        'compact VSS test fixture has a short coefficient vector.',
                    );
                }
                unreducedShareValue +=
                    BigInt(coefficientValue) * recipientPointPower;
                recipientPointPower *= recipientTrusteePoint;
            }

            return residue(unreducedShareValue, input.rnsPrime);
        },
    );
};

const expectedAggregateVssShareSum = (input: {
    readonly sourceTrusteeOpeningStates: readonly VssSourceTrusteeCoefficientOpeningState[];
    readonly recipientRosterPosition: number;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly ringDegree: number;
    readonly thresholdDegree: number;
}): Readonly<{
    readonly aggregateShareValues: readonly number[];
    readonly aggregateCommitmentMessageValues: readonly number[];
}> => {
    const aggregateCommitmentMessageValues = Array.from(
        { length: input.ringDegree },
        () => 0n,
    );
    input.sourceTrusteeOpeningStates.forEach((sourceTrusteeOpeningState) => {
        const sourceShareValues = expectedPrivateVssShareValues({
            sourceTrusteeOpeningState,
            recipientRosterPosition: input.recipientRosterPosition,
            rnsLimbIndex: input.rnsLimbIndex,
            rnsPrime: input.rnsPrime,
            ringDegree: input.ringDegree,
            thresholdDegree: input.thresholdDegree,
        });
        sourceShareValues.forEach((sourceShareValue, coefficientPosition) => {
            aggregateCommitmentMessageValues[coefficientPosition] =
                (aggregateCommitmentMessageValues[coefficientPosition] ?? 0n) +
                BigInt(sourceShareValue);
        });
    });
    return {
        aggregateShareValues: aggregateCommitmentMessageValues.map(
            (shareValue) => residue(shareValue, input.rnsPrime),
        ),
        aggregateCommitmentMessageValues: aggregateCommitmentMessageValues.map(
            (shareValue) => Number(shareValue),
        ),
    };
};

const compactVssShadowCoefficientMessage = (input: {
    readonly sourceTrusteeRosterPosition: number;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly shamirCoefficientIndex: number;
    readonly ringDegree: number;
}): readonly number[] =>
    Array.from({ length: input.ringDegree }, (_unused, coefficientPosition) =>
        residue(
            BigInt(
                input.rnsPrime -
                    1 -
                    ((input.sourceTrusteeRosterPosition + coefficientPosition) %
                        7),
            ) +
                BigInt(
                    (input.sourceTrusteeRosterPosition + 1) * 19 +
                        (input.rnsLimbIndex + 1) * 23 +
                        (input.shamirCoefficientIndex + 1) * 31 +
                        (coefficientPosition + 1) * 37 +
                        input.sourceTrusteeRosterPosition *
                            input.shamirCoefficientIndex *
                            coefficientPosition,
                ),
            input.rnsPrime,
        ),
    );

const compactVssShadowSourceTrusteeOpeningStates = (input: {
    readonly participantCount: number;
    readonly qSharePrimes: readonly number[];
    readonly thresholdDegree: number;
    readonly ringDegree: number;
}): readonly VssSourceTrusteeCoefficientOpeningState[] =>
    Array.from(
        { length: input.participantCount },
        (_unusedSource, sourceTrusteeRosterPosition) => ({
            sourceTrusteeIdentity: `source-${String(sourceTrusteeRosterPosition)}`,
            sourceTrusteeRosterPosition,
            coefficientOpenings: input.qSharePrimes.flatMap(
                (rnsPrime, rnsLimbIndex) =>
                    Array.from(
                        { length: input.thresholdDegree },
                        (_unusedCoefficient, shamirCoefficientIndex) => ({
                            rnsLimbIndex,
                            rnsPrime,
                            shamirCoefficientIndex,
                            coefficientMessage:
                                compactVssShadowCoefficientMessage({
                                    sourceTrusteeRosterPosition,
                                    rnsLimbIndex,
                                    rnsPrime,
                                    shamirCoefficientIndex,
                                    ringDegree: input.ringDegree,
                                }),
                            randomnessByColumn: [],
                        }),
                    ),
            ),
        }),
    );

const findRecipientShareCredential = (
    credentials: readonly CompactVssRecipientShareOpeningCredential[],
    input: {
        readonly sourceTrusteeRosterPosition: number;
        readonly recipientRosterPosition: number;
        readonly rnsLimbIndex: number;
    },
): CompactVssRecipientShareOpeningCredential => {
    const credential = credentials.find(
        (candidateCredential) =>
            candidateCredential.sourceTrusteeRosterPosition ===
                input.sourceTrusteeRosterPosition &&
            candidateCredential.recipientRosterPosition ===
                input.recipientRosterPosition &&
            candidateCredential.rnsLimbIndex === input.rnsLimbIndex,
    );
    if (credential === undefined) {
        throw new Error(
            'compact VSS test fixture is missing a recipient share credential.',
        );
    }

    return credential;
};

const findAggregateThresholdCredential = (
    credentials: readonly CompactVssAggregateThresholdOpeningCredential[],
    input: {
        readonly recipientRosterPosition: number;
        readonly rnsLimbIndex: number;
    },
): CompactVssAggregateThresholdOpeningCredential => {
    const credential = credentials.find(
        (candidateCredential) =>
            candidateCredential.recipientRosterPosition ===
                input.recipientRosterPosition &&
            candidateCredential.rnsLimbIndex === input.rnsLimbIndex,
    );
    if (credential === undefined) {
        throw new Error(
            'compact VSS test fixture is missing an aggregate threshold credential.',
        );
    }

    return credential;
};

describe('compact VSS development commitments', () => {
    it('verifies openings and rejects a tampered message', () => {
        const firstOpening = opening('0', [3, 5, 8, 13, 21, 34, 55, 89], 0);
        const commitment = computeCompactVssCommitmentFromOpening(firstOpening);

        expect(commitment).toMatchObject({
            ok: true,
            operation: 'computeCompactVssCommitmentFromOpening',
            setupProfileId: 'CollectiveBgvSetup-v1',
            encodedCommitmentByteLength:
                compactVssEncodedCommitmentByteLength(),
            commitment: {
                objectType: 'CompactVssCommitment',
                profileId: compactVssCommitmentProfileId,
                outputCoordinateCount: 16,
                randomnessColumnCount: 2,
            },
        });
        expect(commitment.commitmentRoot).toHaveLength(128);
        expect(
            verifyCompactVssCommitmentOpening({
                opening: firstOpening,
                expectedCommitmentRoot: commitment.commitmentRoot,
            }),
        ).toMatchObject({
            ok: true,
            operation: 'verifyCompactVssCommitmentOpening',
            commitmentRoot: commitment.commitmentRoot,
        });

        expect(() =>
            verifyCompactVssCommitmentOpening({
                opening: {
                    ...firstOpening,
                    messageCoefficients: [
                        4,
                        ...firstOpening.messageCoefficients.slice(1),
                    ],
                },
                expectedCommitmentRoot: commitment.commitmentRoot,
            }),
        ).toThrow(/opening does not match/u);
    });

    it('round-trips the canonical encoded commitment body and rejects malformed bodies', () => {
        const firstOpening = opening('0', [3, 5, 8, 13, 21, 34, 55, 89], 0);
        const commitment = computeCompactVssCommitmentFromOpening(firstOpening);
        const commitmentBodyBytes = encodeCompactVssCommitmentBody(
            commitment.commitment,
        );
        const metadata: CompactVssCommitmentBodyMetadata = {
            commitmentRole: commitment.commitment.commitmentRole,
            commitmentContextHash: commitment.commitment.commitmentContextHash,
            publicMatrixSeedHash: commitment.commitment.publicMatrixSeedHash,
            rnsLimbIndex: commitment.commitment.rnsLimbIndex,
            rnsPrime: commitment.commitment.rnsPrime,
            ringDegree: commitment.commitment.ringDegree,
        };

        expect(commitmentBodyBytes.byteLength).toBe(
            compactVssEncodedCommitmentByteLength(),
        );

        const decodedCommitment = decodeCompactVssCommitmentBody({
            metadata,
            commitmentBodyBytes,
        });

        expect(decodedCommitment).toEqual(commitment.commitment);
        expect(encodeCompactVssCommitmentBody(decodedCommitment)).toEqual(
            commitmentBodyBytes,
        );

        expect(() =>
            decodeCompactVssCommitmentBody({
                metadata,
                commitmentBodyBytes: commitmentBodyBytes.slice(0, -8),
            }),
        ).toThrow(/length must match/u);

        const firstCommitmentLimb = commitment.commitment.commitmentLimbs[0];
        if (firstCommitmentLimb === undefined) {
            throw new Error(
                'compact VSS test fixture is missing a commitment limb.',
            );
        }
        const outOfRangeBodyBytes = commitmentBodyBytes.slice();
        writeTestLittleEndianU64(
            outOfRangeBodyBytes,
            0,
            firstCommitmentLimb.modulus,
        );
        expect(() =>
            decodeCompactVssCommitmentBody({
                metadata,
                commitmentBodyBytes: outOfRangeBodyBytes,
            }),
        ).toThrow(/residue below the commitment modulus/u);

        const reorderedCommitment = {
            ...commitment.commitment,
            commitmentLimbs: [
                ...commitment.commitment.commitmentLimbs,
            ].reverse(),
        } satisfies CompactVssCommitmentValue;
        expect(() =>
            encodeCompactVssCommitmentBody(reorderedCommitment),
        ).toThrow(/commitment modulus index is not canonical/u);
    });

    it('round-trips packed ternary opening randomness and rejects malformed packed columns', () => {
        const randomnessByColumn = [
            [-1, 0, 1, -1, 1],
            [1, -1, 0, 1, -1],
        ] as const;
        const packed = encodeCompactVssTernaryRandomnessColumnsHex(
            randomnessByColumn,
            5,
        );

        expect(packed).toEqual(['2402', '9200']);
        expect(decodeCompactVssTernaryRandomnessColumnsHex(packed, 5)).toEqual(
            randomnessByColumn,
        );

        expect(() =>
            decodeCompactVssTernaryRandomnessColumnsHex(['ff', '00'], 4),
        ).toThrow(/invalid ternary code/u);
        expect(() =>
            decodeCompactVssTernaryRandomnessColumnsHex(['2406', '9200'], 5),
        ).toThrow(/padding/u);
        expect(() =>
            encodeCompactVssTernaryRandomnessColumnsHex(
                [
                    [-1, 2, 0],
                    [0, 1, -1],
                ],
                3,
            ),
        ).toThrow(/ternary coefficient/u);
    });

    it('profiles compact matrix expansion and binds coordinates to seed and input column', () => {
        const profile = compactVssMatrixExpansionProfile();

        expect(profile).toMatchObject({
            objectType: 'CompactVssMatrixExpansionProfile',
            profileId: compactVssCommitmentProfileId,
            matrixKind: 'compact-vss-commitment-key',
            ringDegree: 32_768,
            commitmentModulusLimbIndices: [0, 1, 2],
            outputCoordinateCount: 16,
            projectionWeight: 32,
            randomnessColumnCount: 2,
            inputColumnLabels: ['message', 'randomness:0', 'randomness:1'],
            coordinateCountPerCommitment: 48,
            sampledMatrixResiduesPerCoordinate: 96,
            sampledProjectionIndicesPerCoordinate: 96,
            sampledMatrixResiduesPerCommitment: 4_608,
            sampledProjectionIndicesPerCommitment: 4_608,
            residueMultiplyAddsPerCommitment: 4_608,
        });
        expect(
            deriveProtocolHash('CompactVssMatrixExpansionProfileHash', profile),
        ).toHaveLength(128);
        expect(profile.matrixResiduePreimageFields).toEqual(
            expect.arrayContaining([
                'publicMatrixSeedHash',
                'inputColumn',
                'projectionTermIndex',
            ]),
        );
        expect(profile.projectionIndexPreimageFields).toEqual(
            expect.arrayContaining([
                'publicMatrixSeedHash',
                'inputColumn',
                'ringDegree',
            ]),
        );

        const zeroColumn = [0, 0, 0, 0, 0, 0, 0, 0];
        const messageOnlyOpening: CompactVssCommitmentOpeningInput = {
            commitmentRole: 'recipient-share',
            commitmentContext: {
                objectType: 'CompactVssRecipientShareCommitmentContext',
                objectVersion: 1,
                sourceTrusteeIdentity: 'source-domain',
                recipientIdentity: 'recipient-0',
            },
            publicMatrixSeedHash,
            rnsLimbIndex: 0,
            rnsPrime: 65_537,
            ringDegree: zeroColumn.length,
            messageCoefficients: [1, ...zeroColumn.slice(1)],
            randomnessByColumn: [zeroColumn, zeroColumn],
        };
        const alternateSeedOpening = {
            ...messageOnlyOpening,
            publicMatrixSeedHash: deriveProtocolHash(
                'SetupPublicMatrixSeedHash',
                {
                    fixture: 'compact-vss-commitments',
                    label: 'alternate-public-matrix-seed',
                },
            ),
        };
        const randomnessOnlyOpening = {
            ...messageOnlyOpening,
            messageCoefficients: zeroColumn,
            randomnessByColumn: [[1, ...zeroColumn.slice(1)], zeroColumn],
        };

        const messageOnlyCommitment =
            computeCompactVssCommitmentFromOpening(messageOnlyOpening);
        const alternateSeedCommitment =
            computeCompactVssCommitmentFromOpening(alternateSeedOpening);
        const randomnessOnlyCommitment = computeCompactVssCommitmentFromOpening(
            randomnessOnlyOpening,
        );

        expect(messageOnlyCommitment.commitment.commitmentLimbs).not.toEqual(
            alternateSeedCommitment.commitment.commitmentLimbs,
        );
        expect(messageOnlyCommitment.commitment.commitmentLimbs).not.toEqual(
            randomnessOnlyCommitment.commitment.commitmentLimbs,
        );
    });

    it('combines public coordinates into the same aggregate commitment as the aggregate opening', () => {
        const firstOpening = opening('0', [7, 11, 13, 17, 19, 23, 29, 31], 0);
        const secondOpening = opening('1', [2, 3, 5, 7, 11, 13, 17, 19], 1);
        const firstCommitment =
            computeCompactVssCommitmentFromOpening(firstOpening);
        const secondCommitment =
            computeCompactVssCommitmentFromOpening(secondOpening);
        const expectedAggregateOpening = aggregateOpening(
            firstOpening,
            secondOpening,
            2,
        );
        const directAggregateCommitment =
            computeCompactVssCommitmentFromOpening(expectedAggregateOpening);
        const combinedAggregateCommitment = combineCompactVssCommitments({
            commitmentRole: 'aggregate-threshold-share',
            commitmentContext: expectedAggregateOpening.commitmentContext,
            terms: [
                {
                    commitment: firstCommitment.commitment,
                    scalar: 1,
                },
                {
                    commitment: secondCommitment.commitment,
                    scalar: 2,
                },
            ],
        });

        expect(combinedAggregateCommitment.commitment).toEqual(
            directAggregateCommitment.commitment,
        );
        expect(combinedAggregateCommitment.commitmentRoot).toBe(
            directAggregateCommitment.commitmentRoot,
        );
    });

    it('binds compact parameter certificate inputs without claiming final certificate evidence', () => {
        const targetBasisHash = deriveProtocolHash('TargetBasisHash', {
            fixture: 'compact-vss-commitments',
            label: 'target-basis',
        });
        const sameSecretProofFamilyBindingRoot = deriveProtocolHash(
            'SameSecretProofFamilyBindingRoot',
            {
                fixture: 'compact-vss-commitments',
                label: 'same-secret-proof-family-binding',
            },
        );
        const binding = compactVssParameterCertificateInputBinding({
            participantCount: 10,
            sourceRnsPrimes: [65_537, 65_539, 65_543, 65_551],
            targetRnsPrimes: acceptedBgvSetupQSharePrimes.slice(0, 2),
            thresholdDegree: 4,
            targetBasisHash,
            sameSecretProofFamilyBindingRoot,
            ringDegree: 32_768,
        });

        expect(binding).toMatchObject({
            objectType: 'CompactVssParameterCertificateInputBinding',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            profileId: compactVssCommitmentProfileId,
            participantCount: 10,
            sourceRnsLimbCount: 4,
            targetRnsLimbCount: 2,
            thresholdDegree: 4,
            ringDegree: 32_768,
            commitmentRelation: {
                relation: 'C = A0 * m + A1 * r mod q_c',
                outputCoordinateCount: 16,
                messageWidth: 1,
                randomnessWidth: 2,
                projectionWeight: 32,
                coordinateCountPerCommitment: 48,
                inputColumnLabels: ['message', 'randomness:0', 'randomness:1'],
            },
            commonCommitmentKey: {
                sparseProjectionShape: {
                    inputColumnCount: 3,
                    projectionWeight: 32,
                    coordinateCountPerCommitment: 48,
                    sampledMatrixResiduesPerCoordinate: 96,
                    sampledProjectionIndicesPerCoordinate: 96,
                    sampledMatrixResiduesPerCommitment: 4_608,
                    sampledProjectionIndicesPerCommitment: 4_608,
                },
            },
            sameSecretBridgeInput: {
                targetBasisHash,
                targetRnsPrimes: acceptedBgvSetupQSharePrimes.slice(0, 2),
                sameSecretProofFamilyBindingRoot,
                targetBasisLimbOrder: 'profile-order-prefix',
            },
        });
        expect(binding.commitmentRelation.commitmentModulusLimbs).toStrictEqual(
            [
                { commitmentModulusIndex: 0, modulus: 65_537 },
                { commitmentModulusIndex: 1, modulus: 65_539 },
                { commitmentModulusIndex: 2, modulus: 65_543 },
            ],
        );
        expect(
            binding.normInputClasses.map((normInputClass) =>
                String(normInputClass.className),
            ),
        ).toStrictEqual([
            'shamirScalarL1Amplification',
            'messageEncodingNorm',
            'openingRandomnessNorm',
            'aggregateDealerCount',
        ]);
        expect(binding.normInputClasses[0]).toMatchObject({
            maximumRecipientTrusteePoint: 10,
            shamirCoefficientCount: 4,
            maximumOneSourceShamirScalarL1: 1_111,
            oneRecipientAggregateShamirScalarL1: 11_110,
        });
        expect(binding.normInputClasses[1]).toMatchObject({
            sourceCoefficientUpperBoundMultiplier: 1,
            recipientShareCoefficientUpperBoundMultiplier: 1,
            aggregateCoefficientUpperBoundMultiplier: 10,
        });
        expect(binding.estimatorInputRows).toEqual([
            expect.objectContaining({
                rowId: 'compact-vss-module-sis-binding-input',
                problem: 'Module-SIS',
                outputCoordinateCount: 16,
                projectionWeight: 32,
                sampledMatrixResiduesPerCommitment: 4_608,
                sampledProjectionIndicesPerCommitment: 4_608,
            }),
            expect.objectContaining({
                rowId: 'compact-vss-module-lwe-hiding-input',
                problem: 'Module-LWE',
                outputCoordinateCount: 16,
                projectionWeight: 32,
                sampledMatrixResiduesPerCommitment: 4_608,
                sampledProjectionIndicesPerCommitment: 4_608,
            }),
        ]);

        const {
            compactVssParameterCertificateInputBindingHash,
            ...certificateInputBody
        } = binding;
        expect(compactVssParameterCertificateInputBindingHash).toBe(
            deriveProtocolHash(
                'CompactVssParameterCertificateInputBindingHash',
                certificateInputBody,
            ),
        );
        expect(() =>
            compactVssParameterCertificateInputBinding({
                participantCount: 10,
                sourceRnsPrimes: [65_537],
                targetRnsPrimes: acceptedBgvSetupQSharePrimes.slice(0, 1),
                thresholdDegree: 4,
                targetBasisHash,
                sameSecretProofFamilyBindingRoot,
                ringDegree: 32_768,
            }),
        ).toThrow(/commitment modulus limb/u);
        expect(() =>
            compactVssParameterCertificateInputBinding({
                participantCount: 10,
                sourceRnsPrimes: [65_537, 65_539, 65_543, 65_551],
                targetRnsPrimes: [acceptedBgvSetupQSharePrimes[0] + 2],
                thresholdDegree: 4,
                targetBasisHash,
                sameSecretProofFamilyBindingRoot,
                ringDegree: 32_768,
            }),
        ).toThrow(/canonical target basis prefix/u);
    });

    it('reports the current full transport reduction and compact CPU work model', () => {
        const measurement = compactVssCommitmentMeasurement({
            participantCount: 10,
            sourceRnsLimbCount: 17,
            targetRnsLimbCount: 7,
            thresholdDegree: 4,
            currentFullCoefficientTransportBytes: 1_604_341_697,
        });

        expect(measurement).toMatchObject({
            objectType: 'CompactVssCommitmentMeasurement',
            profileId: compactVssCommitmentProfileId,
            singleCompactCommitmentBytes: 384,
            fullCoefficientCommitmentBytes: 261_120,
            recipientShareCommitmentBytes: 268_800,
            aggregateThresholdCommitmentBytes: 26_880,
            totalCompactPublicCommitmentBytes: 556_800,
            largestSingleObjectBytes: 384,
            largestWasmBoundaryCopyBytes: 384,
            projectionWeight: compactVssProjectionWeight,
            cpuWorkModel: {
                residueMultiplyAddsPerCommitment: 4_608,
                totalCommitments: 1_450,
                totalResidueMultiplyAdds: 6_681_600,
                aggregatePublicSumResidueAdditions: 33_600,
                totalResidueArithmeticOperations: 6_715_200,
            },
            budgetComparison: {
                publicSetupDownloadBudgetBytes: 67_108_864,
                sourceTrusteeUploadBudgetBytes: 268_435_456,
                oneSourcePublicCommitmentUploadBytes: 52_992,
                largestSingleObjectBudgetBytes: 16_777_216,
                largestWasmBoundaryCopyBudgetBytes: 1_572_864,
            },
        });
        expect(
            measurement.cpuWorkModel.aggregatePublicSumFractionOfCommitmentWork,
        ).toBeCloseTo(33_600 / 6_681_600);
        expect(
            measurement.budgetComparison
                .totalCompactPublicCommitmentFractionOfDownloadBudget,
        ).toBeCloseTo(556_800 / 67_108_864);
        expect(
            measurement.budgetComparison
                .oneSourcePublicCommitmentUploadFractionOfBudget,
        ).toBeCloseTo(52_992 / 268_435_456);
        expect(measurement.byteReduction.reductionFactor).toBeGreaterThan(
            2_800,
        );
        expect(measurement.byteReduction.compactFractionOfCurrent).toBeLessThan(
            0.001,
        );
    });

    it('builds fresh recipient-share commitments with aggregate share parity', () => {
        const sourceTrusteeOpeningStates = [
            {
                sourceTrusteeIdentity: 'source-0',
                sourceTrusteeRosterPosition: 0,
                coefficientOpenings: [
                    {
                        rnsLimbIndex: 0,
                        rnsPrime: 65_537,
                        shamirCoefficientIndex: 0,
                        coefficientMessage: [1, 2, 3, 4],
                        randomnessByColumn: [],
                    },
                    {
                        rnsLimbIndex: 0,
                        rnsPrime: 65_537,
                        shamirCoefficientIndex: 1,
                        coefficientMessage: [10, 20, 30, 40],
                        randomnessByColumn: [],
                    },
                ],
            },
            {
                sourceTrusteeIdentity: 'source-1',
                sourceTrusteeRosterPosition: 1,
                coefficientOpenings: [
                    {
                        rnsLimbIndex: 0,
                        rnsPrime: 65_537,
                        shamirCoefficientIndex: 0,
                        coefficientMessage: [5, 6, 7, 8],
                        randomnessByColumn: [],
                    },
                    {
                        rnsLimbIndex: 0,
                        rnsPrime: 65_537,
                        shamirCoefficientIndex: 1,
                        coefficientMessage: [50, 60, 70, 80],
                        randomnessByColumn: [],
                    },
                ],
            },
        ];
        const recipientTrustees = [
            {
                trusteeIdentity: 'recipient-0',
                trusteeRosterPosition: 0,
            },
            {
                trusteeIdentity: 'recipient-1',
                trusteeRosterPosition: 1,
            },
        ];
        const coefficientCommitmentSet =
            createCompactVssCoefficientCommitmentSet({
                setupContext,
                publicMatrixSeedHash,
                participantCount: 2,
                qSharePrimes: [65_537],
                ringDegree: 4,
                thresholdDegree: 2,
                sourceTrusteeOpeningStates,
                coefficientOpeningRandomness: ({
                    trusteeRosterPosition,
                    shamirCoefficientIndex,
                    ringDegree,
                }) => [
                    Array.from(
                        { length: ringDegree },
                        (_unused, coefficientIndex) =>
                            ((trusteeRosterPosition +
                                shamirCoefficientIndex +
                                coefficientIndex) %
                                3) -
                            1,
                    ),
                    Array.from(
                        { length: ringDegree },
                        (_unused, coefficientIndex) =>
                            ((trusteeRosterPosition +
                                shamirCoefficientIndex +
                                coefficientIndex +
                                1) %
                                3) -
                            1,
                    ),
                ],
            });
        const recipientShareBundle =
            createCompactVssRecipientShareCommitmentBundle({
                setupContext,
                publicMatrixSeedHash,
                participantCount: 2,
                qSharePrimes: [65_537],
                ringDegree: 4,
                thresholdDegree: 2,
                sourceTrusteeOpeningStates,
                recipientTrustees,
                shareOpeningRandomness: ({
                    trusteeRosterPosition,
                    recipientRosterPosition,
                    ringDegree,
                }) => [
                    Array.from(
                        { length: ringDegree },
                        (_unused, coefficientIndex) =>
                            ((trusteeRosterPosition +
                                recipientRosterPosition +
                                coefficientIndex) %
                                3) -
                            1,
                    ),
                    Array.from(
                        { length: ringDegree },
                        (_unused, coefficientIndex) =>
                            ((trusteeRosterPosition +
                                recipientRosterPosition +
                                coefficientIndex +
                                1) %
                                3) -
                            1,
                    ),
                ],
            });

        expect(coefficientCommitmentSet.sourceTrusteeRecords).toHaveLength(2);
        expect(
            coefficientCommitmentSet.sourceTrusteeRecords[0]
                ?.coefficientCommitments,
        ).toHaveLength(2);
        expect(
            recipientShareBundle.recipientShareCommitmentSet
                .sourceTrusteeRecords,
        ).toHaveLength(2);
        expect(
            recipientShareBundle.recipientShareOpeningCredentials,
        ).toHaveLength(4);

        const aggregateBundle = aggregateCompactVssThresholdShareCommitments({
            setupContext,
            publicMatrixSeedHash,
            participantCount: 2,
            qSharePrimes: [65_537],
            ringDegree: 4,
            recipientTrustees,
            recipientShareOpeningCredentials:
                recipientShareBundle.recipientShareOpeningCredentials,
        });
        expect(
            verifyCompactVssRecipientShareCommitmentSet({
                recipientShareCommitmentSet:
                    recipientShareBundle.recipientShareCommitmentSet,
            }),
        ).toBe(recipientShareBundle.recipientShareCommitmentSet);
        expect(
            verifyCompactVssAggregateThresholdCommitmentSet({
                aggregateThresholdCommitmentSet:
                    aggregateBundle.aggregateThresholdCommitmentSet,
            }),
        ).toBe(aggregateBundle.aggregateThresholdCommitmentSet);
        const linkageStatement = createCompactVssShareLinkageStatement({
            setupContext,
            publicMatrixSeedHash,
            targetBasisHash: deriveProtocolHash('TargetBasisHash', {
                fixture: 'compact-vss',
                label: 'target-basis',
            }),
            coefficientCommitmentSet,
            recipientShareCommitmentSet:
                recipientShareBundle.recipientShareCommitmentSet,
            aggregateThresholdCommitmentSet:
                aggregateBundle.aggregateThresholdCommitmentSet,
        });

        expect(
            aggregateBundle.aggregateThresholdCommitmentSet.recipientRecords,
        ).toHaveLength(2);
        expect(
            aggregateBundle.aggregateThresholdOpeningCredentials,
        ).toHaveLength(2);
        expect(
            verifyCompactVssShareLinkageStatement({
                statement: linkageStatement,
                coefficientCommitmentSet,
                recipientShareCommitmentSet:
                    recipientShareBundle.recipientShareCommitmentSet,
                aggregateThresholdCommitmentSet:
                    aggregateBundle.aggregateThresholdCommitmentSet,
            }),
        ).toBe(linkageStatement);
        expect(linkageStatement).toMatchObject({
            participantCount: 2,
            targetRnsLimbCount: 1,
            thresholdDegree: 2,
            proofBatchingRule: compactVssShareLinkageProofBatchingRule,
            shamirEvaluationRule: compactVssShareLinkageShamirEvaluationRule,
            aggregateThresholdRule:
                compactVssShareLinkageAggregateThresholdRule,
            commonKeyRule: compactVssShareLinkageCommonKeyRule,
        });
        expect(linkageStatement.sourceStatementRecords).toHaveLength(2);
        expect(linkageStatement.sourceStatementRecords[0]).toMatchObject({
            objectType: 'CompactVssShareLinkageSourceStatement',
            sourceTrusteeIdentity: 'source-0',
            sourceTrusteeRosterPosition: 0,
            sourceCoefficientCommitmentRoot:
                coefficientCommitmentSet.sourceTrusteeRecords[0]
                    ?.sourceCoefficientCommitmentRoot,
            sourceRecipientShareCommitmentRoot:
                recipientShareBundle.recipientShareCommitmentSet
                    .sourceTrusteeRecords[0]
                    ?.sourceRecipientShareCommitmentRoot,
            aggregateThresholdCommitmentRoot:
                aggregateBundle.aggregateThresholdCommitmentSet
                    .aggregateThresholdCommitmentRoot,
        });
        const proofMaterialInputs: CompactVssShareLinkageProofMaterialInput[] =
            linkageStatement.sourceStatementRecords.map((sourceStatement) => {
                const proofStatementHash = deriveProtocolHash(
                    'SetupProofRecordBindingHash',
                    {
                        fixture: 'compact-vss',
                        label: 'restricted-share-linkage-proof-statement',
                        sourceTrusteeIdentity:
                            sourceStatement.sourceTrusteeIdentity,
                    },
                );

                return {
                    sourceStatementRoot: sourceStatement.sourceStatementRoot,
                    proofRecords: [
                        {
                            proofStatementHash,
                            proofStatement: { proofStatementHash },
                            proofBytesHex: 'ab'.repeat(
                                32 +
                                    sourceStatement.sourceTrusteeRosterPosition,
                            ),
                        },
                    ],
                };
            });
        const proofMaterialSet = createCompactVssShareLinkageProofMaterialSet({
            statement: linkageStatement,
            proofMaterialInputs,
        });
        expect(
            verifyCompactVssShareLinkageProofMaterialSet({
                statement: linkageStatement,
                proofMaterialSet,
            }),
        ).toBe(proofMaterialSet);
        expect(proofMaterialSet).toMatchObject({
            objectType: 'CompactVssShareLinkageProofMaterialSet',
            proofFamily: compactVssShareLinkageProofFamily,
            participantCount: 2,
            shareLinkageStatementRoot: linkageStatement.statementRoot,
        });
        expect(proofMaterialSet.proofMaterials[0]).toMatchObject({
            objectType: 'CompactVssShareLinkageProofMaterial',
            sourceTrusteeIdentity: 'source-0',
            sourceTrusteeRosterPosition: 0,
            sourceStatementRoot:
                linkageStatement.sourceStatementRecords[0]?.sourceStatementRoot,
            proofRecords: [
                {
                    objectType: 'CompactVssShareLinkageProofRecord',
                    proofByteLength: 32,
                },
            ],
        });
        const repeatedProofInputRoot =
            proofMaterialInputs[0]?.sourceStatementRoot;
        if (repeatedProofInputRoot === undefined) {
            throw new Error(
                'compact VSS fixture did not create proof material inputs.',
            );
        }
        expect(() =>
            createCompactVssShareLinkageProofMaterialSet({
                statement: linkageStatement,
                proofMaterialInputs: proofMaterialInputs.map(
                    (proofMaterialInput, proofMaterialIndex) =>
                        proofMaterialIndex === 1
                            ? {
                                  ...proofMaterialInput,
                                  sourceStatementRoot: repeatedProofInputRoot,
                              }
                            : proofMaterialInput,
                ),
            }),
        ).toThrow(/must not repeat/u);
        const proofMaterialSetWithTamperedRecordBytes =
            structuredClone(proofMaterialSet);
        const tamperedProofMaterialSetBytes =
            proofMaterialSetWithTamperedRecordBytes as unknown as MutableCompactVssProofMaterialSetBytes;
        const tamperedProofRecord =
            tamperedProofMaterialSetBytes.proofMaterials[0]?.proofRecords[0];
        if (tamperedProofRecord === undefined) {
            throw new Error(
                'compact VSS proof material fixture did not create a proof record.',
            );
        }
        tamperedProofRecord.proofBytesHex = `00${tamperedProofRecord.proofBytesHex.slice(
            2,
        )}`;
        expect(() =>
            verifyCompactVssShareLinkageProofMaterialSet({
                statement: linkageStatement,
                proofMaterialSet: proofMaterialSetWithTamperedRecordBytes,
            }),
        ).toThrow(/proofBytesHash/u);
        const rebindLinkageStatementRoot = (
            statement: typeof linkageStatement,
        ): typeof linkageStatement => {
            const { statementRoot: _statementRoot, ...statementWithoutRoot } =
                statement;

            return {
                ...statement,
                statementRoot: deriveProtocolHash(
                    'SetupProofRecordBindingHash',
                    statementWithoutRoot,
                ),
            };
        };
        const rebindSourceStatementRoot = (
            sourceStatement: (typeof linkageStatement.sourceStatementRecords)[number],
        ): (typeof linkageStatement.sourceStatementRecords)[number] => {
            const {
                sourceStatementRoot: _sourceStatementRoot,
                ...sourceStatementWithoutRoot
            } = sourceStatement;

            return {
                ...sourceStatement,
                sourceStatementRoot: deriveProtocolHash(
                    'SetupProofRecordBindingHash',
                    sourceStatementWithoutRoot,
                ),
            };
        };
        const forgedSourceRecipientRootStatement = rebindLinkageStatementRoot({
            ...linkageStatement,
            sourceStatementRecords: linkageStatement.sourceStatementRecords.map(
                (sourceStatement, sourceStatementIndex) =>
                    sourceStatementIndex === 0
                        ? rebindSourceStatementRoot({
                              ...sourceStatement,
                              sourceRecipientShareCommitmentRoot:
                                  deriveProtocolHash(
                                      'ThresholdShareCommitmentRoot',
                                      {
                                          fixture: 'compact-vss',
                                          label: 'forged-source-recipient-root',
                                      },
                                  ),
                          })
                        : sourceStatement,
            ),
        });
        expect(
            verifyCompactVssShareLinkageStatement({
                statement: forgedSourceRecipientRootStatement,
            }),
        ).toBe(forgedSourceRecipientRootStatement);
        expect(() =>
            verifyCompactVssShareLinkageStatement({
                statement: forgedSourceRecipientRootStatement,
                coefficientCommitmentSet,
                recipientShareCommitmentSet:
                    recipientShareBundle.recipientShareCommitmentSet,
                aggregateThresholdCommitmentSet:
                    aggregateBundle.aggregateThresholdCommitmentSet,
            }),
        ).toThrow(/evidence source roots/u);
        expect(() =>
            verifyCompactVssShareLinkageStatement({
                statement: {
                    ...linkageStatement,
                    recipientShareCommitmentRoot: deriveProtocolHash(
                        'ThresholdShareCommitmentRoot',
                        {
                            fixture: 'compact-vss',
                            label: 'tampered-recipient-share-root',
                        },
                    ),
                },
            }),
        ).toThrow(/linkage statement root/u);
        expect(() =>
            createCompactVssShareLinkageStatement({
                setupContext,
                publicMatrixSeedHash,
                targetBasisHash: linkageStatement.targetBasisHash,
                coefficientCommitmentSet: {
                    ...coefficientCommitmentSet,
                    coefficientCommitmentRoot: deriveProtocolHash(
                        'VssCoefficientCommitmentRoot',
                        {
                            fixture: 'compact-vss',
                            label: 'tampered-compact-coefficient-set',
                        },
                    ),
                },
                recipientShareCommitmentSet:
                    recipientShareBundle.recipientShareCommitmentSet,
                aggregateThresholdCommitmentSet:
                    aggregateBundle.aggregateThresholdCommitmentSet,
            }),
        ).toThrow(/coefficient commitment set root/u);
        const firstSourceRecipientRecord =
            recipientShareBundle.recipientShareCommitmentSet
                .sourceTrusteeRecords[0];
        const firstRecipientShareCommitment =
            firstSourceRecipientRecord?.recipientShareCommitments[0];
        if (
            firstSourceRecipientRecord === undefined ||
            firstRecipientShareCommitment === undefined
        ) {
            throw new Error(
                'compact VSS fixture did not create recipient-share commitment records.',
            );
        }
        const tamperedRecipientShareCommitmentSet = {
            ...recipientShareBundle.recipientShareCommitmentSet,
            sourceTrusteeRecords:
                recipientShareBundle.recipientShareCommitmentSet.sourceTrusteeRecords.map(
                    (sourceRecord, sourceRecordIndex) =>
                        sourceRecordIndex === 0
                            ? {
                                  ...sourceRecord,
                                  recipientShareCommitments:
                                      sourceRecord.recipientShareCommitments.map(
                                          (
                                              recipientShareCommitment,
                                              recipientShareRecordIndex,
                                          ) =>
                                              recipientShareRecordIndex === 0
                                                  ? {
                                                        ...recipientShareCommitment,
                                                        shareCommitmentRoot:
                                                            deriveProtocolHash(
                                                                'ThresholdShareCommitmentRoot',
                                                                {
                                                                    fixture:
                                                                        'compact-vss',
                                                                    label: 'tampered-recipient-share-record',
                                                                },
                                                            ),
                                                    }
                                                  : recipientShareCommitment,
                                      ),
                              }
                            : sourceRecord,
                ),
        };
        expect(() =>
            verifyCompactVssRecipientShareCommitmentSet({
                recipientShareCommitmentSet:
                    tamperedRecipientShareCommitmentSet,
            }),
        ).toThrow(/recipient-share commitment commitment canonical root/u);
        expect(() =>
            createCompactVssShareLinkageStatement({
                setupContext,
                publicMatrixSeedHash,
                targetBasisHash: linkageStatement.targetBasisHash,
                coefficientCommitmentSet,
                recipientShareCommitmentSet:
                    tamperedRecipientShareCommitmentSet,
                aggregateThresholdCommitmentSet:
                    aggregateBundle.aggregateThresholdCommitmentSet,
            }),
        ).toThrow(/recipient-share commitment commitment canonical root/u);
        const tamperedAggregateThresholdCommitmentSet = {
            ...aggregateBundle.aggregateThresholdCommitmentSet,
            recipientRecords:
                aggregateBundle.aggregateThresholdCommitmentSet.recipientRecords.map(
                    (recipientRecord, recipientRecordIndex) =>
                        recipientRecordIndex === 0
                            ? {
                                  ...recipientRecord,
                                  aggregateCommitmentRoot: deriveProtocolHash(
                                      'ThresholdShareCommitmentRoot',
                                      {
                                          fixture: 'compact-vss',
                                          label: 'tampered-aggregate-threshold-record',
                                      },
                                  ),
                              }
                            : recipientRecord,
                ),
        };
        expect(() =>
            verifyCompactVssAggregateThresholdCommitmentSet({
                aggregateThresholdCommitmentSet:
                    tamperedAggregateThresholdCommitmentSet,
            }),
        ).toThrow(/aggregate threshold commitment commitment canonical root/u);
        expect(() =>
            createCompactVssShareLinkageStatement({
                setupContext,
                publicMatrixSeedHash,
                targetBasisHash: linkageStatement.targetBasisHash,
                coefficientCommitmentSet,
                recipientShareCommitmentSet:
                    recipientShareBundle.recipientShareCommitmentSet,
                aggregateThresholdCommitmentSet:
                    tamperedAggregateThresholdCommitmentSet,
            }),
        ).toThrow(/aggregate threshold commitment commitment canonical root/u);
        const verifiedAggregateThresholdCommitmentSet: CompactVssAggregateThresholdCommitmentSet =
            verifyCompactVssAggregateThresholdCommitmentSet({
                aggregateThresholdCommitmentSet:
                    aggregateBundle.aggregateThresholdCommitmentSet,
            });
        const firstAggregateRecord =
            verifiedAggregateThresholdCommitmentSet.recipientRecords[0];
        if (firstAggregateRecord === undefined) {
            throw new Error(
                'compact VSS fixture did not create aggregate threshold records.',
            );
        }
        const tamperedAggregateCommitment =
            computeCompactVssCommitmentFromOpening(
                aggregateOpening(
                    opening('aggregate-mismatch-a', [1, 2, 3, 4], 0),
                    opening('aggregate-mismatch-b', [5, 6, 7, 8], 1),
                    1,
                ),
            ).commitment;
        const reboundAggregateRecord: CompactVssAggregateThresholdCommitmentSet['recipientRecords'][number] =
            {
                ...firstAggregateRecord,
                commitment: tamperedAggregateCommitment,
                aggregateCommitmentRoot: deriveProtocolHash(
                    'SetupCommitmentRoot',
                    tamperedAggregateCommitment,
                ),
            };
        const aggregateBodyMismatchSetWithOldRoot = {
            ...verifiedAggregateThresholdCommitmentSet,
            recipientRecords:
                verifiedAggregateThresholdCommitmentSet.recipientRecords.map(
                    (recipientRecord, recipientRecordIndex) =>
                        recipientRecordIndex === 0
                            ? reboundAggregateRecord
                            : recipientRecord,
                ),
        };
        const {
            aggregateThresholdCommitmentRoot: _oldAggregateMismatchRoot,
            ...aggregateBodyMismatchSetWithoutRoot
        } = aggregateBodyMismatchSetWithOldRoot;
        const aggregateBodyMismatchSet = {
            ...aggregateBodyMismatchSetWithoutRoot,
            aggregateThresholdCommitmentRoot: deriveProtocolHash(
                'ThresholdShareCommitmentRoot',
                aggregateBodyMismatchSetWithoutRoot,
            ),
        };
        expect(
            verifyCompactVssAggregateThresholdCommitmentSet({
                aggregateThresholdCommitmentSet: aggregateBodyMismatchSet,
            }),
        ).toBe(aggregateBodyMismatchSet);
        expect(() =>
            createCompactVssShareLinkageStatement({
                setupContext,
                publicMatrixSeedHash,
                targetBasisHash: linkageStatement.targetBasisHash,
                coefficientCommitmentSet,
                recipientShareCommitmentSet:
                    recipientShareBundle.recipientShareCommitmentSet,
                aggregateThresholdCommitmentSet: aggregateBodyMismatchSet,
            }),
        ).toThrow(/public sum of recipient-share commitments/u);
        expect(() =>
            verifyCompactVssShareLinkageStatement({
                statement: rebindLinkageStatementRoot({
                    ...linkageStatement,
                    sourceStatementRecords:
                        linkageStatement.sourceStatementRecords.map(
                            (sourceStatement, sourceStatementIndex) =>
                                sourceStatementIndex === 0
                                    ? {
                                          ...sourceStatement,
                                          sourceRecipientShareCommitmentRoot:
                                              deriveProtocolHash(
                                                  'ThresholdShareCommitmentRoot',
                                                  {
                                                      fixture: 'compact-vss',
                                                      label: 'tampered-source-recipient-root',
                                                  },
                                              ),
                                      }
                                    : sourceStatement,
                        ),
                }),
            }),
        ).toThrow(/source statement root/u);
        expect(() =>
            verifyCompactVssShareLinkageStatement({
                statement: rebindLinkageStatementRoot({
                    ...linkageStatement,
                    objectType: 'UnsupportedCompactVssStatement',
                } as unknown as typeof linkageStatement),
            }),
        ).toThrow(/objectType/u);
        expect(
            aggregateBundle.aggregateThresholdOpeningCredentials.find(
                (credential) => credential.recipientIdentity === 'recipient-0',
            )?.aggregateShareValues,
        ).toEqual([66, 88, 110, 132]);
        expect(
            aggregateBundle.aggregateThresholdOpeningCredentials.find(
                (credential) => credential.recipientIdentity === 'recipient-1',
            )?.aggregateShareValues,
        ).toEqual([126, 168, 210, 252]);

        const firstCredential =
            recipientShareBundle.recipientShareOpeningCredentials[0];
        if (firstCredential === undefined) {
            throw new Error('compact VSS fixture did not create credentials.');
        }
        const tamperedCredential = {
            ...firstCredential,
            shareValues: [0, 0, 0, 0],
        };
        expect(() =>
            aggregateCompactVssThresholdShareCommitments({
                setupContext,
                publicMatrixSeedHash,
                participantCount: 2,
                qSharePrimes: [65_537],
                ringDegree: 4,
                recipientTrustees,
                recipientShareOpeningCredentials: [
                    tamperedCredential,
                    ...recipientShareBundle.recipientShareOpeningCredentials.slice(
                        1,
                    ),
                ],
            }),
        ).toThrow(/does not match its public commitment roots/u);
    });

    it('matches compact recipient openings to private VSS share evaluation', () => {
        const participantCount = 3;
        const qSharePrimes = [101, 103];
        const ringDegree = 5;
        const thresholdDegree = 3;
        const sourceTrusteeOpeningStates =
            compactVssShadowSourceTrusteeOpeningStates({
                participantCount,
                qSharePrimes,
                ringDegree,
                thresholdDegree,
            });
        const recipientTrustees = Array.from(
            { length: participantCount },
            (_unused, trusteeRosterPosition) => ({
                trusteeIdentity: `recipient-${String(trusteeRosterPosition)}`,
                trusteeRosterPosition,
            }),
        );

        const recipientShareBundle =
            createCompactVssRecipientShareCommitmentBundle({
                setupContext,
                publicMatrixSeedHash,
                participantCount,
                qSharePrimes,
                ringDegree,
                thresholdDegree,
                sourceTrusteeOpeningStates,
                recipientTrustees,
                shareOpeningRandomness: ({
                    trusteeRosterPosition,
                    recipientRosterPosition,
                    rnsLimbIndex,
                    ringDegree: randomnessRingDegree,
                }) => [
                    Array.from(
                        { length: randomnessRingDegree },
                        (_unused, coefficientPosition) =>
                            ((trusteeRosterPosition * 2 +
                                recipientRosterPosition * 3 +
                                rnsLimbIndex +
                                coefficientPosition) %
                                5) -
                            2,
                    ),
                    Array.from(
                        { length: randomnessRingDegree },
                        (_unused, coefficientPosition) =>
                            (((trusteeRosterPosition + 1) *
                                (coefficientPosition + 1) +
                                recipientRosterPosition +
                                rnsLimbIndex * 2) %
                                7) -
                            3,
                    ),
                ],
            });
        expect(
            recipientShareBundle.recipientShareOpeningCredentials,
        ).toHaveLength(
            participantCount * participantCount * qSharePrimes.length,
        );

        sourceTrusteeOpeningStates.forEach((sourceTrusteeOpeningState) => {
            recipientTrustees.forEach((recipientTrustee) => {
                qSharePrimes.forEach((rnsPrime, rnsLimbIndex) => {
                    const credential = findRecipientShareCredential(
                        recipientShareBundle.recipientShareOpeningCredentials,
                        {
                            sourceTrusteeRosterPosition:
                                sourceTrusteeOpeningState.sourceTrusteeRosterPosition,
                            recipientRosterPosition:
                                recipientTrustee.trusteeRosterPosition,
                            rnsLimbIndex,
                        },
                    );
                    expect(credential.recipientTrusteePoint).toBe(
                        recipientTrustee.trusteeRosterPosition + 1,
                    );
                    expect(credential.rnsPrime).toBe(rnsPrime);
                    expect(credential.shareValues).toEqual(
                        expectedPrivateVssShareValues({
                            sourceTrusteeOpeningState,
                            recipientRosterPosition:
                                recipientTrustee.trusteeRosterPosition,
                            rnsLimbIndex,
                            rnsPrime,
                            ringDegree,
                            thresholdDegree,
                        }),
                    );
                });
            });
        });
        expect(
            findRecipientShareCredential(
                recipientShareBundle.recipientShareOpeningCredentials,
                {
                    sourceTrusteeRosterPosition: 2,
                    recipientRosterPosition: 2,
                    rnsLimbIndex: 1,
                },
            ).shareValues,
        ).toEqual([54, 49, 44, 39, 34]);

        const aggregateBundle = aggregateCompactVssThresholdShareCommitments({
            setupContext,
            publicMatrixSeedHash,
            participantCount,
            qSharePrimes,
            ringDegree,
            recipientTrustees,
            recipientShareOpeningCredentials:
                recipientShareBundle.recipientShareOpeningCredentials,
        });
        expect(
            aggregateBundle.aggregateThresholdOpeningCredentials,
        ).toHaveLength(participantCount * qSharePrimes.length);
        recipientTrustees.forEach((recipientTrustee) => {
            qSharePrimes.forEach((rnsPrime, rnsLimbIndex) => {
                const aggregateCredential = findAggregateThresholdCredential(
                    aggregateBundle.aggregateThresholdOpeningCredentials,
                    {
                        recipientRosterPosition:
                            recipientTrustee.trusteeRosterPosition,
                        rnsLimbIndex,
                    },
                );
                expect(aggregateCredential.recipientTrusteePoint).toBe(
                    recipientTrustee.trusteeRosterPosition + 1,
                );
                expect(aggregateCredential.rnsPrime).toBe(rnsPrime);
                const expectedAggregateShareSum = expectedAggregateVssShareSum({
                    sourceTrusteeOpeningStates,
                    recipientRosterPosition:
                        recipientTrustee.trusteeRosterPosition,
                    rnsLimbIndex,
                    rnsPrime,
                    ringDegree,
                    thresholdDegree,
                });
                expect(aggregateCredential.aggregateShareValues).toEqual(
                    expectedAggregateShareSum.aggregateShareValues,
                );
                expect(
                    aggregateCredential.aggregateCommitmentMessageValues,
                ).toEqual(
                    expectedAggregateShareSum.aggregateCommitmentMessageValues,
                );
                expect(
                    verifyCompactVssAggregateOpeningCredential({
                        credential: aggregateCredential,
                        participantCount,
                        ringDegree,
                    }),
                ).toBe(aggregateCredential);
            });
        });
        const selectedAggregateCredential = findAggregateThresholdCredential(
            aggregateBundle.aggregateThresholdOpeningCredentials,
            {
                recipientRosterPosition: 2,
                rnsLimbIndex: 1,
            },
        );
        expect(selectedAggregateCredential.aggregateShareValues).toEqual([
            78, 0, 25, 50, 75,
        ]);
        expect(
            selectedAggregateCredential.aggregateCommitmentMessageValues,
        ).toEqual([181, 103, 128, 153, 75]);
    });
});
