import { deriveProtocolHash } from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import {
    aggregateCompactVssThresholdShareCommitments,
    compactVssCommitmentMeasurement,
    compactVssMessageDigitBase,
    compactVssMessageDigitCount,
    compactVssMessageDigitTritCount,
    compactVssMatrixExpansionProfile,
    compactVssParameterCertificateInputBinding,
    compactVssCommitmentProfileId,
    compactVssCarryClaimMaskDigitCount,
    compactVssDigitClaimMaskDigitCount,
    compactVssShareLinkageAggregateThresholdRule,
    compactVssShareLinkageCommonKeyRule,
    compactVssShareLinkageProofBatchingRule,
    compactVssShareLinkageShamirEvaluationRule,
    compactVssRandomnessProjectionWeight,
    compactVssEncodedCommitmentByteLength,
    combineCompactVssCommitments,
    createCompactVssCoefficientCommitmentSet,
    createCompactVssDerivedRecipientShareCommitmentBundle,
    createCompactVssShareLinkageProofMaterialSet,
    createCompactVssRecipientShareCommitmentBundle,
    createCompactVssShareLinkageStatement,
    computeCompactVssCommitmentFromOpening,
    decodeCompactVssCommitmentBody,
    decodeCompactVssTernaryRandomnessColumnsHex,
    encodeCompactVssTernaryRandomnessColumnsHex,
    encodeCompactVssCommitmentBody,
    verifyCompactVssAggregateThresholdCommitmentSet,
    verifyCompactVssDerivedRecipientShareCommitmentSet,
    verifyCompactVssRecipientShareCommitmentSet,
    verifyCompactVssShareLinkageProofMaterialSet,
    verifyCompactVssShareLinkageStatement,
    verifyCompactVssCommitmentOpening,
    targetDecryptionAggregateMessageClaimMaskDigitCount,
    targetDecryptionSmudgingMessageClaimMaskDigitCount,
    type CompactVssAggregateThresholdCommitmentSet,
    type CompactVssCoefficientCommitmentSet,
    type CompactVssCommitmentBodyMetadata,
    type CompactVssCommitmentValue,
    type CompactVssCommitmentOpeningInput,
    type CompactVssRecipientShareCommitmentSet,
    type CompactVssRecipientShareOpeningCredential,
    type CompactVssShareLinkageProofRecordInput,
    type CompactVssShareLinkageProofStatement,
    type CompactVssShareLinkageStatement,
} from '#packages/protocol/src/setup/compact-vss-commitments.js';
import { acceptedBgvSetupQSharePrimes } from '#packages/protocol/src/setup/vss-coefficient-commitments.js';
import type { VssSourceTrusteeCoefficientOpeningState } from '#packages/protocol/src/setup/vss-coefficient-commitments.js';

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

const compactVssShareLinkageProofStatementForSource = (input: {
    readonly statement: CompactVssShareLinkageStatement;
    readonly coefficientCommitmentSet: CompactVssCoefficientCommitmentSet;
    readonly recipientShareCommitmentSet: CompactVssRecipientShareCommitmentSet;
    readonly sourceTrusteeRosterPosition: number;
}): CompactVssShareLinkageProofStatement => {
    const sourceStatement =
        input.statement.sourceStatementRecords[
            input.sourceTrusteeRosterPosition
        ];
    const coefficientSourceRecord =
        input.coefficientCommitmentSet.sourceTrusteeRecords[
            input.sourceTrusteeRosterPosition
        ];
    const recipientSourceRecord =
        input.recipientShareCommitmentSet.sourceTrusteeRecords[
            input.sourceTrusteeRosterPosition
        ];
    if (
        sourceStatement === undefined ||
        coefficientSourceRecord === undefined ||
        recipientSourceRecord === undefined
    ) {
        throw new Error(
            'compact VSS share-linkage proof fixture is missing source records.',
        );
    }

    const proofItems = Array.from(
        { length: input.statement.participantCount },
        (_unusedRecipient, recipientRosterPosition) =>
            Array.from(
                { length: input.statement.targetRnsLimbCount },
                (_unusedLimb, sourceRnsLimbIndex) => {
                    const coefficientStart =
                        sourceRnsLimbIndex * input.statement.thresholdDegree;
                    const coefficientRecords =
                        coefficientSourceRecord.coefficientCommitments.slice(
                            coefficientStart,
                            coefficientStart + input.statement.thresholdDegree,
                        );
                    const recipientRecordIndex =
                        recipientRosterPosition *
                            input.statement.targetRnsLimbCount +
                        sourceRnsLimbIndex;
                    const recipientRecord =
                        recipientSourceRecord.recipientShareCommitments[
                            recipientRecordIndex
                        ];
                    if (
                        coefficientRecords.length !==
                            input.statement.thresholdDegree ||
                        recipientRecord === undefined
                    ) {
                        throw new Error(
                            'compact VSS share-linkage proof fixture is missing linkage records.',
                        );
                    }

                    return {
                        sourceTrusteeIdentity:
                            sourceStatement.sourceTrusteeIdentity,
                        sourceTrusteeRosterPosition:
                            input.sourceTrusteeRosterPosition,
                        sourceCoefficientCommitmentRoot:
                            sourceStatement.sourceCoefficientCommitmentRoot,
                        sourceRecipientShareCommitmentRoot:
                            sourceStatement.sourceRecipientShareCommitmentRoot,
                        recipientIdentity: recipientRecord.recipientIdentity,
                        recipientRosterPosition,
                        sourceRnsLimbIndex,
                        sourceMessageModulus: recipientRecord.rnsPrime,
                        coefficientCommitmentRoots: coefficientRecords.map(
                            (record) => record.coefficientCommitmentRoot,
                        ),
                        coefficientOpeningRoots: coefficientRecords.map(
                            (record) => record.coefficientOpeningRoot,
                        ),
                        coefficientCommitments: coefficientRecords.map(
                            (record) => record.commitment,
                        ),
                        recipientShareCommitmentRoot:
                            recipientRecord.shareCommitmentRoot,
                        recipientShareOpeningRoot:
                            recipientRecord.shareOpeningRoot,
                        recipientShareCommitment: recipientRecord.commitment,
                    };
                },
            ),
    ).flat();
    const primaryProofItem = proofItems[0];
    if (primaryProofItem === undefined) {
        throw new Error(
            'compact VSS share-linkage proof fixture has no linkage items.',
        );
    }

    return {
        publicMatrixSeedHash: input.statement.publicMatrixSeedHash,
        shareLinkageStatementRoot: input.statement.statementRoot,
        ...primaryProofItem,
        additionalLinkageItems: proofItems.slice(1),
    };
};

function residue(value: bigint, modulus: number): number {
    const modulusWide = BigInt(modulus);
    const residueValue = value % modulusWide;

    return Number(
        residueValue < 0n ? residueValue + modulusWide : residueValue,
    );
}

const compactVssMessageDigitColumns = (
    messageCoefficients: readonly (number | bigint)[],
): readonly (readonly number[])[] =>
    Array.from({ length: compactVssMessageDigitCount }, (_unused, digitIndex) =>
        messageCoefficients.map((coefficient) => {
            let remaining = BigInt(coefficient);
            for (
                let skippedDigitIndex = 0;
                skippedDigitIndex < digitIndex;
                skippedDigitIndex += 1
            ) {
                remaining /= compactVssMessageDigitBase;
            }

            return Number(remaining % compactVssMessageDigitBase);
        }),
    );

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
    messageDigitColumns: compactVssMessageDigitColumns(messageCoefficients),
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
): CompactVssCommitmentOpeningInput => {
    const messageCoefficients = leftOpening.messageCoefficients.map(
        (leftCoefficient, coefficientIndex) =>
            residue(
                BigInt(leftCoefficient) +
                    BigInt(rightScalar) *
                        BigInt(
                            rightOpening.messageCoefficients[
                                coefficientIndex
                            ] ?? 0,
                        ),
                leftOpening.rnsPrime,
            ),
    );

    return {
        ...leftOpening,
        commitmentRole: 'aggregate-threshold-share',
        commitmentContext: {
            objectType: 'CompactVssAggregateThresholdShareCommitmentContext',
            objectVersion: 1,
            recipientIdentity: 'recipient-0',
        },
        messageCoefficients,
        messageDigitColumns: compactVssMessageDigitColumns(messageCoefficients),
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
    };
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

function expectedPrivateVssShareMessageValues(input: {
    readonly sourceTrusteeOpeningState: VssSourceTrusteeCoefficientOpeningState;
    readonly recipientRosterPosition: number;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly ringDegree: number;
    readonly thresholdDegree: number;
}): readonly bigint[] {
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

            return unreducedShareValue;
        },
    );
}

const expectedPrivateVssShareValues = (input: {
    readonly sourceTrusteeOpeningState: VssSourceTrusteeCoefficientOpeningState;
    readonly recipientRosterPosition: number;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly ringDegree: number;
    readonly thresholdDegree: number;
}): readonly number[] =>
    expectedPrivateVssShareMessageValues(input).map((shareValue) =>
        residue(shareValue, input.rnsPrime),
    );

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
                expectedOpeningRoot: commitment.openingRoot,
            }),
        ).toMatchObject({
            ok: true,
            operation: 'verifyCompactVssCommitmentOpening',
            commitmentRoot: commitment.commitmentRoot,
            openingRoot: commitment.openingRoot,
        });

        const tamperedMessageCoefficients = [
            4,
            ...firstOpening.messageCoefficients.slice(1),
        ];
        expect(() =>
            verifyCompactVssCommitmentOpening({
                opening: {
                    ...firstOpening,
                    messageCoefficients: tamperedMessageCoefficients,
                    messageDigitColumns: compactVssMessageDigitColumns(
                        tamperedMessageCoefficients,
                    ),
                },
                expectedCommitmentRoot: commitment.commitmentRoot,
                expectedOpeningRoot: commitment.openingRoot,
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
            messageCoverageTermsPerCoordinate: 683,
            randomnessProjectionWeight: 32,
            randomnessColumnCount: 2,
            inputColumnLabels: [
                'message:0',
                'message:1',
                'randomness:0',
                'randomness:1',
            ],
            coordinateCountPerCommitment: 48,
            messageMatrixResiduesPerCommitment: 65_536,
            randomnessMatrixResiduesPerCoordinate: 64,
            randomnessMatrixResiduesPerCommitment: 3_072,
            sampledMatrixResiduesPerCoordinate: 1_430,
            sampledRandomnessProjectionIndicesPerCoordinate: 64,
            sampledMatrixResiduesPerCommitment: 68_608,
            sampledRandomnessProjectionIndicesPerCommitment: 3_072,
            residueMultiplyAddsPerCommitment: 68_608,
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
            messageDigitColumns: compactVssMessageDigitColumns([
                1,
                ...zeroColumn.slice(1),
            ]),
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
            messageDigitColumns: compactVssMessageDigitColumns(zeroColumn),
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

    it('binds compact parameter certificate inputs and conclusion rows', () => {
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
            objectVersion: 8,
            setupProfileId: 'CollectiveBgvSetup-v1',
            profileId: compactVssCommitmentProfileId,
            participantCount: 10,
            sourceRnsLimbCount: 4,
            targetRnsLimbCount: 2,
            thresholdDegree: 4,
            ringDegree: 32_768,
            commitmentRelation: {
                relation: 'C = A_message * m + A_randomness * r mod q_c',
                outputCoordinateCount: 16,
                messageWidth: 2,
                randomnessWidth: 2,
                messageCoverageTermsPerCoordinate: 683,
                randomnessProjectionWeight: 32,
                coordinateCountPerCommitment: 48,
                inputColumnLabels: [
                    'message:0',
                    'message:1',
                    'randomness:0',
                    'randomness:1',
                ],
            },
            commonCommitmentKey: {
                messageCoverageShape: {
                    inputColumnCount: 4,
                    coordinateCountPerCommitment: 48,
                    messageCoverageTermsPerCoordinate: 683,
                    sampledMessageMatrixResiduesPerCommitment: 65_536,
                    coveredMessageCoefficientsPerMessageColumn: 32_768,
                    uncoveredMessageCoefficientsPerMessageColumn: 0,
                },
                randomnessProjectionShape: {
                    randomnessProjectionWeight: 32,
                    sampledMatrixResiduesPerCoordinate: 64,
                    sampledRandomnessProjectionIndicesPerCoordinate: 64,
                    sampledMatrixResiduesPerCommitment: 3_072,
                    sampledRandomnessProjectionIndicesPerCommitment: 3_072,
                },
            },
            messageEncoding: {
                proofRangeEncodingRule:
                    'share-linkage, same-secret bridge, and target-decryption rows bind message digit columns with masked consistency claims and verifier-side trit decoder columns',
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
            recipientShareCoefficientUpperBoundMultiplier: 1_111,
            aggregateCoefficientUpperBoundMultiplier: 11_110,
        });
        expect(binding.parameterReviewInputs).toMatchObject({
            inputVersion: 1,
            coefficientRing: {
                ringPolynomial: 'X^N+1',
                ringDegree: 32_768,
                commitmentModulusLimbs: [
                    { commitmentModulusIndex: 0, modulus: 65_537 },
                    { commitmentModulusIndex: 1, modulus: 65_539 },
                    { commitmentModulusIndex: 2, modulus: 65_543 },
                ],
            },
            messageCoordinateCoverageReview: {
                rowId: 'compact-vss-message-coordinate-coverage',
                ringDegree: 32_768,
                messageWidth: 2,
                coordinateCountPerCommitment: 48,
                messageCoverageTermsPerCoordinate: 683,
                scheduledMessageTermsPerMessageColumn: 32_784,
                unusedScheduledTermsPerMessageColumn: 16,
                sampledMessageTermsPerCommitment: 65_536,
                coveredMessageCoefficientsPerMessageColumn: 32_768,
                uncoveredMessageCoefficientsPerMessageColumn: 0,
                coverageRule:
                    'globalCoordinateIndex + coverageTermIndex * coordinateCountPerCommitment covers coefficient positions below ringDegree exactly once per message digit column',
                remainingReplacementRequirement:
                    'Target-result release still needs accepted compact setup, same-secret bridge acceptance, production smudging evidence, and final runtime evidence.',
            },
            openingWitnessRows: [
                expect.objectContaining({
                    rowId: 'compact-vss-fresh-opening-witness',
                    messageCoefficientUpperBoundMultiplier: 1_111,
                    randomnessDifferenceInfinityBound: 2,
                    witnessCoefficientCount: 131_072,
                }),
                expect.objectContaining({
                    rowId: 'compact-vss-aggregate-opening-witness',
                    messageCoefficientUpperBoundMultiplier: 11_110,
                    randomnessCoefficientInfinityBound: 10,
                    randomnessDifferenceInfinityBound: 20,
                    witnessCoefficientCount: 131_072,
                }),
            ],
            commitmentExposureRows: [
                expect.objectContaining({
                    rowId: 'compact-vss-final-public-commitment-exposure',
                    sourceCoefficientCommitments: 160,
                    recipientShareCommitments: 200,
                    aggregateThresholdCommitments: 20,
                    totalCompactCommitments: 380,
                    totalPublicCommitmentCoordinates: 18_240,
                    totalSampledMatrixResidues: 26_071_040,
                }),
            ],
            linearRelationRows: [
                expect.objectContaining({
                    rowId: 'compact-vss-recipient-share-shamir-evaluation',
                    sourceShamirScalarL1: 1_111,
                    combinedRelationTermL1: 1_112,
                }),
                expect.objectContaining({
                    rowId: 'compact-vss-aggregate-threshold-public-sum',
                    combinedRelationTermL1: 11,
                }),
                expect.objectContaining({
                    rowId: 'compact-vss-one-recipient-aggregate-from-source-coefficients',
                    oneRecipientAggregateShamirScalarL1: 11_110,
                }),
            ],
            proofExtractionRows: [
                expect.objectContaining({
                    rowId: 'compact-vss-share-linkage-proof-extraction-input',
                    proofFamily: 'compact-vss-share-linkage',
                }),
                expect.objectContaining({
                    rowId: 'compact-vss-same-secret-bridge-proof-extraction-input',
                    proofFamily: 'compact-same-secret-bridge',
                }),
                expect.objectContaining({
                    rowId: 'compact-vss-target-decryption-proof-extraction-input',
                    proofFamily: 'target-decryption-share',
                }),
            ],
            maskedClaimNormRows: [
                expect.objectContaining({
                    rowId: 'compact-vss-share-linkage-carry-claim',
                    proofFamily: 'compact-vss-share-linkage',
                    witnessInfinityBound: 1_111,
                    clearClaimBoundDecimal: (
                        1_111n *
                        32_768n *
                        ((1n << 40n) - 1n)
                    ).toString(),
                    consistencyRepetitions: 4,
                    consistencyCoefficientBits: 40,
                    maskDigitCount: compactVssCarryClaimMaskDigitCount,
                }),
                expect.objectContaining({
                    rowId: 'compact-vss-share-linkage-message-digit-claim',
                    witnessInfinityBoundDecimal: (
                        compactVssMessageDigitBase - 1n
                    ).toString(),
                    consistencyRepetitions: 4,
                    consistencyCoefficientBits: 40,
                    maskDigitCount: compactVssDigitClaimMaskDigitCount,
                }),
                expect.objectContaining({
                    rowId: 'compact-vss-same-secret-bridge-non-digit-claim',
                    proofFamily: 'compact-same-secret-bridge',
                    witnessInfinityBound: 2,
                    consistencyRepetitions: 20,
                    consistencyCoefficientBits: 8,
                    maskDigitCount: 58,
                }),
                expect.objectContaining({
                    rowId: 'compact-vss-same-secret-bridge-message-digit-claim',
                    directDigitVectorCount: 4,
                    maskDigitCount: compactVssDigitClaimMaskDigitCount,
                }),
                expect.objectContaining({
                    rowId: 'compact-vss-target-decryption-aggregate-message-claim',
                    proofFamily: 'target-decryption-share',
                    targetRnsLimbCount: 2,
                    claimVectorClass: 'aggregate-opening-message-digit',
                    messageDigitBaseDecimal:
                        compactVssMessageDigitBase.toString(),
                    messageDigitCount: compactVssMessageDigitCount,
                    witnessInfinityBoundDecimal: (
                        compactVssMessageDigitBase - 1n
                    ).toString(),
                    maskDigitCount:
                        targetDecryptionAggregateMessageClaimMaskDigitCount,
                }),
                expect.objectContaining({
                    rowId: 'compact-vss-target-decryption-smudging-message-claim',
                    smudgingMessageCoefficientBound: 33,
                    claimVectorClass: 'smudging-opening-message-digit',
                    messageDigitBaseDecimal:
                        compactVssMessageDigitBase.toString(),
                    messageDigitCount: compactVssMessageDigitCount,
                    witnessInfinityBoundDecimal: '32',
                    maskDigitCount:
                        targetDecryptionSmudgingMessageClaimMaskDigitCount,
                }),
            ],
            targetBasisReductionRows: [
                expect.objectContaining({
                    rowId: 'compact-vss-same-secret-bridge-target-reduction',
                    sourceSignedRepresentativeInfinityBound: 1,
                    targetRnsLimbCount: 2,
                    targetBasisHash,
                    sameSecretProofFamilyBindingRoot,
                }),
            ],
            structuredRingRows: [
                expect.objectContaining({
                    rowId: 'compact-vss-structured-ring-review-input',
                    cyclotomicFamily: 'power-of-two negacyclic',
                    sampledMatrixResiduesPerCommitment: 68_608,
                }),
            ],
            multiOpeningRows: [
                expect.objectContaining({
                    rowId: 'compact-vss-multi-opening-review-input',
                    totalCompactCommitments: 380,
                    maximumNonReconstructingRecipientCount: 3,
                    corruptedRecipientOpeningCredentialCount: 60,
                }),
            ],
            reviewReductionRows: [
                expect.objectContaining({
                    rowId: 'compact-vss-module-sis-binding-review-input',
                    problem: 'Module-SIS',
                    bindingRows: [
                        'compact-vss-covered-message-module-sis-binding-input',
                    ],
                    maskedClaimNormRows: [
                        'compact-vss-share-linkage-carry-claim',
                        'compact-vss-share-linkage-message-digit-claim',
                        'compact-vss-same-secret-bridge-non-digit-claim',
                        'compact-vss-same-secret-bridge-message-digit-claim',
                        'compact-vss-target-decryption-aggregate-message-claim',
                        'compact-vss-target-decryption-smudging-message-claim',
                    ],
                }),
                expect.objectContaining({
                    rowId: 'compact-vss-module-lwe-hiding-review-input',
                    problem: 'Module-LWE',
                    hidingRows: [
                        'compact-vss-covered-message-module-lwe-hiding-input',
                    ],
                    sampledRandomnessProjectionIndicesPerCommitment: 3_072,
                }),
            ],
            moduleSisBindingRows: [
                expect.objectContaining({
                    rowId: 'compact-vss-covered-message-module-sis-binding-input',
                    messageDigitBaseDecimal:
                        compactVssMessageDigitBase.toString(),
                    messageDigitCount: compactVssMessageDigitCount,
                    messageDigitTritCount: compactVssMessageDigitTritCount,
                    messageDigitDifferenceInfinityBoundDecimal: (
                        compactVssMessageDigitBase - 1n
                    ).toString(),
                    aggregateRandomnessDifferenceInfinityBound: 20,
                    sampledMatrixResiduesPerCommitment: 68_608,
                    estimatorSmallnessPrecondition: {
                        smallestCommitmentModulus: 65_537,
                        strictDifferenceUpperBoundDecimal: '32768',
                        messageDigitDifferenceInfinityBoundDecimal: (
                            compactVssMessageDigitBase - 1n
                        ).toString(),
                        marginDecimal: '-129107394',
                    },
                }),
            ],
            moduleLweHidingRows: [
                expect.objectContaining({
                    rowId: 'compact-vss-covered-message-module-lwe-hiding-input',
                    totalPublicCommitmentCoordinates: 18_240,
                    totalSampledRandomnessProjectionIndices: 1_167_360,
                    maximumNonReconstructingRecipientCount: 3,
                    corruptedRecipientOpeningCredentialCount: 60,
                }),
            ],
            certificateConclusionRows: [
                expect.objectContaining({
                    rowId: 'compact-vss-covered-message-module-sis-binding-conclusion',
                    problem: 'Module-SIS',
                    sourceInputRows: [
                        'compact-vss-covered-message-module-sis-binding-input',
                        'compact-vss-message-coordinate-coverage',
                        'compact-vss-fresh-opening-witness',
                        'compact-vss-aggregate-opening-witness',
                        'compact-vss-share-linkage-proof-extraction-input',
                        'compact-vss-same-secret-bridge-proof-extraction-input',
                        'compact-vss-target-decryption-proof-extraction-input',
                        'compact-vss-multi-opening-review-input',
                    ],
                    witnessDifferenceInfinityBoundDecimal: (
                        compactVssMessageDigitBase - 1n
                    ).toString(),
                    estimatorPrecondition: {
                        source: 'malb/lattice-estimator SIS lattice row requires length_bound < (q - 1) / 2',
                        smallestCommitmentModulus: 65_537,
                        strictDifferenceUpperBoundDecimal: '32768',
                        witnessDifferenceInfinityBoundDecimal: (
                            compactVssMessageDigitBase - 1n
                        ).toString(),
                        marginDecimal: '-129107394',
                    },
                }),
                expect.objectContaining({
                    rowId: 'compact-vss-covered-message-module-lwe-hiding-conclusion',
                    problem: 'Module-LWE',
                    publicSampleRows: {
                        totalCompactCommitments: 380,
                        totalPublicCommitmentCoordinates: 18_240,
                        sampledRandomnessProjectionIndicesPerCommitment: 3_072,
                        totalSampledRandomnessProjectionIndices: 1_167_360,
                    },
                    corruptedRecipientOpeningCredentialCount: 60,
                }),
                expect.objectContaining({
                    rowId: 'compact-vss-structured-ring-review-conclusion',
                    ringDegree: 32_768,
                }),
                expect.objectContaining({
                    rowId: 'compact-vss-multi-opening-review-conclusion',
                    totalCompactCommitments: 380,
                    corruptedRecipientOpeningCredentialCount: 60,
                }),
            ],
        });
        expect(binding.estimatorInputRows).toEqual([
            expect.objectContaining({
                rowId: 'compact-vss-module-sis-binding-input',
                problem: 'Module-SIS',
                outputCoordinateCount: 16,
                messageCoverageTermsPerCoordinate: 683,
                randomnessProjectionWeight: 32,
                sampledMatrixResiduesPerCommitment: 68_608,
                sampledRandomnessProjectionIndicesPerCommitment: 3_072,
            }),
            expect.objectContaining({
                rowId: 'compact-vss-module-lwe-hiding-input',
                problem: 'Module-LWE',
                outputCoordinateCount: 16,
                messageCoverageTermsPerCoordinate: 683,
                randomnessProjectionWeight: 32,
                sampledMatrixResiduesPerCommitment: 68_608,
                sampledRandomnessProjectionIndicesPerCommitment: 3_072,
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
            targetRnsLimbCount: 5,
            thresholdDegree: 4,
            currentFullCoefficientTransportBytes: 1_604_341_697,
        });

        expect(measurement).toMatchObject({
            objectType: 'CompactVssCommitmentMeasurement',
            profileId: compactVssCommitmentProfileId,
            singleCompactCommitmentBytes: 384,
            fullCoefficientCommitmentBytes: 261_120,
            recipientShareCommitmentBytes: 192_000,
            aggregateThresholdCommitmentBytes: 19_200,
            totalCompactPublicCommitmentBytes: 472_320,
            largestSingleObjectBytes: 384,
            largestWasmBoundaryCopyBytes: 384,
            messageCoverageTermsPerCoordinate: 683,
            randomnessProjectionWeight: compactVssRandomnessProjectionWeight,
            cpuWorkModel: {
                residueMultiplyAddsPerCommitment: 68_608,
                messageResidueMultiplyAddsPerCommitment: 65_536,
                randomnessResidueMultiplyAddsPerCommitment: 3_072,
                totalCommitments: 1_230,
                totalResidueMultiplyAdds: 84_387_840,
                aggregatePublicSumResidueAdditions: 24_000,
                totalResidueArithmeticOperations: 84_411_840,
            },
            budgetComparison: {
                publicSetupDownloadBudgetBytes: 67_108_864,
                sourceTrusteeUploadBudgetBytes: 268_435_456,
                oneSourcePublicCommitmentUploadBytes: 45_312,
                largestSingleObjectBudgetBytes: 16_777_216,
                largestWasmBoundaryCopyBudgetBytes: 1_572_864,
            },
        });
        expect(
            measurement.cpuWorkModel.aggregatePublicSumFractionOfCommitmentWork,
        ).toBeCloseTo(24_000 / 84_387_840);
        expect(
            measurement.budgetComparison
                .totalCompactPublicCommitmentFractionOfDownloadBudget,
        ).toBeCloseTo(472_320 / 67_108_864);
        expect(
            measurement.budgetComparison
                .oneSourcePublicCommitmentUploadFractionOfBudget,
        ).toBeCloseTo(45_312 / 268_435_456);
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
        const coefficientOpeningRandomness = ({
            trusteeRosterPosition,
            shamirCoefficientIndex,
            ringDegree,
        }: {
            readonly trusteeRosterPosition: number;
            readonly shamirCoefficientIndex: number;
            readonly ringDegree: number;
        }): readonly (readonly number[])[] => [
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
                coefficientOpeningRandomness,
            });
        const recipientShareBundle =
            createCompactVssRecipientShareCommitmentBundle({
                setupContext,
                publicMatrixSeedHash,
                participantCount: 2,
                qSharePrimes: [65_537],
                ringDegree: 4,
                thresholdDegree: 2,
                coefficientCommitmentSet,
                sourceTrusteeOpeningStates,
                recipientTrustees,
                coefficientOpeningRandomness,
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
        const proofRecordInputs: CompactVssShareLinkageProofRecordInput[] =
            linkageStatement.sourceStatementRecords.map(
                (_sourceStatement, sourceTrusteeRosterPosition) => ({
                    compactVssShareLinkage:
                        compactVssShareLinkageProofStatementForSource({
                            statement: linkageStatement,
                            coefficientCommitmentSet,
                            recipientShareCommitmentSet:
                                recipientShareBundle.recipientShareCommitmentSet,
                            sourceTrusteeRosterPosition,
                        }),
                    proofBytesHex: 'ab'.repeat(sourceTrusteeRosterPosition + 1),
                }),
            );
        const proofMaterialSet = createCompactVssShareLinkageProofMaterialSet({
            statement: linkageStatement,
            coefficientCommitmentSet,
            recipientShareCommitmentSet:
                recipientShareBundle.recipientShareCommitmentSet,
            aggregateThresholdCommitmentSet:
                aggregateBundle.aggregateThresholdCommitmentSet,
            ringDegree: 4,
            proofRecordInputs,
        });
        expect(proofMaterialSet.proofRecords).toHaveLength(2);
        expect(proofMaterialSet.proofRecords[0]?.linkageItems).toHaveLength(2);
        expect(
            verifyCompactVssShareLinkageProofMaterialSet({
                statement: linkageStatement,
                coefficientCommitmentSet,
                recipientShareCommitmentSet:
                    recipientShareBundle.recipientShareCommitmentSet,
                aggregateThresholdCommitmentSet:
                    aggregateBundle.aggregateThresholdCommitmentSet,
                proofMaterialSet,
            }),
        ).toBe(proofMaterialSet);
        expect(() =>
            createCompactVssShareLinkageProofMaterialSet({
                statement: linkageStatement,
                coefficientCommitmentSet,
                recipientShareCommitmentSet:
                    recipientShareBundle.recipientShareCommitmentSet,
                aggregateThresholdCommitmentSet:
                    aggregateBundle.aggregateThresholdCommitmentSet,
                ringDegree: 4,
                proofRecordInputs: proofRecordInputs.slice(0, 1),
            }),
        ).toThrow(/cover every source, recipient, and target limb/u);
        expect(() =>
            verifyCompactVssShareLinkageProofMaterialSet({
                statement: linkageStatement,
                coefficientCommitmentSet,
                recipientShareCommitmentSet:
                    recipientShareBundle.recipientShareCommitmentSet,
                aggregateThresholdCommitmentSet:
                    aggregateBundle.aggregateThresholdCommitmentSet,
                proofMaterialSet: {
                    ...proofMaterialSet,
                    proofRecords: proofMaterialSet.proofRecords.map(
                        (proofRecord, proofRecordIndex) =>
                            proofRecordIndex === 0
                                ? {
                                      ...proofRecord,
                                      proofBytesBase64: 'AA==',
                                  }
                                : proofRecord,
                    ),
                },
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
        expect(() =>
            verifyCompactVssShareLinkageStatement({
                statement: forgedSourceRecipientRootStatement,
            } as unknown as Parameters<
                typeof verifyCompactVssShareLinkageStatement
            >[0]),
        ).toThrow(/requires coefficient, recipient-share, and aggregate/u);
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
        const forgedOpeningRootStatement = rebindLinkageStatementRoot({
            ...linkageStatement,
            sourceStatementRecords: linkageStatement.sourceStatementRecords.map(
                (sourceStatement, sourceStatementIndex) =>
                    sourceStatementIndex === 0
                        ? rebindSourceStatementRoot({
                              ...sourceStatement,
                              coefficientOpeningRoots: [
                                  deriveProtocolHash(
                                      'SetupProofRecordBindingHash',
                                      {
                                          fixture: 'compact-vss',
                                          label: 'forged-coefficient-opening-root',
                                      },
                                  ),
                                  ...sourceStatement.coefficientOpeningRoots.slice(
                                      1,
                                  ),
                              ],
                          })
                        : sourceStatement,
            ),
        });
        expect(() =>
            verifyCompactVssShareLinkageStatement({
                statement: forgedOpeningRootStatement,
            } as unknown as Parameters<
                typeof verifyCompactVssShareLinkageStatement
            >[0]),
        ).toThrow(/requires coefficient, recipient-share, and aggregate/u);
        expect(() =>
            verifyCompactVssShareLinkageStatement({
                statement: forgedOpeningRootStatement,
                coefficientCommitmentSet,
                recipientShareCommitmentSet:
                    recipientShareBundle.recipientShareCommitmentSet,
                aggregateThresholdCommitmentSet:
                    aggregateBundle.aggregateThresholdCommitmentSet,
            }),
        ).toThrow(/evidence opening roots/u);
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
                coefficientCommitmentSet,
                recipientShareCommitmentSet:
                    recipientShareBundle.recipientShareCommitmentSet,
                aggregateThresholdCommitmentSet:
                    aggregateBundle.aggregateThresholdCommitmentSet,
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
                coefficientCommitmentSet,
                recipientShareCommitmentSet:
                    recipientShareBundle.recipientShareCommitmentSet,
                aggregateThresholdCommitmentSet:
                    aggregateBundle.aggregateThresholdCommitmentSet,
            }),
        ).toThrow(/source statement root/u);
        expect(() =>
            verifyCompactVssShareLinkageStatement({
                statement: rebindLinkageStatementRoot({
                    ...linkageStatement,
                    objectType: 'UnsupportedCompactVssStatement',
                } as unknown as typeof linkageStatement),
                coefficientCommitmentSet,
                recipientShareCommitmentSet:
                    recipientShareBundle.recipientShareCommitmentSet,
                aggregateThresholdCommitmentSet:
                    aggregateBundle.aggregateThresholdCommitmentSet,
            }),
        ).toThrow(/objectType/u);
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
        const coefficientOpeningRandomness = ({
            trusteeRosterPosition,
            shamirCoefficientIndex,
            rnsLimbIndex,
            ringDegree: randomnessRingDegree,
        }: {
            readonly trusteeRosterPosition: number;
            readonly shamirCoefficientIndex: number;
            readonly rnsLimbIndex: number;
            readonly ringDegree: number;
        }): readonly (readonly number[])[] => [
            Array.from(
                { length: randomnessRingDegree },
                (_unused, coefficientPosition) =>
                    ((trusteeRosterPosition * 2 +
                        shamirCoefficientIndex * 3 +
                        rnsLimbIndex +
                        coefficientPosition) %
                        5) -
                    2,
            ),
            Array.from(
                { length: randomnessRingDegree },
                (_unused, coefficientPosition) =>
                    (((trusteeRosterPosition + 1) * (coefficientPosition + 1) +
                        shamirCoefficientIndex +
                        rnsLimbIndex * 2) %
                        7) -
                    3,
            ),
        ];
        const coefficientCommitmentSet =
            createCompactVssCoefficientCommitmentSet({
                setupContext,
                publicMatrixSeedHash,
                participantCount,
                qSharePrimes,
                ringDegree,
                thresholdDegree,
                sourceTrusteeOpeningStates,
                coefficientOpeningRandomness,
            });

        const recipientShareBundle =
            createCompactVssRecipientShareCommitmentBundle({
                setupContext,
                publicMatrixSeedHash,
                participantCount,
                qSharePrimes,
                ringDegree,
                thresholdDegree,
                coefficientCommitmentSet,
                sourceTrusteeOpeningStates,
                recipientTrustees,
                coefficientOpeningRandomness,
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
            aggregateBundle.aggregateThresholdCommitmentSet.recipientRecords,
        ).toHaveLength(participantCount * qSharePrimes.length);
        recipientTrustees.forEach((recipientTrustee) => {
            qSharePrimes.forEach((rnsPrime, rnsLimbIndex) => {
                const aggregateRecord =
                    aggregateBundle.aggregateThresholdCommitmentSet.recipientRecords.find(
                        (record) =>
                            record.recipientRosterPosition ===
                                recipientTrustee.trusteeRosterPosition &&
                            record.rnsLimbIndex === rnsLimbIndex,
                    );
                if (aggregateRecord === undefined) {
                    throw new Error(
                        'compact VSS test fixture is missing an aggregate threshold record.',
                    );
                }
                expect(aggregateRecord.recipientTrusteePoint).toBe(
                    recipientTrustee.trusteeRosterPosition + 1,
                );
                expect(aggregateRecord.rnsPrime).toBe(rnsPrime);
            });
        });
    });

    it('derives recipient-share commitments from coefficient commitments with carried digit columns', () => {
        const participantCount = 3;
        const qSharePrimes = [1_000_000_007, 1_000_000_009];
        const derivedRnsLimbCount = 1;
        const targetQSharePrimes = qSharePrimes.slice(0, derivedRnsLimbCount);
        const ringDegree = 3;
        const thresholdDegree = 3;
        const sourceTrusteeOpeningStates = Array.from(
            { length: participantCount },
            (_unusedSource, sourceTrusteeRosterPosition) => ({
                sourceTrusteeIdentity: `source-${String(sourceTrusteeRosterPosition)}`,
                sourceTrusteeRosterPosition,
                coefficientOpenings: qSharePrimes.flatMap(
                    (rnsPrime, rnsLimbIndex) =>
                        Array.from(
                            { length: thresholdDegree },
                            (_unusedCoefficient, shamirCoefficientIndex) => ({
                                rnsLimbIndex,
                                rnsPrime,
                                shamirCoefficientIndex,
                                coefficientMessage: Array.from(
                                    { length: ringDegree },
                                    (_unused, coefficientPosition) =>
                                        residue(
                                            BigInt(880_000_000) +
                                                BigInt(
                                                    sourceTrusteeRosterPosition *
                                                        37_000_000 +
                                                        shamirCoefficientIndex *
                                                            41_000_000 +
                                                        coefficientPosition *
                                                            17_000_000,
                                                ),
                                            rnsPrime,
                                        ),
                                ),
                                randomnessByColumn: [],
                            }),
                        ),
                ),
            }),
        );
        const recipientTrustees = Array.from(
            { length: participantCount },
            (_unused, trusteeRosterPosition) => ({
                trusteeIdentity: `recipient-${String(trusteeRosterPosition)}`,
                trusteeRosterPosition,
            }),
        );
        const coefficientOpeningRandomness = ({
            trusteeRosterPosition,
            shamirCoefficientIndex,
            ringDegree: randomnessRingDegree,
        }: {
            readonly trusteeRosterPosition: number;
            readonly shamirCoefficientIndex: number;
            readonly ringDegree: number;
        }): readonly (readonly number[])[] => [
            Array.from(
                { length: randomnessRingDegree },
                (_unused, coefficientPosition) =>
                    ((trusteeRosterPosition +
                        shamirCoefficientIndex +
                        coefficientPosition) %
                        3) -
                    1,
            ),
            Array.from(
                { length: randomnessRingDegree },
                (_unused, coefficientPosition) =>
                    ((trusteeRosterPosition * 2 +
                        shamirCoefficientIndex +
                        coefficientPosition) %
                        3) -
                    1,
            ),
        ];
        const coefficientCommitmentSet =
            createCompactVssCoefficientCommitmentSet({
                setupContext,
                publicMatrixSeedHash,
                participantCount,
                qSharePrimes,
                ringDegree,
                thresholdDegree,
                sourceTrusteeOpeningStates,
                coefficientOpeningRandomness,
            });
        const derivedRecipientShareBundle =
            createCompactVssDerivedRecipientShareCommitmentBundle({
                setupContext,
                publicMatrixSeedHash,
                participantCount,
                qSharePrimes,
                derivedRnsLimbCount,
                ringDegree,
                thresholdDegree,
                coefficientCommitmentSet,
                sourceTrusteeOpeningStates,
                recipientTrustees,
                coefficientOpeningRandomness,
            });

        expect(
            verifyCompactVssRecipientShareCommitmentSet({
                recipientShareCommitmentSet:
                    derivedRecipientShareBundle.recipientShareCommitmentSet,
            }),
        ).toBe(derivedRecipientShareBundle.recipientShareCommitmentSet);
        expect(
            verifyCompactVssDerivedRecipientShareCommitmentSet({
                setupContext,
                coefficientCommitmentSet,
                recipientShareCommitmentSet:
                    derivedRecipientShareBundle.recipientShareCommitmentSet,
                derivedRnsLimbCount,
            }),
        ).toBe(derivedRecipientShareBundle.recipientShareCommitmentSet);
        expect(
            derivedRecipientShareBundle.recipientShareCommitmentSet
                .rnsLimbCount,
        ).toBe(derivedRnsLimbCount);
        const freshRecipientShareBundle =
            createCompactVssRecipientShareCommitmentBundle({
                setupContext,
                publicMatrixSeedHash,
                participantCount,
                qSharePrimes,
                ringDegree,
                thresholdDegree,
                coefficientCommitmentSet,
                sourceTrusteeOpeningStates,
                recipientTrustees,
                coefficientOpeningRandomness,
            });
        expect(() =>
            verifyCompactVssDerivedRecipientShareCommitmentSet({
                setupContext,
                coefficientCommitmentSet,
                recipientShareCommitmentSet:
                    freshRecipientShareBundle.recipientShareCommitmentSet,
            }),
        ).toThrow(/derived recipient-share commitment/u);
        const selectedSourceTrusteeOpeningState = sourceTrusteeOpeningStates[2];
        if (selectedSourceTrusteeOpeningState === undefined) {
            throw new Error('compact VSS test fixture is missing source 2.');
        }
        const selectedCredential = findRecipientShareCredential(
            derivedRecipientShareBundle.recipientShareOpeningCredentials,
            {
                sourceTrusteeRosterPosition: 2,
                recipientRosterPosition: 2,
                rnsLimbIndex: 0,
            },
        );
        const selectedMessageValues = expectedPrivateVssShareMessageValues({
            sourceTrusteeOpeningState: selectedSourceTrusteeOpeningState,
            recipientRosterPosition: 2,
            rnsLimbIndex: 0,
            rnsPrime: qSharePrimes[0] ?? 1_000_000_007,
            ringDegree,
            thresholdDegree,
        });
        expect(selectedCredential.shareValues).toEqual(
            selectedMessageValues.map((value) =>
                residue(value, qSharePrimes[0] ?? 1_000_000_007),
            ),
        );
        expect(selectedCredential.shareCommitmentMessageCarryValues).toEqual(
            selectedMessageValues.map((value, valueIndex) =>
                Number(
                    (value -
                        BigInt(
                            selectedCredential.shareValues[valueIndex] ?? 0,
                        )) /
                        BigInt(qSharePrimes[0] ?? 1_000_000_007),
                ),
            ),
        );
        expect(
            selectedCredential.shareCommitmentMessageDigitColumns?.[0]?.some(
                (value) => BigInt(value) > compactVssMessageDigitBase,
            ),
        ).toBe(true);

        const selectedCommitmentRecord =
            derivedRecipientShareBundle.recipientShareCommitmentSet
                .sourceTrusteeRecords[2]?.recipientShareCommitments[2];
        if (selectedCommitmentRecord === undefined) {
            throw new Error(
                'compact VSS test fixture is missing the selected derived commitment.',
            );
        }
        const derivedRecipientShareContext = {
            objectType: 'CompactVssDerivedRecipientShareCommitmentContext',
            objectVersion: 1,
            ...setupContext,
            sourceTrusteeIdentity: 'source-2',
            sourceTrusteeRosterPosition: 2,
            recipientIdentity: 'recipient-2',
            recipientRosterPosition: 2,
            rnsLimbIndex: 0,
            rnsPrime: qSharePrimes[0] ?? 1_000_000_007,
        };
        const selectedMessageDigitColumns =
            selectedCredential.shareCommitmentMessageDigitColumns;
        if (selectedMessageDigitColumns === undefined) {
            throw new Error(
                'compact VSS derived recipient-share fixture is missing message digit columns.',
            );
        }
        const selectedOpening = {
            commitmentRole: 'recipient-share',
            commitmentContext: derivedRecipientShareContext,
            publicMatrixSeedHash,
            rnsLimbIndex: 0,
            rnsPrime: qSharePrimes[0] ?? 1_000_000_007,
            ringDegree,
            messageCoefficients: selectedMessageValues,
            messageDigitColumns: selectedMessageDigitColumns,
            messageCoefficientBound:
                compactVssMessageDigitBase * compactVssMessageDigitBase,
            randomnessByColumn: selectedCredential.randomnessByColumn,
        } satisfies CompactVssCommitmentOpeningInput;
        expect(
            verifyCompactVssCommitmentOpening({
                opening: selectedOpening,
                expectedCommitmentRoot: selectedCredential.shareCommitmentRoot,
                expectedOpeningRoot: selectedCredential.shareOpeningRoot,
            }).commitmentRoot,
        ).toBe(selectedCredential.shareCommitmentRoot);

        const coefficientCommitments =
            coefficientCommitmentSet.sourceTrusteeRecords[2]?.coefficientCommitments.filter(
                (record) => record.rnsLimbIndex === 0,
            ) ?? [];
        const combinedDerivedCommitment = combineCompactVssCommitments({
            commitmentRole: 'recipient-share',
            commitmentContext: derivedRecipientShareContext,
            terms: coefficientCommitments.map(
                (coefficientCommitment, coefficientIndex) => ({
                    commitment: coefficientCommitment.commitment,
                    scalar: 3 ** coefficientIndex,
                }),
            ),
        });
        expect(combinedDerivedCommitment.commitmentRoot).toBe(
            selectedCredential.shareCommitmentRoot,
        );
        expect(selectedCommitmentRecord.shareCommitmentRoot).toBe(
            selectedCredential.shareCommitmentRoot,
        );

        const aggregateBundle = aggregateCompactVssThresholdShareCommitments({
            setupContext,
            publicMatrixSeedHash,
            participantCount,
            qSharePrimes: targetQSharePrimes,
            ringDegree,
            recipientTrustees,
            recipientShareOpeningCredentials:
                derivedRecipientShareBundle.recipientShareOpeningCredentials,
        });
        expect(
            verifyCompactVssAggregateThresholdCommitmentSet({
                aggregateThresholdCommitmentSet:
                    aggregateBundle.aggregateThresholdCommitmentSet,
            }),
        ).toBe(aggregateBundle.aggregateThresholdCommitmentSet);
        expect(
            aggregateBundle.aggregateThresholdCommitmentSet.recipientRecords,
        ).toHaveLength(participantCount * derivedRnsLimbCount);

        const targetBasisHash = deriveProtocolHash('TargetBasisHash', {
            fixture: 'compact-vss',
            label: 'target-prefix-derived-recipient-shares',
        });
        const linkageStatement = createCompactVssShareLinkageStatement({
            setupContext,
            publicMatrixSeedHash,
            targetBasisHash,
            coefficientCommitmentSet,
            recipientShareCommitmentSet:
                derivedRecipientShareBundle.recipientShareCommitmentSet,
            aggregateThresholdCommitmentSet:
                aggregateBundle.aggregateThresholdCommitmentSet,
        });
        expect(linkageStatement.targetRnsLimbCount).toBe(derivedRnsLimbCount);
        linkageStatement.sourceStatementRecords.forEach(
            (sourceStatementRecord) => {
                expect(
                    sourceStatementRecord.coefficientOpeningRoots,
                ).toHaveLength(thresholdDegree * derivedRnsLimbCount);
                expect(
                    sourceStatementRecord.recipientShareOpeningRoots,
                ).toHaveLength(participantCount * derivedRnsLimbCount);
            },
        );
        expect(
            verifyCompactVssShareLinkageStatement({
                statement: linkageStatement,
                coefficientCommitmentSet,
                recipientShareCommitmentSet:
                    derivedRecipientShareBundle.recipientShareCommitmentSet,
                aggregateThresholdCommitmentSet:
                    aggregateBundle.aggregateThresholdCommitmentSet,
            }),
        ).toBe(linkageStatement);

        const tamperedDigitColumns =
            selectedCredential.shareCommitmentMessageDigitColumns?.map(
                (column, digitIndex) =>
                    digitIndex === 0
                        ? [BigInt(column[0] ?? 0) + 1n, ...column.slice(1)]
                        : column,
            );
        if (tamperedDigitColumns === undefined) {
            throw new Error(
                'compact VSS test fixture did not produce derived digit columns.',
            );
        }
        expect(() =>
            aggregateCompactVssThresholdShareCommitments({
                setupContext,
                publicMatrixSeedHash,
                participantCount,
                qSharePrimes: targetQSharePrimes,
                ringDegree,
                recipientTrustees,
                recipientShareOpeningCredentials:
                    derivedRecipientShareBundle.recipientShareOpeningCredentials.map(
                        (credential) =>
                            credential === selectedCredential
                                ? {
                                      ...credential,
                                      shareCommitmentMessageDigitColumns:
                                          tamperedDigitColumns,
                                  }
                                : credential,
                    ),
            }),
        ).toThrow(/message digit columns/u);
    });
});
