import { deriveProtocolHash } from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import {
    aggregateCompactVssThresholdShareCommitments,
    compactVssCommitmentMeasurement,
    compactVssMatrixExpansionProfile,
    compactVssParameterCertificateInputBinding,
    compactVssPrivateWitnessPayloadMeasurement,
    compactVssCommitmentProfileId,
    compactVssShareLinkageAggregateThresholdRule,
    compactVssShareLinkageCommonKeyRule,
    compactVssShareLinkageProofBatchingRule,
    compactVssShareLinkageRecipientApprovalBoundary,
    compactVssShareLinkageShamirEvaluationRule,
    compactVssProjectionWeight,
    compactVssEncodedCommitmentByteLength,
    combineCompactVssCommitments,
    createCompactVssCoefficientCommitmentSet,
    createCompactVssRecipientShareCommitmentBundle,
    createCompactVssShareLinkageStatement,
    computeCompactVssCommitmentFromOpening,
    verifyCompactVssAggregateThresholdCommitmentSet,
    verifyCompactVssRecipientShareCommitmentSet,
    verifyCompactVssShareLinkageStatement,
    verifyCompactVssCommitmentOpening,
    type CompactVssCommitmentOpeningInput,
} from '#packages/protocol/src/setup/compact-vss-commitments.js';

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
            combinedMessageVectorHash512:
                directAggregateCommitment.commitment.messageVectorHash512,
            combinedOpeningRandomnessHash512:
                directAggregateCommitment.commitment.openingRandomnessHash512,
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
            targetRnsPrimes: [65_537, 65_539],
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
            developmentScope:
                'development-only-not-certified-for-production-use',
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
                inputColumnLabels: ['message', 'randomness:0', 'randomness:1'],
            },
            sameSecretBridgeInput: {
                targetBasisHash,
                targetRnsPrimes: [65_537, 65_539],
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
            'proofExtractedOpeningNorm',
            'targetDecryptionOpeningNorm',
            'targetDecryptionRecombinationCoefficientAmplification',
        ]);
        expect(binding.normInputClasses[0]).toMatchObject({
            maximumRecipientTrusteePoint: 10,
            shamirCoefficientCount: 4,
            maximumOneSourceShamirScalarL1: 1_111,
            oneRecipientAggregateShamirScalarL1: 11_110,
        });
        expect(binding.proofCoverageInputs).toMatchObject({
            sameSecretBridgeProof:
                'target-basis compact constant coefficient commitments must bind to the same signed ternary trustee secret as data-basis setup proof roots',
            targetDecryptionProof:
                'recipient-owned restored compact aggregate opening material must generate the target-bound decryption share proof without dealer state',
            recombination:
                'target result acceptance requires denominator-cleared Lagrange recombination and decoding-margin verification',
        });

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
                targetRnsPrimes: [65_537],
                thresholdDegree: 4,
                targetBasisHash,
                sameSecretProofFamilyBindingRoot,
                ringDegree: 32_768,
            }),
        ).toThrow(/commitment modulus limb/u);
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
            byteAccountingScope:
                'compact public commitment bodies only: source coefficient commitments, source-to-recipient share commitments, and recipient aggregate-threshold commitments',
            measuredPublicCommitmentRoles: [
                'source coefficient commitments',
                'source-to-recipient share commitments',
                'recipient aggregate-threshold commitments',
            ],
            largestSingleObjectBytes: 384,
            largestWasmBoundaryCopyBytes: 384,
            projectionWeight: compactVssProjectionWeight,
            cpuWorkModel: {
                residueMultiplyAddsPerCommitment: 4_608,
                totalCommitments: 1_450,
                totalResidueMultiplyAdds: 6_681_600,
            },
        });
        expect(measurement.byteReduction.reductionFactor).toBeGreaterThan(
            2_800,
        );
        expect(measurement.byteReduction.compactFractionOfCurrent).toBeLessThan(
            0.001,
        );
        expect(measurement.excludedByteCategories).toEqual(
            expect.arrayContaining([
                'public share-linkage zero-knowledge proof bytes',
                'compact same-secret bridge proof bytes',
                'private mailbox share and opening-credential bytes',
                'target-decryption proof bytes, production smudging proof bytes, and recombination proof material',
            ]),
        );
    });

    it('reports compact private opening payload bytes separately from public setup bytes', () => {
        const measurement = compactVssPrivateWitnessPayloadMeasurement({
            participantCount: 10,
            targetRnsLimbCount: 7,
        });

        expect(measurement).toMatchObject({
            objectType: 'CompactVssPrivateWitnessPayloadMeasurement',
            profileId: compactVssCommitmentProfileId,
            oneSourceRecipientCredentialPayloadBytes: 786_432,
            oneRecipientPrivateMailboxCredentialPayloadBytes: 55_050_240,
            oneRecipientPersistentAggregateCredentialPayloadBytes: 5_505_024,
            allRecipientsPrivateMailboxCredentialPayloadBytes: 550_502_400,
            allRecipientsPersistentAggregateCredentialPayloadBytes: 55_050_240,
            largestSingleCredentialPayloadBytes: 786_432,
        });
        expect(measurement.byteAccountingScope).toContain(
            'compact private opening payload vectors only',
        );
        expect(measurement.excludedByteCategories).toEqual(
            expect.arrayContaining([
                'mailbox KEM, AEAD, nonce, tag, and associated-data overhead',
                'encrypted local-state wrapper overhead',
                'future target-decryption proof bytes',
            ]),
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
            recipientApprovalBoundary:
                compactVssShareLinkageRecipientApprovalBoundary,
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
            recipientApprovalBoundary:
                compactVssShareLinkageRecipientApprovalBoundary,
        });
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
        ).toThrow(/recipient-share commitment root/u);
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
        ).toThrow(/recipient-share commitment root/u);
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
        ).toThrow(/aggregate threshold commitment set root/u);
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
        ).toThrow(/aggregate threshold commitment set root/u);
        expect(() =>
            verifyCompactVssShareLinkageStatement({
                statement: rebindLinkageStatementRoot({
                    ...linkageStatement,
                    proofBoundary:
                        'statement binding only; unsupported test boundary',
                } as unknown as typeof linkageStatement),
            }),
        ).toThrow(/proofBoundary/u);
        expect(() =>
            verifyCompactVssShareLinkageStatement({
                statement: rebindLinkageStatementRoot({
                    ...linkageStatement,
                    recipientApprovalBoundary:
                        'recipient approval is sufficient for this unsupported test statement',
                } as unknown as typeof linkageStatement),
            }),
        ).toThrow(/recipientApprovalBoundary/u);
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
});
