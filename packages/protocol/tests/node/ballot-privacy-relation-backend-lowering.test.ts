import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import { buildEncodedScoreFieldLinearProofProjection } from '../../src/ballot-privacy/ballot-proof-linear-statement';
import {
    createBallotPrivacyProfileSet,
    createShareCommitmentMessageBoundCert,
    type BallotPrivacyRelationCompilerInput,
} from '../../src/ballot-privacy/index';
import {
    lowerBallotPrivacyRelationToBackendStatement,
    type BallotPrivacyRelationBackendPublicContext,
} from '../../src/ballot-privacy/relation-backend-lowering';

const digest = (label: string): string =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        label,
        purpose: 'ballot-privacy-relation-lowering-test',
    });

const oneHotScore = (score: number): readonly number[] =>
    Array.from({ length: 10 }, (_unusedValue, scoreIndex) =>
        scoreIndex + 1 === score ? 1 : 0,
    );

const encodedShareVector = (input: {
    readonly firstOptionScoreShare: number;
    readonly secondOptionScoreShare: number;
}): readonly number[] => [
    input.firstOptionScoreShare,
    ...oneHotScore(7),
    input.secondOptionScoreShare,
    ...oneHotScore(3),
];

const encodedCoordinateShamirCoefficients =
    (): readonly (readonly number[])[] => [
        [65_536],
        ...Array.from({ length: 10 }, () => [0] as const),
        [9],
        ...Array.from({ length: 10 }, () => [0] as const),
    ];

const validRelationInput = (): BallotPrivacyRelationCompilerInput => ({
    encodedCoordinateShamirCoefficients: encodedCoordinateShamirCoefficients(),
    normalizedScores: [7, 3],
    optionCount: 2,
    pvssThreshold: 2,
    receivers: [
        {
            receiverIdentity: 'receiver-1',
            receiverRosterPosition: 1,
            receiverShareVector: encodedShareVector({
                firstOptionScoreShare: 6,
                secondOptionScoreShare: 12,
            }),
        },
        {
            receiverIdentity: 'receiver-2',
            receiverRosterPosition: 2,
            receiverShareVector: encodedShareVector({
                firstOptionScoreShare: 5,
                secondOptionScoreShare: 21,
            }),
        },
        {
            receiverIdentity: 'receiver-3',
            receiverRosterPosition: 3,
            receiverShareVector: encodedShareVector({
                firstOptionScoreShare: 4,
                secondOptionScoreShare: 30,
            }),
        },
    ],
    rosterSize: 3,
    scoreOneHotWitnesses: [oneHotScore(7), oneHotScore(3)],
});

const publicContext = (): BallotPrivacyRelationBackendPublicContext => {
    const profileSet = createBallotPrivacyProfileSet();
    const certificate = createShareCommitmentMessageBoundCert({
        maximumCanonicalTurnout: 20,
        shareCommitmentProfile: profileSet.shareCommitmentProfile,
    });
    const receiverReferences = [1, 2, 3].map((receiverRosterPosition) => ({
        receiverIdentity: `receiver-${receiverRosterPosition}`,
        receiverRosterPosition,
    }));

    return {
        actionContextDigest: digest('action-context'),
        aggregateInputEncodingProfileDigest:
            profileSet.aggregateInputEncodingProfile
                .aggregateInputEncodingProfileDigest,
        ballotProofProfileDigest:
            profileSet.ballotProofProfile.ballotProofProfileDigest,
        ballotProofStatementDigest: digest('ballot-proof-statement'),
        ballotScoreEncodingProfileDigest:
            profileSet.ballotScoreEncodingProfile
                .ballotScoreEncodingProfileDigest,
        ballotShareLayoutProfileDigest:
            profileSet.ballotShareLayoutProfile.ballotShareLayoutProfileDigest,
        ceremonyId: 'ceremony-relation-lowering',
        encodedAggregateLayoutDigest:
            profileSet.encodedAggregateLayoutProfile
                .encodedAggregateLayoutDigest,
        encodedShareVectorLayoutDigest:
            profileSet.encodedShareVectorLayoutProfile
                .encodedShareVectorLayoutDigest,
        manifestDigest: digest('manifest'),
        pollSpecDigest: digest('poll-spec'),
        receiverEncryptionProfileDigest:
            profileSet.receiverEncryptionProfile
                .receiverEncryptionProfileDigest,
        receiverKeyProofRoot: digest('receiver-key-proof-root'),
        receiverKeyRoot: digest('receiver-key-root'),
        receiverPayloads: receiverReferences.map((receiverReference) => ({
            ...receiverReference,
            receiverPayloadCiphertextRoot: digest(
                `receiver-payload-ciphertext-root-${receiverReference.receiverRosterPosition}`,
            ),
            receiverPayloadDigest: digest(
                `receiver-payload-${receiverReference.receiverRosterPosition}`,
            ),
        })),
        receiverPublicKeys: receiverReferences.map((receiverReference) => ({
            ...receiverReference,
            receiverPublicKeyDigest: digest(
                `receiver-public-key-${receiverReference.receiverRosterPosition}`,
            ),
        })),
        rosterDigest: digest('roster'),
        rosterExternalAcceptanceDigest: digest('external-acceptance'),
        scoreMembershipProfileDigest:
            profileSet.scoreMembershipProfile.scoreMembershipProfileDigest,
        shareCommitmentMessageBoundCertDigest:
            certificate.shareCommitmentMessageBoundCertDigest,
        shareCommitmentProfileDigest:
            profileSet.shareCommitmentProfile.shareCommitmentProfileDigest,
        shareCommitments: receiverReferences.map((receiverReference) => ({
            ...receiverReference,
            shareCommitmentDigest: digest(
                `share-commitment-${receiverReference.receiverRosterPosition}`,
            ),
        })),
    };
};

describe('ballot privacy relation backend lowering', () => {
    it('lowers encoded score constraints into sparse backend rows without witness values', () => {
        const result = lowerBallotPrivacyRelationToBackendStatement({
            publicContext: publicContext(),
            relationInput: validRelationInput(),
        });

        expect(result.ok).toBe(true);
        if (!result.ok) {
            throw new Error('valid relation input should lower');
        }

        expect(result.statement).toMatchObject({
            encodedCoordinateCount: 22,
            fieldModulus: 65_537,
            optionCount: 2,
            pvssThreshold: 2,
            relationLabel: 'BallotPrivacyPvssRelation',
            relationStatementFormat:
                'SparseIntegerRowsModuloGF65537WithBoundGadgets-v1',
            rosterSize: 3,
            shareVectorWidth: 22,
        });
        expect(result.statement.relationStatementDigest).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(result.statement.linearRows).toHaveLength(2 * 2 + 3 * 22);
        expect(result.statement.algebraicRows).toHaveLength(3 * 4);
        expect(result.statement.variables).toHaveLength(
            22 + 22 + 3 * 22 * 2 + 3 * 64 + 3 * 2,
        );
        expect(result.statement.backendStatement).toMatchObject({
            backendStatementFormat: 'SparseSignedIntegerBackendStatement-v1',
            columnCount: 374,
            digestExpandedRowCount: 3 * (1_024 + 86 + 1_280 + 1_024),
            explicitRowCount: 70,
            objectType: 'BallotPrivacyProofBackendStatement',
            rowCount: 70 + 3 * (1_024 + 86 + 1_280 + 1_024),
        });
        expect(
            result.statement.backendStatement.backendStatementDigest,
        ).toMatch(/^[a-f0-9]{128}$/u);
        expect(result.statement.backendStatement.rowBatches).toHaveLength(13);
        expect(result.statement.backendStatement.rowBatches[0]).toMatchObject({
            batchKind: 'ExplicitSparseRows',
            batchName: 'encoded_score_field_rows',
            rowCount: 70,
            rowOffset: 0,
        });
        expect(result.statement.backendStatement.rowBatches[1]).toMatchObject({
            batchKind: 'DigestExpandedRows',
            batchName: 'receiver_1_share_commitment_equation_backend_rows',
            rowCount: 1_024,
            rowOffset: 70,
            rowKind: 'ShareCommitmentEquation',
        });
        expect(
            result.statement.backendStatement.rowBatches[
                result.statement.backendStatement.rowBatches.length - 1
            ],
        ).toMatchObject({
            batchKind: 'DigestExpandedRows',
            rowCount: 1_024,
            rowKind: 'ReceiverKeyBinding',
        });
        expect(
            result.statement.backendStatement.rowBatches[0]?.matrixDigest,
        ).toMatch(/^[a-f0-9]{128}$/u);
        expect(
            result.statement.backendStatement.rowBatches[0]?.targetVectorDigest,
        ).toMatch(/^[a-f0-9]{128}$/u);
        const explicitBackendRowBatch =
            result.statement.backendStatement.rowBatches[0];
        if (explicitBackendRowBatch?.batchKind !== 'ExplicitSparseRows') {
            throw new Error('Expected the first backend batch to be explicit.');
        }

        expect(explicitBackendRowBatch.rows[4]).toMatchObject({
            rowKind: 'ShamirEvaluationQuotient',
            target: '0',
            terms: [
                {
                    coefficient: '1',
                    variableName: 'option_1_scalar_constant',
                },
                {
                    coefficient: '1',
                    variableName: 'encoded_coordinate_0_coefficient_degree_1',
                },
                {
                    coefficient: '-1',
                    variableName: 'receiver_1_encoded_coordinate_0_share',
                },
                {
                    coefficient: '-65537',
                    variableName: 'receiver_1_encoded_coordinate_0_quotient',
                },
            ],
        });
        const shareCommitmentOpeningBackendBound =
            result.statement.backendStatement.bounds.find(
                (bound) =>
                    bound.boundName ===
                    'share_commitment_openings_certified_absolute_bound',
            );
        expect(shareCommitmentOpeningBackendBound).toMatchObject({
            absoluteMaximum: '1024',
        });
        expect(
            shareCommitmentOpeningBackendBound?.variableColumnIndices.includes(
                176,
            ),
        ).toBe(true);
        expect(result.statement.linearRows).toEqual(
            expect.arrayContaining([
                {
                    modulus: 65_537,
                    optionIndex: 0,
                    rowKind: 'OneHotSum',
                    rowName: 'option_1_one_hot_sum',
                    target: 1,
                    terms: Array.from(
                        { length: 10 },
                        (_unusedValue, score) => ({
                            coefficient: 1,
                            variableName: `option_1_score_bucket_${score + 1}`,
                        }),
                    ),
                },
                {
                    modulus: 65_537,
                    optionIndex: 0,
                    rowKind: 'ScalarScoreConsistency',
                    rowName: 'option_1_scalar_score_consistency',
                    target: 0,
                    terms: [
                        {
                            coefficient: 1,
                            variableName: 'option_1_scalar_constant',
                        },
                        ...Array.from(
                            { length: 10 },
                            (_unusedValue, score) => ({
                                coefficient: -(score + 1),
                                variableName: `option_1_score_bucket_${
                                    score + 1
                                }`,
                            }),
                        ),
                    ],
                },
                {
                    encodedCoordinateIndex: 0,
                    modulus: 65_537,
                    optionIndex: 0,
                    receiverRosterPosition: 2,
                    rowKind: 'ShamirEvaluationQuotient',
                    rowName:
                        'receiver_2_encoded_coordinate_0_shamir_evaluation',
                    target: 0,
                    terms: [
                        {
                            coefficient: 1,
                            variableName: 'option_1_scalar_constant',
                        },
                        {
                            coefficient: 2,
                            variableName:
                                'encoded_coordinate_0_coefficient_degree_1',
                        },
                        {
                            coefficient: -1,
                            variableName:
                                'receiver_2_encoded_coordinate_0_share',
                        },
                        {
                            coefficient: -65_537,
                            variableName:
                                'receiver_2_encoded_coordinate_0_quotient',
                        },
                    ],
                },
            ]),
        );
        expect(result.statement.bounds).toContainEqual({
            boundKind: 'Boolean',
            boundName: 'option_1_score_bucket_7_boolean',
            maximum: 1,
            minimum: 0,
            variableNames: ['option_1_score_bucket_7'],
        });
        const quotientBound = result.statement.bounds.find(
            (bound) =>
                bound.boundName === 'shamir_quotients_certified_absolute_bound',
        );
        expect(quotientBound).toMatchObject({
            absoluteMaximum: 65_537,
            boundKind: 'SignedIntegerAbsoluteBound',
        });
        expect(quotientBound?.variableNames).toEqual(
            expect.arrayContaining([
                'receiver_1_encoded_coordinate_0_quotient',
                'receiver_3_encoded_coordinate_21_quotient',
            ]),
        );
        const firstCommitmentRow = result.statement.algebraicRows.find(
            (row) =>
                row.rowKind === 'ShareCommitmentEquation' &&
                row.receiverRosterPosition === 1,
        );
        const firstPlaintextBindingRow = result.statement.algebraicRows.find(
            (row) =>
                row.rowKind === 'ReceiverPayloadPlaintextBinding' &&
                row.receiverRosterPosition === 1,
        );
        const firstEncryptionRow = result.statement.algebraicRows.find(
            (row) =>
                row.rowKind === 'ReceiverPayloadEncryptionEquation' &&
                row.receiverRosterPosition === 1,
        );
        const firstReceiverKeyRow = result.statement.algebraicRows.find(
            (row) =>
                row.rowKind === 'ReceiverKeyBinding' &&
                row.receiverRosterPosition === 1,
        );

        expect(firstCommitmentRow).toMatchObject({
            equationCount: 1_024,
            modulus: '18446744069414584321',
            rowName: 'receiver_1_share_commitment_equation',
        });
        expect(firstCommitmentRow?.variableNames).toEqual(
            expect.arrayContaining([
                'receiver_1_encoded_coordinate_0_share',
                'receiver_1_share_commitment_opening_coordinate_63',
            ]),
        );
        expect(firstPlaintextBindingRow).toMatchObject({
            equationCount: 86,
            modulus: 65_537,
        });
        expect(firstPlaintextBindingRow?.variableNames).toEqual(
            expect.arrayContaining([
                'receiver_1_encoded_coordinate_21_share',
                'receiver_1_share_commitment_opening_coordinate_0',
            ]),
        );
        expect(firstEncryptionRow).toMatchObject({
            equationCount: 1_280,
            modulus: 12_289,
        });
        expect(firstEncryptionRow?.variableNames).toEqual(
            expect.arrayContaining([
                'receiver_1_receiver_encryption_randomness',
                'receiver_1_receiver_encryption_noise',
            ]),
        );
        expect(firstReceiverKeyRow).toMatchObject({
            equationCount: 1_024,
            modulus: 12_289,
            variableNames: [],
        });
        expect(result.statement.bounds).toEqual(
            expect.arrayContaining([
                expect.objectContaining({
                    absoluteMaximum: 1_024,
                    boundName:
                        'share_commitment_openings_certified_absolute_bound',
                }),
                expect.objectContaining({
                    absoluteMaximum: 2,
                    boundName:
                        'receiver_encryption_randomness_certified_absolute_bound',
                }),
                expect.objectContaining({
                    absoluteMaximum: 2,
                    boundName:
                        'receiver_encryption_noise_certified_absolute_bound',
                }),
            ]),
        );
        expect(
            result.statement.bounds.find(
                (bound) =>
                    bound.boundName ===
                    'share_commitment_openings_certified_absolute_bound',
            )?.variableNames,
        ).toEqual(
            expect.arrayContaining([
                'receiver_1_share_commitment_opening_coordinate_0',
            ]),
        );
        expect(JSON.stringify(result.statement)).not.toMatch(
            /normalizedScores|scoreOneHotWitnesses|receiverShareVector|encodedCoordinateShamirCoefficients/u,
        );
    });

    it('projects encoded-score field rows into the linear proof backend shape', () => {
        const relationInput = validRelationInput();
        const context = publicContext();
        const loweringResult = lowerBallotPrivacyRelationToBackendStatement({
            publicContext: context,
            relationInput,
        });

        expect(loweringResult.ok).toBe(true);
        if (!loweringResult.ok) {
            throw new Error('valid relation input should lower');
        }

        const projection = buildEncodedScoreFieldLinearProofProjection({
            ballotProofStatementDigest: context.ballotProofStatementDigest,
            loweredStatement: loweringResult.statement,
            parameterProfileId: 'encoded-score-field-linear-compatibility-v1',
            relationInput,
            sourceRingDegree: 64,
            witnessL2BoundSquared: '65536',
        });

        expect(projection.sourceRowBatchName).toBe('encoded_score_field_rows');
        expect(projection.sourceBackendColumnIndices).toHaveLength(176);
        expect(projection.sourceBackendColumnIndices[0]).toBe(0);
        expect(
            projection.sourceBackendColumnIndices[
                projection.sourceBackendColumnIndices.length - 1
            ],
        ).toBe(175);
        expect(projection.linearStatement).toMatchObject({
            ballotProofStatementDigest: context.ballotProofStatementDigest,
            coefficientModulus: '65537',
            objectType: 'BallotProofLinearProofStatement',
            parameterProfileId: 'encoded-score-field-linear-compatibility-v1',
            relation: 'A*w + t = 0',
            ringDegree: 64,
            statementColumns: 176,
            statementRows: 70,
            witnessL2BoundSquared: '65536',
        });
        expect(
            projection.linearStatement.statementMatrixCoefficients,
        ).toHaveLength(70);
        expect(
            projection.linearStatement.statementMatrixCoefficients[0],
        ).toHaveLength(176);
        expect(
            projection.linearStatement.statementMatrixCoefficients[0]?.[0],
        ).toHaveLength(64);
        expect(
            projection.linearStatement.targetVectorCoefficients,
        ).toHaveLength(70);
        expect(projection.linearStatement.statementDigest).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(projection.privateWitnessVectorCoefficients).toHaveLength(176);
        expect(
            projection.privateWitnessVectorCoefficients.some(
                (polynomial) => polynomial[0] === -1,
            ),
        ).toBe(true);
        expect(
            projection.privateWitnessVectorCoefficients.every(
                (polynomial) =>
                    polynomial.length === 64 &&
                    polynomial
                        .slice(1)
                        .every((coefficient) => coefficient === 0),
            ),
        ).toBe(true);
        expect(projection.linearStatement).not.toHaveProperty(
            'privateWitnessVectorCoefficients',
        );
        expect(JSON.stringify(projection.linearStatement)).not.toMatch(
            /normalizedScores|scoreOneHotWitnesses|receiverShareVector|privateWitness/u,
        );
    });

    it('binds every public context digest into the relation statement digest', () => {
        const firstResult = lowerBallotPrivacyRelationToBackendStatement({
            publicContext: publicContext(),
            relationInput: validRelationInput(),
        });
        const changedContext = {
            ...publicContext(),
            actionContextDigest: digest('changed-action-context'),
        };
        const secondResult = lowerBallotPrivacyRelationToBackendStatement({
            publicContext: changedContext,
            relationInput: validRelationInput(),
        });

        expect(firstResult.ok).toBe(true);
        expect(secondResult.ok).toBe(true);
        if (firstResult.ok && secondResult.ok) {
            expect(firstResult.statement.relationStatementDigest).not.toBe(
                secondResult.statement.relationStatementDigest,
            );
        }
    });

    it('keeps hostile compiler inputs as relation refusals before lowering', () => {
        const wrongShareInput = validRelationInput();
        const result = lowerBallotPrivacyRelationToBackendStatement({
            publicContext: publicContext(),
            relationInput: {
                ...wrongShareInput,
                receivers: wrongShareInput.receivers.map((receiver) =>
                    receiver.receiverRosterPosition === 2
                        ? {
                              ...receiver,
                              receiverShareVector:
                                  receiver.receiverShareVector.map(
                                      (shareRepresentative, coordinateIndex) =>
                                          coordinateIndex === 0
                                              ? shareRepresentative + 1
                                              : shareRepresentative,
                                  ),
                          }
                        : receiver,
                ),
            },
        });

        expect(result).toMatchObject({
            ok: false,
            unresolvedReason: 'BallotPrivacyRelationInvalid',
        });
        if (!result.ok) {
            expect(
                result.refusedObjects.some((refusal) =>
                    refusal.message.includes(
                        'Shamir quotient constraint is not exact',
                    ),
                ),
            ).toBe(true);
        }
    });
});
