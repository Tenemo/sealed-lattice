// This file is one targeted part of the split test suite.
import { describe, expect, it } from 'vitest';

import type { BackendProofComponentView } from './shared.js';
import {
    publicContext,
    shareCommitmentModulus,
    shareCommitmentOpeningForReceiver,
    validRelationInput,
} from './shared.js';

import { buildEncodedScoreFieldLinearProofProjection } from '#packages/protocol/src/ballot-privacy/ballot-proof-linear-statement';
import { lowerBallotPrivacyRelationToBackendStatement } from '#packages/protocol/src/ballot-privacy/relation-backend-lowering';

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
        expect(result.statement.relationStatementHash).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(result.statement.linearRows).toHaveLength(
            2 * 2 + 3 * 22 + 3 * (22 + 64),
        );
        expect(result.statement.algebraicRows).toHaveLength(3 * 3);
        expect(result.statement.variables).toHaveLength(
            22 + 22 + 3 * 22 * 2 + 3 * (22 + 64 + 64 + 2),
        );
        expect(result.statement.backendStatement).toMatchObject({
            backendStatementFormat: 'SparseSignedIntegerBackendStatement-v1',
            columnCount: 632,
            hashExpandedRowCount: 3 * (1_280 + 1_024),
            explicitRowCount: 70 + 3 * (22 + 64) + 3 * 1_024,
            objectType: 'BallotPrivacyProofBackendStatement',
            rowCount: 70 + 3 * (1_024 + 86 + 1_280 + 1_024),
        });
        expect(result.statement.backendStatement.proofComponents).toHaveLength(
            5,
        );
        const proofComponents = result.statement.backendStatement
            .proofComponents as unknown as readonly BackendProofComponentView[];
        expect(
            proofComponents.map((component) => component.componentId),
        ).toEqual([
            'score-and-shamir-field-component',
            'payload-plaintext-field-component',
            'share-commitment-component',
            'receiver-encryption-component',
            'receiver-key-binding-component',
        ]);
        expect(result.statement.backendStatement.proofComponents).toEqual(
            expect.arrayContaining([
                expect.objectContaining({
                    coefficientModulus: '65537',
                    componentId: 'score-and-shamir-field-component',
                    proofLoweringStatus: 'explicitRowsAvailable',
                    rowCount: 70,
                    rowKinds: ['EncodedScoreFieldRows'],
                    variableColumnCount: 176,
                }),
                expect.objectContaining({
                    coefficientModulus: '65537',
                    componentId: 'payload-plaintext-field-component',
                    proofLoweringStatus: 'explicitRowsAvailable',
                    rowCount: 3 * 86,
                    rowKinds: ['ReceiverPayloadPlaintextBindingRows'],
                    variableColumnCount: 516,
                }),
                expect.objectContaining({
                    coefficientModulus: '18446744069414584321',
                    componentId: 'share-commitment-component',
                    proofLoweringStatus: 'explicitRowsAvailable',
                    rowCount: 3 * 1_024,
                    rowKinds: ['ShareCommitmentEquationRows'],
                    variableColumnCount: 258,
                }),
                expect.objectContaining({
                    coefficientModulus: '12289',
                    componentId: 'receiver-encryption-component',
                    proofLoweringStatus: 'HashExpandedRowsPending',
                    rowCount: 3 * 1_280,
                    rowKinds: ['ReceiverPayloadEncryptionEquation'],
                }),
                expect.objectContaining({
                    coefficientModulus: '12289',
                    componentId: 'receiver-key-binding-component',
                    proofLoweringStatus: 'HashExpandedRowsPending',
                    rowCount: 3 * 1_024,
                    rowKinds: ['ReceiverKeyBinding'],
                    variableColumnCount: 0,
                }),
            ]),
        );
        for (const proofComponent of proofComponents) {
            expect(proofComponent.componentHash).toMatch(/^[a-f0-9]{128}$/u);
            expect(proofComponent.rowBatchNames.length).toBeGreaterThan(0);
            expect(proofComponent.variableColumnIndices).toEqual(
                [...proofComponent.variableColumnIndices].sort(
                    (leftColumnIndex, rightColumnIndex) =>
                        leftColumnIndex - rightColumnIndex,
                ),
            );
        }
        expect(result.statement.backendStatement.proofComponentsHash).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(result.statement.backendStatement.backendStatementHash).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(result.statement.backendStatement.rowBatches).toHaveLength(9);
        expect(result.statement.backendStatement.rowBatches[0]).toMatchObject({
            batchKind: 'ExplicitSparseRows',
            batchName: 'encoded_score_field_rows',
            rowCount: 70,
            rowOffset: 0,
        });
        expect(result.statement.backendStatement.rowBatches[1]).toMatchObject({
            batchKind: 'ExplicitSparseRows',
            batchName: 'receiver_payload_plaintext_binding_rows',
            rowCount: 258,
            rowOffset: 70,
            rowKind: 'ReceiverPayloadPlaintextBindingRows',
        });
        expect(result.statement.backendStatement.rowBatches[2]).toMatchObject({
            batchKind: 'ExplicitSparseRows',
            batchName: 'share_commitment_equation_rows',
            rowCount: 3_072,
            rowOffset: 328,
            rowKind: 'ShareCommitmentEquationRows',
        });
        const explicitShareCommitmentRowBatch =
            result.statement.backendStatement.rowBatches[2];
        if (
            explicitShareCommitmentRowBatch?.batchKind !== 'ExplicitSparseRows'
        ) {
            throw new Error('Expected share commitment rows to be explicit.');
        }
        const firstShareCommitmentEquationRow =
            explicitShareCommitmentRowBatch.rows.find(
                (row) =>
                    row.rowName ===
                    'receiver_1_share_commitment_vector_0_coefficient_0_equation',
            );
        if (firstShareCommitmentEquationRow === undefined) {
            throw new Error('Missing first share commitment equation row.');
        }
        const firstReceiver = validRelationInput().receivers[0];
        const validWitnessValues = new Map<string, bigint>();
        firstReceiver?.receiverShareVector.forEach(
            (shareRepresentative, encodedCoordinateIndex) => {
                validWitnessValues.set(
                    `receiver_1_encoded_coordinate_${encodedCoordinateIndex}_share`,
                    BigInt(shareRepresentative),
                );
            },
        );
        shareCommitmentOpeningForReceiver(1).forEach(
            (openingCoordinate, openingCoordinateIndex) => {
                validWitnessValues.set(
                    `receiver_1_share_commitment_opening_coordinate_${openingCoordinateIndex}`,
                    BigInt(openingCoordinate),
                );
            },
        );
        const evaluateShareCommitmentRow = (
            witnessValues: ReadonlyMap<string, bigint>,
        ): bigint =>
            firstShareCommitmentEquationRow.terms.reduce(
                (accumulatedValue, term) =>
                    (accumulatedValue +
                        BigInt(term.coefficient) *
                            (witnessValues.get(term.variableName) ?? 0n)) %
                    shareCommitmentModulus,
                0n,
            );
        expect(
            (evaluateShareCommitmentRow(validWitnessValues) +
                shareCommitmentModulus) %
                shareCommitmentModulus,
        ).toBe(BigInt(firstShareCommitmentEquationRow.target));
        const wrongOpeningWitnessValues = new Map(validWitnessValues);
        wrongOpeningWitnessValues.set(
            'receiver_1_share_commitment_opening_coordinate_0',
            (wrongOpeningWitnessValues.get(
                'receiver_1_share_commitment_opening_coordinate_0',
            ) ?? 0n) + 1n,
        );
        expect(
            (evaluateShareCommitmentRow(wrongOpeningWitnessValues) +
                shareCommitmentModulus) %
                shareCommitmentModulus,
        ).not.toBe(BigInt(firstShareCommitmentEquationRow.target));
        expect(
            result.statement.backendStatement.rowBatches[
                result.statement.backendStatement.rowBatches.length - 1
            ],
        ).toMatchObject({
            batchKind: 'HashExpandedRows',
            rowCount: 1_024,
            rowKind: 'ReceiverKeyBinding',
        });
        expect(
            result.statement.backendStatement.rowBatches[0]?.matrixHash,
        ).toMatch(/^[a-f0-9]{128}$/u);
        expect(
            result.statement.backendStatement.rowBatches[0]?.targetVectorHash,
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
        expect(shareCommitmentOpeningBackendBound?.variableNames).toEqual(
            expect.arrayContaining([
                'receiver_1_share_commitment_opening_coordinate_0',
            ]),
        );
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
        const explicitPayloadPlaintextRowBatch =
            result.statement.backendStatement.rowBatches[1];
        if (
            explicitPayloadPlaintextRowBatch?.batchKind !== 'ExplicitSparseRows'
        ) {
            throw new Error(
                'Expected payload plaintext binding rows to be explicit.',
            );
        }
        const payloadShareBindingRow =
            explicitPayloadPlaintextRowBatch.rows.find(
                (row) =>
                    row.rowName ===
                    'receiver_1_payload_plaintext_encoded_coordinate_21_share_binding',
            );
        expect(payloadShareBindingRow).toMatchObject({
            rowKind: 'ReceiverPayloadSharePlaintextBinding',
            target: '0',
        });
        expect(
            payloadShareBindingRow?.terms.map(
                ({ coefficient, variableName }) => ({
                    coefficient,
                    variableName,
                }),
            ),
        ).toEqual([
            {
                coefficient: '1',
                variableName:
                    'receiver_1_payload_plaintext_encoded_coordinate_21_share',
            },
            {
                coefficient: '-1',
                variableName: 'receiver_1_encoded_coordinate_21_share',
            },
        ]);
        expect(
            payloadShareBindingRow?.terms.every((term) =>
                Number.isInteger(term.columnIndex),
            ),
        ).toBe(true);
        const payloadOpeningBindingRow =
            explicitPayloadPlaintextRowBatch.rows.find(
                (row) =>
                    row.rowName ===
                    'receiver_1_payload_plaintext_opening_coordinate_0_binding',
            );
        expect(payloadOpeningBindingRow).toMatchObject({
            rowKind: 'ReceiverPayloadOpeningPlaintextBinding',
            target: '0',
        });
        expect(
            payloadOpeningBindingRow?.terms.map(
                ({ coefficient, variableName }) => ({
                    coefficient,
                    variableName,
                }),
            ),
        ).toEqual([
            {
                coefficient: '1',
                variableName:
                    'receiver_1_payload_plaintext_opening_coordinate_0',
            },
            {
                coefficient: '-1',
                variableName:
                    'receiver_1_share_commitment_opening_coordinate_0',
            },
        ]);
        expect(
            payloadOpeningBindingRow?.terms.every((term) =>
                Number.isInteger(term.columnIndex),
            ),
        ).toBe(true);
        expect(firstEncryptionRow).toMatchObject({
            equationCount: 1_280,
            modulus: 12_289,
        });
        expect(firstEncryptionRow?.variableNames).toEqual(
            expect.arrayContaining([
                'receiver_1_payload_plaintext_encoded_coordinate_0_share',
                'receiver_1_payload_plaintext_opening_coordinate_63',
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
                    absoluteMaximum: 1_024,
                    boundName:
                        'receiver_payload_plaintext_openings_certified_absolute_bound',
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
            ballotProofStatementHash: context.ballotProofStatementHash,
            loweredStatement: loweringResult.statement,
            parameterProfileId: 'encoded-score-field-linear-proof-parameter-v1',
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
            ballotProofStatementHash: context.ballotProofStatementHash,
            coefficientModulus: '65537',
            objectType: 'BallotProofLinearProofStatement',
            parameterProfileId: 'encoded-score-field-linear-proof-parameter-v1',
            projectionCoverage: 'encoded-score-field-rows-only',
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
        expect(projection.linearStatement.statementHash).toMatch(
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
});
