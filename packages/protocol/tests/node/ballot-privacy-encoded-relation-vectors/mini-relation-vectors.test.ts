// This file is one focused part of the split test suite.
import { describe, expect, it } from 'vitest';

import {
    caseByName,
    collectObjectKeys,
    encodedRelationVectors,
    forbiddenPublicVectorKeys,
} from './shared.js';

describe('ballot privacy encoded relation vectors', () => {
    it('records all required encoded ballot relation cases without witness material', () => {
        const caseNames = new Set(
            encodedRelationVectors.cases.map(
                (vectorCase) => vectorCase.caseName,
            ),
        );
        const discoveredKeys = new Set<string>();
        collectObjectKeys(encodedRelationVectors, discoveredKeys);

        expect(encodedRelationVectors).toMatchObject({
            generationStatus: 'generated',
            objectType: 'BallotPrivacyEncodedBallotLinearRelationVectors',
            objectVersion: 1,
            profileId: 'encoded-ballot-linear-relation-v1',
            statementFormat:
                'SparseIntegerRowsModuloGF65537WithBoundGadgets-v1',
        });
        for (const requiredCaseName of encodedRelationVectors.requiredCaseNames) {
            expect(caseNames.has(requiredCaseName)).toBe(true);
        }
        for (const forbiddenKey of forbiddenPublicVectorKeys) {
            expect(discoveredKeys.has(forbiddenKey)).toBe(false);
        }
    });

    it('contains a mini relation statement with encoded-score rows and bounds', () => {
        const miniCase = caseByName('mini-encoded-ballot-relation');

        expect(miniCase).toMatchObject({
            compilerAccepted: true,
            expectedOutcome: 'accept',
        });
        expect(miniCase.loweredStatement).toBeDefined();
        expect(miniCase.loweredStatement).toMatchObject({
            encodedCoordinateCount: 22,
            optionCount: 2,
            relationStatementFormat:
                'SparseIntegerRowsModuloGF65537WithBoundGadgets-v1',
            rosterSize: 3,
            shareVectorWidth: 22,
        });
        expect(miniCase.loweredStatement?.linearRows).toHaveLength(328);
        expect(miniCase.loweredStatement?.algebraicRows).toHaveLength(9);
        expect(miniCase.loweredStatement?.variables).toHaveLength(632);
        expect(miniCase.loweredStatement?.bounds).toHaveLength(32);
        expect(miniCase.loweredStatement?.backendStatement).toMatchObject({
            backendStatementFormat: 'SparseSignedIntegerBackendStatement-v1',
            columnCount: 632,
            digestExpandedRowCount: 9_984,
            explicitRowCount: 328,
            rowCount: 10_312,
        });
        expect(
            miniCase.loweredStatement?.backendStatement.backendStatementDigest,
        ).toMatch(/^[a-f0-9]{128}$/u);
        expect(
            miniCase.loweredStatement?.backendStatement.rowBatches,
        ).toHaveLength(11);
        expect(
            miniCase.loweredStatement?.backendStatement.proofComponents,
        ).toHaveLength(5);
        expect(
            miniCase.loweredStatement?.backendStatement.proofComponents,
        ).toEqual(
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
                    rowCount: 258,
                    rowKinds: ['ReceiverPayloadPlaintextBindingRows'],
                    variableColumnCount: 516,
                }),
                expect.objectContaining({
                    coefficientModulus: '18446744069414584321',
                    componentId: 'share-commitment-component',
                    proofLoweringStatus: 'digestExpandedRowsPending',
                    rowCount: 3_072,
                    rowKinds: ['ShareCommitmentEquation'],
                }),
                expect.objectContaining({
                    coefficientModulus: '12289',
                    componentId: 'receiver-encryption-component',
                    proofLoweringStatus: 'digestExpandedRowsPending',
                    rowCount: 3_840,
                    rowKinds: ['ReceiverPayloadEncryptionEquation'],
                }),
                expect.objectContaining({
                    coefficientModulus: '12289',
                    componentId: 'receiver-key-binding-component',
                    proofLoweringStatus: 'digestExpandedRowsPending',
                    rowCount: 3_072,
                    rowKinds: ['ReceiverKeyBinding'],
                    variableColumnCount: 0,
                }),
            ]),
        );
        expect(
            miniCase.loweredStatement?.backendStatement.proofComponentsDigest,
        ).toMatch(/^[a-f0-9]{128}$/u);
        expect(miniCase.componentBundleStatement).toMatchObject({
            bundleCoverage: 'component-bundle-incomplete',
            requiredComponentIds: [
                'score-and-shamir-field-component',
                'payload-plaintext-field-component',
                'share-commitment-component',
                'receiver-encryption-component',
                'receiver-key-binding-component',
            ],
        });
        expect(
            miniCase.componentBundleStatement?.componentBundleStatementDigest,
        ).toMatch(/^[a-f0-9]{128}$/u);
        expect(
            miniCase.componentBundleStatement?.componentStatements.map(
                (componentStatement) => componentStatement.componentId,
            ),
        ).toEqual([
            'score-and-shamir-field-component',
            'payload-plaintext-field-component',
            'share-commitment-component',
            'receiver-encryption-component',
            'receiver-key-binding-component',
        ]);
        expect(
            miniCase.componentBundleStatement?.componentStatements[0],
        ).toMatchObject({
            componentId: 'score-and-shamir-field-component',
            proofLoweringStatus: 'explicitRowsAvailable',
            rowBatchNames: ['encoded_score_field_rows'],
        });
        expect(
            miniCase.componentBundleStatement?.componentStatements[1],
        ).toMatchObject({
            componentId: 'payload-plaintext-field-component',
            proofLoweringStatus: 'explicitRowsAvailable',
            rowBatchNames: ['receiver_payload_plaintext_binding_rows'],
        });
        expect(
            miniCase.componentBundleStatement?.componentStatements
                .slice(2)
                .every(
                    (componentStatement) =>
                        componentStatement.proofLoweringStatus ===
                        'digestExpandedRowsPending',
                ),
        ).toBe(true);
        expect(
            miniCase.loweredStatement?.backendStatement.rowBatches[0],
        ).toMatchObject({
            batchKind: 'ExplicitSparseRows',
            rowCount: 70,
            rowOffset: 0,
            rowKind: 'EncodedScoreFieldRows',
        });
        expect(
            miniCase.loweredStatement?.backendStatement.rowBatches[1],
        ).toMatchObject({
            batchKind: 'ExplicitSparseRows',
            rowCount: 258,
            rowKind: 'ReceiverPayloadPlaintextBindingRows',
        });
        expect(
            miniCase.loweredStatement?.backendStatement.rowBatches[2],
        ).toMatchObject({
            batchKind: 'DigestExpandedRows',
            rowCount: 1_024,
            rowKind: 'ShareCommitmentEquation',
        });
        expect(miniCase.loweredStatement?.relationStatementDigest).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(
            miniCase.loweredStatement?.linearRows.some(
                (row) =>
                    row.rowKind === 'OneHotSum' &&
                    row.terms.some(
                        (term) =>
                            term.coefficient === 1 &&
                            term.variableName === 'option_1_score_bucket_7',
                    ),
            ),
        ).toBe(true);
        expect(
            miniCase.loweredStatement?.linearRows.some(
                (row) =>
                    row.rowKind === 'ScalarScoreConsistency' &&
                    row.terms.some(
                        (term) =>
                            term.coefficient === -7 &&
                            term.variableName === 'option_1_score_bucket_7',
                    ),
            ),
        ).toBe(true);
        expect(
            miniCase.loweredStatement?.linearRows.some(
                (row) =>
                    row.rowKind === 'ShamirEvaluationQuotient' &&
                    row.terms.some(
                        (term) =>
                            term.coefficient === -65_537 &&
                            term.variableName ===
                                'receiver_2_encoded_coordinate_0_quotient',
                    ),
            ),
        ).toBe(true);
        const firstCommitmentRow =
            miniCase.loweredStatement?.algebraicRows.find(
                (row) => row.rowKind === 'ShareCommitmentEquation',
            );
        const firstEncryptionRow =
            miniCase.loweredStatement?.algebraicRows.find(
                (row) => row.rowKind === 'ReceiverPayloadEncryptionEquation',
            );
        const firstReceiverKeyRow =
            miniCase.loweredStatement?.algebraicRows.find(
                (row) => row.rowKind === 'ReceiverKeyBinding',
            );

        expect(firstCommitmentRow?.equationCount).toBe(1_024);
        expect(firstCommitmentRow?.variableNames).toEqual(
            expect.arrayContaining([
                'receiver_1_encoded_coordinate_0_share',
                'receiver_1_share_commitment_opening_coordinate_63',
            ]),
        );
        expect(firstEncryptionRow?.equationCount).toBe(1_280);
        expect(firstEncryptionRow?.variableNames).toEqual(
            expect.arrayContaining([
                'receiver_1_payload_plaintext_encoded_coordinate_0_share',
                'receiver_1_payload_plaintext_opening_coordinate_63',
                'receiver_1_receiver_encryption_randomness',
                'receiver_1_receiver_encryption_noise',
            ]),
        );
        expect(firstReceiverKeyRow?.equationCount).toBe(1_024);
        const explicitBackendBatch =
            miniCase.loweredStatement?.backendStatement.rowBatches[0];
        if (explicitBackendBatch?.batchKind !== 'ExplicitSparseRows') {
            throw new Error('Expected first backend batch to be explicit.');
        }
        expect(explicitBackendBatch.rows?.[4]).toMatchObject({
            rowKind: 'ShamirEvaluationQuotient',
            target: '0',
        });
        expect(
            explicitBackendBatch.rows?.[4]?.terms.some(
                (term) =>
                    term.coefficient === '-65537' &&
                    term.variableName ===
                        'receiver_1_encoded_coordinate_0_quotient',
            ),
        ).toBe(true);
        const explicitPayloadPlaintextBatch =
            miniCase.loweredStatement?.backendStatement.rowBatches[1];
        if (explicitPayloadPlaintextBatch?.batchKind !== 'ExplicitSparseRows') {
            throw new Error(
                'Expected payload plaintext backend batch to be explicit.',
            );
        }
        expect(explicitPayloadPlaintextBatch.rows?.[0]).toMatchObject({
            rowKind: 'ReceiverPayloadSharePlaintextBinding',
            rowName:
                'receiver_1_payload_plaintext_encoded_coordinate_0_share_binding',
            target: '0',
        });
        expect(
            explicitPayloadPlaintextBatch.rows?.some(
                (row) =>
                    row.rowKind === 'ReceiverPayloadOpeningPlaintextBinding' &&
                    row.terms.some(
                        (term) =>
                            term.variableName ===
                            'receiver_1_share_commitment_opening_coordinate_0',
                    ),
            ),
        ).toBe(true);
    });

    it('contains a mini relation summary with explicit share commitment rows', () => {
        const explicitCommitmentCase = caseByName(
            'mini-encoded-ballot-share-commitment-explicit-relation',
        );

        expect(explicitCommitmentCase).toMatchObject({
            compilerAccepted: true,
            expectedOutcome: 'accept',
        });
        expect(explicitCommitmentCase.loweredStatementSummary).toMatchObject({
            backendDigestExpandedRowCount: 6_912,
            backendExplicitRowCount: 3_400,
            backendRowBatchCount: 9,
            backendRowCount: 10_312,
            encodedCoordinateCount: 22,
            optionCount: 2,
            rosterSize: 3,
            shareVectorWidth: 22,
        });
        expect(explicitCommitmentCase.componentBundleSummary).toMatchObject({
            bundleCoverage: 'component-bundle-incomplete',
            componentCount: 5,
            explicitComponentCount: 3,
            pendingComponentIds: [
                'receiver-encryption-component',
                'receiver-key-binding-component',
            ],
        });
        expect(
            explicitCommitmentCase.loweredStatementSummary
                ?.relationStatementDigest,
        ).toMatch(/^[a-f0-9]{128}$/u);
        expect(
            explicitCommitmentCase.componentBundleSummary
                ?.componentBundleStatementDigest,
        ).toMatch(/^[a-f0-9]{128}$/u);
        expect(
            explicitCommitmentCase.loweredStatementSummary?.firstAlgebraicRow,
        ).toMatchObject({
            equationCount: 1_024,
            rowKind: 'ShareCommitmentEquation',
        });
        expect(
            (
                explicitCommitmentCase.loweredStatementSummary
                    ?.firstAlgebraicRow as {
                    readonly shareCommitmentPolynomialVector?: readonly unknown[];
                }
            ).shareCommitmentPolynomialVector,
        ).toHaveLength(4);
        expect(
            explicitCommitmentCase.componentProjectionSummaries,
        ).toHaveLength(3);
        expect(
            explicitCommitmentCase.componentProjectionSummaries?.map(
                (projectionSummary) => projectionSummary.componentId,
            ),
        ).toEqual([
            'score-and-shamir-field-component',
            'payload-plaintext-field-component',
            'share-commitment-component',
        ]);
        expect(explicitCommitmentCase.componentProjectionSummaries).toEqual(
            expect.arrayContaining([
                expect.objectContaining({
                    coefficientModulus: '65537',
                    projectionCoverage: 'encoded-score-field-rows-only',
                    sourceBackendColumnCount: 176,
                    sourceRowBatchNames: ['encoded_score_field_rows'],
                    statementColumns: 176,
                    statementRows: 70,
                }),
                expect.objectContaining({
                    coefficientModulus: '65537',
                    projectionCoverage: 'payload-plaintext-field-rows-only',
                    sourceBackendColumnCount: 516,
                    sourceRowBatchNames: [
                        'receiver_payload_plaintext_binding_rows',
                    ],
                    statementColumns: 516,
                    statementRows: 258,
                }),
                expect.objectContaining({
                    coefficientModulus: '18446744069414584321',
                    projectionCoverage: 'share-commitment-rows-only',
                    sourceBackendColumnCount: 258,
                    sourceRowBatchNames: ['share_commitment_equation_rows'],
                    statementColumns: 258,
                    statementRows: 3_072,
                }),
            ]),
        );
        for (const projectionSummary of explicitCommitmentCase.componentProjectionSummaries ??
            []) {
            expect(projectionSummary.linearStatementDigest).toMatch(
                /^[a-f0-9]{128}$/u,
            );
            expect(projectionSummary.matrixDigest).toMatch(/^[a-f0-9]{128}$/u);
            expect(projectionSummary.targetVectorDigest).toMatch(
                /^[a-f0-9]{128}$/u,
            );
            expect(projectionSummary.ringDegree).toBe(1);
        }
    });
});
