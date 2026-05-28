// This file is one targeted part of the split test suite.
import { describe, expect, it } from 'vitest';

import { caseByName } from './shared.js';

describe('ballot privacy encoded relation vectors', () => {
    it('contains a mini relation summary with full explicit component coverage', () => {
        const fullExplicitCase = caseByName(
            'mini-encoded-ballot-full-explicit-relation',
        );

        expect(fullExplicitCase).toMatchObject({
            compilerAccepted: true,
            expectedOutcome: 'accept',
        });
        expect(fullExplicitCase.loweredStatement).toBeUndefined();
        expect(fullExplicitCase.loweredStatementSummary).toMatchObject({
            backendHashExpandedRowCount: 0,
            backendExplicitRowCount: 21_989,
            backendProofComponentCount: 5,
            backendRowBatchCount: 6,
            backendRowCount: 21_989,
            encodedCoordinateCount: 11,
            optionCount: 1,
            rosterSize: 3,
            shareVectorWidth: 11,
            variableCount: 31_018,
        });
        expect(fullExplicitCase.componentBundleSummary).toMatchObject({
            bundleCoverage: 'full-encoded-score-ballot-relation',
            componentCount: 5,
            explicitComponentCount: 5,
            pendingComponentIds: [],
            requiredComponentIds: [
                'score-and-shamir-field-component',
                'payload-plaintext-field-component',
                'share-commitment-component',
                'receiver-encryption-component',
                'receiver-key-binding-component',
            ],
        });
        expect(
            fullExplicitCase.componentBundleSummary
                ?.componentBundleStatementHash,
        ).toMatch(/^[a-f0-9]{128}$/u);
        expect(
            fullExplicitCase.loweredStatementSummary?.firstBackendRowBatch,
        ).toMatchObject({
            batchKind: 'ExplicitSparseRows',
            rowCount: 35,
            rowKind: 'EncodedScoreFieldRows',
        });
        expect(
            fullExplicitCase.loweredStatementSummary?.lastBackendRowBatch,
        ).toMatchObject({
            batchKind: 'ExplicitSparseRows',
            rowCount: 3_072,
            rowKind: 'ReceiverKeyBindingRows',
        });
        expect(
            fullExplicitCase.loweredStatementSummary?.lastProofComponent,
        ).toMatchObject({
            componentId: 'receiver-key-binding-component',
            proofLoweringStatus: 'explicitRowsAvailable',
            rowBatchNames: ['receiver_key_binding_rows'],
        });
        expect(fullExplicitCase.componentProjectionSummaries).toEqual(
            expect.arrayContaining([
                expect.objectContaining({
                    componentId: 'score-and-shamir-field-component',
                    projectionCoverage: 'encoded-score-field-rows-only',
                    sourceBackendColumnCount: 88,
                    statementColumns: 88,
                    statementRows: 35,
                }),
                expect.objectContaining({
                    componentId: 'payload-plaintext-field-component',
                    projectionCoverage: 'payload-plaintext-field-rows-only',
                    sourceBackendColumnCount: 3_315,
                    statementColumns: 3_315,
                    statementRows: 450,
                }),
                expect.objectContaining({
                    componentId: 'share-commitment-component',
                    projectionCoverage: 'share-commitment-rows-only',
                    sourceBackendColumnCount: 225,
                    statementColumns: 225,
                    statementRows: 3_072,
                }),
            ]),
        );
        expect(fullExplicitCase.proofReadinessSummary).toEqual({
            denseMatrixOracleComponentCount: 1,
            fullComponentProofBytesAvailable: false,
            publicZeroWitnessComponentCount: 1,
            sparseOrStructuredComponentCount: 3,
            totalComponentCount: 5,
        });
        expect(fullExplicitCase.componentProofReadinessManifests).toEqual([
            {
                coefficientModulus: '65537',
                componentId: 'score-and-shamir-field-component',
                denseCoefficientCount: '197120',
                denseMatrixOracleStatus: 'available-for-small-field-component',
                objectType: 'BallotProofComponentProofReadinessManifest',
                objectVersion: 1,
                proofLoweringStatus: 'explicitRowsAvailable',
                proofStatementFormat: 'dense-polynomial-matrix-linear-proof-v1',
                recommendedSourceRingDegree: 64,
                rowBatchNames: ['encoded_score_field_rows'],
                rowCount: 35,
                variableColumnCount: 88,
            },
            {
                coefficientModulus: '65537',
                componentId: 'payload-plaintext-field-component',
                denseCoefficientCount: '95472000',
                denseMatrixOracleStatus:
                    'blocked-pending-sparse-proof-statement',
                objectType: 'BallotProofComponentProofReadinessManifest',
                objectVersion: 1,
                proofLoweringStatus: 'explicitRowsAvailable',
                proofStatementFormat:
                    'sparse-polynomial-matrix-linear-proof-v1',
                recommendedSourceRingDegree: 64,
                rowBatchNames: [
                    'receiver_payload_plaintext_binding_rows',
                    'receiver_payload_plaintext_bit_decomposition_rows',
                ],
                rowCount: 450,
                variableColumnCount: 3_315,
            },
            {
                coefficientModulus: '18446744069414584321',
                componentId: 'share-commitment-component',
                denseCoefficientCount: '176947200',
                denseMatrixOracleStatus:
                    'blocked-pending-sparse-proof-statement',
                objectType: 'BallotProofComponentProofReadinessManifest',
                objectVersion: 1,
                proofLoweringStatus: 'explicitRowsAvailable',
                proofStatementFormat:
                    'sparse-polynomial-matrix-linear-proof-v1',
                recommendedSourceRingDegree: 256,
                rowBatchNames: ['share_commitment_equation_rows'],
                rowCount: 3_072,
                variableColumnCount: 225,
            },
            {
                coefficientModulus: '12289',
                componentId: 'receiver-encryption-component',
                denseCoefficientCount: '119981998080',
                denseMatrixOracleStatus:
                    'not-applicable-for-structured-component',
                objectType: 'BallotProofComponentProofReadinessManifest',
                objectVersion: 1,
                proofLoweringStatus: 'explicitRowsAvailable',
                proofStatementFormat: 'structured-module-lwe-linear-proof-v1',
                recommendedSourceRingDegree: 256,
                rowBatchNames: ['receiver_payload_encryption_equation_rows'],
                rowCount: 15_360,
                variableColumnCount: 30_513,
            },
            {
                coefficientModulus: '12289',
                componentId: 'receiver-key-binding-component',
                denseCoefficientCount: null,
                denseMatrixOracleStatus:
                    'not-applicable-for-public-zero-witness-component',
                objectType: 'BallotProofComponentProofReadinessManifest',
                objectVersion: 1,
                proofLoweringStatus: 'explicitRowsAvailable',
                proofStatementFormat: 'public-zero-witness-binding-check-v1',
                recommendedSourceRingDegree: null,
                rowBatchNames: ['receiver_key_binding_rows'],
                rowCount: 3_072,
                variableColumnCount: 0,
            },
        ]);
        expect(fullExplicitCase.componentProofStatementPlans).toEqual([
            expect.objectContaining({
                coefficientModulus: '65537',
                componentId: 'score-and-shamir-field-component',
                denseCoefficientCount: '197120',
                objectType: 'BallotProofComponentProofStatementPlan',
                objectVersion: 1,
                proofBytesAvailability: 'available-for-small-dense-oracle',
                proofStatementFormat: 'dense-polynomial-matrix-linear-proof-v1',
                proofSystemRingDegree: 64,
                rowBatchNames: ['encoded_score_field_rows'],
                rowBatchTermCounts: ['153'],
                rowCount: 35,
                sourceRingDegree: 64,
                variableColumnCount: 88,
            }),
            expect.objectContaining({
                coefficientModulus: '65537',
                componentId: 'payload-plaintext-field-component',
                denseCoefficientCount: '95472000',
                objectType: 'BallotProofComponentProofStatementPlan',
                objectVersion: 1,
                proofBytesAvailability: 'requires-sparse-proof-statement',
                proofStatementFormat:
                    'sparse-polynomial-matrix-linear-proof-v1',
                proofSystemRingDegree: 64,
                rowBatchNames: [
                    'receiver_payload_plaintext_binding_rows',
                    'receiver_payload_plaintext_bit_decomposition_rows',
                ],
                rowBatchTermCounts: ['450', '3090'],
                rowCount: 450,
                sparseTermCount: '3540',
                sourceRingDegree: 64,
                variableColumnCount: 3_315,
            }),
            expect.objectContaining({
                coefficientModulus: '18446744069414584321',
                componentId: 'share-commitment-component',
                denseCoefficientCount: '176947200',
                objectType: 'BallotProofComponentProofStatementPlan',
                objectVersion: 1,
                proofBytesAvailability: 'requires-sparse-proof-statement',
                proofStatementFormat:
                    'sparse-polynomial-matrix-linear-proof-v1',
                proofSystemRingDegree: 64,
                rowBatchNames: ['share_commitment_equation_rows'],
                rowBatchTermCounts: ['230400'],
                rowCount: 3_072,
                sparseTermCount: '230400',
                sourceRingDegree: 256,
                variableColumnCount: 225,
            }),
            expect.objectContaining({
                coefficientModulus: '12289',
                componentId: 'receiver-encryption-component',
                denseCoefficientCount: '119981998080',
                objectType: 'BallotProofComponentProofStatementPlan',
                objectVersion: 1,
                proofBytesAvailability: 'requires-structured-proof-statement',
                proofStatementFormat: 'structured-module-lwe-linear-proof-v1',
                proofSystemRingDegree: 64,
                rowBatchNames: ['receiver_payload_encryption_equation_rows'],
                rowBatchTermCounts: ['15746865'],
                rowCount: 15_360,
                sourceRingDegree: 256,
                structuredCiphertextChunkCount: 12,
                structuredReceiverCount: 3,
                structuredWitnessTermCount: '15746865',
                variableColumnCount: 30_513,
            }),
            expect.objectContaining({
                coefficientModulus: '12289',
                componentId: 'receiver-key-binding-component',
                denseCoefficientCount: null,
                objectType: 'BallotProofComponentProofStatementPlan',
                objectVersion: 1,
                proofBytesAvailability: 'public-zero-witness-binding-check',
                proofStatementFormat: 'public-zero-witness-binding-check-v1',
                proofSystemRingDegree: null,
                rowBatchNames: ['receiver_key_binding_rows'],
                rowBatchTermCounts: ['0'],
                rowCount: 3_072,
                sourceRingDegree: null,
                variableColumnCount: 0,
            }),
        ]);
        for (const proofStatementPlan of fullExplicitCase.componentProofStatementPlans ??
            []) {
            expect(proofStatementPlan.componentProofStatementHash).toMatch(
                /^[a-f0-9]{128}$/u,
            );
            expect(
                proofStatementPlan.rowBatchTermCounts.every((termCount) =>
                    /^(0|[1-9][0-9]*)$/u.test(termCount),
                ),
            ).toBe(true);
        }
        expect(
            JSON.stringify(fullExplicitCase.componentProofStatementPlans),
        ).not.toMatch(
            /normalizedScores|scoreOneHotWitnesses|receiverShareVector|privateWitness/u,
        );
        expect(fullExplicitCase.explicitComponentVerificationSummaries).toEqual(
            [
                {
                    checkedRowBatchNames: ['encoded_score_field_rows'],
                    componentId: 'score-and-shamir-field-component',
                    rowCount: 35,
                    verificationStatus: 'explicitRowsSatisfied',
                },
                {
                    checkedRowBatchNames: [
                        'receiver_payload_plaintext_binding_rows',
                        'receiver_payload_plaintext_bit_decomposition_rows',
                    ],
                    componentId: 'payload-plaintext-field-component',
                    rowCount: 450,
                    verificationStatus: 'explicitRowsSatisfied',
                },
                {
                    checkedRowBatchNames: ['share_commitment_equation_rows'],
                    componentId: 'share-commitment-component',
                    rowCount: 3_072,
                    verificationStatus: 'explicitRowsSatisfied',
                },
                {
                    checkedRowBatchNames: [
                        'receiver_payload_encryption_equation_rows',
                    ],
                    componentId: 'receiver-encryption-component',
                    rowCount: 15_360,
                    verificationStatus: 'explicitRowsSatisfied',
                },
                {
                    checkedRowBatchNames: ['receiver_key_binding_rows'],
                    componentId: 'receiver-key-binding-component',
                    rowCount: 3_072,
                    verificationStatus: 'explicitRowsSatisfied',
                },
            ],
        );
    });

    it('contains a mandatory-profile encoded relation summary without a multi-megabyte matrix fixture', () => {
        const mandatoryCase = caseByName(
            'mandatory-profile-encoded-ballot-relation',
        );

        expect(mandatoryCase).toMatchObject({
            compilerAccepted: true,
            expectedOutcome: 'accept',
        });
        expect(mandatoryCase.loweredStatement).toBeUndefined();
        expect(mandatoryCase.loweredStatementSummary).toMatchObject({
            algebraicRowCount: 60,
            backendColumnCount: 17_340,
            backendHashExpandedRowCount: 66_560,
            backendExplicitRowCount: 10_120,
            backendRowBatchCount: 62,
            backendRowCount: 76_680,
            backendStatementFormat: 'SparseSignedIntegerBackendStatement-v1',
            backendProofComponentCount: 5,
            boundCount: 212,
            encodedCoordinateCount: 220,
            linearRowCount: 10_120,
            optionCount: 20,
            relationStatementFormat:
                'SparseIntegerRowsModuloGF65537WithBoundGadgets-v1',
            rosterSize: 20,
            shareVectorWidth: 220,
            variableCount: 17_340,
        });
        expect(mandatoryCase.componentBundleSummary).toMatchObject({
            bundleCoverage: 'component-bundle-incomplete',
            componentCount: 5,
            explicitComponentCount: 2,
            firstComponentStatement: {
                componentId: 'score-and-shamir-field-component',
                proofLoweringStatus: 'explicitRowsAvailable',
            },
            lastComponentStatement: {
                componentId: 'receiver-key-binding-component',
                proofLoweringStatus: 'HashExpandedRowsPending',
            },
            pendingComponentIds: [
                'share-commitment-component',
                'receiver-encryption-component',
                'receiver-key-binding-component',
            ],
        });
        expect(
            mandatoryCase.componentBundleSummary?.componentBundleStatementHash,
        ).toMatch(/^[a-f0-9]{128}$/u);
        expect(
            mandatoryCase.loweredStatementSummary?.firstLinearRow,
        ).toMatchObject({
            rowKind: 'OneHotSum',
        });
        expect(
            mandatoryCase.loweredStatementSummary?.lastLinearRow,
        ).toMatchObject({
            rowKind: 'ReceiverPayloadOpeningPlaintextBinding',
        });
        expect(
            mandatoryCase.loweredStatementSummary?.firstAlgebraicRow,
        ).toMatchObject({
            equationCount: 1_024,
            rowKind: 'ShareCommitmentEquation',
        });
        expect(
            mandatoryCase.loweredStatementSummary?.lastAlgebraicRow,
        ).toMatchObject({
            equationCount: 1_024,
            rowKind: 'ReceiverKeyBinding',
        });
        expect(
            mandatoryCase.loweredStatementSummary?.firstProofComponent,
        ).toMatchObject({
            componentId: 'score-and-shamir-field-component',
            proofLoweringStatus: 'explicitRowsAvailable',
        });
        expect(
            mandatoryCase.loweredStatementSummary?.lastProofComponent,
        ).toMatchObject({
            componentId: 'receiver-key-binding-component',
            proofLoweringStatus: 'HashExpandedRowsPending',
        });
        expect(
            mandatoryCase.loweredStatementSummary?.firstBackendRowBatch,
        ).toMatchObject({
            batchKind: 'ExplicitSparseRows',
            rowCount: 4_440,
            rowKind: 'EncodedScoreFieldRows',
        });
        expect(
            mandatoryCase.loweredStatementSummary?.lastBackendRowBatch,
        ).toMatchObject({
            batchKind: 'HashExpandedRows',
            rowCount: 1_024,
            rowKind: 'ReceiverKeyBinding',
        });
    });

    it('records public commitment, payload, and receiver-key mutations as hash-changing vectors', () => {
        const caseNames = [
            'wrong-share-commitment-target-changes-hash',
            'wrong-receiver-payload-target-changes-hash',
            'wrong-receiver-key-target-changes-hash',
        ] as const;

        for (const caseName of caseNames) {
            const vectorCase = caseByName(caseName);

            expect(vectorCase).toMatchObject({
                compilerAccepted: true,
                expectedOutcome: 'accept',
            });
            expect(vectorCase.trace.expectedHashChanged).toBe(true);
            expect(vectorCase.trace.relationStatementHash).toMatch(
                /^[a-f0-9]{128}$/u,
            );
            expect(vectorCase.trace.relationStatementHash).not.toBe(
                vectorCase.trace.baselineRelationStatementHash,
            );
        }
    });

    it('records backend statement mutations as preflight reject vectors', () => {
        const caseNames = [
            'backend-matrix-row-mutation-rejects',
            'backend-target-vector-mutation-rejects',
            'backend-bound-mutation-rejects',
            'backend-proof-component-mutation-rejects',
            'backend-variable-order-mutation-rejects',
            'noncanonical-backend-coefficient-rejects',
            'truncated-backend-statement-rejects',
        ] as const;

        for (const caseName of caseNames) {
            const vectorCase = caseByName(caseName);

            expect(vectorCase).toMatchObject({
                compilerAccepted: true,
                expectedOutcome: 'reject',
            });
            expect(vectorCase.trace.expectedLogicalRejectionLayer).toBe(
                'backend-statement-preflight',
            );
            expect(vectorCase.loweredStatement).toBeDefined();
        }
    });

    it('records hostile relation compiler mutations as reject vectors', () => {
        const expectedRefusalSnippets = new Map([
            ['score-zero-rejects', 'score is outside the frozen score domain'],
            [
                'score-eleven-rejects',
                'score is outside the frozen score domain',
            ],
            [
                'malformed-one-hot-rejects',
                'score one-hot witness is not a valid score encoding',
            ],
            [
                'signed-cancellation-one-hot-rejects',
                'score one-hot witness is not a valid score encoding',
            ],
            [
                'wrong-quotient-rejects',
                'Shamir quotient constraint is not exact',
            ],
            ['wrong-degree-rejects', 'degree less than the PVSS threshold'],
            [
                'omitted-receiver-rejects',
                'one receiver entry for every roster position',
            ],
            [
                'duplicate-receiver-rejects',
                'receiver roster positions must be unique',
            ],
            ['nonzero-padding-rejects', 'share-vector padding must be zero'],
        ]);

        for (const [caseName, refusalSnippet] of expectedRefusalSnippets) {
            const vectorCase = caseByName(caseName);

            expect(vectorCase).toMatchObject({
                compilerAccepted: false,
                expectedOutcome: 'reject',
            });
            expect(
                vectorCase.refusalMessages?.some((message) =>
                    message.includes(refusalSnippet),
                ),
            ).toBe(true);
        }
    });
});
