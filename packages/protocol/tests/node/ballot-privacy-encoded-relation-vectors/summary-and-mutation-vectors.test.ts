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
            backendExplicitRowCount: 25_930,
            backendProofComponentCount: 5,
            backendRowBatchCount: 6,
            backendRowCount: 25_930,
            encodedCoordinateCount: 22,
            optionCount: 2,
            rosterSize: 3,
            shareVectorWidth: 22,
            variableCount: 38_612,
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
            rowCount: 70,
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
                    sourceBackendColumnCount: 176,
                    statementColumns: 176,
                    statementRows: 70,
                }),
                expect.objectContaining({
                    componentId: 'payload-plaintext-field-component',
                    projectionCoverage: 'payload-plaintext-field-rows-only',
                    sourceBackendColumnCount: 3_942,
                    statementColumns: 3_942,
                    statementRows: 516,
                }),
                expect.objectContaining({
                    componentId: 'share-commitment-component',
                    projectionCoverage: 'share-commitment-rows-only',
                    sourceBackendColumnCount: 258,
                    statementColumns: 258,
                    statementRows: 3_072,
                }),
            ]),
        );
        expect(fullExplicitCase.proofReadinessSummary).toEqual({
            denseMatrixOracleComponentCount: 1,
            fullComponentProofBytesAvailable: false,
            publicBindingCheckComponentCount: 1,
            sparseOrStructuredComponentCount: 3,
            totalComponentCount: 5,
        });
        expect(fullExplicitCase.componentProofReadinessManifests).toEqual([
            {
                coefficientModulus: '65537',
                componentId: 'score-and-shamir-field-component',
                denseCoefficientCount: '788480',
                denseMatrixOracleStatus: 'available-for-small-field-component',
                objectType: 'BallotProofComponentProofReadinessManifest',
                objectVersion: 1,
                proofLoweringStatus: 'explicitRowsAvailable',
                proofStatementFormat: 'dense-polynomial-matrix-linear-proof-v1',
                recommendedSourceRingDegree: 64,
                rowBatchNames: ['encoded_score_field_rows'],
                rowCount: 70,
                variableColumnCount: 176,
            },
            {
                coefficientModulus: '65537',
                componentId: 'payload-plaintext-field-component',
                denseCoefficientCount: '130180608',
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
                rowCount: 516,
                variableColumnCount: 3_942,
            },
            {
                coefficientModulus: '18446744069414584321',
                componentId: 'share-commitment-component',
                denseCoefficientCount: '202899456',
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
                variableColumnCount: 258,
            },
            {
                coefficientModulus: '12289',
                componentId: 'receiver-encryption-component',
                denseCoefficientCount: '186708787200',
                denseMatrixOracleStatus:
                    'not-applicable-for-structured-component',
                objectType: 'BallotProofComponentProofReadinessManifest',
                objectVersion: 1,
                proofLoweringStatus: 'explicitRowsAvailable',
                proofStatementFormat: 'structured-module-lwe-linear-proof-v1',
                recommendedSourceRingDegree: 256,
                rowBatchNames: ['receiver_payload_encryption_equation_rows'],
                rowCount: 19_200,
                variableColumnCount: 37_986,
            },
            {
                coefficientModulus: '12289',
                componentId: 'receiver-key-binding-component',
                denseCoefficientCount: null,
                denseMatrixOracleStatus:
                    'not-applicable-for-public-binding-check-component',
                objectType: 'BallotProofComponentProofReadinessManifest',
                objectVersion: 1,
                proofLoweringStatus: 'explicitRowsAvailable',
                proofStatementFormat: 'public-binding-check-only-v1',
                recommendedSourceRingDegree: null,
                rowBatchNames: ['receiver_key_binding_rows'],
                rowCount: 3_072,
                variableColumnCount: 0,
            },
        ]);
        expect(fullExplicitCase.componentProofStatementDescriptors).toEqual([
            expect.objectContaining({
                coefficientModulus: '65537',
                componentId: 'score-and-shamir-field-component',
                denseCoefficientCount: '788480',
                objectType: 'BallotProofComponentProofStatementDescriptor',
                objectVersion: 1,
                proofBackendRequirement: 'dense-proof-bytes-available-lab-only',
                proofStatementFormat: 'dense-polynomial-matrix-linear-proof-v1',
                proofSystemRingDegree: 64,
                rowBatchNames: ['encoded_score_field_rows'],
                rowBatchTermCounts: ['306'],
                rowCount: 70,
                sourceRingDegree: 64,
                variableColumnCount: 176,
            }),
            expect.objectContaining({
                coefficientModulus: '65537',
                componentId: 'payload-plaintext-field-component',
                denseCoefficientCount: '130180608',
                objectType: 'BallotProofComponentProofStatementDescriptor',
                objectVersion: 1,
                proofBackendRequirement: 'sparse-proof-statement-required',
                proofStatementFormat:
                    'sparse-polynomial-matrix-linear-proof-v1',
                proofSystemRingDegree: 64,
                rowBatchNames: [
                    'receiver_payload_plaintext_binding_rows',
                    'receiver_payload_plaintext_bit_decomposition_rows',
                ],
                rowBatchTermCounts: ['516', '3684'],
                rowCount: 516,
                sparseTermCount: '4200',
                sourceRingDegree: 64,
                variableColumnCount: 3_942,
            }),
            expect.objectContaining({
                coefficientModulus: '18446744069414584321',
                componentId: 'share-commitment-component',
                denseCoefficientCount: '202899456',
                objectType: 'BallotProofComponentProofStatementDescriptor',
                objectVersion: 1,
                proofBackendRequirement: 'sparse-proof-statement-required',
                proofStatementFormat:
                    'sparse-polynomial-matrix-linear-proof-v1',
                proofSystemRingDegree: 64,
                rowBatchNames: ['share_commitment_equation_rows'],
                rowBatchTermCounts: ['264192'],
                rowCount: 3_072,
                sparseTermCount: '264192',
                sourceRingDegree: 256,
                variableColumnCount: 258,
            }),
            expect.objectContaining({
                coefficientModulus: '12289',
                componentId: 'receiver-encryption-component',
                denseCoefficientCount: '186708787200',
                objectType: 'BallotProofComponentProofStatementDescriptor',
                objectVersion: 1,
                proofBackendRequirement: 'structured-proof-statement-required',
                proofStatementFormat: 'structured-module-lwe-linear-proof-v1',
                proofSystemRingDegree: 64,
                rowBatchNames: ['receiver_payload_encryption_equation_rows'],
                rowBatchTermCounts: ['19683426'],
                rowCount: 19_200,
                sourceRingDegree: 256,
                structuredCiphertextChunkCount: 15,
                structuredReceiverCount: 3,
                structuredWitnessTermCount: '19683426',
                variableColumnCount: 37_986,
            }),
            expect.objectContaining({
                coefficientModulus: '12289',
                componentId: 'receiver-key-binding-component',
                denseCoefficientCount: null,
                objectType: 'BallotProofComponentProofStatementDescriptor',
                objectVersion: 1,
                proofBackendRequirement: 'public-binding-check-only',
                proofStatementFormat: 'public-binding-check-only-v1',
                proofSystemRingDegree: null,
                rowBatchNames: ['receiver_key_binding_rows'],
                rowBatchTermCounts: ['0'],
                rowCount: 3_072,
                sourceRingDegree: null,
                variableColumnCount: 0,
            }),
        ]);
        for (const proofStatementDescriptor of fullExplicitCase.componentProofStatementDescriptors ??
            []) {
            expect(
                proofStatementDescriptor.componentProofStatementHash,
            ).toMatch(/^[a-f0-9]{128}$/u);
            expect(
                proofStatementDescriptor.rowBatchTermCounts.every((termCount) =>
                    /^(0|[1-9][0-9]*)$/u.test(termCount),
                ),
            ).toBe(true);
        }
        expect(
            JSON.stringify(fullExplicitCase.componentProofStatementDescriptors),
        ).not.toMatch(
            /normalizedScores|scoreOneHotWitnesses|receiverShareVector|privateWitness/u,
        );
        expect(fullExplicitCase.explicitComponentVerificationSummaries).toEqual(
            [
                {
                    checkedRowBatchNames: ['encoded_score_field_rows'],
                    componentId: 'score-and-shamir-field-component',
                    rowCount: 70,
                    verificationStatus: 'explicitRowsSatisfied',
                },
                {
                    checkedRowBatchNames: [
                        'receiver_payload_plaintext_binding_rows',
                        'receiver_payload_plaintext_bit_decomposition_rows',
                    ],
                    componentId: 'payload-plaintext-field-component',
                    rowCount: 516,
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
                    rowCount: 19_200,
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
