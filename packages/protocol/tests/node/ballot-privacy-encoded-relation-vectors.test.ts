import { describe, expect, it } from 'vitest';

import encodedRelationVectorsJson from '../../../../test-vectors/ballot-privacy/encoded-ballot-linear-relation-vectors.json';

type EncodedRelationVectorCase = {
    readonly caseName: string;
    readonly compilerAccepted: boolean;
    readonly componentBundleStatement?: {
        readonly bundleCoverage: string;
        readonly componentBundleStatementDigest: string;
        readonly componentStatements: readonly {
            readonly componentId: string;
            readonly componentStatementDigest: string;
            readonly proofLoweringStatus: string;
            readonly rowBatchMatrixDigests: readonly string[];
            readonly rowBatchNames: readonly string[];
            readonly rowBatchTargetVectorDigests: readonly string[];
        }[];
        readonly requiredComponentIds: readonly string[];
    };
    readonly componentBundleSummary?: {
        readonly bundleCoverage: string;
        readonly componentBundleStatementDigest: string;
        readonly componentCount: number;
        readonly explicitComponentCount: number;
        readonly firstComponentStatement: {
            readonly componentId: string;
            readonly proofLoweringStatus: string;
        };
        readonly lastComponentStatement: {
            readonly componentId: string;
            readonly proofLoweringStatus: string;
        };
        readonly pendingComponentIds: readonly string[];
        readonly requiredComponentIds: readonly string[];
    };
    readonly componentProjectionSummaries?: readonly {
        readonly coefficientModulus: string;
        readonly componentId: string;
        readonly linearStatementDigest: string;
        readonly matrixDigest: string;
        readonly parameterProfileId: string;
        readonly projectionCoverage: string;
        readonly ringDegree: number;
        readonly sourceBackendColumnCount: number;
        readonly sourceRowBatchNames: readonly string[];
        readonly statementColumns: number;
        readonly statementRows: number;
        readonly targetVectorDigest: string;
        readonly witnessL2BoundSquared: string;
    }[];
    readonly componentProofReadinessManifests?: readonly {
        readonly coefficientModulus: string;
        readonly componentId: string;
        readonly denseCoefficientCount: string | null;
        readonly denseMatrixOracleStatus:
            | 'available-for-small-field-component'
            | 'blocked-pending-sparse-proof-statement'
            | 'not-applicable-for-structured-component'
            | 'not-applicable-for-public-zero-witness-component';
        readonly objectType: 'BallotProofComponentProofReadinessManifest';
        readonly objectVersion: 1;
        readonly proofLoweringStatus: string;
        readonly proofStatementFormat:
            | 'dense-polynomial-matrix-linear-proof-v1'
            | 'sparse-polynomial-matrix-linear-proof-v1'
            | 'structured-module-lwe-linear-proof-v1'
            | 'public-zero-witness-binding-check-v1';
        readonly recommendedSourceRingDegree: number | null;
        readonly rowBatchNames: readonly string[];
        readonly rowCount: number;
        readonly variableColumnCount: number;
    }[];
    readonly componentProofStatementPlans?: readonly {
        readonly coefficientModulus: string;
        readonly componentId: string;
        readonly componentProofStatementDigest: string;
        readonly denseCoefficientCount: string | null;
        readonly objectType: 'BallotProofComponentProofStatementPlan';
        readonly objectVersion: 1;
        readonly proofBytesAvailability:
            | 'available-for-small-dense-oracle'
            | 'requires-sparse-proof-statement'
            | 'requires-structured-proof-statement'
            | 'public-zero-witness-binding-check';
        readonly proofStatementFormat:
            | 'dense-polynomial-matrix-linear-proof-v1'
            | 'sparse-polynomial-matrix-linear-proof-v1'
            | 'structured-module-lwe-linear-proof-v1'
            | 'public-zero-witness-binding-check-v1';
        readonly proofSystemRingDegree: number | null;
        readonly rowBatchNames: readonly string[];
        readonly rowBatchTermCounts: readonly string[];
        readonly rowCount: number;
        readonly sparseTermCount: string | null;
        readonly sourceRingDegree: number | null;
        readonly structuredCiphertextChunkCount: number | null;
        readonly structuredReceiverCount: number | null;
        readonly structuredWitnessTermCount: string | null;
        readonly variableColumnCount: number;
    }[];
    readonly proofReadinessSummary?: {
        readonly denseMatrixOracleComponentCount: number;
        readonly fullComponentProofBytesAvailable: false;
        readonly publicZeroWitnessComponentCount: number;
        readonly sparseOrStructuredComponentCount: number;
        readonly totalComponentCount: number;
    };
    readonly explicitComponentVerificationSummaries?: readonly {
        readonly checkedRowBatchNames: readonly string[];
        readonly componentId: string;
        readonly rowCount: number;
        readonly verificationStatus: 'explicitRowsSatisfied';
    }[];
    readonly expectedOutcome: 'accept' | 'reject';
    readonly loweredStatement?: {
        readonly algebraicRows: readonly {
            readonly equationCount: number;
            readonly rowKind: string;
            readonly targetDigest: string;
            readonly variableNames: readonly string[];
        }[];
        readonly backendStatement: {
            readonly backendStatementDigest: string;
            readonly backendStatementFormat: string;
            readonly bounds: readonly unknown[];
            readonly columnCount: number;
            readonly digestExpandedRowCount: number;
            readonly explicitRowCount: number;
            readonly proofComponents: readonly {
                readonly componentId: string;
                readonly coefficientModulus: string;
                readonly proofLoweringStatus: string;
                readonly rowCount: number;
                readonly rowKinds: readonly string[];
                readonly variableColumnCount: number;
            }[];
            readonly proofComponentsDigest: string;
            readonly rowBatches: readonly {
                readonly batchKind: string;
                readonly matrixDigest: string;
                readonly rowCount: number;
                readonly rowKind: string;
                readonly rowOffset: number;
                readonly rows?: readonly {
                    readonly rowKind: string;
                    readonly target: string;
                    readonly terms: readonly {
                        readonly coefficient: string;
                        readonly variableName: string;
                    }[];
                }[];
                readonly targetVectorDigest: string;
            }[];
            readonly rowCount: number;
        };
        readonly bounds: readonly unknown[];
        readonly encodedCoordinateCount: number;
        readonly linearRows: readonly {
            readonly rowKind: string;
            readonly terms: readonly {
                readonly coefficient: number;
                readonly variableName: string;
            }[];
        }[];
        readonly optionCount: number;
        readonly relationStatementDigest: string;
        readonly relationStatementFormat: string;
        readonly rosterSize: number;
        readonly shareVectorWidth: number;
        readonly variables: readonly unknown[];
    };
    readonly loweredStatementSummary?: {
        readonly algebraicRowCount: number;
        readonly backendColumnCount: number;
        readonly backendDigestExpandedRowCount: number;
        readonly backendExplicitRowCount: number;
        readonly backendProofComponentCount: number;
        readonly backendRowBatchCount: number;
        readonly backendRowCount: number;
        readonly backendStatementDigest: string;
        readonly backendStatementFormat: string;
        readonly boundCount: number;
        readonly encodedCoordinateCount: number;
        readonly firstBackendRowBatch: {
            readonly batchKind: string;
            readonly rowCount: number;
            readonly rowKind: string;
        };
        readonly firstProofComponent: {
            readonly componentId: string;
            readonly proofLoweringStatus: string;
        };
        readonly firstAlgebraicRow: {
            readonly equationCount: number;
            readonly rowKind: string;
        };
        readonly firstLinearRow: {
            readonly rowKind: string;
            readonly terms: readonly {
                readonly coefficient: number;
                readonly variableName: string;
            }[];
        };
        readonly lastAlgebraicRow: {
            readonly equationCount: number;
            readonly rowKind: string;
        };
        readonly lastBackendRowBatch: {
            readonly batchKind: string;
            readonly rowCount: number;
            readonly rowKind: string;
        };
        readonly lastProofComponent: {
            readonly componentId: string;
            readonly proofLoweringStatus: string;
        };
        readonly lastLinearRow: {
            readonly rowKind: string;
            readonly terms: readonly {
                readonly coefficient: number;
                readonly variableName: string;
            }[];
        };
        readonly linearRowCount: number;
        readonly optionCount: number;
        readonly relationStatementDigest: string;
        readonly relationStatementFormat: string;
        readonly rosterSize: number;
        readonly shareVectorWidth: number;
        readonly variableCount: number;
    };
    readonly refusalMessages?: readonly string[];
    readonly trace: {
        readonly baselineRelationStatementDigest?: string;
        readonly expectedDigestChanged?: true;
        readonly expectedLogicalRejectionLayer?:
            | 'relation-compiler'
            | 'backend-statement-preflight';
        readonly relationStatementDigest?: string;
    };
};

type EncodedRelationVectorFile = {
    readonly objectType: 'BallotPrivacyEncodedBallotLinearRelationVectors';
    readonly objectVersion: 1;
    readonly profileId: 'encoded-ballot-linear-relation-v1';
    readonly generationStatus: 'generated';
    readonly requiredCaseNames: readonly string[];
    readonly statementFormat: string;
    readonly cases: readonly EncodedRelationVectorCase[];
};

const encodedRelationVectors =
    encodedRelationVectorsJson as EncodedRelationVectorFile;
const forbiddenPublicVectorKeys = new Set([
    'encodedCoordinateShamirCoefficients',
    'errorVector',
    'normalizedScores',
    'privateWitness',
    'ciphertextChunks',
    'encryptionRandomness',
    'openingRandomness',
    'proofRandomness',
    'receiverShareVector',
    'scoreOneHotWitnesses',
    'secretState',
    'secretVector',
    'witness',
]);

const collectObjectKeys = (value: unknown, keys: Set<string>): void => {
    if (Array.isArray(value)) {
        for (const item of value) {
            collectObjectKeys(item, keys);
        }

        return;
    }
    if (value !== null && typeof value === 'object') {
        for (const [key, child] of Object.entries(value)) {
            keys.add(key);
            collectObjectKeys(child, keys);
        }
    }
};

const caseByName = (caseName: string): EncodedRelationVectorCase => {
    const vectorCase = encodedRelationVectors.cases.find(
        (candidate) => candidate.caseName === caseName,
    );
    if (vectorCase === undefined) {
        throw new Error(`Missing encoded relation vector case ${caseName}.`);
    }

    return vectorCase;
};

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
            backendDigestExpandedRowCount: 0,
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
                ?.componentBundleStatementDigest,
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
            expect(proofStatementPlan.componentProofStatementDigest).toMatch(
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
            backendDigestExpandedRowCount: 66_560,
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
                proofLoweringStatus: 'digestExpandedRowsPending',
            },
            pendingComponentIds: [
                'share-commitment-component',
                'receiver-encryption-component',
                'receiver-key-binding-component',
            ],
        });
        expect(
            mandatoryCase.componentBundleSummary
                ?.componentBundleStatementDigest,
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
            proofLoweringStatus: 'digestExpandedRowsPending',
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
            batchKind: 'DigestExpandedRows',
            rowCount: 1_024,
            rowKind: 'ReceiverKeyBinding',
        });
    });

    it('records public commitment, payload, and receiver-key mutations as digest-changing vectors', () => {
        const caseNames = [
            'wrong-share-commitment-target-changes-digest',
            'wrong-receiver-payload-target-changes-digest',
            'wrong-receiver-key-target-changes-digest',
        ] as const;

        for (const caseName of caseNames) {
            const vectorCase = caseByName(caseName);

            expect(vectorCase).toMatchObject({
                compilerAccepted: true,
                expectedOutcome: 'accept',
            });
            expect(vectorCase.trace.expectedDigestChanged).toBe(true);
            expect(vectorCase.trace.relationStatementDigest).toMatch(
                /^[a-f0-9]{128}$/u,
            );
            expect(vectorCase.trace.relationStatementDigest).not.toBe(
                vectorCase.trace.baselineRelationStatementDigest,
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
