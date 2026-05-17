import { describe, expect, it } from 'vitest';

import encodedRelationVectorsJson from '../../../../test-vectors/ballot-privacy/encoded-ballot-linear-relation-vectors.json';

type EncodedRelationVectorCase = {
    readonly caseName: string;
    readonly compilerAccepted: boolean;
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
    'commitmentPolynomialVector',
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
        expect(miniCase.loweredStatement?.linearRows).toHaveLength(70);
        expect(miniCase.loweredStatement?.algebraicRows).toHaveLength(12);
        expect(miniCase.loweredStatement?.variables).toHaveLength(374);
        expect(miniCase.loweredStatement?.bounds).toHaveLength(27);
        expect(miniCase.loweredStatement?.backendStatement).toMatchObject({
            backendStatementFormat: 'SparseSignedIntegerBackendStatement-v1',
            columnCount: 374,
            digestExpandedRowCount: 10_242,
            explicitRowCount: 70,
            rowCount: 10_312,
        });
        expect(
            miniCase.loweredStatement?.backendStatement.backendStatementDigest,
        ).toMatch(/^[a-f0-9]{128}$/u);
        expect(
            miniCase.loweredStatement?.backendStatement.rowBatches,
        ).toHaveLength(13);
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
        const firstPlaintextBindingRow =
            miniCase.loweredStatement?.algebraicRows.find(
                (row) => row.rowKind === 'ReceiverPayloadPlaintextBinding',
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
        expect(firstPlaintextBindingRow?.equationCount).toBe(86);
        expect(firstEncryptionRow?.equationCount).toBe(1_280);
        expect(firstEncryptionRow?.variableNames).toEqual(
            expect.arrayContaining([
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
            algebraicRowCount: 80,
            backendColumnCount: 11_660,
            backendDigestExpandedRowCount: 72_240,
            backendExplicitRowCount: 4_440,
            backendRowBatchCount: 81,
            backendRowCount: 76_680,
            backendStatementFormat: 'SparseSignedIntegerBackendStatement-v1',
            boundCount: 207,
            encodedCoordinateCount: 220,
            linearRowCount: 4_440,
            optionCount: 20,
            relationStatementFormat:
                'SparseIntegerRowsModuloGF65537WithBoundGadgets-v1',
            rosterSize: 20,
            shareVectorWidth: 220,
            variableCount: 11_660,
        });
        expect(
            mandatoryCase.loweredStatementSummary?.firstLinearRow,
        ).toMatchObject({
            rowKind: 'OneHotSum',
        });
        expect(
            mandatoryCase.loweredStatementSummary?.lastLinearRow,
        ).toMatchObject({
            rowKind: 'ShamirEvaluationQuotient',
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
