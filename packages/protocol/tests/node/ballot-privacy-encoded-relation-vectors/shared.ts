// Shared ballot privacy encoded relation vector fixtures.
import encodedRelationVectorsJson from '../../../../../test-vectors/ballot-privacy/encoded-ballot-linear-relation-vectors.json';

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

export {
    encodedRelationVectors,
    forbiddenPublicVectorKeys,
    collectObjectKeys,
    caseByName,
};
