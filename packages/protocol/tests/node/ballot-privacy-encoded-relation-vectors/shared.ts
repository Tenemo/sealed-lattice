// Shared ballot privacy encoded relation vector fixtures.
import encodedRelationVectorsJson from '#test-vectors/ballot-privacy/encoded-ballot-linear-relation-vectors.json';

type EncodedRelationVectorCase = {
    readonly caseName: string;
    readonly compilerAccepted: boolean;
    readonly componentBundleStatement?: {
        readonly bundleCoverage: string;
        readonly componentBundleStatementHash: string;
        readonly componentStatements: readonly {
            readonly componentId: string;
            readonly componentStatementHash: string;
            readonly proofLoweringStatus: string;
            readonly rowBatchMatrixHashes: readonly string[];
            readonly rowBatchNames: readonly string[];
            readonly rowBatchTargetVectorHashes: readonly string[];
        }[];
        readonly requiredComponentIds: readonly string[];
    };
    readonly componentBundleSummary?: {
        readonly bundleCoverage: string;
        readonly componentBundleStatementHash: string;
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
        readonly linearStatementHash: string;
        readonly matrixHash: string;
        readonly parameterProfileId: string;
        readonly projectionCoverage: string;
        readonly ringDegree: number;
        readonly sourceBackendColumnCount: number;
        readonly sourceRowBatchNames: readonly string[];
        readonly statementColumns: number;
        readonly statementRows: number;
        readonly targetVectorHash: string;
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
            | 'not-applicable-for-public-binding-check-component';
        readonly objectType: 'BallotProofComponentProofReadinessManifest';
        readonly objectVersion: 1;
        readonly proofLoweringStatus: string;
        readonly proofStatementFormat:
            | 'dense-polynomial-matrix-linear-proof-v1'
            | 'sparse-polynomial-matrix-linear-proof-v1'
            | 'structured-module-lwe-linear-proof-v1'
            | 'public-binding-check-only-v1';
        readonly recommendedSourceRingDegree: number | null;
        readonly rowBatchNames: readonly string[];
        readonly rowCount: number;
        readonly variableColumnCount: number;
    }[];
    readonly componentProofStatementDescriptors?: readonly {
        readonly coefficientModulus: string;
        readonly componentId: string;
        readonly componentProofStatementHash: string;
        readonly denseCoefficientCount: string | null;
        readonly objectType: 'BallotProofComponentProofStatementDescriptor';
        readonly objectVersion: 1;
        readonly proofBackendRequirement:
            | 'dense-proof-bytes-available-lab-only'
            | 'sparse-proof-statement-required'
            | 'structured-proof-statement-required'
            | 'public-binding-check-only';
        readonly proofStatementFormat:
            | 'dense-polynomial-matrix-linear-proof-v1'
            | 'sparse-polynomial-matrix-linear-proof-v1'
            | 'structured-module-lwe-linear-proof-v1'
            | 'public-binding-check-only-v1';
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
        readonly publicBindingCheckComponentCount: number;
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
            readonly targetHash: string;
            readonly variableNames: readonly string[];
        }[];
        readonly backendStatement: {
            readonly backendStatementHash: string;
            readonly backendStatementFormat: string;
            readonly bounds: readonly unknown[];
            readonly columnCount: number;
            readonly hashExpandedRowCount: number;
            readonly explicitRowCount: number;
            readonly proofComponents: readonly {
                readonly componentId: string;
                readonly coefficientModulus: string;
                readonly proofLoweringStatus: string;
                readonly rowCount: number;
                readonly rowKinds: readonly string[];
                readonly variableColumnCount: number;
            }[];
            readonly proofComponentsHash: string;
            readonly rowBatches: readonly {
                readonly batchKind: string;
                readonly matrixHash: string;
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
                readonly targetVectorHash: string;
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
        readonly relationStatementHash: string;
        readonly relationStatementFormat: string;
        readonly rosterSize: number;
        readonly shareVectorWidth: number;
        readonly variables: readonly unknown[];
    };
    readonly loweredStatementSummary?: {
        readonly algebraicRowCount: number;
        readonly backendColumnCount: number;
        readonly backendHashExpandedRowCount: number;
        readonly backendExplicitRowCount: number;
        readonly backendProofComponentCount: number;
        readonly backendRowBatchCount: number;
        readonly backendRowCount: number;
        readonly backendStatementHash: string;
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
        readonly relationStatementHash: string;
        readonly relationStatementFormat: string;
        readonly rosterSize: number;
        readonly shareVectorWidth: number;
        readonly variableCount: number;
    };
    readonly refusalMessages?: readonly string[];
    readonly trace: {
        readonly baselineRelationStatementHash?: string;
        readonly expectedHashChanged?: true;
        readonly expectedLogicalRejectionLayer?:
            | 'relation-compiler'
            | 'backend-statement-preflight';
        readonly relationStatementHash?: string;
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
