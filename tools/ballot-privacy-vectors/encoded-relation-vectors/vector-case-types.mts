import type {
    BallotProofComponentBundleStatement,
    BallotProofComponentProofStatementPlan,
    BallotProofComponentStatement,
} from "#packages/protocol/src/ballot-privacy/ballot-proof-linear-statement.js";
import type { BallotPrivacyLoweredLinearRelationStatement } from "#packages/protocol/src/ballot-privacy/relation-backend-lowering.js";

export interface EncodedBallotRelationVectorCase {
    readonly caseName: string;
    readonly description: string;
    readonly mutation: string;
    readonly expectedOutcome: "accept" | "reject";
    readonly compilerAccepted: boolean;
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
            | "available-for-small-field-component"
            | "blocked-pending-sparse-proof-statement"
            | "not-applicable-for-structured-component"
            | "not-applicable-for-public-zero-witness-component";
        readonly objectType: "BallotProofComponentProofReadinessManifest";
        readonly objectVersion: 1;
        readonly proofLoweringStatus: string;
        readonly proofStatementFormat:
            | "dense-polynomial-matrix-linear-proof-v1"
            | "sparse-polynomial-matrix-linear-proof-v1"
            | "structured-module-sis-share-commitment-v1"
            | "structured-module-lwe-linear-proof-v1"
            | "public-zero-witness-binding-check-v1";
        readonly recommendedSourceRingDegree: number | null;
        readonly rowBatchNames: readonly string[];
        readonly rowCount: number;
        readonly variableColumnCount: number;
    }[];
    readonly componentProofStatementPlans?: readonly BallotProofComponentProofStatementPlan[];
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
        readonly verificationStatus: "explicitRowsSatisfied";
    }[];
    readonly componentBundleStatement?: BallotProofComponentBundleStatement;
    readonly componentBundleSummary?: {
        readonly bundleCoverage: string;
        readonly componentBundleStatementHash: string;
        readonly componentCount: number;
        readonly explicitComponentCount: number;
        readonly firstComponentStatement: BallotProofComponentStatement;
        readonly lastComponentStatement: BallotProofComponentStatement;
        readonly pendingComponentIds: readonly string[];
        readonly requiredComponentIds: readonly string[];
    };
    readonly loweredStatement?: BallotPrivacyLoweredLinearRelationStatement;
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
        readonly firstBackendRowBatch: unknown;
        readonly firstProofComponent: unknown;
        readonly firstAlgebraicRow: unknown;
        readonly firstBound: unknown;
        readonly firstLinearRow: unknown;
        readonly lastAlgebraicRow: unknown;
        readonly lastBackendRowBatch: unknown;
        readonly lastBound: unknown;
        readonly lastProofComponent: unknown;
        readonly lastLinearRow: unknown;
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
        readonly expectedLogicalRejectionLayer?:
            | "relation-compiler"
            | "backend-statement-preflight";
        readonly optionCount: number;
        readonly rosterSize: number;
        readonly pvssThreshold: number;
        readonly shareVectorWidth: number;
        readonly relationStatementHash?: string;
        readonly baselineRelationStatementHash?: string;
        readonly expectedHashChanged?: true;
    };
}
