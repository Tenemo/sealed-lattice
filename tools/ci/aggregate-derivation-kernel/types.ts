import type { RunnerTarget } from './config.js';

import type { createPendingBridgeProofRecordFromBridgeEvidence } from '#packages/protocol/src/ballot-privacy/aggregate-bridge/structure-verification.js';
import type {
    buildAggregateDerivationProofInput,
    buildAggregateDerivationStatement,
    createAggregateDerivationComponent,
    sumAggregateDerivationWitnesses,
} from '#packages/protocol/src/ballot-privacy/index';
import type { createMandatoryProfileBallotProofRecordBenchmarkFixture } from '#packages/protocol/tests/node/ballot-privacy-proof-record-generation-fixtures/fixture-assembly.js';
import type {
    AggregateContribution,
    ClaimBearingBallotPackage,
    ShareCommitmentMessageBoundCert,
} from '#packages/types/src/index';
import type { loadTranscriptCoreKernel } from '#packages/wasm/src/index';
import type { TopKEvaluatorEncryptedAggregateInput } from '#packages/wasm/src/transcript-core-bridge/kernel-types';

export type TranscriptCoreKernel = Awaited<
    ReturnType<typeof loadTranscriptCoreKernel>
>;
export type AggregateFixture = ReturnType<
    typeof createMandatoryProfileBallotProofRecordBenchmarkFixture
>;
export type AggregateStatementInput = Parameters<
    typeof buildAggregateDerivationStatement
>[0];
export type AggregateStatementBuild = ReturnType<
    typeof buildAggregateDerivationStatement
>;
export type AggregateWitness = ReturnType<
    typeof sumAggregateDerivationWitnesses
>;
export type AggregateProofBuild = ReturnType<
    typeof buildAggregateDerivationProofInput
>;
export type AggregateProofGeneration = ReturnType<
    TranscriptCoreKernel['generateAggregateDerivationProof']
>;
export type AggregateComponent = ReturnType<
    typeof createAggregateDerivationComponent
>;
export type PendingBridgeProofRecordInput = Parameters<
    typeof createPendingBridgeProofRecordFromBridgeEvidence
>[0];

export type PostCloseEvidence = {
    readonly closeRecord: Record<string, unknown>;
    readonly closeRecordHash: string;
    readonly contributorActionContext: Record<string, unknown>;
    readonly postVotingClosedContextHash: string;
};

export type BallotPackageCheckpoint = {
    readonly ballotPackage: ClaimBearingBallotPackage;
    readonly ballotPackageWithoutProofBytes: ClaimBearingBallotPackage;
    readonly ballotProofGeneration: Record<string, unknown>;
    readonly certificate: ShareCommitmentMessageBoundCert;
    readonly fixtureStatementHash: string;
    readonly postCloseEvidence: PostCloseEvidence;
    readonly statementInput: AggregateStatementInput;
};

export type BallotPackageContext = BallotPackageCheckpoint & {
    readonly fixture: AggregateFixture;
    readonly kernel: TranscriptCoreKernel;
};

export type AggregateComponentContext = BallotPackageContext &
    AggregateStatementBuild & {
        readonly component: AggregateComponent;
        readonly generatedAggregateProof: AggregateProofGeneration;
        readonly postCloseEvidence: PostCloseEvidence;
        readonly proofBuild: AggregateProofBuild;
        readonly statementInput: AggregateStatementInput;
        readonly witness: AggregateWitness;
    };

export type ComponentCheckpoint = Omit<
    AggregateComponentContext,
    'fixture' | 'kernel'
>;

export type BridgeContributorCheckpoint = {
    readonly bridgeEncryption: Record<string, unknown>;
    readonly bridgeVerification: Record<string, unknown>;
    readonly contribution: AggregateContribution;
    readonly encryptedAggregateInput: TopKEvaluatorEncryptedAggregateInput;
    readonly receiver: number;
};

export type BridgeSupportHashes = {
    readonly aggregateSelectionPolicyHash: string;
    readonly bridgeWitnessPrivacyProfileHash: string;
    readonly heParamHash: string;
};

export type WorkerRunConfig = {
    readonly checkpointDir: string;
    readonly dependencyArtifactHash: string;
    readonly forceRecompute: readonly string[];
    readonly kernelHash: string;
    readonly receiver: number;
    readonly requireCheckpoints: boolean;
    readonly resumeCheckpoints: boolean;
    readonly setupPackage?: Record<string, unknown>;
    readonly sourceFingerprint: string;
    readonly supportHashes?: BridgeSupportHashes;
    readonly target: RunnerTarget;
};

export type WorkerResult =
    | {
          readonly componentHash: string;
          readonly receiver: number;
          readonly statementHash: string;
          readonly workerJob: 'component-receiver';
      }
    | (BridgeContributorCheckpoint & {
          readonly cachedFreshCsprngArtifact: boolean;
          readonly fromCheckpoint: boolean;
          readonly workerJob: 'bridge-contributor';
      });

export type RunnerSummary = {
    readonly aggregateReadyRecordHash: string;
    readonly bridgeContributorCount: number;
    readonly checkpointDir: string;
    readonly durationMilliseconds: number;
    readonly aggregateReadyVerificationStatus: string;
    readonly objectType: 'AggregateDerivationKernelRunSummary';
    readonly objectVersion: 1;
    readonly reusedCachedFreshCsprngArtifacts: boolean;
    readonly target: RunnerTarget;
    readonly workerCount: number;
};
