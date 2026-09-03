import type {
    FinalitySignatureCarrier,
    SourceCarrier,
} from './finality-runtime.js';
import type {
    FoundationKernelLoaderOptions,
    KernelResourceMeasurement,
} from './foundation-kernel/kernel-runtime.js';
import type { PaddedTallyPlan } from './padded-tally-runtime.js';
import type { PreparationParentCarrier } from './source-runtime.js';

export type PrivatePreparationWorkerInitialization = Readonly<{
    databaseName: string;
    kernelUrl: string;
    kernelOptions: FoundationKernelLoaderOptions;
    runtimeIdentity: Uint8Array;
    candidateBuildIdentity: Uint8Array;
}>;

export type PrivatePreparationActionContext = Readonly<{
    actionProposalIdentity: Uint8Array;
    actionDefinitionIdentity: Uint8Array;
    predecessorIdentity: Uint8Array;
    participantPosition: number;
}>;

export type SourcePublicationChoice =
    | Readonly<{ declaration: 'abstain' }>
    | Readonly<{ declaration: 'submit'; scoreEncodings: Uint8Array }>;

export type PrivatePreparationWorkerRequest =
    | Readonly<{
          requestId: number;
          operation: 'initialize';
          input: PrivatePreparationWorkerInitialization;
      }>
    | Readonly<{
          requestId: number;
          operation: 'create-preparation-package';
          input: PrivatePreparationActionContext & {
              canonicalRosterBytes: Uint8Array;
              signingSecretKey: Uint8Array;
              mailboxDecapsulationKey: Uint8Array;
              preparationAttempt: number;
          };
      }>
    | Readonly<{
          requestId: number;
          operation: 'consume-private-preparation';
          input: PrivatePreparationActionContext & {
              canonicalRosterBytes: Uint8Array;
              preparationAttempt: number;
              parentBody: Uint8Array;
              parentSignature: Uint8Array;
              privateBody: Uint8Array;
          };
      }>
    | Readonly<{
          requestId: number;
          operation: 'create-source-package';
          input: PrivatePreparationActionContext & {
              canonicalRosterBytes: Uint8Array;
              preparationAttempt: number;
              preparationParents: readonly PreparationParentCarrier[];
              choice: SourcePublicationChoice;
          };
      }>
    | Readonly<{
          requestId: number;
          operation: 'create-finality-signature';
          input: PrivatePreparationActionContext & {
              canonicalRosterBytes: Uint8Array;
              preparationAttempt: number;
              sources: readonly SourceCarrier[];
              topCount: number;
          };
      }>
    | Readonly<{
          requestId: number;
          operation: 'finalize-no-result';
          input: PrivatePreparationActionContext & {
              canonicalRosterBytes: Uint8Array;
              preparationAttempt: number;
              sources: readonly SourceCarrier[];
              finalitySignatures: readonly FinalitySignatureCarrier[];
              topCount: number;
          };
      }>
    | Readonly<{
          requestId: number;
          operation: 'initialize-padded-tally-generation';
          input: PrivatePreparationActionContext & {
              canonicalRosterBytes: Uint8Array;
              preparationAttempt: number;
              preparationParents: readonly PreparationParentCarrier[];
              sources: readonly SourceCarrier[];
              finalitySignatures: readonly FinalitySignatureCarrier[];
              topCount: number;
          };
      }>
    | Readonly<{
          requestId: number;
          operation: 'create-padded-tally-chunk';
          input: PrivatePreparationActionContext & {
              expectedChunkOrdinal: number;
          };
      }>
    | Readonly<{
          requestId: number;
          operation: 'initialize-padded-tally-evaluation';
          input: PrivatePreparationActionContext & {
              canonicalRosterBytes: Uint8Array;
              finalitySignatures: readonly FinalitySignatureCarrier[];
              manifests: readonly Uint8Array[];
              activationSignatures: readonly Uint8Array[];
          };
      }>
    | Readonly<{
          requestId: number;
          operation: 'evaluate-padded-tally-chunk';
          input: PrivatePreparationActionContext & {
              expectedChunkOrdinal: number;
              chunkParticipantPosition: number;
              chunk: Uint8Array;
          };
      }>
    | Readonly<{
          requestId: number;
          operation: 'read-tally-result';
          input: PrivatePreparationActionContext;
      }>;

export type PublishedPreparationPackage = Readonly<{
    parentBody: Uint8Array;
    parentSignature: Uint8Array;
    privateBodies: readonly Uint8Array[];
}>;

export type PrivatePreparationConsumption = Readonly<{
    senderPosition: number;
    status: 'already-resolved' | 'burned' | 'resolved';
}>;

export type PublishedSourcePackage = Readonly<{
    sourceBody: Uint8Array;
    sourceSignature: Uint8Array;
}>;

export type PublishedFinalityPackage = Readonly<{
    targetBody: Uint8Array;
    targetIdentity: Uint8Array;
    sourceSubmissionBitmap: number;
    topCount: number;
    targetKind: 'computation' | 'no-result';
    finalitySignature: Uint8Array;
}>;

export type PaddedTallyWorkerInitialization = Readonly<{
    status: 'already-initialized' | 'initialized';
    plan: PaddedTallyPlan;
    resources: KernelResourceMeasurement;
}>;

export type PublishedPaddedTallyChunk = Readonly<{
    chunkOrdinal: number;
    chunk: Uint8Array;
    chunkIdentity: Uint8Array;
}> &
    (
        | Readonly<{ status: 'pending' }>
        | Readonly<{
              status: 'complete';
              manifest: Uint8Array;
              manifestIdentity: Uint8Array;
              activationSignature: Uint8Array;
          }>
    );

export type TallyEvaluationProgress =
    | Readonly<{
          kind: 'no-result';
          terminalPath: 'source-empty';
          acceptedBallotAuthorshipBitmap: number;
          resources: KernelResourceMeasurement;
      }>
    | Readonly<{
          kind: 'no-result';
          terminalPath: 'evaluated';
          acceptedBallotAuthorshipBitmap: number;
          batchIdentity: Uint8Array;
          terminalBody: Uint8Array;
          terminalIdentity: Uint8Array;
          resources: KernelResourceMeasurement;
      }>
    | Readonly<{
          kind: 'result';
          acceptedBallotAuthorshipBitmap: number;
          orderedOptionPositions: readonly number[];
          batchIdentity: Uint8Array;
          terminalBody: Uint8Array;
          terminalIdentity: Uint8Array;
          resources: KernelResourceMeasurement;
      }>;

export type PaddedTallyEvaluationStep =
    | Readonly<{
          kind: 'pending';
          chunkOrdinal: number;
          nextChunkOrdinal: number;
          nextParticipantPosition: number;
          resources: KernelResourceMeasurement;
      }>
    | TallyEvaluationProgress;

type PrivatePreparationWorkerSuccess = Readonly<{
    requestId: number;
    ok: true;
    result:
        | PrivatePreparationConsumption
        | PublishedPreparationPackage
        | PublishedFinalityPackage
        | PublishedPaddedTallyChunk
        | PublishedSourcePackage
        | PaddedTallyEvaluationStep
        | PaddedTallyWorkerInitialization
        | TallyEvaluationProgress
        | Readonly<{ initialized: true }>;
}>;

export type PrivatePreparationWorkerFailure = Readonly<{
    requestId: number;
    ok: false;
    error: Readonly<{
        code:
            | 'Conflict'
            | 'CorruptState'
            | 'InvalidRequest'
            | 'MissingPersistence'
            | 'ProtocolRefusal'
            | 'StateLost'
            | 'StorageFailure';
        message: string;
    }>;
}>;

export type PrivatePreparationWorkerResponse =
    PrivatePreparationWorkerFailure | PrivatePreparationWorkerSuccess;
