import type {
    FinalitySignatureCarrier,
    SourceCarrier,
} from './finality-runtime.js';
import type {
    FoundationKernelLoaderOptions,
    KernelResourceMeasurement,
} from './foundation-kernel/kernel-runtime.js';
import type { PreparationParentCarrier } from './source-runtime.js';
import type {
    ActivationChunkDescriptor,
    SignedActivationManifest,
} from './tally-activation-runtime.js';

export type PrivatePreparationWorkerInitialization = Readonly<{
    databaseName: string;
    kernelUrl: string;
    kernelOptions: FoundationKernelLoaderOptions;
    runtimeIdentity: Uint8Array;
    candidateBuildIdentity: Uint8Array;
}>;

export type PrivatePreparationActionContext = Readonly<{
    actionProposalIdentity: Uint8Array;
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
          operation: 'register-action-keys';
          input: PrivatePreparationActionContext;
      }>
    | Readonly<{
          requestId: number;
          operation: 'confirm-action-key-roster';
          input: PrivatePreparationActionContext & {
              actionKeySetBodies: readonly Uint8Array[];
          };
      }>
    | Readonly<{
          requestId: number;
          operation: 'create-preparation-package';
          input: PrivatePreparationActionContext & {
              actionKeySetBodies: readonly Uint8Array[];
              preparationAttempt: number;
          };
      }>
    | Readonly<{
          requestId: number;
          operation: 'consume-private-preparation';
          input: PrivatePreparationActionContext & {
              actionKeySetBodies: readonly Uint8Array[];
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
              actionKeySetBodies: readonly Uint8Array[];
              preparationAttempt: number;
              preparationParents: readonly PreparationParentCarrier[];
              choice: SourcePublicationChoice;
          };
      }>
    | Readonly<{
          requestId: number;
          operation: 'create-finality-signature';
          input: PrivatePreparationActionContext & {
              actionKeySetBodies: readonly Uint8Array[];
              preparationAttempt: number;
              sources: readonly SourceCarrier[];
              topCount: number;
          };
      }>
    | Readonly<{
          requestId: number;
          operation: 'create-tally-activation';
          input: PrivatePreparationActionContext & {
              actionKeySetBodies: readonly Uint8Array[];
              preparationAttempt: number;
              sources: readonly SourceCarrier[];
              finalitySignatures: readonly FinalitySignatureCarrier[];
              topCount: number;
          };
      }>
    | Readonly<{
          requestId: number;
          operation: 'finalize-no-result';
          input: PrivatePreparationActionContext & {
              actionKeySetBodies: readonly Uint8Array[];
              preparationAttempt: number;
              sources: readonly SourceCarrier[];
              finalitySignatures: readonly FinalitySignatureCarrier[];
              topCount: number;
          };
      }>
    | Readonly<{
          requestId: number;
          operation: 'read-tally-activation-chunk';
          input: PrivatePreparationActionContext & {
              chunkIndex: number;
          };
      }>
    | Readonly<{
          requestId: number;
          operation: 'advance-tally';
          input: PrivatePreparationActionContext & {
              actionKeySetBodies: readonly Uint8Array[];
              preparationAttempt: number;
              sources: readonly SourceCarrier[];
              finalitySignatures: readonly FinalitySignatureCarrier[];
              topCount: number;
              activationManifests: readonly SignedActivationManifest[];
              rangeIndex: number;
              chunks: readonly Uint8Array[];
          };
      }>
    | Readonly<{
          requestId: number;
          operation: 'read-tally-result';
          input: PrivatePreparationActionContext;
      }>;

export type RegisteredActionKeys = Readonly<{
    actionKeySetBody: Uint8Array;
    actionKeySetIdentity: Uint8Array;
}>;

export type ConfirmedActionKeyRoster = Readonly<{
    actionKeySetRosterIdentity: Uint8Array;
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

export type PublishedTallyActivation = Readonly<{
    targetIdentity: Uint8Array;
    topCount: number;
    sourceSubmissionBitmap: number;
    operationCount: number;
    constantOperationCount: number;
    exclusiveOrOperationCount: number;
    conjunctionCount: number;
    negationOperationCount: number;
    outputBitCount: number;
    chunks: readonly ActivationChunkDescriptor[];
    manifestBody: Uint8Array;
    manifestSignature: Uint8Array;
}>;

export type PublishedTallyActivationChunk = Readonly<{
    chunkIndex: number;
    chunk: Uint8Array;
}>;

export type TallyEvaluationProgress =
    | Readonly<{
          kind: 'pending';
          nextRangeIndex: number;
          checkpointByteLength: number;
          resources: KernelResourceMeasurement;
      }>
    | Readonly<{
          kind: 'no-result';
          acceptedBallotAuthorshipBitmap: number;
          resources: KernelResourceMeasurement;
      }>
    | Readonly<{
          kind: 'result';
          acceptedBallotAuthorshipBitmap: number;
          orderedOptionPositions: readonly number[];
          resources: KernelResourceMeasurement;
      }>;

export type PrivatePreparationWorkerSuccess = Readonly<{
    requestId: number;
    ok: true;
    result:
        | ConfirmedActionKeyRoster
        | PrivatePreparationConsumption
        | PublishedPreparationPackage
        | PublishedFinalityPackage
        | PublishedSourcePackage
        | PublishedTallyActivation
        | PublishedTallyActivationChunk
        | RegisteredActionKeys
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
    | PrivatePreparationWorkerFailure
    | PrivatePreparationWorkerSuccess;
