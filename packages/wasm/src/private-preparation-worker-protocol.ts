import type {
    FinalitySignatureCarrier,
    SourceCarrier,
} from './finality-runtime.js';
import type {
    FoundationKernelLoaderOptions,
    KernelResourceMeasurement,
} from './foundation-kernel/kernel-runtime.js';
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

export type TallyEvaluationProgress = Readonly<{
    kind: 'no-result';
    acceptedBallotAuthorshipBitmap: number;
    resources: KernelResourceMeasurement;
}>;

type PrivatePreparationWorkerSuccess = Readonly<{
    requestId: number;
    ok: true;
    result:
        | ConfirmedActionKeyRoster
        | PrivatePreparationConsumption
        | PublishedPreparationPackage
        | PublishedFinalityPackage
        | PublishedSourcePackage
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
    PrivatePreparationWorkerFailure | PrivatePreparationWorkerSuccess;
