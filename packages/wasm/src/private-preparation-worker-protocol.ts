import type { FoundationKernelLoaderOptions } from './foundation-kernel/kernel-runtime.js';

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

export type PrivatePreparationWorkerSuccess = Readonly<{
    requestId: number;
    ok: true;
    result:
        | ConfirmedActionKeyRoster
        | PrivatePreparationConsumption
        | PublishedPreparationPackage
        | RegisteredActionKeys
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
