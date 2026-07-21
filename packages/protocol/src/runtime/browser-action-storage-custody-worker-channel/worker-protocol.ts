import {
    releaseClosedWorkerCommonProofGenerationFamilyAdapter,
    runClosedWorkerCommonProofGenerationFamilyAdapter,
    runClosedWorkerCommonProofVerificationFamilyAdapter,
    type ClosedWorkerCommonProofGenerationFamilyAdapter,
    type ClosedWorkerCommonProofVerificationFamilyAdapter,
    type CommonProofGenerationWorkerOptions,
    type CommonProofVerificationWorkerOptions,
    type VerifiedCommonProofCapability,
} from '@sealed-lattice/wasm';

import type { CheckpointOperationIdentity } from '../authenticated-checkpoint-store.js';
import {
    BrowserActionStorageCustodyError,
    type BrowserActionStorageCustodyErrorCode,
} from '../browser-action-storage-custody.js';
import type {
    CommonProofApplicationHandoff,
    CommonProofBrowserCustody,
    CommonProofCheckpointResumeDescriptor,
} from '../common-proof-browser-custody.js';

import {
    copyBoundedBytes,
    copyBytes,
    maximumCheckpointDescriptorByteLength,
    mutationIdentifierByteLength,
    storageRootCommitmentByteLength,
} from './message-validation.js';

export type CustodyWorkerCommand =
    | 'activate-fresh-foundation-initialization'
    | 'activate-recovered-foundation-initialization'
    | 'abort-checkpoint-publication'
    | 'abort-checkpoint-restore'
    | 'begin-checkpoint'
    | 'begin-checkpoint-publication'
    | 'begin-checkpoint-restore'
    | 'cache-foundation-witness-exact-output'
    | 'cache-foundation-witness-signed-vote-carrier'
    | 'certify-foundation-action-randomness-reservation'
    | 'commit-checkpoint-publication'
    | 'copy-checkpoint-description'
    | 'close-action-randomness'
    | 'close-foundation-action-randomness'
    | 'close-foundation-witness-durable-binding'
    | 'close-state-verifier-session'
    | 'close'
    | 'commit-fresh-foundation-initialization'
    | 'commit-foundation-operation-initialization'
    | 'compare-and-lock-foundation-witness-intent'
    | 'copy-foundation-witness-subject'
    | 'current-snapshot'
    | 'delete'
    | 'derive-record-identifier'
    | 'derive-target-release-attempt'
    | 'derive-foundation-target-release-attempt'
    | 'evict-checkpoint'
    | 'hash-record-envelope'
    | 'authenticate-foundation-head'
    | 'initialize'
    | 'create-and-seal-action-randomness'
    | 'open-sealed-action-randomness'
    | 'open-recovered-foundation-initialization'
    | 'open-foundation-witness-durable-binding'
    | 'open-state-verifier-session'
    | 'open-record'
    | 'open-custody'
    | 'open-root'
    | 'release-state-object'
    | 'release-foundation-state-reservation-intent'
    | 'read-checkpoint-restore-chunk'
    | 'read-foundation-witness-exact-output'
    | 'read-foundation-witness-signed-vote-carrier'
    | 'retire'
    | 'resume-checkpoint'
    | 'seal-record'
    | 'write-checkpoint-publication-chunk'
    | 'verify-state-reservation'
    | 'verify-foundation-action-randomness-reservation'
    | 'produce-foundation-action-randomness-reservation-intent'
    | 'vote-for-foundation-action-randomness-reservation-intent'
    | 'verify-action-randomness-reservation';

export type CustodyWorkerRequest = Readonly<{
    command: CustodyWorkerCommand;
    input: unknown;
    messageKind: 'browser-action-storage-custody-request';
    requestIdentifier: number;
}>;

export type CustodyWorkerResponse =
    | Readonly<{
          messageKind: 'browser-action-storage-custody-completed';
          requestIdentifier: number;
          result: unknown;
      }>
    | Readonly<{
          errorCode: BrowserActionStorageCustodyErrorCode;
          errorMessage?: string;
          messageKind: 'browser-action-storage-custody-failed';
          requestIdentifier: number;
      }>
    | Readonly<{
          errorCode: 'OwnedWorkerFailure';
          messageKind: 'browser-action-storage-custody-channel-failed';
      }>;

export type CustodyWorkerLike = Pick<
    Worker,
    'addEventListener' | 'postMessage' | 'removeEventListener' | 'terminate'
>;

type InstalledCustodyWorkerHost = () => Promise<void>;

export type InstalledCommonProofCapabilityTransfer = Readonly<{
    capability: VerifiedCommonProofCapability;
    restore(): void;
}>;

type PendingInstalledCommonProofApplication = Readonly<{
    durableBindingIdentifier: string;
    handoff: CommonProofApplicationHandoff;
    witnessRoleIdentifier: string;
}>;

export class DefinitelyUnpublishedCommonProofApplicationError extends Error {
    public readonly failureCause: unknown;

    public constructor(failureCause: unknown) {
        super('The common-proof application was definitely not published.');
        this.name = 'DefinitelyUnpublishedCommonProofApplicationError';
        this.failureCause = failureCause;
    }
}

export type InstalledCommonProofApplicationInput = Readonly<{
    durableBindingIdentifier: string;
    handoff: CommonProofApplicationHandoff;
    transferVerifiedCapability(): InstalledCommonProofCapabilityTransfer;
    witnessRoleIdentifier: string;
}>;

export const installedCommonProofExecutionEnvironmentBrand = Symbol(
    'installed-common-proof-execution-environment',
);
export const installedCommonProofCheckpointLineageReservationBrand = Symbol(
    'installed-common-proof-checkpoint-lineage-reservation',
);
export const installedCommonProofPreparedOperationBrand = Symbol(
    'installed-common-proof-prepared-operation',
);

export type InstalledCommonProofExecutionEnvironment = Readonly<{
    readonly [installedCommonProofExecutionEnvironmentBrand]: true;
}>;

export type InstalledCommonProofCheckpointLineageReservation = Readonly<{
    readonly [installedCommonProofCheckpointLineageReservationBrand]: true;
}>;

export type InstalledCommonProofPreparedOperation = Readonly<{
    readonly [installedCommonProofPreparedOperationBrand]: true;
}>;

type OpenInstalledCommonProofExecutionEnvironmentInput = Readonly<{
    preparedOperation: InstalledCommonProofPreparedOperation;
}>;

export type ResolvedInstalledCommonProofExecutionEnvironmentInput = Readonly<{
    commonProofRuntimeBindingHash: Uint8Array<ArrayBuffer>;
    foundationActionRandomnessHandleIdentifier: string;
    generationFamilyAdapter: ClosedWorkerCommonProofGenerationFamilyAdapter;
    proofAttemptLineageIdentifier: Uint8Array<ArrayBuffer>;
    checkpointOperationIdentity?: CheckpointOperationIdentity;
    resumeDescriptor?: CommonProofCheckpointResumeDescriptor;
}>;

export const destroyCommonProofCheckpointResumeDescriptor = (
    descriptor: CommonProofCheckpointResumeDescriptor | undefined,
): void => {
    if (descriptor === undefined) {
        return;
    }
    descriptor.checkpointLineageIdentifier.fill(0);
    descriptor.commonProofEnvironmentIdentifier.fill(0);
    descriptor.privateRandomCursorManifestBytes.fill(0);
    descriptor.privateRandomnessStreamAttemptIdentifier?.fill(0);
    descriptor.stableAttemptBindingHash.fill(0);
};

export const copyCommonProofCheckpointResumeDescriptorForWorker = (
    descriptor: CommonProofCheckpointResumeDescriptor,
): CommonProofCheckpointResumeDescriptor => {
    if (
        !(descriptor.privateRandomCursorManifestBytes instanceof Uint8Array) ||
        descriptor.privateRandomCursorManifestBytes.byteLength >
            maximumCheckpointDescriptorByteLength ||
        !Number.isSafeInteger(descriptor.safeBoundaryOrdinal) ||
        descriptor.safeBoundaryOrdinal < 0 ||
        descriptor.safeBoundaryOrdinal > 0xffff_ffff
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The common-proof checkpoint resume descriptor is malformed or outside the worker-channel copy bound.',
        );
    }
    let checkpointLineageIdentifier = new Uint8Array(0);
    let commonProofEnvironmentIdentifier = new Uint8Array(0);
    let privateRandomCursorManifestBytes = new Uint8Array(0);
    let privateRandomnessStreamAttemptIdentifier:
        | Uint8Array<ArrayBuffer>
        | undefined;
    let stableAttemptBindingHash = new Uint8Array(0);
    try {
        checkpointLineageIdentifier = Uint8Array.from(
            copyBytes(
                descriptor.checkpointLineageIdentifier,
                mutationIdentifierByteLength,
                'Common-proof checkpoint-lineage identifier',
            ),
        );
        commonProofEnvironmentIdentifier = Uint8Array.from(
            copyBytes(
                descriptor.commonProofEnvironmentIdentifier,
                mutationIdentifierByteLength,
                'Checkpoint common-proof environment identifier',
            ),
        );
        privateRandomCursorManifestBytes = Uint8Array.from(
            copyBoundedBytes(
                descriptor.privateRandomCursorManifestBytes,
                maximumCheckpointDescriptorByteLength,
                'Common-proof checkpoint cursor manifest',
            ),
        );
        privateRandomnessStreamAttemptIdentifier =
            descriptor.privateRandomnessStreamAttemptIdentifier === undefined
                ? undefined
                : Uint8Array.from(
                      copyBytes(
                          descriptor.privateRandomnessStreamAttemptIdentifier,
                          mutationIdentifierByteLength,
                          'Common-proof private-randomness stream-attempt identifier',
                      ),
                  );
        stableAttemptBindingHash = Uint8Array.from(
            copyBytes(
                descriptor.stableAttemptBindingHash,
                storageRootCommitmentByteLength,
                'Stable attempt-binding hash',
            ),
        );
        return Object.freeze({
            checkpointLineageIdentifier,
            commonProofEnvironmentIdentifier,
            privateRandomCursorManifestBytes,
            ...(privateRandomnessStreamAttemptIdentifier === undefined
                ? {}
                : { privateRandomnessStreamAttemptIdentifier }),
            safeBoundaryOrdinal: descriptor.safeBoundaryOrdinal,
            stableAttemptBindingHash,
        });
    } catch (error) {
        checkpointLineageIdentifier.fill(0);
        commonProofEnvironmentIdentifier.fill(0);
        privateRandomCursorManifestBytes.fill(0);
        privateRandomnessStreamAttemptIdentifier?.fill(0);
        stableAttemptBindingHash.fill(0);
        throw error;
    }
};

export type InstalledCommonProofPreparedOperationRecord = {
    checkpointOperationIdentity?: CheckpointOperationIdentity;
    commonProofRuntimeBindingHash: Uint8Array<ArrayBuffer>;
    consumed: boolean;
    foundationActionRandomnessHandleIdentifier: string;
    generationFamilyAdapter:
        | ClosedWorkerCommonProofGenerationFamilyAdapter
        | undefined;
    installedHost: InstalledCustodyWorkerHost;
    proofAttemptLineageIdentifier: Uint8Array<ArrayBuffer>;
    resumeDescriptor?: CommonProofCheckpointResumeDescriptor;
};

export const installedCommonProofPreparedOperationRecords = new WeakMap<
    InstalledCommonProofPreparedOperation,
    InstalledCommonProofPreparedOperationRecord
>();

type InstalledCommonProofCheckpointLineageReservationRecord = {
    checkpointLineageIdentifier: Uint8Array<ArrayBuffer>;
    installedHost: InstalledCustodyWorkerHost;
    state: 'available' | 'consumed';
};

export const installedCommonProofCheckpointLineageReservationRecords =
    new WeakMap<
        InstalledCommonProofCheckpointLineageReservation,
        InstalledCommonProofCheckpointLineageReservationRecord
    >();

export const installedCustodyWorkerHostCommonProofCheckpointLineageReservers =
    new WeakMap<
        InstalledCustodyWorkerHost,
        () => Promise<InstalledCommonProofCheckpointLineageReservation>
    >();

export const installedCustodyWorkerHostCommonProofCheckpointLineageReleasers =
    new WeakMap<
        InstalledCustodyWorkerHost,
        (
            reservation: InstalledCommonProofCheckpointLineageReservation,
        ) => Promise<void>
    >();

export const reserveCommonProofCheckpointLineageInInstalledCustodyWorker = (
    installedHost: InstalledCustodyWorkerHost,
): Promise<InstalledCommonProofCheckpointLineageReservation> => {
    const reserveLineage =
        installedCustodyWorkerHostCommonProofCheckpointLineageReservers.get(
            installedHost,
        );
    if (reserveLineage === undefined) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The installed custody worker host cannot reserve common-proof checkpoint lineage.',
        );
    }
    return reserveLineage();
};

export const copyReservedCommonProofCheckpointLineageIdentifier = (
    reservation: InstalledCommonProofCheckpointLineageReservation,
): Uint8Array<ArrayBuffer> => {
    const record =
        installedCommonProofCheckpointLineageReservationRecords.get(
            reservation,
        );
    if (record === undefined || record.state !== 'available') {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The common-proof checkpoint-lineage reservation is unavailable.',
        );
    }
    return record.checkpointLineageIdentifier.slice();
};

export const releaseReservedCommonProofCheckpointLineageInInstalledCustodyWorker =
    (
        installedHost: InstalledCustodyWorkerHost,
        reservation: InstalledCommonProofCheckpointLineageReservation,
    ): Promise<void> => {
        const releaseLineage =
            installedCustodyWorkerHostCommonProofCheckpointLineageReleasers.get(
                installedHost,
            );
        if (releaseLineage === undefined) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'The installed custody worker host cannot release common-proof checkpoint lineage.',
            );
        }
        return releaseLineage(reservation);
    };

export const installedCustodyWorkerHostCommonProofGenerationPreparers =
    new WeakMap<
        InstalledCustodyWorkerHost,
        (input: {
            checkpoint:
                | Readonly<{
                      generationMode: 'fresh';
                      reservation: InstalledCommonProofCheckpointLineageReservation;
                  }>
                | Readonly<{
                      generationMode: 'resumed';
                      resumeDescriptor: CommonProofCheckpointResumeDescriptor;
                  }>;
            foundationActionRandomnessHandleIdentifier: string;
            generationFamilyAdapter: ClosedWorkerCommonProofGenerationFamilyAdapter;
        }) => Promise<InstalledCommonProofPreparedOperation>
    >();

/** Internal exact-family adapter entry; intentionally absent from the protocol root. */
export const prepareCommonProofGenerationInInstalledCustodyWorker = (
    installedHost: InstalledCustodyWorkerHost,
    input: {
        checkpoint:
            | Readonly<{
                  generationMode: 'fresh';
                  reservation: InstalledCommonProofCheckpointLineageReservation;
              }>
            | Readonly<{
                  generationMode: 'resumed';
                  resumeDescriptor: CommonProofCheckpointResumeDescriptor;
              }>;
        foundationActionRandomnessHandleIdentifier: string;
        generationFamilyAdapter: ClosedWorkerCommonProofGenerationFamilyAdapter;
    },
): Promise<InstalledCommonProofPreparedOperation> => {
    const prepareOperation =
        installedCustodyWorkerHostCommonProofGenerationPreparers.get(
            installedHost,
        );
    if (prepareOperation === undefined) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The installed custody worker host cannot prepare common-proof generation.',
        );
    }
    return prepareOperation(input);
};

export type InstalledCommonProofExecutionEnvironmentRecord = {
    applyVerifiedCommonProof(
        input: InstalledCommonProofApplicationInput,
    ): Promise<void>;
    closed: boolean;
    commonProofRuntimeBindingHash: Uint8Array<ArrayBuffer>;
    custody: CommonProofBrowserCustody;
    foundationActionRandomnessHandleIdentifier: string;
    generationCompleted: boolean;
    installedHost: InstalledCustodyWorkerHost;
    operationActive: boolean;
    pendingApplication: PendingInstalledCommonProofApplication | undefined;
    generationFamilyAdapter:
        | ClosedWorkerCommonProofGenerationFamilyAdapter
        | undefined;
    proofAttemptLineageIdentifier: Uint8Array<ArrayBuffer>;
    resumedFromCheckpoint: boolean;
    releaseOwnerReference(): void;
    runInHostQueue<Result>(operation: () => Promise<Result>): Promise<Result>;
    assertDurableBindingCurrent(input: {
        durableBindingIdentifier: string;
        witnessRoleIdentifier: string;
    }): Promise<void>;
    refreshDurableBindingAfterControlledCleanup(input: {
        durableBindingIdentifier: string;
        witnessRoleIdentifier: string;
    }): Promise<void>;
    failAfterApplicationHandoff(failureCause: unknown): void;
    suspendedResumeDescriptor:
        | CommonProofCheckpointResumeDescriptor
        | undefined;
    terminalCustodySettled: boolean;
    terminalCleanupStarted: boolean;
    verifiedCapability: VerifiedCommonProofCapability | undefined;
};

export const installedCommonProofExecutionEnvironmentRecords = new WeakMap<
    InstalledCommonProofExecutionEnvironment,
    InstalledCommonProofExecutionEnvironmentRecord
>();

export const installedCustodyWorkerHostCommonProofEnvironmentOpeners =
    new WeakMap<
        InstalledCustodyWorkerHost,
        (
            input: OpenInstalledCommonProofExecutionEnvironmentInput,
        ) => Promise<InstalledCommonProofExecutionEnvironment>
    >();

export const openCommonProofExecutionEnvironmentInInstalledCustodyWorker = (
    installedHost: InstalledCustodyWorkerHost,
    input: OpenInstalledCommonProofExecutionEnvironmentInput,
): Promise<InstalledCommonProofExecutionEnvironment> => {
    const openEnvironment =
        installedCustodyWorkerHostCommonProofEnvironmentOpeners.get(
            installedHost,
        );
    if (openEnvironment === undefined) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The installed custody worker host cannot open common-proof execution custody.',
        );
    }
    return openEnvironment(input);
};

export const copyInstalledCommonProofCheckpointResumeDescriptor = (
    environment: InstalledCommonProofExecutionEnvironment,
): CommonProofCheckpointResumeDescriptor | undefined => {
    const record =
        installedCommonProofExecutionEnvironmentRecords.get(environment);
    if (record === undefined || record.closed) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The common-proof execution environment is unavailable.',
        );
    }
    return record.custody.copyCheckpointResumeDescriptor();
};

/**
 * Closes one interrupted environment after its authenticated checkpoint is
 * durable, returning the only descriptor accepted by a continuation adapter.
 * The operation is intentionally absent from the protocol package root.
 */
export const suspendCommonProofExecutionEnvironmentForAuthenticatedResumeInInstalledCustodyWorker =
    async (
        environment: InstalledCommonProofExecutionEnvironment,
    ): Promise<CommonProofCheckpointResumeDescriptor> => {
        const record =
            installedCommonProofExecutionEnvironmentRecords.get(environment);
        if (
            record === undefined ||
            record.operationActive ||
            record.verifiedCapability !== undefined ||
            (record.closed &&
                (record.suspendedResumeDescriptor === undefined ||
                    record.terminalCleanupStarted))
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'The common-proof execution environment cannot suspend in its current state.',
            );
        }
        if (record.suspendedResumeDescriptor === undefined) {
            const resumeDescriptor =
                record.custody.copyCheckpointResumeDescriptor();
            if (resumeDescriptor === undefined) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidState',
                    'The common-proof execution environment has no authenticated resume point.',
                );
            }
            try {
                await record.custody.suspendForAuthenticatedResume();
            } catch (error) {
                destroyCommonProofCheckpointResumeDescriptor(resumeDescriptor);
                throw error;
            }
            record.closed = true;
            record.suspendedResumeDescriptor = resumeDescriptor;
            record.terminalCustodySettled = true;
        }
        if (record.generationFamilyAdapter !== undefined) {
            try {
                releaseClosedWorkerCommonProofGenerationFamilyAdapter(
                    record.generationFamilyAdapter,
                );
                record.generationFamilyAdapter = undefined;
            } catch (error) {
                throw new BrowserActionStorageCustodyError(
                    'StorageFailure',
                    'The authenticated common-proof suspension is durable, but its generation authority remains retained for cleanup retry.',
                    error,
                );
            }
        }
        const resumeDescriptor = record.suspendedResumeDescriptor;
        record.suspendedResumeDescriptor = undefined;
        finishInstalledCommonProofTerminalCleanup(environment, record);
        return resumeDescriptor;
    };

export const closeCommonProofExecutionEnvironmentInInstalledCustodyWorker =
    async (
        environment: InstalledCommonProofExecutionEnvironment,
    ): Promise<void> => {
        const record =
            installedCommonProofExecutionEnvironmentRecords.get(environment);
        if (record === undefined) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'The common-proof execution environment is unavailable.',
            );
        }
        if (record.pendingApplication !== undefined) {
            const pendingApplicationClosureFailure =
                new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'Closing a pending common-proof application permanently retires its browser-owned foundation authority.',
                );
            record.failAfterApplicationHandoff(
                pendingApplicationClosureFailure,
            );
            try {
                await retireInstalledCommonProofExecutionEnvironment(
                    environment,
                    record,
                );
            } catch (retirementError) {
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The pending common-proof application retired its host but verifier-authority cleanup also failed.',
                    [pendingApplicationClosureFailure, retirementError],
                );
            }
            throw pendingApplicationClosureFailure;
        }
        await retireInstalledCommonProofExecutionEnvironment(
            environment,
            record,
        );
    };

type InstalledCommonProofGenerationOptions = Pick<
    CommonProofGenerationWorkerOptions,
    'signal' | 'yieldControl'
>;

const destroyPendingInstalledCommonProofApplication = (
    record: InstalledCommonProofExecutionEnvironmentRecord,
): void => {
    record.pendingApplication?.handoff.canonicalMarkerRecordBytes.fill(0);
    record.pendingApplication = undefined;
};

const beginInstalledCommonProofTerminalCleanup = (
    record: InstalledCommonProofExecutionEnvironmentRecord,
): unknown[] => {
    record.terminalCleanupStarted = true;
    record.closed = true;
    destroyPendingInstalledCommonProofApplication(record);
    const failures: unknown[] = [];
    if (record.generationFamilyAdapter !== undefined) {
        try {
            releaseClosedWorkerCommonProofGenerationFamilyAdapter(
                record.generationFamilyAdapter,
            );
            record.generationFamilyAdapter = undefined;
        } catch (error) {
            failures.push(error);
        }
    }
    if (record.verifiedCapability !== undefined) {
        try {
            record.verifiedCapability.release();
            record.verifiedCapability = undefined;
        } catch (error) {
            failures.push(error);
        }
    }
    return failures;
};

const finishInstalledCommonProofTerminalCleanup = (
    environment: InstalledCommonProofExecutionEnvironment,
    record: InstalledCommonProofExecutionEnvironmentRecord,
): void => {
    if (
        record.generationFamilyAdapter !== undefined ||
        record.verifiedCapability !== undefined ||
        !record.terminalCustodySettled
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidState',
            'The installed common-proof environment still owns terminal authority or custody.',
        );
    }
    record.commonProofRuntimeBindingHash.fill(0);
    record.proofAttemptLineageIdentifier.fill(0);
    destroyCommonProofCheckpointResumeDescriptor(
        record.suspendedResumeDescriptor,
    );
    record.suspendedResumeDescriptor = undefined;
    installedCommonProofExecutionEnvironmentRecords.delete(environment);
    record.releaseOwnerReference();
};

export const retireInstalledCommonProofExecutionEnvironment = async (
    environment: InstalledCommonProofExecutionEnvironment,
    record: InstalledCommonProofExecutionEnvironmentRecord,
): Promise<void> => {
    if (
        installedCommonProofExecutionEnvironmentRecords.get(environment) !==
        record
    ) {
        return;
    }
    const failures = beginInstalledCommonProofTerminalCleanup(record);
    if (!record.terminalCustodySettled) {
        try {
            await record.custody.retire();
            record.terminalCustodySettled = true;
        } catch (error) {
            failures.push(error);
        }
    }
    if (failures.length !== 0) {
        throw new BrowserActionStorageCustodyError(
            'StorageFailure',
            'The installed common-proof environment could not retire all worker-owned authority and durable records.',
            failures,
        );
    }
    finishInstalledCommonProofTerminalCleanup(environment, record);
};

const completeInstalledCommonProofCustody = async (
    record: InstalledCommonProofExecutionEnvironmentRecord,
): Promise<void> => {
    if (record.closed || record.terminalCustodySettled) {
        throw new BrowserActionStorageCustodyError(
            'InvalidState',
            'The installed common-proof custody cannot complete twice.',
        );
    }
    try {
        await record.custody.completeVerifiedOutput();
        record.terminalCustodySettled = true;
    } catch (completionError) {
        try {
            await record.custody.retire();
            record.terminalCustodySettled = true;
        } catch (retirementError) {
            throw new BrowserActionStorageCustodyError(
                'StorageFailure',
                'Verified common-proof completion failed and its retryable terminal cleanup remains incomplete.',
                [completionError, retirementError],
            );
        }
    }
};

const finalizeInstalledCommonProofExecutionEnvironment = (
    environment: InstalledCommonProofExecutionEnvironment,
    record: InstalledCommonProofExecutionEnvironmentRecord,
): void => {
    if (
        installedCommonProofExecutionEnvironmentRecords.get(environment) !==
        record
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidState',
            'The installed common-proof environment was lost before application finalization.',
        );
    }
    const failures = beginInstalledCommonProofTerminalCleanup(record);
    if (failures.length !== 0) {
        throw new BrowserActionStorageCustodyError(
            'StorageFailure',
            'The installed common-proof environment retained authority after application.',
            failures,
        );
    }
    finishInstalledCommonProofTerminalCleanup(environment, record);
};

/** Runs one family-prepared prover without exposing custody or Rust handles. */
export const runCommonProofGenerationInInstalledCustodyWorker = async (
    environment: InstalledCommonProofExecutionEnvironment,
    options: InstalledCommonProofGenerationOptions = {},
): Promise<void> => {
    const record =
        installedCommonProofExecutionEnvironmentRecords.get(environment);
    if (record === undefined || record.closed) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The common-proof execution environment is unavailable.',
        );
    }
    return record.runInHostQueue(async () => {
        if (
            record.closed ||
            installedCommonProofExecutionEnvironmentRecords.get(environment) !==
                record
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'The common-proof execution environment became unavailable before generation.',
            );
        }
        if (record.operationActive) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'The common-proof execution environment already owns an active operation.',
            );
        }
        if (
            record.generationCompleted ||
            record.generationFamilyAdapter === undefined
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'The common-proof execution environment has no prepared generation operation.',
            );
        }
        const checkpointCustody = record.custody.checkpointCustody;
        if (checkpointCustody === undefined) {
            throw new BrowserActionStorageCustodyError(
                'Unavailable',
                'Installed common-proof generation requires authenticated checkpoint custody.',
            );
        }
        record.operationActive = true;
        const generationFamilyAdapter = record.generationFamilyAdapter;
        record.generationFamilyAdapter = undefined;
        try {
            await runClosedWorkerCommonProofGenerationFamilyAdapter(
                generationFamilyAdapter,
                record.custody.externalMemory,
                record.custody.outputStore,
                {
                    ...(record.resumedFromCheckpoint
                        ? {
                              resume: {
                                  checkpointCustody,
                                  prefixReplayExternalMemory:
                                      record.custody.prefixReplayExternalMemory,
                              },
                          }
                        : { checkpointCustody }),
                    ...(options.signal === undefined
                        ? {}
                        : { signal: options.signal }),
                    ...(options.yieldControl === undefined
                        ? {}
                        : { yieldControl: options.yieldControl }),
                },
            );
        } catch (error) {
            if (
                typeof error === 'object' &&
                error !== null &&
                'permanentRetirementRequired' in error &&
                error.permanentRetirementRequired === true
            ) {
                try {
                    await retireInstalledCommonProofExecutionEnvironment(
                        environment,
                        record,
                    );
                } catch (retirementError) {
                    record.operationActive = false;
                    throw new BrowserActionStorageCustodyError(
                        'StorageFailure',
                        'The installed common-proof generation failed and durable retirement was incomplete.',
                        [error, retirementError],
                    );
                }
            }
            if (!record.closed) {
                record.operationActive = false;
            }
            throw error;
        }
        try {
            record.custody.sealCanonicalOutput();
            await record.custody.releaseExternalMemory();
            record.generationCompleted = true;
        } catch (error) {
            const cleanupFailures: unknown[] = [error];
            try {
                await retireInstalledCommonProofExecutionEnvironment(
                    environment,
                    record,
                );
            } catch (retirementError) {
                cleanupFailures.push(retirementError);
            }
            throw new BrowserActionStorageCustodyError(
                'OwnedWorkerFailure',
                'The installed common-proof generation completed but final custody closure failed.',
                cleanupFailures,
            );
        } finally {
            if (!record.closed) {
                record.operationActive = false;
            }
        }
    });
};

type VerifyAndApplyInstalledCommonProofInput = Readonly<{
    durableBindingIdentifier: string;
    signal?: CommonProofVerificationWorkerOptions['signal'];
    verificationFamilyAdapter: ClosedWorkerCommonProofVerificationFamilyAdapter;
    witnessRoleIdentifier: string;
    yieldControl?: CommonProofVerificationWorkerOptions['yieldControl'];
}>;

type RetryPendingInstalledCommonProofApplicationInput = Readonly<{
    durableBindingIdentifier: string;
    witnessRoleIdentifier: string;
}>;

const runInstalledCommonProofApplication = async (
    environment: InstalledCommonProofExecutionEnvironment,
    record: InstalledCommonProofExecutionEnvironmentRecord,
    input: RetryPendingInstalledCommonProofApplicationInput,
    verifyCommonProof?: () => Promise<VerifiedCommonProofCapability>,
): Promise<void> => {
    record.operationActive = true;
    let applicationHandoffBoundaryStarted =
        record.pendingApplication !== undefined;
    try {
        if (record.pendingApplication === undefined) {
            if (verifyCommonProof === undefined) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidState',
                    'The common-proof environment has no pending application to retry.',
                );
            }
            record.verifiedCapability = await verifyCommonProof();
            await record.assertDurableBindingCurrent(input);
            applicationHandoffBoundaryStarted = true;
            const handoff = await record.custody.armApplicationHandoff();
            record.pendingApplication = Object.freeze({
                durableBindingIdentifier: input.durableBindingIdentifier,
                handoff,
                witnessRoleIdentifier: input.witnessRoleIdentifier,
            });
            await completeInstalledCommonProofCustody(record);
            await record.refreshDurableBindingAfterControlledCleanup(input);
        } else if (verifyCommonProof !== undefined) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'The common-proof environment must retry its retained application without another verifier.',
            );
        }

        const pendingApplication = record.pendingApplication;
        if (pendingApplication === undefined) {
            throw new BrowserActionStorageCustodyError(
                'OwnedWorkerFailure',
                'The common-proof application handoff was lost before durable application.',
            );
        }
        const result = await record.applyVerifiedCommonProof({
            durableBindingIdentifier:
                pendingApplication.durableBindingIdentifier,
            handoff: pendingApplication.handoff,
            transferVerifiedCapability: () => {
                if (
                    installedCommonProofExecutionEnvironmentRecords.get(
                        environment,
                    ) !== record ||
                    record.closed ||
                    record.verifiedCapability === undefined
                ) {
                    throw new BrowserActionStorageCustodyError(
                        'InvalidState',
                        'The installed common-proof environment no longer owns verifier authority for application.',
                    );
                }
                const capability = record.verifiedCapability;
                record.verifiedCapability = undefined;
                let restorationAvailable = true;
                return Object.freeze({
                    capability,
                    restore: () => {
                        if (!restorationAvailable) {
                            throw new BrowserActionStorageCustodyError(
                                'InvalidState',
                                'The common-proof verifier authority transfer cannot be restored twice.',
                            );
                        }
                        if (
                            installedCommonProofExecutionEnvironmentRecords.get(
                                environment,
                            ) !== record ||
                            record.closed ||
                            record.verifiedCapability !== undefined
                        ) {
                            throw new BrowserActionStorageCustodyError(
                                'InvalidState',
                                'The common-proof verifier authority cannot return to its execution environment.',
                            );
                        }
                        record.verifiedCapability = capability;
                        restorationAvailable = false;
                    },
                });
            },
            witnessRoleIdentifier: pendingApplication.witnessRoleIdentifier,
        });
        destroyPendingInstalledCommonProofApplication(record);
        finalizeInstalledCommonProofExecutionEnvironment(environment, record);
        return result;
    } catch (error) {
        if (
            error instanceof DefinitelyUnpublishedCommonProofApplicationError &&
            record.pendingApplication !== undefined &&
            record.verifiedCapability !== undefined &&
            !record.closed
        ) {
            throw error.failureCause;
        }

        let capabilityReleaseFailure: unknown;
        if (record.verifiedCapability !== undefined) {
            try {
                record.verifiedCapability.release();
                record.verifiedCapability = undefined;
            } catch (releaseError) {
                capabilityReleaseFailure = releaseError;
            }
        }
        if (applicationHandoffBoundaryStarted) {
            destroyPendingInstalledCommonProofApplication(record);
            record.failAfterApplicationHandoff(error);
            if (capabilityReleaseFailure !== undefined) {
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'Common-proof application failed after handoff with verifier authority retained for terminal cleanup retry.',
                    [error, capabilityReleaseFailure],
                );
            }
        } else if (capabilityReleaseFailure !== undefined) {
            try {
                await retireInstalledCommonProofExecutionEnvironment(
                    environment,
                    record,
                );
            } catch (retirementError) {
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'Common-proof verification failed with verifier authority pending and durable retirement also failed.',
                    [error, capabilityReleaseFailure, retirementError],
                );
            }
            throw new BrowserActionStorageCustodyError(
                'OwnedWorkerFailure',
                'Common-proof verification failed and its verifier authority required terminal retirement.',
                [error, capabilityReleaseFailure],
            );
        }
        throw error;
    } finally {
        if (!record.closed) {
            record.operationActive = false;
        }
    }
};

/**
 * Authenticates the committed generated stream, completes the Rust verifier,
 * and applies only its opaque capability to one durable foundation successor.
 */
export const verifyAndApplyCommonProofInInstalledCustodyWorker = async (
    environment: InstalledCommonProofExecutionEnvironment,
    input: VerifyAndApplyInstalledCommonProofInput,
): Promise<void> => {
    const record =
        installedCommonProofExecutionEnvironmentRecords.get(environment);
    if (record === undefined || record.closed) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The common-proof execution environment is unavailable.',
        );
    }
    return record.runInHostQueue(async () => {
        if (
            record.closed ||
            installedCommonProofExecutionEnvironmentRecords.get(environment) !==
                record
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'The common-proof execution environment became unavailable before verification.',
            );
        }
        if (record.operationActive || !record.generationCompleted) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'The common-proof execution environment has no sealed generated proof ready for verification.',
            );
        }
        if (record.pendingApplication !== undefined) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'The common-proof execution environment already owns a pending application retry.',
            );
        }
        return runInstalledCommonProofApplication(
            environment,
            record,
            {
                durableBindingIdentifier: input.durableBindingIdentifier,
                witnessRoleIdentifier: input.witnessRoleIdentifier,
            },
            () =>
                runClosedWorkerCommonProofVerificationFamilyAdapter(
                    input.verificationFamilyAdapter,
                    record.custody.authenticatedOutput(),
                    {
                        ...(input.signal === undefined
                            ? {}
                            : { signal: input.signal }),
                        ...(input.yieldControl === undefined
                            ? {}
                            : { yieldControl: input.yieldControl }),
                    },
                ),
        );
    });
};

/** Retries one definitely unpublished application without rerunning proof verification. */
export const retryPendingCommonProofApplicationInInstalledCustodyWorker =
    async (
        environment: InstalledCommonProofExecutionEnvironment,
        input: RetryPendingInstalledCommonProofApplicationInput,
    ): Promise<void> => {
        const record =
            installedCommonProofExecutionEnvironmentRecords.get(environment);
        if (record === undefined || record.closed) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'The common-proof execution environment is unavailable.',
            );
        }
        return record.runInHostQueue(async () => {
            if (
                record.closed ||
                installedCommonProofExecutionEnvironmentRecords.get(
                    environment,
                ) !== record
            ) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'The common-proof execution environment became unavailable before application retry.',
                );
            }
            const pendingApplication = record.pendingApplication;
            if (
                record.operationActive ||
                pendingApplication === undefined ||
                record.verifiedCapability === undefined ||
                !record.terminalCustodySettled
            ) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidState',
                    'The common-proof execution environment has no definitely unpublished application to retry.',
                );
            }
            if (
                input.durableBindingIdentifier !==
                    pendingApplication.durableBindingIdentifier ||
                input.witnessRoleIdentifier !==
                    pendingApplication.witnessRoleIdentifier
            ) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'The common-proof application retry must preserve its exact durable binding and witness role.',
                );
            }
            return runInstalledCommonProofApplication(
                environment,
                record,
                input,
            );
        });
    };
