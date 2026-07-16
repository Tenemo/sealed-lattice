import {
    browserActionStorageCustodyErrorCodes,
    foundationProfile,
    refusalReasonCodes,
} from '@sealed-lattice/types';
import type {
    BrowserStateObjectSignatureOperation,
    BrowserFoundationInitializationPreparationInput,
    RefusalReason,
} from '@sealed-lattice/types';
import {
    certifyClosedWorkerActionRandomnessReservation,
    copyVerifiedStateDurableBinding,
    describeClosedWorkerCommonProofGenerationFamilyAdapter,
    describeClosedWorkerCommonProofVerificationFamilyAdapter,
    openClosedWorkerVerifiedStateDurableBinding,
    prepareClosedWorkerVerifiedCommonProofApplication,
    produceClosedWorkerActionRandomnessReservationIntent,
    produceClosedWorkerActionRandomnessReservationWitnessVote,
    releaseClosedWorkerCommonProofGenerationFamilyAdapter,
    releaseClosedWorkerCommonProofVerificationFamilyAdapter,
    runClosedWorkerCommonProofGenerationFamilyAdapter,
    runClosedWorkerCommonProofVerificationFamilyAdapter,
    type ClosedWorkerCommonProofGenerationFamilyAdapter,
    type ClosedWorkerCommonProofVerificationFamilyAdapter,
    type CommonProofGenerationWorkerOptions,
    type CommonProofVerificationWorkerOptions,
    type VerifiedCommonProofCapability,
    type VerifiedStateDurableBinding,
    verifyClosedWorkerActionRandomnessReservationIntentForWitness,
} from '@sealed-lattice/wasm';

import type {
    AuthenticatedCheckpointStore,
    AuthenticatedCheckpointStoreLimits,
    CheckpointBoundary,
    CheckpointBoundaryPolicy,
    CheckpointOperationIdentity,
    CheckpointRandomCursorKernel,
    ExpectedCheckpointBoundary,
    ResumedCheckpoint,
} from './authenticated-checkpoint-store.js';
import { bytesToHex } from './authenticated-runtime-record.js';
import {
    copyActionProofAttemptBinding,
    copyActionRandomnessReservationVerificationInput,
    copyActionStateReservationVerificationInput,
    copyActionStateVerifierSessionInput,
    copyCreateAndSealActionRandomnessInput,
    copyOpenedActionRandomnessSession,
    copyOpaqueWorkerIdentifier,
    copyOpenSealedActionRandomnessInput,
    copySealedActionRandomnessSession,
    copyTargetReleaseAttemptInput,
    copyWorkerIdentifierVerificationResult,
} from './browser-action-cryptography-validation.js';
import type { BrowserActionStorageWorkerKernel } from './browser-action-storage-custody-internal.js';
import {
    BrowserActionStorageCustodyError,
    type BrowserActionProofAttemptBinding,
    type BrowserActionRandomnessRecordContext,
    type BrowserActionRandomnessReservationVerificationInput,
    type BrowserActionStateReservationVerificationInput,
    type BrowserActionStateVerifierSessionInput,
    type BrowserOpenedActionRandomnessSession,
    type BrowserSealedActionRandomnessSession,
    type BrowserTargetReleaseAttemptInput,
    type BrowserActionStorageCustody,
    type BrowserActionStorageCustodyErrorCode,
    type BrowserActionStorageRootBinding,
    type BrowserDeviceWrappingSnapshot,
    type BrowserFoundationFreshnessCoordinate,
    type BrowserFoundationCheckpointDescription,
    type BrowserFoundationCheckpointHandle,
    type BrowserFoundationStorageAuthority,
    type BrowserFreshFoundationInitializationCommit,
    type BrowserLocalRecordIdentifierInput,
    type BrowserLocalRecordOpenInput,
    type BrowserLocalRecordSealInput,
    type UntrustedExpectedStorageRootCommitment,
    type VerificationResult,
    type TransferableBrowserFoundationStorageAuthority,
} from './browser-action-storage-custody.js';
import { copyBrowserFoundationInitializationPreparationInput } from './browser-foundation-initialization.js';
import type {
    BrowserFoundationActionRandomnessHandle,
    BrowserFoundationDurableStateBindingHandle,
    BrowserFoundationInitializationInput,
    BrowserFoundationNormalWitnessRoleHandle,
    BrowserFoundationOperationOwner,
    BrowserFoundationProducedStateReservation,
    BrowserFoundationProducedStateReservationIntent,
    BrowserRecoveredFoundationInitialization,
    BrowserRecoveredFoundationInitializationBatch,
    BrowserFoundationStateReservationIntentHandle,
    TransferableBrowserFoundationOperationOwner,
} from './browser-foundation-operation-owner.js';
import {
    copyLocalRecordBytes,
    copyLocalRecordIdentifierInput,
    copyLocalRecordOpenInput,
    copyLocalRecordSealInput,
    destroyLocalRecordIdentifierInput,
    destroyLocalRecordOpenInput,
    destroyLocalRecordSealInput,
} from './browser-local-record-validation.js';
import type {
    CommonProofApplicationHandoff,
    CommonProofBrowserCustody,
    CommonProofCheckpointResumeDescriptor,
} from './common-proof-browser-custody.js';
import type {
    DurableStateWitnessServiceLimits,
    DurableStateWitnessService,
    TransferableDurableStateWitnessService,
} from './durable-state-witness-service.js';
import { persistCommonProofApplicationAuthorization } from './durable-state-witness-service.js';
import {
    ExclusiveResourceLifecycle,
    type ExclusiveResourceOwnerToken,
} from './exclusive-resource-lifecycle.js';
import type { UntrustedStorageTransactionLimits } from './untrusted-storage-transaction-store.js';
import {
    openWebLockOwnedBrowserActionStorageCustody,
    type WebLockOwnedBrowserActionStorageCustody,
    type WebLockCommittedBrowserFoundationInitialization,
    type WebLockFoundationWitnessRecord,
    type WebLockOwnedFoundationWitnessRole,
    type WebLockRecoveredBrowserFoundationInitialization,
} from './web-lock-owned-untrusted-storage-transaction-store.js';

const mutationIdentifierByteLength = 32;
const storageRootCommitmentByteLength = 64;
const maximumDatabaseNameLength = 256;
const maximumNamespaceLength = 64;
const maximumCheckpointCollectionLength = 4096;
const maximumCheckpointDescriptorByteLength = 1_048_576;
const maximumActiveCheckpointHandleCount = 64;
const namespacePattern = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;

export type BrowserActionStorageCustodyWorkerConfiguration = Readonly<{
    acquisitionDeadlineEpochMilliseconds?: number;
    binding: BrowserActionStorageRootBinding;
    databaseName: string;
    knownStorageRootCommitment?: Uint8Array;
    limits: UntrustedStorageTransactionLimits;
    namespace: string;
    runtimeBuildManifestHash: Uint8Array;
}>;

export type BrowserFoundationOperationOwnerWorkerRootOpening =
    | Readonly<{ mode: 'fresh' }>
    | Readonly<{
          expectedSnapshot: BrowserDeviceWrappingSnapshot;
          mode: 'recovered';
          untrustedExpectedCommitment: UntrustedExpectedStorageRootCommitment;
      }>;

export type OpenedBrowserFoundationOperationOwnerWorker = Readonly<{
    deviceWrappingSnapshot: BrowserDeviceWrappingSnapshot;
    operationOwner: TransferableBrowserFoundationOperationOwner;
}>;

type CustodyWorkerCommand =
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

type CustodyWorkerRequest = Readonly<{
    command: CustodyWorkerCommand;
    input: unknown;
    messageKind: 'browser-action-storage-custody-request';
    requestIdentifier: number;
}>;

type CustodyWorkerResponse =
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

type CustodyWorkerLike = Pick<
    Worker,
    'addEventListener' | 'postMessage' | 'removeEventListener' | 'terminate'
>;

type InstalledCustodyWorkerHost = () => Promise<void>;

type InstalledCommonProofCapabilityTransfer = Readonly<{
    capability: VerifiedCommonProofCapability;
    restore(): void;
}>;

type InstalledCommonProofApplicationInput = Readonly<{
    durableBindingIdentifier: string;
    handoff: CommonProofApplicationHandoff;
    transferVerifiedCapability(): InstalledCommonProofCapabilityTransfer;
    witnessRoleIdentifier: string;
}>;

const installedCommonProofExecutionEnvironmentBrand = Symbol(
    'installed-common-proof-execution-environment',
);
const installedCommonProofPreparedOperationBrand = Symbol(
    'installed-common-proof-prepared-operation',
);

type InstalledCommonProofExecutionEnvironment = Readonly<{
    readonly [installedCommonProofExecutionEnvironmentBrand]: true;
}>;

type InstalledCommonProofPreparedOperation = Readonly<{
    readonly [installedCommonProofPreparedOperationBrand]: true;
}>;

type OpenInstalledCommonProofExecutionEnvironmentInput = Readonly<{
    preparedOperation: InstalledCommonProofPreparedOperation;
    resumeDescriptor?: CommonProofCheckpointResumeDescriptor;
}>;

type ResolvedInstalledCommonProofExecutionEnvironmentInput = Readonly<{
    commonProofRuntimeBindingHash: Uint8Array<ArrayBuffer>;
    commonProofVerificationBindingHash: Uint8Array<ArrayBuffer>;
    foundationActionRandomnessHandleIdentifier: string;
    generationFamilyAdapter: ClosedWorkerCommonProofGenerationFamilyAdapter;
    proofAttemptLineageIdentifier: Uint8Array<ArrayBuffer>;
    resumeDescriptor?: CommonProofCheckpointResumeDescriptor;
}>;

const destroyCommonProofCheckpointResumeDescriptor = (
    descriptor: CommonProofCheckpointResumeDescriptor | undefined,
): void => {
    if (descriptor === undefined) {
        return;
    }
    descriptor.checkpointLineageIdentifier.fill(0);
    descriptor.commonProofEnvironmentIdentifier.fill(0);
    for (const cursorBytes of descriptor.orderedPrivateRandomCursorBytes) {
        cursorBytes.fill(0);
    }
    descriptor.stableAttemptBindingHash.fill(0);
};

const copyCommonProofCheckpointResumeDescriptorForWorker = (
    descriptor: CommonProofCheckpointResumeDescriptor,
): CommonProofCheckpointResumeDescriptor => {
    if (
        !Array.isArray(descriptor.orderedPrivateRandomCursorBytes) ||
        descriptor.orderedPrivateRandomCursorBytes.length >
            maximumCheckpointCollectionLength ||
        !Number.isSafeInteger(descriptor.safeBoundaryOrdinal) ||
        descriptor.safeBoundaryOrdinal < 0 ||
        descriptor.safeBoundaryOrdinal > 0xffff_ffff
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The common-proof checkpoint resume descriptor is malformed or outside the worker-channel copy bound.',
        );
    }
    let cursorAggregateByteLength = 0;
    for (const cursorBytes of descriptor.orderedPrivateRandomCursorBytes) {
        if (
            !(cursorBytes instanceof Uint8Array) ||
            cursorBytes.byteLength === 0 ||
            cursorBytes.byteLength >
                maximumCheckpointDescriptorByteLength -
                    cursorAggregateByteLength
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'The common-proof checkpoint cursors are malformed or exceed the aggregate worker-channel copy bound.',
            );
        }
        cursorAggregateByteLength += cursorBytes.byteLength;
    }
    let checkpointLineageIdentifier = new Uint8Array(0);
    let commonProofEnvironmentIdentifier = new Uint8Array(0);
    const orderedPrivateRandomCursorBytes: Uint8Array<ArrayBuffer>[] = [];
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
        for (
            let cursorIndex = 0;
            cursorIndex < descriptor.orderedPrivateRandomCursorBytes.length;
            cursorIndex += 1
        ) {
            orderedPrivateRandomCursorBytes.push(
                Uint8Array.from(
                    copyBoundedBytes(
                        descriptor.orderedPrivateRandomCursorBytes[cursorIndex],
                        maximumCheckpointDescriptorByteLength,
                        `Common-proof checkpoint cursor ${String(cursorIndex)}`,
                    ),
                ),
            );
        }
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
            orderedPrivateRandomCursorBytes: Object.freeze(
                orderedPrivateRandomCursorBytes,
            ),
            safeBoundaryOrdinal: descriptor.safeBoundaryOrdinal,
            stableAttemptBindingHash,
        });
    } catch (error) {
        checkpointLineageIdentifier.fill(0);
        commonProofEnvironmentIdentifier.fill(0);
        for (const cursorBytes of orderedPrivateRandomCursorBytes) {
            cursorBytes.fill(0);
        }
        stableAttemptBindingHash.fill(0);
        throw error;
    }
};

type InstalledCommonProofPreparedOperationRecord = {
    commonProofRuntimeBindingHash: Uint8Array<ArrayBuffer>;
    commonProofVerificationBindingHash: Uint8Array<ArrayBuffer>;
    consumed: boolean;
    foundationActionRandomnessHandleIdentifier: string;
    generationFamilyAdapter:
        | ClosedWorkerCommonProofGenerationFamilyAdapter
        | undefined;
    installedHost: InstalledCustodyWorkerHost;
    proofAttemptLineageIdentifier: Uint8Array<ArrayBuffer>;
};

const installedCommonProofPreparedOperationRecords = new WeakMap<
    InstalledCommonProofPreparedOperation,
    InstalledCommonProofPreparedOperationRecord
>();

const installedCustodyWorkerHostCommonProofGenerationPreparers = new WeakMap<
    InstalledCustodyWorkerHost,
    (input: {
        foundationActionRandomnessHandleIdentifier: string;
        generationFamilyAdapter: ClosedWorkerCommonProofGenerationFamilyAdapter;
    }) => InstalledCommonProofPreparedOperation
>();

/** Internal exact-family adapter entry; intentionally absent from the protocol root. */
export const prepareCommonProofGenerationInInstalledCustodyWorker = (
    installedHost: InstalledCustodyWorkerHost,
    input: {
        foundationActionRandomnessHandleIdentifier: string;
        generationFamilyAdapter: ClosedWorkerCommonProofGenerationFamilyAdapter;
    },
): InstalledCommonProofPreparedOperation => {
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

type InstalledCommonProofExecutionEnvironmentRecord = {
    applyVerifiedCommonProof(
        input: InstalledCommonProofApplicationInput,
    ): Promise<void>;
    closed: boolean;
    commonProofRuntimeBindingHash: Uint8Array<ArrayBuffer>;
    commonProofVerificationBindingHash: Uint8Array<ArrayBuffer>;
    custody: CommonProofBrowserCustody;
    foundationActionRandomnessHandleIdentifier: string;
    generationCompleted: boolean;
    installedHost: InstalledCustodyWorkerHost;
    operationActive: boolean;
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

const installedCommonProofExecutionEnvironmentRecords = new WeakMap<
    InstalledCommonProofExecutionEnvironment,
    InstalledCommonProofExecutionEnvironmentRecord
>();

const installedCustodyWorkerHostCommonProofEnvironmentOpeners = new WeakMap<
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
        await retireInstalledCommonProofExecutionEnvironment(
            environment,
            record,
        );
    };

type InstalledCommonProofGenerationOptions = Pick<
    CommonProofGenerationWorkerOptions,
    'signal' | 'yieldControl'
>;

const beginInstalledCommonProofTerminalCleanup = (
    record: InstalledCommonProofExecutionEnvironmentRecord,
): unknown[] => {
    record.terminalCleanupStarted = true;
    record.closed = true;
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
    record.commonProofVerificationBindingHash.fill(0);
    record.proofAttemptLineageIdentifier.fill(0);
    destroyCommonProofCheckpointResumeDescriptor(
        record.suspendedResumeDescriptor,
    );
    record.suspendedResumeDescriptor = undefined;
    installedCommonProofExecutionEnvironmentRecords.delete(environment);
    record.releaseOwnerReference();
};

const retireInstalledCommonProofExecutionEnvironment = async (
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
        const verificationDescription =
            describeClosedWorkerCommonProofVerificationFamilyAdapter(
                input.verificationFamilyAdapter,
            );
        try {
            if (
                !bytesEqual(
                    verificationDescription.commonProofVerificationBindingHash,
                    record.commonProofVerificationBindingHash,
                )
            ) {
                try {
                    releaseClosedWorkerCommonProofVerificationFamilyAdapter(
                        input.verificationFamilyAdapter,
                    );
                } catch (releaseError) {
                    throw new BrowserActionStorageCustodyError(
                        'OwnedWorkerFailure',
                        'The mismatched common-proof verifier preparation could not be retired.',
                        releaseError,
                    );
                }
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'The prepared common-proof verifier belongs to another proof attempt.',
                );
            }
        } finally {
            verificationDescription.commonProofVerificationBindingHash.fill(0);
        }

        record.operationActive = true;
        let applicationHandoff: CommonProofApplicationHandoff | undefined;
        let applicationHandoffBoundaryStarted = false;
        try {
            record.verifiedCapability =
                await runClosedWorkerCommonProofVerificationFamilyAdapter(
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
                );
            await record.assertDurableBindingCurrent({
                durableBindingIdentifier: input.durableBindingIdentifier,
                witnessRoleIdentifier: input.witnessRoleIdentifier,
            });
            applicationHandoffBoundaryStarted = true;
            applicationHandoff = await record.custody.armApplicationHandoff();
            await completeInstalledCommonProofCustody(record);
            await record.refreshDurableBindingAfterControlledCleanup({
                durableBindingIdentifier: input.durableBindingIdentifier,
                witnessRoleIdentifier: input.witnessRoleIdentifier,
            });
            const result = await record.applyVerifiedCommonProof({
                durableBindingIdentifier: input.durableBindingIdentifier,
                handoff: applicationHandoff,
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
                witnessRoleIdentifier: input.witnessRoleIdentifier,
            });
            finalizeInstalledCommonProofExecutionEnvironment(
                environment,
                record,
            );
            return result;
        } catch (error) {
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
            applicationHandoff?.canonicalMarkerRecordBytes.fill(0);
            if (!record.closed) {
                record.operationActive = false;
            }
        }
    });
};

type CustodyWorkerScope = Readonly<{
    addEventListener(
        type: 'message',
        listener: (event: MessageEvent<unknown>) => void,
    ): void;
    postMessage(message: CustodyWorkerResponse): void;
    removeEventListener(
        type: 'message',
        listener: (event: MessageEvent<unknown>) => void,
    ): void;
}>;

type ActiveClientRequest = Readonly<{
    command: CustodyWorkerCommand;
    reject(error: Error): void;
    requestIdentifier: number;
    resolve(value: unknown): void;
    validateResult(value: unknown): unknown;
}>;

type WorkerCommittedFoundationInitializationResult = Readonly<{
    batchIdentifier: string;
    freshnessCoordinate: BrowserFoundationFreshnessCoordinate;
}>;

type WorkerActivatedFoundationInitializationResult = Readonly<{
    actionRandomnessHandleIdentifier: string;
    orderedWitnessRoleHandleIdentifiers: readonly string[];
}>;

const committedFoundationBatchIdentifiers = new WeakMap<object, string>();
const recoveredFoundationBatchIdentifiers = new WeakMap<object, string>();
const normalWitnessRoleSessionIdentifiers = new WeakMap<object, string>();
const foundationActionRandomnessHandleIdentifiers = new WeakMap<
    object,
    string
>();
const foundationStateReservationIntentHandleIdentifiers = new WeakMap<
    object,
    string
>();
const durableStateBindingHandleIdentifiers = new WeakMap<object, string>();
const checkpointIdentifiers = new WeakMap<object, string>();

const requireCheckpointIdentifier = (
    checkpoint: BrowserFoundationCheckpointHandle,
): string => {
    const identifier =
        typeof checkpoint === 'object' && checkpoint !== null
            ? checkpointIdentifiers.get(checkpoint)
            : undefined;
    if (identifier === undefined) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The checkpoint handle was not issued by this browser foundation storage authority.',
        );
    }
    return identifier;
};

const requireIssuedHandleIdentifier = (
    handle: unknown,
    identifiers: WeakMap<object, string>,
    label: string,
): string => {
    const identifier =
        typeof handle === 'object' && handle !== null
            ? identifiers.get(handle)
            : undefined;
    if (identifier === undefined) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            `${label} was not issued by this browser foundation operation owner.`,
        );
    }
    return identifier;
};

const isPlainRecord = (value: unknown): value is Record<string, unknown> => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        return false;
    }
    const prototype = Reflect.getPrototypeOf(value);

    return prototype === Object.prototype || prototype === null;
};

const hasRequiredKeys = (
    value: Record<string, unknown>,
    requiredKeys: readonly string[],
): boolean =>
    requiredKeys.every((requiredKey) =>
        Object.prototype.hasOwnProperty.call(value, requiredKey),
    );

const isSafePositiveInteger = (value: unknown): value is number =>
    typeof value === 'number' && Number.isSafeInteger(value) && value > 0;

const isCustodyErrorCode = (
    value: unknown,
): value is BrowserActionStorageCustodyErrorCode =>
    typeof value === 'string' &&
    browserActionStorageCustodyErrorCodes.includes(
        value as BrowserActionStorageCustodyErrorCode,
    );

const copyBytes = (
    value: unknown,
    byteLength: number,
    label: string,
): Uint8Array => {
    if (!(value instanceof Uint8Array) || value.byteLength !== byteLength) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            `${label} must contain exactly ${byteLength} bytes.`,
        );
    }

    return value.slice();
};

const copyBoundedBytes = (
    value: unknown,
    maximumByteLength: number,
    label: string,
): Uint8Array => {
    if (
        !(value instanceof Uint8Array) ||
        value.byteLength > maximumByteLength
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            `${label} must be a byte array within the worker-channel copy bound.`,
        );
    }
    return value.slice();
};

const copyCheckpointBoundary = <
    Boundary extends CheckpointBoundary | ExpectedCheckpointBoundary,
>(
    value: Boundary,
    includeDescriptor: Boundary extends CheckpointBoundary ? true : false,
): Boundary => {
    const stateStreamDescriptorBytes = (value as Partial<CheckpointBoundary>)
        .stateStreamDescriptorBytes;
    if (
        !isPlainRecord(value) ||
        !Number.isSafeInteger(value.operationKind) ||
        !Number.isSafeInteger(value.safeBoundaryOrdinal) ||
        typeof value.stateStreamDomain !== 'string' ||
        !Array.isArray(value.orderedRandomCursors) ||
        !Array.isArray(value.orderedSourceDigests) ||
        value.orderedRandomCursors.length > maximumCheckpointCollectionLength ||
        value.orderedSourceDigests.length > maximumCheckpointCollectionLength ||
        (includeDescriptor &&
            !(stateStreamDescriptorBytes instanceof Uint8Array))
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The checkpoint boundary is malformed or outside the worker-channel copy bound.',
        );
    }
    const orderedRandomCursors = value.orderedRandomCursors.map(
        (cursor, cursorIndex) => {
            if (
                !isPlainRecord(cursor) ||
                !Number.isSafeInteger(cursor.family) ||
                !Number.isSafeInteger(cursor.purpose) ||
                typeof cursor.nextCounter !== 'bigint' ||
                (cursor.nextUnreadBitOffsetInBufferedBlock !== undefined &&
                    !Number.isSafeInteger(
                        cursor.nextUnreadBitOffsetInBufferedBlock,
                    ))
            ) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    `Checkpoint random cursor ${String(cursorIndex)} is malformed.`,
                );
            }
            return Object.freeze({
                derivationContextHash: copyBytes(
                    cursor.derivationContextHash,
                    storageRootCommitmentByteLength,
                    `Checkpoint random cursor ${String(cursorIndex)} derivation-context hash`,
                ),
                family: cursor.family,
                nextCounter: cursor.nextCounter,
                ...(cursor.nextUnreadBitOffsetInBufferedBlock === undefined
                    ? {}
                    : {
                          nextUnreadBitOffsetInBufferedBlock:
                              cursor.nextUnreadBitOffsetInBufferedBlock,
                      }),
                purpose: cursor.purpose,
                streamAttemptIdentifier: copyBytes(
                    cursor.streamAttemptIdentifier,
                    32,
                    `Checkpoint random cursor ${String(cursorIndex)} stream-attempt identifier`,
                ),
            });
        },
    );
    return Object.freeze({
        operationKind: value.operationKind,
        orderedRandomCursors: Object.freeze(orderedRandomCursors),
        orderedSourceDigests: Object.freeze(
            value.orderedSourceDigests.map((digest, digestIndex) =>
                copyBytes(
                    digest,
                    storageRootCommitmentByteLength,
                    `Checkpoint source digest ${String(digestIndex)}`,
                ),
            ),
        ),
        safeBoundaryOrdinal: value.safeBoundaryOrdinal,
        ...(includeDescriptor
            ? {
                  stateStreamDescriptorBytes: copyBoundedBytes(
                      stateStreamDescriptorBytes,
                      maximumCheckpointDescriptorByteLength,
                      'Checkpoint state-stream descriptor',
                  ),
              }
            : {}),
        stateStreamDomain: value.stateStreamDomain,
    }) as Boundary;
};

const copyCheckpointDescription = (
    value: unknown,
): BrowserFoundationCheckpointDescription => {
    if (
        !isPlainRecord(value) ||
        !(value.checkpointLineageIdentifier instanceof Uint8Array)
    ) {
        throw new BrowserActionStorageCustodyError(
            'OwnedWorkerFailure',
            'The owned worker returned a malformed checkpoint description.',
        );
    }
    return Object.freeze({
        checkpointLineageIdentifier: copyBytes(
            value.checkpointLineageIdentifier,
            32,
            'Checkpoint lineage identifier',
        ),
        ...(value.canonicalManifestBytes === undefined
            ? {}
            : {
                  canonicalManifestBytes: copyBoundedBytes(
                      value.canonicalManifestBytes,
                      maximumCheckpointDescriptorByteLength,
                      'Checkpoint canonical manifest',
                  ),
              }),
        ...(value.stateStreamDescriptorBytes === undefined
            ? {}
            : {
                  stateStreamDescriptorBytes: copyBoundedBytes(
                      value.stateStreamDescriptorBytes,
                      maximumCheckpointDescriptorByteLength,
                      'Checkpoint state-stream descriptor',
                  ),
              }),
    });
};

const createCheckpointHandle = (
    value: unknown,
): BrowserFoundationCheckpointHandle => {
    if (
        !isPlainRecord(value) ||
        typeof value.checkpointIdentifier !== 'string' ||
        !/^[0-9a-f]{64}$/u.test(value.checkpointIdentifier)
    ) {
        throw new BrowserActionStorageCustodyError(
            'OwnedWorkerFailure',
            'The owned worker returned a malformed checkpoint handle.',
        );
    }
    const checkpoint = Object.freeze({}) as BrowserFoundationCheckpointHandle;
    checkpointIdentifiers.set(checkpoint, value.checkpointIdentifier);
    return checkpoint;
};

const copyFoundationFreshnessCoordinate = (
    value: unknown,
): BrowserFoundationFreshnessCoordinate => {
    if (
        !isPlainRecord(value) ||
        !hasRequiredKeys(value, [
            'authenticatedHeadDigest',
            'freshnessSequence',
            'storageInstanceIdentity',
        ]) ||
        typeof value.freshnessSequence !== 'bigint' ||
        value.freshnessSequence < 0n
    ) {
        throw new BrowserActionStorageCustodyError(
            'OwnedWorkerFailure',
            'The owned worker returned a malformed foundation freshness coordinate.',
        );
    }
    return Object.freeze({
        authenticatedHeadDigest: copyBytes(
            value.authenticatedHeadDigest,
            storageRootCommitmentByteLength,
            'Foundation authenticated-head digest',
        ),
        freshnessSequence: value.freshnessSequence,
        storageInstanceIdentity: copyBytes(
            value.storageInstanceIdentity,
            storageRootCommitmentByteLength,
            'Foundation storage-instance identity',
        ),
    });
};

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean => {
    if (left.byteLength !== right.byteLength) {
        return false;
    }
    let difference = 0;
    for (let byteIndex = 0; byteIndex < left.byteLength; byteIndex += 1) {
        difference |= (left[byteIndex] ?? 0) ^ (right[byteIndex] ?? 0);
    }
    return difference === 0;
};

const foundationCoordinatesEqual = (
    left: BrowserFoundationFreshnessCoordinate,
    right: BrowserFoundationFreshnessCoordinate,
): boolean =>
    left.freshnessSequence === right.freshnessSequence &&
    bytesEqual(left.authenticatedHeadDigest, right.authenticatedHeadDigest) &&
    bytesEqual(left.storageInstanceIdentity, right.storageInstanceIdentity);

const destroyFoundationCoordinate = (
    coordinate: BrowserFoundationFreshnessCoordinate,
): void => {
    coordinate.authenticatedHeadDigest.fill(0);
    coordinate.storageInstanceIdentity.fill(0);
};

const copyWorkerCommittedFoundationInitializationResult = (
    value: unknown,
): WorkerCommittedFoundationInitializationResult => {
    if (
        !isPlainRecord(value) ||
        !hasRequiredKeys(value, ['batchIdentifier', 'freshnessCoordinate']) ||
        typeof value.batchIdentifier !== 'string' ||
        !/^[0-9a-f]{64}$/u.test(value.batchIdentifier)
    ) {
        throw new BrowserActionStorageCustodyError(
            'OwnedWorkerFailure',
            'The owned worker returned malformed committed foundation initialization authority.',
        );
    }
    const freshnessCoordinate = copyFoundationFreshnessCoordinate(
        value.freshnessCoordinate,
    );
    if (freshnessCoordinate.freshnessSequence !== 0n) {
        throw new BrowserActionStorageCustodyError(
            'OwnedWorkerFailure',
            'Fresh foundation initialization must begin at freshness sequence zero.',
        );
    }
    return Object.freeze({
        batchIdentifier: value.batchIdentifier,
        freshnessCoordinate,
    });
};

const createBrowserFreshFoundationInitializationCommit = (
    value: unknown,
): BrowserFreshFoundationInitializationCommit => {
    const copied = copyWorkerCommittedFoundationInitializationResult(value);
    const committedBatch = Object.freeze(
        {},
    ) as BrowserFreshFoundationInitializationCommit['committedBatch'];
    committedFoundationBatchIdentifiers.set(
        committedBatch,
        copied.batchIdentifier,
    );
    return Object.freeze({
        committedBatch,
        freshnessCoordinate: copied.freshnessCoordinate,
    });
};

const createBrowserRecoveredFoundationInitialization = (
    value: unknown,
): BrowserRecoveredFoundationInitialization => {
    if (
        !isPlainRecord(value) ||
        typeof value.batchIdentifier !== 'string' ||
        !/^[0-9a-f]{64}$/u.test(value.batchIdentifier)
    ) {
        throw new BrowserActionStorageCustodyError(
            'OwnedWorkerFailure',
            'The owned worker returned malformed recovered foundation initialization authority.',
        );
    }
    const freshnessCoordinate = copyFoundationFreshnessCoordinate(
        value.freshnessCoordinate,
    );
    const recoveredBatch = Object.freeze(
        {},
    ) as BrowserRecoveredFoundationInitializationBatch;
    recoveredFoundationBatchIdentifiers.set(
        recoveredBatch,
        value.batchIdentifier,
    );
    destroyFoundationCoordinate(freshnessCoordinate);
    return Object.freeze({ recoveredBatch });
};

const copyWorkerActivatedFoundationInitializationResult = (
    value: unknown,
): WorkerActivatedFoundationInitializationResult => {
    if (
        !isPlainRecord(value) ||
        typeof value.actionRandomnessHandleIdentifier !== 'string' ||
        !/^[0-9a-f]{64}$/u.test(value.actionRandomnessHandleIdentifier) ||
        !Array.isArray(value.orderedWitnessRoleHandleIdentifiers) ||
        value.orderedWitnessRoleHandleIdentifiers.length !==
            foundationProfile.participantCount - 1 ||
        value.orderedWitnessRoleHandleIdentifiers.some(
            (identifier) =>
                typeof identifier !== 'string' ||
                !/^[0-9a-f]{64}$/u.test(identifier),
        ) ||
        new Set(value.orderedWitnessRoleHandleIdentifiers).size !==
            foundationProfile.participantCount - 1
    ) {
        throw new BrowserActionStorageCustodyError(
            'OwnedWorkerFailure',
            'The owned worker returned malformed activated foundation authority.',
        );
    }
    return Object.freeze({
        actionRandomnessHandleIdentifier:
            value.actionRandomnessHandleIdentifier,
        orderedWitnessRoleHandleIdentifiers: Object.freeze(
            value.orderedWitnessRoleHandleIdentifiers.map(
                (identifier) => identifier as string,
            ),
        ),
    });
};

const createBrowserActivatedFoundationInitialization = (
    value: unknown,
): Awaited<
    ReturnType<
        BrowserFoundationOperationOwner['activateFreshFoundationInitialization']
    >
> => {
    const copied = copyWorkerActivatedFoundationInitializationResult(value);
    const actionRandomnessHandle = Object.freeze(
        {},
    ) as BrowserFoundationActionRandomnessHandle;
    foundationActionRandomnessHandleIdentifiers.set(
        actionRandomnessHandle,
        copied.actionRandomnessHandleIdentifier,
    );
    const orderedWitnessRoleHandles =
        copied.orderedWitnessRoleHandleIdentifiers.map((identifier) => {
            const handle = Object.freeze(
                {},
            ) as BrowserFoundationNormalWitnessRoleHandle;
            normalWitnessRoleSessionIdentifiers.set(handle, identifier);
            return handle;
        });
    return Object.freeze({
        actionRandomnessHandle,
        orderedWitnessRoleHandles: Object.freeze(orderedWitnessRoleHandles),
    });
};

const createDurableStateBindingHandle = (
    value: unknown,
): BrowserFoundationDurableStateBindingHandle => {
    const identifier = copyOpaqueWorkerIdentifier(
        value,
        'Durable state binding handle identifier',
    );
    const handle = Object.freeze(
        {},
    ) as BrowserFoundationDurableStateBindingHandle;
    durableStateBindingHandleIdentifiers.set(handle, identifier);
    return handle;
};

const copyBytesVerificationResult = (
    value: unknown,
): VerificationResult<Uint8Array> => {
    if (!isPlainRecord(value) || typeof value.isValid !== 'boolean') {
        throw new BrowserActionStorageCustodyError(
            'OwnedWorkerFailure',
            'The owned worker returned a malformed verification result.',
        );
    }
    if (value.isValid) {
        return Object.freeze({
            isValid: true,
            value: copyBoundedBytes(
                value.value,
                foundationProfile.maximumCopiedBufferByteLength,
                'Verified canonical bytes',
            ),
        });
    }
    if (
        typeof value.refusalReason !== 'string' ||
        !Object.prototype.hasOwnProperty.call(
            refusalReasonCodes,
            value.refusalReason,
        )
    ) {
        throw new BrowserActionStorageCustodyError(
            'OwnedWorkerFailure',
            'The owned worker returned an unassigned refusal reason.',
        );
    }
    return Object.freeze({
        isValid: false,
        refusalReason: value.refusalReason as RefusalReason,
    });
};

const copyWorkerProducedStateReservationIntentVerificationResult = (
    value: unknown,
): VerificationResult<
    Readonly<{
        canonicalReservationIntentCarrier: Uint8Array;
        stateIntentIdentifier: string;
    }>
> => {
    if (!isPlainRecord(value) || typeof value.isValid !== 'boolean') {
        throw new BrowserActionStorageCustodyError(
            'OwnedWorkerFailure',
            'The worker state producer returned a malformed reservation-intent result.',
        );
    }
    if (value.isValid) {
        if (!isPlainRecord(value.value)) {
            throw new BrowserActionStorageCustodyError(
                'OwnedWorkerFailure',
                'The worker state producer returned malformed reservation-intent material.',
            );
        }
        return Object.freeze({
            isValid: true,
            value: Object.freeze({
                canonicalReservationIntentCarrier: copyBoundedBytes(
                    value.value.canonicalReservationIntentCarrier,
                    foundationProfile.maximumCopiedBufferByteLength,
                    'Produced canonical state reservation-intent carrier',
                ),
                stateIntentIdentifier: copyOpaqueWorkerIdentifier(
                    value.value.stateIntentIdentifier,
                    'Produced state reservation-intent identifier',
                ),
            }),
        });
    }
    if (
        typeof value.refusalReason !== 'string' ||
        !Object.prototype.hasOwnProperty.call(
            refusalReasonCodes,
            value.refusalReason,
        )
    ) {
        throw new BrowserActionStorageCustodyError(
            'OwnedWorkerFailure',
            'The worker state producer returned an unassigned reservation-intent refusal reason.',
        );
    }
    return Object.freeze({
        isValid: false,
        refusalReason: value.refusalReason as RefusalReason,
    });
};

const copyProducedStateReservationIntentVerificationResult = (
    value: unknown,
): VerificationResult<BrowserFoundationProducedStateReservationIntent> => {
    if (!isPlainRecord(value) || typeof value.isValid !== 'boolean') {
        throw new BrowserActionStorageCustodyError(
            'OwnedWorkerFailure',
            'The owned worker returned a malformed produced-intent result.',
        );
    }
    if (value.isValid) {
        if (!isPlainRecord(value.value)) {
            throw new BrowserActionStorageCustodyError(
                'OwnedWorkerFailure',
                'The owned worker returned malformed produced-intent material.',
            );
        }
        const identifier = copyOpaqueWorkerIdentifier(
            value.value.stateIntentIdentifier,
            'Produced state reservation-intent identifier',
        );
        const intentHandle = Object.freeze(
            {},
        ) as BrowserFoundationStateReservationIntentHandle;
        foundationStateReservationIntentHandleIdentifiers.set(
            intentHandle,
            identifier,
        );
        return Object.freeze({
            isValid: true,
            value: Object.freeze({
                canonicalReservationIntentCarrier: copyBoundedBytes(
                    value.value.canonicalReservationIntentCarrier,
                    foundationProfile.maximumCopiedBufferByteLength,
                    'Produced canonical state reservation-intent carrier',
                ),
                intentHandle,
            }),
        });
    }
    if (
        typeof value.refusalReason !== 'string' ||
        !Object.prototype.hasOwnProperty.call(
            refusalReasonCodes,
            value.refusalReason,
        )
    ) {
        throw new BrowserActionStorageCustodyError(
            'OwnedWorkerFailure',
            'The owned worker returned an unassigned produced-intent refusal reason.',
        );
    }
    return Object.freeze({
        isValid: false,
        refusalReason: value.refusalReason as RefusalReason,
    });
};

const copyProducedStateReservationVerificationResult = (
    value: unknown,
): VerificationResult<BrowserFoundationProducedStateReservation> => {
    if (!isPlainRecord(value) || typeof value.isValid !== 'boolean') {
        throw new BrowserActionStorageCustodyError(
            'OwnedWorkerFailure',
            'The owned worker returned a malformed produced-reservation result.',
        );
    }
    if (value.isValid) {
        if (!isPlainRecord(value.value)) {
            throw new BrowserActionStorageCustodyError(
                'OwnedWorkerFailure',
                'The owned worker returned malformed produced-reservation material.',
            );
        }
        return Object.freeze({
            isValid: true,
            value: Object.freeze({
                canonicalStateCertificate: copyBoundedBytes(
                    value.value.canonicalStateCertificate,
                    foundationProfile.maximumCopiedBufferByteLength,
                    'Produced canonical state certificate',
                ),
                stateReservationIdentifier: copyOpaqueWorkerIdentifier(
                    value.value.stateReservationIdentifier,
                    'Produced state reservation identifier',
                ),
            }),
        });
    }
    if (
        typeof value.refusalReason !== 'string' ||
        !Object.prototype.hasOwnProperty.call(
            refusalReasonCodes,
            value.refusalReason,
        )
    ) {
        throw new BrowserActionStorageCustodyError(
            'OwnedWorkerFailure',
            'The owned worker returned an unassigned produced-reservation refusal reason.',
        );
    }
    return Object.freeze({
        isValid: false,
        refusalReason: value.refusalReason as RefusalReason,
    });
};

const copyRootBinding = (value: unknown): BrowserActionStorageRootBinding => {
    if (
        !isPlainRecord(value) ||
        !hasRequiredKeys(value, [
            'actionContextHash',
            'ceremonyContextHash',
            'participantId',
            'suiteId',
        ])
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The browser action-storage root binding is malformed.',
        );
    }

    return Object.freeze({
        actionContextHash: copyBytes(
            value.actionContextHash,
            storageRootCommitmentByteLength,
            'Action-context hash',
        ),
        ceremonyContextHash: copyBytes(
            value.ceremonyContextHash,
            storageRootCommitmentByteLength,
            'Ceremony-context hash',
        ),
        participantId: copyBytes(
            value.participantId,
            storageRootCommitmentByteLength,
            'Participant identity',
        ),
        suiteId: copyBytes(
            value.suiteId,
            storageRootCommitmentByteLength,
            'Suite identifier',
        ),
    });
};

const copyFoundationOperationInitializationInput = (
    value: unknown,
): BrowserFoundationInitializationInput => {
    if (!isPlainRecord(value)) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'Browser foundation initialization input is malformed.',
        );
    }
    const preparation = copyBrowserFoundationInitializationPreparationInput(
        value as BrowserFoundationInitializationPreparationInput,
    );
    return Object.freeze({
        ...preparation,
        canonicalRosterBytes: copyBoundedBytes(
            value.canonicalRosterBytes,
            foundationProfile.maximumCopiedBufferByteLength,
            'Canonical roster bytes',
        ),
    });
};

const copyUntrustedExpectedCommitment = (
    value: unknown,
): UntrustedExpectedStorageRootCommitment => {
    if (
        !isPlainRecord(value) ||
        !hasRequiredKeys(value, ['storageRootCommitment'])
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The untrusted expected storage-root commitment is malformed.',
        );
    }

    return Object.freeze({
        storageRootCommitment: copyBytes(
            value.storageRootCommitment,
            storageRootCommitmentByteLength,
            'Untrusted expected storage-root commitment',
        ),
    });
};

const copySnapshot = (value: unknown): BrowserDeviceWrappingSnapshot => {
    if (
        !isPlainRecord(value) ||
        !hasRequiredKeys(value, ['mutationIdentifier', 'storageRootCommitment'])
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The browser action-storage custody snapshot is malformed.',
        );
    }

    return Object.freeze({
        mutationIdentifier: copyBytes(
            value.mutationIdentifier,
            mutationIdentifierByteLength,
            'Custody mutation identifier',
        ),
        storageRootCommitment: copyBytes(
            value.storageRootCommitment,
            storageRootCommitmentByteLength,
            'Snapshot storage-root commitment',
        ),
    });
};

const copyBoundSnapshotInput = (
    value: unknown,
): Readonly<{
    expectedSnapshot: BrowserDeviceWrappingSnapshot;
    untrustedExpectedCommitment: UntrustedExpectedStorageRootCommitment;
}> => {
    if (
        !isPlainRecord(value) ||
        !hasRequiredKeys(value, [
            'expectedSnapshot',
            'untrustedExpectedCommitment',
        ])
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The commitment-bound custody input is malformed.',
        );
    }

    return Object.freeze({
        expectedSnapshot: copySnapshot(value.expectedSnapshot),
        untrustedExpectedCommitment: copyUntrustedExpectedCommitment(
            value.untrustedExpectedCommitment,
        ),
    });
};

const copyOptionalSnapshot = (
    value: unknown,
): BrowserDeviceWrappingSnapshot | undefined =>
    value === undefined ? undefined : copySnapshot(value);

const validateVoidResult = (value: unknown): undefined => {
    if (value !== undefined) {
        throw new BrowserActionStorageCustodyError(
            'OwnedWorkerFailure',
            'The owned worker returned unexpected command output.',
        );
    }

    return undefined;
};

const copyLimits = (value: unknown): UntrustedStorageTransactionLimits => {
    const keys = [
        'maximumActiveTransactionCount',
        'maximumLeaseByteLength',
        'maximumLeaseCountPerTransaction',
        'maximumOwnedRecordCount',
        'maximumStoredValueByteLength',
        'maximumTransactionByteLength',
        'maximumTransactionLifetimeMilliseconds',
    ] as const;
    if (!isPlainRecord(value) || !hasRequiredKeys(value, keys)) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'Browser storage transaction limits are malformed.',
        );
    }
    for (const key of keys) {
        if (!isSafePositiveInteger(value[key])) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                `Browser storage transaction limit ${key} must be a positive safe integer.`,
            );
        }
    }

    return Object.freeze({
        maximumActiveTransactionCount: value.maximumActiveTransactionCount,
        maximumLeaseByteLength: value.maximumLeaseByteLength,
        maximumLeaseCountPerTransaction: value.maximumLeaseCountPerTransaction,
        maximumOwnedRecordCount: value.maximumOwnedRecordCount,
        maximumStoredValueByteLength: value.maximumStoredValueByteLength,
        maximumTransactionByteLength: value.maximumTransactionByteLength,
        maximumTransactionLifetimeMilliseconds:
            value.maximumTransactionLifetimeMilliseconds,
    }) as UntrustedStorageTransactionLimits;
};

const copyWorkerConfiguration = (
    value: unknown,
): BrowserActionStorageCustodyWorkerConfiguration => {
    if (
        !isPlainRecord(value) ||
        !hasRequiredKeys(value, [
            'acquisitionDeadlineEpochMilliseconds',
            'binding',
            'databaseName',
            'knownStorageRootCommitment',
            'limits',
            'namespace',
            'runtimeBuildManifestHash',
        ]) ||
        typeof value.databaseName !== 'string' ||
        value.databaseName.length === 0 ||
        value.databaseName.length > maximumDatabaseNameLength ||
        typeof value.namespace !== 'string' ||
        value.namespace.length > maximumNamespaceLength ||
        !namespacePattern.test(value.namespace) ||
        (value.acquisitionDeadlineEpochMilliseconds !== undefined &&
            (!Number.isSafeInteger(
                value.acquisitionDeadlineEpochMilliseconds,
            ) ||
                (value.acquisitionDeadlineEpochMilliseconds as number) < 0))
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'Browser action-storage worker configuration is malformed.',
        );
    }

    return Object.freeze({
        acquisitionDeadlineEpochMilliseconds:
            value.acquisitionDeadlineEpochMilliseconds as number | undefined,
        binding: copyRootBinding(value.binding),
        databaseName: value.databaseName,
        knownStorageRootCommitment:
            value.knownStorageRootCommitment === undefined
                ? undefined
                : copyBytes(
                      value.knownStorageRootCommitment,
                      storageRootCommitmentByteLength,
                      'Known storage-root commitment',
                  ),
        limits: copyLimits(value.limits),
        namespace: value.namespace,
        runtimeBuildManifestHash: copyBytes(
            value.runtimeBuildManifestHash,
            storageRootCommitmentByteLength,
            'Runtime build-manifest hash',
        ),
    });
};

const isCustodyWorkerResponse = (
    value: unknown,
): value is CustodyWorkerResponse => {
    if (!isPlainRecord(value)) {
        return false;
    }
    if (value.messageKind === 'browser-action-storage-custody-channel-failed') {
        return (
            hasRequiredKeys(value, ['errorCode', 'messageKind']) &&
            value.errorCode === 'OwnedWorkerFailure'
        );
    }
    if (!isSafePositiveInteger(value.requestIdentifier)) {
        return false;
    }
    if (value.messageKind === 'browser-action-storage-custody-completed') {
        return hasRequiredKeys(value, [
            'messageKind',
            'requestIdentifier',
            'result',
        ]);
    }

    return (
        value.messageKind === 'browser-action-storage-custody-failed' &&
        hasRequiredKeys(value, [
            'errorCode',
            'messageKind',
            'requestIdentifier',
        ]) &&
        isCustodyErrorCode(value.errorCode)
    );
};

const custodyWorkerCommands: readonly CustodyWorkerCommand[] = [
    'activate-fresh-foundation-initialization',
    'activate-recovered-foundation-initialization',
    'abort-checkpoint-publication',
    'abort-checkpoint-restore',
    'authenticate-foundation-head',
    'begin-checkpoint',
    'begin-checkpoint-publication',
    'begin-checkpoint-restore',
    'cache-foundation-witness-exact-output',
    'cache-foundation-witness-signed-vote-carrier',
    'certify-foundation-action-randomness-reservation',
    'close-action-randomness',
    'close-foundation-action-randomness',
    'close-foundation-witness-durable-binding',
    'close-state-verifier-session',
    'close',
    'commit-fresh-foundation-initialization',
    'commit-foundation-operation-initialization',
    'compare-and-lock-foundation-witness-intent',
    'commit-checkpoint-publication',
    'copy-checkpoint-description',
    'copy-foundation-witness-subject',
    'current-snapshot',
    'delete',
    'derive-record-identifier',
    'derive-target-release-attempt',
    'derive-foundation-target-release-attempt',
    'evict-checkpoint',
    'hash-record-envelope',
    'initialize',
    'create-and-seal-action-randomness',
    'open-sealed-action-randomness',
    'open-recovered-foundation-initialization',
    'open-foundation-witness-durable-binding',
    'open-state-verifier-session',
    'open-record',
    'open-custody',
    'open-root',
    'produce-foundation-action-randomness-reservation-intent',
    'release-foundation-state-reservation-intent',
    'release-state-object',
    'read-checkpoint-restore-chunk',
    'read-foundation-witness-exact-output',
    'read-foundation-witness-signed-vote-carrier',
    'retire',
    'resume-checkpoint',
    'seal-record',
    'verify-action-randomness-reservation',
    'verify-foundation-action-randomness-reservation',
    'verify-state-reservation',
    'vote-for-foundation-action-randomness-reservation-intent',
    'write-checkpoint-publication-chunk',
];

const isCustodyWorkerRequest = (
    value: unknown,
): value is CustodyWorkerRequest =>
    isPlainRecord(value) &&
    hasRequiredKeys(value, [
        'command',
        'input',
        'messageKind',
        'requestIdentifier',
    ]) &&
    value.messageKind === 'browser-action-storage-custody-request' &&
    isSafePositiveInteger(value.requestIdentifier) &&
    typeof value.command === 'string' &&
    custodyWorkerCommands.includes(value.command as CustodyWorkerCommand);

class BrowserActionStorageCustodyWorkerClient implements BrowserFoundationStorageAuthority {
    #activeRequest: ActiveClientRequest | undefined;
    #binding: BrowserActionStorageRootBinding | undefined;
    #closed = false;
    #closing = false;
    #closePromise: Promise<void> | undefined;
    #nextRequestIdentifier = 1;
    #operationTail: Promise<void> = Promise.resolve();
    #terminalFailure: BrowserActionStorageCustodyError | undefined;
    readonly #worker: CustodyWorkerLike;
    readonly #errorListener: EventListener;
    readonly #messageErrorListener: EventListener;
    readonly #messageListener: EventListener;

    public constructor(worker: CustodyWorkerLike) {
        this.#worker = worker;
        this.#messageListener = (event): void => {
            this.#handleMessage((event as MessageEvent<unknown>).data);
        };
        this.#errorListener = (): void => {
            this.#failChannel(
                new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The browser action-storage worker failed.',
                ),
            );
        };
        this.#messageErrorListener = (): void => {
            this.#failChannel(
                new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The browser action-storage worker returned an uncloneable message.',
                ),
            );
        };
        worker.addEventListener('message', this.#messageListener);
        worker.addEventListener('error', this.#errorListener);
        worker.addEventListener('messageerror', this.#messageErrorListener);
    }

    public open(
        configuration: BrowserActionStorageCustodyWorkerConfiguration,
    ): Promise<void> {
        let copiedConfiguration: BrowserActionStorageCustodyWorkerConfiguration;
        try {
            copiedConfiguration = copyWorkerConfiguration({
                acquisitionDeadlineEpochMilliseconds:
                    configuration.acquisitionDeadlineEpochMilliseconds,
                binding: configuration.binding,
                databaseName: configuration.databaseName,
                knownStorageRootCommitment:
                    configuration.knownStorageRootCommitment,
                limits: configuration.limits,
                namespace: configuration.namespace,
                runtimeBuildManifestHash:
                    configuration.runtimeBuildManifestHash,
            });
        } catch (error) {
            return Promise.reject(
                error instanceof Error
                    ? error
                    : new BrowserActionStorageCustodyError(
                          'InvalidInput',
                          'Browser action-storage worker configuration could not be copied.',
                          error,
                      ),
            );
        }

        return this.#queueOperation(async () => {
            await this.#sendRequest(
                'open-custody',
                copiedConfiguration,
                validateVoidResult,
            );
            this.#binding = copyRootBinding(copiedConfiguration.binding);
        });
    }

    public copyBinding(): BrowserActionStorageRootBinding {
        if (this.#binding === undefined) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'The browser action-storage worker binding is unavailable.',
            );
        }
        return copyRootBinding(this.#binding);
    }

    public initialize(): Promise<BrowserDeviceWrappingSnapshot> {
        return this.#queueOperation(() =>
            this.#sendRequest('initialize', undefined, copySnapshot),
        );
    }

    public currentSnapshot(): Promise<
        BrowserDeviceWrappingSnapshot | undefined
    > {
        return this.#queueOperation(() =>
            this.#sendRequest(
                'current-snapshot',
                undefined,
                copyOptionalSnapshot,
            ),
        );
    }

    public openIntoOwnedWorker(input: {
        expectedSnapshot: BrowserDeviceWrappingSnapshot;
        untrustedExpectedCommitment: UntrustedExpectedStorageRootCommitment;
    }): Promise<void> {
        return this.#queueValidatedOperation(
            () => copyBoundSnapshotInput(input),
            (copiedInput) =>
                this.#sendRequest('open-root', copiedInput, validateVoidResult),
        );
    }

    public authenticateFoundationHead(): Promise<BrowserFoundationFreshnessCoordinate> {
        return this.#queueOperation(() =>
            this.#sendRequest(
                'authenticate-foundation-head',
                undefined,
                copyFoundationFreshnessCoordinate,
            ),
        );
    }

    public beginCheckpoint(
        streamAttemptIdentifiers: readonly Uint8Array[],
    ): Promise<BrowserFoundationCheckpointHandle> {
        return this.#queueValidatedOperation(
            () => {
                if (
                    !Array.isArray(streamAttemptIdentifiers) ||
                    streamAttemptIdentifiers.length >
                        maximumCheckpointCollectionLength
                ) {
                    throw new BrowserActionStorageCustodyError(
                        'InvalidInput',
                        'Checkpoint stream-attempt identifiers are outside the worker-channel copy bound.',
                    );
                }
                return Object.freeze(
                    streamAttemptIdentifiers.map((identifier, index) =>
                        copyBytes(
                            identifier,
                            32,
                            `Checkpoint stream-attempt identifier ${String(index)}`,
                        ),
                    ),
                );
            },
            (copiedIdentifiers) =>
                this.#sendRequest(
                    'begin-checkpoint',
                    copiedIdentifiers,
                    createCheckpointHandle,
                ),
        );
    }

    public copyCheckpointDescription(
        checkpoint: BrowserFoundationCheckpointHandle,
    ): Promise<BrowserFoundationCheckpointDescription> {
        return this.#queueValidatedOperation(
            () => requireCheckpointIdentifier(checkpoint),
            (checkpointIdentifier) =>
                this.#sendRequest(
                    'copy-checkpoint-description',
                    checkpointIdentifier,
                    copyCheckpointDescription,
                ),
        );
    }

    public evictCheckpoint(
        checkpoint: BrowserFoundationCheckpointHandle,
    ): Promise<void> {
        return this.#queueValidatedOperation(
            () => requireCheckpointIdentifier(checkpoint),
            async (checkpointIdentifier) => {
                await this.#sendRequest(
                    'evict-checkpoint',
                    checkpointIdentifier,
                    validateVoidResult,
                );
                checkpointIdentifiers.delete(checkpoint);
            },
        );
    }

    public publishCheckpoint(
        checkpoint: BrowserFoundationCheckpointHandle,
        input: {
            boundary: CheckpointBoundary;
            stateChunks: AsyncIterable<Uint8Array> | Iterable<Uint8Array>;
        },
    ): Promise<Uint8Array> {
        return this.#queueOperation(async () => {
            const checkpointIdentifier =
                requireCheckpointIdentifier(checkpoint);
            const boundary = copyCheckpointBoundary(input.boundary, true);
            const source = input.stateChunks;
            if (typeof source !== 'object' || source === null) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'Checkpoint state chunks must be iterable.',
                );
            }
            const asyncIteratorFactory = (
                source as Partial<AsyncIterable<Uint8Array>>
            )[Symbol.asyncIterator];
            const iteratorFactory = (source as Partial<Iterable<Uint8Array>>)[
                Symbol.iterator
            ];
            const iterator =
                typeof asyncIteratorFactory === 'function'
                    ? asyncIteratorFactory.call(source)
                    : typeof iteratorFactory === 'function'
                      ? iteratorFactory.call(source)
                      : undefined;
            if (iterator === undefined || typeof iterator.next !== 'function') {
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'Checkpoint state chunks returned an invalid iterator.',
                );
            }
            const publicationIdentifier = await this.#sendRequest(
                'begin-checkpoint-publication',
                { boundary, checkpointIdentifier },
                (value) =>
                    copyOpaqueWorkerIdentifier(
                        value,
                        'Checkpoint publication identifier',
                    ),
            );
            try {
                let chunkIndex = 0;
                for (;;) {
                    const next = await iterator.next();
                    if (typeof next !== 'object' || next === null) {
                        throw new BrowserActionStorageCustodyError(
                            'InvalidInput',
                            'Checkpoint state iterator returned a malformed result.',
                        );
                    }
                    if (next.done === true) {
                        break;
                    }
                    const chunk = copyBoundedBytes(
                        next.value,
                        maximumCheckpointDescriptorByteLength,
                        `Checkpoint state chunk ${String(chunkIndex)}`,
                    );
                    await this.#sendRequest(
                        'write-checkpoint-publication-chunk',
                        { chunk, publicationIdentifier },
                        validateVoidResult,
                    );
                    chunkIndex += 1;
                    if (chunkIndex > maximumCheckpointCollectionLength) {
                        throw new BrowserActionStorageCustodyError(
                            'InvalidInput',
                            'Checkpoint state chunk count exceeds the worker-channel copy bound.',
                        );
                    }
                }
                return await this.#sendRequest(
                    'commit-checkpoint-publication',
                    publicationIdentifier,
                    (value) =>
                        copyBoundedBytes(
                            value,
                            maximumCheckpointDescriptorByteLength,
                            'Checkpoint canonical manifest',
                        ),
                );
            } catch (error) {
                try {
                    await this.#sendRequest(
                        'abort-checkpoint-publication',
                        publicationIdentifier,
                        validateVoidResult,
                    );
                } catch (abortError) {
                    throw new BrowserActionStorageCustodyError(
                        'OwnedWorkerFailure',
                        'Checkpoint publication failed and worker-owned rollback also failed.',
                        [error, abortError],
                    );
                }
                throw error;
            }
        });
    }

    public restoreCheckpointState(
        checkpoint: BrowserFoundationCheckpointHandle,
        consumeChunk: (
            chunkIndex: number,
            chunkBytes: Uint8Array,
        ) => Promise<void> | void,
    ): Promise<void> {
        return this.#queueOperation(async () => {
            if (typeof consumeChunk !== 'function') {
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'Checkpoint restore requires a chunk consumer.',
                );
            }
            const checkpointIdentifier =
                requireCheckpointIdentifier(checkpoint);
            const restoreIdentifier = await this.#sendRequest(
                'begin-checkpoint-restore',
                checkpointIdentifier,
                (value) =>
                    copyOpaqueWorkerIdentifier(
                        value,
                        'Checkpoint restore identifier',
                    ),
            );
            try {
                let expectedChunkIndex = 0;
                for (;;) {
                    const restored = await this.#sendRequest(
                        'read-checkpoint-restore-chunk',
                        restoreIdentifier,
                        (value) => {
                            if (
                                !isPlainRecord(value) ||
                                typeof value.done !== 'boolean'
                            ) {
                                throw new BrowserActionStorageCustodyError(
                                    'OwnedWorkerFailure',
                                    'The owned worker returned malformed checkpoint restore output.',
                                );
                            }
                            if (value.done) {
                                return Object.freeze({ done: true as const });
                            }
                            if (!Number.isSafeInteger(value.chunkIndex)) {
                                throw new BrowserActionStorageCustodyError(
                                    'OwnedWorkerFailure',
                                    'The owned worker returned a malformed checkpoint chunk index.',
                                );
                            }
                            return Object.freeze({
                                chunkBytes: copyBoundedBytes(
                                    value.chunkBytes,
                                    maximumCheckpointDescriptorByteLength,
                                    'Restored checkpoint chunk',
                                ),
                                chunkIndex: value.chunkIndex as number,
                                done: false as const,
                            });
                        },
                    );
                    if (restored.done) {
                        return;
                    }
                    if (restored.chunkIndex !== expectedChunkIndex) {
                        restored.chunkBytes.fill(0);
                        throw new BrowserActionStorageCustodyError(
                            'OwnedWorkerFailure',
                            'The owned worker returned checkpoint chunks out of order.',
                        );
                    }
                    await consumeChunk(
                        restored.chunkIndex,
                        restored.chunkBytes,
                    );
                    expectedChunkIndex += 1;
                }
            } catch (error) {
                try {
                    await this.#sendRequest(
                        'abort-checkpoint-restore',
                        restoreIdentifier,
                        validateVoidResult,
                    );
                } catch (abortError) {
                    throw new BrowserActionStorageCustodyError(
                        'OwnedWorkerFailure',
                        'Checkpoint restore failed and worker-owned abort also failed.',
                        [error, abortError],
                    );
                }
                throw error;
            }
        });
    }

    public resumeCheckpoint(input: {
        checkpointLineageIdentifier: Uint8Array;
        expectedBoundary: ExpectedCheckpointBoundary;
    }): Promise<BrowserFoundationCheckpointHandle> {
        return this.#queueValidatedOperation(
            () => ({
                checkpointLineageIdentifier: copyBytes(
                    input.checkpointLineageIdentifier,
                    32,
                    'Checkpoint lineage identifier',
                ),
                expectedBoundary: copyCheckpointBoundary(
                    input.expectedBoundary,
                    false,
                ),
            }),
            (copiedInput) =>
                this.#sendRequest(
                    'resume-checkpoint',
                    copiedInput,
                    createCheckpointHandle,
                ),
        );
    }

    public commitFreshFoundationInitialization(
        input: BrowserFoundationInitializationPreparationInput,
    ): Promise<BrowserFreshFoundationInitializationCommit> {
        return this.#queueValidatedOperation(
            () => copyBrowserFoundationInitializationPreparationInput(input),
            (copiedInput) =>
                this.#sendRequest(
                    'commit-fresh-foundation-initialization',
                    copiedInput,
                    createBrowserFreshFoundationInitializationCommit,
                ),
        );
    }

    public commitFoundationOperationInitialization(
        input: BrowserFoundationInitializationInput,
    ): Promise<BrowserFreshFoundationInitializationCommit> {
        return this.#queueValidatedOperation(
            () => copyFoundationOperationInitializationInput(input),
            (copiedInput) =>
                this.#sendRequest(
                    'commit-foundation-operation-initialization',
                    copiedInput,
                    createBrowserFreshFoundationInitializationCommit,
                ),
        );
    }

    public openRecoveredFoundationInitialization(
        input: BrowserFoundationInitializationInput,
    ): Promise<BrowserRecoveredFoundationInitialization> {
        return this.#queueValidatedOperation(
            () => copyFoundationOperationInitializationInput(input),
            (copiedInput) =>
                this.#sendRequest(
                    'open-recovered-foundation-initialization',
                    copiedInput,
                    createBrowserRecoveredFoundationInitialization,
                ),
        );
    }

    public activateFreshFoundationInitialization(
        committedBatch: BrowserFreshFoundationInitializationCommit['committedBatch'],
    ): ReturnType<
        BrowserFoundationOperationOwner['activateFreshFoundationInitialization']
    > {
        return this.#queueValidatedOperation(
            () =>
                requireIssuedHandleIdentifier(
                    committedBatch,
                    committedFoundationBatchIdentifiers,
                    'Committed foundation initialization batch',
                ),
            async (batchIdentifier) => {
                const activated = await this.#sendRequest(
                    'activate-fresh-foundation-initialization',
                    batchIdentifier,
                    createBrowserActivatedFoundationInitialization,
                );
                committedFoundationBatchIdentifiers.delete(committedBatch);
                return activated;
            },
        );
    }

    public activateRecoveredFoundationInitialization(
        recoveredBatch: BrowserRecoveredFoundationInitializationBatch,
    ): ReturnType<
        BrowserFoundationOperationOwner['activateRecoveredFoundationInitialization']
    > {
        return this.#queueValidatedOperation(
            () =>
                requireIssuedHandleIdentifier(
                    recoveredBatch,
                    recoveredFoundationBatchIdentifiers,
                    'Recovered foundation initialization batch',
                ),
            async (batchIdentifier) => {
                const activated = await this.#sendRequest(
                    'activate-recovered-foundation-initialization',
                    batchIdentifier,
                    createBrowserActivatedFoundationInitialization,
                );
                recoveredFoundationBatchIdentifiers.delete(recoveredBatch);
                return activated;
            },
        );
    }

    public copyWitnessSubjectParticipantIdentity(
        witnessRole: BrowserFoundationNormalWitnessRoleHandle,
    ): Promise<Uint8Array> {
        return this.#queueValidatedOperation(
            () =>
                requireIssuedHandleIdentifier(
                    witnessRole,
                    normalWitnessRoleSessionIdentifiers,
                    'Foundation witness role',
                ),
            (witnessRoleIdentifier) =>
                this.#sendRequest(
                    'copy-foundation-witness-subject',
                    witnessRoleIdentifier,
                    (value) =>
                        copyBytes(
                            value,
                            storageRootCommitmentByteLength,
                            'Witness subject participant identity',
                        ),
                ),
        );
    }

    public openWitnessDurableStateBinding(
        witnessRole: BrowserFoundationNormalWitnessRoleHandle,
        stateObjectIdentifier: string,
    ): Promise<BrowserFoundationDurableStateBindingHandle> {
        return this.#queueValidatedOperation(
            () => ({
                stateObjectIdentifier: copyOpaqueWorkerIdentifier(
                    stateObjectIdentifier,
                    'State object identifier',
                ),
                witnessRoleIdentifier: requireIssuedHandleIdentifier(
                    witnessRole,
                    normalWitnessRoleSessionIdentifiers,
                    'Foundation witness role',
                ),
            }),
            (copiedInput) =>
                this.#sendRequest(
                    'open-foundation-witness-durable-binding',
                    copiedInput,
                    createDurableStateBindingHandle,
                ),
        );
    }

    public closeWitnessDurableStateBinding(
        durableBinding: BrowserFoundationDurableStateBindingHandle,
    ): Promise<void> {
        return this.#queueValidatedOperation(
            () =>
                requireIssuedHandleIdentifier(
                    durableBinding,
                    durableStateBindingHandleIdentifiers,
                    'Durable state binding',
                ),
            async (durableBindingIdentifier) => {
                await this.#sendRequest(
                    'close-foundation-witness-durable-binding',
                    durableBindingIdentifier,
                    validateVoidResult,
                );
                durableStateBindingHandleIdentifiers.delete(durableBinding);
            },
        );
    }

    public deriveLocalRecordIdentifier(
        input: BrowserLocalRecordIdentifierInput,
    ): Promise<Uint8Array> {
        return this.#queueValidatedOperation(
            () => copyLocalRecordIdentifierInput(input),
            async (copiedInput) => {
                try {
                    return await this.#sendRequest(
                        'derive-record-identifier',
                        copiedInput,
                        (value) => {
                            try {
                                return copyLocalRecordBytes(value, {
                                    allowEmpty: false,
                                    errorCode: 'OwnedWorkerFailure',
                                    exactByteLength:
                                        storageRootCommitmentByteLength,
                                    label: 'Worker-derived local-record identifier',
                                });
                            } finally {
                                if (value instanceof Uint8Array) {
                                    value.fill(0);
                                }
                            }
                        },
                    );
                } finally {
                    destroyLocalRecordIdentifierInput(copiedInput);
                }
            },
        );
    }

    public sealLocalRecord(
        input: BrowserLocalRecordSealInput,
    ): Promise<Uint8Array> {
        return this.#queueValidatedOperation(
            () => copyLocalRecordSealInput(input),
            async (copiedInput) => {
                try {
                    return await this.#sendRequest(
                        'seal-record',
                        copiedInput,
                        (value) => {
                            try {
                                return copyLocalRecordBytes(value, {
                                    allowEmpty: false,
                                    errorCode: 'OwnedWorkerFailure',
                                    label: 'Worker-produced local-record envelope',
                                });
                            } finally {
                                if (value instanceof Uint8Array) {
                                    value.fill(0);
                                }
                            }
                        },
                    );
                } finally {
                    destroyLocalRecordSealInput(copiedInput);
                }
            },
        );
    }

    public openLocalRecord(
        input: BrowserLocalRecordOpenInput,
    ): Promise<Uint8Array> {
        return this.#queueValidatedOperation(
            () => copyLocalRecordOpenInput(input),
            async (copiedInput) => {
                try {
                    return await this.#sendRequest(
                        'open-record',
                        copiedInput,
                        (value) => {
                            try {
                                return copyLocalRecordBytes(value, {
                                    allowEmpty: true,
                                    errorCode: 'OwnedWorkerFailure',
                                    label: 'Worker-opened local-record plaintext',
                                });
                            } finally {
                                if (value instanceof Uint8Array) {
                                    value.fill(0);
                                }
                            }
                        },
                    );
                } finally {
                    destroyLocalRecordOpenInput(copiedInput);
                }
            },
        );
    }

    public hashLocalRecordEnvelope(envelope: Uint8Array): Promise<Uint8Array> {
        return this.#queueValidatedOperation(
            () =>
                copyLocalRecordBytes(envelope, {
                    allowEmpty: false,
                    errorCode: 'InvalidInput',
                    label: 'Local-record envelope',
                }),
            async (copiedEnvelope) => {
                try {
                    return await this.#sendRequest(
                        'hash-record-envelope',
                        copiedEnvelope,
                        (value) => {
                            try {
                                return copyLocalRecordBytes(value, {
                                    allowEmpty: false,
                                    errorCode: 'OwnedWorkerFailure',
                                    exactByteLength:
                                        storageRootCommitmentByteLength,
                                    label: 'Worker-derived local-record envelope hash',
                                });
                            } finally {
                                if (value instanceof Uint8Array) {
                                    value.fill(0);
                                }
                            }
                        },
                    );
                } finally {
                    copiedEnvelope.fill(0);
                }
            },
        );
    }

    public openActionStateVerifierSession(
        input: BrowserActionStateVerifierSessionInput,
    ): Promise<VerificationResult<string>> {
        return this.#queueValidatedOperation(
            () => copyActionStateVerifierSessionInput(input),
            (copiedInput) =>
                this.#sendRequest(
                    'open-state-verifier-session',
                    copiedInput,
                    copyWorkerIdentifierVerificationResult,
                ),
        );
    }

    public verifyActionStateReservation(
        input: BrowserActionStateReservationVerificationInput,
    ): Promise<VerificationResult<string>> {
        return this.#queueValidatedOperation(
            () => copyActionStateReservationVerificationInput(input),
            (copiedInput) =>
                this.#sendRequest(
                    'verify-state-reservation',
                    copiedInput,
                    copyWorkerIdentifierVerificationResult,
                ),
        );
    }

    public verifyActionRandomnessReservation(
        input: BrowserActionRandomnessReservationVerificationInput,
    ): Promise<VerificationResult<string>> {
        return this.#queueValidatedOperation(
            () => copyActionRandomnessReservationVerificationInput(input),
            (copiedInput) =>
                this.#sendRequest(
                    'verify-action-randomness-reservation',
                    copiedInput,
                    copyWorkerIdentifierVerificationResult,
                ),
        );
    }

    public produceFoundationActionRandomnessReservationIntent(
        actionRandomness: BrowserFoundationActionRandomnessHandle,
        input: { stateVerifierSessionIdentifier: string },
    ): Promise<
        VerificationResult<BrowserFoundationProducedStateReservationIntent>
    > {
        return this.#queueValidatedOperation(
            () => ({
                actionRandomnessHandleIdentifier: requireIssuedHandleIdentifier(
                    actionRandomness,
                    foundationActionRandomnessHandleIdentifiers,
                    'Foundation action-randomness handle',
                ),
                stateVerifierSessionIdentifier: copyOpaqueWorkerIdentifier(
                    input.stateVerifierSessionIdentifier,
                    'State-verifier session identifier',
                ),
            }),
            (copiedInput) =>
                this.#sendRequest(
                    'produce-foundation-action-randomness-reservation-intent',
                    copiedInput,
                    copyProducedStateReservationIntentVerificationResult,
                ),
        );
    }

    public certifyFoundationActionRandomnessReservation(
        intent: BrowserFoundationStateReservationIntentHandle,
        untrustedVoteCarriers: readonly Uint8Array[],
    ): Promise<VerificationResult<BrowserFoundationProducedStateReservation>> {
        return this.#queueValidatedOperation(
            () => {
                if (
                    !Array.isArray(untrustedVoteCarriers) ||
                    untrustedVoteCarriers.length === 0 ||
                    untrustedVoteCarriers.length >
                        foundationProfile.participantCount * 2
                ) {
                    throw new BrowserActionStorageCustodyError(
                        'InvalidInput',
                        'State reservation certification requires a bounded non-empty vote-carrier array.',
                    );
                }
                return {
                    stateIntentIdentifier: requireIssuedHandleIdentifier(
                        intent,
                        foundationStateReservationIntentHandleIdentifiers,
                        'State reservation-intent handle',
                    ),
                    untrustedVoteCarriers: untrustedVoteCarriers.map(
                        (carrier) =>
                            copyBoundedBytes(
                                carrier,
                                foundationProfile.maximumCopiedBufferByteLength,
                                'Canonical state witness-vote carrier',
                            ),
                    ),
                };
            },
            async (copiedInput) => {
                const result = await this.#sendRequest(
                    'certify-foundation-action-randomness-reservation',
                    copiedInput,
                    copyProducedStateReservationVerificationResult,
                );
                if (result.isValid) {
                    foundationStateReservationIntentHandleIdentifiers.delete(
                        intent,
                    );
                }
                return result;
            },
        );
    }

    public releaseFoundationStateReservationIntent(
        intent: BrowserFoundationStateReservationIntentHandle,
    ): Promise<void> {
        return this.#queueValidatedOperation(
            () =>
                requireIssuedHandleIdentifier(
                    intent,
                    foundationStateReservationIntentHandleIdentifiers,
                    'State reservation-intent handle',
                ),
            async (stateIntentIdentifier) => {
                await this.#sendRequest(
                    'release-foundation-state-reservation-intent',
                    stateIntentIdentifier,
                    validateVoidResult,
                );
                foundationStateReservationIntentHandleIdentifiers.delete(
                    intent,
                );
            },
        );
    }

    public voteForFoundationActionRandomnessReservationIntent(
        witnessRole: BrowserFoundationNormalWitnessRoleHandle,
        input: {
            canonicalReservationIntentCarrier: Uint8Array;
            stateVerifierSessionIdentifier: string;
            subjectParticipantIdentity: Uint8Array;
        },
    ): Promise<VerificationResult<Uint8Array>> {
        return this.#queueValidatedOperation(
            () => ({
                canonicalReservationIntentCarrier: copyBoundedBytes(
                    input.canonicalReservationIntentCarrier,
                    foundationProfile.maximumCopiedBufferByteLength,
                    'Canonical action-randomness reservation-intent carrier',
                ),
                stateVerifierSessionIdentifier: copyOpaqueWorkerIdentifier(
                    input.stateVerifierSessionIdentifier,
                    'State-verifier session identifier',
                ),
                subjectParticipantIdentity: copyBytes(
                    input.subjectParticipantIdentity,
                    storageRootCommitmentByteLength,
                    'State reservation subject participant identity',
                ),
                witnessRoleIdentifier: requireIssuedHandleIdentifier(
                    witnessRole,
                    normalWitnessRoleSessionIdentifiers,
                    'Foundation witness role',
                ),
            }),
            (copiedInput) =>
                this.#sendRequest(
                    'vote-for-foundation-action-randomness-reservation-intent',
                    copiedInput,
                    copyBytesVerificationResult,
                ),
        );
    }

    public releaseActionStateObject(identifier: string): Promise<void> {
        return this.#queueValidatedOperation(
            () =>
                copyOpaqueWorkerIdentifier(
                    identifier,
                    'State object identifier',
                ),
            (copiedIdentifier) =>
                this.#sendRequest(
                    'release-state-object',
                    copiedIdentifier,
                    validateVoidResult,
                ),
        );
    }

    public closeActionStateVerifierSession(identifier: string): Promise<void> {
        return this.#queueValidatedOperation(
            () =>
                copyOpaqueWorkerIdentifier(
                    identifier,
                    'State-verifier session identifier',
                ),
            (copiedIdentifier) =>
                this.#sendRequest(
                    'close-state-verifier-session',
                    copiedIdentifier,
                    validateVoidResult,
                ),
        );
    }

    public createAndSealActionRandomness(
        input: BrowserActionRandomnessRecordContext,
    ): Promise<BrowserSealedActionRandomnessSession> {
        return this.#queueValidatedOperation(
            () => copyCreateAndSealActionRandomnessInput(input),
            (copiedInput) =>
                this.#sendRequest(
                    'create-and-seal-action-randomness',
                    copiedInput,
                    copySealedActionRandomnessSession,
                ),
        );
    }

    public openSealedActionRandomness(
        input: BrowserActionRandomnessRecordContext &
            Readonly<{
                actionRandomnessCommitment: Uint8Array;
                canonicalEnvelope: Uint8Array;
            }>,
    ): Promise<BrowserOpenedActionRandomnessSession> {
        return this.#queueValidatedOperation(
            () => copyOpenSealedActionRandomnessInput(input),
            (copiedInput) =>
                this.#sendRequest(
                    'open-sealed-action-randomness',
                    copiedInput,
                    copyOpenedActionRandomnessSession,
                ),
        );
    }

    public closeActionRandomness(identifier: string): Promise<void> {
        return this.#queueValidatedOperation(
            () =>
                copyOpaqueWorkerIdentifier(
                    identifier,
                    'Action-randomness session identifier',
                ),
            (copiedIdentifier) =>
                this.#sendRequest(
                    'close-action-randomness',
                    copiedIdentifier,
                    validateVoidResult,
                ),
        );
    }

    public deriveTargetReleaseAttempt(
        input: BrowserTargetReleaseAttemptInput,
    ): Promise<BrowserActionProofAttemptBinding> {
        return this.#queueValidatedOperation(
            () => copyTargetReleaseAttemptInput(input),
            (copiedInput) =>
                this.#sendRequest(
                    'derive-target-release-attempt',
                    copiedInput,
                    copyActionProofAttemptBinding,
                ),
        );
    }

    public compareAndLockWitnessIntent(
        witnessRole: BrowserFoundationNormalWitnessRoleHandle,
        input: { durableBinding: BrowserFoundationDurableStateBindingHandle },
    ): Promise<void> {
        return this.#foundationWitnessDurableOperation(
            'compare-and-lock-foundation-witness-intent',
            witnessRole,
            input.durableBinding,
            undefined,
            undefined,
            validateVoidResult,
        );
    }

    public cacheWitnessSignedVoteCarrier(
        witnessRole: BrowserFoundationNormalWitnessRoleHandle,
        input: {
            canonicalSignedVoteCarrier: Uint8Array;
            durableBinding: BrowserFoundationDurableStateBindingHandle;
        },
    ): Promise<Uint8Array> {
        return this.#foundationWitnessDurableOperation(
            'cache-foundation-witness-signed-vote-carrier',
            witnessRole,
            input.durableBinding,
            input.canonicalSignedVoteCarrier,
            'Canonical signed vote carrier',
            (candidate) =>
                copyBoundedBytes(
                    candidate,
                    foundationProfile.maximumCopiedBufferByteLength,
                    'Canonical cached signed vote carrier',
                ),
        );
    }

    public readWitnessSignedVoteCarrier(
        witnessRole: BrowserFoundationNormalWitnessRoleHandle,
        input: { durableBinding: BrowserFoundationDurableStateBindingHandle },
    ): Promise<Uint8Array> {
        return this.#foundationWitnessDurableOperation(
            'read-foundation-witness-signed-vote-carrier',
            witnessRole,
            input.durableBinding,
            undefined,
            undefined,
            (value) =>
                copyBoundedBytes(
                    value,
                    foundationProfile.maximumCopiedBufferByteLength,
                    'Canonical cached signed vote carrier',
                ),
        );
    }

    public cacheWitnessExactOutput(
        witnessRole: BrowserFoundationNormalWitnessRoleHandle,
        input: {
            durableBinding: BrowserFoundationDurableStateBindingHandle;
            exactOutputBytes: Uint8Array;
        },
    ): Promise<void> {
        return this.#foundationWitnessDurableOperation(
            'cache-foundation-witness-exact-output',
            witnessRole,
            input.durableBinding,
            input.exactOutputBytes,
            'Exact output bytes',
            validateVoidResult,
        );
    }

    public readWitnessExactOutput(
        witnessRole: BrowserFoundationNormalWitnessRoleHandle,
        input: { durableBinding: BrowserFoundationDurableStateBindingHandle },
    ): Promise<Uint8Array> {
        return this.#foundationWitnessDurableOperation(
            'read-foundation-witness-exact-output',
            witnessRole,
            input.durableBinding,
            undefined,
            undefined,
            (value) =>
                copyBoundedBytes(
                    value,
                    foundationProfile.maximumCopiedBufferByteLength,
                    'Exact cached output bytes',
                ),
        );
    }

    public verifyFoundationActionRandomnessReservation(
        actionRandomness: BrowserFoundationActionRandomnessHandle,
        input: Omit<
            BrowserActionRandomnessReservationVerificationInput,
            'actionRandomnessSessionIdentifier'
        >,
    ): Promise<VerificationResult<string>> {
        return this.#queueValidatedOperation(
            () => ({
                actionRandomnessHandleIdentifier: requireIssuedHandleIdentifier(
                    actionRandomness,
                    foundationActionRandomnessHandleIdentifiers,
                    'Foundation action-randomness handle',
                ),
                verificationInput:
                    copyActionRandomnessReservationVerificationInput({
                        ...input,
                        actionRandomnessSessionIdentifier: '0'.repeat(64),
                    }),
            }),
            (copiedInput) =>
                this.#sendRequest(
                    'verify-foundation-action-randomness-reservation',
                    copiedInput,
                    copyWorkerIdentifierVerificationResult,
                ),
        );
    }

    public deriveFoundationTargetReleaseAttempt(
        actionRandomness: BrowserFoundationActionRandomnessHandle,
        input: Omit<
            BrowserTargetReleaseAttemptInput,
            'actionRandomnessSessionIdentifier'
        >,
    ): Promise<BrowserActionProofAttemptBinding> {
        return this.#queueValidatedOperation(
            () => ({
                actionRandomnessHandleIdentifier: requireIssuedHandleIdentifier(
                    actionRandomness,
                    foundationActionRandomnessHandleIdentifiers,
                    'Foundation action-randomness handle',
                ),
                attemptInput: copyTargetReleaseAttemptInput({
                    ...input,
                    actionRandomnessSessionIdentifier: '0'.repeat(64),
                }),
            }),
            (copiedInput) =>
                this.#sendRequest(
                    'derive-foundation-target-release-attempt',
                    copiedInput,
                    copyActionProofAttemptBinding,
                ),
        );
    }

    public closeFoundationActionRandomness(
        actionRandomness: BrowserFoundationActionRandomnessHandle,
    ): Promise<void> {
        return this.#queueValidatedOperation(
            () =>
                requireIssuedHandleIdentifier(
                    actionRandomness,
                    foundationActionRandomnessHandleIdentifiers,
                    'Foundation action-randomness handle',
                ),
            async (actionRandomnessHandleIdentifier) => {
                await this.#sendRequest(
                    'close-foundation-action-randomness',
                    actionRandomnessHandleIdentifier,
                    validateVoidResult,
                );
                foundationActionRandomnessHandleIdentifiers.delete(
                    actionRandomness,
                );
            },
        );
    }

    public delete(
        expectedSnapshot: BrowserDeviceWrappingSnapshot,
    ): Promise<void> {
        return this.#queueValidatedOperation(
            () => copySnapshot(expectedSnapshot),
            (snapshot) =>
                this.#sendRequest('delete', snapshot, validateVoidResult),
        );
    }

    public retire(): Promise<void> {
        return this.#queueOperation(() =>
            this.#sendRequest('retire', undefined, validateVoidResult),
        );
    }

    public close(): Promise<void> {
        if (this.#closePromise !== undefined) {
            return this.#closePromise;
        }
        if (this.#closed) {
            return this.#terminalFailure === undefined
                ? Promise.resolve()
                : Promise.reject(this.#terminalFailure);
        }
        this.#closing = true;
        this.#closePromise = this.#enqueue(async () => {
            try {
                await this.#sendRequest('close', undefined, validateVoidResult);
            } finally {
                this.#disposeWorker();
                this.#closed = true;
            }
        });

        return this.#closePromise;
    }

    public abortAfterOpenFailure(): void {
        this.#disposeWorker();
        this.#closed = true;
    }

    #queueValidatedOperation<Input, Result>(
        validateInput: () => Input,
        operation: (input: Input) => Promise<Result>,
    ): Promise<Result> {
        let copiedInput: Input;
        try {
            copiedInput = validateInput();
        } catch (error) {
            return Promise.reject(
                error instanceof Error
                    ? error
                    : new BrowserActionStorageCustodyError(
                          'InvalidInput',
                          'Browser action-storage command input could not be copied.',
                          error,
                      ),
            );
        }

        return this.#queueOperation(() => operation(copiedInput));
    }

    #foundationWitnessDurableOperation<Result>(
        command:
            | 'cache-foundation-witness-exact-output'
            | 'cache-foundation-witness-signed-vote-carrier'
            | 'compare-and-lock-foundation-witness-intent'
            | 'read-foundation-witness-exact-output'
            | 'read-foundation-witness-signed-vote-carrier',
        witnessRole: BrowserFoundationNormalWitnessRoleHandle,
        durableBinding: BrowserFoundationDurableStateBindingHandle,
        value: unknown,
        valueLabel: string | undefined,
        validateResult: (candidate: unknown) => Result,
    ): Promise<Result> {
        return this.#queueValidatedOperation(
            () => ({
                durableBindingIdentifier: requireIssuedHandleIdentifier(
                    durableBinding,
                    durableStateBindingHandleIdentifiers,
                    'Durable state binding',
                ),
                value:
                    value === undefined
                        ? undefined
                        : copyBoundedBytes(
                              value,
                              foundationProfile.maximumCopiedBufferByteLength,
                              valueLabel ?? 'Durable witness value',
                          ),
                witnessRoleIdentifier: requireIssuedHandleIdentifier(
                    witnessRole,
                    normalWitnessRoleSessionIdentifiers,
                    'Foundation witness role',
                ),
            }),
            async (copiedInput) => {
                try {
                    return await this.#sendRequest(
                        command,
                        copiedInput,
                        validateResult,
                    );
                } finally {
                    copiedInput.value?.fill(0);
                }
            },
        );
    }

    #queueOperation<Result>(operation: () => Promise<Result>): Promise<Result> {
        if (this.#closing || this.#closed) {
            return Promise.reject(
                this.#terminalFailure ??
                    new BrowserActionStorageCustodyError(
                        'Closed',
                        'The browser action-storage worker channel is closed.',
                    ),
            );
        }

        return this.#enqueue(operation);
    }

    #enqueue<Result>(operation: () => Promise<Result>): Promise<Result> {
        const result = this.#operationTail.then(operation, operation);
        this.#operationTail = result.then(
            () => undefined,
            () => undefined,
        );

        return result;
    }

    #sendRequest<Result>(
        command: CustodyWorkerCommand,
        input: unknown,
        validateResult: (value: unknown) => Result,
    ): Promise<Result> {
        if (this.#closed || this.#activeRequest !== undefined) {
            return Promise.reject(
                this.#terminalFailure ??
                    new BrowserActionStorageCustodyError(
                        this.#closed ? 'Closed' : 'OwnedWorkerFailure',
                        this.#closed
                            ? 'The browser action-storage worker channel is closed.'
                            : 'The browser action-storage worker channel attempted overlapping requests.',
                    ),
            );
        }
        const requestIdentifier = this.#nextRequestIdentifier;
        this.#nextRequestIdentifier += 1;
        if (!Number.isSafeInteger(this.#nextRequestIdentifier)) {
            this.#nextRequestIdentifier = 1;
        }

        return new Promise<Result>((resolve, reject) => {
            this.#activeRequest = {
                command,
                reject,
                requestIdentifier,
                resolve: (value) => resolve(value as Result),
                validateResult,
            };
            const message: CustodyWorkerRequest = {
                command,
                input,
                messageKind: 'browser-action-storage-custody-request',
                requestIdentifier,
            };
            try {
                this.#worker.postMessage(message);
            } catch (error) {
                this.#failChannel(
                    new BrowserActionStorageCustodyError(
                        'OwnedWorkerFailure',
                        'Posting a browser action-storage worker command failed.',
                        error,
                    ),
                );
            }
        });
    }

    #handleMessage(message: unknown): void {
        if (!isCustodyWorkerResponse(message)) {
            this.#failChannel(
                new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The browser action-storage worker returned a malformed response.',
                ),
            );
            return;
        }
        if (
            message.messageKind ===
            'browser-action-storage-custody-channel-failed'
        ) {
            this.#failChannel(
                new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The browser action-storage worker channel failed closed.',
                ),
            );
            return;
        }
        const activeRequest = this.#activeRequest;
        if (message.requestIdentifier !== activeRequest?.requestIdentifier) {
            this.#failChannel(
                new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The browser action-storage worker returned a malformed, unsolicited, or mismatched response.',
                ),
            );
            return;
        }
        this.#activeRequest = undefined;
        if (message.messageKind === 'browser-action-storage-custody-failed') {
            activeRequest.reject(
                new BrowserActionStorageCustodyError(
                    message.errorCode,
                    `The browser action-storage worker refused ${activeRequest.command}${message.errorMessage === undefined ? '.' : `: ${message.errorMessage}`}`,
                ),
            );
            return;
        }
        try {
            activeRequest.resolve(activeRequest.validateResult(message.result));
        } catch (error) {
            this.#failChannel(
                new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    `The browser action-storage worker result failed validation${error instanceof Error ? `: ${error.message}` : '.'}`,
                    error,
                ),
                activeRequest,
            );
        }
    }

    #failChannel(
        error: BrowserActionStorageCustodyError,
        detachedRequest?: ActiveClientRequest,
    ): void {
        const activeRequest = detachedRequest ?? this.#activeRequest;
        this.#activeRequest = undefined;
        this.#closing = true;
        this.#closed = true;
        this.#terminalFailure ??= error;
        this.#disposeWorker();
        activeRequest?.reject(this.#terminalFailure);
    }

    #disposeWorker(): void {
        this.#worker.removeEventListener('message', this.#messageListener);
        this.#worker.removeEventListener('error', this.#errorListener);
        this.#worker.removeEventListener(
            'messageerror',
            this.#messageErrorListener,
        );
        this.#worker.terminate();
    }
}

const makeTransferableCustody = (
    custody: BrowserFoundationStorageAuthority,
): TransferableBrowserFoundationStorageAuthority => {
    const lifecycle = new ExclusiveResourceLifecycle({
        cleanup: () => custody.close(),
        createInvalidStateError: (message) =>
            new BrowserActionStorageCustodyError('InvalidState', message),
    });
    const initialOwner = lifecycle.initialOwner();
    const createOwnedCustody = (
        owner: ExclusiveResourceOwnerToken,
    ): BrowserFoundationStorageAuthority =>
        Object.freeze({
            authenticateFoundationHead: () =>
                lifecycle.run(owner, () =>
                    custody.authenticateFoundationHead(),
                ),
            beginCheckpoint: (streamAttemptIdentifiers) =>
                lifecycle.run(owner, () =>
                    custody.beginCheckpoint(streamAttemptIdentifiers),
                ),
            close: () => lifecycle.close(owner),
            closeActionRandomness: (identifier) =>
                lifecycle.run(owner, () =>
                    custody.closeActionRandomness(identifier),
                ),
            closeActionStateVerifierSession: (identifier) =>
                lifecycle.run(owner, () =>
                    custody.closeActionStateVerifierSession(identifier),
                ),
            copyBinding: () => {
                lifecycle.assertOpen(owner);
                return custody.copyBinding();
            },
            copyCheckpointDescription: (checkpoint) =>
                lifecycle.run(owner, () =>
                    custody.copyCheckpointDescription(checkpoint),
                ),
            commitFreshFoundationInitialization: (preparationInput) =>
                lifecycle.run(owner, () =>
                    custody.commitFreshFoundationInitialization(
                        preparationInput,
                    ),
                ),
            createAndSealActionRandomness: (operationInput) =>
                lifecycle.run(owner, () =>
                    custody.createAndSealActionRandomness(operationInput),
                ),
            evictCheckpoint: (checkpoint) =>
                lifecycle.run(owner, () => custody.evictCheckpoint(checkpoint)),
            currentSnapshot: () =>
                lifecycle.run(owner, () => custody.currentSnapshot()),
            delete: (expectedSnapshot) =>
                lifecycle.run(owner, () => custody.delete(expectedSnapshot)),
            retire: () => lifecycle.run(owner, () => custody.retire()),
            deriveLocalRecordIdentifier: (identifierInput) =>
                lifecycle.run(owner, () =>
                    custody.deriveLocalRecordIdentifier(identifierInput),
                ),
            deriveTargetReleaseAttempt: (attemptInput) =>
                lifecycle.run(owner, () =>
                    custody.deriveTargetReleaseAttempt(attemptInput),
                ),
            hashLocalRecordEnvelope: (envelope) =>
                lifecycle.run(owner, () =>
                    custody.hashLocalRecordEnvelope(envelope),
                ),
            initialize: () => lifecycle.run(owner, () => custody.initialize()),
            openActionStateVerifierSession: (sessionInput) =>
                lifecycle.run(owner, () =>
                    custody.openActionStateVerifierSession(sessionInput),
                ),
            openIntoOwnedWorker: (openInput) =>
                lifecycle.run(owner, () =>
                    custody.openIntoOwnedWorker(openInput),
                ),
            openLocalRecord: (recordInput) =>
                lifecycle.run(owner, () =>
                    custody.openLocalRecord(recordInput),
                ),
            openSealedActionRandomness: (operationInput) =>
                lifecycle.run(owner, () =>
                    custody.openSealedActionRandomness(operationInput),
                ),
            publishCheckpoint: (checkpoint, publicationInput) =>
                lifecycle.run(owner, () =>
                    custody.publishCheckpoint(checkpoint, publicationInput),
                ),
            releaseActionStateObject: (identifier) =>
                lifecycle.run(owner, () =>
                    custody.releaseActionStateObject(identifier),
                ),
            restoreCheckpointState: (checkpoint, consumeChunk) =>
                lifecycle.run(owner, () =>
                    custody.restoreCheckpointState(checkpoint, consumeChunk),
                ),
            resumeCheckpoint: (resumeInput) =>
                lifecycle.run(owner, () =>
                    custody.resumeCheckpoint(resumeInput),
                ),
            sealLocalRecord: (recordInput) =>
                lifecycle.run(owner, () =>
                    custody.sealLocalRecord(recordInput),
                ),
            verifyActionRandomnessReservation: (verificationInput) =>
                lifecycle.run(owner, () =>
                    custody.verifyActionRandomnessReservation(
                        verificationInput,
                    ),
                ),
            verifyActionStateReservation: (verificationInput) =>
                lifecycle.run(owner, () =>
                    custody.verifyActionStateReservation(verificationInput),
                ),
        });
    const initialCustody = createOwnedCustody(initialOwner);
    return Object.freeze({
        ...initialCustody,
        claimExclusiveOwner: () =>
            createOwnedCustody(lifecycle.claim(initialOwner)),
    });
};

const makeTransferableFoundationOperationOwner = (
    client: BrowserActionStorageCustodyWorkerClient,
): TransferableBrowserFoundationOperationOwner => {
    const lifecycle = new ExclusiveResourceLifecycle({
        cleanup: () => client.close(),
        createInvalidStateError: (message) =>
            new BrowserActionStorageCustodyError('InvalidState', message),
    });
    const initialOwner = lifecycle.initialOwner();
    const createOwnedOperationOwner = (
        owner: ExclusiveResourceOwnerToken,
    ): BrowserFoundationOperationOwner =>
        Object.freeze({
            activateFreshFoundationInitialization: (committedBatch) =>
                lifecycle.run(owner, () =>
                    client.activateFreshFoundationInitialization(
                        committedBatch,
                    ),
                ),
            activateRecoveredFoundationInitialization: (recoveredBatch) =>
                lifecycle.run(owner, () =>
                    client.activateRecoveredFoundationInitialization(
                        recoveredBatch,
                    ),
                ),
            beginCheckpoint: (streamAttemptIdentifiers) =>
                lifecycle.run(owner, () =>
                    client.beginCheckpoint(streamAttemptIdentifiers),
                ),
            cacheWitnessExactOutput: (witnessRole, cacheInput) =>
                lifecycle.run(owner, () =>
                    client.cacheWitnessExactOutput(witnessRole, cacheInput),
                ),
            cacheWitnessSignedVoteCarrier: (witnessRole, cacheInput) =>
                lifecycle.run(owner, () =>
                    client.cacheWitnessSignedVoteCarrier(
                        witnessRole,
                        cacheInput,
                    ),
                ),
            close: () => lifecycle.close(owner),
            closeFoundationActionRandomness: (actionRandomness) =>
                lifecycle.run(owner, () =>
                    client.closeFoundationActionRandomness(actionRandomness),
                ),
            closeWitnessDurableStateBinding: (durableBinding) =>
                lifecycle.run(owner, () =>
                    client.closeWitnessDurableStateBinding(durableBinding),
                ),
            commitFreshFoundationInitialization: (initializationInput) =>
                lifecycle.run(owner, () =>
                    client.commitFoundationOperationInitialization(
                        initializationInput,
                    ),
                ),
            compareAndLockWitnessIntent: (witnessRole, compareInput) =>
                lifecycle.run(owner, () =>
                    client.compareAndLockWitnessIntent(
                        witnessRole,
                        compareInput,
                    ),
                ),
            certifyFoundationActionRandomnessReservation: (
                intent,
                untrustedVoteCarriers,
            ) =>
                lifecycle.run(owner, () =>
                    client.certifyFoundationActionRandomnessReservation(
                        intent,
                        untrustedVoteCarriers,
                    ),
                ),
            copyBinding: () => {
                lifecycle.assertOpen(owner);
                return client.copyBinding();
            },
            copyCheckpointDescription: (checkpoint) =>
                lifecycle.run(owner, () =>
                    client.copyCheckpointDescription(checkpoint),
                ),
            copyWitnessSubjectParticipantIdentity: (witnessRole) =>
                lifecycle.run(owner, () =>
                    client.copyWitnessSubjectParticipantIdentity(witnessRole),
                ),
            deriveFoundationTargetReleaseAttempt: (
                actionRandomness,
                attemptInput,
            ) =>
                lifecycle.run(owner, () =>
                    client.deriveFoundationTargetReleaseAttempt(
                        actionRandomness,
                        attemptInput,
                    ),
                ),
            openActionStateVerifierSession: (sessionInput) =>
                lifecycle.run(owner, () =>
                    client.openActionStateVerifierSession(sessionInput),
                ),
            openRecoveredFoundationInitialization: (initializationInput) =>
                lifecycle.run(owner, () =>
                    client.openRecoveredFoundationInitialization(
                        initializationInput,
                    ),
                ),
            openWitnessDurableStateBinding: (
                witnessRole,
                stateObjectIdentifier,
            ) =>
                lifecycle.run(owner, () =>
                    client.openWitnessDurableStateBinding(
                        witnessRole,
                        stateObjectIdentifier,
                    ),
                ),
            produceFoundationActionRandomnessReservationIntent: (
                actionRandomness,
                productionInput,
            ) =>
                lifecycle.run(owner, () =>
                    client.produceFoundationActionRandomnessReservationIntent(
                        actionRandomness,
                        productionInput,
                    ),
                ),
            publishCheckpoint: (checkpoint, publicationInput) =>
                lifecycle.run(owner, () =>
                    client.publishCheckpoint(checkpoint, publicationInput),
                ),
            readWitnessExactOutput: (witnessRole, readInput) =>
                lifecycle.run(owner, () =>
                    client.readWitnessExactOutput(witnessRole, readInput),
                ),
            readWitnessSignedVoteCarrier: (witnessRole, readInput) =>
                lifecycle.run(owner, () =>
                    client.readWitnessSignedVoteCarrier(witnessRole, readInput),
                ),
            retire: () => lifecycle.run(owner, () => client.retire()),
            releaseActionStateObject: (identifier) =>
                lifecycle.run(owner, () =>
                    client.releaseActionStateObject(identifier),
                ),
            releaseFoundationStateReservationIntent: (intent) =>
                lifecycle.run(owner, () =>
                    client.releaseFoundationStateReservationIntent(intent),
                ),
            restoreCheckpointState: (checkpoint, consumeChunk) =>
                lifecycle.run(owner, () =>
                    client.restoreCheckpointState(checkpoint, consumeChunk),
                ),
            resumeCheckpoint: (resumeInput) =>
                lifecycle.run(owner, () =>
                    client.resumeCheckpoint(resumeInput),
                ),
            verifyActionStateReservation: (verificationInput) =>
                lifecycle.run(owner, () =>
                    client.verifyActionStateReservation(verificationInput),
                ),
            verifyFoundationActionRandomnessReservation: (
                actionRandomness,
                verificationInput,
            ) =>
                lifecycle.run(owner, () =>
                    client.verifyFoundationActionRandomnessReservation(
                        actionRandomness,
                        verificationInput,
                    ),
                ),
            voteForFoundationActionRandomnessReservationIntent: (
                witnessRole,
                voteInput,
            ) =>
                lifecycle.run(owner, () =>
                    client.voteForFoundationActionRandomnessReservationIntent(
                        witnessRole,
                        voteInput,
                    ),
                ),
        });
    const initialOperationOwner = createOwnedOperationOwner(initialOwner);
    return Object.freeze({
        ...initialOperationOwner,
        claimExclusiveOwner: () =>
            createOwnedOperationOwner(lifecycle.claim(initialOwner)),
    });
};

export const openBrowserActionStorageCustodyWorker = async (input: {
    configuration: BrowserActionStorageCustodyWorkerConfiguration;
    worker: CustodyWorkerLike;
}): Promise<TransferableBrowserFoundationStorageAuthority> => {
    const client = new BrowserActionStorageCustodyWorkerClient(input.worker);
    try {
        await client.open(input.configuration);

        return makeTransferableCustody(
            Object.freeze({
                authenticateFoundationHead: () =>
                    client.authenticateFoundationHead(),
                beginCheckpoint: (streamAttemptIdentifiers) =>
                    client.beginCheckpoint(streamAttemptIdentifiers),
                closeActionRandomness: (identifier) =>
                    client.closeActionRandomness(identifier),
                closeActionStateVerifierSession: (identifier) =>
                    client.closeActionStateVerifierSession(identifier),
                close: () => client.close(),
                copyBinding: () => client.copyBinding(),
                copyCheckpointDescription: (checkpoint) =>
                    client.copyCheckpointDescription(checkpoint),
                commitFreshFoundationInitialization: (preparationInput) =>
                    client.commitFreshFoundationInitialization(
                        preparationInput,
                    ),
                currentSnapshot: () => client.currentSnapshot(),
                createAndSealActionRandomness: (operationInput) =>
                    client.createAndSealActionRandomness(operationInput),
                delete: (expectedSnapshot) => client.delete(expectedSnapshot),
                retire: () => client.retire(),
                deriveLocalRecordIdentifier: (identifierInput) =>
                    client.deriveLocalRecordIdentifier(identifierInput),
                deriveTargetReleaseAttempt: (attemptInput) =>
                    client.deriveTargetReleaseAttempt(attemptInput),
                evictCheckpoint: (checkpoint) =>
                    client.evictCheckpoint(checkpoint),
                hashLocalRecordEnvelope: (envelope) =>
                    client.hashLocalRecordEnvelope(envelope),
                initialize: () => client.initialize(),
                openLocalRecord: (recordInput) =>
                    client.openLocalRecord(recordInput),
                openActionStateVerifierSession: (sessionInput) =>
                    client.openActionStateVerifierSession(sessionInput),
                openIntoOwnedWorker: (openInput) =>
                    client.openIntoOwnedWorker(openInput),
                openSealedActionRandomness: (operationInput) =>
                    client.openSealedActionRandomness(operationInput),
                publishCheckpoint: (checkpoint, publicationInput) =>
                    client.publishCheckpoint(checkpoint, publicationInput),
                releaseActionStateObject: (identifier) =>
                    client.releaseActionStateObject(identifier),
                restoreCheckpointState: (checkpoint, consumeChunk) =>
                    client.restoreCheckpointState(checkpoint, consumeChunk),
                resumeCheckpoint: (resumeInput) =>
                    client.resumeCheckpoint(resumeInput),
                sealLocalRecord: (recordInput) =>
                    client.sealLocalRecord(recordInput),
                verifyActionStateReservation: (verificationInput) =>
                    client.verifyActionStateReservation(verificationInput),
                verifyActionRandomnessReservation: (verificationInput) =>
                    client.verifyActionRandomnessReservation(verificationInput),
            } satisfies BrowserFoundationStorageAuthority),
        );
    } catch (error) {
        client.abortAfterOpenFailure();
        throw error;
    }
};

export const openBrowserFoundationOperationOwnerWorker = async (input: {
    configuration: BrowserActionStorageCustodyWorkerConfiguration;
    rootOpening: BrowserFoundationOperationOwnerWorkerRootOpening;
    worker: CustodyWorkerLike;
}): Promise<OpenedBrowserFoundationOperationOwnerWorker> => {
    const client = new BrowserActionStorageCustodyWorkerClient(input.worker);
    let freshSnapshot: BrowserDeviceWrappingSnapshot | undefined;
    try {
        await client.open(input.configuration);
        const deviceWrappingSnapshot =
            input.rootOpening.mode === 'fresh'
                ? await client.initialize()
                : copySnapshot(input.rootOpening.expectedSnapshot);
        if (input.rootOpening.mode === 'fresh') {
            freshSnapshot = deviceWrappingSnapshot;
            await client.openIntoOwnedWorker({
                expectedSnapshot: deviceWrappingSnapshot,
                untrustedExpectedCommitment: Object.freeze({
                    storageRootCommitment:
                        deviceWrappingSnapshot.storageRootCommitment.slice(),
                }),
            });
        } else {
            await client.openIntoOwnedWorker({
                expectedSnapshot: deviceWrappingSnapshot,
                untrustedExpectedCommitment:
                    input.rootOpening.untrustedExpectedCommitment,
            });
        }
        return Object.freeze({
            deviceWrappingSnapshot: copySnapshot(deviceWrappingSnapshot),
            operationOwner: makeTransferableFoundationOperationOwner(client),
        });
    } catch (error) {
        if (freshSnapshot !== undefined) {
            try {
                await client.delete(freshSnapshot);
            } catch (cleanupFailure) {
                client.abortAfterOpenFailure();
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'Fresh foundation root opening failed and its worker-owned rollback also failed.',
                    [error, cleanupFailure],
                );
            }
        }
        const errorCode =
            error instanceof Error && 'code' in error
                ? String((error as { code?: unknown }).code)
                : undefined;
        if (
            input.rootOpening.mode === 'recovered' &&
            (errorCode === 'RecordAuthenticationFailed' ||
                errorCode === 'StorageFailure' ||
                errorCode === 'Unavailable' ||
                errorCode === 'OwnedWorkerFailure')
        ) {
            try {
                await client.retire();
            } catch (retirementError) {
                client.abortAfterOpenFailure();
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'Recovered local foundation state was unavailable or unauthenticated, and durable retirement also failed.',
                    [error, retirementError],
                );
            }
        }
        client.abortAfterOpenFailure();
        throw error;
    }
};

const copyHostCommandInput = (
    command: CustodyWorkerCommand,
    input: unknown,
): unknown => {
    switch (command) {
        case 'open-custody':
            return copyWorkerConfiguration(input);
        case 'initialize':
        case 'current-snapshot':
        case 'authenticate-foundation-head':
        case 'retire':
        case 'close':
            return validateVoidResult(input);
        case 'activate-fresh-foundation-initialization':
        case 'activate-recovered-foundation-initialization':
            return copyOpaqueWorkerIdentifier(
                input,
                'Foundation initialization batch identifier',
            );
        case 'copy-foundation-witness-subject':
            return copyOpaqueWorkerIdentifier(
                input,
                'Foundation witness role identifier',
            );
        case 'close-foundation-action-randomness':
            return copyOpaqueWorkerIdentifier(
                input,
                'Foundation action-randomness handle identifier',
            );
        case 'close-foundation-witness-durable-binding':
            return copyOpaqueWorkerIdentifier(
                input,
                'Durable state binding handle identifier',
            );
        case 'release-foundation-state-reservation-intent':
            return copyOpaqueWorkerIdentifier(
                input,
                'State reservation-intent identifier',
            );
        case 'open-root':
            return copyBoundSnapshotInput(input);
        case 'begin-checkpoint':
            if (
                !Array.isArray(input) ||
                input.length > maximumCheckpointCollectionLength
            ) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'Checkpoint stream-attempt identifiers are malformed.',
                );
            }
            return Object.freeze(
                input.map((identifier, index) =>
                    copyBytes(
                        identifier,
                        32,
                        `Checkpoint stream-attempt identifier ${String(index)}`,
                    ),
                ),
            );
        case 'copy-checkpoint-description':
        case 'evict-checkpoint':
        case 'begin-checkpoint-restore':
            return copyOpaqueWorkerIdentifier(input, 'Checkpoint identifier');
        case 'commit-checkpoint-publication':
        case 'abort-checkpoint-publication':
            return copyOpaqueWorkerIdentifier(
                input,
                'Checkpoint publication identifier',
            );
        case 'abort-checkpoint-restore':
        case 'read-checkpoint-restore-chunk':
            return copyOpaqueWorkerIdentifier(
                input,
                'Checkpoint restore identifier',
            );
        case 'resume-checkpoint':
            if (!isPlainRecord(input)) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'Checkpoint resume input is malformed.',
                );
            }
            return Object.freeze({
                checkpointLineageIdentifier: copyBytes(
                    input.checkpointLineageIdentifier,
                    32,
                    'Checkpoint lineage identifier',
                ),
                expectedBoundary: copyCheckpointBoundary(
                    input.expectedBoundary as ExpectedCheckpointBoundary,
                    false,
                ),
            });
        case 'begin-checkpoint-publication':
            if (!isPlainRecord(input)) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'Checkpoint publication input is malformed.',
                );
            }
            return Object.freeze({
                boundary: copyCheckpointBoundary(
                    input.boundary as CheckpointBoundary,
                    true,
                ),
                checkpointIdentifier: copyOpaqueWorkerIdentifier(
                    input.checkpointIdentifier,
                    'Checkpoint identifier',
                ),
            });
        case 'write-checkpoint-publication-chunk':
            if (!isPlainRecord(input)) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'Checkpoint publication chunk input is malformed.',
                );
            }
            return Object.freeze({
                chunk: copyBoundedBytes(
                    input.chunk,
                    maximumCheckpointDescriptorByteLength,
                    'Checkpoint state chunk',
                ),
                publicationIdentifier: copyOpaqueWorkerIdentifier(
                    input.publicationIdentifier,
                    'Checkpoint publication identifier',
                ),
            });
        case 'open-foundation-witness-durable-binding':
            if (!isPlainRecord(input)) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'Foundation durable state binding input is malformed.',
                );
            }
            return Object.freeze({
                stateObjectIdentifier: copyOpaqueWorkerIdentifier(
                    input.stateObjectIdentifier,
                    'State object identifier',
                ),
                witnessRoleIdentifier: copyOpaqueWorkerIdentifier(
                    input.witnessRoleIdentifier,
                    'Foundation witness role identifier',
                ),
            });
        case 'produce-foundation-action-randomness-reservation-intent':
            if (!isPlainRecord(input)) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'Foundation state reservation-intent production input is malformed.',
                );
            }
            return Object.freeze({
                actionRandomnessHandleIdentifier: copyOpaqueWorkerIdentifier(
                    input.actionRandomnessHandleIdentifier,
                    'Foundation action-randomness handle identifier',
                ),
                stateVerifierSessionIdentifier: copyOpaqueWorkerIdentifier(
                    input.stateVerifierSessionIdentifier,
                    'State-verifier session identifier',
                ),
            });
        case 'certify-foundation-action-randomness-reservation':
            if (
                !isPlainRecord(input) ||
                !Array.isArray(input.untrustedVoteCarriers) ||
                input.untrustedVoteCarriers.length === 0 ||
                input.untrustedVoteCarriers.length >
                    foundationProfile.participantCount * 2
            ) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'Foundation state reservation certification input is malformed.',
                );
            }
            return Object.freeze({
                stateIntentIdentifier: copyOpaqueWorkerIdentifier(
                    input.stateIntentIdentifier,
                    'State reservation-intent identifier',
                ),
                untrustedVoteCarriers: Object.freeze(
                    input.untrustedVoteCarriers.map((carrier, carrierIndex) =>
                        copyBoundedBytes(
                            carrier,
                            foundationProfile.maximumCopiedBufferByteLength,
                            `Canonical state witness-vote carrier ${String(carrierIndex)}`,
                        ),
                    ),
                ),
            });
        case 'vote-for-foundation-action-randomness-reservation-intent':
            if (!isPlainRecord(input)) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'Foundation state reservation witness-vote input is malformed.',
                );
            }
            return Object.freeze({
                canonicalReservationIntentCarrier: copyBoundedBytes(
                    input.canonicalReservationIntentCarrier,
                    foundationProfile.maximumCopiedBufferByteLength,
                    'Canonical action-randomness reservation-intent carrier',
                ),
                stateVerifierSessionIdentifier: copyOpaqueWorkerIdentifier(
                    input.stateVerifierSessionIdentifier,
                    'State-verifier session identifier',
                ),
                subjectParticipantIdentity: copyBytes(
                    input.subjectParticipantIdentity,
                    storageRootCommitmentByteLength,
                    'State reservation subject participant identity',
                ),
                witnessRoleIdentifier: copyOpaqueWorkerIdentifier(
                    input.witnessRoleIdentifier,
                    'Foundation witness role identifier',
                ),
            });
        case 'compare-and-lock-foundation-witness-intent':
        case 'read-foundation-witness-exact-output':
        case 'read-foundation-witness-signed-vote-carrier':
        case 'cache-foundation-witness-exact-output':
        case 'cache-foundation-witness-signed-vote-carrier': {
            if (!isPlainRecord(input)) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'Foundation durable witness operation input is malformed.',
                );
            }
            const operationCarriesValue =
                command === 'cache-foundation-witness-exact-output' ||
                command === 'cache-foundation-witness-signed-vote-carrier';
            if (!operationCarriesValue) {
                validateVoidResult(input.value);
            }
            return Object.freeze({
                durableBindingIdentifier: copyOpaqueWorkerIdentifier(
                    input.durableBindingIdentifier,
                    'Durable state binding handle identifier',
                ),
                value: operationCarriesValue
                    ? copyBoundedBytes(
                          input.value,
                          foundationProfile.maximumCopiedBufferByteLength,
                          'Foundation durable witness operation bytes',
                      )
                    : undefined,
                witnessRoleIdentifier: copyOpaqueWorkerIdentifier(
                    input.witnessRoleIdentifier,
                    'Foundation witness role identifier',
                ),
            });
        }
        case 'verify-foundation-action-randomness-reservation':
            if (!isPlainRecord(input)) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'Foundation action-randomness verification input is malformed.',
                );
            }
            return Object.freeze({
                actionRandomnessHandleIdentifier: copyOpaqueWorkerIdentifier(
                    input.actionRandomnessHandleIdentifier,
                    'Foundation action-randomness handle identifier',
                ),
                verificationInput:
                    copyActionRandomnessReservationVerificationInput(
                        input.verificationInput,
                    ),
            });
        case 'derive-foundation-target-release-attempt':
            if (!isPlainRecord(input)) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'Foundation target-release attempt input is malformed.',
                );
            }
            return Object.freeze({
                actionRandomnessHandleIdentifier: copyOpaqueWorkerIdentifier(
                    input.actionRandomnessHandleIdentifier,
                    'Foundation action-randomness handle identifier',
                ),
                attemptInput: copyTargetReleaseAttemptInput(input.attemptInput),
            });
        case 'derive-record-identifier':
            return copyLocalRecordIdentifierInput(input);
        case 'open-state-verifier-session':
            return copyActionStateVerifierSessionInput(input);
        case 'verify-state-reservation':
            return copyActionStateReservationVerificationInput(input);
        case 'verify-action-randomness-reservation':
            return copyActionRandomnessReservationVerificationInput(input);
        case 'release-state-object':
            return copyOpaqueWorkerIdentifier(input, 'State object identifier');
        case 'close-state-verifier-session':
            return copyOpaqueWorkerIdentifier(
                input,
                'State-verifier session identifier',
            );
        case 'create-and-seal-action-randomness':
            return copyCreateAndSealActionRandomnessInput(input);
        case 'open-sealed-action-randomness':
            return copyOpenSealedActionRandomnessInput(input);
        case 'close-action-randomness':
            return copyOpaqueWorkerIdentifier(
                input,
                'Action-randomness session identifier',
            );
        case 'derive-target-release-attempt':
            return copyTargetReleaseAttemptInput(input);
        case 'seal-record':
            return copyLocalRecordSealInput(input);
        case 'open-record':
            return copyLocalRecordOpenInput(input);
        case 'hash-record-envelope':
            return copyLocalRecordBytes(input, {
                allowEmpty: false,
                errorCode: 'InvalidInput',
                label: 'Local-record envelope',
            });
        case 'commit-fresh-foundation-initialization':
            return copyBrowserFoundationInitializationPreparationInput(
                input as BrowserFoundationInitializationPreparationInput,
            );
        case 'commit-foundation-operation-initialization':
        case 'open-recovered-foundation-initialization':
            return copyFoundationOperationInitializationInput(input);
        case 'delete':
            return copySnapshot(input);
    }
};

const copyHostCommandResult = (
    command: CustodyWorkerCommand,
    result: unknown,
): unknown => {
    switch (command) {
        case 'open-custody':
        case 'open-root':
        case 'abort-checkpoint-publication':
        case 'abort-checkpoint-restore':
        case 'evict-checkpoint':
        case 'write-checkpoint-publication-chunk':
        case 'close-action-randomness':
        case 'close-state-verifier-session':
        case 'release-foundation-state-reservation-intent':
        case 'release-state-object':
        case 'delete':
        case 'retire':
        case 'close':
            return validateVoidResult(result);
        case 'activate-fresh-foundation-initialization':
        case 'activate-recovered-foundation-initialization':
            return copyWorkerActivatedFoundationInitializationResult(result);
        case 'begin-checkpoint':
        case 'resume-checkpoint': {
            if (
                !isPlainRecord(result) ||
                typeof result.checkpointIdentifier !== 'string'
            ) {
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The owned worker returned a malformed checkpoint handle.',
                );
            }
            return Object.freeze({
                checkpointIdentifier: copyOpaqueWorkerIdentifier(
                    result.checkpointIdentifier,
                    'Checkpoint identifier',
                ),
            });
        }
        case 'copy-checkpoint-description':
            return copyCheckpointDescription(result);
        case 'begin-checkpoint-publication':
        case 'begin-checkpoint-restore':
            return copyOpaqueWorkerIdentifier(
                result,
                'Checkpoint stream identifier',
            );
        case 'commit-checkpoint-publication':
            return copyBoundedBytes(
                result,
                maximumCheckpointDescriptorByteLength,
                'Checkpoint canonical manifest',
            );
        case 'read-checkpoint-restore-chunk':
            if (!isPlainRecord(result) || typeof result.done !== 'boolean') {
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The owned worker returned malformed checkpoint restore output.',
                );
            }
            return result.done
                ? Object.freeze({ done: true })
                : Object.freeze({
                      chunkBytes: copyBoundedBytes(
                          result.chunkBytes,
                          maximumCheckpointDescriptorByteLength,
                          'Restored checkpoint chunk',
                      ),
                      chunkIndex: result.chunkIndex,
                      done: false,
                  });
        case 'authenticate-foundation-head':
            return copyFoundationFreshnessCoordinate(result);
        case 'commit-fresh-foundation-initialization':
        case 'commit-foundation-operation-initialization':
            return copyWorkerCommittedFoundationInitializationResult(result);
        case 'open-recovered-foundation-initialization': {
            if (
                !isPlainRecord(result) ||
                typeof result.batchIdentifier !== 'string'
            ) {
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The owned worker returned malformed recovered foundation initialization authority.',
                );
            }
            return Object.freeze({
                batchIdentifier: copyOpaqueWorkerIdentifier(
                    result.batchIdentifier,
                    'Recovered foundation initialization batch identifier',
                ),
                freshnessCoordinate: copyFoundationFreshnessCoordinate(
                    result.freshnessCoordinate,
                ),
            });
        }
        case 'copy-foundation-witness-subject':
            return copyBytes(
                result,
                storageRootCommitmentByteLength,
                'Foundation witness subject participant identity',
            );
        case 'vote-for-foundation-action-randomness-reservation-intent':
            return copyBytesVerificationResult(result);
        case 'open-foundation-witness-durable-binding':
            return copyOpaqueWorkerIdentifier(
                result,
                'Durable state binding handle identifier',
            );
        case 'compare-and-lock-foundation-witness-intent':
        case 'cache-foundation-witness-exact-output':
            return validateVoidResult(result);
        case 'cache-foundation-witness-signed-vote-carrier':
            return copyBoundedBytes(
                result,
                foundationProfile.maximumCopiedBufferByteLength,
                'Canonical cached signed vote carrier',
            );
        case 'read-foundation-witness-exact-output':
        case 'read-foundation-witness-signed-vote-carrier':
            return copyBoundedBytes(
                result,
                foundationProfile.maximumCopiedBufferByteLength,
                'Foundation durable witness bytes',
            );
        case 'derive-record-identifier':
        case 'hash-record-envelope':
            return copyLocalRecordBytes(result, {
                allowEmpty: false,
                errorCode: 'OwnedWorkerFailure',
                exactByteLength: storageRootCommitmentByteLength,
                label: 'Worker-derived local-record hash',
            });
        case 'open-state-verifier-session':
        case 'verify-action-randomness-reservation':
        case 'verify-foundation-action-randomness-reservation':
        case 'verify-state-reservation':
            return copyWorkerIdentifierVerificationResult(result);
        case 'produce-foundation-action-randomness-reservation-intent':
            return copyWorkerProducedStateReservationIntentVerificationResult(
                result,
            );
        case 'certify-foundation-action-randomness-reservation':
            return copyProducedStateReservationVerificationResult(result);
        case 'create-and-seal-action-randomness':
            return copySealedActionRandomnessSession(result);
        case 'open-sealed-action-randomness':
            return copyOpenedActionRandomnessSession(result);
        case 'derive-target-release-attempt':
        case 'derive-foundation-target-release-attempt':
            return copyActionProofAttemptBinding(result);
        case 'seal-record':
            return copyLocalRecordBytes(result, {
                allowEmpty: false,
                errorCode: 'OwnedWorkerFailure',
                label: 'Worker-produced local-record envelope',
            });
        case 'open-record':
            return copyLocalRecordBytes(result, {
                allowEmpty: true,
                errorCode: 'OwnedWorkerFailure',
                label: 'Worker-opened local-record plaintext',
            });
        case 'initialize':
            return copySnapshot(result);
        case 'current-snapshot':
            return copyOptionalSnapshot(result);
    }
};

const destroyHostLocalRecordCommandInput = (
    command: CustodyWorkerCommand,
    input: unknown,
): void => {
    switch (command) {
        case 'derive-record-identifier':
            destroyLocalRecordIdentifierInput(
                input as BrowserLocalRecordIdentifierInput,
            );
            return;
        case 'seal-record':
            destroyLocalRecordSealInput(input as BrowserLocalRecordSealInput);
            return;
        case 'open-record':
            destroyLocalRecordOpenInput(input as BrowserLocalRecordOpenInput);
            return;
        case 'hash-record-envelope':
            (input as Uint8Array).fill(0);
    }
};

const destroyHostLocalRecordCommandResult = (
    command: CustodyWorkerCommand,
    result: unknown,
): void => {
    switch (command) {
        case 'derive-record-identifier':
        case 'seal-record':
        case 'open-record':
        case 'hash-record-envelope':
            if (result instanceof Uint8Array) {
                result.fill(0);
            }
    }
};

const normalizeHostErrorCode = (
    error: unknown,
): BrowserActionStorageCustodyErrorCode => {
    if (typeof error === 'object' && error !== null && 'code' in error) {
        if (error.code === 'Conflict') {
            return 'Conflict';
        }
        if (error.code === 'AuthenticationFailed') {
            return 'RecordAuthenticationFailed';
        }
        if (error.code === 'MissingRecord') {
            return 'MissingRecord';
        }
        if (error.code === 'InvalidConfiguration') {
            return 'InvalidInput';
        }
    }
    if (
        error instanceof BrowserActionStorageCustodyError &&
        isCustodyErrorCode(error.code)
    ) {
        return error.code;
    }
    if (
        typeof error === 'object' &&
        error !== null &&
        'name' in error &&
        error.name === 'BrowserActionStorageCustodyError' &&
        'code' in error &&
        isCustodyErrorCode(error.code)
    ) {
        return error.code;
    }
    if (
        isPlainRecord(error) &&
        (error.code === 'Unavailable' || error.code === 'InvalidConfiguration')
    ) {
        return error.code === 'Unavailable' ? 'Unavailable' : 'InvalidInput';
    }

    return 'OwnedWorkerFailure';
};

const describeHostError = (error: unknown, depth = 0): string => {
    if (depth >= 12) {
        return 'nested failure';
    }
    if (Array.isArray(error)) {
        return error
            .map((item) => describeHostError(item, depth + 1))
            .join(' | ');
    }
    if (error instanceof Error) {
        const failureCause =
            'failureCause' in error
                ? (error as Error & { failureCause?: unknown }).failureCause
                : undefined;
        return `${error.name}: ${error.message}${failureCause === undefined ? '' : ` -> ${describeHostError(failureCause, depth + 1)}`}`;
    }
    return String(error);
};

class BoundedWorkerAsyncChannel<Value> implements AsyncIterable<Value> {
    #failure: Error | undefined;
    #finished = false;
    #pending:
        | Readonly<{
              reject(error: unknown): void;
              resolve(): void;
              value: Value;
          }>
        | undefined;
    #waiting:
        | Readonly<{
              reject(error: unknown): void;
              resolve(result: IteratorResult<Value>): void;
          }>
        | undefined;

    public [Symbol.asyncIterator](): AsyncIterator<Value> {
        return { next: () => this.read() };
    }

    public write(value: Value): Promise<void> {
        if (this.#failure !== undefined) {
            return Promise.reject(this.#failure);
        }
        if (this.#finished || this.#pending !== undefined) {
            return Promise.reject(
                new BrowserActionStorageCustodyError(
                    'InvalidState',
                    'The bounded worker stream cannot accept another chunk.',
                ),
            );
        }
        const waiting = this.#waiting;
        if (waiting !== undefined) {
            this.#waiting = undefined;
            waiting.resolve({ done: false, value });
            return Promise.resolve();
        }
        return new Promise<void>((resolve, reject) => {
            this.#pending = { reject, resolve, value };
        });
    }

    public finish(): void {
        if (this.#finished) {
            return;
        }
        this.#finished = true;
        this.#waiting?.resolve({ done: true, value: undefined });
        this.#waiting = undefined;
    }

    public fail(error: unknown): void {
        if (this.#failure !== undefined) {
            return;
        }
        const failure =
            error instanceof Error
                ? error
                : new BrowserActionStorageCustodyError(
                      'OwnedWorkerFailure',
                      'The bounded worker stream failed with a non-error value.',
                      error,
                  );
        this.#failure = failure;
        this.#pending?.reject(failure);
        this.#pending = undefined;
        this.#waiting?.reject(failure);
        this.#waiting = undefined;
    }

    public read(): Promise<IteratorResult<Value>> {
        if (this.#failure !== undefined) {
            return Promise.reject(this.#failure);
        }
        const pending = this.#pending;
        if (pending !== undefined) {
            this.#pending = undefined;
            pending.resolve();
            return Promise.resolve({ done: false, value: pending.value });
        }
        if (this.#finished) {
            return Promise.resolve({ done: true, value: undefined });
        }
        if (this.#waiting !== undefined) {
            return Promise.reject(
                new BrowserActionStorageCustodyError(
                    'InvalidState',
                    'The bounded worker stream already has a waiting reader.',
                ),
            );
        }
        return new Promise<IteratorResult<Value>>((resolve, reject) => {
            this.#waiting = { reject, resolve };
        });
    }
}

/**
 * Installs the worker half of the bounded custody channel. The cryptographic
 * kernel, Web Lock handle, IndexedDB adapter, device key, wrapped envelope, and
 * plaintext root all remain in this worker realm.
 */
type BrowserFoundationWitnessCryptography = Readonly<{
    stateObjectSignatureOperation: BrowserStateObjectSignatureOperation;
}>;

type BrowserFoundationWitnessRuntimeConfiguration = Readonly<{
    durableStateLimits: DurableStateWitnessServiceLimits;
    openVerifiedStateDurableBinding?(
        stateObjectIdentifier: string,
    ): Promise<VerificationResult<VerifiedStateDurableBinding>>;
    openWitnessCryptography(input: {
        canonicalRosterBytes: Uint8Array;
    }):
        | Promise<BrowserFoundationWitnessCryptography>
        | BrowserFoundationWitnessCryptography;
}>;

type WorkerFoundationOperationInitializationBatch = Readonly<{
    canonicalRosterBytes: Uint8Array;
    initialization:
        | WebLockCommittedBrowserFoundationInitialization
        | WebLockRecoveredBrowserFoundationInitialization;
    openingMode: 'fresh-provisioned' | 'recovered';
}>;

type WorkerFoundationInitializationCleanupOwner = {
    canonicalRosterBytes?: Uint8Array;
    initialization:
        | WebLockCommittedBrowserFoundationInitialization
        | WebLockRecoveredBrowserFoundationInitialization;
};

type WorkerFoundationNormalWitnessRole = Readonly<{
    durableStateService: DurableStateWitnessService;
    freshnessCoordinate: BrowserFoundationFreshnessCoordinate;
    record: WebLockFoundationWitnessRecord;
    stateObjectSignatureOperation: BrowserStateObjectSignatureOperation;
}>;

type WorkerFoundationActionRandomnessHandle = Readonly<{
    actionRandomnessCommitment: Uint8Array;
    actionRandomnessSessionIdentifier: string;
}>;

type WorkerFoundationDurableStateBinding = {
    binding: VerifiedStateDurableBinding;
    expectedFreshnessCoordinate: BrowserFoundationFreshnessCoordinate;
    stateObjectIdentifier: string;
    witnessRoleIdentifier: string;
};

export type BrowserActionStorageCustodyWorkerHostConfiguration = Readonly<{
    checkpointStore?: Readonly<{
        boundaryPolicy: CheckpointBoundaryPolicy;
        cursorKernel: CheckpointRandomCursorKernel;
        limits: AuthenticatedCheckpointStoreLimits;
    }>;
    cryptoProvider?: Crypto;
    indexedDbFactory?: IDBFactory;
    keyRangeFactory?: typeof IDBKeyRange;
    lockManager?: LockManager | null;
    foundationWitnessRuntime?: BrowserFoundationWitnessRuntimeConfiguration;
    workerScope: CustodyWorkerScope;
}> &
    (
        | Readonly<{
              openOwnedCustody?: never;
              workerKernel: BrowserActionStorageWorkerKernel;
          }>
        | Readonly<{
              openOwnedCustody(
                  configuration: BrowserActionStorageCustodyWorkerConfiguration,
                  acquisitionSignal: AbortSignal,
              ): Promise<WebLockOwnedBrowserActionStorageCustody>;
              workerKernel?: BrowserActionStorageWorkerKernel;
          }>
    );

export const installBrowserActionStorageCustodyWorkerHost = (
    input: BrowserActionStorageCustodyWorkerHostConfiguration,
): (() => Promise<void>) => {
    if (typeof globalThis.document !== 'undefined') {
        throw new BrowserActionStorageCustodyError(
            'Unavailable',
            'Browser action-storage custody host must run inside a dedicated worker.',
        );
    }
    let lastRequestIdentifier = 0;
    let ownedCustody: WebLockOwnedBrowserActionStorageCustody | undefined;
    let checkpointStore: AuthenticatedCheckpointStore | undefined;
    let openingCheckpointStore:
        | Promise<AuthenticatedCheckpointStore>
        | undefined;
    let openingCustody:
        | Promise<WebLockOwnedBrowserActionStorageCustody>
        | undefined;
    let openingCustodyAbortController: AbortController | undefined;
    let operationTail: Promise<void> = Promise.resolve();
    let terminalCleanup: Promise<void> | undefined;
    let terminalFailure: BrowserActionStorageCustodyError | undefined;
    let uninstalled = false;
    const committedFoundationInitializationBatches = new Map<
        string,
        WebLockCommittedBrowserFoundationInitialization
    >();
    const foundationOperationInitializationBatches = new Map<
        string,
        WorkerFoundationOperationInitializationBatch
    >();
    const foundationNormalWitnessRoles = new Map<
        string,
        WorkerFoundationNormalWitnessRole
    >();
    const foundationWitnessRolesPendingCleanup =
        new Set<WorkerFoundationNormalWitnessRole>();
    const foundationTransferableWitnessServicesPendingCleanup =
        new Set<TransferableDurableStateWitnessService>();
    const foundationActionRandomnessHandles = new Map<
        string,
        WorkerFoundationActionRandomnessHandle
    >();
    const foundationDurableStateBindings = new Map<
        string,
        WorkerFoundationDurableStateBinding
    >();
    const foundationStateObjectIdentifiers = new Set<string>();
    const foundationInitializationsPendingCleanup =
        new Set<WorkerFoundationInitializationCleanupOwner>();
    const checkpoints = new Map<
        string,
        Readonly<{
            identity: CheckpointOperationIdentity;
            resumed?: ResumedCheckpoint;
        }>
    >();
    const requireAvailableCheckpointHandleCapacity = (): void => {
        if (checkpoints.size >= maximumActiveCheckpointHandleCount) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                `The worker already owns the maximum ${maximumActiveCheckpointHandleCount} active checkpoint handles.`,
            );
        }
    };
    const checkpointPublications = new Map<
        string,
        Readonly<{
            channel: BoundedWorkerAsyncChannel<Uint8Array>;
            checkpointLineageKey: string;
            publication: Promise<Uint8Array>;
        }>
    >();
    const checkpointRestores = new Map<
        string,
        Readonly<{
            channel: BoundedWorkerAsyncChannel<
                Readonly<{ chunkBytes: Uint8Array; chunkIndex: number }>
            >;
            checkpointLineageKey: string;
            restoration: Promise<void>;
        }>
    >();
    const requireAvailableCheckpointLineage = (
        checkpointLineageIdentifier: Uint8Array,
    ): string => {
        const checkpointLineageKey = bytesToHex(checkpointLineageIdentifier);
        if (
            [...checkpointPublications.values()].some(
                (publication) =>
                    publication.checkpointLineageKey === checkpointLineageKey,
            ) ||
            [...checkpointRestores.values()].some(
                (restore) =>
                    restore.checkpointLineageKey === checkpointLineageKey,
            )
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'The checkpoint lineage already owns an active publication or restore stream.',
            );
        }
        return checkpointLineageKey;
    };
    const commonProofExecutionEnvironments =
        new Set<InstalledCommonProofExecutionEnvironment>();
    const commonProofPreparedOperations =
        new Set<InstalledCommonProofPreparedOperation>();
    const retirePreparedCommonProofOperation = (
        preparedOperation: InstalledCommonProofPreparedOperation,
    ): void => {
        const record =
            installedCommonProofPreparedOperationRecords.get(preparedOperation);
        if (record !== undefined) {
            record.consumed = true;
            if (record.generationFamilyAdapter !== undefined) {
                releaseClosedWorkerCommonProofGenerationFamilyAdapter(
                    record.generationFamilyAdapter,
                );
                record.generationFamilyAdapter = undefined;
            }
            record.commonProofRuntimeBindingHash.fill(0);
            record.commonProofVerificationBindingHash.fill(0);
            record.proofAttemptLineageIdentifier.fill(0);
            installedCommonProofPreparedOperationRecords.delete(
                preparedOperation,
            );
        }
        commonProofPreparedOperations.delete(preparedOperation);
    };
    const finishPreparedCommonProofOperationTransfer = (
        preparedOperation: InstalledCommonProofPreparedOperation,
        record: InstalledCommonProofPreparedOperationRecord,
    ): void => {
        if (
            installedCommonProofPreparedOperationRecords.get(
                preparedOperation,
            ) !== record ||
            !record.consumed ||
            record.generationFamilyAdapter !== undefined
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'The common-proof prepared operation cannot finish its neutral authority transfer.',
            );
        }
        record.commonProofRuntimeBindingHash.fill(0);
        record.commonProofVerificationBindingHash.fill(0);
        record.proofAttemptLineageIdentifier.fill(0);
        installedCommonProofPreparedOperationRecords.delete(preparedOperation);
        commonProofPreparedOperations.delete(preparedOperation);
    };
    const listenerHolder: {
        value?: (event: MessageEvent<unknown>) => void;
    } = {};
    const issueFoundationInitializationBatchIdentifier = (
        additionallyReservedIdentifiers?: ReadonlySet<string>,
    ): string => {
        const cryptoProvider = input.cryptoProvider ?? globalThis.crypto;
        if (cryptoProvider?.getRandomValues === undefined) {
            throw new BrowserActionStorageCustodyError(
                'Unavailable',
                'Secure randomness is unavailable for a foundation initialization batch identifier.',
            );
        }
        for (let attempt = 0; attempt < 16; attempt += 1) {
            const identifierBytes = new Uint8Array(32);
            cryptoProvider.getRandomValues(identifierBytes);
            const identifier = Array.from(identifierBytes, (byte) =>
                byte.toString(16).padStart(2, '0'),
            ).join('');
            identifierBytes.fill(0);
            if (
                !committedFoundationInitializationBatches.has(identifier) &&
                !foundationOperationInitializationBatches.has(identifier) &&
                !foundationNormalWitnessRoles.has(identifier) &&
                !foundationActionRandomnessHandles.has(identifier) &&
                !foundationDurableStateBindings.has(identifier) &&
                !checkpoints.has(identifier) &&
                !checkpointPublications.has(identifier) &&
                !checkpointRestores.has(identifier) &&
                !additionallyReservedIdentifiers?.has(identifier)
            ) {
                return identifier;
            }
        }
        throw new BrowserActionStorageCustodyError(
            'Unavailable',
            'Secure randomness repeatedly produced an existing foundation initialization batch identifier.',
        );
    };
    const requireCheckpointStore =
        async (): Promise<AuthenticatedCheckpointStore> => {
            if (checkpointStore !== undefined) {
                return checkpointStore;
            }
            if (
                input.checkpointStore === undefined ||
                ownedCustody === undefined
            ) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidState',
                    'Worker-owned checkpoint storage is not configured or root-active.',
                );
            }
            openingCheckpointStore ??= ownedCustody
                .openCheckpointStore(input.checkpointStore)
                .then((opened) => opened.claimExclusiveOwner());
            checkpointStore = await openingCheckpointStore;
            return checkpointStore;
        };
    const requireFoundationWitnessRuntime =
        (): BrowserFoundationWitnessRuntimeConfiguration => {
            if (input.foundationWitnessRuntime === undefined) {
                throw new BrowserActionStorageCustodyError(
                    'Unavailable',
                    'Worker-owned foundation witness cryptography is not configured.',
                );
            }
            return input.foundationWitnessRuntime;
        };
    const requireFoundationWorkerKernel =
        (): BrowserActionStorageWorkerKernel => {
            if (input.workerKernel === undefined) {
                throw new BrowserActionStorageCustodyError(
                    'Unavailable',
                    'The worker-owned foundation kernel is unavailable.',
                );
            }
            return input.workerKernel;
        };
    const destroyFoundationWitnessRecord = (
        record: WebLockFoundationWitnessRecord,
    ): void => {
        record.actionRandomnessCommitment.fill(0);
        record.authorizedEmptyPlaintext.fill(0);
        record.localRecordIdentifier.fill(0);
        record.stateKey.fill(0);
        record.subjectParticipantIdentity.fill(0);
        record.witnessParticipantIdentity.fill(0);
    };
    const copyFoundationWitnessRecord = (
        record: WebLockFoundationWitnessRecord,
    ): WebLockFoundationWitnessRecord =>
        Object.freeze({
            actionRandomnessCommitment:
                record.actionRandomnessCommitment.slice(),
            authorizedEmptyPlaintext: record.authorizedEmptyPlaintext.slice(),
            localRecordIdentifier: record.localRecordIdentifier.slice(),
            roleIndex: record.roleIndex,
            stateKey: record.stateKey.slice(),
            subjectParticipantIdentity:
                record.subjectParticipantIdentity.slice(),
            witnessParticipantIdentity:
                record.witnessParticipantIdentity.slice(),
        });
    const destroyCommittedFoundationInitialization = (
        initialization:
            | WebLockCommittedBrowserFoundationInitialization
            | WebLockRecoveredBrowserFoundationInitialization,
    ): void => {
        initialization.actionRandomnessCommitment.fill(0);
        destroyFoundationCoordinate(initialization.freshnessCoordinate);
        for (const record of initialization.orderedWitnessRecords) {
            destroyFoundationWitnessRecord(record);
        }
    };
    const closeFoundationNormalWitnessRole = async (
        role: WorkerFoundationNormalWitnessRole,
    ): Promise<void> => {
        try {
            await role.durableStateService.close();
        } catch (error) {
            throw new BrowserActionStorageCustodyError(
                'OwnedWorkerFailure',
                'Worker-owned foundation witness cleanup failed.',
                error,
            );
        }
        destroyFoundationCoordinate(role.freshnessCoordinate);
        destroyFoundationWitnessRecord(role.record);
    };
    const closeFoundationInitializationCleanupOwner = async (
        owner: WorkerFoundationInitializationCleanupOwner,
    ): Promise<void> => {
        await custody().closeActionRandomness(
            owner.initialization.actionRandomnessSessionIdentifier,
        );
        owner.canonicalRosterBytes?.fill(0);
        destroyCommittedFoundationInitialization(owner.initialization);
        foundationInitializationsPendingCleanup.delete(owner);
    };
    const closePendingFoundationRollbackResources = async (): Promise<void> => {
        const failures: unknown[] = [];
        for (const service of foundationTransferableWitnessServicesPendingCleanup) {
            try {
                await service.close();
                foundationTransferableWitnessServicesPendingCleanup.delete(
                    service,
                );
            } catch (error) {
                failures.push(error);
            }
        }
        for (const role of foundationWitnessRolesPendingCleanup) {
            try {
                await closeFoundationNormalWitnessRole(role);
                foundationWitnessRolesPendingCleanup.delete(role);
            } catch (error) {
                failures.push(error);
            }
        }
        for (const owner of foundationInitializationsPendingCleanup) {
            try {
                await closeFoundationInitializationCleanupOwner(owner);
            } catch (error) {
                failures.push(error);
            }
        }
        if (failures.length !== 0) {
            throw new BrowserActionStorageCustodyError(
                'OwnedWorkerFailure',
                'Worker-owned foundation rollback cleanup remains incomplete.',
                failures,
            );
        }
    };
    const failFoundationInitializationRetention = async (
        owner: WorkerFoundationInitializationCleanupOwner,
        operationFailure: unknown,
        failureMessage: string,
    ): Promise<never> => {
        try {
            await closeFoundationInitializationCleanupOwner(owner);
        } catch (cleanupFailure) {
            throw new BrowserActionStorageCustodyError(
                'OwnedWorkerFailure',
                failureMessage,
                [operationFailure, cleanupFailure],
            );
        }
        throw operationFailure;
    };
    const closeFoundationOperationResources = async (): Promise<void> => {
        const failures: unknown[] = [];
        for (const preparedOperation of commonProofPreparedOperations) {
            try {
                retirePreparedCommonProofOperation(preparedOperation);
            } catch (error) {
                failures.push(error);
            }
        }
        for (const [identifier, role] of foundationNormalWitnessRoles) {
            try {
                await closeFoundationNormalWitnessRole(role);
                foundationNormalWitnessRoles.delete(identifier);
            } catch (error) {
                failures.push(error);
            }
        }
        for (const role of foundationWitnessRolesPendingCleanup) {
            try {
                await closeFoundationNormalWitnessRole(role);
                foundationWitnessRolesPendingCleanup.delete(role);
            } catch (error) {
                failures.push(error);
            }
        }
        for (const service of foundationTransferableWitnessServicesPendingCleanup) {
            try {
                await service.close();
                foundationTransferableWitnessServicesPendingCleanup.delete(
                    service,
                );
            } catch (error) {
                failures.push(error);
            }
        }
        for (const binding of foundationDurableStateBindings.values()) {
            destroyFoundationCoordinate(binding.expectedFreshnessCoordinate);
        }
        foundationDurableStateBindings.clear();
        const workerKernel = input.workerKernel;
        for (const stateObjectIdentifier of foundationStateObjectIdentifiers) {
            try {
                if (workerKernel === undefined) {
                    throw new BrowserActionStorageCustodyError(
                        'Unavailable',
                        'The worker-owned foundation kernel is unavailable for state-object cleanup.',
                    );
                }
                await workerKernel.releaseActionStateObject(
                    stateObjectIdentifier,
                );
                foundationStateObjectIdentifiers.delete(stateObjectIdentifier);
            } catch (error) {
                failures.push(error);
            }
        }
        for (const [identifier, handle] of foundationActionRandomnessHandles) {
            try {
                await custody().closeActionRandomness(
                    handle.actionRandomnessSessionIdentifier,
                );
                handle.actionRandomnessCommitment.fill(0);
                foundationActionRandomnessHandles.delete(identifier);
            } catch (error) {
                failures.push(error);
            }
        }
        for (const [
            identifier,
            batch,
        ] of foundationOperationInitializationBatches) {
            try {
                await custody().closeActionRandomness(
                    batch.initialization.actionRandomnessSessionIdentifier,
                );
                batch.canonicalRosterBytes.fill(0);
                destroyCommittedFoundationInitialization(batch.initialization);
                foundationOperationInitializationBatches.delete(identifier);
            } catch (error) {
                failures.push(error);
            }
        }
        for (const [
            identifier,
            batch,
        ] of committedFoundationInitializationBatches) {
            try {
                await custody().closeActionRandomness(
                    batch.actionRandomnessSessionIdentifier,
                );
                destroyCommittedFoundationInitialization(batch);
                committedFoundationInitializationBatches.delete(identifier);
            } catch (error) {
                failures.push(error);
            }
        }
        for (const owner of foundationInitializationsPendingCleanup) {
            try {
                await closeFoundationInitializationCleanupOwner(owner);
            } catch (error) {
                failures.push(error);
            }
        }
        if (failures.length !== 0) {
            throw new BrowserActionStorageCustodyError(
                'OwnedWorkerFailure',
                'Worker-owned foundation operation cleanup failed.',
                failures,
            );
        }
    };
    const closeCheckpointResources = async (): Promise<void> => {
        const closingError = new BrowserActionStorageCustodyError(
            'Closed',
            'Worker-owned checkpoint storage is closing.',
        );
        for (const publication of checkpointPublications.values()) {
            publication.channel.fail(closingError);
        }
        for (const restore of checkpointRestores.values()) {
            restore.channel.fail(closingError);
        }
        const commonProofCleanupOutcomes = await Promise.allSettled(
            [...commonProofExecutionEnvironments].map(async (environment) => {
                const record =
                    installedCommonProofExecutionEnvironmentRecords.get(
                        environment,
                    );
                if (record === undefined) {
                    return;
                }
                await retireInstalledCommonProofExecutionEnvironment(
                    environment,
                    record,
                );
            }),
        );
        const operationOutcomes = await Promise.allSettled([
            ...[...checkpointPublications.values()].map(
                (record) => record.publication,
            ),
            ...[...checkpointRestores.values()].map(
                (record) => record.restoration,
            ),
        ]);
        checkpointPublications.clear();
        checkpointRestores.clear();
        const failures = operationOutcomes
            .filter(
                (outcome): outcome is PromiseRejectedResult =>
                    outcome.status === 'rejected',
            )
            .map((outcome) => outcome.reason as unknown);
        const commonProofCleanupFailures = commonProofCleanupOutcomes
            .filter(
                (outcome): outcome is PromiseRejectedResult =>
                    outcome.status === 'rejected',
            )
            .map((outcome) => outcome.reason as unknown);
        failures.push(...commonProofCleanupFailures);
        if (commonProofCleanupFailures.length === 0) {
            let store = checkpointStore;
            if (store === undefined && openingCheckpointStore !== undefined) {
                try {
                    store = await openingCheckpointStore;
                } catch (error) {
                    failures.push(error);
                    store = undefined;
                }
            }
            if (store === undefined && checkpoints.size !== 0) {
                failures.push(
                    new BrowserActionStorageCustodyError(
                        'OwnedWorkerFailure',
                        'Worker-owned checkpoint identities lost their authenticated store.',
                    ),
                );
            } else if (store !== undefined) {
                for (const [identifier, checkpoint] of checkpoints) {
                    try {
                        await store.releaseOperationIdentity(
                            checkpoint.identity,
                        );
                        checkpoints.delete(identifier);
                    } catch (error) {
                        failures.push(error);
                    }
                }
            }
            if (checkpoints.size === 0) {
                try {
                    await store?.close();
                    checkpointStore = undefined;
                    openingCheckpointStore = undefined;
                } catch (error) {
                    failures.push(error);
                }
            }
        }
        if (failures.length !== 0) {
            throw new BrowserActionStorageCustodyError(
                'OwnedWorkerFailure',
                'Worker-owned checkpoint cleanup failed.',
                failures,
            );
        }
    };

    const closeForTerminalFailure = async (
        originalFailure: BrowserActionStorageCustodyError,
    ): Promise<void> => {
        const cleanupFailures: unknown[] = [];
        let childResourceCleanupCompleted = true;
        try {
            await closeCheckpointResources();
        } catch (error) {
            childResourceCleanupCompleted = false;
            cleanupFailures.push(error);
        }
        try {
            await closeFoundationOperationResources();
        } catch (error) {
            childResourceCleanupCompleted = false;
            cleanupFailures.push(error);
        }
        const handle = ownedCustody;
        if (childResourceCleanupCompleted && handle !== undefined) {
            try {
                await handle.close();
                if (ownedCustody === handle) {
                    ownedCustody = undefined;
                }
            } catch (error) {
                cleanupFailures.push(error);
            }
        }
        if (cleanupFailures.length > 0) {
            terminalFailure = new BrowserActionStorageCustodyError(
                'OwnedWorkerFailure',
                'The browser action-storage worker channel failed and custody cleanup also failed.',
                [originalFailure, ...cleanupFailures],
            );
        }
        let notificationFailure: unknown;
        try {
            input.workerScope.postMessage({
                errorCode: 'OwnedWorkerFailure',
                messageKind: 'browser-action-storage-custody-channel-failed',
            });
        } catch (error) {
            notificationFailure = error;
        }
        if (notificationFailure !== undefined) {
            terminalFailure = new BrowserActionStorageCustodyError(
                'OwnedWorkerFailure',
                'The browser action-storage worker channel failed, then its terminal notification failed.',
                [terminalFailure ?? originalFailure, notificationFailure],
            );
        }
        if (cleanupFailures.length > 0 || notificationFailure !== undefined) {
            throw terminalFailure ?? originalFailure;
        }
    };

    const failHost = (failureCause: unknown): void => {
        if (terminalFailure !== undefined) {
            return;
        }
        terminalFailure = new BrowserActionStorageCustodyError(
            'OwnedWorkerFailure',
            'The browser action-storage worker channel received invalid traffic or output.',
            failureCause,
        );
        uninstalled = true;
        openingCustodyAbortController?.abort(terminalFailure);
        if (listenerHolder.value !== undefined) {
            input.workerScope.removeEventListener(
                'message',
                listenerHolder.value,
            );
        }
        const originalFailure = terminalFailure;
        terminalCleanup = operationTail.then(
            () => closeForTerminalFailure(originalFailure),
            (operationFailure: unknown) => {
                const combinedFailure = new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The browser action-storage worker channel failed while a prior operation also failed.',
                    [originalFailure, operationFailure],
                );
                terminalFailure = combinedFailure;
                return closeForTerminalFailure(combinedFailure);
            },
        );
        void terminalCleanup.catch(() => undefined);
    };

    const custody = (): BrowserActionStorageCustody => {
        if (ownedCustody === undefined) {
            throw new BrowserActionStorageCustodyError(
                'Closed',
                'Browser action-storage custody is not open in this worker.',
            );
        }

        return ownedCustody.custody;
    };

    const requireOwnedCustody = (): WebLockOwnedBrowserActionStorageCustody => {
        if (ownedCustody === undefined) {
            throw new BrowserActionStorageCustodyError(
                'Closed',
                'Browser foundation storage ownership is not open in this worker.',
            );
        }
        return ownedCustody;
    };

    const requireFoundationNormalWitnessRole = (
        identifier: string,
    ): WorkerFoundationNormalWitnessRole => {
        const role = foundationNormalWitnessRoles.get(identifier);
        if (role === undefined) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'The foundation witness role is unavailable in this worker.',
            );
        }
        return role;
    };

    const requireFoundationDurableStateBinding = (
        identifier: string,
        witnessRoleIdentifier: string,
    ): WorkerFoundationDurableStateBinding => {
        const binding = foundationDurableStateBindings.get(identifier);
        if (
            binding === undefined ||
            binding.witnessRoleIdentifier !== witnessRoleIdentifier
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'The durable state binding is unavailable or belongs to another witness context.',
            );
        }
        return binding;
    };

    const requireCurrentDurableBindingHead = async (
        binding: WorkerFoundationDurableStateBinding,
    ): Promise<BrowserFoundationFreshnessCoordinate> => {
        const current = copyFoundationFreshnessCoordinate(
            await requireOwnedCustody().authenticateFoundationHead(),
        );
        if (
            !foundationCoordinatesEqual(
                current,
                binding.expectedFreshnessCoordinate,
            )
        ) {
            destroyFoundationCoordinate(current);
            throw new BrowserActionStorageCustodyError(
                'Conflict',
                'The durable state binding is stale for the authenticated storage head.',
            );
        }
        return current;
    };

    const classifyFoundationHeadTransition = (
        before: BrowserFoundationFreshnessCoordinate,
        after: BrowserFoundationFreshnessCoordinate,
    ): boolean => {
        if (foundationCoordinatesEqual(before, after)) {
            return false;
        }
        if (
            after.freshnessSequence !== before.freshnessSequence + 1n ||
            !bytesEqual(
                before.storageInstanceIdentity,
                after.storageInstanceIdentity,
            ) ||
            bytesEqual(
                before.authenticatedHeadDigest,
                after.authenticatedHeadDigest,
            )
        ) {
            throw new BrowserActionStorageCustodyError(
                'OwnedWorkerFailure',
                'The worker-owned operation produced an invalid authenticated storage transition.',
            );
        }
        return true;
    };

    const assertCommonProofDurableBindingCurrent = async (bindingInput: {
        durableBindingIdentifier: string;
        witnessRoleIdentifier: string;
    }): Promise<void> => {
        requireFoundationNormalWitnessRole(bindingInput.witnessRoleIdentifier);
        const binding = requireFoundationDurableStateBinding(
            bindingInput.durableBindingIdentifier,
            bindingInput.witnessRoleIdentifier,
        );
        const current = await requireCurrentDurableBindingHead(binding);
        destroyFoundationCoordinate(current);
    };

    const refreshCommonProofDurableBindingAfterControlledCleanup =
        async (bindingInput: {
            durableBindingIdentifier: string;
            witnessRoleIdentifier: string;
        }): Promise<void> => {
            requireFoundationNormalWitnessRole(
                bindingInput.witnessRoleIdentifier,
            );
            const binding = requireFoundationDurableStateBinding(
                bindingInput.durableBindingIdentifier,
                bindingInput.witnessRoleIdentifier,
            );
            const current = copyFoundationFreshnessCoordinate(
                await requireOwnedCustody().authenticateFoundationHead(),
            );
            if (
                current.freshnessSequence <=
                    binding.expectedFreshnessCoordinate.freshnessSequence ||
                !bytesEqual(
                    current.storageInstanceIdentity,
                    binding.expectedFreshnessCoordinate.storageInstanceIdentity,
                ) ||
                bytesEqual(
                    current.authenticatedHeadDigest,
                    binding.expectedFreshnessCoordinate.authenticatedHeadDigest,
                )
            ) {
                destroyFoundationCoordinate(current);
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'Common-proof handoff cleanup produced an invalid authenticated storage transition.',
                );
            }
            destroyFoundationCoordinate(binding.expectedFreshnessCoordinate);
            binding.expectedFreshnessCoordinate = current;
        };

    const runFoundationWitnessMutation = async <Value>(operationInput: {
        durableBindingIdentifier: string;
        operation(
            role: WorkerFoundationNormalWitnessRole,
            binding: VerifiedStateDurableBinding,
            predecessor: BrowserFoundationFreshnessCoordinate,
        ): Promise<Value>;
        witnessRoleIdentifier: string;
    }): Promise<Value> => {
        const role = requireFoundationNormalWitnessRole(
            operationInput.witnessRoleIdentifier,
        );
        const binding = requireFoundationDurableStateBinding(
            operationInput.durableBindingIdentifier,
            operationInput.witnessRoleIdentifier,
        );
        const before = await requireCurrentDurableBindingHead(binding);
        let after: BrowserFoundationFreshnessCoordinate | undefined;
        try {
            const value = await operationInput.operation(
                role,
                binding.binding,
                before,
            );
            after = copyFoundationFreshnessCoordinate(
                await requireOwnedCustody().authenticateFoundationHead(),
            );
            classifyFoundationHeadTransition(before, after);
            destroyFoundationCoordinate(binding.expectedFreshnessCoordinate);
            binding.expectedFreshnessCoordinate =
                copyFoundationFreshnessCoordinate(after);
            return value;
        } finally {
            destroyFoundationCoordinate(before);
            if (after !== undefined) {
                destroyFoundationCoordinate(after);
            }
        }
    };

    const runVerifiedCommonProofApplication = async (
        operationInput: InstalledCommonProofApplicationInput,
    ): Promise<void> => {
        let commitAttempted = false;
        let abortFailed = false;
        try {
            return await runFoundationWitnessMutation({
                durableBindingIdentifier:
                    operationInput.durableBindingIdentifier,
                operation: async (role, _binding, predecessor) => {
                    let capabilityTransfer:
                        | InstalledCommonProofCapabilityTransfer
                        | undefined;
                    const capability = (capabilityTransfer =
                        operationInput.transferVerifiedCapability()).capability;
                    let prepared: Awaited<
                        ReturnType<
                            typeof prepareClosedWorkerVerifiedCommonProofApplication
                        >
                    >;
                    try {
                        prepared =
                            await prepareClosedWorkerVerifiedCommonProofApplication(
                                requireFoundationWorkerKernel(),
                                capability,
                                predecessor,
                            );
                    } catch (error) {
                        try {
                            capabilityTransfer?.restore();
                        } catch (restorationError) {
                            abortFailed = true;
                            throw new BrowserActionStorageCustodyError(
                                'OwnedWorkerFailure',
                                'The common-proof application preparation failed and its verifier capability could not return to execution custody.',
                                [error, restorationError],
                            );
                        }
                        throw error;
                    }
                    let authenticatedAuthorizationFrame: Uint8Array | undefined;
                    let successor:
                        | BrowserFoundationFreshnessCoordinate
                        | undefined;
                    try {
                        authenticatedAuthorizationFrame =
                            await persistCommonProofApplicationAuthorization(
                                role.durableStateService,
                                {
                                    authorizationFrame:
                                        prepared.authorizationFrame,
                                    handoff: operationInput.handoff,
                                    onCommitAttempt: () => {
                                        if (commitAttempted) {
                                            throw new BrowserActionStorageCustodyError(
                                                'InvalidState',
                                                'The common-proof application attempted more than one durable commit.',
                                            );
                                        }
                                        commitAttempted = true;
                                    },
                                    proofApplicationSlotHash:
                                        prepared.proofApplicationSlotHash,
                                },
                            );
                        if (!commitAttempted) {
                            throw new BrowserActionStorageCustodyError(
                                'OwnedWorkerFailure',
                                'Common-proof persistence returned without an authenticated commit attempt.',
                            );
                        }
                        successor = copyFoundationFreshnessCoordinate(
                            await requireOwnedCustody().authenticateFoundationHead(),
                        );
                        if (
                            !classifyFoundationHeadTransition(
                                predecessor,
                                successor,
                            )
                        ) {
                            throw new BrowserActionStorageCustodyError(
                                'OwnedWorkerFailure',
                                'The common-proof application did not advance the authenticated storage head.',
                            );
                        }
                        await prepared.confirm({
                            authenticatedAuthorizationFrame,
                            successor,
                        });
                        return undefined;
                    } catch (error) {
                        if (!commitAttempted) {
                            try {
                                await prepared.abort();
                                capabilityTransfer?.restore();
                            } catch (abortError) {
                                abortFailed = true;
                                throw new BrowserActionStorageCustodyError(
                                    'OwnedWorkerFailure',
                                    'The common-proof application failed before commit and its verifier capability could not be restored.',
                                    [error, abortError],
                                );
                            }
                        }
                        throw error;
                    } finally {
                        authenticatedAuthorizationFrame?.fill(0);
                        if (successor !== undefined) {
                            destroyFoundationCoordinate(successor);
                        }
                    }
                },
                witnessRoleIdentifier: operationInput.witnessRoleIdentifier,
            });
        } catch (error) {
            const errorCode =
                error instanceof Error && 'code' in error
                    ? String((error as { code?: unknown }).code)
                    : undefined;
            const permanentStateFailure =
                abortFailed ||
                commitAttempted ||
                errorCode === 'AuthenticationFailed' ||
                errorCode === 'CleanupFailed' ||
                errorCode === 'Conflict' ||
                errorCode === 'MissingRecord';
            if (!permanentStateFailure) {
                throw error;
            }
            const terminalError =
                error instanceof BrowserActionStorageCustodyError &&
                error.code === 'OwnedWorkerFailure'
                    ? error
                    : new BrowserActionStorageCustodyError(
                          'OwnedWorkerFailure',
                          'The common-proof application could not establish one exact authenticated durable successor.',
                          error,
                      );
            failHost(terminalError);
            throw terminalError;
        }
    };

    const runFoundationWitnessRead = async <Value>(operationInput: {
        durableBindingIdentifier: string;
        operation(
            role: WorkerFoundationNormalWitnessRole,
            binding: VerifiedStateDurableBinding,
        ): Promise<Value>;
        witnessRoleIdentifier: string;
    }): Promise<Value> => {
        const role = requireFoundationNormalWitnessRole(
            operationInput.witnessRoleIdentifier,
        );
        const binding = requireFoundationDurableStateBinding(
            operationInput.durableBindingIdentifier,
            operationInput.witnessRoleIdentifier,
        );
        const before = await requireCurrentDurableBindingHead(binding);
        let after: BrowserFoundationFreshnessCoordinate | undefined;
        try {
            const value = await operationInput.operation(role, binding.binding);
            after = copyFoundationFreshnessCoordinate(
                await requireOwnedCustody().authenticateFoundationHead(),
            );
            if (!foundationCoordinatesEqual(before, after)) {
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'A worker-owned durable read changed the authenticated storage head.',
                );
            }
            return value;
        } finally {
            destroyFoundationCoordinate(before);
            if (after !== undefined) {
                destroyFoundationCoordinate(after);
            }
        }
    };

    const requireFoundationStateObjectSignatureOperation =
        (): BrowserStateObjectSignatureOperation => {
            const rootBinding = custody().copyBinding();
            try {
                for (const role of foundationNormalWitnessRoles.values()) {
                    if (
                        bytesEqual(
                            role.record.witnessParticipantIdentity,
                            rootBinding.participantId,
                        )
                    ) {
                        return role.stateObjectSignatureOperation;
                    }
                }
            } finally {
                rootBinding.actionContextHash.fill(0);
                rootBinding.ceremonyContextHash.fill(0);
                rootBinding.participantId.fill(0);
                rootBinding.suiteId.fill(0);
            }
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'The active participant has no worker-owned foundation state signer.',
            );
        };

    const openFoundationWitnessDurableBinding = async (
        witnessRoleIdentifier: string,
        stateObjectIdentifier: string,
    ): Promise<string> => {
        const role = requireFoundationNormalWitnessRole(witnessRoleIdentifier);
        const runtime = requireFoundationWitnessRuntime();
        const opened =
            runtime.openVerifiedStateDurableBinding === undefined
                ? await openClosedWorkerVerifiedStateDurableBinding(
                      requireFoundationWorkerKernel(),
                      stateObjectIdentifier,
                  )
                : await runtime.openVerifiedStateDurableBinding(
                      stateObjectIdentifier,
                  );
        if (!opened.isValid) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                `The verified state object cannot issue a durable binding: ${opened.refusalReason}.`,
            );
        }
        const description = copyVerifiedStateDurableBinding(opened.value);
        const rootBinding = custody().copyBinding();
        try {
            if (
                !bytesEqual(
                    description.actionContextHash,
                    rootBinding.actionContextHash,
                ) ||
                !bytesEqual(
                    description.ceremonyContextHash,
                    rootBinding.ceremonyContextHash,
                ) ||
                !bytesEqual(description.suiteIdentifier, rootBinding.suiteId) ||
                !bytesEqual(
                    description.subjectParticipantIdentity,
                    role.record.subjectParticipantIdentity,
                )
            ) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'The verified state object belongs to another action or witness subject.',
                );
            }
        } finally {
            description.actionContextHash.fill(0);
            description.ceremonyContextHash.fill(0);
            description.exactOutputHash?.fill(0);
            description.intentObjectHash.fill(0);
            description.outputIntentObjectHash?.fill(0);
            description.reservationIntentObjectHash?.fill(0);
            description.stateKey.fill(0);
            description.subjectParticipantIdentity.fill(0);
            description.suiteIdentifier.fill(0);
            rootBinding.actionContextHash.fill(0);
            rootBinding.ceremonyContextHash.fill(0);
            rootBinding.participantId.fill(0);
            rootBinding.suiteId.fill(0);
        }
        const identifier = issueFoundationInitializationBatchIdentifier();
        foundationDurableStateBindings.set(identifier, {
            binding: opened.value,
            expectedFreshnessCoordinate: copyFoundationFreshnessCoordinate(
                await requireOwnedCustody().authenticateFoundationHead(),
            ),
            stateObjectIdentifier,
            witnessRoleIdentifier,
        });
        return identifier;
    };

    const voteForFoundationActionRandomnessReservationIntent =
        async (voteInput: {
            canonicalReservationIntentCarrier: Uint8Array;
            stateVerifierSessionIdentifier: string;
            subjectParticipantIdentity: Uint8Array;
            witnessRoleIdentifier: string;
        }): Promise<VerificationResult<Uint8Array>> => {
            const role = requireFoundationNormalWitnessRole(
                voteInput.witnessRoleIdentifier,
            );
            if (
                !bytesEqual(
                    role.record.subjectParticipantIdentity,
                    voteInput.subjectParticipantIdentity,
                )
            ) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'The foundation witness role belongs to another state subject.',
                );
            }
            const verified =
                await verifyClosedWorkerActionRandomnessReservationIntentForWitness(
                    requireFoundationWorkerKernel(),
                    {
                        canonicalReservationIntentCarrier:
                            voteInput.canonicalReservationIntentCarrier,
                        stateVerifierSessionIdentifier:
                            voteInput.stateVerifierSessionIdentifier,
                        subjectParticipantIdentity:
                            voteInput.subjectParticipantIdentity,
                    },
                );
            if (!verified.isValid) {
                return verified;
            }

            const stateIntentIdentifier = verified.value;
            foundationStateObjectIdentifiers.add(stateIntentIdentifier);
            let durableBindingIdentifier: string | undefined;
            let canonicalVoteCarrier: Uint8Array | undefined;
            let cachedVoteCarrier: Uint8Array | undefined;
            let readVoteCarrier: Uint8Array | undefined;
            try {
                durableBindingIdentifier =
                    await openFoundationWitnessDurableBinding(
                        voteInput.witnessRoleIdentifier,
                        stateIntentIdentifier,
                    );
                await runFoundationWitnessMutation({
                    durableBindingIdentifier,
                    operation: (witnessRole, binding) =>
                        witnessRole.durableStateService.compareAndLockIntent({
                            verifiedIntentBinding: binding,
                        }),
                    witnessRoleIdentifier: voteInput.witnessRoleIdentifier,
                });
                const produced =
                    await produceClosedWorkerActionRandomnessReservationWitnessVote(
                        requireFoundationWorkerKernel(),
                        {
                            signatureOperation:
                                role.stateObjectSignatureOperation,
                            stateIntentIdentifier,
                            witnessParticipantIdentity:
                                role.record.witnessParticipantIdentity,
                        },
                    );
                if (!produced.isValid) {
                    throw new BrowserActionStorageCustodyError(
                        'OwnedWorkerFailure',
                        `The verified foundation reservation intent could not produce a witness vote: ${produced.refusalReason}.`,
                    );
                }
                canonicalVoteCarrier = produced.value;
                const cached = await runFoundationWitnessMutation({
                    durableBindingIdentifier,
                    operation: (witnessRole, binding) =>
                        witnessRole.durableStateService.cacheSignedVoteCarrier({
                            canonicalSignedVoteCarrier: produced.value,
                            verifiedIntentBinding: binding,
                        }),
                    witnessRoleIdentifier: voteInput.witnessRoleIdentifier,
                });
                cachedVoteCarrier = cached;
                if (!bytesEqual(canonicalVoteCarrier, cachedVoteCarrier)) {
                    throw new BrowserActionStorageCustodyError(
                        'OwnedWorkerFailure',
                        'The durable state service did not retain the exact worker-produced witness vote carrier.',
                    );
                }
                readVoteCarrier = await runFoundationWitnessRead({
                    durableBindingIdentifier,
                    operation: (witnessRole, binding) =>
                        witnessRole.durableStateService.readSignedVoteCarrier({
                            verifiedIntentBinding: binding,
                        }),
                    witnessRoleIdentifier: voteInput.witnessRoleIdentifier,
                });
                if (!bytesEqual(canonicalVoteCarrier, readVoteCarrier)) {
                    throw new BrowserActionStorageCustodyError(
                        'OwnedWorkerFailure',
                        'The durable state service did not read back the exact worker-produced witness vote carrier.',
                    );
                }
                return Object.freeze({
                    isValid: true,
                    value: canonicalVoteCarrier.slice(),
                });
            } finally {
                canonicalVoteCarrier?.fill(0);
                cachedVoteCarrier?.fill(0);
                readVoteCarrier?.fill(0);
                if (durableBindingIdentifier !== undefined) {
                    const binding = foundationDurableStateBindings.get(
                        durableBindingIdentifier,
                    );
                    if (binding !== undefined) {
                        destroyFoundationCoordinate(
                            binding.expectedFreshnessCoordinate,
                        );
                        foundationDurableStateBindings.delete(
                            durableBindingIdentifier,
                        );
                    }
                }
                await requireFoundationWorkerKernel().releaseActionStateObject(
                    stateIntentIdentifier,
                );
                foundationStateObjectIdentifiers.delete(stateIntentIdentifier);
            }
        };

    const activateFoundationInitialization = async (
        batchIdentifier: string,
        expectedOpeningMode: 'fresh-provisioned' | 'recovered',
    ): Promise<WorkerActivatedFoundationInitializationResult> => {
        await closePendingFoundationRollbackResources();
        const batch =
            foundationOperationInitializationBatches.get(batchIdentifier);
        if (batch === undefined || batch.openingMode !== expectedOpeningMode) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'The requested foundation initialization batch is unavailable or has the wrong lifecycle.',
            );
        }
        const runtime = requireFoundationWitnessRuntime();
        const foundationCustody = requireOwnedCustody();
        const before = copyFoundationFreshnessCoordinate(
            await foundationCustody.authenticateFoundationHead(),
        );
        if (
            !foundationCoordinatesEqual(
                before,
                batch.initialization.freshnessCoordinate,
            )
        ) {
            destroyFoundationCoordinate(before);
            throw new BrowserActionStorageCustodyError(
                'Conflict',
                'The foundation initialization batch is stale for the authenticated storage head.',
            );
        }
        const openedRoles: Array<
            Readonly<{
                identifier: string;
                role: WorkerFoundationNormalWitnessRole;
            }>
        > = [];
        const openedRoleIdentifiers = new Set<string>();
        let after: BrowserFoundationFreshnessCoordinate | undefined;
        try {
            for (const witnessRecord of batch.initialization
                .orderedWitnessRecords) {
                const identifier = issueFoundationInitializationBatchIdentifier(
                    openedRoleIdentifiers,
                );
                openedRoleIdentifiers.add(identifier);
                const cryptography = await runtime.openWitnessCryptography({
                    canonicalRosterBytes: batch.canonicalRosterBytes.slice(),
                });
                const retainedWitnessRecord =
                    copyFoundationWitnessRecord(witnessRecord);
                let openedRole: WebLockOwnedFoundationWitnessRole;
                try {
                    openedRole =
                        await foundationCustody.openFoundationWitnessRole({
                            durableStateLimits: runtime.durableStateLimits,
                            openingMode: batch.openingMode,
                            record: retainedWitnessRecord,
                        });
                } catch (error) {
                    destroyFoundationWitnessRecord(retainedWitnessRecord);
                    throw error;
                }
                let durableStateService: DurableStateWitnessService | undefined;
                try {
                    durableStateService =
                        openedRole.durableStateService.claimExclusiveOwner();
                } catch (error) {
                    foundationTransferableWitnessServicesPendingCleanup.add(
                        openedRole.durableStateService,
                    );
                    try {
                        await openedRole.durableStateService.close();
                        foundationTransferableWitnessServicesPendingCleanup.delete(
                            openedRole.durableStateService,
                        );
                    } catch (cleanupError) {
                        destroyFoundationWitnessRecord(retainedWitnessRecord);
                        throw new BrowserActionStorageCustodyError(
                            'OwnedWorkerFailure',
                            'Foundation witness ownership transfer and cleanup both failed.',
                            [error, cleanupError],
                        );
                    }
                    destroyFoundationWitnessRecord(retainedWitnessRecord);
                    throw error;
                }
                const role: WorkerFoundationNormalWitnessRole = Object.freeze({
                    durableStateService,
                    freshnessCoordinate:
                        copyFoundationFreshnessCoordinate(before),
                    record: retainedWitnessRecord,
                    stateObjectSignatureOperation:
                        cryptography.stateObjectSignatureOperation,
                });
                openedRoles.push({ identifier, role });
            }
            after = copyFoundationFreshnessCoordinate(
                await foundationCustody.authenticateFoundationHead(),
            );
            if (!foundationCoordinatesEqual(before, after)) {
                throw new BrowserActionStorageCustodyError(
                    'Conflict',
                    'Opening the foundation witness roles changed the authenticated storage head.',
                );
            }
            const actionRandomnessHandleIdentifier =
                issueFoundationInitializationBatchIdentifier(
                    openedRoleIdentifiers,
                );
            const activatedResult = Object.freeze({
                actionRandomnessHandleIdentifier,
                orderedWitnessRoleHandleIdentifiers: Object.freeze(
                    openedRoles.map((opened) => opened.identifier),
                ),
            });
            for (const opened of openedRoles) {
                foundationNormalWitnessRoles.set(
                    opened.identifier,
                    opened.role,
                );
            }
            foundationActionRandomnessHandles.set(
                actionRandomnessHandleIdentifier,
                Object.freeze({
                    actionRandomnessCommitment:
                        batch.initialization.actionRandomnessCommitment.slice(),
                    actionRandomnessSessionIdentifier:
                        batch.initialization.actionRandomnessSessionIdentifier,
                }),
            );
            foundationOperationInitializationBatches.delete(batchIdentifier);
            batch.canonicalRosterBytes.fill(0);
            batch.initialization.actionRandomnessCommitment.fill(0);
            destroyFoundationCoordinate(
                batch.initialization.freshnessCoordinate,
            );
            for (const witnessRecord of batch.initialization
                .orderedWitnessRecords) {
                destroyFoundationWitnessRecord(witnessRecord);
            }
            return activatedResult;
        } catch (error) {
            for (const opened of openedRoles) {
                foundationNormalWitnessRoles.delete(opened.identifier);
                foundationWitnessRolesPendingCleanup.add(opened.role);
            }
            const cleanupOutcomes = await Promise.allSettled(
                openedRoles.map(async (opened) => {
                    await closeFoundationNormalWitnessRole(opened.role);
                    foundationWitnessRolesPendingCleanup.delete(opened.role);
                }),
            );
            const cleanupFailures = cleanupOutcomes
                .filter(
                    (outcome): outcome is PromiseRejectedResult =>
                        outcome.status === 'rejected',
                )
                .map((outcome) => outcome.reason as unknown);
            if (cleanupFailures.length !== 0) {
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'Foundation activation and worker-owned cleanup both failed.',
                    [error, ...cleanupFailures],
                );
            }
            throw error;
        } finally {
            destroyFoundationCoordinate(before);
            if (after !== undefined) {
                destroyFoundationCoordinate(after);
            }
        }
    };

    const execute = async (
        request: CustodyWorkerRequest,
        copiedInput: unknown,
    ): Promise<unknown> => {
        switch (request.command) {
            case 'open-custody': {
                if (ownedCustody !== undefined) {
                    throw new BrowserActionStorageCustodyError(
                        'InvalidState',
                        'Browser action-storage custody is already open in this worker.',
                    );
                }
                const configuration =
                    copiedInput as BrowserActionStorageCustodyWorkerConfiguration;
                const acquisitionAbortController = new AbortController();
                openingCustodyAbortController = acquisitionAbortController;
                const opening =
                    input.openOwnedCustody === undefined
                        ? openWebLockOwnedBrowserActionStorageCustody({
                              acquisitionDeadlineEpochMilliseconds:
                                  configuration.acquisitionDeadlineEpochMilliseconds,
                              acquisitionSignal:
                                  acquisitionAbortController.signal,
                              binding: configuration.binding,
                              cryptoProvider: input.cryptoProvider,
                              databaseName: configuration.databaseName,
                              indexedDbFactory: input.indexedDbFactory,
                              keyRangeFactory: input.keyRangeFactory,
                              limits: configuration.limits,
                              lockManager: input.lockManager,
                              knownStorageRootCommitment:
                                  configuration.knownStorageRootCommitment,
                              namespace: configuration.namespace,
                              runtimeBuildManifestHash:
                                  configuration.runtimeBuildManifestHash,
                              workerKernel: input.workerKernel,
                          })
                        : input.openOwnedCustody(
                              configuration,
                              acquisitionAbortController.signal,
                          );
                openingCustody = opening;
                let openedCustody: WebLockOwnedBrowserActionStorageCustody;
                try {
                    openedCustody = await opening;
                } finally {
                    if (openingCustody === opening) {
                        openingCustody = undefined;
                    }
                    if (
                        openingCustodyAbortController ===
                        acquisitionAbortController
                    ) {
                        openingCustodyAbortController = undefined;
                    }
                }
                if (terminalFailure !== undefined) {
                    await openedCustody.close();
                    throw terminalFailure;
                }
                ownedCustody = openedCustody;
                return undefined;
            }
            case 'initialize':
                return custody().initialize();
            case 'current-snapshot':
                return custody().currentSnapshot();
            case 'open-root':
                if (ownedCustody === undefined) {
                    throw new BrowserActionStorageCustodyError(
                        'Closed',
                        'Browser foundation storage ownership is not open in this worker.',
                    );
                }
                await ownedCustody.openRootAndAuthenticatedStore(
                    copiedInput as {
                        expectedSnapshot: BrowserDeviceWrappingSnapshot;
                        untrustedExpectedCommitment: UntrustedExpectedStorageRootCommitment;
                    },
                );
                return undefined;
            case 'begin-checkpoint': {
                requireAvailableCheckpointHandleCapacity();
                const checkpointIdentifier =
                    issueFoundationInitializationBatchIdentifier();
                const store = await requireCheckpointStore();
                const identity = await store.beginOperation(
                    copiedInput as readonly Uint8Array[],
                );
                checkpoints.set(checkpointIdentifier, { identity });
                return { checkpointIdentifier };
            }
            case 'resume-checkpoint': {
                requireAvailableCheckpointHandleCapacity();
                const resumeInput = copiedInput as {
                    checkpointLineageIdentifier: Uint8Array;
                    expectedBoundary: ExpectedCheckpointBoundary;
                };
                requireAvailableCheckpointLineage(
                    resumeInput.checkpointLineageIdentifier,
                );
                const checkpointIdentifier =
                    issueFoundationInitializationBatchIdentifier();
                const store = await requireCheckpointStore();
                const resumed = await store.resume(resumeInput);
                checkpoints.set(checkpointIdentifier, {
                    identity: resumed.operationIdentity,
                    resumed,
                });
                return { checkpointIdentifier };
            }
            case 'copy-checkpoint-description': {
                const record = checkpoints.get(copiedInput as string);
                if (record === undefined) {
                    throw new BrowserActionStorageCustodyError(
                        'InvalidInput',
                        'The checkpoint handle is unavailable in this worker.',
                    );
                }
                return {
                    checkpointLineageIdentifier:
                        record.identity.checkpointLineageIdentifier,
                    ...(record.resumed === undefined
                        ? {}
                        : {
                              canonicalManifestBytes:
                                  record.resumed.canonicalManifestBytes,
                              stateStreamDescriptorBytes:
                                  record.resumed.stateStreamDescriptorBytes,
                          }),
                };
            }
            case 'begin-checkpoint-publication': {
                if (checkpointPublications.size >= 1) {
                    throw new BrowserActionStorageCustodyError(
                        'InvalidState',
                        'The worker already owns the maximum one active checkpoint publication.',
                    );
                }
                const publicationInput = copiedInput as {
                    boundary: CheckpointBoundary;
                    checkpointIdentifier: string;
                };
                const checkpoint = checkpoints.get(
                    publicationInput.checkpointIdentifier,
                );
                if (checkpoint === undefined) {
                    throw new BrowserActionStorageCustodyError(
                        'InvalidInput',
                        'The checkpoint handle is unavailable in this worker.',
                    );
                }
                const checkpointLineageKey = requireAvailableCheckpointLineage(
                    checkpoint.identity.checkpointLineageIdentifier,
                );
                const publicationIdentifier =
                    issueFoundationInitializationBatchIdentifier();
                const store = await requireCheckpointStore();
                const channel = new BoundedWorkerAsyncChannel<Uint8Array>();
                const publication = store.publish({
                    boundary: publicationInput.boundary,
                    identity: checkpoint.identity,
                    stateChunks: channel,
                });
                void publication.catch((error: unknown) => {
                    channel.fail(error);
                });
                checkpointPublications.set(publicationIdentifier, {
                    channel,
                    checkpointLineageKey,
                    publication,
                });
                return publicationIdentifier;
            }
            case 'write-checkpoint-publication-chunk': {
                const writeInput = copiedInput as {
                    chunk: Uint8Array;
                    publicationIdentifier: string;
                };
                const publication = checkpointPublications.get(
                    writeInput.publicationIdentifier,
                );
                if (publication === undefined) {
                    throw new BrowserActionStorageCustodyError(
                        'InvalidInput',
                        'The checkpoint publication is unavailable in this worker.',
                    );
                }
                await publication.channel.write(writeInput.chunk.slice());
                return undefined;
            }
            case 'commit-checkpoint-publication': {
                const identifier = copiedInput as string;
                const publication = checkpointPublications.get(identifier);
                if (publication === undefined) {
                    throw new BrowserActionStorageCustodyError(
                        'InvalidInput',
                        'The checkpoint publication is unavailable in this worker.',
                    );
                }
                publication.channel.finish();
                try {
                    return await publication.publication;
                } finally {
                    checkpointPublications.delete(identifier);
                }
            }
            case 'abort-checkpoint-publication': {
                const identifier = copiedInput as string;
                const publication = checkpointPublications.get(identifier);
                if (publication === undefined) {
                    return undefined;
                }
                const abortFailure = new BrowserActionStorageCustodyError(
                    'InvalidState',
                    'Checkpoint publication was aborted by its owner.',
                );
                publication.channel.fail(abortFailure);
                try {
                    await publication.publication;
                } catch (error) {
                    if (error !== abortFailure) {
                        throw error;
                    }
                } finally {
                    checkpointPublications.delete(identifier);
                }
                return undefined;
            }
            case 'abort-checkpoint-restore': {
                const identifier = copiedInput as string;
                const restore = checkpointRestores.get(identifier);
                if (restore === undefined) {
                    return undefined;
                }
                const abortFailure = new BrowserActionStorageCustodyError(
                    'InvalidState',
                    'Checkpoint restore was aborted by its owner.',
                );
                restore.channel.fail(abortFailure);
                try {
                    await restore.restoration;
                } catch (error) {
                    if (error !== abortFailure) {
                        throw error;
                    }
                } finally {
                    checkpointRestores.delete(identifier);
                }
                return undefined;
            }
            case 'evict-checkpoint': {
                const identifier = copiedInput as string;
                const checkpoint = checkpoints.get(identifier);
                if (checkpoint === undefined) {
                    throw new BrowserActionStorageCustodyError(
                        'InvalidInput',
                        'The checkpoint handle is unavailable in this worker.',
                    );
                }
                requireAvailableCheckpointLineage(
                    checkpoint.identity.checkpointLineageIdentifier,
                );
                const store = await requireCheckpointStore();
                await store.evict(
                    checkpoint.identity.checkpointLineageIdentifier,
                );
                await store.releaseOperationIdentity(checkpoint.identity);
                checkpoints.delete(identifier);
                return undefined;
            }
            case 'begin-checkpoint-restore': {
                if (checkpointRestores.size >= 1) {
                    throw new BrowserActionStorageCustodyError(
                        'InvalidState',
                        'The worker already owns the maximum one active checkpoint restore.',
                    );
                }
                const checkpoint = checkpoints.get(copiedInput as string);
                if (checkpoint?.resumed === undefined) {
                    throw new BrowserActionStorageCustodyError(
                        'InvalidInput',
                        'Checkpoint restore requires a resumed checkpoint handle.',
                    );
                }
                const checkpointLineageKey = requireAvailableCheckpointLineage(
                    checkpoint.identity.checkpointLineageIdentifier,
                );
                const restoreIdentifier =
                    issueFoundationInitializationBatchIdentifier();
                const channel = new BoundedWorkerAsyncChannel<
                    Readonly<{ chunkBytes: Uint8Array; chunkIndex: number }>
                >();
                const restoration = checkpoint.resumed
                    .restoreState((chunkIndex, chunkBytes) =>
                        channel.write({
                            chunkBytes: chunkBytes.slice(),
                            chunkIndex,
                        }),
                    )
                    .then(
                        () => channel.finish(),
                        (error) => {
                            channel.fail(error);
                            throw error;
                        },
                    );
                void restoration.catch(() => undefined);
                checkpointRestores.set(restoreIdentifier, {
                    channel,
                    checkpointLineageKey,
                    restoration,
                });
                return restoreIdentifier;
            }
            case 'read-checkpoint-restore-chunk': {
                const identifier = copiedInput as string;
                const restore = checkpointRestores.get(identifier);
                if (restore === undefined) {
                    throw new BrowserActionStorageCustodyError(
                        'InvalidInput',
                        'The checkpoint restore is unavailable in this worker.',
                    );
                }
                const next = await restore.channel.read();
                if (next.done) {
                    try {
                        await restore.restoration;
                    } finally {
                        checkpointRestores.delete(identifier);
                    }
                    return { done: true };
                }
                return {
                    chunkBytes: next.value.chunkBytes,
                    chunkIndex: next.value.chunkIndex,
                    done: false,
                };
            }
            case 'derive-record-identifier':
                return custody().deriveLocalRecordIdentifier(
                    copiedInput as BrowserLocalRecordIdentifierInput,
                );
            case 'seal-record':
                return custody().sealLocalRecord(
                    copiedInput as BrowserLocalRecordSealInput,
                );
            case 'open-record':
                return custody().openLocalRecord(
                    copiedInput as BrowserLocalRecordOpenInput,
                );
            case 'hash-record-envelope':
                return custody().hashLocalRecordEnvelope(
                    copiedInput as Uint8Array,
                );
            case 'commit-fresh-foundation-initialization': {
                await closePendingFoundationRollbackResources();
                const batchIdentifier =
                    issueFoundationInitializationBatchIdentifier();
                const committed =
                    await requireOwnedCustody().commitFreshFoundationInitialization(
                        copiedInput as BrowserFoundationInitializationPreparationInput,
                    );
                committedFoundationInitializationBatches.set(
                    batchIdentifier,
                    committed,
                );
                return Object.freeze({
                    batchIdentifier,
                    freshnessCoordinate: committed.freshnessCoordinate,
                });
            }
            case 'commit-foundation-operation-initialization': {
                await closePendingFoundationRollbackResources();
                const foundationCustody = requireOwnedCustody();
                const initializationInput =
                    copiedInput as BrowserFoundationInitializationInput;
                const batchIdentifier =
                    issueFoundationInitializationBatchIdentifier();
                const committed =
                    await foundationCustody.commitFreshFoundationInitialization(
                        initializationInput,
                    );
                const cleanupOwner: WorkerFoundationInitializationCleanupOwner =
                    {
                        initialization: committed,
                    };
                foundationInitializationsPendingCleanup.add(cleanupOwner);
                try {
                    if (
                        committed.orderedWitnessRecords.length !==
                        foundationProfile.participantCount - 1
                    ) {
                        throw new BrowserActionStorageCustodyError(
                            'OwnedWorkerFailure',
                            'The worker-owned foundation commit did not retain the exact fixed-roster witness set.',
                        );
                    }
                    const canonicalRosterBytes =
                        initializationInput.canonicalRosterBytes.slice();
                    cleanupOwner.canonicalRosterBytes = canonicalRosterBytes;
                    foundationOperationInitializationBatches.set(
                        batchIdentifier,
                        Object.freeze({
                            canonicalRosterBytes,
                            initialization: committed,
                            openingMode: 'fresh-provisioned',
                        }),
                    );
                    foundationInitializationsPendingCleanup.delete(
                        cleanupOwner,
                    );
                    return Object.freeze({
                        batchIdentifier,
                        freshnessCoordinate: committed.freshnessCoordinate,
                    });
                } catch (error) {
                    foundationOperationInitializationBatches.delete(
                        batchIdentifier,
                    );
                    return failFoundationInitializationRetention(
                        cleanupOwner,
                        error,
                        'Foundation commit retention and worker-owned cleanup both failed.',
                    );
                }
            }
            case 'open-recovered-foundation-initialization': {
                await closePendingFoundationRollbackResources();
                const initializationInput =
                    copiedInput as BrowserFoundationInitializationInput;
                const batchIdentifier =
                    issueFoundationInitializationBatchIdentifier();
                const recovered =
                    await requireOwnedCustody().openRecoveredFoundationInitialization(
                        initializationInput,
                    );
                const cleanupOwner: WorkerFoundationInitializationCleanupOwner =
                    {
                        initialization: recovered,
                    };
                foundationInitializationsPendingCleanup.add(cleanupOwner);
                try {
                    if (
                        recovered.orderedWitnessRecords.length !==
                        foundationProfile.participantCount - 1
                    ) {
                        throw new BrowserActionStorageCustodyError(
                            'OwnedWorkerFailure',
                            'Recovered foundation initialization did not retain the exact fixed-roster witness set.',
                        );
                    }
                    const canonicalRosterBytes =
                        initializationInput.canonicalRosterBytes.slice();
                    cleanupOwner.canonicalRosterBytes = canonicalRosterBytes;
                    foundationOperationInitializationBatches.set(
                        batchIdentifier,
                        Object.freeze({
                            canonicalRosterBytes,
                            initialization: recovered,
                            openingMode: 'recovered',
                        }),
                    );
                    foundationInitializationsPendingCleanup.delete(
                        cleanupOwner,
                    );
                    return Object.freeze({
                        batchIdentifier,
                        freshnessCoordinate: recovered.freshnessCoordinate,
                    });
                } catch (error) {
                    foundationOperationInitializationBatches.delete(
                        batchIdentifier,
                    );
                    return failFoundationInitializationRetention(
                        cleanupOwner,
                        error,
                        'Recovered foundation retention and worker-owned cleanup both failed.',
                    );
                }
            }
            case 'activate-fresh-foundation-initialization':
                return activateFoundationInitialization(
                    copiedInput as string,
                    'fresh-provisioned',
                );
            case 'activate-recovered-foundation-initialization':
                return activateFoundationInitialization(
                    copiedInput as string,
                    'recovered',
                );
            case 'copy-foundation-witness-subject':
                return requireFoundationNormalWitnessRole(
                    copiedInput as string,
                ).record.subjectParticipantIdentity.slice();
            case 'open-foundation-witness-durable-binding': {
                const bindingInput = copiedInput as {
                    stateObjectIdentifier: string;
                    witnessRoleIdentifier: string;
                };
                return openFoundationWitnessDurableBinding(
                    bindingInput.witnessRoleIdentifier,
                    bindingInput.stateObjectIdentifier,
                );
            }
            case 'close-foundation-witness-durable-binding': {
                const identifier = copiedInput as string;
                const binding = foundationDurableStateBindings.get(identifier);
                if (binding !== undefined) {
                    destroyFoundationCoordinate(
                        binding.expectedFreshnessCoordinate,
                    );
                    foundationDurableStateBindings.delete(identifier);
                }
                return undefined;
            }
            case 'compare-and-lock-foundation-witness-intent': {
                const operationInput = copiedInput as {
                    durableBindingIdentifier: string;
                    witnessRoleIdentifier: string;
                };
                return runFoundationWitnessMutation({
                    ...operationInput,
                    operation: (role, binding) =>
                        role.durableStateService.compareAndLockIntent({
                            verifiedIntentBinding: binding,
                        }),
                });
            }
            case 'cache-foundation-witness-signed-vote-carrier': {
                const operationInput = copiedInput as {
                    durableBindingIdentifier: string;
                    value: Uint8Array;
                    witnessRoleIdentifier: string;
                };
                return runFoundationWitnessMutation({
                    ...operationInput,
                    operation: (role, binding) =>
                        role.durableStateService.cacheSignedVoteCarrier({
                            canonicalSignedVoteCarrier: operationInput.value,
                            verifiedIntentBinding: binding,
                        }),
                });
            }
            case 'read-foundation-witness-signed-vote-carrier': {
                const operationInput = copiedInput as {
                    durableBindingIdentifier: string;
                    witnessRoleIdentifier: string;
                };
                return runFoundationWitnessRead({
                    ...operationInput,
                    operation: (role, binding) =>
                        role.durableStateService.readSignedVoteCarrier({
                            verifiedIntentBinding: binding,
                        }),
                });
            }
            case 'cache-foundation-witness-exact-output': {
                const operationInput = copiedInput as {
                    durableBindingIdentifier: string;
                    value: Uint8Array;
                    witnessRoleIdentifier: string;
                };
                return runFoundationWitnessMutation({
                    ...operationInput,
                    operation: (role, binding) =>
                        role.durableStateService.cacheExactOutput({
                            exactOutputBytes: operationInput.value,
                            verifiedOutputBinding: binding,
                        }),
                });
            }
            case 'read-foundation-witness-exact-output': {
                const operationInput = copiedInput as {
                    durableBindingIdentifier: string;
                    witnessRoleIdentifier: string;
                };
                return runFoundationWitnessRead({
                    ...operationInput,
                    operation: (role, binding) =>
                        role.durableStateService.readExactOutput({
                            verifiedOutputBinding: binding,
                        }),
                });
            }
            case 'authenticate-foundation-head': {
                if (ownedCustody === undefined) {
                    throw new BrowserActionStorageCustodyError(
                        'Closed',
                        'Browser foundation storage ownership is not open in this worker.',
                    );
                }
                return ownedCustody.authenticateFoundationHead();
            }
            case 'open-state-verifier-session':
                return custody().openActionStateVerifierSession(
                    copiedInput as BrowserActionStateVerifierSessionInput,
                );
            case 'verify-state-reservation':
                return custody().verifyActionStateReservation(
                    copiedInput as BrowserActionStateReservationVerificationInput,
                );
            case 'verify-action-randomness-reservation':
                return custody().verifyActionRandomnessReservation(
                    copiedInput as BrowserActionRandomnessReservationVerificationInput,
                );
            case 'produce-foundation-action-randomness-reservation-intent': {
                const productionInput = copiedInput as {
                    actionRandomnessHandleIdentifier: string;
                    stateVerifierSessionIdentifier: string;
                };
                const handle = foundationActionRandomnessHandles.get(
                    productionInput.actionRandomnessHandleIdentifier,
                );
                if (handle === undefined) {
                    throw new BrowserActionStorageCustodyError(
                        'InvalidInput',
                        'The foundation action-randomness handle is unavailable in this worker.',
                    );
                }
                const produced =
                    await produceClosedWorkerActionRandomnessReservationIntent(
                        requireFoundationWorkerKernel(),
                        {
                            actionRandomnessSessionIdentifier:
                                handle.actionRandomnessSessionIdentifier,
                            signatureOperation:
                                requireFoundationStateObjectSignatureOperation(),
                            stateVerifierSessionIdentifier:
                                productionInput.stateVerifierSessionIdentifier,
                        },
                    );
                if (produced.isValid) {
                    foundationStateObjectIdentifiers.add(
                        produced.value.stateIntentIdentifier,
                    );
                }
                return produced;
            }
            case 'vote-for-foundation-action-randomness-reservation-intent':
                return voteForFoundationActionRandomnessReservationIntent(
                    copiedInput as {
                        canonicalReservationIntentCarrier: Uint8Array;
                        stateVerifierSessionIdentifier: string;
                        subjectParticipantIdentity: Uint8Array;
                        witnessRoleIdentifier: string;
                    },
                );
            case 'certify-foundation-action-randomness-reservation': {
                const certificationInput = copiedInput as {
                    stateIntentIdentifier: string;
                    untrustedVoteCarriers: readonly Uint8Array[];
                };
                if (
                    !foundationStateObjectIdentifiers.has(
                        certificationInput.stateIntentIdentifier,
                    )
                ) {
                    throw new BrowserActionStorageCustodyError(
                        'InvalidInput',
                        'The foundation state reservation intent is unavailable in this worker.',
                    );
                }
                const produced =
                    await certifyClosedWorkerActionRandomnessReservation(
                        requireFoundationWorkerKernel(),
                        certificationInput,
                    );
                if (produced.isValid) {
                    foundationStateObjectIdentifiers.delete(
                        certificationInput.stateIntentIdentifier,
                    );
                    foundationStateObjectIdentifiers.add(
                        produced.value.stateReservationIdentifier,
                    );
                }
                return produced;
            }
            case 'verify-foundation-action-randomness-reservation': {
                const verificationInput = copiedInput as {
                    actionRandomnessHandleIdentifier: string;
                    verificationInput: BrowserActionRandomnessReservationVerificationInput;
                };
                const handle = foundationActionRandomnessHandles.get(
                    verificationInput.actionRandomnessHandleIdentifier,
                );
                if (handle === undefined) {
                    throw new BrowserActionStorageCustodyError(
                        'InvalidInput',
                        'The foundation action-randomness handle is unavailable in this worker.',
                    );
                }
                return custody().verifyActionRandomnessReservation({
                    ...verificationInput.verificationInput,
                    actionRandomnessSessionIdentifier:
                        handle.actionRandomnessSessionIdentifier,
                });
            }
            case 'release-state-object': {
                const stateObjectIdentifier = copiedInput as string;
                for (const [
                    identifier,
                    binding,
                ] of foundationDurableStateBindings) {
                    if (
                        binding.stateObjectIdentifier !== stateObjectIdentifier
                    ) {
                        continue;
                    }
                    destroyFoundationCoordinate(
                        binding.expectedFreshnessCoordinate,
                    );
                    foundationDurableStateBindings.delete(identifier);
                }
                await custody().releaseActionStateObject(stateObjectIdentifier);
                foundationStateObjectIdentifiers.delete(stateObjectIdentifier);
                return undefined;
            }
            case 'release-foundation-state-reservation-intent': {
                const stateObjectIdentifier = copiedInput as string;
                if (
                    !foundationStateObjectIdentifiers.has(stateObjectIdentifier)
                ) {
                    return undefined;
                }
                await requireFoundationWorkerKernel().releaseActionStateObject(
                    stateObjectIdentifier,
                );
                foundationStateObjectIdentifiers.delete(stateObjectIdentifier);
                return undefined;
            }
            case 'close-state-verifier-session':
                return custody().closeActionStateVerifierSession(
                    copiedInput as string,
                );
            case 'create-and-seal-action-randomness':
                return custody().createAndSealActionRandomness(
                    copiedInput as BrowserActionRandomnessRecordContext,
                );
            case 'open-sealed-action-randomness':
                return custody().openSealedActionRandomness(
                    copiedInput as BrowserActionRandomnessRecordContext &
                        Readonly<{
                            actionRandomnessCommitment: Uint8Array;
                            canonicalEnvelope: Uint8Array;
                        }>,
                );
            case 'close-action-randomness':
                return custody().closeActionRandomness(copiedInput as string);
            case 'close-foundation-action-randomness': {
                const identifier = copiedInput as string;
                const handle =
                    foundationActionRandomnessHandles.get(identifier);
                if (handle === undefined) {
                    return undefined;
                }
                const closureFailures: unknown[] = [];
                for (const preparedOperation of commonProofPreparedOperations) {
                    const preparedRecord =
                        installedCommonProofPreparedOperationRecords.get(
                            preparedOperation,
                        );
                    if (
                        preparedRecord?.foundationActionRandomnessHandleIdentifier ===
                        identifier
                    ) {
                        try {
                            retirePreparedCommonProofOperation(
                                preparedOperation,
                            );
                        } catch (error) {
                            closureFailures.push(error);
                        }
                    }
                }
                const associatedEnvironments = [
                    ...commonProofExecutionEnvironments,
                ].filter((environment) => {
                    const record =
                        installedCommonProofExecutionEnvironmentRecords.get(
                            environment,
                        );
                    return (
                        record !== undefined &&
                        record.foundationActionRandomnessHandleIdentifier ===
                            identifier
                    );
                });
                const closureOutcomes = await Promise.allSettled(
                    associatedEnvironments.map(async (environment) => {
                        const record =
                            installedCommonProofExecutionEnvironmentRecords.get(
                                environment,
                            );
                        if (record === undefined) {
                            return;
                        }
                        await retireInstalledCommonProofExecutionEnvironment(
                            environment,
                            record,
                        );
                    }),
                );
                closureFailures.push(
                    ...closureOutcomes
                        .filter(
                            (outcome): outcome is PromiseRejectedResult =>
                                outcome.status === 'rejected',
                        )
                        .map((outcome) => outcome.reason as unknown),
                );
                if (closureFailures.length !== 0) {
                    throw new BrowserActionStorageCustodyError(
                        'OwnedWorkerFailure',
                        'Closing foundation action randomness could not retire every common-proof operation and environment.',
                        closureFailures,
                    );
                }
                await custody().closeActionRandomness(
                    handle.actionRandomnessSessionIdentifier,
                );
                foundationActionRandomnessHandles.delete(identifier);
                handle.actionRandomnessCommitment.fill(0);
                return undefined;
            }
            case 'derive-target-release-attempt':
                return custody().deriveTargetReleaseAttempt(
                    copiedInput as BrowserTargetReleaseAttemptInput,
                );
            case 'derive-foundation-target-release-attempt': {
                const attemptInput = copiedInput as {
                    actionRandomnessHandleIdentifier: string;
                    attemptInput: BrowserTargetReleaseAttemptInput;
                };
                const handle = foundationActionRandomnessHandles.get(
                    attemptInput.actionRandomnessHandleIdentifier,
                );
                if (handle === undefined) {
                    throw new BrowserActionStorageCustodyError(
                        'InvalidInput',
                        'The foundation action-randomness handle is unavailable in this worker.',
                    );
                }
                return custody().deriveTargetReleaseAttempt({
                    ...attemptInput.attemptInput,
                    actionRandomnessSessionIdentifier:
                        handle.actionRandomnessSessionIdentifier,
                });
            }
            case 'delete':
                return custody().delete(
                    copiedInput as BrowserDeviceWrappingSnapshot,
                );
            case 'retire': {
                await closeFoundationOperationResources();
                await closeCheckpointResources();
                await requireOwnedCustody().retire();
                return undefined;
            }
            case 'close': {
                const handle = ownedCustody;
                await closeCheckpointResources();
                await closeFoundationOperationResources();
                if (handle !== undefined) {
                    await handle.close();
                    if (ownedCustody === handle) {
                        ownedCustody = undefined;
                    }
                }
                return undefined;
            }
        }
    };

    const handleRequest = async (
        request: CustodyWorkerRequest,
    ): Promise<void> => {
        if (terminalFailure !== undefined) {
            return;
        }
        let copiedInput: unknown;
        try {
            copiedInput = copyHostCommandInput(request.command, request.input);
        } catch (error) {
            failHost(error);
            return;
        }
        let result: unknown;
        try {
            result = await execute(request, copiedInput);
        } catch (error) {
            if (terminalFailure !== undefined) {
                return;
            }
            try {
                input.workerScope.postMessage({
                    errorCode: normalizeHostErrorCode(error),
                    errorMessage: describeHostError(error),
                    messageKind: 'browser-action-storage-custody-failed',
                    requestIdentifier: request.requestIdentifier,
                });
            } catch (postError) {
                failHost([error, postError]);
            }
            return;
        } finally {
            destroyHostLocalRecordCommandInput(request.command, copiedInput);
        }
        if (terminalFailure !== undefined) {
            destroyHostLocalRecordCommandResult(request.command, result);
            return;
        }
        let copiedResult: unknown;
        try {
            copiedResult = copyHostCommandResult(request.command, result);
        } catch (error) {
            failHost(error);
            return;
        } finally {
            destroyHostLocalRecordCommandResult(request.command, result);
        }
        try {
            input.workerScope.postMessage({
                messageKind: 'browser-action-storage-custody-completed',
                requestIdentifier: request.requestIdentifier,
                result: copiedResult,
            });
        } catch (error) {
            failHost(error);
        } finally {
            destroyHostLocalRecordCommandResult(request.command, copiedResult);
        }
    };

    const listener = (event: MessageEvent<unknown>): void => {
        if (uninstalled) {
            return;
        }
        const request = event.data;
        if (
            !isCustodyWorkerRequest(request) ||
            request.requestIdentifier <= lastRequestIdentifier
        ) {
            failHost(
                new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'The browser action-storage worker received a malformed, duplicate, or nonmonotonic request.',
                ),
            );
            return;
        }
        lastRequestIdentifier = request.requestIdentifier;
        operationTail = operationTail.then(
            () => handleRequest(request),
            () => handleRequest(request),
        );
    };

    listenerHolder.value = listener;
    input.workerScope.addEventListener('message', listener);

    const uninstall = async (): Promise<void> => {
        if (!uninstalled) {
            uninstalled = true;
            input.workerScope.removeEventListener('message', listener);
        }
        terminalCleanup ??= (async () => {
            await operationTail;
            const handle = ownedCustody;
            await closeCheckpointResources();
            await closeFoundationOperationResources();
            if (handle !== undefined) {
                await handle.close();
                ownedCustody = undefined;
            }
        })();
        try {
            await terminalCleanup;
        } catch (error) {
            terminalCleanup = undefined;
            throw error;
        }
    };
    installedCustodyWorkerHostCommonProofGenerationPreparers.set(
        uninstall,
        (preparationInput) => {
            if (uninstalled || terminalFailure !== undefined) {
                throw (
                    terminalFailure ??
                    new BrowserActionStorageCustodyError(
                        'Closed',
                        'The custody worker host is no longer available for common-proof preparation.',
                    )
                );
            }
            if (
                commonProofPreparedOperations.size +
                    commonProofExecutionEnvironments.size >=
                1
            ) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidState',
                    'The installed worker already owns the maximum one common-proof preparation or execution chain.',
                );
            }
            const foundationActionRandomnessHandleIdentifier =
                copyOpaqueWorkerIdentifier(
                    preparationInput.foundationActionRandomnessHandleIdentifier,
                    'Foundation action-randomness handle identifier',
                );
            if (
                !foundationActionRandomnessHandles.has(
                    foundationActionRandomnessHandleIdentifier,
                )
            ) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'The foundation action-randomness handle is unavailable for common-proof preparation.',
                );
            }
            const description =
                describeClosedWorkerCommonProofGenerationFamilyAdapter(
                    preparationInput.generationFamilyAdapter,
                );
            try {
                const preparedOperation = Object.freeze({
                    [installedCommonProofPreparedOperationBrand]: true as const,
                });
                installedCommonProofPreparedOperationRecords.set(
                    preparedOperation,
                    {
                        commonProofRuntimeBindingHash:
                            description.commonProofRuntimeBindingHash,
                        commonProofVerificationBindingHash:
                            description.commonProofVerificationBindingHash,
                        consumed: false,
                        foundationActionRandomnessHandleIdentifier,
                        generationFamilyAdapter:
                            preparationInput.generationFamilyAdapter,
                        installedHost: uninstall,
                        proofAttemptLineageIdentifier:
                            description.proofAttemptLineageIdentifier,
                    },
                );
                commonProofPreparedOperations.add(preparedOperation);
                return preparedOperation;
            } catch (error) {
                description.commonProofRuntimeBindingHash.fill(0);
                description.commonProofVerificationBindingHash.fill(0);
                description.proofAttemptLineageIdentifier.fill(0);
                throw error;
            }
        },
    );
    installedCustodyWorkerHostCommonProofEnvironmentOpeners.set(
        uninstall,
        (environmentInput) => {
            if (uninstalled || terminalFailure !== undefined) {
                return Promise.reject(
                    terminalFailure ??
                        new BrowserActionStorageCustodyError(
                            'Closed',
                            'The custody worker host is no longer available for common-proof execution.',
                        ),
                );
            }
            let copiedRuntimeBindingHash = new Uint8Array(0);
            let copiedVerificationBindingHash = new Uint8Array(0);
            let copiedProofAttemptLineageIdentifier = new Uint8Array(0);
            let generationFamilyAdapter:
                | ClosedWorkerCommonProofGenerationFamilyAdapter
                | undefined;
            let copiedResumeDescriptor:
                | CommonProofCheckpointResumeDescriptor
                | undefined;
            let copiedInput: ResolvedInstalledCommonProofExecutionEnvironmentInput;
            const preparedRecord =
                installedCommonProofPreparedOperationRecords.get(
                    environmentInput.preparedOperation,
                );
            try {
                if (
                    preparedRecord === undefined ||
                    preparedRecord.installedHost !== uninstall ||
                    preparedRecord.consumed ||
                    preparedRecord.generationFamilyAdapter === undefined ||
                    !foundationActionRandomnessHandles.has(
                        preparedRecord.foundationActionRandomnessHandleIdentifier,
                    )
                ) {
                    throw new BrowserActionStorageCustodyError(
                        'InvalidInput',
                        'The common-proof prepared operation is unavailable in this worker.',
                    );
                }
                preparedRecord.consumed = true;
                copiedRuntimeBindingHash = Uint8Array.from(
                    copyBytes(
                        preparedRecord.commonProofRuntimeBindingHash,
                        storageRootCommitmentByteLength,
                        'Common-proof runtime-binding hash',
                    ),
                );
                copiedVerificationBindingHash = Uint8Array.from(
                    copyBytes(
                        preparedRecord.commonProofVerificationBindingHash,
                        storageRootCommitmentByteLength,
                        'Common-proof verification-binding hash',
                    ),
                );
                copiedProofAttemptLineageIdentifier = Uint8Array.from(
                    copyBytes(
                        preparedRecord.proofAttemptLineageIdentifier,
                        mutationIdentifierByteLength,
                        'Proof-attempt lineage identifier',
                    ),
                );
                copiedResumeDescriptor =
                    environmentInput.resumeDescriptor === undefined
                        ? undefined
                        : copyCommonProofCheckpointResumeDescriptorForWorker(
                              environmentInput.resumeDescriptor,
                          );
                generationFamilyAdapter =
                    preparedRecord.generationFamilyAdapter;
                preparedRecord.generationFamilyAdapter = undefined;
                copiedInput = Object.freeze({
                    commonProofRuntimeBindingHash: copiedRuntimeBindingHash,
                    commonProofVerificationBindingHash:
                        copiedVerificationBindingHash,
                    foundationActionRandomnessHandleIdentifier:
                        preparedRecord.foundationActionRandomnessHandleIdentifier,
                    generationFamilyAdapter,
                    proofAttemptLineageIdentifier:
                        copiedProofAttemptLineageIdentifier,
                    ...(copiedResumeDescriptor === undefined
                        ? {}
                        : { resumeDescriptor: copiedResumeDescriptor }),
                });
            } catch (error) {
                copiedRuntimeBindingHash.fill(0);
                copiedVerificationBindingHash.fill(0);
                copiedProofAttemptLineageIdentifier.fill(0);
                destroyCommonProofCheckpointResumeDescriptor(
                    copiedResumeDescriptor,
                );
                let cleanupFailure: unknown;
                if (
                    preparedRecord !== undefined &&
                    preparedRecord.installedHost === uninstall &&
                    preparedRecord.consumed
                ) {
                    if (
                        generationFamilyAdapter !== undefined &&
                        preparedRecord.generationFamilyAdapter === undefined
                    ) {
                        preparedRecord.generationFamilyAdapter =
                            generationFamilyAdapter;
                    }
                    try {
                        retirePreparedCommonProofOperation(
                            environmentInput.preparedOperation,
                        );
                    } catch (cleanupError) {
                        cleanupFailure = cleanupError;
                    }
                } else if (generationFamilyAdapter !== undefined) {
                    try {
                        releaseClosedWorkerCommonProofGenerationFamilyAdapter(
                            generationFamilyAdapter,
                        );
                    } catch (cleanupError) {
                        cleanupFailure = cleanupError;
                    }
                }
                const inputError =
                    error instanceof Error
                        ? error
                        : new BrowserActionStorageCustodyError(
                              'InvalidInput',
                              'The common-proof environment input is malformed.',
                              error,
                          );
                if (cleanupFailure !== undefined) {
                    return Promise.reject(
                        new BrowserActionStorageCustodyError(
                            'OwnedWorkerFailure',
                            'The common-proof environment input failed and its prepared generation authority remains retained for cleanup retry.',
                            [inputError, cleanupFailure],
                        ),
                    );
                }
                return Promise.reject(inputError);
            }
            let generationFamilyAdapterOwnedByEnvironment = false;
            const result = operationTail.then(
                async () => {
                    const actionRandomnessHandle =
                        foundationActionRandomnessHandles.get(
                            copiedInput.foundationActionRandomnessHandleIdentifier,
                        );
                    if (actionRandomnessHandle === undefined) {
                        throw new BrowserActionStorageCustodyError(
                            'InvalidInput',
                            'The foundation action-randomness handle is unavailable for common-proof execution.',
                        );
                    }
                    const cryptoProvider =
                        input.cryptoProvider ?? globalThis.crypto;
                    if (
                        copiedInput.resumeDescriptor === undefined &&
                        cryptoProvider?.getRandomValues === undefined
                    ) {
                        throw new BrowserActionStorageCustodyError(
                            'Unavailable',
                            'Secure randomness is unavailable for a common-proof environment identifier.',
                        );
                    }
                    const commonProofEnvironmentIdentifier =
                        copiedInput.resumeDescriptor === undefined
                            ? new Uint8Array(mutationIdentifierByteLength)
                            : copiedInput.resumeDescriptor.commonProofEnvironmentIdentifier.slice();
                    let commonProofCustody: CommonProofBrowserCustody;
                    try {
                        if (copiedInput.resumeDescriptor === undefined) {
                            cryptoProvider.getRandomValues(
                                commonProofEnvironmentIdentifier,
                            );
                        }
                        const owned = requireOwnedCustody();
                        if (
                            input.checkpointStore === undefined ||
                            owned.openCommonProofCustody === undefined
                        ) {
                            throw new BrowserActionStorageCustodyError(
                                'Unavailable',
                                'The installed worker does not provide common-proof checkpoint and execution custody.',
                            );
                        }
                        commonProofCustody = await owned.openCommonProofCustody(
                            {
                                actionRandomnessCommitment:
                                    actionRandomnessHandle.actionRandomnessCommitment.slice(),
                                checkpoint: {
                                    cursorKernel:
                                        input.checkpointStore.cursorKernel,
                                    ...(copiedInput.resumeDescriptor ===
                                    undefined
                                        ? {}
                                        : {
                                              resumeDescriptor:
                                                  copiedInput.resumeDescriptor,
                                          }),
                                    store: await requireCheckpointStore(),
                                },
                                commonProofEnvironmentIdentifier,
                                commonProofRuntimeBindingHash:
                                    copiedInput.commonProofRuntimeBindingHash,
                                proofAttemptLineageIdentifier:
                                    copiedInput.proofAttemptLineageIdentifier,
                            },
                        );
                    } finally {
                        commonProofEnvironmentIdentifier.fill(0);
                    }
                    const environment = Object.freeze({
                        [installedCommonProofExecutionEnvironmentBrand]:
                            true as const,
                    });
                    const environmentRecord: InstalledCommonProofExecutionEnvironmentRecord =
                        {
                            applyVerifiedCommonProof:
                                runVerifiedCommonProofApplication,
                            assertDurableBindingCurrent:
                                assertCommonProofDurableBindingCurrent,
                            closed: false,
                            commonProofRuntimeBindingHash:
                                copiedInput.commonProofRuntimeBindingHash.slice(),
                            commonProofVerificationBindingHash:
                                copiedInput.commonProofVerificationBindingHash.slice(),
                            custody: commonProofCustody,
                            foundationActionRandomnessHandleIdentifier:
                                copiedInput.foundationActionRandomnessHandleIdentifier,
                            generationCompleted: false,
                            installedHost: uninstall,
                            operationActive: false,
                            generationFamilyAdapter:
                                copiedInput.generationFamilyAdapter,
                            proofAttemptLineageIdentifier:
                                copiedInput.proofAttemptLineageIdentifier.slice(),
                            refreshDurableBindingAfterControlledCleanup:
                                refreshCommonProofDurableBindingAfterControlledCleanup,
                            releaseOwnerReference: () => {
                                commonProofExecutionEnvironments.delete(
                                    environment,
                                );
                            },
                            resumedFromCheckpoint:
                                copiedInput.resumeDescriptor !== undefined,
                            runInHostQueue: <Result>(
                                operation: () => Promise<Result>,
                            ): Promise<Result> => {
                                const queuedResult = operationTail.then(
                                    operation,
                                    operation,
                                );
                                operationTail = queuedResult.then(
                                    () => undefined,
                                    () => undefined,
                                );
                                return queuedResult;
                            },
                            failAfterApplicationHandoff: failHost,
                            suspendedResumeDescriptor: undefined,
                            terminalCustodySettled: false,
                            terminalCleanupStarted: false,
                            verifiedCapability: undefined,
                        };
                    finishPreparedCommonProofOperationTransfer(
                        environmentInput.preparedOperation,
                        preparedRecord,
                    );
                    installedCommonProofExecutionEnvironmentRecords.set(
                        environment,
                        environmentRecord,
                    );
                    commonProofExecutionEnvironments.add(environment);
                    generationFamilyAdapterOwnedByEnvironment = true;
                    return environment;
                },
                () => {
                    throw (
                        terminalFailure ??
                        new BrowserActionStorageCustodyError(
                            'OwnedWorkerFailure',
                            'The installed custody worker operation queue failed before common-proof environment creation.',
                        )
                    );
                },
            );
            const resultWithDestroyedInput = result
                .catch((error: unknown) => {
                    if (!generationFamilyAdapterOwnedByEnvironment) {
                        let cleanupFailure: unknown;
                        const retainedPreparedRecord =
                            installedCommonProofPreparedOperationRecords.get(
                                environmentInput.preparedOperation,
                            );
                        if (retainedPreparedRecord === preparedRecord) {
                            if (
                                retainedPreparedRecord.generationFamilyAdapter ===
                                undefined
                            ) {
                                retainedPreparedRecord.generationFamilyAdapter =
                                    copiedInput.generationFamilyAdapter;
                            }
                            try {
                                retirePreparedCommonProofOperation(
                                    environmentInput.preparedOperation,
                                );
                            } catch (cleanupError) {
                                cleanupFailure = cleanupError;
                            }
                        } else {
                            try {
                                releaseClosedWorkerCommonProofGenerationFamilyAdapter(
                                    copiedInput.generationFamilyAdapter,
                                );
                            } catch (cleanupError) {
                                cleanupFailure = cleanupError;
                            }
                        }
                        if (cleanupFailure !== undefined) {
                            throw new BrowserActionStorageCustodyError(
                                'OwnedWorkerFailure',
                                'Opening common-proof execution custody failed and its generation authority remains retained for cleanup retry.',
                                [error, cleanupFailure],
                            );
                        }
                    }
                    throw error;
                })
                .finally(() => {
                    copiedInput.commonProofRuntimeBindingHash.fill(0);
                    copiedInput.commonProofVerificationBindingHash.fill(0);
                    copiedInput.proofAttemptLineageIdentifier.fill(0);
                    destroyCommonProofCheckpointResumeDescriptor(
                        copiedInput.resumeDescriptor,
                    );
                });
            operationTail = resultWithDestroyedInput.then(
                () => undefined,
                () => undefined,
            );
            return resultWithDestroyedInput;
        },
    );
    return uninstall;
};
