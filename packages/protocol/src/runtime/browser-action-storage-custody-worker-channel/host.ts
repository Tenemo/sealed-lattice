import {
    configurableParticipantCountRange,
    foundationProfile,
} from '@sealed-lattice/types';
import type {
    BrowserStateObjectSignatureOperation,
    BrowserFoundationInitializationPreparationInput,
} from '@sealed-lattice/types';
import {
    certifyClosedWorkerActionRandomnessReservation,
    copyVerifiedStateDurableBinding,
    describeClosedWorkerCommonProofGenerationFamilyAdapter,
    openClosedWorkerVerifiedStateDurableBinding,
    prepareClosedWorkerVerifiedCommonProofApplication,
    produceClosedWorkerActionRandomnessReservationIntent,
    produceClosedWorkerActionRandomnessReservationWitnessVote,
    releaseClosedWorkerCommonProofGenerationFamilyAdapter,
    type ClosedWorkerCommonProofGenerationFamilyAdapter,
    type VerifiedStateDurableBinding,
    verifyClosedWorkerActionRandomnessReservationIntentForWitness,
} from '@sealed-lattice/wasm';

import type {
    AuthenticatedCheckpointStore,
    AuthenticatedCheckpointStoreLimits,
    CheckpointBoundary,
    CheckpointBoundaryPolicy,
    CheckpointLineageReservation,
    CheckpointOperationIdentity,
    ExpectedCheckpointBoundary,
    ResumedCheckpoint,
} from '../authenticated-checkpoint-store.js';
import { bytesToHex } from '../authenticated-runtime-record.js';
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
} from '../browser-action-cryptography-validation.js';
import type { BrowserActionStorageWorkerKernel } from '../browser-action-storage-custody-internal.js';
import {
    BrowserActionStorageCustodyError,
    type BrowserActionRandomnessRecordContext,
    type BrowserActionRandomnessReservationVerificationInput,
    type BrowserActionStateReservationVerificationInput,
    type BrowserActionStateVerifierSessionInput,
    type BrowserTargetReleaseAttemptInput,
    type BrowserActionStorageCustody,
    type BrowserActionStorageCustodyErrorCode,
    type BrowserDeviceWrappingSnapshot,
    type BrowserFoundationFreshnessCoordinate,
    type BrowserLocalRecordIdentifierInput,
    type BrowserLocalRecordOpenInput,
    type BrowserLocalRecordSealInput,
    type UntrustedExpectedStorageRootCommitment,
    type VerificationResult,
} from '../browser-action-storage-custody.js';
import { copyBrowserFoundationInitializationPreparationInput } from '../browser-foundation-initialization.js';
import type { BrowserFoundationInitializationInput } from '../browser-foundation-operation-owner.js';
import {
    copyLocalRecordBytes,
    copyLocalRecordIdentifierInput,
    copyLocalRecordOpenInput,
    copyLocalRecordSealInput,
    destroyLocalRecordIdentifierInput,
    destroyLocalRecordOpenInput,
    destroyLocalRecordSealInput,
} from '../browser-local-record-validation.js';
import type {
    CommonProofBrowserCustody,
    CommonProofCheckpointResumeDescriptor,
} from '../common-proof-browser-custody.js';
import type {
    CommonProofApplicationPublicationDisposition,
    DurableStateWitnessServiceLimits,
    DurableStateWitnessService,
    TransferableDurableStateWitnessService,
} from '../durable-state-witness-service.js';
import { persistCommonProofApplicationAuthorization } from '../durable-state-witness-service.js';
import {
    openWebLockOwnedBrowserActionStorageCustody,
    type WebLockOwnedBrowserActionStorageCustody,
    type WebLockCommittedBrowserFoundationInitialization,
    type WebLockFoundationWitnessRecord,
    type WebLockOwnedFoundationWitnessRole,
    type WebLockRecoveredBrowserFoundationInitialization,
} from '../web-lock-owned-untrusted-storage-transaction-store.js';

import {
    bytesEqual,
    copyBoundedBytes,
    copyBytes,
    maximumCheckpointDescriptorByteLength,
    mutationIdentifierByteLength,
    storageRootCommitmentByteLength,
} from './message-validation.js';
import {
    copyBoundSnapshotInput,
    copyBytesVerificationResult,
    copyCheckpointBoundary,
    copyCheckpointDescription,
    copyFoundationFreshnessCoordinate,
    copyFoundationOperationInitializationInput,
    copyOptionalSnapshot,
    copyProducedStateReservationVerificationResult,
    copySnapshot,
    copyWorkerActivatedFoundationInitializationResult,
    copyWorkerCommittedFoundationInitializationResult,
    copyWorkerConfiguration,
    copyWorkerProducedStateReservationIntentVerificationResult,
    destroyFoundationCoordinate,
    foundationCoordinatesEqual,
    isCustodyErrorCode,
    isCustodyWorkerRequest,
    isPlainRecord,
    maximumActiveCheckpointHandleCount,
    validateVoidResult,
    type BrowserActionStorageCustodyWorkerConfiguration,
    type CustodyWorkerScope,
    type WorkerActivatedFoundationInitializationResult,
} from './runtime.js';
import {
    DefinitelyUnpublishedCommonProofApplicationError,
    copyCommonProofCheckpointResumeDescriptorForWorker,
    destroyCommonProofCheckpointResumeDescriptor,
    installedCommonProofExecutionEnvironmentBrand,
    installedCommonProofExecutionEnvironmentRecords,
    installedCommonProofCheckpointLineageReservationBrand,
    installedCommonProofCheckpointLineageReservationRecords,
    installedCommonProofPreparedOperationBrand,
    installedCommonProofPreparedOperationRecords,
    installedCustodyWorkerHostCommonProofEnvironmentOpeners,
    installedCustodyWorkerHostCommonProofCheckpointLineageReleasers,
    installedCustodyWorkerHostCommonProofCheckpointLineageReservers,
    installedCustodyWorkerHostCommonProofGenerationPreparers,
    retireInstalledCommonProofExecutionEnvironment,
    type CustodyWorkerCommand,
    type CustodyWorkerRequest,
    type InstalledCommonProofApplicationInput,
    type InstalledCommonProofCapabilityTransfer,
    type InstalledCommonProofExecutionEnvironment,
    type InstalledCommonProofExecutionEnvironmentRecord,
    type InstalledCommonProofCheckpointLineageReservation,
    type InstalledCommonProofPreparedOperation,
    type InstalledCommonProofPreparedOperationRecord,
    type ResolvedInstalledCommonProofExecutionEnvironmentInput,
} from './worker-protocol.js';

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
            return input === undefined
                ? undefined
                : copyBytes(
                      input,
                      32,
                      'Checkpoint private-randomness stream-attempt identifier',
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
                    configurableParticipantCountRange.maximum * 2
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
    const commonProofCustodiesPendingCleanup =
        new Set<CommonProofBrowserCustody>();
    const commonProofCheckpointLineageReservations = new Map<
        InstalledCommonProofCheckpointLineageReservation,
        CheckpointLineageReservation
    >();
    const commonProofPreparedOperations =
        new Set<InstalledCommonProofPreparedOperation>();
    const retirePreparedCommonProofOperation = async (
        preparedOperation: InstalledCommonProofPreparedOperation,
    ): Promise<void> => {
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
            if (record.checkpointOperationIdentity !== undefined) {
                const store = await requireCheckpointStore();
                await store.releaseOperationIdentity(
                    record.checkpointOperationIdentity,
                );
                record.checkpointOperationIdentity = undefined;
            }
            destroyCommonProofCheckpointResumeDescriptor(
                record.resumeDescriptor,
            );
            record.resumeDescriptor = undefined;
            record.commonProofRuntimeBindingHash.fill(0);
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
            record.generationFamilyAdapter !== undefined ||
            record.checkpointOperationIdentity !== undefined ||
            record.resumeDescriptor !== undefined
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'The common-proof prepared operation cannot finish its neutral authority transfer.',
            );
        }
        record.commonProofRuntimeBindingHash.fill(0);
        record.proofAttemptLineageIdentifier.fill(0);
        destroyCommonProofCheckpointResumeDescriptor(record.resumeDescriptor);
        record.resumeDescriptor = undefined;
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
                await retirePreparedCommonProofOperation(preparedOperation);
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
        const pendingCommonProofCustodyCleanupOutcomes =
            await Promise.allSettled(
                [...commonProofCustodiesPendingCleanup].map(
                    async (commonProofCustody) => {
                        await commonProofCustody.retire();
                        commonProofCustodiesPendingCleanup.delete(
                            commonProofCustody,
                        );
                    },
                ),
            );
        const commonProofPreparedOperationCleanupOutcomes =
            await Promise.allSettled(
                [...commonProofPreparedOperations].map((preparedOperation) =>
                    retirePreparedCommonProofOperation(preparedOperation),
                ),
            );
        const commonProofReservationCleanupOutcomes =
            await Promise.allSettled(
                [...commonProofCheckpointLineageReservations.keys()].map(
                    (reservation) => {
                        const releaseReservation =
                            installedCustodyWorkerHostCommonProofCheckpointLineageReleasers.get(
                                uninstall,
                            );
                        if (releaseReservation === undefined) {
                            throw new BrowserActionStorageCustodyError(
                                'OwnedWorkerFailure',
                                'Worker-owned common-proof checkpoint reservation lost its release authority.',
                            );
                        }
                        return releaseReservation(reservation);
                    },
                ),
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
        const pendingCommonProofCustodyCleanupFailures =
            pendingCommonProofCustodyCleanupOutcomes
                .filter(
                    (outcome): outcome is PromiseRejectedResult =>
                        outcome.status === 'rejected',
                )
                .map((outcome) => outcome.reason as unknown);
        const commonProofPreparedOperationCleanupFailures =
            commonProofPreparedOperationCleanupOutcomes
                .filter(
                    (outcome): outcome is PromiseRejectedResult =>
                        outcome.status === 'rejected',
                )
                .map((outcome) => outcome.reason as unknown);
        const commonProofReservationCleanupFailures =
            commonProofReservationCleanupOutcomes
                .filter(
                    (outcome): outcome is PromiseRejectedResult =>
                        outcome.status === 'rejected',
                )
                .map((outcome) => outcome.reason as unknown);
        failures.push(
            ...commonProofCleanupFailures,
            ...pendingCommonProofCustodyCleanupFailures,
            ...commonProofPreparedOperationCleanupFailures,
            ...commonProofReservationCleanupFailures,
        );
        if (
            commonProofCleanupFailures.length === 0 &&
            pendingCommonProofCustodyCleanupFailures.length === 0 &&
            commonProofPreparedOperationCleanupFailures.length === 0 &&
            commonProofReservationCleanupFailures.length === 0
        ) {
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
        let publicationDisposition:
            | CommonProofApplicationPublicationDisposition
            | undefined;
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
                                    onPublicationDisposition: (disposition) => {
                                        publicationDisposition = disposition;
                                    },
                                    proofApplicationSlotHash:
                                        prepared.proofApplicationSlotHash,
                                },
                            );
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
                        if (
                            publicationDisposition !==
                            'published-or-indeterminate'
                        ) {
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
                            const prepublicationErrorCode =
                                error instanceof Error && 'code' in error
                                    ? String((error as { code?: unknown }).code)
                                    : undefined;
                            if (
                                publicationDisposition ===
                                    'definitely-not-published' ||
                                (prepublicationErrorCode !==
                                    'AuthenticationFailed' &&
                                    prepublicationErrorCode !==
                                        'CleanupFailed' &&
                                    prepublicationErrorCode !== 'Conflict' &&
                                    prepublicationErrorCode !== 'MissingRecord')
                            ) {
                                throw new DefinitelyUnpublishedCommonProofApplicationError(
                                    error,
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
            const applicationFailure =
                error instanceof
                DefinitelyUnpublishedCommonProofApplicationError
                    ? error.failureCause
                    : error;
            const errorCode =
                applicationFailure instanceof Error &&
                'code' in applicationFailure
                    ? String((applicationFailure as { code?: unknown }).code)
                    : undefined;
            const definitelyNotPublished =
                error instanceof
                DefinitelyUnpublishedCommonProofApplicationError;
            const permanentStateFailure =
                abortFailed ||
                publicationDisposition === 'published-or-indeterminate' ||
                errorCode === 'AuthenticationFailed' ||
                errorCode === 'CleanupFailed' ||
                errorCode === 'MissingRecord' ||
                (errorCode === 'Conflict' && !definitelyNotPublished);
            if (!permanentStateFailure) {
                throw error;
            }
            const terminalError =
                applicationFailure instanceof
                    BrowserActionStorageCustodyError &&
                applicationFailure.code === 'OwnedWorkerFailure'
                    ? applicationFailure
                    : new BrowserActionStorageCustodyError(
                          'OwnedWorkerFailure',
                          'The common-proof application could not establish one exact authenticated durable successor.',
                          applicationFailure,
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
                    copiedInput as Uint8Array | undefined,
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
                        initializationInput.orderedWitnessBindings.length
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
                        initializationInput.orderedWitnessBindings.length
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
                            await retirePreparedCommonProofOperation(
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
    installedCustodyWorkerHostCommonProofCheckpointLineageReservers.set(
        uninstall,
        async () => {
            if (uninstalled || terminalFailure !== undefined) {
                throw (
                    terminalFailure ??
                    new BrowserActionStorageCustodyError(
                        'Closed',
                        'The custody worker host is no longer available for common-proof checkpoint reservation.',
                    )
                );
            }
            if (
                commonProofCheckpointLineageReservations.size +
                    commonProofPreparedOperations.size +
                    commonProofExecutionEnvironments.size >=
                1
            ) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidState',
                    'The installed worker already owns the maximum one common-proof reservation, preparation, or execution chain.',
                );
            }
            const store = await requireCheckpointStore();
            const storeReservation =
                await store.reserveCheckpointLineage();
            const checkpointLineageIdentifier = Uint8Array.from(
                storeReservation.checkpointLineageIdentifier,
            );
            if (
                checkpointLineageIdentifier.byteLength !==
                mutationIdentifierByteLength
            ) {
                checkpointLineageIdentifier.fill(0);
                await store.releaseCheckpointLineageReservation(
                    storeReservation,
                );
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The authenticated checkpoint store returned a malformed lineage reservation.',
                );
            }
            const reservation = Object.freeze({
                [installedCommonProofCheckpointLineageReservationBrand]:
                    true as const,
            });
            installedCommonProofCheckpointLineageReservationRecords.set(
                reservation,
                {
                    checkpointLineageIdentifier,
                    installedHost: uninstall,
                    state: 'available',
                },
            );
            commonProofCheckpointLineageReservations.set(
                reservation,
                storeReservation,
            );
            return reservation;
        },
    );
    installedCustodyWorkerHostCommonProofCheckpointLineageReleasers.set(
        uninstall,
        async (reservation) => {
            const record =
                installedCommonProofCheckpointLineageReservationRecords.get(
                    reservation,
                );
            const storeReservation =
                commonProofCheckpointLineageReservations.get(reservation);
            if (
                record === undefined ||
                record.installedHost !== uninstall ||
                record.state !== 'available' ||
                storeReservation === undefined
            ) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'The common-proof checkpoint-lineage reservation is unavailable in this worker.',
                );
            }
            const store = await requireCheckpointStore();
            await store.releaseCheckpointLineageReservation(storeReservation);
            record.state = 'consumed';
            record.checkpointLineageIdentifier.fill(0);
            commonProofCheckpointLineageReservations.delete(reservation);
        },
    );
    installedCustodyWorkerHostCommonProofGenerationPreparers.set(
        uninstall,
        async (preparationInput) => {
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
                    1 ||
                (preparationInput.checkpoint.generationMode === 'resumed' &&
                    commonProofCheckpointLineageReservations.size !== 0)
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
            let checkpointOperationIdentity:
                | CheckpointOperationIdentity
                | undefined;
            let copiedResumeDescriptor:
                | CommonProofCheckpointResumeDescriptor
                | undefined;
            try {
                const preparedOperation = Object.freeze({
                    [installedCommonProofPreparedOperationBrand]: true as const,
                });
                if (
                    preparationInput.checkpoint.generationMode === 'fresh'
                ) {
                    const reservation =
                        preparationInput.checkpoint.reservation;
                    const reservationRecord =
                        installedCommonProofCheckpointLineageReservationRecords.get(
                            reservation,
                        );
                    const storeReservation =
                        commonProofCheckpointLineageReservations.get(
                            reservation,
                        );
                    if (
                        reservationRecord === undefined ||
                        reservationRecord.installedHost !== uninstall ||
                        reservationRecord.state !== 'available' ||
                        storeReservation === undefined ||
                        !bytesEqual(
                            reservationRecord.checkpointLineageIdentifier,
                            description.checkpointLineageIdentifier,
                        )
                    ) {
                        throw new BrowserActionStorageCustodyError(
                            'InvalidInput',
                            'The fresh common-proof adapter is not bound to the reserved checkpoint lineage.',
                        );
                    }
                    checkpointOperationIdentity =
                        await (
                            await requireCheckpointStore()
                        ).bindCheckpointLineageToProofAttempt(
                            storeReservation,
                            description.proofAttemptLineageIdentifier,
                        );
                    reservationRecord.state = 'consumed';
                    reservationRecord.checkpointLineageIdentifier.fill(0);
                    commonProofCheckpointLineageReservations.delete(
                        reservation,
                    );
                } else {
                    copiedResumeDescriptor =
                        copyCommonProofCheckpointResumeDescriptorForWorker(
                            preparationInput.checkpoint.resumeDescriptor,
                        );
                    if (
                        !bytesEqual(
                            copiedResumeDescriptor.checkpointLineageIdentifier,
                            description.checkpointLineageIdentifier,
                        ) ||
                        copiedResumeDescriptor.privateRandomnessStreamAttemptIdentifier ===
                            undefined ||
                        !bytesEqual(
                            copiedResumeDescriptor.privateRandomnessStreamAttemptIdentifier,
                            description.proofAttemptLineageIdentifier,
                        )
                    ) {
                        throw new BrowserActionStorageCustodyError(
                            'RecordAuthenticationFailed',
                            'The resumed common-proof adapter differs from the authenticated checkpoint lineage or proof attempt.',
                        );
                    }
                }
                installedCommonProofPreparedOperationRecords.set(
                    preparedOperation,
                    {
                        ...(checkpointOperationIdentity === undefined
                            ? {}
                            : { checkpointOperationIdentity }),
                        commonProofRuntimeBindingHash:
                            description.commonProofRuntimeBindingHash,
                        consumed: false,
                        foundationActionRandomnessHandleIdentifier,
                        generationFamilyAdapter:
                            preparationInput.generationFamilyAdapter,
                        installedHost: uninstall,
                        proofAttemptLineageIdentifier:
                            description.proofAttemptLineageIdentifier,
                        ...(copiedResumeDescriptor === undefined
                            ? {}
                            : { resumeDescriptor: copiedResumeDescriptor }),
                    },
                );
                commonProofPreparedOperations.add(preparedOperation);
                description.commonProofGenerationAuthorizationHash.fill(0);
                description.checkpointLineageIdentifier.fill(0);
                return preparedOperation;
            } catch (error) {
                description.commonProofRuntimeBindingHash.fill(0);
                description.commonProofGenerationAuthorizationHash.fill(0);
                description.proofAttemptLineageIdentifier.fill(0);
                description.checkpointLineageIdentifier.fill(0);
                destroyCommonProofCheckpointResumeDescriptor(
                    copiedResumeDescriptor,
                );
                if (checkpointOperationIdentity !== undefined) {
                    try {
                        await (
                            await requireCheckpointStore()
                        ).releaseOperationIdentity(
                            checkpointOperationIdentity,
                        );
                    } catch (cleanupError) {
                        throw new BrowserActionStorageCustodyError(
                            'OwnedWorkerFailure',
                            'Common-proof preparation failed after binding its checkpoint lineage and the unused identity could not be released.',
                            [error, cleanupError],
                        );
                    }
                }
                throw error;
            }
        },
    );
    installedCustodyWorkerHostCommonProofEnvironmentOpeners.set(
        uninstall,
        async (environmentInput) => {
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
            let copiedProofAttemptLineageIdentifier = new Uint8Array(0);
            let generationFamilyAdapter:
                | ClosedWorkerCommonProofGenerationFamilyAdapter
                | undefined;
            let copiedResumeDescriptor:
                | CommonProofCheckpointResumeDescriptor
                | undefined;
            let checkpointOperationIdentity:
                | CheckpointOperationIdentity
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
                copiedProofAttemptLineageIdentifier = Uint8Array.from(
                    copyBytes(
                        preparedRecord.proofAttemptLineageIdentifier,
                        mutationIdentifierByteLength,
                        'Proof-attempt lineage identifier',
                    ),
                );
                copiedResumeDescriptor = preparedRecord.resumeDescriptor;
                preparedRecord.resumeDescriptor = undefined;
                checkpointOperationIdentity =
                    preparedRecord.checkpointOperationIdentity;
                preparedRecord.checkpointOperationIdentity = undefined;
                if (
                    (copiedResumeDescriptor === undefined) ===
                    (checkpointOperationIdentity === undefined)
                ) {
                    throw new BrowserActionStorageCustodyError(
                        'InvalidState',
                        'The common-proof preparation does not own exactly one fresh or resumed checkpoint authority.',
                    );
                }
                generationFamilyAdapter =
                    preparedRecord.generationFamilyAdapter;
                preparedRecord.generationFamilyAdapter = undefined;
                copiedInput = Object.freeze({
                    commonProofRuntimeBindingHash: copiedRuntimeBindingHash,
                    foundationActionRandomnessHandleIdentifier:
                        preparedRecord.foundationActionRandomnessHandleIdentifier,
                    generationFamilyAdapter,
                    proofAttemptLineageIdentifier:
                        copiedProofAttemptLineageIdentifier,
                    ...(checkpointOperationIdentity === undefined
                        ? {}
                        : { checkpointOperationIdentity }),
                    ...(copiedResumeDescriptor === undefined
                        ? {}
                        : { resumeDescriptor: copiedResumeDescriptor }),
                });
            } catch (error) {
                copiedRuntimeBindingHash.fill(0);
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
                    preparedRecord.checkpointOperationIdentity =
                        checkpointOperationIdentity;
                    checkpointOperationIdentity = undefined;
                    preparedRecord.resumeDescriptor = copiedResumeDescriptor;
                    copiedResumeDescriptor = undefined;
                    try {
                        await retirePreparedCommonProofOperation(
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
            let openedCommonProofCustody:
                | CommonProofBrowserCustody
                | undefined;
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
                        const store = await requireCheckpointStore();
                        openedCommonProofCustody =
                            await owned.openCommonProofCustody({
                                actionRandomnessCommitment:
                                    actionRandomnessHandle.actionRandomnessCommitment.slice(),
                                checkpoint:
                                    copiedInput.resumeDescriptor === undefined
                                        ? {
                                              operationIdentity:
                                                  copiedInput.checkpointOperationIdentity!,
                                              store,
                                          }
                                        : {
                                              resumeDescriptor:
                                                  copiedInput.resumeDescriptor,
                                              store,
                                          },
                                commonProofEnvironmentIdentifier,
                                commonProofRuntimeBindingHash:
                                    copiedInput.commonProofRuntimeBindingHash,
                                proofAttemptLineageIdentifier:
                                    copiedInput.proofAttemptLineageIdentifier,
                            });
                        commonProofCustodiesPendingCleanup.add(
                            openedCommonProofCustody,
                        );
                    } finally {
                        commonProofEnvironmentIdentifier.fill(0);
                    }
                    const commonProofCustody = openedCommonProofCustody;
                    if (commonProofCustody === undefined) {
                        throw new BrowserActionStorageCustodyError(
                            'OwnedWorkerFailure',
                            'Common-proof execution custody ended without an owned environment.',
                        );
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
                            custody: commonProofCustody,
                            foundationActionRandomnessHandleIdentifier:
                                copiedInput.foundationActionRandomnessHandleIdentifier,
                            generationCompleted: false,
                            installedHost: uninstall,
                            operationActive: false,
                            pendingApplication: undefined,
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
                    commonProofCustodiesPendingCleanup.delete(
                        commonProofCustody,
                    );
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
                .catch(async (error: unknown) => {
                    if (!generationFamilyAdapterOwnedByEnvironment) {
                        const cleanupFailures: unknown[] = [];
                        const checkpointAuthorityOwnedByCustody =
                            openedCommonProofCustody !== undefined;
                        if (openedCommonProofCustody !== undefined) {
                            try {
                                await openedCommonProofCustody.retire();
                                commonProofCustodiesPendingCleanup.delete(
                                    openedCommonProofCustody,
                                );
                            } catch (cleanupError) {
                                cleanupFailures.push(cleanupError);
                            }
                        }
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
                            if (!checkpointAuthorityOwnedByCustody) {
                                retainedPreparedRecord.checkpointOperationIdentity =
                                    copiedInput.checkpointOperationIdentity;
                                retainedPreparedRecord.resumeDescriptor =
                                    copiedInput.resumeDescriptor;
                            }
                            try {
                                await retirePreparedCommonProofOperation(
                                    environmentInput.preparedOperation,
                                );
                            } catch (cleanupError) {
                                cleanupFailures.push(cleanupError);
                            }
                        } else {
                            try {
                                releaseClosedWorkerCommonProofGenerationFamilyAdapter(
                                    copiedInput.generationFamilyAdapter,
                                );
                            } catch (cleanupError) {
                                cleanupFailures.push(cleanupError);
                            }
                            if (
                                !checkpointAuthorityOwnedByCustody &&
                                copiedInput.checkpointOperationIdentity !==
                                    undefined
                            ) {
                                try {
                                    await (
                                        await requireCheckpointStore()
                                    ).releaseOperationIdentity(
                                        copiedInput.checkpointOperationIdentity,
                                    );
                                } catch (cleanupError) {
                                    cleanupFailures.push(cleanupError);
                                }
                            }
                        }
                        if (cleanupFailures.length !== 0) {
                            throw new BrowserActionStorageCustodyError(
                                'OwnedWorkerFailure',
                                'Opening common-proof execution custody failed and one or more worker-owned authorities remain retained for cleanup retry.',
                                [error, ...cleanupFailures],
                            );
                        }
                    }
                    throw error;
                })
                .finally(() => {
                    copiedInput.commonProofRuntimeBindingHash.fill(0);
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
