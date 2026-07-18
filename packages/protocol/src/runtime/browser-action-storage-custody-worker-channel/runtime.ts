import {
    copyAuthenticatedMailboxFrozenRosterParticipantIdentities,
    openAuthenticatedMailboxFrozenRoster,
} from '@sealed-lattice/crypto';
import {
    browserActionStorageCustodyErrorCodes,
    configurableParticipantCountRange,
    deriveFoundationRosterParameters,
    foundationProfile,
    refusalReasonCodes,
} from '@sealed-lattice/types';
import type {
    BrowserFoundationInitializationPreparationInput,
    RefusalReason,
} from '@sealed-lattice/types';

import type {
    CheckpointBoundary,
    ExpectedCheckpointBoundary,
} from '../authenticated-checkpoint-store.js';
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
} from '../browser-action-storage-custody.js';
import { copyBrowserFoundationInitializationPreparationInput } from '../browser-foundation-initialization.js';
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
} from '../browser-foundation-operation-owner.js';
import {
    copyLocalRecordBytes,
    copyLocalRecordIdentifierInput,
    copyLocalRecordOpenInput,
    copyLocalRecordSealInput,
    destroyLocalRecordIdentifierInput,
    destroyLocalRecordOpenInput,
    destroyLocalRecordSealInput,
} from '../browser-local-record-validation.js';
import {
    ExclusiveResourceLifecycle,
    type ExclusiveResourceOwnerToken,
} from '../exclusive-resource-lifecycle.js';
import type { UntrustedStorageTransactionLimits } from '../untrusted-storage-transaction-store.js';

import {
    bytesEqual,
    copyBoundedBytes,
    copyBytes,
    maximumCheckpointCollectionLength,
    maximumCheckpointDescriptorByteLength,
    mutationIdentifierByteLength,
    storageRootCommitmentByteLength,
} from './message-validation.js';
import type {
    CustodyWorkerCommand,
    CustodyWorkerLike,
    CustodyWorkerRequest,
    CustodyWorkerResponse,
} from './worker-protocol.js';

const maximumDatabaseNameLength = 256;
const maximumNamespaceLength = 64;
export const maximumActiveCheckpointHandleCount = 64;
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

export type CustodyWorkerScope = Readonly<{
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

export type WorkerActivatedFoundationInitializationResult = Readonly<{
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

export const isPlainRecord = (
    value: unknown,
): value is Record<string, unknown> => {
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

export const isCustodyErrorCode = (
    value: unknown,
): value is BrowserActionStorageCustodyErrorCode =>
    typeof value === 'string' &&
    browserActionStorageCustodyErrorCodes.includes(
        value as BrowserActionStorageCustodyErrorCode,
    );

export const copyCheckpointBoundary = <
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
        !(value.privateRandomCursorManifestBytes instanceof Uint8Array) ||
        value.privateRandomCursorManifestBytes.byteLength >
            maximumCheckpointDescriptorByteLength ||
        !Array.isArray(value.orderedSourceDigests) ||
        value.orderedSourceDigests.length > maximumCheckpointCollectionLength ||
        (value.privateRandomnessStreamAttemptIdentifier !== undefined &&
            !(value.privateRandomnessStreamAttemptIdentifier instanceof
                Uint8Array)) ||
        (includeDescriptor &&
            !(stateStreamDescriptorBytes instanceof Uint8Array))
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The checkpoint boundary is malformed or outside the worker-channel copy bound.',
        );
    }
    return Object.freeze({
        operationKind: value.operationKind,
        orderedSourceDigests: Object.freeze(
            value.orderedSourceDigests.map((digest, digestIndex) =>
                copyBytes(
                    digest,
                    storageRootCommitmentByteLength,
                    `Checkpoint source digest ${String(digestIndex)}`,
                ),
            ),
        ),
        privateRandomCursorManifestBytes: copyBoundedBytes(
            value.privateRandomCursorManifestBytes,
            maximumCheckpointDescriptorByteLength,
            'Checkpoint private-randomness cursor manifest',
        ),
        ...(value.privateRandomnessStreamAttemptIdentifier === undefined
            ? {}
            : {
                  privateRandomnessStreamAttemptIdentifier: copyBytes(
                      value.privateRandomnessStreamAttemptIdentifier,
                      32,
                      'Checkpoint private-randomness stream-attempt identifier',
                  ),
              }),
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

export const copyCheckpointDescription = (
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

export const copyFoundationFreshnessCoordinate = (
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

export const foundationCoordinatesEqual = (
    left: BrowserFoundationFreshnessCoordinate,
    right: BrowserFoundationFreshnessCoordinate,
): boolean =>
    left.freshnessSequence === right.freshnessSequence &&
    bytesEqual(left.authenticatedHeadDigest, right.authenticatedHeadDigest) &&
    bytesEqual(left.storageInstanceIdentity, right.storageInstanceIdentity);

export const destroyFoundationCoordinate = (
    coordinate: BrowserFoundationFreshnessCoordinate,
): void => {
    coordinate.authenticatedHeadDigest.fill(0);
    coordinate.storageInstanceIdentity.fill(0);
};

export const copyWorkerCommittedFoundationInitializationResult = (
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

export const copyWorkerActivatedFoundationInitializationResult = (
    value: unknown,
): WorkerActivatedFoundationInitializationResult => {
    if (
        !isPlainRecord(value) ||
        typeof value.actionRandomnessHandleIdentifier !== 'string' ||
        !/^[0-9a-f]{64}$/u.test(value.actionRandomnessHandleIdentifier) ||
        !Array.isArray(value.orderedWitnessRoleHandleIdentifiers)
    ) {
        throw new BrowserActionStorageCustodyError(
            'OwnedWorkerFailure',
            'The owned worker returned malformed activated foundation authority.',
        );
    }
    try {
        deriveFoundationRosterParameters(
            value.orderedWitnessRoleHandleIdentifiers.length + 1,
        );
    } catch (error) {
        throw new BrowserActionStorageCustodyError(
            'OwnedWorkerFailure',
            'The owned worker returned foundation authority outside the configurable participant-count range.',
            error,
        );
    }
    if (
        value.orderedWitnessRoleHandleIdentifiers.some(
            (identifier) =>
                typeof identifier !== 'string' ||
                !/^[0-9a-f]{64}$/u.test(identifier),
        ) ||
        new Set(value.orderedWitnessRoleHandleIdentifiers).size !==
            value.orderedWitnessRoleHandleIdentifiers.length
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

export const copyBytesVerificationResult = (
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

export const copyWorkerProducedStateReservationIntentVerificationResult = (
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

export const copyProducedStateReservationVerificationResult = (
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

export const copyFoundationOperationInitializationInput = (
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
    const canonicalRosterBytes = copyBoundedBytes(
        value.canonicalRosterBytes,
        foundationProfile.maximumCopiedBufferByteLength,
        'Canonical roster bytes',
    );
    let participantCount: number;
    try {
        participantCount =
            copyAuthenticatedMailboxFrozenRosterParticipantIdentities(
                openAuthenticatedMailboxFrozenRoster(canonicalRosterBytes),
            ).length;
    } catch (error) {
        canonicalRosterBytes.fill(0);
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'Browser foundation initialization requires a canonical roster within the configurable participant-count range.',
            error,
        );
    }
    if (preparation.orderedWitnessBindings.length !== participantCount - 1) {
        canonicalRosterBytes.fill(0);
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'Browser foundation initialization witness bindings do not match the canonical roster participant count.',
        );
    }
    return Object.freeze({
        ...preparation,
        canonicalRosterBytes,
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

export const copySnapshot = (value: unknown): BrowserDeviceWrappingSnapshot => {
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

export const copyBoundSnapshotInput = (
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

export const copyOptionalSnapshot = (
    value: unknown,
): BrowserDeviceWrappingSnapshot | undefined =>
    value === undefined ? undefined : copySnapshot(value);

export const validateVoidResult = (value: unknown): undefined => {
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

export const copyWorkerConfiguration = (
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

export const isCustodyWorkerRequest = (
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
        privateRandomnessStreamAttemptIdentifier?: Uint8Array,
    ): Promise<BrowserFoundationCheckpointHandle> {
        return this.#queueValidatedOperation(
            () =>
                privateRandomnessStreamAttemptIdentifier === undefined
                    ? undefined
                    : copyBytes(
                          privateRandomnessStreamAttemptIdentifier,
                          32,
                          'Checkpoint private-randomness stream-attempt identifier',
                      ),
            (copiedIdentifier) =>
                this.#sendRequest(
                    'begin-checkpoint',
                    copiedIdentifier,
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
                        configurableParticipantCountRange.maximum * 2
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
            beginCheckpoint: (privateRandomnessStreamAttemptIdentifier) =>
                lifecycle.run(owner, () =>
                    custody.beginCheckpoint(
                        privateRandomnessStreamAttemptIdentifier,
                    ),
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
            beginCheckpoint: (privateRandomnessStreamAttemptIdentifier) =>
                lifecycle.run(owner, () =>
                    client.beginCheckpoint(
                        privateRandomnessStreamAttemptIdentifier,
                    ),
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
                beginCheckpoint: (
                    privateRandomnessStreamAttemptIdentifier,
                ) =>
                    client.beginCheckpoint(
                        privateRandomnessStreamAttemptIdentifier,
                    ),
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
