import { sha512 } from '@noble/hashes/sha2.js';

import {
    openAuthenticatedCheckpointStoreWithProtection,
    type AuthenticatedCheckpointStore,
    type AuthenticatedCheckpointStoreLimits,
    type CheckpointBoundaryPolicy,
    type CheckpointRandomCursorKernel,
    type TransferableAuthenticatedCheckpointStore,
} from './authenticated-checkpoint-store.js';
import {
    createRuntimeRecordProtectionFromSession,
    releaseRuntimeRecordProtection,
    type RuntimeRecordProtection,
    type RuntimeRecordProtectionSession,
} from './authenticated-runtime-record.js';
import {
    createBrowserActionStorageCustodyForOwnedWorker,
    type BrowserActionStorageCustodyForOwnedWorker,
    type BrowserActionStorageWorkerKernel,
} from './browser-action-storage-custody-internal.js';
import type {
    BrowserActionStorageCustody,
    BrowserActionStorageRootBinding,
    BrowserDeviceWrappingSnapshot,
    BrowserFoundationFreshnessCoordinate,
    BrowserFoundationInitializationPreparationInput,
    UntrustedExpectedStorageRootCommitment,
} from './browser-action-storage-custody.js';
import { BrowserActionStorageCustodyError } from './browser-action-storage-custody.js';
import {
    destroyWorkerPreparedBrowserFoundationInitialization,
    takePreparedBrowserFoundationInitializationForAuthenticatedCommit,
} from './browser-foundation-initialization.js';
import {
    deriveCommonProofAttemptLogicalRecordPrefix,
    openCommonProofBrowserCustody,
    type CommonProofBrowserCustody,
    type CommonProofCheckpointResumeDescriptor,
} from './common-proof-browser-custody.js';
import {
    openDurableStateWitnessServiceWithProtection,
    type DurableStateWitnessServiceLimits,
    type TransferableDurableStateWitnessService,
} from './durable-state-witness-service.js';
import {
    ExclusiveResourceLifecycle,
    type ExclusiveResourceOwnerToken,
} from './exclusive-resource-lifecycle.js';
import {
    IndexedDbUntrustedStorageAdapter,
    openIndexedDbUntrustedStorageAdapter,
} from './indexed-db-untrusted-storage-adapter.js';
import {
    openUntrustedStorageTransactionStore,
    type UntrustedStorageAdapter,
    type UntrustedStorageAuthenticatedRepairProtection,
    type UntrustedStorageAuthenticatedHeadSnapshot,
    type UntrustedStorageRepairReport,
    type UntrustedStorageTransactionStoreOpenResult,
    type UntrustedStorageTransactionLimits,
    type UntrustedStorageTransactionStore,
} from './untrusted-storage-transaction-store.js';

const commonProofScratchByteLength = 268_435_456n;
const commonProofLiveObjectCount = 4_096;
const commonProofDataChunkByteLength = 49_152n;
const commonProofSecretRecordOverheadByteLength = 968n;
const commonProofObjectHeaderPayloadByteLength = 9n;
const commonProofCanonicalOutputChunkByteLength = 1_048_576n;
const commonProofMaximumOutputChunkCount = 5n;
const commonProofPublicRecordOverheadByteLength = 74n;
const commonProofMaximumIndexValueByteLength = 231n;
const commonProofDeletionBatchRecordCount = 64;
const authenticatedRepairRecordFixedByteLength = 2n + 2n + 64n;
const textEncoder = new TextEncoder();
const commonProofLiveObjectCountBigInt = BigInt(commonProofLiveObjectCount);
// Every positive-length object owns one partial data chunk. Each additional
// chunk consumes another complete chunk span. Every object also owns one
// header and one seal record.
const commonProofMaximumDataChunkCount =
    commonProofLiveObjectCountBigInt +
    (commonProofScratchByteLength - commonProofLiveObjectCountBigInt) /
        commonProofDataChunkByteLength;
const commonProofExternalMemoryRecordCountBigInt =
    commonProofMaximumDataChunkCount + 2n * commonProofLiveObjectCountBigInt;
if (
    commonProofExternalMemoryRecordCountBigInt > BigInt(Number.MAX_SAFE_INTEGER)
) {
    throw new Error(
        'The common-proof external-memory record ceiling exceeds the exact JavaScript integer range.',
    );
}
const commonProofExternalMemoryRecordCount = Number(
    commonProofExternalMemoryRecordCountBigInt,
);
const commonProofAttemptLogicalRecordPrefixByteLength = BigInt(
    textEncoder.encode(`common-proof-attempt/${'0'.repeat(128)}/`).byteLength,
);
const commonProofExternalLogicalRecordKeyByteLength =
    commonProofAttemptLogicalRecordPrefixByteLength +
    BigInt(textEncoder.encode('external-memory/').byteLength) +
    128n;
const commonProofOutputLogicalRecordKeyByteLength =
    commonProofAttemptLogicalRecordPrefixByteLength +
    BigInt(textEncoder.encode('canonical-output/').byteLength) +
    128n;
const commonProofExternalStoredValueByteLength =
    commonProofScratchByteLength +
    commonProofLiveObjectCountBigInt *
        commonProofObjectHeaderPayloadByteLength +
    commonProofExternalMemoryRecordCountBigInt *
        commonProofSecretRecordOverheadByteLength;
const commonProofOutputStoredValueByteLength =
    commonProofMaximumOutputChunkCount *
    (commonProofCanonicalOutputChunkByteLength +
        commonProofPublicRecordOverheadByteLength);
const commonProofLogicalRecordCountBigInt =
    commonProofExternalMemoryRecordCountBigInt +
    commonProofMaximumOutputChunkCount;
const commonProofIndexStoredValueByteLength =
    commonProofLogicalRecordCountBigInt *
    commonProofMaximumIndexValueByteLength;
const commonProofMaximumStagedReplacementByteLength =
    commonProofCanonicalOutputChunkByteLength +
    commonProofPublicRecordOverheadByteLength;
const commonProofMaximumAdditionalStoredValueByteLengthBigInt =
    commonProofExternalStoredValueByteLength +
    commonProofOutputStoredValueByteLength +
    commonProofIndexStoredValueByteLength +
    commonProofMaximumStagedReplacementByteLength;
const commonProofMaximumAdditionalAuthenticatedRepairHeadPlaintextByteLengthBigInt =
    commonProofExternalMemoryRecordCountBigInt *
        (authenticatedRepairRecordFixedByteLength +
            commonProofExternalLogicalRecordKeyByteLength +
            commonProofMaximumIndexValueByteLength) +
    commonProofMaximumOutputChunkCount *
        (authenticatedRepairRecordFixedByteLength +
            commonProofOutputLogicalRecordKeyByteLength +
            commonProofMaximumIndexValueByteLength);
const commonProofMaximumAdditionalOwnedRecordCountBigInt =
    commonProofLogicalRecordCountBigInt * 2n + 1n;
const commonProofMaximumRecordStorageByteLengthBigInt =
    commonProofCanonicalOutputChunkByteLength +
    commonProofPublicRecordOverheadByteLength;
const commonProofMaximumTransactionChangeCountBigInt = BigInt(
    commonProofDeletionBatchRecordCount,
);
const commonProofMaximumTransactionByteLengthBigInt =
    commonProofMaximumRecordStorageByteLengthBigInt;
const commonProofCapacityValues = [
    commonProofMaximumAdditionalStoredValueByteLengthBigInt,
    commonProofMaximumAdditionalAuthenticatedRepairHeadPlaintextByteLengthBigInt,
    commonProofMaximumAdditionalOwnedRecordCountBigInt,
    commonProofMaximumRecordStorageByteLengthBigInt,
    commonProofMaximumTransactionChangeCountBigInt,
    commonProofMaximumTransactionByteLengthBigInt,
] as const;
if (
    commonProofAttemptLogicalRecordPrefixByteLength !== 150n ||
    commonProofExternalLogicalRecordKeyByteLength !== 294n ||
    commonProofOutputLogicalRecordKeyByteLength !== 295n ||
    commonProofCapacityValues.some(
        (value) => value > BigInt(Number.MAX_SAFE_INTEGER),
    )
) {
    throw new Error(
        'The derived common-proof storage profile is outside its exact JavaScript or logical-key bounds.',
    );
}
const commonProofMaximumAdditionalStoredValueByteLength = Number(
    commonProofMaximumAdditionalStoredValueByteLengthBigInt,
);
const commonProofMaximumAdditionalAuthenticatedRepairHeadPlaintextByteLength =
    Number(
        commonProofMaximumAdditionalAuthenticatedRepairHeadPlaintextByteLengthBigInt,
    );
const commonProofMaximumAdditionalOwnedRecordCount = Number(
    commonProofMaximumAdditionalOwnedRecordCountBigInt,
);
const commonProofMaximumRecordStorageByteLength = Number(
    commonProofMaximumRecordStorageByteLengthBigInt,
);
const commonProofMaximumTransactionChangeCount = Number(
    commonProofMaximumTransactionChangeCountBigInt,
);
const commonProofMaximumTransactionByteLength = Number(
    commonProofMaximumTransactionByteLengthBigInt,
);

export const commonProofStorageCapacityProfile = Object.freeze({
    maximumAdditionalAuthenticatedRepairHeadPlaintextByteLength:
        commonProofMaximumAdditionalAuthenticatedRepairHeadPlaintextByteLength,
    maximumAdditionalOwnedRecordCount:
        commonProofMaximumAdditionalOwnedRecordCount,
    maximumAdditionalStoredValueByteLength:
        commonProofMaximumAdditionalStoredValueByteLength,
    maximumLeaseByteLength: commonProofMaximumRecordStorageByteLength,
    maximumLeaseCountPerTransaction: commonProofMaximumTransactionChangeCount,
    maximumTransactionByteLength: commonProofMaximumTransactionByteLength,
});
const maximumDatabaseNameByteLength = 256;
const maximumLockAcquisitionDelayMilliseconds = 2_147_483_647;
const foundationHashByteLength = 64;
const namespacePattern = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;
const lockNamePrefix = 'sealed-lattice-storage-namespace-';
const runtimeRecordProtectedPlaintextMagic = Uint8Array.of(
    0x53,
    0x4c,
    0x52,
    0x50,
);
const runtimeRecordProtectedPlaintextVersion = 1;
const foundationWitnessRuntimeRecordEnvelopeMagic = Uint8Array.of(
    0x53,
    0x4c,
    0x57,
    0x52,
);
const foundationWitnessRuntimeRecordEnvelopeVersion = 1;
const foundationWitnessRuntimeRecordCoordinateDomain = textEncoder.encode(
    'sealed-lattice/foundation/witness-runtime-record-coordinate/v1',
);
const foundationWitnessAuthorizedEmptyRecord = Uint8Array.of(1, 0, 1);
const actionRandomnessStoredRecordMagic = Uint8Array.of(0x53, 0x4c, 0x41, 0x52);
const actionRandomnessStoredRecordVersion = 1;

type BrowserFoundationRuntimeRecordDomain =
    | 'checkpoint-cache'
    | 'durable-state';

const runtimeRecordProtectionNamespaces: Readonly<
    Record<BrowserFoundationRuntimeRecordDomain, string>
> = Object.freeze({
    'checkpoint-cache': 'foundation-checkpoint-cache',
    'durable-state': 'foundation-durable-state',
});

type WebLockOwnedStorageErrorCode =
    | 'AcquisitionCancelled'
    | 'AcquisitionDeadlineExceeded'
    | 'InvalidConfiguration'
    | 'LockCallbackExited'
    | 'OpenFailed'
    | 'Unavailable';

class WebLockOwnedStorageError extends Error {
    public readonly code: WebLockOwnedStorageErrorCode;
    public readonly failureCause: unknown;

    public constructor(
        code: WebLockOwnedStorageErrorCode,
        message: string,
        failureCause?: unknown,
    ) {
        super(message);
        this.name = 'WebLockOwnedStorageError';
        this.code = code;
        this.failureCause = failureCause;
    }
}

export const requireCommonProofStorageCapacity = (
    limits: UntrustedStorageTransactionLimits,
): void => {
    if (
        limits.maximumLeaseByteLength <
            commonProofMaximumRecordStorageByteLength ||
        limits.maximumLeaseCountPerTransaction <
            commonProofMaximumTransactionChangeCount ||
        limits.maximumOwnedRecordCount <
            commonProofMaximumAdditionalOwnedRecordCount ||
        limits.maximumStoredValueByteLength <
            commonProofMaximumAdditionalStoredValueByteLength +
                commonProofMaximumAdditionalAuthenticatedRepairHeadPlaintextByteLength ||
        limits.maximumTransactionByteLength <
            commonProofMaximumTransactionByteLength
    ) {
        throw new WebLockOwnedStorageError(
            'OpenFailed',
            'The owned browser store cannot reserve the fixed common-proof scratch-record profile.',
        );
    }
};

type WebLockOwnedStorageState = 'open' | 'closing' | 'closed' | 'failed';

export type WebLockOwnedStorageTransactionStore = Readonly<{
    repairReport: UntrustedStorageRepairReport;
    store: UntrustedStorageTransactionStore;
    close(): Promise<void>;
    state(): WebLockOwnedStorageState;
}>;

export type TransferableWebLockOwnedStorageTransactionStore =
    WebLockOwnedStorageTransactionStore &
        Readonly<{
            claimExclusiveOwner(): WebLockOwnedStorageTransactionStore;
        }>;

type WebLockOwnedStorageBaseConfiguration = Readonly<{
    databaseName: string;
    namespace: string;
    limits: UntrustedStorageTransactionLimits;
    acquisitionDeadlineEpochMilliseconds?: number;
    acquisitionSignal?: AbortSignal;
    indexedDbFactory?: IDBFactory;
    keyRangeFactory?: typeof IDBKeyRange;
    lockManager?: LockManager | null;
}>;

export type WebLockOwnedStorageConfiguration =
    WebLockOwnedStorageBaseConfiguration &
        Readonly<{
            authenticatedRepairProtection: UntrustedStorageAuthenticatedRepairProtection;
        }>;

type WebLockOwnedBrowserActionStorageCustodyConfiguration =
    WebLockOwnedStorageBaseConfiguration &
        Readonly<{
            binding: BrowserActionStorageRootBinding;
            cryptoProvider?: Crypto;
            knownStorageRootCommitment?: Uint8Array;
            runtimeBuildManifestHash: Uint8Array;
            workerKernel: BrowserActionStorageWorkerKernel;
        }>;

export type WebLockOwnedBrowserActionStorageCustody = Readonly<{
    authenticateFoundationHead(): Promise<BrowserFoundationFreshnessCoordinate>;
    commitFreshFoundationInitialization(
        input: BrowserFoundationInitializationPreparationInput,
    ): Promise<WebLockCommittedBrowserFoundationInitialization>;
    openRecoveredFoundationInitialization(
        input: BrowserFoundationInitializationPreparationInput,
    ): Promise<WebLockRecoveredBrowserFoundationInitialization>;
    openFoundationWitnessRole(
        input: WebLockFoundationWitnessRoleOpenInput,
    ): Promise<WebLockOwnedFoundationWitnessRole>;
    custody: BrowserActionStorageCustody;
    openRuntimeRecordProtection(
        domain: BrowserFoundationRuntimeRecordDomain,
    ): Promise<RuntimeRecordProtection>;
    openCommonProofCustody?(input: {
        actionRandomnessCommitment: Uint8Array;
        checkpoint?: Readonly<{
            cursorKernel: CheckpointRandomCursorKernel;
            resumeDescriptor?: CommonProofCheckpointResumeDescriptor;
            store: AuthenticatedCheckpointStore;
        }>;
        commonProofEnvironmentIdentifier: Uint8Array;
        commonProofRuntimeBindingHash: Uint8Array;
        proofAttemptLineageIdentifier: Uint8Array;
    }): Promise<CommonProofBrowserCustody>;
    openCheckpointStore(input: {
        boundaryPolicy: CheckpointBoundaryPolicy;
        cursorKernel: CheckpointRandomCursorKernel;
        limits: AuthenticatedCheckpointStoreLimits;
    }): Promise<TransferableAuthenticatedCheckpointStore>;
    openRootAndAuthenticatedStore(input: {
        expectedSnapshot: BrowserDeviceWrappingSnapshot;
        untrustedExpectedCommitment: UntrustedExpectedStorageRootCommitment;
    }): Promise<UntrustedStorageRepairReport>;
    close(): Promise<void>;
    state(): WebLockOwnedStorageState;
}>;

/**
 * Worker-realm result retained by the custody host. It carries only opaque
 * session identifiers after exact authenticated commit and readback; no
 * record envelope, root, state key, or generic store escapes with it.
 */
export type WebLockCommittedBrowserFoundationInitialization = Readonly<{
    actionRandomnessCommitment: Uint8Array;
    actionRandomnessSessionIdentifier: string;
    freshnessCoordinate: BrowserFoundationFreshnessCoordinate;
    orderedWitnessRecords: readonly WebLockFoundationWitnessRecord[];
}>;

export type WebLockFoundationWitnessRecord = Readonly<{
    actionRandomnessCommitment: Uint8Array;
    authorizedEmptyPlaintext: Uint8Array;
    localRecordIdentifier: Uint8Array;
    roleIndex: number;
    stateKey: Uint8Array;
    subjectParticipantIdentity: Uint8Array;
    witnessParticipantIdentity: Uint8Array;
}>;

export type WebLockRecoveredBrowserFoundationInitialization = Readonly<{
    actionRandomnessCommitment: Uint8Array;
    actionRandomnessSessionIdentifier: string;
    freshnessCoordinate: BrowserFoundationFreshnessCoordinate;
    orderedWitnessRecords: readonly WebLockFoundationWitnessRecord[];
}>;

export type WebLockFoundationWitnessRoleOpenInput = Readonly<{
    durableStateLimits: DurableStateWitnessServiceLimits;
    openingMode: 'fresh-provisioned' | 'recovered';
    record: WebLockFoundationWitnessRecord;
}>;

export type WebLockOwnedFoundationWitnessRole = Readonly<{
    durableStateService: TransferableDurableStateWitnessService;
}>;

type Deferred<Value> = Readonly<{
    promise: Promise<Value>;
    reject(error: Error): void;
    resolve(value: Value): void;
}>;

const createDeferred = <Value>(): Deferred<Value> => {
    let resolvePromise: ((value: Value) => void) | undefined;
    let rejectPromise: ((error: Error) => void) | undefined;
    let isSettled = false;
    const promise = new Promise<Value>((resolve, reject) => {
        resolvePromise = resolve;
        rejectPromise = reject;
    });
    if (resolvePromise === undefined || rejectPromise === undefined) {
        throw new WebLockOwnedStorageError(
            'OpenFailed',
            'Web Lock storage promise initialization failed.',
        );
    }
    const resolveDeferred = resolvePromise;
    const rejectDeferred = rejectPromise;

    return {
        promise,
        reject: (error) => {
            if (isSettled) {
                return;
            }
            isSettled = true;
            rejectDeferred(error);
        },
        resolve: (value) => {
            if (isSettled) {
                return;
            }
            isSettled = true;
            resolveDeferred(value);
        },
    };
};

const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean => {
    if (left.byteLength !== right.byteLength) {
        return false;
    }
    let difference = 0;
    for (let byteIndex = 0; byteIndex < left.byteLength; byteIndex += 1) {
        difference |= left[byteIndex] ^ right[byteIndex];
    }
    return difference === 0;
};

type OpenedFoundationWitnessRuntimeRecordEnvelope = Readonly<{
    associatedData: Uint8Array;
    innerCanonicalEnvelope: Uint8Array;
    predecessorRecordHash?: Uint8Array;
    recordVersion: bigint;
}>;

const foundationWitnessRuntimeRecordEnvelopeHeaderByteLength =
    foundationWitnessRuntimeRecordEnvelopeMagic.byteLength +
    2 +
    8 +
    1 +
    foundationHashByteLength +
    4 +
    4;
const maximumUnsigned64 = 0xffff_ffff_ffff_ffffn;

const deriveFoundationWitnessRuntimeRecordStateKey = (input: {
    associatedData: Uint8Array;
    baseStateKey: Uint8Array;
}): Uint8Array => {
    const hash = sha512.create();
    hash.update(foundationWitnessRuntimeRecordCoordinateDomain);
    hash.update(input.baseStateKey);
    hash.update(input.associatedData);
    return hash.digest();
};

const isFoundationWitnessRuntimeRecordEnvelope = (
    canonicalEnvelope: Uint8Array,
): boolean =>
    canonicalEnvelope.byteLength >=
        foundationWitnessRuntimeRecordEnvelopeMagic.byteLength &&
    bytesEqual(
        canonicalEnvelope.subarray(
            0,
            foundationWitnessRuntimeRecordEnvelopeMagic.byteLength,
        ),
        foundationWitnessRuntimeRecordEnvelopeMagic,
    );

const encodeFoundationWitnessRuntimeRecordEnvelope = (input: {
    associatedData: Uint8Array;
    innerCanonicalEnvelope: Uint8Array;
    predecessorRecordHash?: Uint8Array;
    recordVersion: bigint;
}): Uint8Array => {
    const encodedByteLength =
        foundationWitnessRuntimeRecordEnvelopeHeaderByteLength +
        input.associatedData.byteLength +
        input.innerCanonicalEnvelope.byteLength;
    if (
        input.associatedData.byteLength === 0 ||
        input.associatedData.byteLength > 0xffff_ffff ||
        input.innerCanonicalEnvelope.byteLength === 0 ||
        input.innerCanonicalEnvelope.byteLength > 0xffff_ffff ||
        input.recordVersion < 0n ||
        input.recordVersion > maximumUnsigned64 ||
        (input.predecessorRecordHash !== undefined &&
            input.predecessorRecordHash.byteLength !==
                foundationHashByteLength) ||
        !Number.isSafeInteger(encodedByteLength) ||
        encodedByteLength > 0xffff_ffff
    ) {
        throw new WebLockOwnedStorageError(
            'OpenFailed',
            'A foundation witness runtime-record envelope exceeds its canonical profile.',
        );
    }
    const encoded = new Uint8Array(encodedByteLength);
    encoded.set(foundationWitnessRuntimeRecordEnvelopeMagic, 0);
    const view = new DataView(encoded.buffer);
    let offset = foundationWitnessRuntimeRecordEnvelopeMagic.byteLength;
    view.setUint16(offset, foundationWitnessRuntimeRecordEnvelopeVersion, true);
    offset += 2;
    view.setBigUint64(offset, input.recordVersion, true);
    offset += 8;
    view.setUint8(offset, input.predecessorRecordHash === undefined ? 0 : 1);
    offset += 1;
    if (input.predecessorRecordHash !== undefined) {
        encoded.set(input.predecessorRecordHash, offset);
    }
    offset += foundationHashByteLength;
    view.setUint32(offset, input.associatedData.byteLength, true);
    offset += 4;
    view.setUint32(offset, input.innerCanonicalEnvelope.byteLength, true);
    offset += 4;
    encoded.set(input.associatedData, offset);
    offset += input.associatedData.byteLength;
    encoded.set(input.innerCanonicalEnvelope, offset);
    return encoded;
};

const openFoundationWitnessRuntimeRecordEnvelope = (
    canonicalEnvelope: Uint8Array,
): OpenedFoundationWitnessRuntimeRecordEnvelope => {
    if (
        canonicalEnvelope.byteLength <=
            foundationWitnessRuntimeRecordEnvelopeHeaderByteLength ||
        !isFoundationWitnessRuntimeRecordEnvelope(canonicalEnvelope)
    ) {
        throw new WebLockOwnedStorageError(
            'OpenFailed',
            'The foundation witness runtime-record envelope is malformed.',
        );
    }
    const view = new DataView(
        canonicalEnvelope.buffer,
        canonicalEnvelope.byteOffset,
        canonicalEnvelope.byteLength,
    );
    let offset = foundationWitnessRuntimeRecordEnvelopeMagic.byteLength;
    const envelopeVersion = view.getUint16(offset, true);
    offset += 2;
    const recordVersion = view.getBigUint64(offset, true);
    offset += 8;
    const predecessorPresence = view.getUint8(offset);
    offset += 1;
    const predecessorRecordHash = canonicalEnvelope.slice(
        offset,
        offset + foundationHashByteLength,
    );
    offset += foundationHashByteLength;
    const associatedDataByteLength = view.getUint32(offset, true);
    offset += 4;
    const innerCanonicalEnvelopeByteLength = view.getUint32(offset, true);
    offset += 4;
    const associatedDataEnd = offset + associatedDataByteLength;
    const innerCanonicalEnvelopeEnd =
        associatedDataEnd + innerCanonicalEnvelopeByteLength;
    if (
        envelopeVersion !== foundationWitnessRuntimeRecordEnvelopeVersion ||
        (predecessorPresence !== 0 && predecessorPresence !== 1) ||
        (predecessorPresence === 0 &&
            predecessorRecordHash.some((byte) => byte !== 0)) ||
        associatedDataByteLength === 0 ||
        innerCanonicalEnvelopeByteLength === 0 ||
        innerCanonicalEnvelopeEnd !== canonicalEnvelope.byteLength
    ) {
        predecessorRecordHash.fill(0);
        throw new WebLockOwnedStorageError(
            'OpenFailed',
            'The foundation witness runtime-record envelope has a non-canonical version, predecessor, or length.',
        );
    }
    if (predecessorPresence === 0) {
        predecessorRecordHash.fill(0);
    }
    return Object.freeze({
        associatedData: canonicalEnvelope.slice(offset, associatedDataEnd),
        innerCanonicalEnvelope: canonicalEnvelope.slice(
            associatedDataEnd,
            innerCanonicalEnvelopeEnd,
        ),
        ...(predecessorPresence === 0 ? {} : { predecessorRecordHash }),
        recordVersion,
    });
};

const destroyOpenedFoundationWitnessRuntimeRecordEnvelope = (
    envelope: OpenedFoundationWitnessRuntimeRecordEnvelope,
): void => {
    envelope.associatedData.fill(0);
    envelope.innerCanonicalEnvelope.fill(0);
    envelope.predecessorRecordHash?.fill(0);
};

const encodeStoredActionRandomnessRecord = (input: {
    actionRandomnessCommitment: Uint8Array;
    canonicalEnvelope: Uint8Array;
}): Uint8Array => {
    if (
        input.actionRandomnessCommitment.byteLength !==
            foundationHashByteLength ||
        input.canonicalEnvelope.byteLength === 0 ||
        input.canonicalEnvelope.byteLength > 0xffff_ffff
    ) {
        throw new WebLockOwnedStorageError(
            'OpenFailed',
            'Action-randomness storage material has an invalid byte length.',
        );
    }
    const headerByteLength =
        actionRandomnessStoredRecordMagic.byteLength + 2 + 4;
    const encoded = new Uint8Array(
        headerByteLength +
            foundationHashByteLength +
            input.canonicalEnvelope.byteLength,
    );
    encoded.set(actionRandomnessStoredRecordMagic, 0);
    const view = new DataView(encoded.buffer);
    view.setUint16(
        actionRandomnessStoredRecordMagic.byteLength,
        actionRandomnessStoredRecordVersion,
        true,
    );
    view.setUint32(
        actionRandomnessStoredRecordMagic.byteLength + 2,
        input.canonicalEnvelope.byteLength,
        true,
    );
    encoded.set(input.actionRandomnessCommitment, headerByteLength);
    encoded.set(
        input.canonicalEnvelope,
        headerByteLength + foundationHashByteLength,
    );
    return encoded;
};

const openStoredActionRandomnessRecord = (
    bytes: Uint8Array,
): Readonly<{
    actionRandomnessCommitment: Uint8Array;
    canonicalEnvelope: Uint8Array;
}> => {
    const headerByteLength =
        actionRandomnessStoredRecordMagic.byteLength + 2 + 4;
    const fixedByteLength = headerByteLength + foundationHashByteLength;
    if (
        bytes.byteLength <= fixedByteLength ||
        !bytesEqual(
            bytes.subarray(0, actionRandomnessStoredRecordMagic.byteLength),
            actionRandomnessStoredRecordMagic,
        )
    ) {
        throw new WebLockOwnedStorageError(
            'OpenFailed',
            'The retained action-randomness record is malformed.',
        );
    }
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const version = view.getUint16(
        actionRandomnessStoredRecordMagic.byteLength,
        true,
    );
    const envelopeByteLength = view.getUint32(
        actionRandomnessStoredRecordMagic.byteLength + 2,
        true,
    );
    if (
        version !== actionRandomnessStoredRecordVersion ||
        envelopeByteLength !== bytes.byteLength - fixedByteLength
    ) {
        throw new WebLockOwnedStorageError(
            'OpenFailed',
            'The retained action-randomness record has a non-canonical length or version.',
        );
    }
    return Object.freeze({
        actionRandomnessCommitment: bytes.slice(
            headerByteLength,
            fixedByteLength,
        ),
        canonicalEnvelope: bytes.slice(fixedByteLength),
    });
};

const copyFoundationFreshnessCoordinate = (input: {
    foundationTransitionBase: bigint;
    snapshot: UntrustedStorageAuthenticatedHeadSnapshot;
}): BrowserFoundationFreshnessCoordinate => {
    if (input.snapshot.namespaceSequence < input.foundationTransitionBase) {
        throw new WebLockOwnedStorageError(
            'OpenFailed',
            'The authenticated storage sequence precedes foundation initialization.',
        );
    }
    return Object.freeze({
        authenticatedHeadDigest: input.snapshot.authenticatedHeadDigest.slice(),
        freshnessSequence:
            input.snapshot.namespaceSequence - input.foundationTransitionBase,
        storageInstanceIdentity: input.snapshot.storageInstanceIdentity.slice(),
    });
};

const encodeRuntimeRecordProtectedPlaintext = (input: {
    associatedData: Uint8Array;
    plaintext: Uint8Array;
}): Uint8Array => {
    const headerByteLength =
        runtimeRecordProtectedPlaintextMagic.byteLength + 2 + 4;
    const encodedByteLength =
        headerByteLength +
        input.associatedData.byteLength +
        input.plaintext.byteLength;
    if (
        !Number.isSafeInteger(encodedByteLength) ||
        input.associatedData.byteLength > 0xffff_ffff ||
        encodedByteLength > 0xffff_ffff
    ) {
        throw new WebLockOwnedStorageError(
            'OpenFailed',
            'Root-backed runtime-record plaintext exceeds its canonical length profile.',
        );
    }
    const encoded = new Uint8Array(encodedByteLength);
    encoded.set(runtimeRecordProtectedPlaintextMagic, 0);
    const view = new DataView(encoded.buffer);
    view.setUint16(
        runtimeRecordProtectedPlaintextMagic.byteLength,
        runtimeRecordProtectedPlaintextVersion,
        true,
    );
    view.setUint32(
        runtimeRecordProtectedPlaintextMagic.byteLength + 2,
        input.associatedData.byteLength,
        true,
    );
    encoded.set(input.associatedData, headerByteLength);
    encoded.set(
        input.plaintext,
        headerByteLength + input.associatedData.byteLength,
    );
    return encoded;
};

const openRuntimeRecordProtectedPlaintext = (input: {
    associatedData: Uint8Array;
    openedPlaintext: Uint8Array;
}): Uint8Array => {
    const headerByteLength =
        runtimeRecordProtectedPlaintextMagic.byteLength + 2 + 4;
    if (input.openedPlaintext.byteLength < headerByteLength) {
        throw new WebLockOwnedStorageError(
            'OpenFailed',
            'Root-backed runtime-record plaintext is truncated.',
        );
    }
    const view = new DataView(
        input.openedPlaintext.buffer,
        input.openedPlaintext.byteOffset,
        input.openedPlaintext.byteLength,
    );
    const associatedDataByteLength = view.getUint32(
        runtimeRecordProtectedPlaintextMagic.byteLength + 2,
        true,
    );
    const plaintextOffset = headerByteLength + associatedDataByteLength;
    if (
        !bytesEqual(
            input.openedPlaintext.subarray(
                0,
                runtimeRecordProtectedPlaintextMagic.byteLength,
            ),
            runtimeRecordProtectedPlaintextMagic,
        ) ||
        view.getUint16(
            runtimeRecordProtectedPlaintextMagic.byteLength,
            true,
        ) !== runtimeRecordProtectedPlaintextVersion ||
        plaintextOffset > input.openedPlaintext.byteLength ||
        !bytesEqual(
            input.openedPlaintext.subarray(headerByteLength, plaintextOffset),
            input.associatedData,
        )
    ) {
        throw new WebLockOwnedStorageError(
            'OpenFailed',
            'Root-backed runtime-record associated data is malformed or mismatched.',
        );
    }
    return input.openedPlaintext.slice(plaintextOffset);
};

const openFoundationWitnessProtectedEnvelope = async (input: {
    actionRandomnessCommitment: Uint8Array;
    authorizedEmptyPlaintext: Uint8Array;
    canonicalEnvelope: Uint8Array;
    expectedAssociatedData?: Uint8Array;
    stateKey: Uint8Array;
    workerKernel: BrowserActionStorageWorkerKernel;
}): Promise<Uint8Array> => {
    if (!isFoundationWitnessRuntimeRecordEnvelope(input.canonicalEnvelope)) {
        const openedPlaintext = await input.workerKernel.openActiveLocalRecord({
            actionRandomnessCommitment:
                input.actionRandomnessCommitment.slice(),
            envelope: input.canonicalEnvelope.slice(),
            identifierInput: {
                recordType: 'witnessState',
                stateKey: input.stateKey.slice(),
            },
            recordVersion: 0n,
        });
        try {
            if (!bytesEqual(openedPlaintext, input.authorizedEmptyPlaintext)) {
                throw new WebLockOwnedStorageError(
                    'OpenFailed',
                    'An unframed foundation witness record is not the exact authorized genesis value.',
                );
            }
            return foundationWitnessAuthorizedEmptyRecord.slice();
        } finally {
            openedPlaintext.fill(0);
        }
    }

    const framed = openFoundationWitnessRuntimeRecordEnvelope(
        input.canonicalEnvelope,
    );
    const derivedStateKey = deriveFoundationWitnessRuntimeRecordStateKey({
        associatedData: framed.associatedData,
        baseStateKey: input.stateKey,
    });
    let openedPlaintext: Uint8Array | undefined;
    try {
        if (
            input.expectedAssociatedData !== undefined &&
            !bytesEqual(framed.associatedData, input.expectedAssociatedData)
        ) {
            throw new WebLockOwnedStorageError(
                'OpenFailed',
                'The foundation witness runtime-record associated data was substituted.',
            );
        }
        openedPlaintext = await input.workerKernel.openActiveLocalRecord({
            actionRandomnessCommitment:
                input.actionRandomnessCommitment.slice(),
            envelope: framed.innerCanonicalEnvelope.slice(),
            identifierInput: {
                recordType: 'witnessState',
                stateKey: derivedStateKey,
            },
            ...(framed.predecessorRecordHash === undefined
                ? {}
                : {
                      predecessorRecordHash:
                          framed.predecessorRecordHash.slice(),
                  }),
            recordVersion: framed.recordVersion,
        });
        return openRuntimeRecordProtectedPlaintext({
            associatedData:
                input.expectedAssociatedData ?? framed.associatedData,
            openedPlaintext,
        });
    } finally {
        derivedStateKey.fill(0);
        openedPlaintext?.fill(0);
        destroyOpenedFoundationWitnessRuntimeRecordEnvelope(framed);
    }
};

const assertDatabaseName = (databaseName: string): Uint8Array => {
    const databaseNameBytes = textEncoder.encode(databaseName);
    if (
        databaseNameBytes.byteLength === 0 ||
        databaseNameBytes.byteLength > maximumDatabaseNameByteLength
    ) {
        throw new WebLockOwnedStorageError(
            'InvalidConfiguration',
            `databaseName must encode between 1 and ${maximumDatabaseNameByteLength} UTF-8 bytes.`,
        );
    }

    return databaseNameBytes;
};

const assertNamespace = (namespace: string): Uint8Array => {
    if (namespace.length > 64 || !namespacePattern.test(namespace)) {
        throw new WebLockOwnedStorageError(
            'InvalidConfiguration',
            'storage namespace must be lowercase kebab-case with at most 64 characters.',
        );
    }

    return textEncoder.encode(namespace);
};

/**
 * Returns a collision-free lock name for the bounded database and namespace
 * byte strings. Encoding both fields prevents one namespace from blocking an
 * unrelated IndexedDB database while preserving same-origin coordination.
 */
export const deriveWebLockStorageNamespaceName = (input: {
    databaseName: string;
    namespace: string;
}): string => {
    const databaseNameBytes = assertDatabaseName(input.databaseName);
    const namespaceBytes = assertNamespace(input.namespace);

    return `${lockNamePrefix}${bytesToHex(databaseNameBytes)}-${bytesToHex(
        namespaceBytes,
    )}`;
};

const normalizeError = (
    error: unknown,
    code: WebLockOwnedStorageErrorCode,
    message: string,
): WebLockOwnedStorageError =>
    error instanceof WebLockOwnedStorageError
        ? error
        : new WebLockOwnedStorageError(code, message, error);

class OwnedStorageTransactionStore implements WebLockOwnedStorageTransactionStore {
    readonly #adapter: IndexedDbUntrustedStorageAdapter;
    readonly #attachedCustodies = new Set<BrowserActionStorageCustody>();
    readonly #namespace: string;
    readonly #releaseLock: Deferred<void>;
    #lockRequestCompletion: Promise<void> | undefined;
    #closePromise: Promise<void> | undefined;
    #state: WebLockOwnedStorageState = 'open';
    #repairReport: UntrustedStorageRepairReport | undefined;
    #store: UntrustedStorageTransactionStore | undefined;

    public constructor(input: {
        adapter: IndexedDbUntrustedStorageAdapter;
        namespace: string;
        repairReport?: UntrustedStorageRepairReport;
        releaseLock: Deferred<void>;
        store?: UntrustedStorageTransactionStore;
    }) {
        this.#adapter = input.adapter;
        this.#namespace = input.namespace;
        this.#releaseLock = input.releaseLock;
        this.#repairReport = input.repairReport;
        this.#store = input.store;
    }

    public get repairReport(): UntrustedStorageRepairReport {
        if (this.#repairReport === undefined) {
            throw new WebLockOwnedStorageError(
                'OpenFailed',
                'Authenticated browser storage is not active.',
            );
        }
        return this.#repairReport;
    }

    public get store(): UntrustedStorageTransactionStore {
        if (this.#store === undefined) {
            throw new WebLockOwnedStorageError(
                'OpenFailed',
                'Authenticated browser storage is not active.',
            );
        }
        return this.#store;
    }

    public async activateAuthenticatedStore(input: {
        authenticatedRepairProtection: UntrustedStorageAuthenticatedRepairProtection;
        limits: UntrustedStorageTransactionLimits;
    }): Promise<UntrustedStorageRepairReport> {
        if (this.#state !== 'open' || this.#store !== undefined) {
            throw new WebLockOwnedStorageError(
                'OpenFailed',
                'Authenticated browser storage can be activated exactly once while ownership is open.',
            );
        }
        const openedStore = await openUntrustedStorageTransactionStore({
            adapter: this.#adapter,
            authenticatedRepairProtection: input.authenticatedRepairProtection,
            limits: input.limits,
            namespace: this.#namespace,
        });
        if (this.#state !== 'open' || this.#store !== undefined) {
            throw new WebLockOwnedStorageError(
                'LockCallbackExited',
                'Exclusive browser storage ownership ended during authenticated activation.',
            );
        }
        this.#repairReport = openedStore.repairReport;
        this.#store = openedStore.store;
        return openedStore.repairReport;
    }

    public async openAuthenticatedAuxiliaryStore(input: {
        authenticatedRepairProtection: UntrustedStorageAuthenticatedRepairProtection;
        limits: UntrustedStorageTransactionLimits;
        namespace: string;
    }): Promise<UntrustedStorageTransactionStoreOpenResult> {
        assertNamespace(input.namespace);
        if (
            this.#state !== 'open' ||
            this.#store === undefined ||
            input.namespace === this.#namespace
        ) {
            throw new WebLockOwnedStorageError(
                'OpenFailed',
                'An auxiliary authenticated store requires active exclusive ownership and a distinct namespace.',
            );
        }
        const openedStore = await openUntrustedStorageTransactionStore({
            adapter: this.#adapter,
            authenticatedRepairProtection: input.authenticatedRepairProtection,
            limits: input.limits,
            namespace: input.namespace,
        });
        if (this.#state !== 'open') {
            throw new WebLockOwnedStorageError(
                'LockCallbackExited',
                'Exclusive browser storage ownership ended while an auxiliary authenticated store opened.',
            );
        }
        return openedStore;
    }

    public attachBrowserActionStorageCustody(input: {
        binding: BrowserActionStorageRootBinding;
        cryptoProvider?: Crypto;
        knownStorageRootCommitment?: Uint8Array;
        workerKernel: BrowserActionStorageWorkerKernel;
    }): BrowserActionStorageCustodyForOwnedWorker {
        if (this.#state !== 'open') {
            throw new WebLockOwnedStorageError(
                'OpenFailed',
                'Browser action-storage custody cannot be attached after ownership closes.',
            );
        }
        const custody = createBrowserActionStorageCustodyForOwnedWorker({
            assertExclusiveOwnership: () => {
                if (this.#state !== 'open') {
                    throw new WebLockOwnedStorageError(
                        'LockCallbackExited',
                        'Exclusive browser storage ownership is no longer held.',
                    );
                }
            },
            binding: input.binding,
            cryptoProvider: input.cryptoProvider,
            knownStorageRootCommitment: input.knownStorageRootCommitment,
            storage: this.#adapter.createDeviceWrappingStateStorage({
                binding: input.binding,
                namespace: this.#namespace,
            }),
            workerKernel: input.workerKernel,
        });
        this.#attachedCustodies.add(custody);

        return custody;
    }

    public attachLockRequestCompletion(completion: Promise<void>): void {
        if (this.#lockRequestCompletion !== undefined) {
            throw new WebLockOwnedStorageError(
                'OpenFailed',
                'Web Lock request completion was attached more than once.',
            );
        }
        this.#lockRequestCompletion = completion;
    }

    public waitForRelease(): Promise<void> {
        return this.#releaseLock.promise;
    }

    public state(): WebLockOwnedStorageState {
        return this.#state;
    }

    public close(): Promise<void> {
        if (this.#closePromise !== undefined) {
            return this.#closePromise;
        }
        if (this.#state === 'closed') {
            return Promise.resolve();
        }
        if (this.#lockRequestCompletion === undefined) {
            return Promise.reject(
                new WebLockOwnedStorageError(
                    'OpenFailed',
                    'Web Lock request completion is unavailable during close.',
                ),
            );
        }

        this.#state = 'closing';
        this.#closePromise = (async () => {
            const closeFailures: unknown[] = [];
            try {
                await this.#closeAttachedCustodies();
            } catch (error) {
                closeFailures.push(error);
            }
            const adapterClose = this.#adapter.close();
            this.#releaseLock.resolve(undefined);
            try {
                await this.#lockRequestCompletion;
            } catch (error) {
                closeFailures.push(error);
            }
            try {
                await adapterClose;
            } catch (error) {
                closeFailures.push(error);
            }
            if (closeFailures.length === 0) {
                this.#state = 'closed';
                return;
            }
            this.#state = 'failed';
            throw closeFailures.length === 1
                ? normalizeError(
                      closeFailures[0],
                      'LockCallbackExited',
                      'The Web Lock callback exited before an orderly close completed.',
                  )
                : new WebLockOwnedStorageError(
                      'LockCallbackExited',
                      'Multiple failures occurred while closing exclusive browser storage ownership.',
                      closeFailures,
                  );
        })();
        void this.#closePromise.catch(() => undefined);

        return this.#closePromise;
    }

    public fail(error: WebLockOwnedStorageError): void {
        if (this.#state === 'closed' || this.#state === 'failed') {
            return;
        }
        this.#state = 'failed';
        const lockRequestCompletion = this.#lockRequestCompletion;
        this.#closePromise ??= (async () => {
            const failures: unknown[] = [error];
            try {
                await this.#closeAttachedCustodies();
            } catch (closeError) {
                failures.push(closeError);
            }
            const adapterClose = this.#adapter.close();
            this.#releaseLock.resolve(undefined);
            if (lockRequestCompletion !== undefined) {
                try {
                    await lockRequestCompletion;
                } catch (completionError) {
                    if (completionError !== error) {
                        failures.push(completionError);
                    }
                }
            }
            try {
                await adapterClose;
            } catch (adapterCloseError) {
                failures.push(adapterCloseError);
            }
            throw failures.length === 1
                ? error
                : new WebLockOwnedStorageError(
                      'LockCallbackExited',
                      'Exclusive storage ownership failed with additional completion or cleanup failures.',
                      failures,
                  );
        })();
        void this.#closePromise.catch(() => undefined);
    }

    public noteLockCallbackExit(): void {
        if (this.#state !== 'open') {
            return;
        }
        this.fail(
            new WebLockOwnedStorageError(
                'LockCallbackExited',
                'The Web Lock callback exited while the storage handle was open.',
            ),
        );
    }

    async #closeAttachedCustodies(): Promise<void> {
        const closeOutcomes = await Promise.allSettled(
            [...this.#attachedCustodies].map((custody) => custody.close()),
        );
        this.#attachedCustodies.clear();
        const failures = closeOutcomes
            .filter(
                (outcome): outcome is PromiseRejectedResult =>
                    outcome.status === 'rejected',
            )
            .map((outcome) => outcome.reason as unknown);
        if (failures.length > 0) {
            throw new WebLockOwnedStorageError(
                'LockCallbackExited',
                'One or more browser action-storage custody roots could not be destroyed.',
                failures,
            );
        }
    }
}

const resolveLockManager = (
    configuredLockManager: LockManager | null | undefined,
): LockManager => {
    const lockManager =
        configuredLockManager === undefined
            ? globalThis.navigator?.locks
            : configuredLockManager;
    if (lockManager === undefined || lockManager === null) {
        throw new WebLockOwnedStorageError(
            'Unavailable',
            'The Web Locks API is required for exclusive browser storage repair.',
        );
    }

    return lockManager;
};

const createAcquisitionAbortController = (configuration: {
    acquisitionDeadlineEpochMilliseconds?: number;
    acquisitionSignal?: AbortSignal;
}): Readonly<{
    controller: AbortController;
    dispose(): void;
}> => {
    const controller = new AbortController();
    const externalSignal = configuration.acquisitionSignal;
    let deadlineTimer: ReturnType<typeof setTimeout> | undefined;
    let remainingDeadlineMilliseconds: number | undefined;
    const deadline = configuration.acquisitionDeadlineEpochMilliseconds;
    if (deadline !== undefined) {
        if (!Number.isSafeInteger(deadline) || deadline < 0) {
            throw new WebLockOwnedStorageError(
                'InvalidConfiguration',
                'acquisitionDeadlineEpochMilliseconds must be a non-negative safe integer.',
            );
        }
        remainingDeadlineMilliseconds = deadline - Date.now();
        if (
            remainingDeadlineMilliseconds >
            maximumLockAcquisitionDelayMilliseconds
        ) {
            throw new WebLockOwnedStorageError(
                'InvalidConfiguration',
                `the acquisition deadline must be within ${maximumLockAcquisitionDelayMilliseconds} milliseconds.`,
            );
        }
    }
    const abortForExternalSignal = (): void => {
        controller.abort(
            new WebLockOwnedStorageError(
                'AcquisitionCancelled',
                'Web Lock storage acquisition was cancelled while queued.',
                externalSignal?.reason,
            ),
        );
    };

    if (externalSignal?.aborted === true) {
        abortForExternalSignal();
    } else {
        externalSignal?.addEventListener('abort', abortForExternalSignal, {
            once: true,
        });
    }

    if (remainingDeadlineMilliseconds !== undefined) {
        const abortForDeadline = (): void => {
            controller.abort(
                new WebLockOwnedStorageError(
                    'AcquisitionDeadlineExceeded',
                    'Web Lock storage acquisition exceeded its deadline while queued.',
                ),
            );
        };
        if (remainingDeadlineMilliseconds <= 0) {
            abortForDeadline();
        } else {
            deadlineTimer = setTimeout(
                abortForDeadline,
                remainingDeadlineMilliseconds,
            );
        }
    }

    return {
        controller,
        dispose: () => {
            externalSignal?.removeEventListener(
                'abort',
                abortForExternalSignal,
            );
            if (deadlineTimer !== undefined) {
                clearTimeout(deadlineTimer);
                deadlineTimer = undefined;
            }
        },
    };
};

const normalizeLockRequestFailure = (
    error: unknown,
    acquisitionSignal: AbortSignal,
): WebLockOwnedStorageError => {
    if (error instanceof WebLockOwnedStorageError) {
        return error;
    }
    if (acquisitionSignal.reason instanceof WebLockOwnedStorageError) {
        return acquisitionSignal.reason;
    }

    return new WebLockOwnedStorageError(
        'LockCallbackExited',
        'The exclusive Web Lock request failed.',
        error,
    );
};

const openWebLockOwnedStorageTransactionStoreWithFactory = async (
    configuration: WebLockOwnedStorageBaseConfiguration,
    openTransactionStore: (
        adapter: UntrustedStorageAdapter,
    ) => Promise<UntrustedStorageTransactionStoreOpenResult | undefined>,
): Promise<WebLockOwnedStorageTransactionStore> => {
    const lockName = deriveWebLockStorageNamespaceName(configuration);
    const lockManager = resolveLockManager(configuration.lockManager);
    const acquisition = createAcquisitionAbortController(configuration);
    if (acquisition.controller.signal.aborted) {
        acquisition.dispose();
        throw normalizeLockRequestFailure(
            acquisition.controller.signal.reason,
            acquisition.controller.signal,
        );
    }

    const acquiredHandle =
        createDeferred<WebLockOwnedStorageTransactionStore>();
    let activeAdapter: IndexedDbUntrustedStorageAdapter | undefined;
    let lockRequestFailure: WebLockOwnedStorageError | undefined;
    let lockWasGranted = false;
    let ownedHandle: OwnedStorageTransactionStore | undefined;
    let lockRequestCompletion: Promise<void> | undefined;
    const assertLockRequestStillHeld = (): void => {
        const failure = lockRequestFailure;
        if (failure !== undefined) {
            throw failure;
        }
    };
    try {
        lockRequestCompletion = lockManager.request(
            lockName,
            {
                mode: 'exclusive',
                signal: acquisition.controller.signal,
            },
            async (lock) => {
                lockWasGranted = true;
                acquisition.dispose();
                if (lock?.name !== lockName || lock.mode !== 'exclusive') {
                    throw new WebLockOwnedStorageError(
                        'OpenFailed',
                        'The Web Locks API did not grant the requested exclusive namespace lock.',
                    );
                }
                let adapter: IndexedDbUntrustedStorageAdapter | undefined;
                try {
                    adapter = await openIndexedDbUntrustedStorageAdapter({
                        databaseName: configuration.databaseName,
                        indexedDbFactory: configuration.indexedDbFactory,
                        keyRangeFactory: configuration.keyRangeFactory,
                    });
                    activeAdapter = adapter;
                    assertLockRequestStillHeld();
                    const openedStore = await openTransactionStore(adapter);
                    assertLockRequestStillHeld();
                    const releaseLock = createDeferred<void>();
                    ownedHandle = new OwnedStorageTransactionStore({
                        adapter,
                        namespace: configuration.namespace,
                        repairReport: openedStore?.repairReport,
                        releaseLock,
                        store: openedStore?.store,
                    });
                    if (lockRequestCompletion === undefined) {
                        throw new WebLockOwnedStorageError(
                            'OpenFailed',
                            'The Web Lock request was not initialized before acquisition.',
                        );
                    }
                    ownedHandle.attachLockRequestCompletion(
                        lockRequestCompletion,
                    );
                    acquiredHandle.resolve(ownedHandle);
                    await ownedHandle.waitForRelease();
                } catch (error) {
                    const openFailure = normalizeError(
                        error,
                        'OpenFailed',
                        'Opening the exclusively owned browser storage failed.',
                    );
                    acquiredHandle.reject(openFailure);
                    throw openFailure;
                } finally {
                    if (adapter !== undefined) {
                        await adapter.close();
                    }
                    if (activeAdapter === adapter) {
                        activeAdapter = undefined;
                    }
                    ownedHandle?.noteLockCallbackExit();
                }
            },
        );
    } catch (error) {
        acquisition.dispose();
        throw normalizeError(
            error,
            'OpenFailed',
            'Submitting the exclusive Web Lock request failed.',
        );
    }

    void lockRequestCompletion.catch((error: unknown) => {
        acquisition.dispose();
        const failure = lockWasGranted
            ? normalizeError(
                  error,
                  'LockCallbackExited',
                  'The exclusive Web Lock request failed after acquisition.',
              )
            : normalizeLockRequestFailure(error, acquisition.controller.signal);
        lockRequestFailure = failure;
        acquiredHandle.reject(failure);
        if (ownedHandle === undefined) {
            void activeAdapter?.close();
        } else {
            ownedHandle.fail(failure);
        }
    });

    return acquiredHandle.promise;
};

export const openWebLockOwnedStorageTransactionStore = async (
    configuration: WebLockOwnedStorageConfiguration,
): Promise<TransferableWebLockOwnedStorageTransactionStore> => {
    const ownedStorage =
        await openWebLockOwnedStorageTransactionStoreWithFactory(
            configuration,
            (adapter) =>
                openUntrustedStorageTransactionStore({
                    adapter,
                    authenticatedRepairProtection:
                        configuration.authenticatedRepairProtection,
                    limits: configuration.limits,
                    namespace: configuration.namespace,
                }),
        );
    const lifecycle = new ExclusiveResourceLifecycle({
        cleanup: () => ownedStorage.close(),
        createInvalidStateError: (message) =>
            new WebLockOwnedStorageError('Unavailable', message),
    });
    const createOwnedView = (
        owner: ExclusiveResourceOwnerToken,
    ): WebLockOwnedStorageTransactionStore =>
        Object.freeze({
            close: () => lifecycle.close(owner),
            get repairReport(): UntrustedStorageRepairReport {
                lifecycle.assertOpen(owner);
                return ownedStorage.repairReport;
            },
            state: () => {
                lifecycle.assertOwner(owner);
                return ownedStorage.state();
            },
            get store(): UntrustedStorageTransactionStore {
                lifecycle.assertOpen(owner);
                return ownedStorage.store;
            },
        });
    const initialOwner = lifecycle.initialOwner();
    const initialView = createOwnedView(initialOwner);
    return Object.freeze({
        claimExclusiveOwner: () =>
            createOwnedView(lifecycle.claim(initialOwner)),
        close: initialView.close,
        get repairReport(): UntrustedStorageRepairReport {
            return initialView.repairReport;
        },
        state: initialView.state,
        get store(): UntrustedStorageTransactionStore {
            return initialView.store;
        },
    });
};

/**
 * Opens browser action-storage custody inside a dedicated worker and retains
 * its IndexedDB connection and cryptographic kernel under one exclusive Web
 * Lock. The returned surface contains no generic storage adapter or key-bearing
 * state.
 */
export const openWebLockOwnedBrowserActionStorageCustody = async (
    configuration: WebLockOwnedBrowserActionStorageCustodyConfiguration,
): Promise<WebLockOwnedBrowserActionStorageCustody> => {
    if (typeof globalThis.document !== 'undefined') {
        throw new WebLockOwnedStorageError(
            'Unavailable',
            'Browser action-storage custody must be opened inside a dedicated worker.',
        );
    }
    const ownedStorage =
        await openWebLockOwnedStorageTransactionStoreWithFactory(
            configuration,
            () => Promise.resolve(undefined),
        );
    if (!(ownedStorage instanceof OwnedStorageTransactionStore)) {
        await ownedStorage.close();
        throw new WebLockOwnedStorageError(
            'OpenFailed',
            'The exclusive storage owner could not attach browser action-storage custody.',
        );
    }
    try {
        const custody = ownedStorage.attachBrowserActionStorageCustody({
            binding: configuration.binding,
            cryptoProvider: configuration.cryptoProvider,
            knownStorageRootCommitment:
                configuration.knownStorageRootCommitment,
            workerKernel: configuration.workerKernel,
        });
        if (
            !(configuration.runtimeBuildManifestHash instanceof Uint8Array) ||
            configuration.runtimeBuildManifestHash.byteLength !==
                foundationHashByteLength
        ) {
            throw new WebLockOwnedStorageError(
                'InvalidConfiguration',
                `runtimeBuildManifestHash must contain exactly ${String(foundationHashByteLength)} bytes.`,
            );
        }
        const runtimeBuildManifestHash =
            configuration.runtimeBuildManifestHash.slice();
        let activationAttempted = false;
        let authenticatedStoreActive = false;
        let foundationTransitionBase: bigint | undefined;
        let foundationInitializationAttempted = false;
        let repairProtectionSessionIdentifier: string | undefined;
        let checkpointStoreOpeningAttempted = false;
        const runtimeRecordRepairProtectionSessionIdentifiers =
            new Set<string>();
        let closePromise: Promise<void> | undefined;
        const closeCombinedOwner = (): Promise<void> => {
            closePromise ??= (async () => {
                const cleanupFailures: unknown[] = [];
                const runtimeRecordProtectionCloseOutcomes =
                    await Promise.allSettled(
                        [
                            ...runtimeRecordRepairProtectionSessionIdentifiers,
                        ].map((identifier) =>
                            configuration.workerKernel.closeAuthenticatedRepairProtection(
                                identifier,
                            ),
                        ),
                    );
                runtimeRecordRepairProtectionSessionIdentifiers.clear();
                for (const outcome of runtimeRecordProtectionCloseOutcomes) {
                    if (outcome.status === 'rejected') {
                        cleanupFailures.push(outcome.reason as unknown);
                    }
                }
                if (repairProtectionSessionIdentifier !== undefined) {
                    const identifier = repairProtectionSessionIdentifier;
                    repairProtectionSessionIdentifier = undefined;
                    try {
                        await configuration.workerKernel.closeAuthenticatedRepairProtection(
                            identifier,
                        );
                    } catch (error) {
                        cleanupFailures.push(error);
                    }
                }
                runtimeBuildManifestHash.fill(0);
                try {
                    await ownedStorage.close();
                } catch (error) {
                    cleanupFailures.push(error);
                }
                if (cleanupFailures.length === 1) {
                    throw cleanupFailures[0];
                }
                if (cleanupFailures.length > 1) {
                    throw new WebLockOwnedStorageError(
                        'LockCallbackExited',
                        'Closing combined browser foundation storage ownership produced multiple failures.',
                        cleanupFailures,
                    );
                }
            })();
            return closePromise;
        };

        const createFoundationWitnessRecordProtection = (
            record: WebLockFoundationWitnessRecord,
        ): RuntimeRecordProtection => {
            if (
                record.actionRandomnessCommitment.byteLength !==
                    foundationHashByteLength ||
                record.stateKey.byteLength !== foundationHashByteLength ||
                record.authorizedEmptyPlaintext.byteLength === 0
            ) {
                throw new WebLockOwnedStorageError(
                    'OpenFailed',
                    'A worker-owned foundation witness record has malformed cryptographic bindings.',
                );
            }
            const actionRandomnessCommitment =
                record.actionRandomnessCommitment.slice();
            const stateKey = record.stateKey.slice();
            const authorizedEmptyPlaintext =
                record.authorizedEmptyPlaintext.slice();
            const lastSealedRecordCoordinateByDerivedStateKey = new Map<
                string,
                Readonly<{
                    innerCanonicalEnvelopeHash: Uint8Array;
                    recordVersion: bigint;
                }>
            >();
            let closed = false;
            const assertOpen = (): void => {
                if (closed || ownedStorage.state() !== 'open') {
                    throw new WebLockOwnedStorageError(
                        'OpenFailed',
                        'The worker-owned foundation witness record protection is closed.',
                    );
                }
            };
            const session: RuntimeRecordProtectionSession = Object.freeze({
                close: () => {
                    if (closed) {
                        return;
                    }
                    closed = true;
                    actionRandomnessCommitment.fill(0);
                    stateKey.fill(0);
                    authorizedEmptyPlaintext.fill(0);
                    for (const coordinate of lastSealedRecordCoordinateByDerivedStateKey.values()) {
                        coordinate.innerCanonicalEnvelopeHash.fill(0);
                    }
                    lastSealedRecordCoordinateByDerivedStateKey.clear();
                },
                openCanonicalEnvelope: async (recordInput) => {
                    assertOpen();
                    return openFoundationWitnessProtectedEnvelope({
                        actionRandomnessCommitment,
                        authorizedEmptyPlaintext,
                        canonicalEnvelope: recordInput.canonicalEnvelope,
                        expectedAssociatedData: recordInput.associatedData,
                        stateKey,
                        workerKernel: configuration.workerKernel,
                    });
                },
                sampleIdentifier: (identifierInput) => {
                    assertOpen();
                    const cryptoProvider =
                        configuration.cryptoProvider ?? globalThis.crypto;
                    if (cryptoProvider?.getRandomValues === undefined) {
                        throw new WebLockOwnedStorageError(
                            'Unavailable',
                            'Secure randomness is unavailable for witness record protection.',
                        );
                    }
                    const identifier = new Uint8Array(
                        identifierInput.byteLength,
                    );
                    cryptoProvider.getRandomValues(identifier);
                    return identifier;
                },
                sealPlaintext: async (recordInput) => {
                    assertOpen();
                    const encodedPlaintext =
                        encodeRuntimeRecordProtectedPlaintext({
                            associatedData: recordInput.associatedData,
                            plaintext: recordInput.plaintext,
                        });
                    const derivedStateKey =
                        deriveFoundationWitnessRuntimeRecordStateKey({
                            associatedData: recordInput.associatedData,
                            baseStateKey: stateKey,
                        });
                    let predecessorRecordHash: Uint8Array | undefined;
                    let predecessorInnerCanonicalEnvelope:
                        | Uint8Array
                        | undefined;
                    let predecessorOpened:
                        | OpenedFoundationWitnessRuntimeRecordEnvelope
                        | undefined;
                    let innerCanonicalEnvelope: Uint8Array | undefined;
                    try {
                        let candidateRecordVersion = 0n;
                        if (
                            recordInput.predecessorCanonicalEnvelope !==
                            undefined
                        ) {
                            const authenticatedPredecessor =
                                await openFoundationWitnessProtectedEnvelope({
                                    actionRandomnessCommitment,
                                    authorizedEmptyPlaintext,
                                    canonicalEnvelope:
                                        recordInput.predecessorCanonicalEnvelope,
                                    expectedAssociatedData:
                                        recordInput.associatedData,
                                    stateKey,
                                    workerKernel: configuration.workerKernel,
                                });
                            authenticatedPredecessor.fill(0);
                            if (
                                isFoundationWitnessRuntimeRecordEnvelope(
                                    recordInput.predecessorCanonicalEnvelope,
                                )
                            ) {
                                predecessorOpened =
                                    openFoundationWitnessRuntimeRecordEnvelope(
                                        recordInput.predecessorCanonicalEnvelope,
                                    );
                                if (
                                    !bytesEqual(
                                        predecessorOpened.associatedData,
                                        recordInput.associatedData,
                                    ) ||
                                    predecessorOpened.recordVersion ===
                                        maximumUnsigned64
                                ) {
                                    throw new WebLockOwnedStorageError(
                                        'OpenFailed',
                                        'The predecessor foundation witness runtime-record coordinate is invalid.',
                                    );
                                }
                                candidateRecordVersion =
                                    predecessorOpened.recordVersion + 1n;
                                predecessorInnerCanonicalEnvelope =
                                    predecessorOpened.innerCanonicalEnvelope.slice();
                            } else {
                                candidateRecordVersion = 1n;
                                predecessorInnerCanonicalEnvelope =
                                    recordInput.predecessorCanonicalEnvelope.slice();
                            }
                            predecessorRecordHash =
                                await configuration.workerKernel.hashActiveLocalRecordEnvelope(
                                    predecessorInnerCanonicalEnvelope,
                                );
                            if (
                                predecessorRecordHash.byteLength !==
                                foundationHashByteLength
                            ) {
                                throw new WebLockOwnedStorageError(
                                    'OpenFailed',
                                    'The worker returned a malformed foundation witness predecessor hash.',
                                );
                            }
                        }
                        const derivedStateKeyIdentifier =
                            bytesToHex(derivedStateKey);
                        const lastSealedRecordCoordinate =
                            lastSealedRecordCoordinateByDerivedStateKey.get(
                                derivedStateKeyIdentifier,
                            );
                        if (
                            lastSealedRecordCoordinate !== undefined &&
                            candidateRecordVersion <=
                                lastSealedRecordCoordinate.recordVersion
                        ) {
                            if (
                                lastSealedRecordCoordinate.recordVersion ===
                                maximumUnsigned64
                            ) {
                                throw new WebLockOwnedStorageError(
                                    'OpenFailed',
                                    'The foundation witness runtime-record version space is exhausted.',
                                );
                            }
                            candidateRecordVersion =
                                lastSealedRecordCoordinate.recordVersion + 1n;
                            predecessorRecordHash?.fill(0);
                            predecessorRecordHash =
                                lastSealedRecordCoordinate.innerCanonicalEnvelopeHash.slice();
                        }
                        innerCanonicalEnvelope =
                            await configuration.workerKernel.sealActiveLocalRecord(
                                {
                                    actionRandomnessCommitment,
                                    identifierInput: {
                                        recordType: 'witnessState',
                                        stateKey: derivedStateKey,
                                    },
                                    plaintext: encodedPlaintext,
                                    ...(predecessorRecordHash === undefined
                                        ? {}
                                        : {
                                              predecessorRecordHash,
                                          }),
                                    recordVersion: candidateRecordVersion,
                                },
                            );
                        const innerCanonicalEnvelopeHash =
                            await configuration.workerKernel.hashActiveLocalRecordEnvelope(
                                innerCanonicalEnvelope,
                            );
                        if (
                            innerCanonicalEnvelopeHash.byteLength !==
                            foundationHashByteLength
                        ) {
                            innerCanonicalEnvelopeHash.fill(0);
                            throw new WebLockOwnedStorageError(
                                'OpenFailed',
                                'The worker returned a malformed sealed foundation witness record hash.',
                            );
                        }
                        const previousSealedCoordinate =
                            lastSealedRecordCoordinateByDerivedStateKey.get(
                                derivedStateKeyIdentifier,
                            );
                        previousSealedCoordinate?.innerCanonicalEnvelopeHash.fill(
                            0,
                        );
                        lastSealedRecordCoordinateByDerivedStateKey.set(
                            derivedStateKeyIdentifier,
                            {
                                innerCanonicalEnvelopeHash,
                                recordVersion: candidateRecordVersion,
                            },
                        );
                        return encodeFoundationWitnessRuntimeRecordEnvelope({
                            associatedData: recordInput.associatedData,
                            innerCanonicalEnvelope,
                            ...(predecessorRecordHash === undefined
                                ? {}
                                : { predecessorRecordHash }),
                            recordVersion: candidateRecordVersion,
                        });
                    } finally {
                        derivedStateKey.fill(0);
                        encodedPlaintext.fill(0);
                        innerCanonicalEnvelope?.fill(0);
                        predecessorInnerCanonicalEnvelope?.fill(0);
                        predecessorRecordHash?.fill(0);
                        if (predecessorOpened !== undefined) {
                            destroyOpenedFoundationWitnessRuntimeRecordEnvelope(
                                predecessorOpened,
                            );
                        }
                    }
                },
            });
            try {
                return createRuntimeRecordProtectionFromSession({
                    authorityContext: {
                        actionContextHash:
                            configuration.binding.actionContextHash,
                        ceremonyContextHash:
                            configuration.binding.ceremonyContextHash,
                        ownerParticipantIdentity:
                            configuration.binding.participantId,
                        runtimeBuildManifestHash,
                        suiteIdentifier: configuration.binding.suiteId,
                    },
                    session,
                });
            } catch (error) {
                void session.close();
                throw error;
            }
        };

        return Object.freeze({
            authenticateFoundationHead: async () => {
                if (
                    !authenticatedStoreActive ||
                    foundationTransitionBase === undefined
                ) {
                    throw new WebLockOwnedStorageError(
                        'OpenFailed',
                        'The foundation head is unavailable before exact initialization authentication.',
                    );
                }
                return copyFoundationFreshnessCoordinate({
                    foundationTransitionBase,
                    snapshot:
                        await ownedStorage.store.authenticateCurrentHead(),
                });
            },
            close: closeCombinedOwner,
            commitFreshFoundationInitialization: async (preparationInput) => {
                if (
                    !authenticatedStoreActive ||
                    foundationInitializationAttempted
                ) {
                    throw new WebLockOwnedStorageError(
                        'OpenFailed',
                        'Fresh foundation initialization requires one active, unused combined storage owner.',
                    );
                }
                foundationInitializationAttempted = true;
                let actionRandomnessSessionIdentifier: string | undefined;
                let committed = false;
                let preparedMaterial:
                    | ReturnType<
                          typeof takePreparedBrowserFoundationInitializationForAuthenticatedCommit
                      >
                    | undefined;
                let storedActionRandomnessRecord: Uint8Array | undefined;
                let transaction:
                    | Awaited<
                          ReturnType<
                              UntrustedStorageTransactionStore['beginTransaction']
                          >
                      >
                    | undefined;
                try {
                    const predecessorSnapshot =
                        await ownedStorage.store.authenticateCurrentHead();
                    if (predecessorSnapshot.namespaceSequence !== 0n) {
                        throw new WebLockOwnedStorageError(
                            'OpenFailed',
                            'Fresh foundation initialization requires an authenticated empty namespace.',
                        );
                    }
                    const prepared =
                        await custody.prepareBrowserFoundationInitialization(
                            preparationInput,
                        );
                    preparedMaterial =
                        takePreparedBrowserFoundationInitializationForAuthenticatedCommit(
                            prepared,
                        );
                    if (
                        !bytesEqual(
                            preparedMaterial.preparationInput
                                .runtimeBuildManifestHash,
                            runtimeBuildManifestHash,
                        )
                    ) {
                        throw new WebLockOwnedStorageError(
                            'OpenFailed',
                            'Foundation initialization bindings do not match the active root-backed storage instance.',
                        );
                    }
                    actionRandomnessSessionIdentifier =
                        preparedMaterial.workerPreparation.actionRandomness
                            .actionRandomnessSessionIdentifier;
                    storedActionRandomnessRecord =
                        encodeStoredActionRandomnessRecord(
                            preparedMaterial.workerPreparation.actionRandomness,
                        );
                    const actionRandomnessRecord =
                        preparedMaterial.workerPreparation.actionRandomness;
                    const records = [
                        Object.freeze({
                            canonicalEnvelope:
                                actionRandomnessRecord.canonicalEnvelope,
                            envelopeHash: actionRandomnessRecord.envelopeHash,
                            logicalRecordKey: bytesToHex(
                                actionRandomnessRecord.localRecordIdentifier,
                            ),
                            storedBytes: storedActionRandomnessRecord,
                        }),
                        ...preparedMaterial.workerPreparation.witnessStateRecords.map(
                            (record) =>
                                Object.freeze({
                                    canonicalEnvelope: record.canonicalEnvelope,
                                    envelopeHash: record.envelopeHash,
                                    logicalRecordKey: bytesToHex(
                                        record.localRecordIdentifier,
                                    ),
                                    storedBytes: record.canonicalEnvelope,
                                }),
                        ),
                    ];
                    if (
                        records.length !== 10 ||
                        new Set(
                            records.map((record) => record.logicalRecordKey),
                        ).size !== 10
                    ) {
                        throw new WebLockOwnedStorageError(
                            'OpenFailed',
                            'Foundation initialization did not produce ten distinct worker-derived record identifiers.',
                        );
                    }
                    const authenticateExactRecord = async (input: {
                        bytes: Uint8Array;
                        expectedEnvelope: Uint8Array;
                        expectedEnvelopeHash: Uint8Array;
                        expectedLogicalRecordKey: string;
                        expectedStoredBytes: Uint8Array;
                        logicalRecordKey: string;
                    }): Promise<void> => {
                        if (
                            input.logicalRecordKey !==
                                input.expectedLogicalRecordKey ||
                            !bytesEqual(input.bytes, input.expectedStoredBytes)
                        ) {
                            throw new WebLockOwnedStorageError(
                                'OpenFailed',
                                'Foundation initialization record bytes or worker-derived identifier changed during authenticated storage.',
                            );
                        }
                        const observedEnvelopeHash =
                            await configuration.workerKernel.hashActiveLocalRecordEnvelope(
                                input.expectedEnvelope.slice(),
                            );
                        try {
                            if (
                                !bytesEqual(
                                    observedEnvelopeHash,
                                    input.expectedEnvelopeHash,
                                )
                            ) {
                                throw new WebLockOwnedStorageError(
                                    'OpenFailed',
                                    'Foundation initialization envelope authentication failed.',
                                );
                            }
                        } finally {
                            observedEnvelopeHash.fill(0);
                        }
                    };
                    transaction = await ownedStorage.store.beginTransaction({
                        lifetimeMilliseconds:
                            configuration.limits
                                .maximumTransactionLifetimeMilliseconds,
                    });
                    for (const record of records) {
                        const lease = await transaction.issueWriteLease({
                            declaredByteLength: record.storedBytes.byteLength,
                            expectedCurrentValue: null,
                            logicalRecordKey: record.logicalRecordKey,
                        });
                        await lease.write(record.storedBytes);
                        await lease.seal((authenticationInput) =>
                            authenticateExactRecord({
                                ...authenticationInput,
                                expectedEnvelope: record.canonicalEnvelope,
                                expectedEnvelopeHash: record.envelopeHash,
                                expectedLogicalRecordKey:
                                    record.logicalRecordKey,
                                expectedStoredBytes: record.storedBytes,
                            }),
                        );
                    }
                    await transaction.commit();
                    committed = true;
                    for (const record of records) {
                        const readback =
                            await ownedStorage.store.readAuthenticated({
                                authenticate: (authenticationInput) =>
                                    authenticateExactRecord({
                                        ...authenticationInput,
                                        expectedEnvelope:
                                            record.canonicalEnvelope,
                                        expectedEnvelopeHash:
                                            record.envelopeHash,
                                        expectedLogicalRecordKey:
                                            record.logicalRecordKey,
                                        expectedStoredBytes: record.storedBytes,
                                    }),
                                logicalRecordKey: record.logicalRecordKey,
                            });
                        try {
                            if (
                                readback === undefined ||
                                !bytesEqual(readback, record.storedBytes)
                            ) {
                                throw new WebLockOwnedStorageError(
                                    'OpenFailed',
                                    'Foundation initialization exact authenticated readback failed.',
                                );
                            }
                        } finally {
                            readback?.fill(0);
                        }
                    }
                    const successorSnapshot =
                        await ownedStorage.store.authenticateCurrentHead();
                    if (
                        successorSnapshot.namespaceSequence !== 1n ||
                        !bytesEqual(
                            successorSnapshot.storageInstanceIdentity,
                            predecessorSnapshot.storageInstanceIdentity,
                        ) ||
                        bytesEqual(
                            successorSnapshot.authenticatedHeadDigest,
                            predecessorSnapshot.authenticatedHeadDigest,
                        )
                    ) {
                        throw new WebLockOwnedStorageError(
                            'OpenFailed',
                            'Foundation initialization did not produce exactly one authenticated namespace successor.',
                        );
                    }
                    foundationTransitionBase =
                        successorSnapshot.namespaceSequence;
                    return Object.freeze({
                        actionRandomnessCommitment:
                            preparedMaterial.workerPreparation.actionRandomness.actionRandomnessCommitment.slice(),
                        actionRandomnessSessionIdentifier,
                        freshnessCoordinate: copyFoundationFreshnessCoordinate({
                            foundationTransitionBase,
                            snapshot: successorSnapshot,
                        }),
                        orderedWitnessRecords: Object.freeze(
                            preparedMaterial.workerPreparation.witnessStateRecords.map(
                                (record, roleIndex) => {
                                    const binding =
                                        preparedMaterial!.preparationInput
                                            .orderedWitnessBindings[roleIndex];
                                    if (binding === undefined) {
                                        throw new WebLockOwnedStorageError(
                                            'OpenFailed',
                                            'Foundation initialization lost a fixed-roster witness binding.',
                                        );
                                    }
                                    return Object.freeze({
                                        actionRandomnessCommitment:
                                            preparedMaterial!.workerPreparation.actionRandomness.actionRandomnessCommitment.slice(),
                                        authorizedEmptyPlaintext:
                                            record.authorizedEmptyPlaintext.slice(),
                                        localRecordIdentifier:
                                            record.localRecordIdentifier.slice(),
                                        roleIndex,
                                        stateKey: record.stateKey.slice(),
                                        subjectParticipantIdentity:
                                            binding.subjectParticipantIdentity.slice(),
                                        witnessParticipantIdentity:
                                            binding.witnessParticipantIdentity.slice(),
                                    });
                                },
                            ),
                        ),
                    });
                } catch (error) {
                    const cleanupFailures: unknown[] = [];
                    if (transaction !== undefined) {
                        try {
                            await transaction.closeAfterFailure();
                        } catch (cleanupError) {
                            cleanupFailures.push(cleanupError);
                        }
                    }
                    if (actionRandomnessSessionIdentifier !== undefined) {
                        try {
                            await custody.closeActionRandomness(
                                actionRandomnessSessionIdentifier,
                            );
                        } catch (cleanupError) {
                            cleanupFailures.push(cleanupError);
                        }
                    }
                    try {
                        await closeCombinedOwner();
                    } catch (cleanupError) {
                        cleanupFailures.push(cleanupError);
                    }
                    if (cleanupFailures.length > 0) {
                        throw new WebLockOwnedStorageError(
                            'OpenFailed',
                            committed
                                ? 'Foundation initialization committed but exact authentication failed, and retirement also failed.'
                                : 'Foundation initialization failed before authenticated completion, and retirement also failed.',
                            [error, ...cleanupFailures],
                        );
                    }
                    throw normalizeError(
                        error,
                        'OpenFailed',
                        committed
                            ? 'Foundation initialization committed but exact authentication failed; the owner was retired.'
                            : 'Foundation initialization failed before authenticated completion; the owner was retired.',
                    );
                } finally {
                    storedActionRandomnessRecord?.fill(0);
                    if (preparedMaterial !== undefined) {
                        destroyWorkerPreparedBrowserFoundationInitialization(
                            preparedMaterial.workerPreparation,
                        );
                    }
                }
            },
            openRecoveredFoundationInitialization: async (preparationInput) => {
                if (
                    !authenticatedStoreActive ||
                    foundationInitializationAttempted ||
                    foundationTransitionBase !== undefined
                ) {
                    throw new WebLockOwnedStorageError(
                        'OpenFailed',
                        'Recovered foundation initialization requires one active, unused combined storage owner.',
                    );
                }
                foundationInitializationAttempted = true;
                let actionRandomnessSessionIdentifier: string | undefined;
                let derivedRecords:
                    | Awaited<
                          ReturnType<
                              BrowserActionStorageWorkerKernel['deriveBrowserFoundationInitializationRecords']
                          >
                      >
                    | undefined;
                try {
                    const currentSnapshot =
                        await ownedStorage.store.authenticateCurrentHead();
                    if (currentSnapshot.namespaceSequence < 1n) {
                        throw new WebLockOwnedStorageError(
                            'OpenFailed',
                            'Recovered foundation initialization requires a retained authenticated ten-record batch.',
                        );
                    }
                    derivedRecords =
                        await configuration.workerKernel.deriveBrowserFoundationInitializationRecords(
                            preparationInput,
                        );
                    const allRecordKeys = [
                        bytesToHex(
                            derivedRecords.actionRandomnessLocalRecordIdentifier,
                        ),
                        ...derivedRecords.witnessStateRecords.map((record) =>
                            bytesToHex(record.localRecordIdentifier),
                        ),
                    ];
                    if (
                        allRecordKeys.length !== 10 ||
                        new Set(allRecordKeys).size !== 10
                    ) {
                        throw new WebLockOwnedStorageError(
                            'OpenFailed',
                            'Recovered foundation initialization did not derive ten distinct record identifiers.',
                        );
                    }
                    const actionRandomnessLogicalRecordKey = allRecordKeys[0];
                    const actionRandomnessReadback =
                        await ownedStorage.store.readAuthenticated({
                            authenticate: (authenticationInput) => {
                                if (
                                    authenticationInput.logicalRecordKey !==
                                    actionRandomnessLogicalRecordKey
                                ) {
                                    throw new WebLockOwnedStorageError(
                                        'OpenFailed',
                                        'The retained action-randomness record identifier changed.',
                                    );
                                }
                                const opened = openStoredActionRandomnessRecord(
                                    authenticationInput.bytes,
                                );
                                opened.actionRandomnessCommitment.fill(0);
                                opened.canonicalEnvelope.fill(0);
                            },
                            logicalRecordKey: actionRandomnessLogicalRecordKey,
                        });
                    if (actionRandomnessReadback === undefined) {
                        throw new WebLockOwnedStorageError(
                            'OpenFailed',
                            'The retained action-randomness record is unavailable.',
                        );
                    }
                    const storedActionRandomness =
                        openStoredActionRandomnessRecord(
                            actionRandomnessReadback,
                        );
                    actionRandomnessReadback.fill(0);
                    const openedActionRandomness =
                        await custody.openSealedActionRandomness({
                            ...preparationInput.actionRandomnessRecordContext,
                            actionRandomnessCommitment:
                                storedActionRandomness.actionRandomnessCommitment,
                            canonicalEnvelope:
                                storedActionRandomness.canonicalEnvelope,
                        });
                    actionRandomnessSessionIdentifier =
                        openedActionRandomness.actionRandomnessSessionIdentifier;
                    try {
                        if (
                            !bytesEqual(
                                openedActionRandomness.actionRandomnessCommitment,
                                storedActionRandomness.actionRandomnessCommitment,
                            )
                        ) {
                            throw new WebLockOwnedStorageError(
                                'OpenFailed',
                                'The retained action-randomness commitment did not authenticate exactly.',
                            );
                        }
                        const orderedWitnessRecords: WebLockFoundationWitnessRecord[] =
                            [];
                        for (const [
                            roleIndex,
                            derivedRecord,
                        ] of derivedRecords.witnessStateRecords.entries()) {
                            const witnessBinding =
                                preparationInput.orderedWitnessBindings[
                                    roleIndex
                                ];
                            const logicalRecordKey =
                                allRecordKeys[roleIndex + 1];
                            if (
                                witnessBinding === undefined ||
                                logicalRecordKey === undefined ||
                                derivedRecord.roleIndex !== roleIndex
                            ) {
                                throw new WebLockOwnedStorageError(
                                    'OpenFailed',
                                    'Recovered foundation witness records are unordered.',
                                );
                            }
                            const witnessEnvelope =
                                await ownedStorage.store.readAuthenticated({
                                    authenticate: async (
                                        authenticationInput,
                                    ) => {
                                        if (
                                            authenticationInput.logicalRecordKey !==
                                            logicalRecordKey
                                        ) {
                                            throw new WebLockOwnedStorageError(
                                                'OpenFailed',
                                                'A retained witness record identifier changed.',
                                            );
                                        }
                                        // Exact domain and logical-key
                                        // authentication occurs when the
                                        // retained role opens its runtime
                                        // record. Recovery authenticates the
                                        // root-owned envelope and its self-bound
                                        // associated data here.
                                        (
                                            await openFoundationWitnessProtectedEnvelope(
                                                {
                                                    actionRandomnessCommitment:
                                                        openedActionRandomness.actionRandomnessCommitment,
                                                    authorizedEmptyPlaintext:
                                                        derivedRecord.authorizedEmptyPlaintext,
                                                    canonicalEnvelope:
                                                        authenticationInput.bytes,
                                                    stateKey:
                                                        derivedRecord.stateKey,
                                                    workerKernel:
                                                        configuration.workerKernel,
                                                },
                                            )
                                        ).fill(0);
                                    },
                                    logicalRecordKey,
                                });
                            if (witnessEnvelope === undefined) {
                                throw new WebLockOwnedStorageError(
                                    'OpenFailed',
                                    'A retained fixed-roster witness record is unavailable.',
                                );
                            }
                            witnessEnvelope.fill(0);
                            orderedWitnessRecords.push(
                                Object.freeze({
                                    actionRandomnessCommitment:
                                        openedActionRandomness.actionRandomnessCommitment.slice(),
                                    authorizedEmptyPlaintext:
                                        derivedRecord.authorizedEmptyPlaintext.slice(),
                                    localRecordIdentifier:
                                        derivedRecord.localRecordIdentifier.slice(),
                                    roleIndex,
                                    stateKey: derivedRecord.stateKey.slice(),
                                    subjectParticipantIdentity:
                                        witnessBinding.subjectParticipantIdentity.slice(),
                                    witnessParticipantIdentity:
                                        witnessBinding.witnessParticipantIdentity.slice(),
                                }),
                            );
                        }
                        const authenticatedSnapshot =
                            await ownedStorage.store.authenticateCurrentHead();
                        if (
                            authenticatedSnapshot.namespaceSequence < 1n ||
                            !bytesEqual(
                                authenticatedSnapshot.storageInstanceIdentity,
                                currentSnapshot.storageInstanceIdentity,
                            )
                        ) {
                            throw new WebLockOwnedStorageError(
                                'OpenFailed',
                                'The retained foundation batch changed during exact authentication.',
                            );
                        }
                        foundationTransitionBase = 1n;
                        return Object.freeze({
                            actionRandomnessCommitment:
                                openedActionRandomness.actionRandomnessCommitment.slice(),
                            actionRandomnessSessionIdentifier:
                                openedActionRandomness.actionRandomnessSessionIdentifier,
                            freshnessCoordinate:
                                copyFoundationFreshnessCoordinate({
                                    foundationTransitionBase,
                                    snapshot: authenticatedSnapshot,
                                }),
                            orderedWitnessRecords: Object.freeze(
                                orderedWitnessRecords,
                            ),
                        });
                    } finally {
                        openedActionRandomness.actionRandomnessCommitment.fill(
                            0,
                        );
                        storedActionRandomness.actionRandomnessCommitment.fill(
                            0,
                        );
                        storedActionRandomness.canonicalEnvelope.fill(0);
                    }
                } catch (error) {
                    const cleanupFailures: unknown[] = [];
                    if (actionRandomnessSessionIdentifier !== undefined) {
                        try {
                            await custody.closeActionRandomness(
                                actionRandomnessSessionIdentifier,
                            );
                        } catch (cleanupError) {
                            cleanupFailures.push(cleanupError);
                        }
                    }
                    try {
                        await closeCombinedOwner();
                    } catch (cleanupError) {
                        cleanupFailures.push(cleanupError);
                    }
                    if (cleanupFailures.length > 0) {
                        throw new WebLockOwnedStorageError(
                            'OpenFailed',
                            'Recovered foundation authentication failed and retirement also failed.',
                            [error, ...cleanupFailures],
                        );
                    }
                    throw normalizeError(
                        error,
                        'OpenFailed',
                        'Recovered foundation authentication failed; the owner was retired.',
                    );
                } finally {
                    if (derivedRecords !== undefined) {
                        derivedRecords.actionRandomnessLocalRecordIdentifier.fill(
                            0,
                        );
                        for (const record of derivedRecords.witnessStateRecords) {
                            record.authorizedEmptyPlaintext.fill(0);
                            record.localRecordIdentifier.fill(0);
                            record.stateKey.fill(0);
                        }
                    }
                }
            },
            openFoundationWitnessRole: async (roleInput) => {
                if (
                    !authenticatedStoreActive ||
                    foundationTransitionBase === undefined ||
                    (roleInput.openingMode !== 'fresh-provisioned' &&
                        roleInput.openingMode !== 'recovered')
                ) {
                    throw new WebLockOwnedStorageError(
                        'OpenFailed',
                        'A foundation witness role requires an exactly authenticated initialization batch.',
                    );
                }
                const durableStateProtection =
                    createFoundationWitnessRecordProtection(roleInput.record);
                try {
                    return Object.freeze({
                        durableStateService:
                            openDurableStateWitnessServiceWithProtection({
                                limits: roleInput.durableStateLimits,
                                protection: durableStateProtection,
                                store: ownedStorage.store,
                            }),
                    });
                } catch (error) {
                    await releaseRuntimeRecordProtection(
                        durableStateProtection,
                    );
                    throw error;
                }
            },
            custody,
            openCommonProofCustody: async (commonProofInput) => {
                if (!authenticatedStoreActive) {
                    throw new WebLockOwnedStorageError(
                        'OpenFailed',
                        'Common-proof custody requires active root-backed storage.',
                    );
                }
                requireCommonProofStorageCapacity(configuration.limits);
                const attemptLogicalRecordPrefix =
                    deriveCommonProofAttemptLogicalRecordPrefix(
                        commonProofInput,
                    );
                const capacityReservation =
                    await ownedStorage.store.reserveExclusiveCapacity({
                        initialLogicalRecordKeyPrefixes: [
                            attemptLogicalRecordPrefix,
                        ],
                        maximumAdditionalAuthenticatedRepairHeadPlaintextByteLength:
                            commonProofMaximumAdditionalAuthenticatedRepairHeadPlaintextByteLength,
                        maximumAdditionalOwnedRecordCount:
                            commonProofMaximumAdditionalOwnedRecordCount,
                        maximumAdditionalStoredValueByteLength:
                            commonProofMaximumAdditionalStoredValueByteLength,
                        maximumDeletionBatchRecordCount:
                            commonProofDeletionBatchRecordCount,
                    });
                try {
                    return openCommonProofBrowserCustody({
                        ...commonProofInput,
                        capacityReservation,
                        limits: {
                            maximumExternalMemoryByteLength:
                                commonProofScratchByteLength,
                            maximumExternalMemoryObjectCount:
                                commonProofLiveObjectCount,
                            maximumExternalMemoryRecordCount:
                                commonProofExternalMemoryRecordCount,
                            transactionLifetimeMilliseconds:
                                configuration.limits
                                    .maximumTransactionLifetimeMilliseconds,
                        },
                        store: ownedStorage.store,
                        workerKernel: configuration.workerKernel,
                    });
                } catch (error) {
                    await capacityReservation.release();
                    throw error;
                }
            },
            openRuntimeRecordProtection: async (domain) => {
                if (
                    !authenticatedStoreActive ||
                    !Object.prototype.hasOwnProperty.call(
                        runtimeRecordProtectionNamespaces,
                        domain,
                    )
                ) {
                    throw new WebLockOwnedStorageError(
                        'OpenFailed',
                        'A root-backed runtime-record protection session requires active combined foundation storage and a fixed domain.',
                    );
                }
                const opened =
                    await configuration.workerKernel.openActiveAuthenticatedRepairProtection(
                        {
                            namespace:
                                runtimeRecordProtectionNamespaces[domain],
                            runtimeBuildManifestHash:
                                runtimeBuildManifestHash.slice(),
                        },
                    );
                const sessionIdentifier =
                    opened.repairProtectionSessionIdentifier;
                runtimeRecordRepairProtectionSessionIdentifiers.add(
                    sessionIdentifier,
                );
                let closed = false;
                const assertOpen = (): void => {
                    if (closed || ownedStorage.state() !== 'open') {
                        throw new WebLockOwnedStorageError(
                            'OpenFailed',
                            'The root-backed runtime-record protection session is closed.',
                        );
                    }
                };
                const session: RuntimeRecordProtectionSession = Object.freeze({
                    close: async () => {
                        if (closed) {
                            return;
                        }
                        closed = true;
                        runtimeRecordRepairProtectionSessionIdentifiers.delete(
                            sessionIdentifier,
                        );
                        await configuration.workerKernel.closeAuthenticatedRepairProtection(
                            sessionIdentifier,
                        );
                    },
                    openCanonicalEnvelope: async (recordInput) => {
                        assertOpen();
                        const openedPlaintext =
                            await configuration.workerKernel.openAuthenticatedRepairHead(
                                {
                                    canonicalEnvelope:
                                        recordInput.canonicalEnvelope.slice(),
                                    repairProtectionSessionIdentifier:
                                        sessionIdentifier,
                                },
                            );
                        try {
                            return openRuntimeRecordProtectedPlaintext({
                                associatedData: recordInput.associatedData,
                                openedPlaintext,
                            });
                        } finally {
                            openedPlaintext.fill(0);
                        }
                    },
                    sampleIdentifier: (identifierInput) => {
                        assertOpen();
                        if (
                            !Number.isSafeInteger(identifierInput.byteLength) ||
                            identifierInput.byteLength <= 0 ||
                            identifierInput.byteLength > 64 ||
                            typeof identifierInput.purpose !== 'string' ||
                            identifierInput.purpose.length === 0 ||
                            identifierInput.purpose.length > 256
                        ) {
                            throw new WebLockOwnedStorageError(
                                'OpenFailed',
                                'The root-backed runtime-record identifier request is outside its fixed profile.',
                            );
                        }
                        const identifier = new Uint8Array(
                            identifierInput.byteLength,
                        );
                        (
                            configuration.cryptoProvider ?? globalThis.crypto
                        ).getRandomValues(identifier);
                        return identifier;
                    },
                    sealPlaintext: async (recordInput) => {
                        assertOpen();
                        const encodedPlaintext =
                            encodeRuntimeRecordProtectedPlaintext({
                                associatedData: recordInput.associatedData,
                                plaintext: recordInput.plaintext,
                            });
                        try {
                            return await configuration.workerKernel.sealAuthenticatedRepairHead(
                                {
                                    plaintext: encodedPlaintext,
                                    repairProtectionSessionIdentifier:
                                        sessionIdentifier,
                                },
                            );
                        } finally {
                            encodedPlaintext.fill(0);
                        }
                    },
                });
                try {
                    return createRuntimeRecordProtectionFromSession({
                        authorityContext: {
                            actionContextHash:
                                configuration.binding.actionContextHash,
                            ceremonyContextHash:
                                configuration.binding.ceremonyContextHash,
                            ownerParticipantIdentity:
                                configuration.binding.participantId,
                            runtimeBuildManifestHash,
                            suiteIdentifier: configuration.binding.suiteId,
                        },
                        session,
                    });
                } catch (error) {
                    await session.close();
                    throw error;
                }
            },
            openCheckpointStore: async (checkpointInput) => {
                if (
                    !authenticatedStoreActive ||
                    checkpointStoreOpeningAttempted
                ) {
                    throw new WebLockOwnedStorageError(
                        'OpenFailed',
                        'The worker-owned checkpoint store requires one active, unused root-backed storage owner.',
                    );
                }
                checkpointStoreOpeningAttempted = true;
                const checkpointProtection = await (async () => {
                    const namespace =
                        runtimeRecordProtectionNamespaces['checkpoint-cache'];
                    const opened =
                        await configuration.workerKernel.openActiveAuthenticatedRepairProtection(
                            {
                                namespace,
                                runtimeBuildManifestHash:
                                    runtimeBuildManifestHash.slice(),
                            },
                        );
                    runtimeRecordRepairProtectionSessionIdentifiers.add(
                        opened.repairProtectionSessionIdentifier,
                    );
                    const sessionIdentifier =
                        opened.repairProtectionSessionIdentifier;
                    const authenticatedRepairProtection: UntrustedStorageAuthenticatedRepairProtection =
                        Object.freeze({
                            deriveDigest: (sealedHeadBytes) =>
                                configuration.workerKernel.deriveAuthenticatedRepairHeadDigest(
                                    {
                                        repairProtectionSessionIdentifier:
                                            sessionIdentifier,
                                        sealedHeadBytes:
                                            sealedHeadBytes.slice(),
                                    },
                                ),
                            open: (sealedHeadBytes) =>
                                configuration.workerKernel.openAuthenticatedRepairHead(
                                    {
                                        canonicalEnvelope:
                                            sealedHeadBytes.slice(),
                                        repairProtectionSessionIdentifier:
                                            sessionIdentifier,
                                    },
                                ),
                            repairIdentity: opened.repairIdentity.slice(),
                            seal: (headPlaintext) =>
                                configuration.workerKernel.sealAuthenticatedRepairHead(
                                    {
                                        plaintext: headPlaintext.slice(),
                                        repairProtectionSessionIdentifier:
                                            sessionIdentifier,
                                    },
                                ),
                        });
                    let sessionClosed = false;
                    const session: RuntimeRecordProtectionSession =
                        Object.freeze({
                            close: async () => {
                                if (sessionClosed) {
                                    return;
                                }
                                sessionClosed = true;
                                runtimeRecordRepairProtectionSessionIdentifiers.delete(
                                    sessionIdentifier,
                                );
                                await configuration.workerKernel.closeAuthenticatedRepairProtection(
                                    sessionIdentifier,
                                );
                            },
                            openCanonicalEnvelope: async (recordInput) => {
                                const openedPlaintext =
                                    await configuration.workerKernel.openAuthenticatedRepairHead(
                                        {
                                            canonicalEnvelope:
                                                recordInput.canonicalEnvelope.slice(),
                                            repairProtectionSessionIdentifier:
                                                sessionIdentifier,
                                        },
                                    );
                                try {
                                    return openRuntimeRecordProtectedPlaintext({
                                        associatedData:
                                            recordInput.associatedData,
                                        openedPlaintext,
                                    });
                                } finally {
                                    openedPlaintext.fill(0);
                                }
                            },
                            sampleIdentifier: (identifierInput) => {
                                const identifier = new Uint8Array(
                                    identifierInput.byteLength,
                                );
                                (
                                    configuration.cryptoProvider ??
                                    globalThis.crypto
                                ).getRandomValues(identifier);
                                return identifier;
                            },
                            sealPlaintext: async (recordInput) => {
                                const encodedPlaintext =
                                    encodeRuntimeRecordProtectedPlaintext({
                                        associatedData:
                                            recordInput.associatedData,
                                        plaintext: recordInput.plaintext,
                                    });
                                try {
                                    return await configuration.workerKernel.sealAuthenticatedRepairHead(
                                        {
                                            plaintext: encodedPlaintext,
                                            repairProtectionSessionIdentifier:
                                                sessionIdentifier,
                                        },
                                    );
                                } finally {
                                    encodedPlaintext.fill(0);
                                }
                            },
                        });
                    const protection = createRuntimeRecordProtectionFromSession(
                        {
                            authorityContext: {
                                actionContextHash:
                                    configuration.binding.actionContextHash,
                                ceremonyContextHash:
                                    configuration.binding.ceremonyContextHash,
                                ownerParticipantIdentity:
                                    configuration.binding.participantId,
                                runtimeBuildManifestHash,
                                suiteIdentifier: configuration.binding.suiteId,
                            },
                            session,
                        },
                    );
                    return { authenticatedRepairProtection, protection };
                })();
                try {
                    const cryptoProvider =
                        configuration.cryptoProvider ?? globalThis.crypto;
                    const namespaceInput = new Uint8Array(
                        foundationHashByteLength * 4,
                    );
                    namespaceInput.set(
                        configuration.binding.actionContextHash,
                        0,
                    );
                    namespaceInput.set(
                        configuration.binding.ceremonyContextHash,
                        foundationHashByteLength,
                    );
                    namespaceInput.set(
                        configuration.binding.participantId,
                        foundationHashByteLength * 2,
                    );
                    namespaceInput.set(
                        configuration.binding.suiteId,
                        foundationHashByteLength * 3,
                    );
                    const namespaceDigest = new Uint8Array(
                        await cryptoProvider.subtle.digest(
                            'SHA-256',
                            namespaceInput,
                        ),
                    );
                    namespaceInput.fill(0);
                    const checkpointNamespace = `checkpoint-${bytesToHex(
                        namespaceDigest.subarray(0, 24),
                    )}`;
                    namespaceDigest.fill(0);
                    const auxiliaryStore =
                        await ownedStorage.openAuthenticatedAuxiliaryStore({
                            authenticatedRepairProtection:
                                checkpointProtection.authenticatedRepairProtection,
                            limits: configuration.limits,
                            namespace: checkpointNamespace,
                        });
                    return openAuthenticatedCheckpointStoreWithProtection({
                        ...checkpointInput,
                        protection: checkpointProtection.protection,
                        store: auxiliaryStore.store,
                    });
                } catch (error) {
                    await releaseRuntimeRecordProtection(
                        checkpointProtection.protection,
                    );
                    throw error;
                }
            },
            openRootAndAuthenticatedStore: async (openInput) => {
                if (activationAttempted) {
                    throw new BrowserActionStorageCustodyError(
                        'Unavailable',
                        'The combined browser storage root activation can be attempted exactly once.',
                    );
                }
                activationAttempted = true;
                let openedRepairProtection:
                    | Awaited<
                          ReturnType<
                              BrowserActionStorageWorkerKernel['openActiveAuthenticatedRepairProtection']
                          >
                      >
                    | undefined;
                let rootActivated = false;
                try {
                    await custody.openIntoOwnedWorker(openInput);
                    rootActivated = true;
                    openedRepairProtection =
                        await configuration.workerKernel.openActiveAuthenticatedRepairProtection(
                            {
                                namespace: configuration.namespace,
                                runtimeBuildManifestHash:
                                    runtimeBuildManifestHash.slice(),
                            },
                        );
                    if (
                        !(
                            openedRepairProtection.repairIdentity instanceof
                            Uint8Array
                        ) ||
                        openedRepairProtection.repairIdentity.byteLength !==
                            foundationHashByteLength
                    ) {
                        throw new WebLockOwnedStorageError(
                            'OpenFailed',
                            'The owned worker returned a malformed authenticated repair identity.',
                        );
                    }
                    repairProtectionSessionIdentifier =
                        openedRepairProtection.repairProtectionSessionIdentifier;
                    const sessionIdentifier = repairProtectionSessionIdentifier;
                    const authenticatedRepairProtection: UntrustedStorageAuthenticatedRepairProtection =
                        Object.freeze({
                            deriveDigest: (sealedHeadBytes) =>
                                configuration.workerKernel.deriveAuthenticatedRepairHeadDigest(
                                    {
                                        repairProtectionSessionIdentifier:
                                            sessionIdentifier,
                                        sealedHeadBytes:
                                            sealedHeadBytes.slice(),
                                    },
                                ),
                            open: (sealedHeadBytes) =>
                                configuration.workerKernel.openAuthenticatedRepairHead(
                                    {
                                        canonicalEnvelope:
                                            sealedHeadBytes.slice(),
                                        repairProtectionSessionIdentifier:
                                            sessionIdentifier,
                                    },
                                ),
                            repairIdentity:
                                openedRepairProtection.repairIdentity.slice(),
                            seal: (headPlaintext) =>
                                configuration.workerKernel.sealAuthenticatedRepairHead(
                                    {
                                        plaintext: headPlaintext.slice(),
                                        repairProtectionSessionIdentifier:
                                            sessionIdentifier,
                                    },
                                ),
                        });
                    const repairReport =
                        await ownedStorage.activateAuthenticatedStore({
                            authenticatedRepairProtection,
                            limits: configuration.limits,
                        });
                    authenticatedStoreActive = true;
                    return repairReport;
                } catch (error) {
                    if (
                        !rootActivated &&
                        error instanceof BrowserActionStorageCustodyError &&
                        error.code === 'CommitmentMismatch'
                    ) {
                        activationAttempted = false;
                        throw error;
                    }
                    let earlyRepairCloseFailure: unknown;
                    if (
                        repairProtectionSessionIdentifier === undefined &&
                        openedRepairProtection !== undefined
                    ) {
                        try {
                            await configuration.workerKernel.closeAuthenticatedRepairProtection(
                                openedRepairProtection.repairProtectionSessionIdentifier,
                            );
                        } catch (cleanupError) {
                            earlyRepairCloseFailure = cleanupError;
                        }
                    }
                    try {
                        await closeCombinedOwner();
                    } catch (cleanupError) {
                        throw new WebLockOwnedStorageError(
                            'OpenFailed',
                            'Activating root-backed authenticated browser storage failed and retirement also failed.',
                            [error, cleanupError],
                        );
                    }
                    if (earlyRepairCloseFailure !== undefined) {
                        throw new WebLockOwnedStorageError(
                            'OpenFailed',
                            'Activating root-backed authenticated browser storage failed and early repair-session retirement also failed.',
                            [error, earlyRepairCloseFailure],
                        );
                    }
                    if (
                        !rootActivated &&
                        error instanceof BrowserActionStorageCustodyError
                    ) {
                        throw error;
                    }
                    throw normalizeError(
                        error,
                        'OpenFailed',
                        'Activating root-backed authenticated browser storage failed.',
                    );
                }
            },
            state: () => ownedStorage.state(),
        });
    } catch (error) {
        let closeFailure: unknown;
        try {
            await ownedStorage.close();
        } catch (cleanupError) {
            closeFailure = cleanupError;
        }
        if (closeFailure !== undefined) {
            throw new WebLockOwnedStorageError(
                'OpenFailed',
                'Attaching browser action-storage custody failed and ownership cleanup also failed.',
                [error, closeFailure],
            );
        }
        throw normalizeError(
            error,
            'OpenFailed',
            'Attaching browser action-storage custody to exclusive storage ownership failed.',
        );
    }
};
