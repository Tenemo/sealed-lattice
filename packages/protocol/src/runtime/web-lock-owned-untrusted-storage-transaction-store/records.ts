import { sha512 } from '@noble/hashes/sha2.js';
import { foundationProfile } from '@sealed-lattice/types';

import type {
    AuthenticatedCheckpointStore,
    CheckpointOperationIdentity,
    AuthenticatedCheckpointStoreLimits,
    CheckpointBoundaryPolicy,
    TransferableAuthenticatedCheckpointStore,
} from '../authenticated-checkpoint-store.js';
import type { RuntimeRecordProtection } from '../authenticated-runtime-record.js';
import type { BrowserActionStorageWorkerKernel } from '../browser-action-storage-custody-internal.js';
import type {
    BrowserActionStorageCustody,
    BrowserActionStorageRootBinding,
    BrowserDeviceWrappingSnapshot,
    BrowserFoundationFreshnessCoordinate,
    BrowserFoundationInitializationPreparationInput,
    UntrustedExpectedStorageRootCommitment,
} from '../browser-action-storage-custody.js';
import {
    commonProofApplicationHandoffLogicalRecordKey,
    commonProofApplicationHandoffMarkerRecordByteLength,
    type CommonProofBrowserCustody,
    type CommonProofCheckpointResumeDescriptor,
} from '../common-proof-browser-custody.js';
import type {
    DurableStateWitnessServiceLimits,
    TransferableDurableStateWitnessService,
} from '../durable-state-witness-service.js';
import type {
    UntrustedStorageAuthenticatedRepairProtection,
    UntrustedStorageAuthenticatedHeadSnapshot,
    UntrustedStorageRepairReport,
    UntrustedStorageTransactionLimits,
    UntrustedStorageTransactionStore,
} from '../untrusted-storage-transaction-store.js';

// Absolute storage safety bound. Phone qualification targets are measured
// separately and do not participate in proof or suite validity.
export const commonProofScratchByteLength = 1_073_741_824n;
export const commonProofLiveObjectCount = 4_096;
const commonProofDataChunkByteLength = 49_152n;
const commonProofSecretRecordOverheadByteLength = 968n;
const commonProofObjectHeaderPayloadByteLength = 9n;
const commonProofCanonicalOutputChunkByteLength = 1_048_576n;
const commonProofMaximumOutputChunkCount = 5n;
const commonProofPublicRecordOverheadByteLength = 74n;
const commonProofMaximumIndexValueByteLength = 231n;
export const commonProofDeletionBatchRecordCount = 64;
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
export const commonProofExternalMemoryRecordCount = Number(
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
const commonProofApplicationHandoffLogicalRecordKeyByteLength = BigInt(
    textEncoder.encode(commonProofApplicationHandoffLogicalRecordKey)
        .byteLength,
);
export const commonProofApplicationHandoffStoredValueByteLength = BigInt(
    commonProofApplicationHandoffMarkerRecordByteLength,
);
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
    commonProofMaximumStagedReplacementByteLength +
    commonProofApplicationHandoffStoredValueByteLength +
    commonProofMaximumIndexValueByteLength;
const commonProofMaximumAdditionalAuthenticatedRepairHeadPlaintextByteLengthBigInt =
    commonProofExternalMemoryRecordCountBigInt *
        (authenticatedRepairRecordFixedByteLength +
            commonProofExternalLogicalRecordKeyByteLength +
            commonProofMaximumIndexValueByteLength) +
    commonProofMaximumOutputChunkCount *
        (authenticatedRepairRecordFixedByteLength +
            commonProofOutputLogicalRecordKeyByteLength +
            commonProofMaximumIndexValueByteLength) +
    authenticatedRepairRecordFixedByteLength +
    commonProofApplicationHandoffLogicalRecordKeyByteLength +
    commonProofMaximumIndexValueByteLength;
const commonProofMaximumAdditionalOwnedRecordCountBigInt =
    (commonProofLogicalRecordCountBigInt + 1n) * 2n + 1n;
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
    commonProofApplicationHandoffLogicalRecordKeyByteLength !== 28n ||
    commonProofCapacityValues.some(
        (value) => value > BigInt(Number.MAX_SAFE_INTEGER),
    )
) {
    throw new Error(
        'The derived common-proof storage profile is outside its exact JavaScript or logical-key bounds.',
    );
}
export const commonProofMaximumAdditionalStoredValueByteLength = Number(
    commonProofMaximumAdditionalStoredValueByteLengthBigInt,
);
export const commonProofMaximumAdditionalAuthenticatedRepairHeadPlaintextByteLength =
    Number(
        commonProofMaximumAdditionalAuthenticatedRepairHeadPlaintextByteLengthBigInt,
    );
export const commonProofMaximumAdditionalOwnedRecordCount = Number(
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
export const maximumLockAcquisitionDelayMilliseconds = 2_147_483_647;
export const foundationHashByteLength = 64;
const namespacePattern = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;
const lockNamePrefix = 'sealed-lattice-storage-namespace-';
const runtimeRecordProtectedPlaintextMagic = Uint8Array.of(
    0x53,
    0x4c,
    0x52,
    0x50,
);
const runtimeRecordProtectedPlaintextVersion = 1;
const runtimeRecordProtectedPlaintextHeaderByteLength =
    runtimeRecordProtectedPlaintextMagic.byteLength + 2 + 4;
const foundationWitnessRuntimeRecordPlaintextReserveByteLength = 1_024;
export const foundationWitnessRuntimeRecordStorageReserveByteLength = 4_096;
export const foundationWitnessMaximumPayloadByteLength =
    foundationProfile.streamChunkByteLength -
    foundationWitnessRuntimeRecordPlaintextReserveByteLength;
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

export const runtimeRecordProtectionNamespaces: Readonly<
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

export class WebLockOwnedStorageError extends Error {
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

export type WebLockOwnedStorageState = 'open' | 'closing' | 'closed' | 'failed';

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

export type WebLockOwnedStorageBaseConfiguration = Readonly<{
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

export type WebLockOwnedBrowserActionStorageCustodyConfiguration =
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
        applicationStatementSchemaIdentifier: number;
        checkpoint?:
            | Readonly<{
                  operationIdentity: CheckpointOperationIdentity;
                  store: AuthenticatedCheckpointStore;
              }>
            | Readonly<{
                  resumeDescriptor: CommonProofCheckpointResumeDescriptor;
                  store: AuthenticatedCheckpointStore;
              }>;
        commonProofEnvironmentIdentifier: Uint8Array;
        commonProofRuntimeBindingHash: Uint8Array;
        proofAttemptLineageIdentifier: Uint8Array;
    }): Promise<CommonProofBrowserCustody>;
    openCheckpointStore(input: {
        boundaryPolicy: CheckpointBoundaryPolicy;
        limits: AuthenticatedCheckpointStoreLimits;
    }): Promise<TransferableAuthenticatedCheckpointStore>;
    openRootAndAuthenticatedStore(input: {
        expectedSnapshot: BrowserDeviceWrappingSnapshot;
        untrustedExpectedCommitment: UntrustedExpectedStorageRootCommitment;
    }): Promise<UntrustedStorageRepairReport>;
    retire(): Promise<void>;
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

export type Deferred<Value> = Readonly<{
    promise: Promise<Value>;
    reject(error: Error): void;
    resolve(value: Value): void;
}>;

export const createDeferred = <Value>(): Deferred<Value> => {
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

export const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

export const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean => {
    if (left.byteLength !== right.byteLength) {
        return false;
    }
    let difference = 0;
    for (let byteIndex = 0; byteIndex < left.byteLength; byteIndex += 1) {
        difference |= left[byteIndex] ^ right[byteIndex];
    }
    return difference === 0;
};

export type OpenedFoundationWitnessRuntimeRecordEnvelope = Readonly<{
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
export const maximumUnsigned64 = 0xffff_ffff_ffff_ffffn;

export const deriveFoundationWitnessRuntimeRecordStateKey = (input: {
    associatedData: Uint8Array;
    baseStateKey: Uint8Array;
}): Uint8Array => {
    const hash = sha512.create();
    hash.update(foundationWitnessRuntimeRecordCoordinateDomain);
    hash.update(input.baseStateKey);
    hash.update(input.associatedData);
    return hash.digest();
};

export const isFoundationWitnessRuntimeRecordEnvelope = (
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

export const encodeFoundationWitnessRuntimeRecordEnvelope = (input: {
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

export const openFoundationWitnessRuntimeRecordEnvelope = (
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

export const destroyOpenedFoundationWitnessRuntimeRecordEnvelope = (
    envelope: OpenedFoundationWitnessRuntimeRecordEnvelope,
): void => {
    envelope.associatedData.fill(0);
    envelope.innerCanonicalEnvelope.fill(0);
    envelope.predecessorRecordHash?.fill(0);
};

export const encodeStoredActionRandomnessRecord = (input: {
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

export const openStoredActionRandomnessRecord = (
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

export const copyFoundationFreshnessCoordinate = (input: {
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

export const encodeRuntimeRecordProtectedPlaintext = (input: {
    associatedData: Uint8Array;
    plaintext: Uint8Array;
}): Uint8Array => {
    const encodedByteLength =
        runtimeRecordProtectedPlaintextHeaderByteLength +
        input.associatedData.byteLength +
        input.plaintext.byteLength;
    if (
        !Number.isSafeInteger(encodedByteLength) ||
        input.associatedData.byteLength > 0xffff_ffff ||
        encodedByteLength > foundationProfile.streamChunkByteLength
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
    encoded.set(
        input.associatedData,
        runtimeRecordProtectedPlaintextHeaderByteLength,
    );
    encoded.set(
        input.plaintext,
        runtimeRecordProtectedPlaintextHeaderByteLength +
            input.associatedData.byteLength,
    );
    return encoded;
};

export const openRuntimeRecordProtectedPlaintext = (input: {
    associatedData: Uint8Array;
    openedPlaintext: Uint8Array;
}): Uint8Array => {
    if (
        input.openedPlaintext.byteLength <
            runtimeRecordProtectedPlaintextHeaderByteLength ||
        input.openedPlaintext.byteLength >
            foundationProfile.streamChunkByteLength
    ) {
        throw new WebLockOwnedStorageError(
            'OpenFailed',
            'Root-backed runtime-record plaintext is outside its canonical length profile.',
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
    const plaintextOffset =
        runtimeRecordProtectedPlaintextHeaderByteLength +
        associatedDataByteLength;
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
            input.openedPlaintext.subarray(
                runtimeRecordProtectedPlaintextHeaderByteLength,
                plaintextOffset,
            ),
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

export const openFoundationWitnessProtectedEnvelope = async (input: {
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

export const assertNamespace = (namespace: string): Uint8Array => {
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

export const normalizeError = (
    error: unknown,
    code: WebLockOwnedStorageErrorCode,
    message: string,
): WebLockOwnedStorageError =>
    error instanceof WebLockOwnedStorageError
        ? error
        : new WebLockOwnedStorageError(code, message, error);
