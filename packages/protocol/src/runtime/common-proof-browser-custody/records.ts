import { shake256 } from '@noble/hashes/sha3.js';
import {
    BrowserActionStorageCustodyError,
    foundationProfile,
    type BrowserActionStorageWorkerKernel,
} from '@sealed-lattice/types';
import type {
    AuthenticatedCommonProofInputStore,
    CommonProofCanonicalOutputStore,
    CommonProofExternalMemoryReadResult,
    CommonProofExternalMemoryRequest,
    CommonProofExternalMemoryTransactionExecutor,
    CommonProofGenerationCheckpoint,
    ClosedWorkerCommonProofScratchRecordIdentifierInput,
} from '@sealed-lattice/wasm';

import type {
    AuthenticatedCheckpointStore,
    CheckpointOperationIdentity,
} from '../authenticated-checkpoint-store.js';
import type {
    UntrustedStorageExclusiveCapacityReservation,
    UntrustedStorageTransaction,
    UntrustedStorageTransactionStore,
} from '../untrusted-storage-transaction-store.js';

export const foundationHashByteLength = 64;
export const identifierByteLength = 32;
export const maximumCanonicalDataChunkByteLength =
    foundationProfile.streamChunkByteLength;
export const maximumDeletionBatchRecordCount = 64;
export const canonicalCommonProofOutputChunkByteLength = 1_048_576;
export const maximumCommonProofOutputChunkCount = 256;
export const maximumCommonProofOutputByteLength = 268_435_456;
export const maximumCheckpointCursorManifestByteLength = 1_048_576;
const maximumUnsigned32 = 0xffff_ffff;
const maximumUnsigned16 = 0xffff;
const publicRecordMagic = Uint8Array.of(0x53, 0x4c, 0x43, 0x50);
const publicRecordVersion = 1;
const publicRecordHeaderByteLength =
    publicRecordMagic.byteLength + 2 + 4 + foundationHashByteLength;
const publicRecordDigestDomain =
    'sealed-lattice/common-proof/browser-public-record/v1';
export const canonicalOutputKeyDomain =
    'sealed-lattice/common-proof/canonical-output-key/v1';
const checkpointEnvironmentBindingDomain =
    'sealed-lattice/common-proof/checkpoint-environment-binding/v1';
export const checkpointStateStreamDomain =
    'sealed-lattice/common-proof/generation-checkpoint-state/v1';
const commonProofAttemptStoragePrefixDomain =
    'sealed-lattice/common-proof/attempt-storage-prefix/v1';
export const textEncoder = new TextEncoder();

export type CommonProofExternalMemoryIdentifierInput =
    ClosedWorkerCommonProofScratchRecordIdentifierInput;

export type ExternalMemoryRecordDescriptor = Readonly<{
    identifierInput: CommonProofExternalMemoryIdentifierInput;
    logicalRecordKey: string;
    protection: 'public-integrity' | 'secret-authenticated-encryption';
}>;

type ExternalMemoryDataChunk = Readonly<{
    byteLength: number;
    byteOffset: bigint;
    descriptor: ExternalMemoryRecordDescriptor;
}>;

export type ExternalMemoryObjectState = {
    appendedByteLength: bigint;
    chunks: ExternalMemoryDataChunk[];
    exactByteLength: bigint;
    header: ExternalMemoryRecordDescriptor;
    nextChunkOrdinal: number;
    protection: 'public-integrity' | 'secret-authenticated-encryption';
    sealMarker?: ExternalMemoryRecordDescriptor;
};

type StagedExternalMemoryRecordWrite = {
    descriptor: ExternalMemoryRecordDescriptor;
    encodedRecord?: Uint8Array<ArrayBuffer>;
    expectedCurrentValue: Uint8Array<ArrayBuffer> | null;
    payloadOwnership?: CommonProofPayloadBufferOwnership;
};

export type CommonProofPayloadBufferOwnership = Readonly<{
    buffer: ArrayBuffer;
    byteLength: number;
    identifier: number;
    ledger: CommonProofPayloadBufferOwnershipLedger;
}>;

export type CommonProofPayloadBufferAccounting = Readonly<{
    claimedBufferCount: bigint;
    claimedByteLength: bigint;
    maximumLiveBufferByteLength: bigint;
    maximumLiveBufferCount: number;
    releasedBufferCount: bigint;
    releasedByteLength: bigint;
    secretRecordOpenByteLength: bigint;
    secretRecordOpenCount: bigint;
    secretRecordSealByteLength: bigint;
    secretRecordSealCount: bigint;
    transferredBufferCount: bigint;
    transferredByteLength: bigint;
}>;

export class CommonProofPayloadBufferOwnershipLedger {
    readonly #liveOwners = new Map<
        ArrayBuffer,
        Readonly<{ byteLength: number; identifier: number; owner: string }>
    >();
    #claimedBufferCount = 0n;
    #claimedByteLength = 0n;
    #liveBufferByteLength = 0n;
    #maximumLiveBufferByteLength = 0n;
    #maximumLiveOwnerCount = 0;
    #nextIdentifier = 1;
    #releasedBufferCount = 0n;
    #releasedByteLength = 0n;
    #transferredBufferCount = 0n;
    #transferredByteLength = 0n;
    readonly #transitions: string[] = [];

    public observe(
        bytes: Uint8Array,
        owner: string,
    ): CommonProofPayloadBufferOwnership | undefined {
        if (!(bytes.buffer instanceof ArrayBuffer)) {
            return undefined;
        }
        const existing = this.#liveOwners.get(bytes.buffer);
        if (existing !== undefined) {
            this.#liveOwners.set(bytes.buffer, {
                byteLength: existing.byteLength,
                identifier: existing.identifier,
                owner,
            });
            this.#transferredBufferCount += 1n;
            this.#transferredByteLength += BigInt(existing.byteLength);
            this.#transitions.push(
                `transfer:${String(existing.identifier)}:${owner}`,
            );
            return Object.freeze({
                buffer: bytes.buffer,
                byteLength: existing.byteLength,
                identifier: existing.identifier,
                ledger: this,
            });
        }
        if (this.#liveOwners.size >= 2) {
            throw new BrowserActionStorageCustodyError(
                'StorageFailure',
                `Common-proof payload custody cannot add ${owner} while ${[
                    ...this.#liveOwners.values(),
                ]
                    .map(
                        (liveOwner) =>
                            `${String(liveOwner.identifier)}:${liveOwner.owner}`,
                    )
                    .join(' and ')} are live.`,
            );
        }
        const identifier = this.#nextIdentifier;
        this.#nextIdentifier += 1;
        const byteLength = bytes.byteLength;
        this.#liveOwners.set(bytes.buffer, { byteLength, identifier, owner });
        this.#claimedBufferCount += 1n;
        this.#claimedByteLength += BigInt(byteLength);
        this.#liveBufferByteLength += BigInt(byteLength);
        this.#maximumLiveBufferByteLength =
            this.#maximumLiveBufferByteLength > this.#liveBufferByteLength
                ? this.#maximumLiveBufferByteLength
                : this.#liveBufferByteLength;
        this.#maximumLiveOwnerCount = Math.max(
            this.#maximumLiveOwnerCount,
            this.#liveOwners.size,
        );
        this.#transitions.push(`claim:${String(identifier)}:${owner}`);
        return Object.freeze({
            buffer: bytes.buffer,
            byteLength,
            identifier,
            ledger: this,
        });
    }

    public transfer(
        ownership: CommonProofPayloadBufferOwnership,
        owner: string,
    ): void {
        this.#requireOwnership(ownership);
        this.#liveOwners.set(ownership.buffer, {
            byteLength: ownership.byteLength,
            identifier: ownership.identifier,
            owner,
        });
        this.#transferredBufferCount += 1n;
        this.#transferredByteLength += BigInt(ownership.byteLength);
        this.#transitions.push(
            `transfer:${String(ownership.identifier)}:${owner}`,
        );
    }

    public replace(
        ownership: CommonProofPayloadBufferOwnership | undefined,
        bytes: Uint8Array,
        owner: string,
    ): CommonProofPayloadBufferOwnership | undefined {
        const replacement = this.observe(bytes, owner);
        if (
            ownership !== undefined &&
            replacement?.buffer !== ownership.buffer
        ) {
            this.release(ownership);
        }
        return replacement;
    }

    public release(ownership: CommonProofPayloadBufferOwnership): void {
        this.#requireOwnership(ownership);
        const owner = this.#liveOwners.get(ownership.buffer);
        this.#liveOwners.delete(ownership.buffer);
        this.#liveBufferByteLength -= BigInt(ownership.byteLength);
        this.#releasedBufferCount += 1n;
        this.#releasedByteLength += BigInt(ownership.byteLength);
        this.#transitions.push(
            `release:${String(ownership.identifier)}:${owner?.owner}`,
        );
    }

    public releaseIfLive(
        ownership: CommonProofPayloadBufferOwnership | undefined,
    ): void {
        if (
            ownership !== undefined &&
            ownership.ledger === this &&
            this.#liveOwners.get(ownership.buffer)?.identifier ===
                ownership.identifier
        ) {
            this.release(ownership);
        }
    }

    public assertReleased(): void {
        if (this.#liveOwners.size !== 0) {
            throw new BrowserActionStorageCustodyError(
                'StorageFailure',
                `Common-proof payload custody retained ${[
                    ...this.#liveOwners.values(),
                ]
                    .map(
                        (owner) => `${String(owner.identifier)}:${owner.owner}`,
                    )
                    .join(' and ')} after the transaction.`,
            );
        }
    }

    public snapshot(): Readonly<{
        accounting: CommonProofPayloadBufferAccounting;
        maximumLiveOwnerCount: number;
        transitions: readonly string[];
    }> {
        return Object.freeze({
            accounting: Object.freeze({
                claimedBufferCount: this.#claimedBufferCount,
                claimedByteLength: this.#claimedByteLength,
                maximumLiveBufferByteLength: this.#maximumLiveBufferByteLength,
                maximumLiveBufferCount: this.#maximumLiveOwnerCount,
                releasedBufferCount: this.#releasedBufferCount,
                releasedByteLength: this.#releasedByteLength,
                secretRecordOpenByteLength: 0n,
                secretRecordOpenCount: 0n,
                secretRecordSealByteLength: 0n,
                secretRecordSealCount: 0n,
                transferredBufferCount: this.#transferredBufferCount,
                transferredByteLength: this.#transferredByteLength,
            }),
            maximumLiveOwnerCount: this.#maximumLiveOwnerCount,
            transitions: Object.freeze([...this.#transitions]),
        });
    }

    #requireOwnership(ownership: CommonProofPayloadBufferOwnership): void {
        if (
            ownership.ledger !== this ||
            !this.#liveOwners.has(ownership.buffer) ||
            this.#liveOwners.get(ownership.buffer)?.identifier !==
                ownership.identifier
        ) {
            throw new BrowserActionStorageCustodyError(
                'StorageFailure',
                'Common-proof payload custody received a stale or foreign ownership claim.',
            );
        }
    }
}

type StagedExternalMemoryRecordDeletion = {
    descriptor: ExternalMemoryRecordDescriptor;
};

export type StagedExternalMemoryRecordChange =
    | Readonly<{
          kind: 'write';
          write: StagedExternalMemoryRecordWrite;
      }>
    | Readonly<{
          deletion: StagedExternalMemoryRecordDeletion;
          kind: 'delete';
      }>;

export type ExternalMemoryShadowState = {
    byteLength: bigint;
    readonly changes: Map<string, StagedExternalMemoryRecordChange>;
    readonly createdDescriptors: Set<ExternalMemoryRecordDescriptor>;
    readonly objects: Map<number, ExternalMemoryObjectState>;
    recordCount: number;
    readonly replay: boolean;
};

export type CanonicalOutputChunk = Readonly<{
    byteLength: number;
    logicalRecordKey: string;
}>;

export type CommonProofBrowserCustodyLimits = Readonly<{
    maximumExternalMemoryByteLength: bigint;
    maximumExternalMemoryObjectCount: number;
    maximumExternalMemoryRecordCount: number;
    transactionLifetimeMilliseconds: number;
}>;

export type CommonProofBrowserCustodyInput = Readonly<{
    actionRandomnessCommitment: Uint8Array;
    applicationStatementSchemaIdentifier: number;
    capacityReservation: UntrustedStorageExclusiveCapacityReservation;
    commonProofEnvironmentIdentifier: Uint8Array;
    commonProofRuntimeBindingHash: Uint8Array;
    limits: CommonProofBrowserCustodyLimits;
    checkpoint?:
        | Readonly<{
              operationIdentity: CheckpointOperationIdentity;
              store: AuthenticatedCheckpointStore;
          }>
        | Readonly<{
              resumeDescriptor: CommonProofCheckpointResumeDescriptor;
              store: AuthenticatedCheckpointStore;
          }>;
    proofAttemptLineageIdentifier: Uint8Array;
    store: UntrustedStorageTransactionStore;
    workerKernel: BrowserActionStorageWorkerKernel;
}>;

export type CommonProofCheckpointResumeDescriptor = Readonly<{
    checkpointLineageIdentifier: Uint8Array;
    commonProofEnvironmentIdentifier: Uint8Array;
    privateRandomCursorManifestBytes: Uint8Array;
    privateRandomnessStreamAttemptIdentifier?: Uint8Array;
    safeBoundaryOrdinal: number;
    stableAttemptBindingHash: Uint8Array;
}>;

export type CommonProofApplicationHandoff = Readonly<{
    canonicalMarkerRecordBytes: Uint8Array<ArrayBuffer>;
    logicalRecordKey: string;
}>;

export type CommonProofCheckpointCustody = Readonly<{
    publishAuthenticatedCheckpoint(
        checkpoint: CommonProofGenerationCheckpoint,
    ): Promise<void>;
    restoreAuthenticatedCheckpointState(): Promise<Uint8Array>;
}>;

/**
 * Internal worker-owned storage composition. The installed custody host wraps
 * this object in an opaque same-realm capability; it is not a protocol-root or
 * SDK export.
 */
export type CommonProofBrowserCustody = Readonly<{
    armApplicationHandoff(): Promise<CommonProofApplicationHandoff>;
    checkpointCustody?: CommonProofCheckpointCustody;
    completeVerifiedOutput(): Promise<void>;
    copyCheckpointResumeDescriptor():
        | CommonProofCheckpointResumeDescriptor
        | undefined;
    externalMemory: CommonProofExternalMemoryTransactionExecutor;
    prefixReplayExternalMemory: Readonly<{
        executeDeterministicPrefixReplayTransaction(
            request: CommonProofExternalMemoryRequest,
        ): Promise<readonly CommonProofExternalMemoryReadResult[]>;
    }>;
    outputStore: CommonProofCanonicalOutputStore;
    authenticatedOutput(): AuthenticatedCommonProofInputStore;
    releaseExternalMemory(): Promise<void>;
    retire(): Promise<void>;
    sealCanonicalOutput(): void;
    suspendForAuthenticatedResume(): Promise<void>;
}>;

export const isSafeUnsigned32 = (value: number): boolean =>
    Number.isSafeInteger(value) && value >= 0 && value <= maximumUnsigned32;

export const isNonzeroUnsigned16 = (value: number): boolean =>
    Number.isSafeInteger(value) && value > 0 && value <= maximumUnsigned16;

export const copyExactBytes = (
    value: Uint8Array,
    expectedByteLength: number,
    label: string,
): Uint8Array<ArrayBuffer> => {
    if (
        !(value instanceof Uint8Array) ||
        value.byteLength !== expectedByteLength
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            `${label} must contain exactly ${String(expectedByteLength)} bytes.`,
        );
    }
    return value.slice();
};

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

export const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

export const deriveCommonProofAttemptLogicalRecordPrefix = (input: {
    commonProofEnvironmentIdentifier: Uint8Array;
    commonProofRuntimeBindingHash: Uint8Array;
    proofAttemptLineageIdentifier: Uint8Array;
}): string => {
    const environmentIdentifier = copyExactBytes(
        input.commonProofEnvironmentIdentifier,
        identifierByteLength,
        'Common-proof environment identifier',
    );
    const runtimeBindingHash = copyExactBytes(
        input.commonProofRuntimeBindingHash,
        foundationHashByteLength,
        'Common-proof runtime-binding hash',
    );
    const attemptLineageIdentifier = copyExactBytes(
        input.proofAttemptLineageIdentifier,
        identifierByteLength,
        'Proof-attempt lineage identifier',
    );
    const hash = shake256.create({ dkLen: foundationHashByteLength });
    try {
        const domainBytes = textEncoder.encode(
            commonProofAttemptStoragePrefixDomain,
        );
        hash.update(unsigned32Bytes(domainBytes.byteLength));
        hash.update(domainBytes);
        hash.update(environmentIdentifier);
        hash.update(runtimeBindingHash);
        hash.update(attemptLineageIdentifier);
        return `common-proof-attempt/${bytesToHex(hash.digest())}/`;
    } finally {
        environmentIdentifier.fill(0);
        runtimeBindingHash.fill(0);
        attemptLineageIdentifier.fill(0);
        hash.destroy();
    }
};

export const commonProofApplicationHandoffLogicalRecordKey =
    'common-proof-handoff/pending';
const commonProofApplicationHandoffMarkerPayloadByteLength =
    foundationHashByteLength;
export const commonProofApplicationHandoffMarkerRecordByteLength =
    publicRecordHeaderByteLength +
    commonProofApplicationHandoffMarkerPayloadByteLength;

export const unsigned32Bytes = (value: number): Uint8Array<ArrayBuffer> => {
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value, true);
    return bytes;
};

export const hexToExactBytes = (
    value: string,
    expectedByteLength: number,
    label: string,
): Uint8Array<ArrayBuffer> => {
    if (
        typeof value !== 'string' ||
        value.length !== expectedByteLength * 2 ||
        !/^[0-9a-f]+$/u.test(value)
    ) {
        throw new BrowserActionStorageCustodyError(
            'RecordAuthenticationFailed',
            `${label} is not canonical lowercase hexadecimal bytes.`,
        );
    }
    const bytes = new Uint8Array(expectedByteLength);
    for (let byteIndex = 0; byteIndex < bytes.byteLength; byteIndex += 1) {
        bytes[byteIndex] = Number.parseInt(
            value.slice(byteIndex * 2, byteIndex * 2 + 2),
            16,
        );
    }
    return bytes;
};

export const copyCheckpointResumeDescriptor = (
    value: CommonProofCheckpointResumeDescriptor,
): CommonProofCheckpointResumeDescriptor => {
    if (
        typeof value !== 'object' ||
        value === null ||
        !(value.privateRandomCursorManifestBytes instanceof Uint8Array) ||
        value.privateRandomCursorManifestBytes.byteLength >
            maximumCheckpointCursorManifestByteLength ||
        !isSafeUnsigned32(value.safeBoundaryOrdinal)
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The common-proof checkpoint resume descriptor is malformed.',
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
        checkpointLineageIdentifier = copyExactBytes(
            value.checkpointLineageIdentifier,
            identifierByteLength,
            'Checkpoint-lineage identifier',
        );
        commonProofEnvironmentIdentifier = copyExactBytes(
            value.commonProofEnvironmentIdentifier,
            identifierByteLength,
            'Checkpoint common-proof environment identifier',
        );
        privateRandomCursorManifestBytes = Uint8Array.from(
            value.privateRandomCursorManifestBytes,
        );
        privateRandomnessStreamAttemptIdentifier =
            value.privateRandomnessStreamAttemptIdentifier === undefined
                ? undefined
                : copyExactBytes(
                      value.privateRandomnessStreamAttemptIdentifier,
                      identifierByteLength,
                      'Private-randomness stream-attempt identifier',
                  );
        stableAttemptBindingHash = copyExactBytes(
            value.stableAttemptBindingHash,
            foundationHashByteLength,
            'Stable attempt-binding hash',
        );
        return Object.freeze({
            checkpointLineageIdentifier,
            commonProofEnvironmentIdentifier,
            privateRandomCursorManifestBytes,
            ...(privateRandomnessStreamAttemptIdentifier === undefined
                ? {}
                : { privateRandomnessStreamAttemptIdentifier }),
            safeBoundaryOrdinal: value.safeBoundaryOrdinal,
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

export const destroyCheckpointResumeDescriptor = (
    descriptor: CommonProofCheckpointResumeDescriptor,
): void => {
    descriptor.checkpointLineageIdentifier.fill(0);
    descriptor.commonProofEnvironmentIdentifier.fill(0);
    descriptor.stableAttemptBindingHash.fill(0);
    descriptor.privateRandomCursorManifestBytes.fill(0);
    descriptor.privateRandomnessStreamAttemptIdentifier?.fill(0);
};

export const destroyIdentifierInput = (
    identifierInput: CommonProofExternalMemoryIdentifierInput,
): void => {
    identifierInput.commonProofEnvironmentIdentifier.fill(0);
    identifierInput.commonProofRuntimeBindingHash.fill(0);
    identifierInput.proofAttemptLineageIdentifier.fill(0);
};

export const allObjectDescriptors = (
    object: ExternalMemoryObjectState,
): readonly ExternalMemoryRecordDescriptor[] => [
    object.header,
    ...object.chunks.map((chunk) => chunk.descriptor),
    ...(object.sealMarker === undefined ? [] : [object.sealMarker]),
];

export const destroyExternalMemoryObjectInMemory = (
    object: ExternalMemoryObjectState,
): void => {
    for (const descriptor of allObjectDescriptors(object)) {
        destroyIdentifierInput(descriptor.identifierInput);
    }
};

export const checkpointEnvironmentBindingHash = (input: {
    commonProofEnvironmentIdentifier: Uint8Array;
    commonProofRuntimeBindingHash: Uint8Array;
    proofAttemptLineageIdentifier: Uint8Array;
}): Uint8Array<ArrayBuffer> => {
    const hash = shake256.create({ dkLen: foundationHashByteLength });
    try {
        const domainBytes = textEncoder.encode(
            checkpointEnvironmentBindingDomain,
        );
        hash.update(unsigned32Bytes(domainBytes.byteLength));
        hash.update(domainBytes);
        hash.update(input.commonProofEnvironmentIdentifier);
        hash.update(input.commonProofRuntimeBindingHash);
        hash.update(input.proofAttemptLineageIdentifier);
        return hash.digest();
    } finally {
        hash.destroy();
    }
};

const publicRecordDigest = (
    logicalRecordKey: string,
    payload: Uint8Array,
): Uint8Array<ArrayBuffer> => {
    const hash = shake256.create({ dkLen: foundationHashByteLength });
    try {
        const domainBytes = textEncoder.encode(publicRecordDigestDomain);
        const keyBytes = textEncoder.encode(logicalRecordKey);
        hash.update(unsigned32Bytes(domainBytes.byteLength));
        hash.update(domainBytes);
        hash.update(unsigned32Bytes(keyBytes.byteLength));
        hash.update(keyBytes);
        hash.update(unsigned32Bytes(payload.byteLength));
        hash.update(payload);
        return hash.digest();
    } finally {
        hash.destroy();
    }
};

export const encodePublicRecord = (
    logicalRecordKey: string,
    payload: Uint8Array,
): Uint8Array<ArrayBuffer> => {
    const record = new Uint8Array(
        publicRecordHeaderByteLength + payload.byteLength,
    );
    const view = new DataView(record.buffer);
    record.set(publicRecordMagic, 0);
    view.setUint16(publicRecordMagic.byteLength, publicRecordVersion, true);
    view.setUint32(publicRecordMagic.byteLength + 2, payload.byteLength, true);
    const digest = publicRecordDigest(logicalRecordKey, payload);
    record.set(digest, publicRecordMagic.byteLength + 2 + 4);
    digest.fill(0);
    record.set(payload, publicRecordHeaderByteLength);
    return record;
};

export const decodePublicRecord = (
    logicalRecordKey: string,
    record: Uint8Array,
): Uint8Array<ArrayBuffer> => {
    if (record.byteLength < publicRecordHeaderByteLength) {
        throw new BrowserActionStorageCustodyError(
            'RecordAuthenticationFailed',
            'A common-proof public record is truncated.',
        );
    }
    const view = new DataView(
        record.buffer,
        record.byteOffset,
        record.byteLength,
    );
    const payloadByteLength = view.getUint32(
        publicRecordMagic.byteLength + 2,
        true,
    );
    if (
        !bytesEqual(
            record.subarray(0, publicRecordMagic.byteLength),
            publicRecordMagic,
        ) ||
        view.getUint16(publicRecordMagic.byteLength, true) !==
            publicRecordVersion ||
        record.byteLength !== publicRecordHeaderByteLength + payloadByteLength
    ) {
        throw new BrowserActionStorageCustodyError(
            'RecordAuthenticationFailed',
            'A common-proof public record has noncanonical framing.',
        );
    }
    const payload = record.slice(publicRecordHeaderByteLength);
    const expectedDigest = publicRecordDigest(logicalRecordKey, payload);
    const suppliedDigest = record.subarray(
        publicRecordMagic.byteLength + 2 + 4,
        publicRecordHeaderByteLength,
    );
    const valid = bytesEqual(suppliedDigest, expectedDigest);
    expectedDigest.fill(0);
    if (!valid) {
        payload.fill(0);
        throw new BrowserActionStorageCustodyError(
            'RecordAuthenticationFailed',
            'A common-proof public record failed its integrity check.',
        );
    }
    return payload;
};

export const closeTransactionAfterFailure = async (
    transaction: UntrustedStorageTransaction,
    operationError: unknown,
): Promise<never> => {
    try {
        await transaction.closeAfterFailure();
    } catch (cleanupError) {
        throw new BrowserActionStorageCustodyError(
            'StorageFailure',
            'A common-proof storage transaction failed and could not clean up.',
            { cleanupError, operationError },
        );
    }
    throw operationError;
};

export const validateLimits = (
    limits: CommonProofBrowserCustodyLimits,
): CommonProofBrowserCustodyLimits => {
    if (
        typeof limits !== 'object' ||
        limits === null ||
        typeof limits.maximumExternalMemoryByteLength !== 'bigint' ||
        limits.maximumExternalMemoryByteLength <= 0n ||
        !Number.isSafeInteger(limits.maximumExternalMemoryObjectCount) ||
        limits.maximumExternalMemoryObjectCount <= 0 ||
        !Number.isSafeInteger(limits.maximumExternalMemoryRecordCount) ||
        limits.maximumExternalMemoryRecordCount <= 0 ||
        !Number.isSafeInteger(limits.transactionLifetimeMilliseconds) ||
        limits.transactionLifetimeMilliseconds <= 0
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'Common-proof browser-custody limits are malformed.',
        );
    }
    return Object.freeze({ ...limits });
};

export const copyIdentifierInput = (
    input: CommonProofExternalMemoryIdentifierInput,
): CommonProofExternalMemoryIdentifierInput => {
    let commonProofEnvironmentIdentifier = new Uint8Array(0);
    let commonProofRuntimeBindingHash = new Uint8Array(0);
    let proofAttemptLineageIdentifier = new Uint8Array(0);
    try {
        commonProofEnvironmentIdentifier =
            input.commonProofEnvironmentIdentifier.slice();
        commonProofRuntimeBindingHash =
            input.commonProofRuntimeBindingHash.slice();
        proofAttemptLineageIdentifier =
            input.proofAttemptLineageIdentifier.slice();
        return Object.freeze({
            commonProofEnvironmentIdentifier,
            commonProofRuntimeBindingHash,
            externalMemoryByteOffset: input.externalMemoryByteOffset,
            externalMemoryChunkOrdinal: input.externalMemoryChunkOrdinal,
            externalMemoryObjectOrdinal: input.externalMemoryObjectOrdinal,
            externalMemoryRecordKind: input.externalMemoryRecordKind,
            proofAttemptLineageIdentifier,
            recordType: input.recordType,
        });
    } catch (error) {
        commonProofEnvironmentIdentifier.fill(0);
        commonProofRuntimeBindingHash.fill(0);
        proofAttemptLineageIdentifier.fill(0);
        throw error;
    }
};
