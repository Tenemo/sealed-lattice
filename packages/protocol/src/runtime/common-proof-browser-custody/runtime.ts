import { shake256 } from '@noble/hashes/sha3.js';
import {
    BrowserActionStorageCustodyError,
    foundationProfile,
} from '@sealed-lattice/types';
import {
    openClosedWorkerCommonProofScratchStorage,
    type AuthenticatedCommonProofInputStore,
    type CommonProofCanonicalOutputStore,
    type CommonProofExternalMemoryReadResult,
    type CommonProofExternalMemoryRequest,
    type CommonProofGenerationCheckpoint,
} from '@sealed-lattice/wasm';

import {
    describeAuthenticatedCheckpointStateStream,
    type CheckpointBoundary,
    type CheckpointOperationIdentity,
    type ExpectedCheckpointBoundary,
} from '../authenticated-checkpoint-store.js';
import type { UntrustedStorageAuthenticator } from '../untrusted-storage-transaction-store.js';

import {
    foundationHashByteLength,
    identifierByteLength,
    maximumCanonicalDataChunkByteLength,
    maximumDeletionBatchRecordCount,
    canonicalCommonProofOutputChunkByteLength,
    maximumCommonProofOutputChunkCount,
    maximumCommonProofOutputByteLength,
    canonicalOutputKeyDomain,
    checkpointStateStreamDomain,
    maximumCheckpointCursorManifestByteLength,
    textEncoder,
    isSafeUnsigned32,
    isNonzeroUnsigned16,
    copyExactBytes,
    bytesEqual,
    bytesToHex,
    deriveCommonProofAttemptLogicalRecordPrefix,
    commonProofApplicationHandoffLogicalRecordKey,
    unsigned32Bytes,
    hexToExactBytes,
    copyCheckpointResumeDescriptor,
    destroyCheckpointResumeDescriptor,
    destroyIdentifierInput,
    allObjectDescriptors,
    destroyExternalMemoryObjectInMemory,
    checkpointEnvironmentBindingHash,
    encodePublicRecord,
    decodePublicRecord,
    closeTransactionAfterFailure,
    validateLimits,
    copyIdentifierInput,
    type CommonProofExternalMemoryIdentifierInput,
    type ExternalMemoryRecordDescriptor,
    type ExternalMemoryObjectState,
    type ExternalMemoryDeletionState,
    type StagedExternalMemoryRecordChange,
    type ExternalMemoryShadowState,
    type CanonicalOutputChunk,
    type CommonProofBrowserCustodyLimits,
    type CommonProofBrowserCustodyInput,
    type CommonProofCheckpointResumeDescriptor,
    type CommonProofApplicationHandoff,
    type CommonProofCheckpointCustody,
    type CommonProofBrowserCustody,
    type CommonProofBrowserCustodyPhysicalAccountingSnapshot,
    type CommonProofPayloadBufferOwnership,
    type CommonProofPayloadBufferAccounting,
    CommonProofPayloadBufferOwnershipLedger,
} from './records.js';

export {
    commonProofApplicationHandoffLogicalRecordKey,
    commonProofApplicationHandoffMarkerRecordByteLength,
    deriveCommonProofAttemptLogicalRecordPrefix,
} from './records.js';
export type {
    CommonProofApplicationHandoff,
    CommonProofBrowserCustody,
    CommonProofBrowserCustodyPhysicalAccountingSnapshot,
    CommonProofCheckpointResumeDescriptor,
} from './records.js';

const storedRecordDigestDomain =
    'sealed-lattice/common-proof/stored-record-digest/v1';
const storedPayloadDigestDomain =
    'sealed-lattice/common-proof/stored-payload-digest/v1';
const externalMemoryObjectContentGenesisDigestDomain =
    'sealed-lattice/common-proof/external-memory-object-content-genesis/v1';
const externalMemoryObjectContentAppendDigestDomain =
    'sealed-lattice/common-proof/external-memory-object-content-append/v1';
const externalMemoryObjectContentSealDigestDomain =
    'sealed-lattice/common-proof/external-memory-object-content-seal/v1';
const externalMemoryObjectStateDigestDomain =
    'sealed-lattice/common-proof/external-memory-object-state/v1';
const externalMemoryDeletionStateGenesisDigestDomain =
    'sealed-lattice/common-proof/external-memory-deletion-state-genesis/v1';
const externalMemoryDeletionStateAppendDigestDomain =
    'sealed-lattice/common-proof/external-memory-deletion-state-append/v1';
const checkpointExternalMemoryStateDigestDomain =
    'sealed-lattice/common-proof/checkpoint-external-memory-state/v1';
const checkpointExternalMemoryStateDigestVersion = 1;
const checkpointExternalMemoryStateTrailerByteLength = foundationHashByteLength;

const destroyOwnedPayloadBuffer = (bytes: Uint8Array | undefined): void => {
    if (bytes === undefined) {
        return;
    }
    if (!(bytes.buffer instanceof ArrayBuffer)) {
        bytes.fill(0);
        return;
    }
    const buffer = bytes.buffer;
    if (buffer.byteLength === 0) {
        return;
    }
    if (bytes.byteOffset !== 0 || bytes.byteLength !== buffer.byteLength) {
        bytes.fill(0);
        return;
    }
    new Uint8Array(buffer).fill(0);
    structuredClone(buffer, { transfer: [buffer] });
};

const emptyPayloadBufferAccounting = (): CommonProofPayloadBufferAccounting =>
    Object.freeze({
        claimedBufferCount: 0n,
        claimedByteLength: 0n,
        maximumLiveBufferByteLength: 0n,
        maximumLiveBufferCount: 0,
        releasedBufferCount: 0n,
        releasedByteLength: 0n,
        secretRecordOpenByteLength: 0n,
        secretRecordOpenCount: 0n,
        secretRecordSealByteLength: 0n,
        secretRecordSealCount: 0n,
        transferredBufferCount: 0n,
        transferredByteLength: 0n,
    });

const addPayloadBufferAccounting = (
    accumulated: CommonProofPayloadBufferAccounting,
    transaction: CommonProofPayloadBufferAccounting,
): CommonProofPayloadBufferAccounting =>
    Object.freeze({
        claimedBufferCount:
            accumulated.claimedBufferCount + transaction.claimedBufferCount,
        claimedByteLength:
            accumulated.claimedByteLength + transaction.claimedByteLength,
        maximumLiveBufferByteLength:
            accumulated.maximumLiveBufferByteLength >
            transaction.maximumLiveBufferByteLength
                ? accumulated.maximumLiveBufferByteLength
                : transaction.maximumLiveBufferByteLength,
        maximumLiveBufferCount: Math.max(
            accumulated.maximumLiveBufferCount,
            transaction.maximumLiveBufferCount,
        ),
        releasedBufferCount:
            accumulated.releasedBufferCount + transaction.releasedBufferCount,
        releasedByteLength:
            accumulated.releasedByteLength + transaction.releasedByteLength,
        secretRecordOpenByteLength:
            accumulated.secretRecordOpenByteLength +
            transaction.secretRecordOpenByteLength,
        secretRecordOpenCount:
            accumulated.secretRecordOpenCount +
            transaction.secretRecordOpenCount,
        secretRecordSealByteLength:
            accumulated.secretRecordSealByteLength +
            transaction.secretRecordSealByteLength,
        secretRecordSealCount:
            accumulated.secretRecordSealCount +
            transaction.secretRecordSealCount,
        transferredBufferCount:
            accumulated.transferredBufferCount +
            transaction.transferredBufferCount,
        transferredByteLength:
            accumulated.transferredByteLength +
            transaction.transferredByteLength,
    });

const unsigned16Bytes = (value: number): Uint8Array<ArrayBuffer> => {
    const bytes = new Uint8Array(2);
    new DataView(bytes.buffer).setUint16(0, value, true);
    return bytes;
};

const unsigned64Bytes = (value: bigint): Uint8Array<ArrayBuffer> => {
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, value, true);
    return bytes;
};

const custodyDigestParts = (
    domain: string,
    parts: readonly Uint8Array[],
): Uint8Array<ArrayBuffer> => {
    const hash = shake256.create({ dkLen: foundationHashByteLength });
    try {
        const domainBytes = textEncoder.encode(domain);
        hash.update(unsigned32Bytes(domainBytes.byteLength));
        hash.update(domainBytes);
        for (const part of parts) {
            hash.update(unsigned32Bytes(part.byteLength));
            hash.update(part);
        }
        return hash.digest();
    } finally {
        hash.destroy();
    }
};

const custodyDigest = (
    domain: string,
    bytes: Uint8Array,
): Uint8Array<ArrayBuffer> => custodyDigestParts(domain, [bytes]);

export const openCommonProofBrowserCustody = (
    input: CommonProofBrowserCustodyInput,
): CommonProofBrowserCustody => {
    if (typeof input !== 'object' || input === null) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'Common-proof browser custody requires a configuration object.',
        );
    }
    const applicationStatementSchemaIdentifier =
        input.applicationStatementSchemaIdentifier;
    if (!isNonzeroUnsigned16(applicationStatementSchemaIdentifier)) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The common-proof application-statement schema identifier is not a nonzero unsigned 16-bit value.',
        );
    }
    const scratchStorage = openClosedWorkerCommonProofScratchStorage(
        input.workerKernel,
    );
    let actionRandomnessCommitment = new Uint8Array(0);
    let commonProofEnvironmentIdentifier = new Uint8Array(0);
    let commonProofRuntimeBindingHash = new Uint8Array(0);
    let proofAttemptLineageIdentifier = new Uint8Array(0);
    let limits: CommonProofBrowserCustodyLimits;
    let attemptLogicalRecordPrefix = '';
    let applicationHandoffLogicalRecordKey = '';
    let latestCheckpointResumeDescriptor:
        | CommonProofCheckpointResumeDescriptor
        | undefined;
    let initialCheckpointOperationIdentity:
        | CheckpointOperationIdentity
        | undefined;
    try {
        actionRandomnessCommitment = copyExactBytes(
            input.actionRandomnessCommitment,
            foundationHashByteLength,
            'Action-randomness commitment',
        );
        commonProofEnvironmentIdentifier = copyExactBytes(
            input.commonProofEnvironmentIdentifier,
            identifierByteLength,
            'Common-proof environment identifier',
        );
        commonProofRuntimeBindingHash = copyExactBytes(
            input.commonProofRuntimeBindingHash,
            foundationHashByteLength,
            'Common-proof runtime-binding hash',
        );
        proofAttemptLineageIdentifier = copyExactBytes(
            input.proofAttemptLineageIdentifier,
            identifierByteLength,
            'Proof-attempt lineage identifier',
        );
        limits = validateLimits(input.limits);
        attemptLogicalRecordPrefix =
            deriveCommonProofAttemptLogicalRecordPrefix({
                commonProofEnvironmentIdentifier,
                commonProofRuntimeBindingHash,
                proofAttemptLineageIdentifier,
            });
        applicationHandoffLogicalRecordKey =
            commonProofApplicationHandoffLogicalRecordKey;
        latestCheckpointResumeDescriptor =
            input.checkpoint !== undefined &&
            'resumeDescriptor' in input.checkpoint
                ? copyCheckpointResumeDescriptor(
                      input.checkpoint.resumeDescriptor,
                  )
                : undefined;
        initialCheckpointOperationIdentity =
            input.checkpoint !== undefined &&
            'operationIdentity' in input.checkpoint
                ? input.checkpoint.operationIdentity
                : undefined;
        if (
            latestCheckpointResumeDescriptor !== undefined &&
            (!bytesEqual(
                latestCheckpointResumeDescriptor.commonProofEnvironmentIdentifier,
                commonProofEnvironmentIdentifier,
            ) ||
                !bytesEqual(
                    latestCheckpointResumeDescriptor.stableAttemptBindingHash,
                    commonProofRuntimeBindingHash,
                ) ||
                latestCheckpointResumeDescriptor.privateRandomnessStreamAttemptIdentifier ===
                    undefined ||
                !bytesEqual(
                    latestCheckpointResumeDescriptor.privateRandomnessStreamAttemptIdentifier,
                    proofAttemptLineageIdentifier,
                ))
        ) {
            throw new BrowserActionStorageCustodyError(
                'RecordAuthenticationFailed',
                'The resumed common-proof environment, runtime binding, or proof-attempt lineage differs from the authenticated checkpoint.',
            );
        }
        if (initialCheckpointOperationIdentity !== undefined) {
            const boundProofAttemptLineageIdentifier =
                initialCheckpointOperationIdentity.privateRandomnessStreamAttemptIdentifier;
            if (
                boundProofAttemptLineageIdentifier === undefined ||
                !bytesEqual(
                    boundProofAttemptLineageIdentifier,
                    proofAttemptLineageIdentifier,
                )
            ) {
                boundProofAttemptLineageIdentifier?.fill(0);
                throw new BrowserActionStorageCustodyError(
                    'RecordAuthenticationFailed',
                    'The reserved checkpoint lineage is not bound to this common-proof attempt.',
                );
            }
            boundProofAttemptLineageIdentifier.fill(0);
        }
        if (input.checkpoint !== undefined) {
            input.checkpoint.store.copyPhysicalAccounting(
                input.checkpoint.physicalAccountingScope,
            );
        }
    } catch (error) {
        actionRandomnessCommitment?.fill(0);
        commonProofEnvironmentIdentifier?.fill(0);
        commonProofRuntimeBindingHash?.fill(0);
        proofAttemptLineageIdentifier?.fill(0);
        if (latestCheckpointResumeDescriptor !== undefined) {
            destroyCheckpointResumeDescriptor(latestCheckpointResumeDescriptor);
        }
        throw error;
    }
    const objects = new Map<number, ExternalMemoryObjectState>();
    const outputChunks = new Map<number, CanonicalOutputChunk>();
    let externalMemoryPayloadByteLength = 0n;
    let externalMemoryRecordCount = 0;
    let payloadBufferAccounting = emptyPayloadBufferAccounting();
    let secretRecordOpenByteLength = 0n;
    let secretRecordOpenCount = 0n;
    let secretRecordOpenPlaintextByteLength = 0n;
    let secretRecordSealByteLength = 0n;
    let secretRecordSealCount = 0n;
    let secretRecordSealCiphertextByteLength = 0n;
    let ciphertextReadByteLength = 0;
    let ciphertextReadCallCount = 0;
    let ciphertextWriteByteLength = 0;
    let ciphertextWriteCallCount = 0;
    let commitReadbackByteLength = 0;
    let commitReadbackCallCount = 0;
    let deterministicRegeneratedByteLength = 0;
    let deterministicRegenerationCallCount = 0;
    let plaintextReadByteLength = 0;
    let plaintextReadCallCount = 0;
    let plaintextWriteByteLength = 0;
    let plaintextWriteCallCount = 0;
    let cleanupDurationMilliseconds = 0;
    let outputByteLength = 0;
    let outputSealed = false;
    let outputTerminalChunkIndex: number | undefined;
    let capacityReservationReleased = false;
    let checkpointPhysicalAccountingScopeReleased =
        input.checkpoint === undefined;
    let checkpointEvictionCompleted = false;
    let durableProofRecordsDeleted = false;
    let terminalCheckpointLineageIdentifier:
        | Uint8Array<ArrayBuffer>
        | undefined;
    let terminalCheckpointOperationIdentity:
        | CheckpointOperationIdentity
        | undefined;
    let retirementCleanupCompleted = false;
    let applicationHandoffArmed = false;
    let state: 'open' | 'releasing-external-memory' | 'retiring' | 'retired' =
        'open';
    let checkpointOperationIdentity = initialCheckpointOperationIdentity;
    let checkpointRestoreAttempted = false;
    let checkpointExternalMemoryStateConfirmed =
        latestCheckpointResumeDescriptor === undefined;
    const checkedAccountingAdd = (
        currentValue: number,
        increment: number,
        label: string,
    ): number => {
        const result = currentValue + increment;
        if (!Number.isSafeInteger(result) || result < 0) {
            throw new BrowserActionStorageCustodyError(
                'StorageFailure',
                `${label} exceeded the safe accounting range.`,
            );
        }
        return result;
    };
    const externalMemoryProtectionCode = (
        protection: ExternalMemoryObjectState['protection'],
    ): number => (protection === 'public-integrity' ? 1 : 2);
    const initialExternalMemoryObjectContentDigest = (inputValue: {
        exactByteLength: bigint;
        objectOrdinal: number;
        protection: ExternalMemoryObjectState['protection'];
    }): Uint8Array<ArrayBuffer> =>
        custodyDigestParts(externalMemoryObjectContentGenesisDigestDomain, [
            commonProofEnvironmentIdentifier,
            commonProofRuntimeBindingHash,
            proofAttemptLineageIdentifier,
            unsigned32Bytes(inputValue.objectOrdinal),
            unsigned16Bytes(
                externalMemoryProtectionCode(inputValue.protection),
            ),
            unsigned64Bytes(inputValue.exactByteLength),
        ]);
    const appendedExternalMemoryObjectContentDigest = (inputValue: {
        byteOffset: bigint;
        chunkByteLength: number;
        chunkOrdinal: number;
        currentContentDigest: Uint8Array;
        payload: Uint8Array;
    }): Uint8Array<ArrayBuffer> => {
        const payloadDigest = custodyDigest(
            storedPayloadDigestDomain,
            inputValue.payload,
        );
        try {
            return custodyDigestParts(
                externalMemoryObjectContentAppendDigestDomain,
                [
                    inputValue.currentContentDigest,
                    unsigned32Bytes(inputValue.chunkOrdinal),
                    unsigned64Bytes(inputValue.byteOffset),
                    unsigned32Bytes(inputValue.chunkByteLength),
                    payloadDigest,
                ],
            );
        } finally {
            payloadDigest.fill(0);
        }
    };
    const sealedExternalMemoryObjectContentDigest = (inputValue: {
        contentDigest: Uint8Array;
        exactByteLength: bigint;
        sealMarkerChunkOrdinal: number;
    }): Uint8Array<ArrayBuffer> =>
        custodyDigestParts(externalMemoryObjectContentSealDigestDomain, [
            inputValue.contentDigest,
            unsigned64Bytes(inputValue.exactByteLength),
            unsigned32Bytes(inputValue.sealMarkerChunkOrdinal),
        ]);
    const externalMemoryObjectStateDigest = (inputValue: {
        object: ExternalMemoryObjectState;
        objectOrdinal: number;
    }): Uint8Array<ArrayBuffer> => {
        const { object, objectOrdinal } = inputValue;
        const sealed = object.sealMarker !== undefined;
        const expectedNextChunkOrdinal =
            object.chunks.length + (sealed ? 2 : 1);
        if (
            !isSafeUnsigned32(objectOrdinal) ||
            object.contentDigest.byteLength !== foundationHashByteLength ||
            sealed !== (object.sealedContentDigest !== undefined) ||
            object.appendedByteLength < 0n ||
            object.appendedByteLength > object.exactByteLength ||
            !Number.isSafeInteger(object.maximumAppendByteLength) ||
            object.maximumAppendByteLength <= 0 ||
            object.maximumAppendByteLength >
                maximumCanonicalDataChunkByteLength ||
            !isSafeUnsigned32(expectedNextChunkOrdinal) ||
            object.nextChunkOrdinal !== expectedNextChunkOrdinal ||
            !isSafeUnsigned32(object.nextChunkOrdinal)
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'A common-proof external-memory object has malformed checkpoint state.',
            );
        }
        return custodyDigestParts(externalMemoryObjectStateDigestDomain, [
            commonProofEnvironmentIdentifier,
            commonProofRuntimeBindingHash,
            proofAttemptLineageIdentifier,
            unsigned32Bytes(objectOrdinal),
            unsigned16Bytes(externalMemoryProtectionCode(object.protection)),
            unsigned64Bytes(object.exactByteLength),
            unsigned64Bytes(object.appendedByteLength),
            unsigned32Bytes(object.maximumAppendByteLength),
            unsigned32Bytes(object.nextChunkOrdinal),
            unsigned16Bytes(sealed ? 1 : 0),
            object.contentDigest,
            ...(object.sealedContentDigest === undefined
                ? []
                : [object.sealedContentDigest]),
        ]);
    };
    let externalMemoryDeletionState: ExternalMemoryDeletionState = {
        deletedObjectCount: 0,
        deletionStateDigest: custodyDigestParts(
            externalMemoryDeletionStateGenesisDigestDomain,
            [
                commonProofEnvironmentIdentifier,
                commonProofRuntimeBindingHash,
                proofAttemptLineageIdentifier,
            ],
        ),
    };
    const appendedExternalMemoryDeletionStateDigest = (inputValue: {
        currentDeletionStateDigest: Uint8Array;
        deletedObjectCount: number;
        objectOrdinal: number;
        objectStateDigest: Uint8Array;
    }): Uint8Array<ArrayBuffer> =>
        custodyDigestParts(externalMemoryDeletionStateAppendDigestDomain, [
            inputValue.currentDeletionStateDigest,
            unsigned32Bytes(inputValue.deletedObjectCount),
            unsigned32Bytes(inputValue.objectOrdinal),
            inputValue.objectStateDigest,
        ]);
    const checkpointExternalMemoryStateDigest = (): Uint8Array<ArrayBuffer> => {
        const liveObjects = [...objects].sort(
            ([leftOrdinal], [rightOrdinal]) => leftOrdinal - rightOrdinal,
        );
        if (liveObjects.length > 0xffff_ffff) {
            throw new BrowserActionStorageCustodyError(
                'StorageFailure',
                'Common-proof checkpoint external-memory state exceeds its canonical count range.',
            );
        }
        const temporaryObjectStateDigests: Uint8Array<ArrayBuffer>[] = [];
        try {
            const parts: Uint8Array[] = [
                unsigned16Bytes(checkpointExternalMemoryStateDigestVersion),
                commonProofEnvironmentIdentifier,
                commonProofRuntimeBindingHash,
                proofAttemptLineageIdentifier,
                unsigned32Bytes(liveObjects.length),
            ];
            for (const [objectOrdinal, object] of liveObjects) {
                const objectStateDigest = externalMemoryObjectStateDigest({
                    object,
                    objectOrdinal,
                });
                temporaryObjectStateDigests.push(objectStateDigest);
                parts.push(unsigned32Bytes(objectOrdinal), objectStateDigest);
            }
            if (
                !isSafeUnsigned32(
                    externalMemoryDeletionState.deletedObjectCount,
                ) ||
                externalMemoryDeletionState.deletionStateDigest.byteLength !==
                    foundationHashByteLength
            ) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidState',
                    'A common-proof checkpoint boundary has malformed deletion state.',
                );
            }
            parts.push(
                unsigned32Bytes(externalMemoryDeletionState.deletedObjectCount),
                externalMemoryDeletionState.deletionStateDigest,
            );
            return custodyDigestParts(
                checkpointExternalMemoryStateDigestDomain,
                parts,
            );
        } finally {
            for (const objectStateDigest of temporaryObjectStateDigests) {
                objectStateDigest.fill(0);
            }
        }
    };
    const authenticatedCheckpointStateBytes = (inputValue: {
        canonicalStateBytes: Uint8Array;
        externalMemoryStateDigest: Uint8Array;
    }): Uint8Array<ArrayBuffer> => {
        if (
            inputValue.canonicalStateBytes.byteLength === 0 ||
            inputValue.externalMemoryStateDigest.byteLength !==
                checkpointExternalMemoryStateTrailerByteLength ||
            inputValue.canonicalStateBytes.byteLength >
                foundationProfile.maximumCanonicalStreamByteLength -
                    checkpointExternalMemoryStateTrailerByteLength
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'A common-proof checkpoint state cannot carry its authenticated external-memory trailer.',
            );
        }
        const authenticatedStateBytes = new Uint8Array(
            inputValue.canonicalStateBytes.byteLength +
                checkpointExternalMemoryStateTrailerByteLength,
        );
        authenticatedStateBytes.set(inputValue.canonicalStateBytes);
        authenticatedStateBytes.set(
            inputValue.externalMemoryStateDigest,
            inputValue.canonicalStateBytes.byteLength,
        );
        return authenticatedStateBytes;
    };
    const checkpointStateChunks = (
        authenticatedStateBytes: Uint8Array,
    ): readonly Uint8Array[] => {
        const chunks: Uint8Array[] = [];
        for (
            let byteOffset = 0;
            byteOffset < authenticatedStateBytes.byteLength;
            byteOffset += foundationProfile.streamChunkByteLength
        ) {
            chunks.push(
                authenticatedStateBytes.subarray(
                    byteOffset,
                    Math.min(
                        authenticatedStateBytes.byteLength,
                        byteOffset + foundationProfile.streamChunkByteLength,
                    ),
                ),
            );
        }
        return Object.freeze(chunks);
    };
    const monotonicMilliseconds = (): number =>
        globalThis.performance?.now() ?? Date.now();
    const recordStorageRead = (
        storedByteLength: number,
        payloadByteLength: number,
    ): void => {
        ciphertextReadCallCount = checkedAccountingAdd(
            ciphertextReadCallCount,
            1,
            'Common-proof ciphertext read count',
        );
        ciphertextReadByteLength = checkedAccountingAdd(
            ciphertextReadByteLength,
            storedByteLength,
            'Common-proof ciphertext read bytes',
        );
        plaintextReadCallCount = checkedAccountingAdd(
            plaintextReadCallCount,
            1,
            'Common-proof plaintext read count',
        );
        plaintextReadByteLength = checkedAccountingAdd(
            plaintextReadByteLength,
            payloadByteLength,
            'Common-proof plaintext read bytes',
        );
    };
    const recordStoredBytesRead = (storedByteLength: number): void => {
        ciphertextReadCallCount = checkedAccountingAdd(
            ciphertextReadCallCount,
            1,
            'Common-proof ciphertext read count',
        );
        ciphertextReadByteLength = checkedAccountingAdd(
            ciphertextReadByteLength,
            storedByteLength,
            'Common-proof ciphertext read bytes',
        );
    };
    const recordStorageWrite = (
        storedByteLength: number,
        payloadByteLength: number,
    ): void => {
        ciphertextWriteCallCount = checkedAccountingAdd(
            ciphertextWriteCallCount,
            1,
            'Common-proof ciphertext write count',
        );
        ciphertextWriteByteLength = checkedAccountingAdd(
            ciphertextWriteByteLength,
            storedByteLength,
            'Common-proof ciphertext write bytes',
        );
        plaintextWriteCallCount = checkedAccountingAdd(
            plaintextWriteCallCount,
            1,
            'Common-proof plaintext write count',
        );
        plaintextWriteByteLength = checkedAccountingAdd(
            plaintextWriteByteLength,
            payloadByteLength,
            'Common-proof plaintext write bytes',
        );
    };
    const recordCommitReadback = (byteLength: number): void => {
        commitReadbackCallCount = checkedAccountingAdd(
            commitReadbackCallCount,
            1,
            'Common-proof commit-readback count',
        );
        commitReadbackByteLength = checkedAccountingAdd(
            commitReadbackByteLength,
            byteLength,
            'Common-proof commit-readback bytes',
        );
    };
    const assertOpen = (): void => {
        if (state !== 'open') {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'The common-proof browser custody environment is not open.',
            );
        }
    };

    const preserveCheckpointLineageForTerminalCleanup = (): void => {
        if (
            checkpointEvictionCompleted ||
            terminalCheckpointLineageIdentifier !== undefined
        ) {
            return;
        }
        if (input.checkpoint === undefined) {
            checkpointEvictionCompleted = true;
            return;
        }
        terminalCheckpointOperationIdentity ??= checkpointOperationIdentity;
        const checkpointLineageIdentifier =
            latestCheckpointResumeDescriptor?.checkpointLineageIdentifier ??
            terminalCheckpointOperationIdentity?.checkpointLineageIdentifier;
        if (checkpointLineageIdentifier === undefined) {
            checkpointEvictionCompleted = true;
            return;
        }
        terminalCheckpointLineageIdentifier =
            checkpointLineageIdentifier.slice();
    };

    const permanentlyRetireInMemory = (
        preserveCheckpointForCleanup = true,
    ): void => {
        if (preserveCheckpointForCleanup) {
            preserveCheckpointLineageForTerminalCleanup();
        }
        state = 'retired';
        actionRandomnessCommitment.fill(0);
        commonProofEnvironmentIdentifier.fill(0);
        commonProofRuntimeBindingHash.fill(0);
        proofAttemptLineageIdentifier.fill(0);
        for (const object of objects.values()) {
            destroyExternalMemoryObjectInMemory(object);
        }
        externalMemoryDeletionState.deletionStateDigest.fill(0);
        checkpointOperationIdentity = undefined;
        if (latestCheckpointResumeDescriptor !== undefined) {
            destroyCheckpointResumeDescriptor(latestCheckpointResumeDescriptor);
            latestCheckpointResumeDescriptor = undefined;
        }
    };

    const checkpointBoundary = (inputValue: {
        authenticatedStateBytes?: Uint8Array;
        commonProofEnvironmentIdentifier: Uint8Array;
        generationCursorManifestBytes: Uint8Array;
        privateRandomnessStreamAttemptIdentifier?: Uint8Array;
        safeBoundaryOrdinal: number;
        stableAttemptBindingHash: Uint8Array;
    }): CheckpointBoundary | ExpectedCheckpointBoundary => {
        if (input.checkpoint === undefined) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'Common-proof checkpoint custody is not configured.',
            );
        }
        const environmentBindingHash = checkpointEnvironmentBindingHash({
            commonProofEnvironmentIdentifier:
                inputValue.commonProofEnvironmentIdentifier,
            commonProofRuntimeBindingHash,
            proofAttemptLineageIdentifier,
        });
        return Object.freeze({
            operationKind: applicationStatementSchemaIdentifier,
            orderedSourceDigests: Object.freeze([
                commonProofRuntimeBindingHash.slice(),
                inputValue.stableAttemptBindingHash.slice(),
                environmentBindingHash,
            ]),
            privateRandomCursorManifestBytes:
                inputValue.generationCursorManifestBytes.slice(),
            ...(inputValue.privateRandomnessStreamAttemptIdentifier ===
            undefined
                ? {}
                : {
                      privateRandomnessStreamAttemptIdentifier:
                          inputValue.privateRandomnessStreamAttemptIdentifier.slice(),
                  }),
            safeBoundaryOrdinal: inputValue.safeBoundaryOrdinal,
            ...(inputValue.authenticatedStateBytes === undefined
                ? {}
                : {
                      stateStreamDescriptorBytes:
                          describeAuthenticatedCheckpointStateStream({
                              stateBytes: inputValue.authenticatedStateBytes,
                              stateStreamDomain: checkpointStateStreamDomain,
                          }),
                  }),
            stateStreamDomain: checkpointStateStreamDomain,
        });
    };

    const configuredCheckpointCustody:
        | CommonProofCheckpointCustody
        | undefined =
        input.checkpoint === undefined
            ? undefined
            : Object.freeze({
                  publishAuthenticatedCheckpoint: async (
                      checkpoint: CommonProofGenerationCheckpoint,
                  ): Promise<void> => {
                      assertOpen();
                      if (
                          !(
                              checkpoint.canonicalStateBytes instanceof
                              Uint8Array
                          ) ||
                          checkpoint.canonicalStateBytes.byteLength === 0 ||
                          !(
                              checkpoint.stableAttemptBindingHash instanceof
                              Uint8Array
                          ) ||
                          checkpoint.stableAttemptBindingHash.byteLength !==
                              foundationHashByteLength ||
                          !(
                              checkpoint.generationCursorManifestBytes instanceof
                              Uint8Array
                          ) ||
                          checkpoint.generationCursorManifestBytes
                              .byteLength === 0 ||
                          checkpoint.generationCursorManifestBytes.byteLength >
                              maximumCheckpointCursorManifestByteLength ||
                          (checkpoint.privateRandomnessStreamAttemptIdentifier !==
                              undefined &&
                              (!(
                                  checkpoint.privateRandomnessStreamAttemptIdentifier instanceof
                                  Uint8Array
                              ) ||
                                  checkpoint
                                      .privateRandomnessStreamAttemptIdentifier
                                      .byteLength !== identifierByteLength)) ||
                          !isSafeUnsigned32(checkpoint.safeBoundaryOrdinal)
                      ) {
                          throw new BrowserActionStorageCustodyError(
                              'InvalidInput',
                              'The common-proof kernel exposed a malformed checkpoint.',
                          );
                      }
                      if (!checkpointExternalMemoryStateConfirmed) {
                          throw new BrowserActionStorageCustodyError(
                              'InvalidState',
                              'A resumed common-proof attempt cannot publish before its external-memory state is confirmed.',
                          );
                      }
                      if (
                          !bytesEqual(
                              checkpoint.stableAttemptBindingHash,
                              commonProofRuntimeBindingHash,
                          )
                      ) {
                          throw new BrowserActionStorageCustodyError(
                              'RecordAuthenticationFailed',
                              'A common-proof checkpoint differs from its installed runtime binding.',
                          );
                      }
                      if (
                          latestCheckpointResumeDescriptor !== undefined &&
                          !bytesEqual(
                              latestCheckpointResumeDescriptor.stableAttemptBindingHash,
                              checkpoint.stableAttemptBindingHash,
                          )
                      ) {
                          throw new BrowserActionStorageCustodyError(
                              'RecordAuthenticationFailed',
                              'A common-proof checkpoint changed its stable attempt binding.',
                          );
                      }
                      const generationCursorManifestBytes = Uint8Array.from(
                          checkpoint.generationCursorManifestBytes,
                      );
                      let externalMemoryStateDigest = new Uint8Array(0);
                      let authenticatedStateBytes = new Uint8Array(0);
                      let privateRandomnessStreamAttemptIdentifier:
                          | Uint8Array<ArrayBuffer>
                          | undefined;
                      try {
                          externalMemoryStateDigest =
                              checkpointExternalMemoryStateDigest();
                          authenticatedStateBytes =
                              authenticatedCheckpointStateBytes({
                                  canonicalStateBytes:
                                      checkpoint.canonicalStateBytes,
                                  externalMemoryStateDigest,
                              });
                          privateRandomnessStreamAttemptIdentifier =
                              checkpoint.privateRandomnessStreamAttemptIdentifier?.slice();
                          const boundary = checkpointBoundary({
                              authenticatedStateBytes,
                              commonProofEnvironmentIdentifier,
                              generationCursorManifestBytes,
                              ...(privateRandomnessStreamAttemptIdentifier ===
                              undefined
                                  ? {}
                                  : {
                                        privateRandomnessStreamAttemptIdentifier,
                                    }),
                              safeBoundaryOrdinal:
                                  checkpoint.safeBoundaryOrdinal,
                              stableAttemptBindingHash:
                                  checkpoint.stableAttemptBindingHash,
                          }) as CheckpointBoundary;
                          if (checkpointOperationIdentity === undefined) {
                              throw new BrowserActionStorageCustodyError(
                                  'InvalidState',
                                  'Fresh common-proof checkpoint publication lost its pre-bound lineage identity.',
                              );
                          }
                          await input.checkpoint!.store.publish({
                              boundary,
                              identity: checkpointOperationIdentity,
                              stateChunks: checkpointStateChunks(
                                  authenticatedStateBytes,
                              ),
                          });
                          const nextResumeDescriptor =
                              copyCheckpointResumeDescriptor({
                                  checkpointLineageIdentifier:
                                      checkpointOperationIdentity.checkpointLineageIdentifier,
                                  commonProofEnvironmentIdentifier,
                                  externalMemoryStateDigest,
                                  generationCursorManifestBytes,
                                  ...(privateRandomnessStreamAttemptIdentifier ===
                                  undefined
                                      ? {}
                                      : {
                                            privateRandomnessStreamAttemptIdentifier,
                                        }),
                                  safeBoundaryOrdinal:
                                      checkpoint.safeBoundaryOrdinal,
                                  stableAttemptBindingHash:
                                      checkpoint.stableAttemptBindingHash,
                              });
                          if (latestCheckpointResumeDescriptor !== undefined) {
                              destroyCheckpointResumeDescriptor(
                                  latestCheckpointResumeDescriptor,
                              );
                          }
                          latestCheckpointResumeDescriptor =
                              nextResumeDescriptor;
                      } finally {
                          authenticatedStateBytes.fill(0);
                          externalMemoryStateDigest.fill(0);
                          generationCursorManifestBytes.fill(0);
                          privateRandomnessStreamAttemptIdentifier?.fill(0);
                      }
                  },
                  restoreAuthenticatedCheckpoint: async (): Promise<
                      Readonly<{
                          canonicalStateBytes: Uint8Array;
                          generationCursorManifestBytes: Uint8Array;
                      }>
                  > => {
                      assertOpen();
                      if (
                          checkpointRestoreAttempted ||
                          latestCheckpointResumeDescriptor === undefined
                      ) {
                          throw new BrowserActionStorageCustodyError(
                              'InvalidState',
                              'The common-proof checkpoint cannot be restored in its current state.',
                          );
                      }
                      checkpointRestoreAttempted = true;
                      try {
                          const resumeDescriptor =
                              latestCheckpointResumeDescriptor;
                          const expectedBoundary = checkpointBoundary({
                              commonProofEnvironmentIdentifier:
                                  resumeDescriptor.commonProofEnvironmentIdentifier,
                              generationCursorManifestBytes:
                                  resumeDescriptor.generationCursorManifestBytes,
                              ...(resumeDescriptor.privateRandomnessStreamAttemptIdentifier ===
                              undefined
                                  ? {}
                                  : {
                                        privateRandomnessStreamAttemptIdentifier:
                                            resumeDescriptor.privateRandomnessStreamAttemptIdentifier,
                                    }),
                              safeBoundaryOrdinal:
                                  resumeDescriptor.safeBoundaryOrdinal,
                              stableAttemptBindingHash:
                                  resumeDescriptor.stableAttemptBindingHash,
                          });
                          const resumed = await input.checkpoint!.store.resume({
                              checkpointLineageIdentifier:
                                  resumeDescriptor.checkpointLineageIdentifier,
                              expectedBoundary,
                          });
                          checkpointOperationIdentity =
                              resumed.operationIdentity;
                          const restoredChunks: Uint8Array[] = [];
                          try {
                              await resumed.restoreState(
                                  (chunkIndex, chunkBytes) => {
                                      if (
                                          chunkIndex !== restoredChunks.length
                                      ) {
                                          throw new BrowserActionStorageCustodyError(
                                              'RecordAuthenticationFailed',
                                              'Authenticated common-proof checkpoint chunks are reordered.',
                                          );
                                      }
                                      restoredChunks.push(chunkBytes.slice());
                                  },
                              );
                              const totalByteLength = restoredChunks.reduce(
                                  (sum, chunk) => sum + chunk.byteLength,
                                  0,
                              );
                              const restoredState = new Uint8Array(
                                  totalByteLength,
                              );
                              let offset = 0;
                              for (const chunk of restoredChunks) {
                                  restoredState.set(chunk, offset);
                                  offset += chunk.byteLength;
                              }
                              if (
                                  restoredState.byteLength <=
                                      checkpointExternalMemoryStateTrailerByteLength ||
                                  !bytesEqual(
                                      restoredState.subarray(
                                          restoredState.byteLength -
                                              checkpointExternalMemoryStateTrailerByteLength,
                                      ),
                                      resumeDescriptor.externalMemoryStateDigest,
                                  )
                              ) {
                                  restoredState.fill(0);
                                  throw new BrowserActionStorageCustodyError(
                                      'RecordAuthenticationFailed',
                                      'The authenticated common-proof checkpoint carries another external-memory state.',
                                  );
                              }
                              const canonicalStateBytes = restoredState.slice(
                                  0,
                                  restoredState.byteLength -
                                      checkpointExternalMemoryStateTrailerByteLength,
                              );
                              restoredState.fill(0);
                              let generationCursorManifestBytes =
                                  new Uint8Array(0);
                              try {
                                  generationCursorManifestBytes =
                                      resumeDescriptor.generationCursorManifestBytes.slice();
                                  return Object.freeze({
                                      canonicalStateBytes,
                                      generationCursorManifestBytes,
                                  });
                              } catch (error) {
                                  canonicalStateBytes.fill(0);
                                  generationCursorManifestBytes.fill(0);
                                  throw error;
                              }
                          } finally {
                              for (const chunk of restoredChunks) {
                                  chunk.fill(0);
                              }
                          }
                      } catch (error) {
                          state = 'retiring';
                          const cleanupFailures =
                              await cleanupTerminalProofAuthority();
                          permanentlyRetireInMemory();
                          if (cleanupFailures.length !== 0) {
                              throw new BrowserActionStorageCustodyError(
                                  'StorageFailure',
                                  'Common-proof checkpoint restoration failed and durable retirement was incomplete.',
                                  [error, ...cleanupFailures],
                              );
                          }
                          throw error;
                      }
                  },
              });

    const identifierInput = (inputValue: {
        byteOffset: bigint;
        chunkOrdinal: number;
        objectOrdinal: number;
        recordKind: CommonProofExternalMemoryIdentifierInput['externalMemoryRecordKind'];
    }): CommonProofExternalMemoryIdentifierInput => {
        let environmentIdentifier = new Uint8Array(0);
        let runtimeBindingHash = new Uint8Array(0);
        let attemptLineageIdentifier = new Uint8Array(0);
        try {
            environmentIdentifier = commonProofEnvironmentIdentifier.slice();
            runtimeBindingHash = commonProofRuntimeBindingHash.slice();
            attemptLineageIdentifier = proofAttemptLineageIdentifier.slice();
            return Object.freeze({
                commonProofEnvironmentIdentifier: environmentIdentifier,
                commonProofRuntimeBindingHash: runtimeBindingHash,
                externalMemoryByteOffset: inputValue.byteOffset,
                externalMemoryChunkOrdinal: inputValue.chunkOrdinal,
                externalMemoryObjectOrdinal: inputValue.objectOrdinal,
                externalMemoryRecordKind: inputValue.recordKind,
                proofAttemptLineageIdentifier: attemptLineageIdentifier,
                recordType: 'commonProofExternalMemory',
            });
        } catch (error) {
            environmentIdentifier.fill(0);
            runtimeBindingHash.fill(0);
            attemptLineageIdentifier.fill(0);
            throw error;
        }
    };

    const createDescriptor = async (
        recordInput: CommonProofExternalMemoryIdentifierInput,
        protection: ExternalMemoryRecordDescriptor['protection'],
    ): Promise<ExternalMemoryRecordDescriptor> => {
        let identifier: Uint8Array = new Uint8Array(0);
        try {
            identifier =
                await scratchStorage.deriveRecordIdentifier(recordInput);
            if (
                !(identifier instanceof Uint8Array) ||
                identifier.byteLength !== foundationHashByteLength
            ) {
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The worker kernel returned an invalid common-proof external-memory identifier.',
                );
            }
            return Object.freeze({
                identifierInput: copyIdentifierInput(recordInput),
                logicalRecordKey: `${attemptLogicalRecordPrefix}external-memory/${bytesToHex(identifier)}`,
                protection,
            });
        } finally {
            identifier.fill(0);
            destroyIdentifierInput(recordInput);
        }
    };

    const openSecretRecord = async (
        descriptor: ExternalMemoryRecordDescriptor,
        canonicalEnvelope: Uint8Array<ArrayBuffer>,
    ): Promise<Uint8Array<ArrayBuffer>> => {
        const commitmentCopy = actionRandomnessCommitment.slice();
        const identifierInputCopy = copyIdentifierInput(
            descriptor.identifierInput,
        );
        try {
            secretRecordOpenCount += 1n;
            secretRecordOpenByteLength += BigInt(canonicalEnvelope.byteLength);
            const plaintext = await scratchStorage.openRecord({
                actionRandomnessCommitment: commitmentCopy,
                envelope: canonicalEnvelope,
                identifierInput: identifierInputCopy,
            });
            if (!(plaintext instanceof Uint8Array)) {
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The worker kernel returned malformed common-proof external-memory plaintext.',
                );
            }
            secretRecordOpenPlaintextByteLength += BigInt(plaintext.byteLength);
            if (!(plaintext.buffer instanceof ArrayBuffer)) {
                plaintext.fill(0);
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The worker kernel returned malformed common-proof external-memory plaintext.',
                );
            }
            if (
                plaintext.byteOffset === 0 &&
                plaintext.byteLength === plaintext.buffer.byteLength
            ) {
                return plaintext as Uint8Array<ArrayBuffer>;
            }
            const ownedPlaintext = plaintext.slice();
            destroyOwnedPayloadBuffer(plaintext);
            return ownedPlaintext;
        } catch (error) {
            if (error instanceof BrowserActionStorageCustodyError) {
                throw error;
            }
            throw new BrowserActionStorageCustodyError(
                'RecordAuthenticationFailed',
                'A secret common-proof external-memory record could not be opened.',
                error,
            );
        } finally {
            commitmentCopy.fill(0);
            destroyOwnedPayloadBuffer(canonicalEnvelope);
            destroyIdentifierInput(identifierInputCopy);
        }
    };

    const encodeRecord = async (
        descriptor: ExternalMemoryRecordDescriptor,
        payload: Uint8Array<ArrayBuffer>,
    ): Promise<Uint8Array<ArrayBuffer>> => {
        if (descriptor.protection === 'public-integrity') {
            try {
                return encodePublicRecord(descriptor.logicalRecordKey, payload);
            } finally {
                destroyOwnedPayloadBuffer(payload);
            }
        }
        const commitmentCopy = actionRandomnessCommitment.slice();
        const identifierInputCopy = copyIdentifierInput(
            descriptor.identifierInput,
        );
        try {
            secretRecordSealCount += 1n;
            secretRecordSealByteLength += BigInt(payload.byteLength);
            const envelope = await scratchStorage.sealRecord({
                actionRandomnessCommitment: commitmentCopy,
                identifierInput: identifierInputCopy,
                plaintext: payload,
            });
            if (!(envelope instanceof Uint8Array)) {
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The worker kernel returned a malformed secret common-proof external-memory envelope.',
                );
            }
            secretRecordSealCiphertextByteLength += BigInt(envelope.byteLength);
            if (
                !(envelope.buffer instanceof ArrayBuffer) ||
                envelope.byteLength === 0
            ) {
                envelope.fill(0);
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The worker kernel returned a malformed secret common-proof external-memory envelope.',
                );
            }
            if (
                envelope.byteOffset === 0 &&
                envelope.byteLength === envelope.buffer.byteLength
            ) {
                return envelope as Uint8Array<ArrayBuffer>;
            }
            const ownedEnvelope = envelope.slice();
            destroyOwnedPayloadBuffer(envelope);
            return ownedEnvelope;
        } finally {
            commitmentCopy.fill(0);
            destroyIdentifierInput(identifierInputCopy);
            destroyOwnedPayloadBuffer(payload);
        }
    };

    const decodeRecord = async (
        descriptor: ExternalMemoryRecordDescriptor,
        storedBytes: Uint8Array<ArrayBuffer>,
    ): Promise<Uint8Array<ArrayBuffer>> => {
        if (descriptor.protection !== 'public-integrity') {
            return openSecretRecord(descriptor, storedBytes);
        }
        try {
            return decodePublicRecord(descriptor.logicalRecordKey, storedBytes);
        } finally {
            destroyOwnedPayloadBuffer(storedBytes);
        }
    };

    const authenticateRecordBytes =
        (
            descriptor: ExternalMemoryRecordDescriptor,
            expectedRecord: Uint8Array,
        ): UntrustedStorageAuthenticator =>
        ({ bytes, logicalRecordKey }) => {
            if (logicalRecordKey !== descriptor.logicalRecordKey) {
                throw new BrowserActionStorageCustodyError(
                    'RecordAuthenticationFailed',
                    'A common-proof record was returned under the wrong logical key.',
                );
            }
            if (!bytesEqual(bytes, expectedRecord)) {
                throw new BrowserActionStorageCustodyError(
                    'RecordAuthenticationFailed',
                    'A common-proof record does not contain the expected canonical bytes.',
                );
            }
        };

    const authenticateRecordDigest =
        (
            descriptor: ExternalMemoryRecordDescriptor,
            expectedRecordDigest: Uint8Array,
        ): UntrustedStorageAuthenticator =>
        ({ bytes, logicalRecordKey }) => {
            if (logicalRecordKey !== descriptor.logicalRecordKey) {
                throw new BrowserActionStorageCustodyError(
                    'RecordAuthenticationFailed',
                    'A common-proof record was returned under the wrong logical key.',
                );
            }
            const digest = custodyDigest(storedRecordDigestDomain, bytes);
            try {
                if (!bytesEqual(digest, expectedRecordDigest)) {
                    throw new BrowserActionStorageCustodyError(
                        'RecordAuthenticationFailed',
                        'A common-proof record changed after its authenticated commit.',
                    );
                }
            } finally {
                digest.fill(0);
            }
        };

    const readStoredRecord = async (
        descriptor: ExternalMemoryRecordDescriptor,
        expectedPayloadDigest?: Uint8Array,
        beforeAuthentication?: () => void,
        retainStoredBytes = false,
    ): Promise<
        | Readonly<{
              payload: Uint8Array<ArrayBuffer>;
              storedBytes?: Uint8Array<ArrayBuffer>;
          }>
        | undefined
    > => {
        let authenticationFailure: unknown;
        let authenticatedPayload: Uint8Array<ArrayBuffer> | undefined;
        let authenticatedStoredByteLength = 0;
        let retainedStoredBytes: Uint8Array<ArrayBuffer> | undefined;
        if (descriptor.protection === 'secret-authenticated-encryption') {
            try {
                const found = await input.store.consumeAuthenticated({
                    consume: async ({ bytes, logicalRecordKey }) => {
                        try {
                            if (
                                logicalRecordKey !== descriptor.logicalRecordKey
                            ) {
                                throw new BrowserActionStorageCustodyError(
                                    'RecordAuthenticationFailed',
                                    'A common-proof record was returned under the wrong logical key.',
                                );
                            }
                            if (authenticatedPayload !== undefined) {
                                throw new BrowserActionStorageCustodyError(
                                    'StorageFailure',
                                    'A common-proof record was authenticated more than once during one logical read.',
                                );
                            }
                            if (
                                !(bytes.buffer instanceof ArrayBuffer) ||
                                bytes.byteOffset !== 0 ||
                                bytes.byteLength !== bytes.buffer.byteLength
                            ) {
                                throw new BrowserActionStorageCustodyError(
                                    'RecordAuthenticationFailed',
                                    'A common-proof secret record was not returned with exact owned browser bytes.',
                                );
                            }
                            beforeAuthentication?.();
                            authenticatedStoredByteLength = bytes.byteLength;
                            if (retainStoredBytes) {
                                retainedStoredBytes = bytes.slice();
                            }
                            let payload: Uint8Array<ArrayBuffer> | undefined;
                            try {
                                payload = await openSecretRecord(
                                    descriptor,
                                    bytes as Uint8Array<ArrayBuffer>,
                                );
                                if (expectedPayloadDigest !== undefined) {
                                    const digest = custodyDigest(
                                        storedPayloadDigestDomain,
                                        payload,
                                    );
                                    try {
                                        if (
                                            !bytesEqual(
                                                digest,
                                                expectedPayloadDigest,
                                            )
                                        ) {
                                            throw new BrowserActionStorageCustodyError(
                                                'RecordAuthenticationFailed',
                                                'A replayed common-proof record differs from its committed payload.',
                                            );
                                        }
                                    } finally {
                                        digest.fill(0);
                                    }
                                }
                                authenticatedPayload = payload;
                                payload = undefined;
                            } finally {
                                if (payload !== undefined) {
                                    destroyOwnedPayloadBuffer(payload);
                                }
                            }
                        } catch (error) {
                            authenticationFailure = error;
                            throw error;
                        }
                    },
                    logicalRecordKey: descriptor.logicalRecordKey,
                });
                if (!found) {
                    return undefined;
                }
            } catch (error) {
                if (authenticatedPayload !== undefined) {
                    destroyOwnedPayloadBuffer(authenticatedPayload);
                }
                destroyOwnedPayloadBuffer(retainedStoredBytes);
                if (
                    authenticationFailure instanceof
                    BrowserActionStorageCustodyError
                ) {
                    throw authenticationFailure;
                }
                throw error;
            }
            if (authenticatedPayload === undefined) {
                destroyOwnedPayloadBuffer(retainedStoredBytes);
                throw new BrowserActionStorageCustodyError(
                    'RecordAuthenticationFailed',
                    'A common-proof secret record was consumed without one authenticated payload.',
                );
            }
            recordStorageRead(
                authenticatedStoredByteLength,
                authenticatedPayload.byteLength,
            );
            return Object.freeze({
                payload: authenticatedPayload,
                ...(retainedStoredBytes === undefined
                    ? {}
                    : { storedBytes: retainedStoredBytes }),
            });
        }
        let storedBytes: Uint8Array | undefined;
        try {
            storedBytes = await input.store.readAuthenticated({
                authenticate: ({ bytes, logicalRecordKey }) => {
                    try {
                        if (logicalRecordKey !== descriptor.logicalRecordKey) {
                            throw new BrowserActionStorageCustodyError(
                                'RecordAuthenticationFailed',
                                'A common-proof record was returned under the wrong logical key.',
                            );
                        }
                        if (authenticatedPayload !== undefined) {
                            throw new BrowserActionStorageCustodyError(
                                'StorageFailure',
                                'A common-proof record was authenticated more than once during one logical read.',
                            );
                        }
                        beforeAuthentication?.();
                        let payload: Uint8Array<ArrayBuffer> | undefined;
                        try {
                            payload = decodePublicRecord(
                                descriptor.logicalRecordKey,
                                bytes,
                            );
                            if (expectedPayloadDigest !== undefined) {
                                const digest = custodyDigest(
                                    storedPayloadDigestDomain,
                                    payload,
                                );
                                try {
                                    if (
                                        !bytesEqual(
                                            digest,
                                            expectedPayloadDigest,
                                        )
                                    ) {
                                        throw new BrowserActionStorageCustodyError(
                                            'RecordAuthenticationFailed',
                                            'A replayed common-proof record differs from its committed payload.',
                                        );
                                    }
                                } finally {
                                    digest.fill(0);
                                }
                            }
                            authenticatedPayload = payload;
                            payload = undefined;
                        } finally {
                            if (payload !== undefined) {
                                destroyOwnedPayloadBuffer(payload);
                            }
                        }
                    } catch (error) {
                        authenticationFailure = error;
                        throw error;
                    }
                },
                logicalRecordKey: descriptor.logicalRecordKey,
            });
        } catch (error) {
            if (authenticatedPayload !== undefined) {
                destroyOwnedPayloadBuffer(authenticatedPayload);
            }
            if (
                authenticationFailure instanceof
                BrowserActionStorageCustodyError
            ) {
                throw authenticationFailure;
            }
            throw error;
        }
        if (storedBytes === undefined) {
            if (authenticatedPayload !== undefined) {
                destroyOwnedPayloadBuffer(authenticatedPayload);
                throw new BrowserActionStorageCustodyError(
                    'RecordAuthenticationFailed',
                    'A common-proof record was authenticated but not returned in owned browser memory.',
                );
            }
            return undefined;
        }
        if (
            !(storedBytes.buffer instanceof ArrayBuffer) ||
            authenticatedPayload === undefined
        ) {
            storedBytes.fill(0);
            if (authenticatedPayload !== undefined) {
                destroyOwnedPayloadBuffer(authenticatedPayload);
            }
            throw new BrowserActionStorageCustodyError(
                'RecordAuthenticationFailed',
                'A common-proof record was not returned with one authenticated payload in owned browser memory.',
            );
        }
        const ownedStoredBytes =
            storedBytes.byteOffset === 0 &&
            storedBytes.byteLength === storedBytes.buffer.byteLength
                ? (storedBytes as Uint8Array<ArrayBuffer>)
                : storedBytes.slice();
        if (ownedStoredBytes !== storedBytes) {
            destroyOwnedPayloadBuffer(storedBytes);
        }
        recordStorageRead(
            ownedStoredBytes.byteLength,
            authenticatedPayload.byteLength,
        );
        return Object.freeze({
            payload: authenticatedPayload,
            storedBytes: ownedStoredBytes,
        });
    };

    const readRecord = async (
        descriptor: ExternalMemoryRecordDescriptor,
    ): Promise<Uint8Array<ArrayBuffer>> => {
        const authenticatedRecord = await readStoredRecord(descriptor);
        if (authenticatedRecord === undefined) {
            throw new BrowserActionStorageCustodyError(
                'RecordAuthenticationFailed',
                'A required common-proof record is unavailable.',
            );
        }
        destroyOwnedPayloadBuffer(authenticatedRecord.storedBytes);
        return authenticatedRecord.payload;
    };

    const readStoredRecordByDigest = async (
        descriptor: ExternalMemoryRecordDescriptor,
        expectedRecordDigest: Uint8Array,
    ): Promise<Uint8Array<ArrayBuffer> | undefined> => {
        const storedBytes = await input.store.readAuthenticated({
            authenticate: authenticateRecordDigest(
                descriptor,
                expectedRecordDigest,
            ),
            logicalRecordKey: descriptor.logicalRecordKey,
        });
        if (storedBytes === undefined) {
            return undefined;
        }
        if (!(storedBytes.buffer instanceof ArrayBuffer)) {
            storedBytes.fill(0);
            throw new BrowserActionStorageCustodyError(
                'RecordAuthenticationFailed',
                'A common-proof record was not returned in owned browser memory.',
            );
        }
        let ownedStoredBytes: Uint8Array<ArrayBuffer>;
        if (
            storedBytes.byteOffset === 0 &&
            storedBytes.byteLength === storedBytes.buffer.byteLength
        ) {
            ownedStoredBytes = storedBytes as Uint8Array<ArrayBuffer>;
        } else {
            ownedStoredBytes = storedBytes.slice();
            destroyOwnedPayloadBuffer(storedBytes);
        }
        recordStoredBytesRead(ownedStoredBytes.byteLength);
        recordCommitReadback(ownedStoredBytes.byteLength);
        return ownedStoredBytes;
    };

    const clearStagedRecordChange = (
        change: StagedExternalMemoryRecordChange,
    ): void => {
        if (change.kind === 'write') {
            if (change.write.encodedRecord !== undefined) {
                destroyOwnedPayloadBuffer(change.write.encodedRecord);
            }
            if (
                change.write.expectedCurrentValue !== null &&
                change.write.expectedCurrentValue !== change.write.encodedRecord
            ) {
                destroyOwnedPayloadBuffer(change.write.expectedCurrentValue);
            }
            if (change.write.payloadOwnership !== undefined) {
                change.write.payloadOwnership.ledger.releaseIfLive(
                    change.write.payloadOwnership,
                );
                change.write.payloadOwnership = undefined;
            }
            return;
        }
    };

    const clearShadowChanges = (shadow: ExternalMemoryShadowState): void => {
        for (const change of shadow.changes.values()) {
            clearStagedRecordChange(change);
        }
        shadow.changes.clear();
    };

    const stageRecordWrite = async (
        shadow: ExternalMemoryShadowState,
        descriptor: ExternalMemoryRecordDescriptor,
        payload: Uint8Array<ArrayBuffer>,
        payloadOwnership?: CommonProofPayloadBufferOwnership,
    ): Promise<void> => {
        if (shadow.changes.has(descriptor.logicalRecordKey)) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'A common-proof transaction changes one record more than once.',
            );
        }
        let encodedRecord: Uint8Array<ArrayBuffer> | undefined;
        let expectedCurrentValue: Uint8Array<ArrayBuffer> | null = null;
        let expectedPayloadDigest: Uint8Array<ArrayBuffer> | undefined;
        const payloadByteLength = payload.byteLength;
        let payloadConsumed = false;
        try {
            if (shadow.replay) {
                deterministicRegenerationCallCount = checkedAccountingAdd(
                    deterministicRegenerationCallCount,
                    1,
                    'Common-proof deterministic regeneration count',
                );
                deterministicRegeneratedByteLength = checkedAccountingAdd(
                    deterministicRegeneratedByteLength,
                    payloadByteLength,
                    'Common-proof deterministic regeneration bytes',
                );
                expectedPayloadDigest = custodyDigest(
                    storedPayloadDigestDomain,
                    payload,
                );
                const authenticatedRecord = await readStoredRecord(
                    descriptor,
                    expectedPayloadDigest,
                    () => {
                        if (payloadConsumed) {
                            return;
                        }
                        destroyOwnedPayloadBuffer(payload);
                        payloadConsumed = true;
                    },
                    true,
                );
                if (authenticatedRecord !== undefined) {
                    destroyOwnedPayloadBuffer(authenticatedRecord.payload);
                    if (authenticatedRecord.storedBytes === undefined) {
                        throw new BrowserActionStorageCustodyError(
                            'StorageFailure',
                            'A replayed common-proof record did not retain its authenticated canonical bytes.',
                        );
                    }
                    encodedRecord = authenticatedRecord.storedBytes;
                    expectedCurrentValue = encodedRecord;
                }
            }
            if (encodedRecord === undefined) {
                encodedRecord = await encodeRecord(descriptor, payload);
                payloadConsumed = true;
            }
            if (payloadOwnership !== undefined) {
                payloadOwnership = payloadOwnership.ledger.replace(
                    payloadOwnership,
                    encodedRecord,
                    'canonical-record',
                );
            }
            shadow.changes.set(
                descriptor.logicalRecordKey,
                Object.freeze({
                    kind: 'write',
                    write: {
                        descriptor,
                        encodedRecord,
                        expectedCurrentValue,
                        payloadByteLength,
                        payloadOwnership,
                    },
                }),
            );
        } catch (error) {
            if (encodedRecord !== undefined) {
                destroyOwnedPayloadBuffer(encodedRecord);
            }
            if (payloadOwnership !== undefined) {
                payloadOwnership.ledger.release(payloadOwnership);
            }
            throw error;
        } finally {
            expectedPayloadDigest?.fill(0);
            if (!payloadConsumed) {
                destroyOwnedPayloadBuffer(payload);
            }
        }
    };

    const stageRecordDeletion = (
        shadow: ExternalMemoryShadowState,
        descriptor: ExternalMemoryRecordDescriptor,
    ): void => {
        const stagedChange = shadow.changes.get(descriptor.logicalRecordKey);
        if (stagedChange?.kind === 'delete') {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'A common-proof transaction deletes one record more than once.',
            );
        }
        if (stagedChange?.kind === 'write') {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'A common-proof transaction cannot write and delete one record.',
            );
        }
        shadow.changes.set(
            descriptor.logicalRecordKey,
            Object.freeze({
                deletion: { descriptor },
                kind: 'delete',
            }),
        );
    };

    const readShadowRecord = async (
        shadow: ExternalMemoryShadowState,
        descriptor: ExternalMemoryRecordDescriptor,
    ): Promise<Uint8Array<ArrayBuffer>> => {
        const stagedChange = shadow.changes.get(descriptor.logicalRecordKey);
        if (stagedChange?.kind === 'write') {
            const encodedRecord = stagedChange.write.encodedRecord;
            if (encodedRecord === undefined) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidState',
                    'A staged common-proof record no longer has readable canonical bytes.',
                );
            }
            return decodeRecord(descriptor, encodedRecord.slice());
        }
        if (stagedChange?.kind === 'delete') {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'A common-proof transaction read a record after deleting it.',
            );
        }
        return readRecord(descriptor);
    };

    const commitShadowChanges = async (
        shadow: ExternalMemoryShadowState,
    ): Promise<void> => {
        if (shadow.changes.size === 0) {
            return;
        }
        const changes = [...shadow.changes.values()];
        const changeBatches: readonly (readonly StagedExternalMemoryRecordChange[])[] =
            changes.every((change) => change.kind === 'delete')
                ? Array.from(
                      {
                          length: Math.ceil(
                              changes.length / maximumDeletionBatchRecordCount,
                          ),
                      },
                      (_unused, batchIndex) =>
                          changes.slice(
                              batchIndex * maximumDeletionBatchRecordCount,
                              (batchIndex + 1) *
                                  maximumDeletionBatchRecordCount,
                          ),
                  )
                : [changes];
        let committedBatchCount = 0;
        for (const changeBatch of changeBatches) {
            const transaction = await input.store.beginTransaction({
                lifetimeMilliseconds: limits.transactionLifetimeMilliseconds,
            });
            let commitAttempted = false;
            try {
                for (const change of changeBatch) {
                    if (change.kind === 'delete') {
                        await transaction.stageDeletion(
                            change.deletion.descriptor.logicalRecordKey,
                        );
                        continue;
                    }
                    const encodedRecord = change.write.encodedRecord;
                    if (encodedRecord === undefined) {
                        throw new BrowserActionStorageCustodyError(
                            'InvalidState',
                            'A staged common-proof record is missing its canonical storage bytes.',
                        );
                    }
                    const lease = await transaction.issueWriteLease({
                        declaredByteLength: encodedRecord.byteLength,
                        expectedCurrentValue: change.write.expectedCurrentValue,
                        logicalRecordKey:
                            change.write.descriptor.logicalRecordKey,
                    });
                    await lease.write(encodedRecord);
                    recordStorageWrite(
                        encodedRecord.byteLength,
                        change.write.payloadByteLength,
                    );
                    await lease.seal(
                        authenticateRecordBytes(
                            change.write.descriptor,
                            encodedRecord,
                        ),
                    );
                }
                commitAttempted = true;
                await transaction.commit();
                committedBatchCount += 1;
            } catch (error) {
                try {
                    await transaction.closeAfterFailure();
                } catch (cleanupError) {
                    permanentlyRetireInMemory();
                    throw new BrowserActionStorageCustodyError(
                        'StorageFailure',
                        'A common-proof transaction failed and could not clean up.',
                        { cleanupError, operationError: error },
                    );
                }
                if (commitAttempted || committedBatchCount > 0) {
                    permanentlyRetireInMemory();
                }
                throw error;
            }
            try {
                for (const change of changeBatch) {
                    if (change.kind === 'delete') {
                        const remaining = await readStoredRecord(
                            change.deletion.descriptor,
                        );
                        if (remaining !== undefined) {
                            destroyOwnedPayloadBuffer(remaining.payload);
                            destroyOwnedPayloadBuffer(remaining.storedBytes);
                            throw new BrowserActionStorageCustodyError(
                                'RecordAuthenticationFailed',
                                'A deleted common-proof record remained visible during exact readback.',
                            );
                        }
                        continue;
                    }
                    const encodedRecord = change.write.encodedRecord;
                    if (encodedRecord === undefined) {
                        throw new BrowserActionStorageCustodyError(
                            'InvalidState',
                            'A committed common-proof record lost its canonical storage bytes before readback.',
                        );
                    }
                    const expectedRecordDigest = custodyDigest(
                        storedRecordDigestDomain,
                        encodedRecord,
                    );
                    try {
                        if (
                            change.write.expectedCurrentValue !== null &&
                            change.write.expectedCurrentValue !== encodedRecord
                        ) {
                            destroyOwnedPayloadBuffer(
                                change.write.expectedCurrentValue,
                            );
                        }
                        change.write.expectedCurrentValue = null;
                        destroyOwnedPayloadBuffer(encodedRecord);
                        change.write.encodedRecord = undefined;
                        if (change.write.payloadOwnership !== undefined) {
                            change.write.payloadOwnership.ledger.release(
                                change.write.payloadOwnership,
                            );
                            change.write.payloadOwnership = undefined;
                        }
                        const committed = await readStoredRecordByDigest(
                            change.write.descriptor,
                            expectedRecordDigest,
                        );
                        if (committed === undefined) {
                            throw new BrowserActionStorageCustodyError(
                                'RecordAuthenticationFailed',
                                'A committed common-proof record is unavailable during exact readback.',
                            );
                        }
                        destroyOwnedPayloadBuffer(committed);
                    } finally {
                        expectedRecordDigest.fill(0);
                    }
                }
            } catch (error) {
                permanentlyRetireInMemory();
                throw error;
            }
        }
    };

    const deleteLogicalRecord = async (
        logicalRecordKey: string,
    ): Promise<void> => {
        const transaction = await input.store.beginTransaction({
            lifetimeMilliseconds: limits.transactionLifetimeMilliseconds,
        });
        try {
            await transaction.stageDeletion(logicalRecordKey);
            await transaction.commit();
        } catch (error) {
            return await closeTransactionAfterFailure(transaction, error);
        }
    };

    const deleteObjectRecords = async (
        object: ExternalMemoryObjectState,
    ): Promise<void> => {
        for (const descriptor of allObjectDescriptors(object)) {
            await deleteLogicalRecord(descriptor.logicalRecordKey);
        }
    };

    const requireObject = (
        objectMap: ReadonlyMap<number, ExternalMemoryObjectState>,
        objectOrdinal: number,
    ): ExternalMemoryObjectState => {
        const object = objectMap.get(objectOrdinal);
        if (object === undefined) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'A common-proof external-memory operation names an unavailable object.',
            );
        }
        return object;
    };

    const reserveRecord = (shadow: ExternalMemoryShadowState): void => {
        if (shadow.recordCount >= limits.maximumExternalMemoryRecordCount) {
            throw new BrowserActionStorageCustodyError(
                'StorageFailure',
                'Common-proof external-memory record custody exceeds its fixed quota.',
            );
        }
        shadow.recordCount += 1;
    };

    const reserveObjectPayload = (
        shadow: ExternalMemoryShadowState,
        exactByteLength: bigint,
    ): void => {
        const nextPayloadByteLength =
            shadow.payloadByteLength + exactByteLength;
        if (nextPayloadByteLength > limits.maximumExternalMemoryByteLength) {
            throw new BrowserActionStorageCustodyError(
                'StorageFailure',
                'Common-proof external-memory payload custody exceeds its fixed quota.',
            );
        }
        shadow.payloadByteLength = nextPayloadByteLength;
    };

    const createObject = async (
        operation: Extract<
            CommonProofExternalMemoryRequest['operations'][number],
            { readonly operationKind: 'create' }
        >,
        shadow: ExternalMemoryShadowState,
        maximumAppendByteLength: number,
    ): Promise<void> => {
        if (
            shadow.objects.has(operation.objectOrdinal) ||
            shadow.objects.size >= limits.maximumExternalMemoryObjectCount ||
            operation.exactByteLength > limits.maximumExternalMemoryByteLength
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'A common-proof create operation conflicts with custody state or quota.',
            );
        }
        const headerPayload = new Uint8Array(9);
        headerPayload[0] = operation.protection === 'public-integrity' ? 1 : 2;
        new DataView(headerPayload.buffer).setBigUint64(
            1,
            operation.exactByteLength,
            true,
        );
        reserveObjectPayload(shadow, operation.exactByteLength);
        reserveRecord(shadow);
        const header = await createDescriptor(
            identifierInput({
                byteOffset: 0n,
                chunkOrdinal: 0,
                objectOrdinal: operation.objectOrdinal,
                recordKind: 'object-header',
            }),
            operation.protection,
        );
        shadow.createdDescriptors.add(header);
        try {
            await stageRecordWrite(shadow, header, headerPayload);
        } finally {
            destroyOwnedPayloadBuffer(headerPayload);
        }
        shadow.objects.set(operation.objectOrdinal, {
            appendedByteLength: 0n,
            chunks: [],
            contentDigest: initialExternalMemoryObjectContentDigest({
                exactByteLength: operation.exactByteLength,
                objectOrdinal: operation.objectOrdinal,
                protection: operation.protection,
            }),
            exactByteLength: operation.exactByteLength,
            header,
            maximumAppendByteLength,
            nextChunkOrdinal: 1,
            protection: operation.protection,
        });
    };

    const appendObject = async (
        operation: Extract<
            CommonProofExternalMemoryRequest['operations'][number],
            { readonly operationKind: 'append' }
        >,
        shadow: ExternalMemoryShadowState,
        payloadLedger: CommonProofPayloadBufferOwnershipLedger,
        maximumAppendByteLength: number,
    ): Promise<void> => {
        const object = requireObject(shadow.objects, operation.objectOrdinal);
        const remainingByteLength =
            object.exactByteLength - object.appendedByteLength;
        const expectedAppendByteLength = Number(
            remainingByteLength < BigInt(object.maximumAppendByteLength)
                ? remainingByteLength
                : BigInt(object.maximumAppendByteLength),
        );
        if (
            object.sealMarker !== undefined ||
            maximumAppendByteLength !== object.maximumAppendByteLength ||
            operation.expectedOffset !== object.appendedByteLength ||
            operation.bytes.byteLength !== expectedAppendByteLength ||
            object.appendedByteLength + BigInt(operation.bytes.byteLength) >
                object.exactByteLength
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'A common-proof append operation violates the object lifecycle.',
            );
        }
        const chunkByteLength = operation.bytes.byteLength;
        const byteOffset = object.appendedByteLength;
        const chunkOrdinal = object.nextChunkOrdinal;
        if (!isSafeUnsigned32(chunkOrdinal)) {
            throw new BrowserActionStorageCustodyError(
                'StorageFailure',
                'Common-proof external-memory chunk ordinals are exhausted.',
            );
        }
        const payloadOwnership = payloadLedger.observe(
            operation.bytes,
            'decoded-append',
        );
        const nextContentDigest = appendedExternalMemoryObjectContentDigest({
            byteOffset,
            chunkByteLength,
            chunkOrdinal,
            currentContentDigest: object.contentDigest,
            payload: operation.bytes,
        });
        let nextContentDigestAdopted = false;
        try {
            reserveRecord(shadow);
            const descriptor = await createDescriptor(
                identifierInput({
                    byteOffset,
                    chunkOrdinal,
                    objectOrdinal: operation.objectOrdinal,
                    recordKind: 'data-chunk',
                }),
                object.protection,
            );
            shadow.createdDescriptors.add(descriptor);
            await stageRecordWrite(
                shadow,
                descriptor,
                operation.bytes as Uint8Array<ArrayBuffer>,
                payloadOwnership,
            );
            object.chunks.push({
                byteLength: chunkByteLength,
                byteOffset,
                descriptor,
            });
            object.contentDigest.fill(0);
            object.contentDigest = nextContentDigest;
            nextContentDigestAdopted = true;
            object.nextChunkOrdinal += 1;
            object.appendedByteLength += BigInt(chunkByteLength);
        } catch (error) {
            if (!nextContentDigestAdopted) {
                nextContentDigest.fill(0);
            }
            destroyOwnedPayloadBuffer(operation.bytes);
            payloadLedger.releaseIfLive(payloadOwnership);
            throw error;
        }
    };

    const sealObject = async (
        operation: Extract<
            CommonProofExternalMemoryRequest['operations'][number],
            { readonly operationKind: 'seal' }
        >,
        shadow: ExternalMemoryShadowState,
    ): Promise<void> => {
        const object = requireObject(shadow.objects, operation.objectOrdinal);
        if (
            object.sealMarker !== undefined ||
            object.appendedByteLength !== object.exactByteLength ||
            !isSafeUnsigned32(object.nextChunkOrdinal)
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'A common-proof seal operation violates the object lifecycle.',
            );
        }
        reserveRecord(shadow);
        const sealMarker = await createDescriptor(
            identifierInput({
                byteOffset: object.exactByteLength,
                chunkOrdinal: object.nextChunkOrdinal,
                objectOrdinal: operation.objectOrdinal,
                recordKind: 'seal-marker',
            }),
            object.protection,
        );
        shadow.createdDescriptors.add(sealMarker);
        const sealedContentDigest = sealedExternalMemoryObjectContentDigest({
            contentDigest: object.contentDigest,
            exactByteLength: object.exactByteLength,
            sealMarkerChunkOrdinal: object.nextChunkOrdinal,
        });
        let sealedContentDigestAdopted = false;
        try {
            await stageRecordWrite(shadow, sealMarker, new Uint8Array(0));
            object.nextChunkOrdinal += 1;
            object.sealedContentDigest = sealedContentDigest;
            sealedContentDigestAdopted = true;
            object.sealMarker = sealMarker;
        } finally {
            if (!sealedContentDigestAdopted) {
                sealedContentDigest.fill(0);
            }
        }
    };

    const readObject = async (
        operation: Extract<
            CommonProofExternalMemoryRequest['operations'][number],
            { readonly operationKind: 'read' }
        >,
        shadow: ExternalMemoryShadowState,
        payloadLedger: CommonProofPayloadBufferOwnershipLedger,
    ): Promise<CommonProofExternalMemoryReadResult> => {
        const object = requireObject(shadow.objects, operation.objectOrdinal);
        const readEnd = operation.offset + BigInt(operation.byteLength);
        if (
            object.sealMarker === undefined ||
            readEnd > object.exactByteLength
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'A common-proof read operation violates the sealed object extent.',
            );
        }
        const exactChunk = object.chunks.find(
            (chunk) =>
                chunk.byteOffset === operation.offset &&
                chunk.byteLength === operation.byteLength,
        );
        if (exactChunk !== undefined) {
            const chunkBytes = await readShadowRecord(
                shadow,
                exactChunk.descriptor,
            );
            const chunkOwnership = payloadLedger.observe(
                chunkBytes,
                'decoded-record',
            );
            let transferredChunk = false;
            try {
                if (chunkBytes.byteLength !== exactChunk.byteLength) {
                    throw new BrowserActionStorageCustodyError(
                        'RecordAuthenticationFailed',
                        'A common-proof external-memory chunk has the wrong length.',
                    );
                }
                if (chunkOwnership !== undefined) {
                    payloadLedger.transfer(
                        chunkOwnership,
                        'transferred-read-result',
                    );
                    payloadLedger.release(chunkOwnership);
                }
                transferredChunk = true;
                return Object.freeze({
                    bytes: chunkBytes,
                    objectOrdinal: operation.objectOrdinal,
                    offset: operation.offset,
                    operationIndex: operation.operationIndex,
                });
            } finally {
                if (!transferredChunk) {
                    destroyOwnedPayloadBuffer(chunkBytes);
                    payloadLedger.releaseIfLive(chunkOwnership);
                }
            }
        }
        const result = new Uint8Array(operation.byteLength);
        const resultOwnership = payloadLedger.observe(
            result,
            'assembled-read-result',
        );
        let copiedByteLength = 0;
        let transferredResult = false;
        try {
            for (const chunk of object.chunks) {
                const chunkEnd = chunk.byteOffset + BigInt(chunk.byteLength);
                if (
                    chunkEnd <= operation.offset ||
                    chunk.byteOffset >= readEnd
                ) {
                    continue;
                }
                const overlapStart =
                    chunk.byteOffset > operation.offset
                        ? chunk.byteOffset
                        : operation.offset;
                const overlapEnd = chunkEnd < readEnd ? chunkEnd : readEnd;
                const sourceStart = Number(overlapStart - chunk.byteOffset);
                const overlapByteLength = Number(overlapEnd - overlapStart);
                const destinationStart = Number(
                    overlapStart - operation.offset,
                );
                const chunkBytes = await readShadowRecord(
                    shadow,
                    chunk.descriptor,
                );
                const chunkOwnership = payloadLedger.observe(
                    chunkBytes,
                    'decoded-record',
                );
                try {
                    if (chunkBytes.byteLength !== chunk.byteLength) {
                        throw new BrowserActionStorageCustodyError(
                            'RecordAuthenticationFailed',
                            'A common-proof external-memory chunk has the wrong length.',
                        );
                    }
                    result.set(
                        chunkBytes.subarray(
                            sourceStart,
                            sourceStart + overlapByteLength,
                        ),
                        destinationStart,
                    );
                } finally {
                    destroyOwnedPayloadBuffer(chunkBytes);
                    payloadLedger.releaseIfLive(chunkOwnership);
                }
                copiedByteLength += overlapByteLength;
            }
            if (copiedByteLength !== operation.byteLength) {
                throw new BrowserActionStorageCustodyError(
                    'RecordAuthenticationFailed',
                    'Common-proof external-memory chunks do not cover the requested range.',
                );
            }
            if (resultOwnership !== undefined) {
                payloadLedger.transfer(
                    resultOwnership,
                    'transferred-read-result',
                );
                payloadLedger.release(resultOwnership);
            }
            transferredResult = true;
            return Object.freeze({
                bytes: result,
                objectOrdinal: operation.objectOrdinal,
                offset: operation.offset,
                operationIndex: operation.operationIndex,
            });
        } finally {
            if (!transferredResult) {
                destroyOwnedPayloadBuffer(result);
                payloadLedger.releaseIfLive(resultOwnership);
            }
        }
    };

    const deleteObject = (
        shadow: ExternalMemoryShadowState,
        objectOrdinal: number,
    ): void => {
        const object = requireObject(shadow.objects, objectOrdinal);
        if (shadow.deletionState.deletedObjectCount === 0xffff_ffff) {
            throw new BrowserActionStorageCustodyError(
                'StorageFailure',
                'Common-proof external-memory deletion ordinals are exhausted.',
            );
        }
        const objectStateDigest = externalMemoryObjectStateDigest({
            object,
            objectOrdinal,
        });
        try {
            for (const descriptor of allObjectDescriptors(object)) {
                stageRecordDeletion(shadow, descriptor);
            }
            const nextDeletionStateDigest =
                appendedExternalMemoryDeletionStateDigest({
                    currentDeletionStateDigest:
                        shadow.deletionState.deletionStateDigest,
                    deletedObjectCount: shadow.deletionState.deletedObjectCount,
                    objectOrdinal,
                    objectStateDigest,
                });
            shadow.deletionState.deletionStateDigest.fill(0);
            shadow.deletionState.deletionStateDigest = nextDeletionStateDigest;
            shadow.deletionState.deletedObjectCount += 1;
        } finally {
            objectStateDigest.fill(0);
        }
        shadow.recordCount -= allObjectDescriptors(object).length;
        shadow.payloadByteLength -= object.exactByteLength;
        shadow.objects.delete(objectOrdinal);
        object.contentDigest.fill(0);
        object.sealedContentDigest?.fill(0);
    };

    const executeTransaction = async (
        request: CommonProofExternalMemoryRequest,
        replay: boolean,
    ): Promise<readonly CommonProofExternalMemoryReadResult[]> => {
        assertOpen();
        if (
            (replay &&
                (latestCheckpointResumeDescriptor === undefined ||
                    !checkpointRestoreAttempted ||
                    checkpointExternalMemoryStateConfirmed)) ||
            (!replay && !checkpointExternalMemoryStateConfirmed)
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'A common-proof external-memory transaction is outside its authenticated replay phase.',
            );
        }
        const firstOperationKind = request.operations[0]?.operationKind;
        if (
            typeof request.maximumPayloadByteLength !== 'bigint' ||
            request.maximumPayloadByteLength <= 0n ||
            request.maximumPayloadByteLength >
                BigInt(maximumCanonicalDataChunkByteLength)
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'A common-proof request has an invalid maximum payload byte length.',
            );
        }
        const maximumAppendByteLength = Number(
            request.maximumPayloadByteLength,
        );
        if (
            firstOperationKind === undefined ||
            (request.operations.length > 1 &&
                (firstOperationKind !== 'delete' ||
                    request.operations.some(
                        (operation) => operation.operationKind !== 'delete',
                    )))
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'A common-proof request does not use the fixed executor transaction grammar.',
            );
        }
        if (
            !bytesEqual(
                request.runtimeBindingHash,
                commonProofRuntimeBindingHash,
            )
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'A common-proof request belongs to another runtime binding.',
            );
        }
        const previousDescriptors = new Set(
            [...objects.values()].flatMap((object) =>
                allObjectDescriptors(object),
            ),
        );
        const shadow: ExternalMemoryShadowState = {
            changes: new Map(),
            createdDescriptors: new Set(),
            deletionState: {
                deletedObjectCount:
                    externalMemoryDeletionState.deletedObjectCount,
                deletionStateDigest:
                    externalMemoryDeletionState.deletionStateDigest.slice(),
            },
            objects: new Map(
                [...objects].map(([objectOrdinal, object]) => [
                    objectOrdinal,
                    {
                        ...object,
                        chunks: [...object.chunks],
                        contentDigest: object.contentDigest.slice(),
                        ...(object.sealedContentDigest === undefined
                            ? {}
                            : {
                                  sealedContentDigest:
                                      object.sealedContentDigest.slice(),
                              }),
                    },
                ]),
            ),
            payloadByteLength: externalMemoryPayloadByteLength,
            recordCount: externalMemoryRecordCount,
            replay,
        };
        const readResults: CommonProofExternalMemoryReadResult[] = [];
        const payloadLedger = new CommonProofPayloadBufferOwnershipLedger();
        try {
            for (const operation of request.operations) {
                switch (operation.operationKind) {
                    case 'create':
                        await createObject(
                            operation,
                            shadow,
                            maximumAppendByteLength,
                        );
                        break;
                    case 'append':
                        await appendObject(
                            operation,
                            shadow,
                            payloadLedger,
                            maximumAppendByteLength,
                        );
                        break;
                    case 'seal':
                        await sealObject(operation, shadow);
                        break;
                    case 'read':
                        readResults.push(
                            await readObject(operation, shadow, payloadLedger),
                        );
                        break;
                    case 'delete':
                        deleteObject(shadow, operation.objectOrdinal);
                        break;
                }
            }
            await commitShadowChanges(shadow);
            const retainedDescriptors = new Set(
                [...shadow.objects.values()].flatMap((object) =>
                    allObjectDescriptors(object),
                ),
            );
            for (const descriptor of previousDescriptors) {
                if (!retainedDescriptors.has(descriptor)) {
                    destroyIdentifierInput(descriptor.identifierInput);
                }
            }
            for (const descriptor of shadow.createdDescriptors) {
                if (!retainedDescriptors.has(descriptor)) {
                    destroyIdentifierInput(descriptor.identifierInput);
                }
            }
            for (const object of objects.values()) {
                object.contentDigest.fill(0);
                object.sealedContentDigest?.fill(0);
            }
            objects.clear();
            for (const [objectOrdinal, object] of shadow.objects) {
                objects.set(objectOrdinal, object);
            }
            externalMemoryDeletionState.deletionStateDigest.fill(0);
            externalMemoryDeletionState = shadow.deletionState;
            externalMemoryPayloadByteLength = shadow.payloadByteLength;
            externalMemoryRecordCount = shadow.recordCount;
            shadow.createdDescriptors.clear();
            return Object.freeze(readResults);
        } catch (error) {
            for (const readResult of readResults) {
                destroyOwnedPayloadBuffer(readResult.bytes);
            }
            for (const descriptor of shadow.createdDescriptors) {
                destroyIdentifierInput(descriptor.identifierInput);
            }
            for (const object of shadow.objects.values()) {
                object.contentDigest.fill(0);
                object.sealedContentDigest?.fill(0);
            }
            shadow.deletionState.deletionStateDigest.fill(0);
            shadow.createdDescriptors.clear();
            throw error;
        } finally {
            clearShadowChanges(shadow);
            payloadLedger.assertReleased();
            payloadBufferAccounting = addPayloadBufferAccounting(
                payloadBufferAccounting,
                payloadLedger.snapshot().accounting,
            );
        }
    };

    const confirmAuthenticatedCheckpointExternalMemoryState = (): void => {
        assertOpen();
        if (
            latestCheckpointResumeDescriptor === undefined ||
            !checkpointRestoreAttempted ||
            checkpointExternalMemoryStateConfirmed
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'Common-proof external-memory state confirmation is outside the authenticated resume boundary.',
            );
        }
        const reconstructedStateDigest = checkpointExternalMemoryStateDigest();
        try {
            if (
                !bytesEqual(
                    reconstructedStateDigest,
                    latestCheckpointResumeDescriptor.externalMemoryStateDigest,
                )
            ) {
                throw new BrowserActionStorageCustodyError(
                    'RecordAuthenticationFailed',
                    'The replay-reconstructed common-proof external-memory state differs from the authenticated checkpoint.',
                );
            }
            checkpointExternalMemoryStateConfirmed = true;
        } finally {
            reconstructedStateDigest.fill(0);
        }
    };

    const outputLogicalRecordKey = (chunkIndex: number): string => {
        const hash = shake256.create({ dkLen: foundationHashByteLength });
        try {
            const domainBytes = textEncoder.encode(canonicalOutputKeyDomain);
            hash.update(unsigned32Bytes(domainBytes.byteLength));
            hash.update(domainBytes);
            hash.update(commonProofEnvironmentIdentifier);
            hash.update(commonProofRuntimeBindingHash);
            hash.update(proofAttemptLineageIdentifier);
            hash.update(unsigned32Bytes(chunkIndex));
            return `${attemptLogicalRecordPrefix}canonical-output/${bytesToHex(hash.digest())}`;
        } finally {
            hash.destroy();
        }
    };

    const readStoredOutputChunk = async (
        chunkIndex: number,
        commitReadback = false,
    ): Promise<
        | Readonly<{
              logicalRecordKey: string;
              payload: Uint8Array<ArrayBuffer>;
              storedBytes: Uint8Array<ArrayBuffer>;
          }>
        | undefined
    > => {
        const logicalRecordKey = outputLogicalRecordKey(chunkIndex);
        let payload: Uint8Array<ArrayBuffer> | undefined;
        const storedBytes = await input.store.readAuthenticated({
            authenticate: ({ bytes, logicalRecordKey: observedKey }) => {
                if (observedKey !== logicalRecordKey) {
                    throw new BrowserActionStorageCustodyError(
                        'RecordAuthenticationFailed',
                        'A common-proof output record was returned under the wrong key.',
                    );
                }
                payload = decodePublicRecord(logicalRecordKey, bytes);
            },
            logicalRecordKey,
        });
        if (storedBytes === undefined) {
            payload?.fill(0);
            return undefined;
        }
        if (payload === undefined) {
            storedBytes.fill(0);
            throw new BrowserActionStorageCustodyError(
                'RecordAuthenticationFailed',
                'A common-proof output record was not authenticated during its read.',
            );
        }
        const ownedStoredBytes = Uint8Array.from(storedBytes);
        storedBytes.fill(0);
        recordStorageRead(ownedStoredBytes.byteLength, payload.byteLength);
        if (commitReadback) {
            recordCommitReadback(ownedStoredBytes.byteLength);
        }
        return Object.freeze({
            logicalRecordKey,
            payload,
            storedBytes: ownedStoredBytes,
        });
    };

    const rebuildCanonicalOutputPrefix = async (
        nextChunkIndex: number,
    ): Promise<void> => {
        if (outputChunks.size === nextChunkIndex) {
            return;
        }
        if (
            latestCheckpointResumeDescriptor === undefined ||
            !checkpointRestoreAttempted ||
            nextChunkIndex < outputChunks.size
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'A common-proof output chunk is outside the authenticated resume prefix.',
            );
        }
        const rebuiltPrefix: CanonicalOutputChunk[] = [];
        let rebuiltByteLength = 0;
        try {
            while (outputChunks.size + rebuiltPrefix.length < nextChunkIndex) {
                const prefixChunkIndex =
                    outputChunks.size + rebuiltPrefix.length;
                const existing = await readStoredOutputChunk(prefixChunkIndex);
                if (existing === undefined) {
                    throw new BrowserActionStorageCustodyError(
                        'RecordAuthenticationFailed',
                        'The authenticated common-proof output prefix is incomplete.',
                    );
                }
                try {
                    if (
                        existing.payload.byteLength !==
                        canonicalCommonProofOutputChunkByteLength
                    ) {
                        throw new BrowserActionStorageCustodyError(
                            'RecordAuthenticationFailed',
                            'A nonterminal common-proof output chunk has the wrong canonical length.',
                        );
                    }
                    rebuiltPrefix.push({
                        byteLength: existing.payload.byteLength,
                        logicalRecordKey: existing.logicalRecordKey,
                    });
                    rebuiltByteLength += existing.payload.byteLength;
                } finally {
                    existing.payload.fill(0);
                    existing.storedBytes.fill(0);
                }
            }
        } catch (error) {
            permanentlyRetireInMemory();
            throw error;
        }
        for (const chunk of rebuiltPrefix) {
            outputChunks.set(outputChunks.size, chunk);
        }
        outputByteLength += rebuiltByteLength;
    };

    const outputStore: CommonProofCanonicalOutputStore = Object.freeze({
        commitChunk: async (chunkIndex, chunkBytes) => {
            assertOpen();
            if (
                outputSealed ||
                !isSafeUnsigned32(chunkIndex) ||
                chunkIndex >= maximumCommonProofOutputChunkCount ||
                !(chunkBytes instanceof Uint8Array) ||
                chunkBytes.byteLength === 0 ||
                chunkBytes.byteLength >
                    canonicalCommonProofOutputChunkByteLength ||
                outputTerminalChunkIndex !== undefined ||
                outputByteLength + chunkBytes.byteLength >
                    maximumCommonProofOutputByteLength
            ) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'A common-proof canonical-output chunk is malformed or out of order.',
                );
            }
            await rebuildCanonicalOutputPrefix(chunkIndex);
            if (chunkIndex !== outputChunks.size) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'A common-proof canonical-output chunk is out of order.',
                );
            }
            const logicalRecordKey = outputLogicalRecordKey(chunkIndex);
            const record = encodePublicRecord(logicalRecordKey, chunkBytes);
            const existing = await readStoredOutputChunk(chunkIndex);
            if (existing !== undefined) {
                try {
                    if (
                        latestCheckpointResumeDescriptor === undefined ||
                        !checkpointRestoreAttempted ||
                        !bytesEqual(existing.payload, chunkBytes) ||
                        !bytesEqual(existing.storedBytes, record)
                    ) {
                        permanentlyRetireInMemory();
                        throw new BrowserActionStorageCustodyError(
                            'RecordAuthenticationFailed',
                            'An existing common-proof output chunk differs from the authenticated resumed bytes.',
                        );
                    }
                    outputChunks.set(chunkIndex, {
                        byteLength: chunkBytes.byteLength,
                        logicalRecordKey,
                    });
                    outputByteLength += chunkBytes.byteLength;
                    if (
                        chunkBytes.byteLength <
                        canonicalCommonProofOutputChunkByteLength
                    ) {
                        outputTerminalChunkIndex = chunkIndex;
                    }
                    return;
                } finally {
                    existing.payload.fill(0);
                    existing.storedBytes.fill(0);
                    record.fill(0);
                }
            }
            const transaction = await input.store.beginTransaction({
                lifetimeMilliseconds: limits.transactionLifetimeMilliseconds,
            });
            let commitAttempted = false;
            try {
                const lease = await transaction.issueWriteLease({
                    declaredByteLength: record.byteLength,
                    expectedCurrentValue: null,
                    logicalRecordKey,
                });
                await lease.write(record);
                recordStorageWrite(record.byteLength, chunkBytes.byteLength);
                await lease.seal(({ bytes }) => {
                    const opened = decodePublicRecord(logicalRecordKey, bytes);
                    try {
                        if (!bytesEqual(opened, chunkBytes)) {
                            throw new BrowserActionStorageCustodyError(
                                'RecordAuthenticationFailed',
                                'A staged common-proof output chunk differs from the kernel bytes.',
                            );
                        }
                    } finally {
                        opened.fill(0);
                    }
                });
                commitAttempted = true;
                await transaction.commit();
            } catch (error) {
                try {
                    await transaction.closeAfterFailure();
                } catch (cleanupError) {
                    throw new BrowserActionStorageCustodyError(
                        'StorageFailure',
                        'A common-proof output transaction failed and could not clean up.',
                        { cleanupError, operationError: error },
                    );
                }
                if (commitAttempted) {
                    permanentlyRetireInMemory();
                }
                throw error;
            } finally {
                record.fill(0);
            }
            try {
                const committed = await readStoredOutputChunk(chunkIndex, true);
                if (committed === undefined) {
                    throw new BrowserActionStorageCustodyError(
                        'RecordAuthenticationFailed',
                        'A committed common-proof output chunk is unavailable during readback.',
                    );
                }
                try {
                    const expectedRecord = encodePublicRecord(
                        logicalRecordKey,
                        chunkBytes,
                    );
                    try {
                        if (
                            !bytesEqual(committed.payload, chunkBytes) ||
                            !bytesEqual(committed.storedBytes, expectedRecord)
                        ) {
                            throw new BrowserActionStorageCustodyError(
                                'RecordAuthenticationFailed',
                                'A committed common-proof output chunk differs during exact readback.',
                            );
                        }
                    } finally {
                        expectedRecord.fill(0);
                    }
                } finally {
                    committed.payload.fill(0);
                    committed.storedBytes.fill(0);
                }
            } catch (error) {
                permanentlyRetireInMemory();
                throw error;
            }
            outputChunks.set(chunkIndex, {
                byteLength: chunkBytes.byteLength,
                logicalRecordKey,
            });
            outputByteLength += chunkBytes.byteLength;
            if (
                chunkBytes.byteLength <
                canonicalCommonProofOutputChunkByteLength
            ) {
                outputTerminalChunkIndex = chunkIndex;
            }
        },
        readChunk: async (chunkIndex, exactByteLength) => {
            assertOpen();
            const chunk = outputChunks.get(chunkIndex);
            if (chunk === undefined || chunk.byteLength !== exactByteLength) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'A common-proof output read names the wrong chunk extent.',
                );
            }
            let opened: Uint8Array<ArrayBuffer> | undefined;
            const record = await input.store.readAuthenticated({
                authenticate: ({ bytes }) => {
                    opened = decodePublicRecord(chunk.logicalRecordKey, bytes);
                },
                logicalRecordKey: chunk.logicalRecordKey,
            });
            record?.fill(0);
            if (record === undefined || opened === undefined) {
                throw new BrowserActionStorageCustodyError(
                    'RecordAuthenticationFailed',
                    'A common-proof output chunk is missing.',
                );
            }
            if (opened.byteLength !== exactByteLength) {
                opened.fill(0);
                throw new BrowserActionStorageCustodyError(
                    'RecordAuthenticationFailed',
                    'A common-proof output chunk changed length.',
                );
            }
            recordStorageRead(record.byteLength, opened.byteLength);
            return opened;
        },
    });

    const deleteAllExternalMemory = async (): Promise<void> => {
        const failures: unknown[] = [];
        for (const object of objects.values()) {
            try {
                await deleteObjectRecords(object);
            } catch (error) {
                failures.push(error);
            } finally {
                destroyExternalMemoryObjectInMemory(object);
            }
        }
        objects.clear();
        externalMemoryPayloadByteLength = 0n;
        externalMemoryRecordCount = 0;
        if (failures.length !== 0) {
            throw new BrowserActionStorageCustodyError(
                'StorageFailure',
                'Common-proof external-memory cleanup failed.',
                failures,
            );
        }
    };

    async function cleanupDurableProofRecords(): Promise<void> {
        if (durableProofRecordsDeleted) {
            return;
        }
        try {
            await input.capacityReservation.deleteAuthenticatedLogicalRecords(
                attemptLogicalRecordPrefix,
            );
        } catch (error) {
            throw new BrowserActionStorageCustodyError(
                'StorageFailure',
                'Common-proof authenticated durable-record cleanup failed.',
                error,
            );
        }
        durableProofRecordsDeleted = true;
        for (const object of objects.values()) {
            destroyExternalMemoryObjectInMemory(object);
        }
        objects.clear();
        externalMemoryPayloadByteLength = 0n;
        externalMemoryRecordCount = 0;
        outputChunks.clear();
        outputByteLength = 0;
        outputSealed = false;
        outputTerminalChunkIndex = undefined;
    }

    async function evictTerminalCheckpoint(): Promise<void> {
        if (checkpointEvictionCompleted) {
            return;
        }
        preserveCheckpointLineageForTerminalCleanup();
        if (checkpointEvictionCompleted) {
            return;
        }
        const checkpointLineageIdentifier = terminalCheckpointLineageIdentifier;
        if (
            checkpointLineageIdentifier === undefined ||
            input.checkpoint === undefined
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'Common-proof terminal checkpoint cleanup lost its retained lineage identifier.',
            );
        }
        await input.checkpoint.store.evict(checkpointLineageIdentifier);
        if (terminalCheckpointOperationIdentity !== undefined) {
            await input.checkpoint.store.releaseOperationIdentity(
                terminalCheckpointOperationIdentity,
            );
            terminalCheckpointOperationIdentity = undefined;
        }
        checkpointEvictionCompleted = true;
        checkpointLineageIdentifier.fill(0);
        terminalCheckpointLineageIdentifier = undefined;
    }

    async function releaseTerminalCapacityReservation(): Promise<void> {
        if (capacityReservationReleased) {
            return;
        }
        await input.capacityReservation.release();
        capacityReservationReleased = true;
    }

    async function releaseCheckpointPhysicalAccountingScope(): Promise<void> {
        if (checkpointPhysicalAccountingScopeReleased) {
            return;
        }
        if (input.checkpoint === undefined) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'Common-proof checkpoint physical accounting lost its authenticated owner.',
            );
        }
        await input.checkpoint.store.releasePhysicalAccountingScope(
            input.checkpoint.physicalAccountingScope,
        );
        checkpointPhysicalAccountingScopeReleased = true;
    }

    async function cleanupTerminalProofAuthority(): Promise<unknown[]> {
        const cleanupStartedAtMilliseconds = monotonicMilliseconds();
        preserveCheckpointLineageForTerminalCleanup();
        const failures: unknown[] = [];
        try {
            await cleanupDurableProofRecords();
        } catch (error) {
            failures.push(error);
        }
        try {
            await evictTerminalCheckpoint();
        } catch (error) {
            failures.push(error);
        }
        if (checkpointEvictionCompleted) {
            try {
                await releaseCheckpointPhysicalAccountingScope();
            } catch (error) {
                failures.push(error);
            }
        }
        if (durableProofRecordsDeleted) {
            try {
                await releaseTerminalCapacityReservation();
            } catch (error) {
                failures.push(error);
            }
        }
        retirementCleanupCompleted =
            durableProofRecordsDeleted &&
            checkpointEvictionCompleted &&
            checkpointPhysicalAccountingScopeReleased &&
            capacityReservationReleased;
        cleanupDurationMilliseconds += Math.max(
            0,
            monotonicMilliseconds() - cleanupStartedAtMilliseconds,
        );
        return failures;
    }

    const armApplicationHandoff =
        async (): Promise<CommonProofApplicationHandoff> => {
            assertOpen();
            if (
                applicationHandoffArmed ||
                !outputSealed ||
                outputByteLength === 0 ||
                objects.size !== 0 ||
                externalMemoryPayloadByteLength !== 0n ||
                externalMemoryRecordCount !== 0
            ) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidState',
                    'Common-proof application handoff requires one sealed output with released scratch authority.',
                );
            }
            const markerPayload = hexToExactBytes(
                attemptLogicalRecordPrefix.slice(
                    'common-proof-attempt/'.length,
                    -1,
                ),
                foundationHashByteLength,
                'Common-proof application handoff attempt identifier',
            );
            const canonicalMarkerRecordBytes = encodePublicRecord(
                applicationHandoffLogicalRecordKey,
                markerPayload,
            );
            const transaction = await input.store.beginTransaction({
                lifetimeMilliseconds: limits.transactionLifetimeMilliseconds,
            });
            let committedRecord: Uint8Array | undefined;
            try {
                const lease = await transaction.issueWriteLease({
                    declaredByteLength: canonicalMarkerRecordBytes.byteLength,
                    expectedCurrentValue: null,
                    logicalRecordKey: applicationHandoffLogicalRecordKey,
                });
                await lease.write(canonicalMarkerRecordBytes);
                recordStorageWrite(
                    canonicalMarkerRecordBytes.byteLength,
                    markerPayload.byteLength,
                );
                await lease.seal(({ bytes }) => {
                    const opened = decodePublicRecord(
                        applicationHandoffLogicalRecordKey,
                        bytes,
                    );
                    try {
                        if (!bytesEqual(opened, markerPayload)) {
                            throw new BrowserActionStorageCustodyError(
                                'RecordAuthenticationFailed',
                                'The staged common-proof handoff marker changed before commit.',
                            );
                        }
                    } finally {
                        opened.fill(0);
                    }
                });
                await transaction.commit();
                committedRecord = await input.store.readAuthenticated({
                    authenticate: ({ bytes }) => {
                        const opened = decodePublicRecord(
                            applicationHandoffLogicalRecordKey,
                            bytes,
                        );
                        try {
                            if (!bytesEqual(opened, markerPayload)) {
                                throw new BrowserActionStorageCustodyError(
                                    'RecordAuthenticationFailed',
                                    'The committed common-proof handoff marker changed during readback.',
                                );
                            }
                        } finally {
                            opened.fill(0);
                        }
                    },
                    logicalRecordKey: applicationHandoffLogicalRecordKey,
                });
                if (
                    committedRecord === undefined ||
                    !bytesEqual(committedRecord, canonicalMarkerRecordBytes)
                ) {
                    throw new BrowserActionStorageCustodyError(
                        'RecordAuthenticationFailed',
                        'The committed common-proof handoff marker is unavailable or differs from its exact bytes.',
                    );
                }
                recordStorageRead(
                    committedRecord.byteLength,
                    markerPayload.byteLength,
                );
                recordCommitReadback(committedRecord.byteLength);
                applicationHandoffArmed = true;
                return Object.freeze({
                    canonicalMarkerRecordBytes:
                        canonicalMarkerRecordBytes.slice(),
                    logicalRecordKey: applicationHandoffLogicalRecordKey,
                });
            } catch (error) {
                return await closeTransactionAfterFailure(transaction, error);
            } finally {
                markerPayload.fill(0);
                canonicalMarkerRecordBytes.fill(0);
                committedRecord?.fill(0);
            }
        };

    const requireAccountingNumber = (value: bigint, label: string): number => {
        const number = Number(value);
        if (!Number.isSafeInteger(number) || number < 0) {
            throw new BrowserActionStorageCustodyError(
                'StorageFailure',
                `${label} exceeded the safe accounting range.`,
            );
        }
        return number;
    };

    const copyPhysicalStorageAccounting =
        (): CommonProofBrowserCustodyPhysicalAccountingSnapshot => {
            const reservationAccounting =
                input.capacityReservation.copyPhysicalStorageAccounting();
            const checkpointAccounting =
                input.checkpoint === undefined
                    ? undefined
                    : input.checkpoint.store.copyPhysicalAccounting(
                          input.checkpoint.physicalAccountingScope,
                      );
            const accountingSum = (
                mainValue: number,
                checkpointValue: number | undefined,
                label: string,
            ): number =>
                checkedAccountingAdd(mainValue, checkpointValue ?? 0, label);
            const physicalReadByteLength = accountingSum(
                reservationAccounting.physicalReadByteLength,
                checkpointAccounting?.physicalReadByteLength,
                'Physical storage read bytes',
            );
            const physicalReadCallCount = accountingSum(
                reservationAccounting.physicalReadCallCount,
                checkpointAccounting?.physicalReadCallCount,
                'Physical storage read calls',
            );
            const physicalWriteByteLength = accountingSum(
                reservationAccounting.physicalWriteByteLength,
                checkpointAccounting?.physicalWriteByteLength,
                'Physical storage write bytes',
            );
            const physicalWriteCallCount = accountingSum(
                reservationAccounting.physicalWriteCallCount,
                checkpointAccounting?.physicalWriteCallCount,
                'Physical storage write calls',
            );
            if (
                physicalReadByteLength < ciphertextReadByteLength ||
                physicalReadCallCount < ciphertextReadCallCount ||
                physicalWriteByteLength < ciphertextWriteByteLength ||
                physicalWriteCallCount < ciphertextWriteCallCount
            ) {
                throw new BrowserActionStorageCustodyError(
                    'StorageFailure',
                    'Physical storage accounting fell below observed common-proof record traffic.',
                );
            }
            return Object.freeze({
                deletedByteLength: accountingSum(
                    reservationAccounting.deletedByteLength,
                    checkpointAccounting?.deletedByteLength,
                    'Physical storage deleted bytes',
                ),
                deletionCount: accountingSum(
                    reservationAccounting.deletionCount,
                    checkpointAccounting?.deletionCount,
                    'Physical storage deletion count',
                ),
                deletionDurationMilliseconds:
                    reservationAccounting.deletionDurationMilliseconds +
                    (checkpointAccounting?.deletionDurationMilliseconds ?? 0),
                cleanupCompleted: retirementCleanupCompleted,
                cleanupDurationMilliseconds,
                commitReadbackByteLength,
                commitReadbackCallCount,
                ciphertextReadByteLength: physicalReadByteLength,
                ciphertextReadCallCount: physicalReadCallCount,
                ciphertextWriteByteLength: physicalWriteByteLength,
                ciphertextWriteCallCount: physicalWriteCallCount,
                deterministicRegeneratedByteLength,
                deterministicRegenerationCallCount,
                openCallCount: accountingSum(
                    requireAccountingNumber(
                        secretRecordOpenCount,
                        'Secret-record open count',
                    ),
                    checkpointAccounting?.openCallCount,
                    'Authenticated record open count',
                ),
                openCiphertextByteLength: accountingSum(
                    requireAccountingNumber(
                        secretRecordOpenByteLength,
                        'Secret-record open ciphertext bytes',
                    ),
                    checkpointAccounting?.openCiphertextByteLength,
                    'Authenticated record open ciphertext bytes',
                ),
                openPlaintextByteLength: accountingSum(
                    requireAccountingNumber(
                        secretRecordOpenPlaintextByteLength,
                        'Secret-record open plaintext bytes',
                    ),
                    checkpointAccounting?.openPlaintextByteLength,
                    'Authenticated record open plaintext bytes',
                ),
                physicalQuotaByteLength: accountingSum(
                    reservationAccounting.physicalQuotaByteLength,
                    checkpointAccounting?.physicalQuotaByteLength,
                    'Physical storage quota bytes',
                ),
                physicalQuotaHeadroomByteLength: accountingSum(
                    reservationAccounting.physicalQuotaHeadroomByteLength,
                    checkpointAccounting?.physicalQuotaHeadroomByteLength,
                    'Physical storage quota headroom bytes',
                ),
                physicalQuotaReservedByteLength: accountingSum(
                    reservationAccounting.physicalQuotaReservedByteLength,
                    checkpointAccounting?.physicalQuotaReservedByteLength,
                    'Physical storage reserved quota bytes',
                ),
                physicalReadByteLength,
                physicalReadCallCount,
                physicalStoredEndByteLength: accountingSum(
                    reservationAccounting.physicalStoredEndByteLength,
                    checkpointAccounting?.physicalStoredEndByteLength,
                    'Physical stored terminal bytes',
                ),
                physicalStoredPeakByteLength: accountingSum(
                    reservationAccounting.physicalStoredPeakByteLength,
                    checkpointAccounting?.physicalStoredPeakByteLength,
                    'Physical stored peak bytes',
                ),
                physicalStoredStartByteLength: accountingSum(
                    reservationAccounting.physicalStoredStartByteLength,
                    checkpointAccounting?.physicalStoredStartByteLength,
                    'Physical stored initial bytes',
                ),
                physicalWriteByteLength,
                physicalWriteCallCount,
                plaintextReadByteLength: accountingSum(
                    plaintextReadByteLength,
                    checkpointAccounting?.openPlaintextByteLength,
                    'Plaintext read bytes',
                ),
                plaintextReadCallCount: accountingSum(
                    plaintextReadCallCount,
                    checkpointAccounting?.openCallCount,
                    'Plaintext read calls',
                ),
                plaintextWriteByteLength: accountingSum(
                    plaintextWriteByteLength,
                    checkpointAccounting?.sealPlaintextByteLength,
                    'Plaintext write bytes',
                ),
                plaintextWriteCallCount: accountingSum(
                    plaintextWriteCallCount,
                    checkpointAccounting?.sealCallCount,
                    'Plaintext write calls',
                ),
                repairHashCallCount: accountingSum(
                    reservationAccounting.repairHashCallCount,
                    checkpointAccounting?.repairHashCallCount,
                    'Repair hash calls',
                ),
                repairHashedByteLength: accountingSum(
                    reservationAccounting.repairHashedByteLength,
                    checkpointAccounting?.repairHashedByteLength,
                    'Repair hash bytes',
                ),
                sealCallCount: accountingSum(
                    requireAccountingNumber(
                        secretRecordSealCount,
                        'Secret-record seal count',
                    ),
                    checkpointAccounting?.sealCallCount,
                    'Authenticated record seal count',
                ),
                sealCiphertextByteLength: accountingSum(
                    requireAccountingNumber(
                        secretRecordSealCiphertextByteLength,
                        'Secret-record seal ciphertext bytes',
                    ),
                    checkpointAccounting?.sealCiphertextByteLength,
                    'Authenticated record seal ciphertext bytes',
                ),
                sealPlaintextByteLength: accountingSum(
                    requireAccountingNumber(
                        secretRecordSealByteLength,
                        'Secret-record seal plaintext bytes',
                    ),
                    checkpointAccounting?.sealPlaintextByteLength,
                    'Authenticated record seal plaintext bytes',
                ),
                storageRequestCount: accountingSum(
                    reservationAccounting.storageRequestCount,
                    checkpointAccounting?.storageRequestCount,
                    'Physical storage requests',
                ),
                storageTransactionCount: accountingSum(
                    reservationAccounting.storageTransactionCount,
                    checkpointAccounting?.storageTransactionCount,
                    'Physical storage transactions',
                ),
            });
        };

    return Object.freeze({
        armApplicationHandoff,
        ...(configuredCheckpointCustody === undefined
            ? {}
            : { checkpointCustody: configuredCheckpointCustody }),
        completeVerifiedOutput: async () => {
            assertOpen();
            if (
                !outputSealed ||
                outputByteLength === 0 ||
                objects.size !== 0 ||
                externalMemoryPayloadByteLength !== 0n ||
                externalMemoryRecordCount !== 0
            ) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidState',
                    'Common-proof output completion requires one sealed output and no retained scratch state.',
                );
            }
            state = 'retiring';
            const completionFailures = await cleanupTerminalProofAuthority();
            permanentlyRetireInMemory();
            if (completionFailures.length !== 0) {
                throw new BrowserActionStorageCustodyError(
                    'StorageFailure',
                    'Verified common-proof output completion could not release every temporary authority.',
                    completionFailures,
                );
            }
        },
        copyPhysicalStorageAccounting,
        copyCheckpointResumeDescriptor: () =>
            latestCheckpointResumeDescriptor === undefined
                ? undefined
                : copyCheckpointResumeDescriptor(
                      latestCheckpointResumeDescriptor,
                  ),
        authenticatedOutput: (): AuthenticatedCommonProofInputStore => {
            assertOpen();
            if (!outputSealed || outputByteLength === 0) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidState',
                    'Common-proof canonical output is not sealed.',
                );
            }
            return Object.freeze({
                declaredByteLength: outputByteLength,
                readCommittedChunk: (chunkIndex, exactByteLength) =>
                    outputStore.readChunk(chunkIndex, exactByteLength),
            });
        },
        externalMemory: Object.freeze({
            copyBrowserStorageAccounting: () =>
                Object.freeze({
                    ...payloadBufferAccounting,
                    secretRecordOpenByteLength,
                    secretRecordOpenCount,
                    secretRecordSealByteLength,
                    secretRecordSealCount,
                }),
            executeTransaction: (request: CommonProofExternalMemoryRequest) =>
                executeTransaction(request, false),
        }),
        outputStore,
        prefixReplayExternalMemory: Object.freeze({
            confirmAuthenticatedCheckpointExternalMemoryState,
            executeDeterministicPrefixReplayTransaction: (
                request: CommonProofExternalMemoryRequest,
            ) => executeTransaction(request, true),
        }),
        releaseExternalMemory: async () => {
            assertOpen();
            state = 'releasing-external-memory';
            try {
                await deleteAllExternalMemory();
                state = 'open';
            } catch (error) {
                permanentlyRetireInMemory();
                throw error;
            }
        },
        retire: async () => {
            if (retirementCleanupCompleted) {
                return;
            }
            state = 'retiring';
            const cleanupFailures = await cleanupTerminalProofAuthority();
            permanentlyRetireInMemory();
            if (cleanupFailures.length !== 0) {
                throw new BrowserActionStorageCustodyError(
                    'StorageFailure',
                    'Common-proof browser custody retirement could not remove every record.',
                    cleanupFailures,
                );
            }
        },
        sealCanonicalOutput: () => {
            assertOpen();
            if (outputSealed || outputChunks.size === 0) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidState',
                    'Common-proof canonical output cannot be sealed in its current state.',
                );
            }
            outputSealed = true;
        },
        suspendForAuthenticatedResume: async () => {
            assertOpen();
            if (latestCheckpointResumeDescriptor === undefined) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidState',
                    'Common-proof custody cannot suspend without an authenticated checkpoint.',
                );
            }
            if (checkpointOperationIdentity !== undefined) {
                if (input.checkpoint === undefined) {
                    throw new BrowserActionStorageCustodyError(
                        'InvalidState',
                        'Common-proof checkpoint identity cleanup lost its authenticated store.',
                    );
                }
                await input.checkpoint.store.releaseOperationIdentity(
                    checkpointOperationIdentity,
                );
                checkpointOperationIdentity = undefined;
            }
            await releaseCheckpointPhysicalAccountingScope();
            await releaseTerminalCapacityReservation();
            for (const object of objects.values()) {
                destroyExternalMemoryObjectInMemory(object);
            }
            objects.clear();
            externalMemoryPayloadByteLength = 0n;
            externalMemoryRecordCount = 0;
            outputChunks.clear();
            outputByteLength = 0;
            outputSealed = false;
            outputTerminalChunkIndex = undefined;
            permanentlyRetireInMemory(false);
            retirementCleanupCompleted = true;
        },
    });
};
