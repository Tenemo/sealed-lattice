import { shake256 } from '@noble/hashes/sha3.js';
import { canonicalJson } from '@sealed-lattice/crypto';
import { foundationProfile } from '@sealed-lattice/types';

import {
    AuthenticatedRuntimeRecordError,
    type AuthenticatedRuntimeRecordErrorCode,
    bytesEqual,
    bytesToHex,
    copyBoundedBytes,
    copyExactBytes,
    copyRuntimeStorageAuthorityContext,
    createRuntimeRecordProtection,
    mapStorageError,
    readRuntimeRecord,
    sampleRuntimeIdentifier,
    stageRuntimeRecordWrite,
    type RuntimeStorageAuthorityContext,
} from './authenticated-runtime-record.js';
import type {
    UntrustedStorageTransaction,
    UntrustedStorageTransactionStore,
} from './untrusted-storage-transaction-store.js';

const checkpointManifestSchemaIdentifier = 0x1805;
const checkpointRandomCursorSchemaIdentifier = 0x1804;
const streamDescriptorSchemaIdentifier = 0x1800;
const canonicalTupleSchemaIdentifier = 0x0001;
const canonicalSchemaVersion = 1;
const hashByteLength = 64;
const identifierByteLength = 32;
const checkpointRecordVersion = 1;
const checkpointManifestOperationDomain =
    'sealed-lattice/runtime/checkpoint-manifest-record/v1';
const checkpointJournalOperationDomain =
    'sealed-lattice/runtime/checkpoint-journal-record/v1';
const checkpointChunkOperationDomain =
    'sealed-lattice/runtime/checkpoint-chunk-record/v1';
const chunkDigestDomain = 'sealed-lattice/transport/chunk/v1';
const fullObjectDigestDomain = 'sealed-lattice/transport/full-object/v1';
const maximumStateStreamDomainByteLength = 256;
const textEncoder = new TextEncoder();
const fatalTextDecoder = new TextDecoder('utf-8', { fatal: true });
const checkpointOperationIdentityBrand = Symbol(
    'checkpoint-operation-identity',
);

export type CheckpointRandomCursor = Readonly<{
    derivationContextHash: Uint8Array;
    family: number;
    nextCounter: bigint;
    nextUnreadBitOffsetInBufferedBlock?: number;
    purpose: number;
    streamAttemptIdentifier: Uint8Array;
}>;

type KernelPrivateRandomCursor = Readonly<{
    derivationContextHash: string;
    family: number;
    nextCounter: string;
    nextUnreadBitOffsetInBufferedBlock?: number;
    purpose: number;
    streamAttemptIdentifierHex: string;
}>;

export type CheckpointRandomCursorKernel = Readonly<{
    decodePrivateRandomCursor(input: {
        canonicalBytesHex: string;
    }): Readonly<{ value: KernelPrivateRandomCursor }>;
    encodePrivateRandomCursor(
        value: KernelPrivateRandomCursor,
    ): Readonly<{ canonicalBytesHex: string }>;
}>;

export type CheckpointBoundaryPolicy = Readonly<{
    validatePublication(input: {
        boundary: CheckpointBoundary;
        checkpointLineageIdentifier: Uint8Array;
        previousBoundary?: CheckpointBoundary;
    }): Promise<void> | void;
    validateResume(input: {
        checkpointLineageIdentifier: Uint8Array;
        expectedBoundary: ExpectedCheckpointBoundary;
    }): Promise<void> | void;
}>;

export type CheckpointOperationIdentity = Readonly<{
    readonly [checkpointOperationIdentityBrand]: true;
    checkpointLineageIdentifier: Uint8Array;
    streamAttemptIdentifiers: readonly Uint8Array[];
}>;

export type CheckpointBoundary = Readonly<{
    operationKind: number;
    orderedRandomCursors: readonly CheckpointRandomCursor[];
    orderedSourceDigests: readonly Uint8Array[];
    safeBoundaryOrdinal: number;
    stateStreamDescriptorBytes: Uint8Array;
    stateStreamDomain: string;
}>;

export type ExpectedCheckpointBoundary = Omit<
    CheckpointBoundary,
    'stateStreamDescriptorBytes'
>;

export type AuthenticatedCheckpointStoreLimits = Readonly<{
    maximumCheckpointStateByteLength: number;
    maximumManifestByteLength: number;
    maximumRandomCursorCount: number;
    maximumRecordSealingCount: number;
    maximumSourceDigestCount: number;
    maximumStreamAttemptCount: number;
    transactionLifetimeMilliseconds: number;
}>;

export type ResumedCheckpoint = Readonly<{
    canonicalManifestBytes: Uint8Array;
    operationIdentity: CheckpointOperationIdentity;
    stateStreamDescriptorBytes: Uint8Array;
    restoreState(
        consumeChunk: (
            chunkIndex: number,
            chunkBytes: Uint8Array,
        ) => Promise<void> | void,
    ): Promise<void>;
}>;

export type AuthenticatedCheckpointStore = Readonly<{
    copyAuthorityContext(): RuntimeStorageAuthorityContext;
    beginOperation(
        streamAttemptIdentifiers: readonly Uint8Array[],
    ): Promise<CheckpointOperationIdentity>;
    evict(checkpointLineageIdentifier: Uint8Array): Promise<void>;
    publish(input: {
        boundary: CheckpointBoundary;
        identity: CheckpointOperationIdentity;
        stateChunks: AsyncIterable<Uint8Array> | Iterable<Uint8Array>;
    }): Promise<Uint8Array>;
    repair(checkpointLineageIdentifier: Uint8Array): Promise<void>;
    resume(input: {
        checkpointLineageIdentifier: Uint8Array;
        expectedBoundary: ExpectedCheckpointBoundary;
    }): Promise<ResumedCheckpoint>;
}>;

type StreamDescriptor = Readonly<{
    fullObjectDigest: Uint8Array;
    orderedChunkDigests: readonly Uint8Array[];
    totalByteLength: number;
}>;

type StoredCheckpointManifest = Readonly<{
    canonicalManifest: string;
    publicationIdentifier: string;
    recordVersion: number;
}>;

type DecodedCheckpointManifest = StoredCheckpointManifest &
    Readonly<{
        chunkRecordKeys: readonly string[];
        stateStreamDescriptorBytes: Uint8Array;
    }>;

type StoredCheckpointJournal = Readonly<{
    checkpointLineageIdentifier: string;
    newChunkRecordKeys: readonly string[];
    obsoleteChunkRecordKeys: readonly string[];
    publicationIdentifier: string;
    recordVersion: number;
}>;

type CheckpointOperationIdentityRecord = {
    checkpointLineageIdentifier: Uint8Array;
    lastCanonicalManifestBytes?: Uint8Array;
    lastPublishedBoundary?: CheckpointBoundary;
    operationKind?: number;
    orderedSourceDigestHex?: readonly string[];
    stateStreamDomain?: string;
    streamAttemptIdentifiers: readonly Uint8Array[];
};

type CanonicalItem = Readonly<{
    itemType: number;
    payload: Uint8Array;
}>;

const isPlainRecord = (value: unknown): value is Record<string, unknown> =>
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;

const requireSafePositiveInteger = (value: number, label: string): void => {
    if (!Number.isSafeInteger(value) || value <= 0) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidConfiguration',
            `${label} must be a positive safe integer.`,
        );
    }
};

const requireSafeNonnegativeInteger = (value: number, label: string): void => {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            `${label} must be a non-negative safe integer.`,
        );
    }
};

const concatenateBytes = (parts: readonly Uint8Array[]): Uint8Array => {
    const totalByteLength = parts.reduce(
        (total, part) => total + part.byteLength,
        0,
    );
    if (!Number.isSafeInteger(totalByteLength)) {
        throw new AuthenticatedRuntimeRecordError(
            'ResourceLimit',
            'Checkpoint framing exceeds the safe integer range.',
        );
    }
    const output = new Uint8Array(totalByteLength);
    let offset = 0;
    for (const part of parts) {
        output.set(part, offset);
        offset += part.byteLength;
    }
    return output;
};

const unsigned16LittleEndian = (value: number): Uint8Array => {
    if (!Number.isInteger(value) || value < 0 || value > 0xffff) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            'Checkpoint unsigned-16 value is out of range.',
        );
    }
    const bytes = new Uint8Array(2);
    new DataView(bytes.buffer).setUint16(0, value, true);
    return bytes;
};

const unsigned32LittleEndian = (value: number): Uint8Array => {
    if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            'Checkpoint unsigned-32 value is out of range.',
        );
    }
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value, true);
    return bytes;
};

const unsigned64LittleEndian = (value: bigint): Uint8Array => {
    if (value < 0n || value > 0xffff_ffff_ffff_ffffn) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            'Checkpoint unsigned-64 value is out of range.',
        );
    }
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, value, true);
    return bytes;
};

const encodeCanonicalTuple = (
    schemaIdentifier: number,
    items: readonly CanonicalItem[],
): Uint8Array =>
    concatenateBytes([
        unsigned16LittleEndian(schemaIdentifier),
        unsigned16LittleEndian(canonicalSchemaVersion),
        unsigned32LittleEndian(items.length),
        ...items.flatMap((item) => [
            unsigned16LittleEndian(item.itemType),
            unsigned32LittleEndian(item.payload.byteLength),
            item.payload,
        ]),
    ]);

const fixedCanonicalItem = (
    itemType: number,
    payload: Uint8Array,
): CanonicalItem => ({ itemType, payload: payload.slice() });

const homogeneousListCanonicalItem = (
    elementType: number,
    elementPayloads: readonly Uint8Array[],
): CanonicalItem => ({
    itemType: 0x0e,
    payload: concatenateBytes([
        unsigned16LittleEndian(elementType),
        unsigned32LittleEndian(elementPayloads.length),
        ...elementPayloads,
    ]),
});

const validateRandomCursor = (
    cursor: CheckpointRandomCursor,
): CheckpointRandomCursor => {
    if (
        !Number.isInteger(cursor.family) ||
        cursor.family < 0 ||
        cursor.family > 0xffff ||
        !Number.isInteger(cursor.purpose) ||
        cursor.purpose < 0 ||
        cursor.purpose > 0xffff ||
        cursor.nextCounter < 0n ||
        cursor.nextCounter > 0xffff_ffff_ffff_ffffn ||
        (cursor.nextUnreadBitOffsetInBufferedBlock !== undefined &&
            (!Number.isInteger(cursor.nextUnreadBitOffsetInBufferedBlock) ||
                cursor.nextUnreadBitOffsetInBufferedBlock < 0 ||
                cursor.nextUnreadBitOffsetInBufferedBlock > 511 ||
                cursor.nextCounter === 0n))
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            'Checkpoint random cursor is outside its canonical range.',
        );
    }
    return Object.freeze({
        derivationContextHash: copyExactBytes(
            cursor.derivationContextHash,
            hashByteLength,
            'derivationContextHash',
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
        streamAttemptIdentifier: copyExactBytes(
            cursor.streamAttemptIdentifier,
            identifierByteLength,
            'streamAttemptIdentifier',
        ),
    });
};

const compareBytes = (left: Uint8Array, right: Uint8Array): number => {
    const sharedByteLength = Math.min(left.byteLength, right.byteLength);
    for (let byteIndex = 0; byteIndex < sharedByteLength; byteIndex += 1) {
        const difference = left[byteIndex] - right[byteIndex];
        if (difference !== 0) {
            return difference;
        }
    }
    return left.byteLength - right.byteLength;
};

const compareRandomCursors = (
    left: CheckpointRandomCursor,
    right: CheckpointRandomCursor,
): number =>
    left.family - right.family ||
    left.purpose - right.purpose ||
    compareBytes(left.derivationContextHash, right.derivationContextHash) ||
    compareBytes(left.streamAttemptIdentifier, right.streamAttemptIdentifier);

function copyAndValidateBoundary(
    boundary: CheckpointBoundary,
    limits: AuthenticatedCheckpointStoreLimits,
): CheckpointBoundary;
function copyAndValidateBoundary(
    boundary: ExpectedCheckpointBoundary,
    limits: AuthenticatedCheckpointStoreLimits,
): ExpectedCheckpointBoundary;
function copyAndValidateBoundary(
    boundary: CheckpointBoundary | ExpectedCheckpointBoundary,
    limits: AuthenticatedCheckpointStoreLimits,
): CheckpointBoundary | ExpectedCheckpointBoundary {
    if (typeof boundary.stateStreamDomain !== 'string') {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            'Checkpoint state stream domain must be a string.',
        );
    }
    const stateStreamDomainBytes = textEncoder.encode(
        boundary.stateStreamDomain,
    );
    if (
        !Number.isInteger(boundary.operationKind) ||
        boundary.operationKind <= 0 ||
        boundary.operationKind > 0xffff ||
        !Number.isInteger(boundary.safeBoundaryOrdinal) ||
        boundary.safeBoundaryOrdinal < 0 ||
        boundary.safeBoundaryOrdinal > 0xffff_ffff ||
        boundary.orderedSourceDigests.length >
            limits.maximumSourceDigestCount ||
        boundary.orderedRandomCursors.length >
            limits.maximumRandomCursorCount ||
        stateStreamDomainBytes.byteLength === 0 ||
        stateStreamDomainBytes.byteLength >
            maximumStateStreamDomainByteLength ||
        ![...stateStreamDomainBytes].every(
            (byte) => byte >= 0x20 && byte <= 0x7e,
        )
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            'Checkpoint boundary is outside the configured profile.',
        );
    }
    const orderedSourceDigests = boundary.orderedSourceDigests.map(
        (digest, digestIndex) =>
            copyExactBytes(
                digest,
                hashByteLength,
                `orderedSourceDigests[${digestIndex}]`,
            ),
    );
    const orderedRandomCursors =
        boundary.orderedRandomCursors.map(validateRandomCursor);
    for (
        let cursorIndex = 1;
        cursorIndex < orderedRandomCursors.length;
        cursorIndex += 1
    ) {
        if (
            compareRandomCursors(
                orderedRandomCursors[cursorIndex - 1],
                orderedRandomCursors[cursorIndex],
            ) >= 0
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'InvalidInput',
                'Checkpoint random cursors must be strictly ordered without duplicates.',
            );
        }
    }
    return Object.freeze({
        operationKind: boundary.operationKind,
        orderedRandomCursors,
        orderedSourceDigests,
        safeBoundaryOrdinal: boundary.safeBoundaryOrdinal,
        ...('stateStreamDescriptorBytes' in boundary
            ? {
                  stateStreamDescriptorBytes: copyBoundedBytes(
                      boundary.stateStreamDescriptorBytes,
                      limits.maximumManifestByteLength,
                      'stateStreamDescriptorBytes',
                  ),
              }
            : {}),
        stateStreamDomain: boundary.stateStreamDomain,
    });
}

const requireCursorTuple = (bytes: Uint8Array): Uint8Array => {
    if (
        bytes.byteLength < 8 ||
        new DataView(
            bytes.buffer,
            bytes.byteOffset,
            bytes.byteLength,
        ).getUint16(0, true) !== checkpointRandomCursorSchemaIdentifier ||
        new DataView(
            bytes.buffer,
            bytes.byteOffset,
            bytes.byteLength,
        ).getUint16(2, true) !== canonicalSchemaVersion
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'The checkpoint cursor codec returned the wrong canonical schema.',
        );
    }
    return bytes.slice();
};

const encodeCheckpointManifest = (input: {
    authorityContext: RuntimeStorageAuthorityContext;
    boundary: CheckpointBoundary | ExpectedCheckpointBoundary;
    checkpointLineageIdentifier: Uint8Array;
    cursorKernel: CheckpointRandomCursorKernel;
    stateStreamDescriptorBytes: Uint8Array;
}): Uint8Array => {
    const encodedCursors: Uint8Array[] = [];
    for (const cursor of input.boundary.orderedRandomCursors) {
        encodedCursors.push(
            requireCursorTuple(
                copyBoundedBytes(
                    encodeCheckpointRandomCursor(input.cursorKernel, cursor),
                    1_024,
                    'canonical random cursor',
                ),
            ),
        );
    }
    return encodeCanonicalTuple(checkpointManifestSchemaIdentifier, [
        fixedCanonicalItem(
            0x06,
            input.authorityContext.runtimeBuildManifestHash,
        ),
        fixedCanonicalItem(0x06, input.authorityContext.suiteIdentifier),
        fixedCanonicalItem(0x06, input.authorityContext.ceremonyContextHash),
        fixedCanonicalItem(0x06, input.authorityContext.actionContextHash),
        fixedCanonicalItem(
            0x07,
            input.authorityContext.ownerParticipantIdentity,
        ),
        fixedCanonicalItem(0x01, input.checkpointLineageIdentifier),
        fixedCanonicalItem(
            0x03,
            unsigned16LittleEndian(input.boundary.operationKind),
        ),
        fixedCanonicalItem(
            0x04,
            unsigned32LittleEndian(input.boundary.safeBoundaryOrdinal),
        ),
        homogeneousListCanonicalItem(0x06, input.boundary.orderedSourceDigests),
        homogeneousListCanonicalItem(0x09, encodedCursors),
        fixedCanonicalItem(0x09, input.stateStreamDescriptorBytes),
    ]);
};

const parseCheckpointManifestReferences = (
    canonicalManifestBytes: Uint8Array,
): Readonly<{
    checkpointLineageIdentifier: Uint8Array;
    stateStreamDescriptorBytes: Uint8Array;
}> => {
    const expectedItemTypes = [
        0x06, 0x06, 0x06, 0x06, 0x07, 0x01, 0x03, 0x04, 0x0e, 0x0e, 0x09,
    ] as const;
    const fixedItemByteLengths = [
        hashByteLength,
        hashByteLength,
        hashByteLength,
        hashByteLength,
        hashByteLength,
        identifierByteLength,
        2,
        4,
    ] as const;
    const view = new DataView(
        canonicalManifestBytes.buffer,
        canonicalManifestBytes.byteOffset,
        canonicalManifestBytes.byteLength,
    );
    let offset = 0;
    const readUnsigned16 = (): number => {
        if (offset + 2 > canonicalManifestBytes.byteLength) {
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                'Canonical checkpoint manifest is truncated.',
            );
        }
        const value = view.getUint16(offset, true);
        offset += 2;
        return value;
    };
    const readUnsigned32 = (): number => {
        if (offset + 4 > canonicalManifestBytes.byteLength) {
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                'Canonical checkpoint manifest is truncated.',
            );
        }
        const value = view.getUint32(offset, true);
        offset += 4;
        return value;
    };
    if (
        readUnsigned16() !== checkpointManifestSchemaIdentifier ||
        readUnsigned16() !== canonicalSchemaVersion ||
        readUnsigned32() !== expectedItemTypes.length
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'Canonical checkpoint manifest has the wrong header.',
        );
    }

    let checkpointLineageIdentifier: Uint8Array | undefined;
    let stateStreamDescriptorBytes: Uint8Array | undefined;
    for (
        let itemIndex = 0;
        itemIndex < expectedItemTypes.length;
        itemIndex += 1
    ) {
        if (readUnsigned16() !== expectedItemTypes[itemIndex]) {
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                'Canonical checkpoint manifest has the wrong item types.',
            );
        }
        const itemByteLength = readUnsigned32();
        if (
            offset + itemByteLength > canonicalManifestBytes.byteLength ||
            (itemIndex < fixedItemByteLengths.length &&
                itemByteLength !== fixedItemByteLengths[itemIndex])
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                'Canonical checkpoint manifest has malformed item framing.',
            );
        }
        const itemBytes = canonicalManifestBytes.slice(
            offset,
            offset + itemByteLength,
        );
        if (itemIndex === 5) {
            checkpointLineageIdentifier = itemBytes;
        } else if (itemIndex === 10) {
            if (itemBytes.byteLength === 0) {
                throw new AuthenticatedRuntimeRecordError(
                    'AuthenticationFailed',
                    'Canonical checkpoint manifest has an empty state descriptor.',
                );
            }
            stateStreamDescriptorBytes = itemBytes;
        }
        offset += itemByteLength;
    }
    if (
        offset !== canonicalManifestBytes.byteLength ||
        checkpointLineageIdentifier === undefined ||
        stateStreamDescriptorBytes === undefined
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'Canonical checkpoint manifest contains trailing or missing data.',
        );
    }
    return { checkpointLineageIdentifier, stateStreamDescriptorBytes };
};

const parseStreamDescriptor = (
    descriptorBytes: Uint8Array,
    limits: AuthenticatedCheckpointStoreLimits,
): StreamDescriptor => {
    const bytes = copyBoundedBytes(
        descriptorBytes,
        limits.maximumManifestByteLength,
        'state stream descriptor',
    );
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    let offset = 0;
    const requireAvailable = (byteLength: number): void => {
        if (offset + byteLength > bytes.byteLength) {
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                'State stream descriptor is truncated.',
            );
        }
    };
    const readUnsigned16 = (): number => {
        requireAvailable(2);
        const value = view.getUint16(offset, true);
        offset += 2;
        return value;
    };
    const readUnsigned32 = (): number => {
        requireAvailable(4);
        const value = view.getUint32(offset, true);
        offset += 4;
        return value;
    };
    const readBytes = (byteLength: number): Uint8Array => {
        requireAvailable(byteLength);
        const value = bytes.slice(offset, offset + byteLength);
        offset += byteLength;
        return value;
    };
    if (
        readUnsigned16() !== streamDescriptorSchemaIdentifier ||
        readUnsigned16() !== canonicalSchemaVersion ||
        readUnsigned32() !== 3 ||
        readUnsigned16() !== 0x05 ||
        readUnsigned32() !== 8
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'State stream descriptor has the wrong canonical header.',
        );
    }
    const totalByteLengthBigInt = new DataView(
        readBytes(8).buffer,
    ).getBigUint64(0, true);
    if (
        totalByteLengthBigInt === 0n ||
        totalByteLengthBigInt >
            BigInt(
                Math.min(
                    limits.maximumCheckpointStateByteLength,
                    foundationProfile.maximumCanonicalStreamByteLength,
                ),
            )
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'ResourceLimit',
            'Checkpoint state length is outside the configured profile.',
        );
    }
    const totalByteLength = Number(totalByteLengthBigInt);
    if (readUnsigned16() !== 0x0e) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'State stream descriptor chunk list has the wrong item type.',
        );
    }
    const chunkListByteLength = readUnsigned32();
    const chunkListStart = offset;
    if (readUnsigned16() !== 0x06) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'State stream descriptor chunk list has the wrong element type.',
        );
    }
    const chunkCount = readUnsigned32();
    const expectedChunkCount = Math.ceil(
        totalByteLength / foundationProfile.streamChunkByteLength,
    );
    if (
        chunkCount !== expectedChunkCount ||
        chunkListByteLength !== 6 + chunkCount * hashByteLength
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'State stream descriptor chunk count is inconsistent.',
        );
    }
    const orderedChunkDigests: Uint8Array[] = [];
    for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex += 1) {
        orderedChunkDigests.push(readBytes(hashByteLength));
    }
    if (offset !== chunkListStart + chunkListByteLength) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'State stream descriptor has malformed chunk framing.',
        );
    }
    if (readUnsigned16() !== 0x06 || readUnsigned32() !== hashByteLength) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'State stream descriptor full-object digest has the wrong item framing.',
        );
    }
    const fullObjectDigest = readBytes(hashByteLength);
    if (offset !== bytes.byteLength) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'State stream descriptor contains trailing bytes.',
        );
    }
    return { fullObjectDigest, orderedChunkDigests, totalByteLength };
};

const updateUnsigned16 = (
    hash: ReturnType<typeof shake256.create>,
    value: number,
): void => {
    hash.update(unsigned16LittleEndian(value));
};

const updateUnsigned32 = (
    hash: ReturnType<typeof shake256.create>,
    value: number,
): void => {
    hash.update(unsigned32LittleEndian(value));
};

const updateAsciiItem = (
    hash: ReturnType<typeof shake256.create>,
    value: string,
): void => {
    const bytes = textEncoder.encode(value);
    updateUnsigned16(hash, 0x02);
    updateUnsigned32(hash, bytes.byteLength + 4);
    updateUnsigned32(hash, bytes.byteLength);
    hash.update(bytes);
};

const deriveChunkDigest = (input: {
    chunkBytes: Uint8Array;
    chunkIndex: number;
    stateStreamDomain: string;
}): Uint8Array => {
    const hash = shake256.create({ dkLen: hashByteLength });
    try {
        updateUnsigned16(hash, canonicalTupleSchemaIdentifier);
        updateUnsigned16(hash, canonicalSchemaVersion);
        updateUnsigned32(hash, 5);
        updateAsciiItem(hash, chunkDigestDomain);
        updateAsciiItem(hash, input.stateStreamDomain);
        updateUnsigned16(hash, 0x04);
        updateUnsigned32(hash, 4);
        updateUnsigned32(hash, input.chunkIndex);
        updateUnsigned16(hash, 0x04);
        updateUnsigned32(hash, 4);
        updateUnsigned32(hash, input.chunkBytes.byteLength);
        updateUnsigned16(hash, 0x01);
        updateUnsigned32(hash, input.chunkBytes.byteLength + 4);
        updateUnsigned32(hash, input.chunkBytes.byteLength);
        hash.update(input.chunkBytes);
        return hash.digest();
    } finally {
        hash.destroy();
    }
};

const createFullObjectDigestHasher = (input: {
    stateStreamDomain: string;
    totalByteLength: number;
}): ReturnType<typeof shake256.create> => {
    const hash = shake256.create({ dkLen: hashByteLength });
    updateUnsigned16(hash, canonicalTupleSchemaIdentifier);
    updateUnsigned16(hash, canonicalSchemaVersion);
    updateUnsigned32(hash, 4);
    updateAsciiItem(hash, fullObjectDigestDomain);
    updateAsciiItem(hash, input.stateStreamDomain);
    updateUnsigned16(hash, 0x05);
    updateUnsigned32(hash, 8);
    hash.update(unsigned64LittleEndian(BigInt(input.totalByteLength)));
    updateUnsigned16(hash, 0x01);
    updateUnsigned32(hash, input.totalByteLength + 4);
    updateUnsigned32(hash, input.totalByteLength);
    return hash;
};

const authenticateFullObjectDigest = (
    hash: ReturnType<typeof shake256.create>,
    expectedDigest: Uint8Array,
): void => {
    if (!bytesEqual(hash.digest(), expectedDigest)) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'Checkpoint state does not match its canonical full-object digest.',
        );
    }
};

const expectedChunkByteLength = (
    descriptor: StreamDescriptor,
    chunkIndex: number,
): number =>
    chunkIndex + 1 < descriptor.orderedChunkDigests.length
        ? foundationProfile.streamChunkByteLength
        : descriptor.totalByteLength -
          foundationProfile.streamChunkByteLength * chunkIndex;

const manifestRecordKey = (lineageIdentifier: Uint8Array): string =>
    `checkpoint/manifest/${bytesToHex(lineageIdentifier)}`;

const journalRecordKey = (lineageIdentifier: Uint8Array): string =>
    `checkpoint/journal/${bytesToHex(lineageIdentifier)}`;

const chunkRecordKey = (input: {
    checkpointLineageIdentifier: Uint8Array;
    chunkDigest: Uint8Array;
    chunkIndex: number;
    publicationIdentifier: Uint8Array;
}): string =>
    `checkpoint/chunk/${bytesToHex(
        input.checkpointLineageIdentifier,
    )}/${bytesToHex(input.publicationIdentifier)}/${input.chunkIndex
        .toString(16)
        .padStart(8, '0')}-${bytesToHex(input.chunkDigest)}`;

const encodeCanonicalJson = (value: unknown): Uint8Array =>
    textEncoder.encode(canonicalJson(value));

const parseCanonicalJsonRecord = (
    bytes: Uint8Array,
    label: string,
): Record<string, unknown> => {
    let value: unknown;
    try {
        value = JSON.parse(fatalTextDecoder.decode(bytes));
    } catch (error) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            `${label} is not valid UTF-8 JSON.`,
            error,
        );
    }
    if (
        !isPlainRecord(value) ||
        !bytesEqual(bytes, encodeCanonicalJson(value))
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            `${label} is not canonical JSON.`,
        );
    }
    return value;
};

const requireExactKeys = (
    value: Record<string, unknown>,
    keys: readonly string[],
    label: string,
): void => {
    if (
        keys.some((key) => !(key in value)) ||
        Object.keys(value).some((key) => !keys.includes(key))
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            `${label} has the wrong fields.`,
        );
    }
};

const decodeCanonicalHex = (
    value: unknown,
    maximumByteLength: number,
    label: string,
): Uint8Array => {
    if (
        typeof value !== 'string' ||
        value.length % 2 !== 0 ||
        value.length > maximumByteLength * 2 ||
        !/^(?:[0-9a-f]{2})+$/u.test(value)
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            `${label} is not bounded canonical hexadecimal.`,
        );
    }
    const bytes = new Uint8Array(value.length / 2);
    for (let byteIndex = 0; byteIndex < bytes.byteLength; byteIndex += 1) {
        bytes[byteIndex] = Number.parseInt(
            value.slice(byteIndex * 2, byteIndex * 2 + 2),
            16,
        );
    }
    return bytes;
};

const decodeExactHex = (
    value: unknown,
    expectedByteLength: number,
    label: string,
): Uint8Array => {
    const bytes = decodeCanonicalHex(value, expectedByteLength, label);
    if (bytes.byteLength !== expectedByteLength) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            `${label} has the wrong byte length.`,
        );
    }
    return bytes;
};

const cursorMatchesKernelValue = (
    cursor: CheckpointRandomCursor,
    value: KernelPrivateRandomCursor,
): boolean =>
    value.family === cursor.family &&
    value.purpose === cursor.purpose &&
    value.derivationContextHash === bytesToHex(cursor.derivationContextHash) &&
    value.streamAttemptIdentifierHex ===
        bytesToHex(cursor.streamAttemptIdentifier) &&
    value.nextCounter === cursor.nextCounter.toString() &&
    value.nextUnreadBitOffsetInBufferedBlock ===
        cursor.nextUnreadBitOffsetInBufferedBlock;

const encodeCheckpointRandomCursor = (
    kernel: CheckpointRandomCursorKernel,
    untrustedCursor: CheckpointRandomCursor,
): Uint8Array => {
    const cursor = validateRandomCursor(untrustedCursor);
    try {
        const encoded = kernel.encodePrivateRandomCursor({
            derivationContextHash: bytesToHex(cursor.derivationContextHash),
            family: cursor.family,
            nextCounter: cursor.nextCounter.toString(),
            ...(cursor.nextUnreadBitOffsetInBufferedBlock === undefined
                ? {}
                : {
                      nextUnreadBitOffsetInBufferedBlock:
                          cursor.nextUnreadBitOffsetInBufferedBlock,
                  }),
            purpose: cursor.purpose,
            streamAttemptIdentifierHex: bytesToHex(
                cursor.streamAttemptIdentifier,
            ),
        });
        const canonicalBytes = decodeCanonicalHex(
            encoded.canonicalBytesHex,
            1_024,
            'canonical random cursor',
        );
        requireCursorTuple(canonicalBytes);
        const decoded = kernel.decodePrivateRandomCursor({
            canonicalBytesHex: bytesToHex(canonicalBytes),
        });
        if (!cursorMatchesKernelValue(cursor, decoded.value)) {
            canonicalBytes.fill(0);
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                'The kernel random-cursor codec did not round-trip the exact checkpoint cursor.',
            );
        }
        return canonicalBytes;
    } catch (error) {
        if (error instanceof AuthenticatedRuntimeRecordError) {
            throw error;
        }
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'The kernel random-cursor codec refused the checkpoint cursor.',
            error,
        );
    }
};

const decodeRecordKeys = (
    value: unknown,
    expectedPrefix: string,
    maximumCount: number,
    label: string,
): readonly string[] => {
    if (!Array.isArray(value) || value.length > maximumCount) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            `${label} is not a bounded key list.`,
        );
    }
    const keys = value.map((key) => {
        if (typeof key !== 'string' || !key.startsWith(expectedPrefix)) {
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                `${label} contains an invalid owned key.`,
            );
        }
        return key;
    });
    if (new Set(keys).size !== keys.length) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            `${label} contains duplicate keys.`,
        );
    }
    return keys;
};

const decodeStoredManifest = (
    bytes: Uint8Array,
    limits: AuthenticatedCheckpointStoreLimits,
    lineageIdentifier: Uint8Array,
): DecodedCheckpointManifest => {
    const value = parseCanonicalJsonRecord(bytes, 'checkpoint manifest record');
    requireExactKeys(
        value,
        ['canonicalManifest', 'publicationIdentifier', 'recordVersion'],
        'checkpoint manifest record',
    );
    if (value.recordVersion !== checkpointRecordVersion) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'Checkpoint manifest record has an unsupported version.',
        );
    }
    const canonicalManifestBytes = decodeCanonicalHex(
        value.canonicalManifest,
        limits.maximumManifestByteLength,
        'canonicalManifest',
    );
    const manifestReferences = parseCheckpointManifestReferences(
        canonicalManifestBytes,
    );
    if (
        !bytesEqual(
            manifestReferences.checkpointLineageIdentifier,
            lineageIdentifier,
        )
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'Checkpoint manifest record has the wrong lineage.',
        );
    }
    const descriptor = parseStreamDescriptor(
        manifestReferences.stateStreamDescriptorBytes,
        limits,
    );
    const publicationIdentifierBytes = decodeExactHex(
        value.publicationIdentifier,
        identifierByteLength,
        'publicationIdentifier',
    );
    const publicationIdentifier = bytesToHex(publicationIdentifierBytes);
    return {
        canonicalManifest: bytesToHex(canonicalManifestBytes),
        chunkRecordKeys: descriptor.orderedChunkDigests.map(
            (chunkDigest, chunkIndex) =>
                chunkRecordKey({
                    checkpointLineageIdentifier: lineageIdentifier,
                    chunkDigest,
                    chunkIndex,
                    publicationIdentifier: publicationIdentifierBytes,
                }),
        ),
        publicationIdentifier,
        recordVersion: checkpointRecordVersion,
        stateStreamDescriptorBytes:
            manifestReferences.stateStreamDescriptorBytes,
    };
};

const decodeStoredJournal = (
    bytes: Uint8Array,
    limits: AuthenticatedCheckpointStoreLimits,
    lineageIdentifier: Uint8Array,
): StoredCheckpointJournal => {
    const value = parseCanonicalJsonRecord(bytes, 'checkpoint journal record');
    requireExactKeys(
        value,
        [
            'checkpointLineageIdentifier',
            'newChunkRecordKeys',
            'obsoleteChunkRecordKeys',
            'publicationIdentifier',
            'recordVersion',
        ],
        'checkpoint journal record',
    );
    const lineageHex = bytesToHex(lineageIdentifier);
    if (
        value.recordVersion !== checkpointRecordVersion ||
        value.checkpointLineageIdentifier !== lineageHex
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'Checkpoint journal record has the wrong version or lineage.',
        );
    }
    const publicationIdentifier = bytesToHex(
        decodeExactHex(
            value.publicationIdentifier,
            identifierByteLength,
            'publicationIdentifier',
        ),
    );
    const maximumChunkCount = Math.ceil(
        limits.maximumCheckpointStateByteLength /
            foundationProfile.streamChunkByteLength,
    );
    return {
        checkpointLineageIdentifier: lineageHex,
        newChunkRecordKeys: decodeRecordKeys(
            value.newChunkRecordKeys,
            `checkpoint/chunk/${lineageHex}/${publicationIdentifier}/`,
            maximumChunkCount,
            'newChunkRecordKeys',
        ),
        obsoleteChunkRecordKeys: decodeRecordKeys(
            value.obsoleteChunkRecordKeys,
            `checkpoint/chunk/${lineageHex}/`,
            maximumChunkCount,
            'obsoleteChunkRecordKeys',
        ),
        publicationIdentifier,
        recordVersion: checkpointRecordVersion,
    };
};

const closeTransactionAfterFailure = async (
    transaction: UntrustedStorageTransaction,
    operationFailure: unknown,
): Promise<AuthenticatedRuntimeRecordError> => {
    const mappedOperationFailure = mapStorageError(operationFailure);
    try {
        await transaction.closeAfterFailure();
    } catch (closeFailure) {
        throw new AuthenticatedRuntimeRecordError(
            'CleanupFailed',
            'A checkpoint transaction failed and could not release its transaction ownership.',
            [mappedOperationFailure, mapStorageError(closeFailure)],
        );
    }
    return mappedOperationFailure;
};

const deleteAuthenticatedRecord = async (input: {
    logicalRecordKey: string;
    operationDomain: string;
    protection: ReturnType<typeof createRuntimeRecordProtection>;
    store: UntrustedStorageTransactionStore;
    transactionLifetimeMilliseconds: number;
}): Promise<void> => {
    const opened = await readRuntimeRecord({
        logicalRecordKey: input.logicalRecordKey,
        operationDomain: input.operationDomain,
        protection: input.protection,
        store: input.store,
    });
    if (opened === undefined) {
        return;
    }
    opened.plaintext.fill(0);
    const transaction = await input.store.beginTransaction({
        lifetimeMilliseconds: input.transactionLifetimeMilliseconds,
    });
    try {
        await transaction.stageDeletion(
            input.logicalRecordKey,
            opened.sealedBytes,
        );
        await transaction.commit();
    } catch (error) {
        throw await closeTransactionAfterFailure(transaction, error);
    }
};

const deleteJournalOwnedChunkRecord = async (input: {
    logicalRecordKey: string;
    store: UntrustedStorageTransactionStore;
    transactionLifetimeMilliseconds: number;
}): Promise<void> => {
    const transaction = await input.store.beginTransaction({
        lifetimeMilliseconds: input.transactionLifetimeMilliseconds,
    });
    try {
        await transaction.stageDeletion(input.logicalRecordKey);
        await transaction.commit();
    } catch (error) {
        throw await closeTransactionAfterFailure(transaction, error);
    }
};

const asAsyncIterable = async function* (
    source: AsyncIterable<Uint8Array> | Iterable<Uint8Array>,
): AsyncGenerator<Uint8Array> {
    if (Symbol.asyncIterator in source) {
        for await (const value of source) {
            yield value;
        }
        return;
    }
    for (const value of source) {
        yield value;
    }
};

const checkpointLineageOperationTails = new WeakMap<
    UntrustedStorageTransactionStore,
    Map<string, Promise<void>>
>();

const runCheckpointLineageExclusive = async <Result>(
    store: UntrustedStorageTransactionStore,
    checkpointLineageIdentifier: Uint8Array,
    operation: () => Promise<Result>,
): Promise<Result> => {
    let operationTails = checkpointLineageOperationTails.get(store);
    if (operationTails === undefined) {
        operationTails = new Map<string, Promise<void>>();
        checkpointLineageOperationTails.set(store, operationTails);
    }
    const lineageKey = bytesToHex(checkpointLineageIdentifier);
    const previousOperation = operationTails.get(lineageKey);
    let releaseOperation: (() => void) | undefined;
    const currentOperation = new Promise<void>((resolve) => {
        releaseOperation = resolve;
    });
    operationTails.set(lineageKey, currentOperation);
    if (previousOperation !== undefined) {
        await previousOperation;
    }
    try {
        return await operation();
    } finally {
        releaseOperation?.();
        if (operationTails.get(lineageKey) === currentOperation) {
            operationTails.delete(lineageKey);
        }
    }
};

export const openAuthenticatedCheckpointStore = (input: {
    authorityContext: RuntimeStorageAuthorityContext;
    boundaryPolicy: CheckpointBoundaryPolicy;
    cryptoProvider?: Crypto;
    cursorKernel: CheckpointRandomCursorKernel;
    encryptionKey: CryptoKey;
    limits: AuthenticatedCheckpointStoreLimits;
    store: UntrustedStorageTransactionStore;
}): AuthenticatedCheckpointStore => {
    for (const [value, label] of [
        [
            input.limits.maximumCheckpointStateByteLength,
            'maximumCheckpointStateByteLength',
        ],
        [input.limits.maximumManifestByteLength, 'maximumManifestByteLength'],
        [input.limits.maximumRandomCursorCount, 'maximumRandomCursorCount'],
        [input.limits.maximumRecordSealingCount, 'maximumRecordSealingCount'],
        [input.limits.maximumSourceDigestCount, 'maximumSourceDigestCount'],
        [input.limits.maximumStreamAttemptCount, 'maximumStreamAttemptCount'],
        [
            input.limits.transactionLifetimeMilliseconds,
            'transactionLifetimeMilliseconds',
        ],
    ] as const) {
        requireSafePositiveInteger(value, label);
    }
    if (input.limits.maximumRecordSealingCount > 0x1_0000_0000) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidConfiguration',
            'maximumRecordSealingCount exceeds the AES-GCM random-nonce invocation ceiling.',
        );
    }
    if (
        input.limits.maximumCheckpointStateByteLength >
        foundationProfile.maximumCanonicalStreamByteLength
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidConfiguration',
            'maximumCheckpointStateByteLength exceeds the canonical stream profile.',
        );
    }
    const limits = Object.freeze({ ...input.limits });
    const protection = createRuntimeRecordProtection({
        authorityContext: input.authorityContext,
        cryptoProvider: input.cryptoProvider,
        encryptionKey: input.encryptionKey,
        maximumRecordSealingCount: limits.maximumRecordSealingCount,
    });
    const issuedIdentifiers = new Set<string>();
    const operationIdentities = new WeakMap<
        CheckpointOperationIdentity,
        CheckpointOperationIdentityRecord
    >();

    const createOperationIdentity = (
        checkpointLineageIdentifier: Uint8Array,
        streamAttemptIdentifiers: readonly Uint8Array[],
        resumedPublication?: Readonly<{
            boundary: CheckpointBoundary;
            canonicalManifestBytes: Uint8Array;
        }>,
    ): CheckpointOperationIdentity => {
        const lineageIdentifier = checkpointLineageIdentifier.slice();
        const attemptIdentifiers = streamAttemptIdentifiers.map((identifier) =>
            identifier.slice(),
        );
        const identity = Object.freeze({
            [checkpointOperationIdentityBrand]: true as const,
            get checkpointLineageIdentifier(): Uint8Array {
                return lineageIdentifier.slice();
            },
            get streamAttemptIdentifiers(): readonly Uint8Array[] {
                return Object.freeze(
                    attemptIdentifiers.map((identifier) => identifier.slice()),
                );
            },
        });
        operationIdentities.set(identity, {
            checkpointLineageIdentifier: lineageIdentifier,
            ...(resumedPublication === undefined
                ? {}
                : {
                      lastCanonicalManifestBytes:
                          resumedPublication.canonicalManifestBytes.slice(),
                      lastPublishedBoundary: copyAndValidateBoundary(
                          resumedPublication.boundary,
                          limits,
                      ),
                      operationKind: resumedPublication.boundary.operationKind,
                      orderedSourceDigestHex:
                          resumedPublication.boundary.orderedSourceDigests.map(
                              bytesToHex,
                          ),
                      stateStreamDomain:
                          resumedPublication.boundary.stateStreamDomain,
                  }),
            streamAttemptIdentifiers: Object.freeze(attemptIdentifiers),
        });
        return identity;
    };

    const runBoundaryPolicy = async (
        operation: 'publish' | 'resume',
        checkpointLineageIdentifier: Uint8Array,
        boundary: CheckpointBoundary | ExpectedCheckpointBoundary,
        previousBoundary?: CheckpointBoundary,
    ): Promise<void> => {
        try {
            if (operation === 'publish') {
                await input.boundaryPolicy.validatePublication({
                    boundary: copyAndValidateBoundary(
                        boundary as CheckpointBoundary,
                        limits,
                    ),
                    checkpointLineageIdentifier:
                        checkpointLineageIdentifier.slice(),
                    ...(previousBoundary === undefined
                        ? {}
                        : {
                              previousBoundary: copyAndValidateBoundary(
                                  previousBoundary,
                                  limits,
                              ),
                          }),
                });
                return;
            }
            await input.boundaryPolicy.validateResume({
                checkpointLineageIdentifier:
                    checkpointLineageIdentifier.slice(),
                expectedBoundary: copyAndValidateBoundary(boundary, limits),
            });
        } catch (error) {
            if (error instanceof AuthenticatedRuntimeRecordError) {
                throw error;
            }
            throw new AuthenticatedRuntimeRecordError(
                'InvalidInput',
                'The operation owner refused the checkpoint boundary.',
                error,
            );
        }
    };

    const requireMonotonicPublicationBoundary = (
        identityRecord: CheckpointOperationIdentityRecord,
        boundary: CheckpointBoundary,
        canonicalManifestBytes: Uint8Array,
    ): void => {
        const sourceDigestHex = boundary.orderedSourceDigests.map(bytesToHex);
        if (identityRecord.operationKind === undefined) {
            identityRecord.operationKind = boundary.operationKind;
            identityRecord.orderedSourceDigestHex = sourceDigestHex;
            identityRecord.stateStreamDomain = boundary.stateStreamDomain;
        } else if (
            identityRecord.operationKind !== boundary.operationKind ||
            identityRecord.stateStreamDomain !== boundary.stateStreamDomain ||
            identityRecord.orderedSourceDigestHex?.length !==
                sourceDigestHex.length ||
            identityRecord.orderedSourceDigestHex.some(
                (digest, digestIndex) =>
                    digest !== sourceDigestHex[digestIndex],
            )
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'Conflict',
                'Checkpoint replacement cannot change its operation or verified source identity.',
            );
        }
        const previousBoundary = identityRecord.lastPublishedBoundary;
        if (previousBoundary === undefined) {
            return;
        }
        if (
            boundary.safeBoundaryOrdinal < previousBoundary.safeBoundaryOrdinal
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'Conflict',
                'Checkpoint replacement cannot rewind its safe boundary.',
            );
        }
        if (
            boundary.safeBoundaryOrdinal ===
            previousBoundary.safeBoundaryOrdinal
        ) {
            if (
                identityRecord.lastCanonicalManifestBytes === undefined ||
                !bytesEqual(
                    canonicalManifestBytes,
                    identityRecord.lastCanonicalManifestBytes,
                )
            ) {
                throw new AuthenticatedRuntimeRecordError(
                    'Conflict',
                    'A checkpoint safe boundary can only be republished byte-identically.',
                );
            }
            return;
        }
        const previousCursorsByKey = new Map(
            previousBoundary.orderedRandomCursors.map((cursor) => [
                [
                    cursor.family,
                    cursor.purpose,
                    bytesToHex(cursor.derivationContextHash),
                    bytesToHex(cursor.streamAttemptIdentifier),
                ].join('/'),
                cursor,
            ]),
        );
        for (const cursor of boundary.orderedRandomCursors) {
            const previousCursor = previousCursorsByKey.get(
                [
                    cursor.family,
                    cursor.purpose,
                    bytesToHex(cursor.derivationContextHash),
                    bytesToHex(cursor.streamAttemptIdentifier),
                ].join('/'),
            );
            if (previousCursor === undefined) {
                continue;
            }
            const counterRewound =
                cursor.nextCounter < previousCursor.nextCounter;
            const positionRewoundAtSameCounter =
                cursor.nextCounter === previousCursor.nextCounter &&
                ((previousCursor.nextUnreadBitOffsetInBufferedBlock ===
                    undefined &&
                    cursor.nextUnreadBitOffsetInBufferedBlock !== undefined) ||
                    (previousCursor.nextUnreadBitOffsetInBufferedBlock !==
                        undefined &&
                        cursor.nextUnreadBitOffsetInBufferedBlock !==
                            undefined &&
                        cursor.nextUnreadBitOffsetInBufferedBlock <
                            previousCursor.nextUnreadBitOffsetInBufferedBlock));
            if (counterRewound || positionRewoundAtSameCounter) {
                throw new AuthenticatedRuntimeRecordError(
                    'Conflict',
                    'Checkpoint replacement cannot rewind a private-randomness cursor.',
                );
            }
        }
    };

    const readManifest = async (lineageIdentifier: Uint8Array) => {
        const logicalRecordKey = manifestRecordKey(lineageIdentifier);
        const opened = await readRuntimeRecord({
            logicalRecordKey,
            operationDomain: checkpointManifestOperationDomain,
            protection,
            store: input.store,
        });
        if (opened === undefined) {
            return undefined;
        }
        try {
            return {
                opened,
                record: decodeStoredManifest(
                    opened.plaintext,
                    limits,
                    lineageIdentifier,
                ),
            };
        } catch (error) {
            opened.plaintext.fill(0);
            throw error;
        }
    };

    const readJournal = async (lineageIdentifier: Uint8Array) => {
        const logicalRecordKey = journalRecordKey(lineageIdentifier);
        const opened = await readRuntimeRecord({
            logicalRecordKey,
            operationDomain: checkpointJournalOperationDomain,
            protection,
            store: input.store,
        });
        if (opened === undefined) {
            return undefined;
        }
        try {
            return {
                opened,
                record: decodeStoredJournal(
                    opened.plaintext,
                    limits,
                    lineageIdentifier,
                ),
            };
        } catch (error) {
            opened.plaintext.fill(0);
            throw error;
        }
    };

    const repairInterruptedPublicationUnlocked = async (
        lineageIdentifier: Uint8Array,
    ): Promise<void> => {
        const journal = await readJournal(lineageIdentifier);
        if (journal === undefined) {
            return;
        }
        const manifest = await readManifest(lineageIdentifier);
        const publicationIsActive =
            manifest?.record.publicationIdentifier ===
            journal.record.publicationIdentifier;
        const chunkKeysToDelete = publicationIsActive
            ? journal.record.obsoleteChunkRecordKeys
            : journal.record.newChunkRecordKeys;
        journal.opened.plaintext.fill(0);
        manifest?.opened.plaintext.fill(0);
        for (const logicalRecordKey of chunkKeysToDelete) {
            await deleteJournalOwnedChunkRecord({
                logicalRecordKey,
                store: input.store,
                transactionLifetimeMilliseconds:
                    limits.transactionLifetimeMilliseconds,
            });
        }
        await deleteAuthenticatedRecord({
            logicalRecordKey: journalRecordKey(lineageIdentifier),
            operationDomain: checkpointJournalOperationDomain,
            protection,
            store: input.store,
            transactionLifetimeMilliseconds:
                limits.transactionLifetimeMilliseconds,
        });
    };

    const repair: AuthenticatedCheckpointStore['repair'] = async (
        checkpointLineageIdentifier,
    ) => {
        const lineageIdentifier = copyExactBytes(
            checkpointLineageIdentifier,
            identifierByteLength,
            'checkpointLineageIdentifier',
        );
        await runCheckpointLineageExclusive(
            input.store,
            lineageIdentifier,
            () => repairInterruptedPublicationUnlocked(lineageIdentifier),
        );
    };

    const beginOperation: AuthenticatedCheckpointStore['beginOperation'] =
        async (untrustedStreamAttemptIdentifiers) => {
            if (!Array.isArray(untrustedStreamAttemptIdentifiers)) {
                throw new AuthenticatedRuntimeRecordError(
                    'InvalidInput',
                    'Checkpoint stream-attempt identifiers must be an array.',
                );
            }
            if (
                untrustedStreamAttemptIdentifiers.length >
                limits.maximumStreamAttemptCount
            ) {
                throw new AuthenticatedRuntimeRecordError(
                    'ResourceLimit',
                    'Checkpoint stream-attempt count exceeds the configured profile.',
                );
            }
            const streamAttemptIdentifiers =
                untrustedStreamAttemptIdentifiers.map(
                    (identifier, identifierIndex) =>
                        copyExactBytes(
                            identifier,
                            identifierByteLength,
                            `streamAttemptIdentifiers[${String(identifierIndex)}]`,
                        ),
                );
            if (
                new Set(streamAttemptIdentifiers.map(bytesToHex)).size !==
                streamAttemptIdentifiers.length
            ) {
                for (const identifier of streamAttemptIdentifiers) {
                    identifier.fill(0);
                }
                throw new AuthenticatedRuntimeRecordError(
                    'InvalidInput',
                    'Checkpoint stream-attempt identifiers must be distinct.',
                );
            }
            const checkpointLineageIdentifier = sampleRuntimeIdentifier(
                protection,
                issuedIdentifiers,
                'checkpoint lineage identifier',
            );
            await runCheckpointLineageExclusive(
                input.store,
                checkpointLineageIdentifier,
                async () => {
                    const collidingManifest = await readManifest(
                        checkpointLineageIdentifier,
                    );
                    const collidingJournal = await readJournal(
                        checkpointLineageIdentifier,
                    );
                    collidingManifest?.opened.plaintext.fill(0);
                    collidingJournal?.opened.plaintext.fill(0);
                    if (
                        collidingManifest !== undefined ||
                        collidingJournal !== undefined
                    ) {
                        throw new AuthenticatedRuntimeRecordError(
                            'EntropyFailure',
                            'Checkpoint lineage identifier collides with retained storage.',
                        );
                    }
                },
            );
            return createOperationIdentity(
                checkpointLineageIdentifier,
                streamAttemptIdentifiers,
            );
        };

    const publishUnlocked: AuthenticatedCheckpointStore['publish'] = async ({
        boundary: untrustedBoundary,
        identity,
        stateChunks,
    }) => {
        const boundary = copyAndValidateBoundary(untrustedBoundary, limits);
        const issuedIdentity = operationIdentities.get(identity);
        if (issuedIdentity === undefined) {
            throw new AuthenticatedRuntimeRecordError(
                'InvalidInput',
                'Checkpoint publication requires an operation identity issued by this authenticated store.',
            );
        }
        const lineageIdentifier =
            issuedIdentity.checkpointLineageIdentifier.slice();
        if (
            issuedIdentity.streamAttemptIdentifiers.length >
            limits.maximumStreamAttemptCount
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'InvalidInput',
                'Checkpoint operation identity has an invalid stream-attempt count.',
            );
        }
        const expectedAttemptIdentifiers =
            issuedIdentity.streamAttemptIdentifiers.map(
                (identifier, identifierIndex) =>
                    copyExactBytes(
                        identifier,
                        identifierByteLength,
                        `streamAttemptIdentifiers[${identifierIndex}]`,
                    ),
            );
        const expectedAttemptIdentifierKeys = new Set(
            expectedAttemptIdentifiers.map(bytesToHex),
        );
        if (
            expectedAttemptIdentifierKeys.size !==
            expectedAttemptIdentifiers.length
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'InvalidInput',
                'Checkpoint operation identity contains a reused stream-attempt identifier.',
            );
        }
        const observedAttemptIdentifiersByKey = new Map<string, Uint8Array>();
        for (const cursor of boundary.orderedRandomCursors) {
            observedAttemptIdentifiersByKey.set(
                bytesToHex(cursor.streamAttemptIdentifier),
                cursor.streamAttemptIdentifier,
            );
        }
        const observedAttemptIdentifiers = [
            ...observedAttemptIdentifiersByKey.values(),
        ];
        if (
            observedAttemptIdentifiers.length !==
                expectedAttemptIdentifiers.length ||
            observedAttemptIdentifiers.some(
                (identifier) =>
                    !expectedAttemptIdentifierKeys.has(bytesToHex(identifier)),
            )
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'InvalidInput',
                'Checkpoint cursor attempts were not issued for this operation.',
            );
        }
        await repairInterruptedPublicationUnlocked(lineageIdentifier);
        const descriptor = parseStreamDescriptor(
            boundary.stateStreamDescriptorBytes,
            limits,
        );
        const previousManifest = await readManifest(lineageIdentifier);
        previousManifest?.opened.plaintext.fill(0);
        const previousCanonicalManifestBytes =
            previousManifest === undefined
                ? undefined
                : decodeCanonicalHex(
                      previousManifest.record.canonicalManifest,
                      limits.maximumManifestByteLength,
                      'canonicalManifest',
                  );
        if (
            (issuedIdentity.lastCanonicalManifestBytes === undefined) !==
                (previousCanonicalManifestBytes === undefined) ||
            (issuedIdentity.lastCanonicalManifestBytes !== undefined &&
                previousCanonicalManifestBytes !== undefined &&
                !bytesEqual(
                    issuedIdentity.lastCanonicalManifestBytes,
                    previousCanonicalManifestBytes,
                ))
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'Conflict',
                'Checkpoint operation identity is stale for the current lineage manifest.',
            );
        }
        const canonicalManifestBytes = encodeCheckpointManifest({
            authorityContext: protection.authorityContext,
            boundary,
            checkpointLineageIdentifier: lineageIdentifier,
            cursorKernel: input.cursorKernel,
            stateStreamDescriptorBytes: boundary.stateStreamDescriptorBytes,
        });
        if (
            canonicalManifestBytes.byteLength > limits.maximumManifestByteLength
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'ResourceLimit',
                'Canonical checkpoint manifest exceeds the configured profile.',
            );
        }
        await runBoundaryPolicy(
            'publish',
            lineageIdentifier,
            boundary,
            issuedIdentity.lastPublishedBoundary,
        );
        requireMonotonicPublicationBoundary(
            issuedIdentity,
            boundary,
            canonicalManifestBytes,
        );
        const publicationIdentifier = sampleRuntimeIdentifier(
            protection,
            issuedIdentifiers,
            'checkpoint publication identifier',
        );
        const newChunkRecordKeys = descriptor.orderedChunkDigests.map(
            (chunkDigest, chunkIndex) =>
                chunkRecordKey({
                    checkpointLineageIdentifier: lineageIdentifier,
                    chunkDigest,
                    chunkIndex,
                    publicationIdentifier,
                }),
        );
        const journalRecord: StoredCheckpointJournal = {
            checkpointLineageIdentifier: bytesToHex(lineageIdentifier),
            newChunkRecordKeys,
            obsoleteChunkRecordKeys:
                previousManifest?.record.chunkRecordKeys ?? [],
            publicationIdentifier: bytesToHex(publicationIdentifier),
            recordVersion: checkpointRecordVersion,
        };
        const journalPlaintext = encodeCanonicalJson(journalRecord);
        const journalTransaction = await input.store.beginTransaction({
            lifetimeMilliseconds: limits.transactionLifetimeMilliseconds,
        });
        try {
            await stageRuntimeRecordWrite({
                expectedCurrentSealedBytes: null,
                logicalRecordKey: journalRecordKey(lineageIdentifier),
                operationDomain: checkpointJournalOperationDomain,
                plaintext: journalPlaintext,
                protection,
                transaction: journalTransaction,
            });
            await journalTransaction.commit();
        } catch (error) {
            throw await closeTransactionAfterFailure(journalTransaction, error);
        } finally {
            journalPlaintext.fill(0);
        }

        const fullObjectDigestHasher = createFullObjectDigestHasher({
            stateStreamDomain: boundary.stateStreamDomain,
            totalByteLength: descriptor.totalByteLength,
        });
        let observedChunkCount = 0;
        try {
            for await (const untrustedChunk of asAsyncIterable(stateChunks)) {
                if (
                    observedChunkCount >= descriptor.orderedChunkDigests.length
                ) {
                    throw new AuthenticatedRuntimeRecordError(
                        'InvalidInput',
                        'Checkpoint state contains a trailing chunk.',
                    );
                }
                const chunkBytes = copyBoundedBytes(
                    untrustedChunk,
                    foundationProfile.streamChunkByteLength,
                    `stateChunks[${observedChunkCount}]`,
                );
                const expectedByteLength = expectedChunkByteLength(
                    descriptor,
                    observedChunkCount,
                );
                const observedDigest = deriveChunkDigest({
                    chunkBytes,
                    chunkIndex: observedChunkCount,
                    stateStreamDomain: boundary.stateStreamDomain,
                });
                if (
                    chunkBytes.byteLength !== expectedByteLength ||
                    !bytesEqual(
                        observedDigest,
                        descriptor.orderedChunkDigests[observedChunkCount],
                    )
                ) {
                    chunkBytes.fill(0);
                    throw new AuthenticatedRuntimeRecordError(
                        'AuthenticationFailed',
                        'Checkpoint state chunk does not match its canonical descriptor.',
                    );
                }
                fullObjectDigestHasher.update(chunkBytes);
                const chunkTransaction = await input.store.beginTransaction({
                    lifetimeMilliseconds:
                        limits.transactionLifetimeMilliseconds,
                });
                try {
                    await stageRuntimeRecordWrite({
                        expectedCurrentSealedBytes: null,
                        logicalRecordKey:
                            newChunkRecordKeys[observedChunkCount],
                        operationDomain: checkpointChunkOperationDomain,
                        plaintext: chunkBytes,
                        protection,
                        transaction: chunkTransaction,
                    });
                    await chunkTransaction.commit();
                } catch (error) {
                    throw await closeTransactionAfterFailure(
                        chunkTransaction,
                        error,
                    );
                } finally {
                    chunkBytes.fill(0);
                }
                observedChunkCount += 1;
            }
            if (observedChunkCount !== descriptor.orderedChunkDigests.length) {
                throw new AuthenticatedRuntimeRecordError(
                    'AuthenticationFailed',
                    'Checkpoint state is incomplete.',
                );
            }
            authenticateFullObjectDigest(
                fullObjectDigestHasher,
                descriptor.fullObjectDigest,
            );
        } finally {
            fullObjectDigestHasher.destroy();
        }

        const storedManifest: StoredCheckpointManifest = {
            canonicalManifest: bytesToHex(canonicalManifestBytes),
            publicationIdentifier: bytesToHex(publicationIdentifier),
            recordVersion: checkpointRecordVersion,
        };
        const manifestPlaintext = encodeCanonicalJson(storedManifest);
        const manifestTransaction = await input.store.beginTransaction({
            lifetimeMilliseconds: limits.transactionLifetimeMilliseconds,
        });
        try {
            await stageRuntimeRecordWrite({
                expectedCurrentSealedBytes:
                    previousManifest?.opened.sealedBytes ?? null,
                logicalRecordKey: manifestRecordKey(lineageIdentifier),
                operationDomain: checkpointManifestOperationDomain,
                plaintext: manifestPlaintext,
                protection,
                transaction: manifestTransaction,
            });
            await manifestTransaction.commit();
            issuedIdentity.lastCanonicalManifestBytes =
                canonicalManifestBytes.slice();
            issuedIdentity.lastPublishedBoundary = copyAndValidateBoundary(
                boundary,
                limits,
            );
        } catch (error) {
            const mappedFailure = await closeTransactionAfterFailure(
                manifestTransaction,
                error,
            );
            const observedManifest = await readManifest(lineageIdentifier);
            if (
                observedManifest?.record.publicationIdentifier ===
                    storedManifest.publicationIdentifier &&
                observedManifest.record.canonicalManifest ===
                    storedManifest.canonicalManifest
            ) {
                issuedIdentity.lastCanonicalManifestBytes =
                    canonicalManifestBytes.slice();
                issuedIdentity.lastPublishedBoundary = copyAndValidateBoundary(
                    boundary,
                    limits,
                );
            }
            observedManifest?.opened.plaintext.fill(0);
            throw mappedFailure;
        } finally {
            manifestPlaintext.fill(0);
        }
        await repairInterruptedPublicationUnlocked(lineageIdentifier);
        return canonicalManifestBytes.slice();
    };

    const publish: AuthenticatedCheckpointStore['publish'] = async (
        publication,
    ) => {
        const identity = publication.identity;
        const issuedIdentity = operationIdentities.get(identity);
        if (issuedIdentity === undefined) {
            throw new AuthenticatedRuntimeRecordError(
                'InvalidInput',
                'Checkpoint publication requires an operation identity issued by this authenticated store.',
            );
        }
        const lineageIdentifier =
            issuedIdentity.checkpointLineageIdentifier.slice();
        const normalizedPublication = Object.freeze({
            boundary: copyAndValidateBoundary(publication.boundary, limits),
            identity,
            stateChunks: publication.stateChunks,
        });
        return runCheckpointLineageExclusive(
            input.store,
            lineageIdentifier,
            () => publishUnlocked(normalizedPublication),
        );
    };

    const resumeUnlocked: AuthenticatedCheckpointStore['resume'] = async ({
        checkpointLineageIdentifier,
        expectedBoundary: untrustedExpectedBoundary,
    }) => {
        const lineageIdentifier = copyExactBytes(
            checkpointLineageIdentifier,
            identifierByteLength,
            'checkpointLineageIdentifier',
        );
        await repairInterruptedPublicationUnlocked(lineageIdentifier);
        const expectedBoundary = copyAndValidateBoundary(
            untrustedExpectedBoundary,
            limits,
        );
        await runBoundaryPolicy('resume', lineageIdentifier, expectedBoundary);
        const manifest = await readManifest(lineageIdentifier);
        if (manifest === undefined) {
            throw new AuthenticatedRuntimeRecordError(
                'MissingRecord',
                'No authenticated checkpoint exists for this lineage.',
            );
        }
        const descriptorBytes =
            manifest.record.stateStreamDescriptorBytes.slice();
        const descriptor = parseStreamDescriptor(descriptorBytes, limits);
        const expectedCanonicalManifest = encodeCheckpointManifest({
            authorityContext: protection.authorityContext,
            boundary: expectedBoundary,
            checkpointLineageIdentifier: lineageIdentifier,
            cursorKernel: input.cursorKernel,
            stateStreamDescriptorBytes: descriptorBytes,
        });
        const storedCanonicalManifest = decodeCanonicalHex(
            manifest.record.canonicalManifest,
            limits.maximumManifestByteLength,
            'canonicalManifest',
        );
        manifest.opened.plaintext.fill(0);
        if (!bytesEqual(storedCanonicalManifest, expectedCanonicalManifest)) {
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                'Checkpoint manifest does not match the exact resume boundary.',
            );
        }
        const manifestSealedBytes = manifest.opened.sealedBytes.slice();
        const chunkRecordKeys = [...manifest.record.chunkRecordKeys];
        const resumedAttemptIdentifiersByHex = new Map<string, Uint8Array>();
        for (const cursor of expectedBoundary.orderedRandomCursors) {
            resumedAttemptIdentifiersByHex.set(
                bytesToHex(cursor.streamAttemptIdentifier),
                cursor.streamAttemptIdentifier,
            );
        }
        const resumedAttemptIdentifiers = [
            ...resumedAttemptIdentifiersByHex.values(),
        ];
        issuedIdentifiers.add(bytesToHex(lineageIdentifier));
        for (const identifier of resumedAttemptIdentifiers) {
            issuedIdentifiers.add(bytesToHex(identifier));
        }
        return Object.freeze({
            canonicalManifestBytes: storedCanonicalManifest.slice(),
            operationIdentity: createOperationIdentity(
                lineageIdentifier,
                resumedAttemptIdentifiers,
                {
                    boundary: {
                        ...expectedBoundary,
                        stateStreamDescriptorBytes: descriptorBytes,
                    },
                    canonicalManifestBytes: storedCanonicalManifest,
                },
            ),
            stateStreamDescriptorBytes: descriptorBytes.slice(),
            restoreState: async (consumeChunk) =>
                runCheckpointLineageExclusive(
                    input.store,
                    lineageIdentifier,
                    async () => {
                        const currentManifest =
                            await readManifest(lineageIdentifier);
                        if (currentManifest === undefined) {
                            throw new AuthenticatedRuntimeRecordError(
                                'MissingRecord',
                                'The checkpoint was evicted before state restoration.',
                            );
                        }
                        const manifestIsCurrent = bytesEqual(
                            currentManifest.opened.sealedBytes,
                            manifestSealedBytes,
                        );
                        currentManifest.opened.plaintext.fill(0);
                        if (!manifestIsCurrent) {
                            throw new AuthenticatedRuntimeRecordError(
                                'Conflict',
                                'The checkpoint changed before state restoration.',
                            );
                        }
                        const fullObjectDigestHasher =
                            createFullObjectDigestHasher({
                                stateStreamDomain:
                                    expectedBoundary.stateStreamDomain,
                                totalByteLength: descriptor.totalByteLength,
                            });
                        try {
                            for (
                                let chunkIndex = 0;
                                chunkIndex < chunkRecordKeys.length;
                                chunkIndex += 1
                            ) {
                                const openedChunk = await readRuntimeRecord({
                                    logicalRecordKey:
                                        chunkRecordKeys[chunkIndex],
                                    operationDomain:
                                        checkpointChunkOperationDomain,
                                    protection,
                                    store: input.store,
                                });
                                if (openedChunk === undefined) {
                                    throw new AuthenticatedRuntimeRecordError(
                                        'MissingRecord',
                                        'An authenticated checkpoint state chunk is missing.',
                                    );
                                }
                                const chunkBytes = openedChunk.plaintext;
                                const observedDigest = deriveChunkDigest({
                                    chunkBytes,
                                    chunkIndex,
                                    stateStreamDomain:
                                        expectedBoundary.stateStreamDomain,
                                });
                                if (
                                    chunkBytes.byteLength !==
                                        expectedChunkByteLength(
                                            descriptor,
                                            chunkIndex,
                                        ) ||
                                    !bytesEqual(
                                        observedDigest,
                                        descriptor.orderedChunkDigests[
                                            chunkIndex
                                        ],
                                    )
                                ) {
                                    chunkBytes.fill(0);
                                    throw new AuthenticatedRuntimeRecordError(
                                        'AuthenticationFailed',
                                        'Checkpoint state chunk failed descriptor authentication.',
                                    );
                                }
                                fullObjectDigestHasher.update(chunkBytes);
                                try {
                                    await consumeChunk(
                                        chunkIndex,
                                        chunkBytes.slice(),
                                    );
                                } finally {
                                    chunkBytes.fill(0);
                                }
                            }
                            authenticateFullObjectDigest(
                                fullObjectDigestHasher,
                                descriptor.fullObjectDigest,
                            );
                        } finally {
                            fullObjectDigestHasher.destroy();
                        }
                    },
                ),
        });
    };

    const resume: AuthenticatedCheckpointStore['resume'] = async (
        resumeInput,
    ) => {
        const lineageIdentifier = copyExactBytes(
            resumeInput.checkpointLineageIdentifier,
            identifierByteLength,
            'checkpointLineageIdentifier',
        );
        const normalizedResumeInput = Object.freeze({
            checkpointLineageIdentifier: lineageIdentifier,
            expectedBoundary: copyAndValidateBoundary(
                resumeInput.expectedBoundary,
                limits,
            ),
        });
        return runCheckpointLineageExclusive(
            input.store,
            lineageIdentifier,
            () => resumeUnlocked(normalizedResumeInput),
        );
    };

    const evictUnlocked: AuthenticatedCheckpointStore['evict'] = async (
        checkpointLineageIdentifier,
    ) => {
        const lineageIdentifier = copyExactBytes(
            checkpointLineageIdentifier,
            identifierByteLength,
            'checkpointLineageIdentifier',
        );
        await repairInterruptedPublicationUnlocked(lineageIdentifier);
        const manifest = await readManifest(lineageIdentifier);
        if (manifest === undefined) {
            return;
        }
        manifest.opened.plaintext.fill(0);
        const journalRecord: StoredCheckpointJournal = {
            checkpointLineageIdentifier: bytesToHex(lineageIdentifier),
            newChunkRecordKeys: manifest.record.chunkRecordKeys,
            obsoleteChunkRecordKeys: [],
            publicationIdentifier: manifest.record.publicationIdentifier,
            recordVersion: checkpointRecordVersion,
        };
        const journalPlaintext = encodeCanonicalJson(journalRecord);
        const journalTransaction = await input.store.beginTransaction({
            lifetimeMilliseconds: limits.transactionLifetimeMilliseconds,
        });
        try {
            await stageRuntimeRecordWrite({
                expectedCurrentSealedBytes: null,
                logicalRecordKey: journalRecordKey(lineageIdentifier),
                operationDomain: checkpointJournalOperationDomain,
                plaintext: journalPlaintext,
                protection,
                transaction: journalTransaction,
            });
            await journalTransaction.commit();
        } catch (error) {
            throw await closeTransactionAfterFailure(journalTransaction, error);
        } finally {
            journalPlaintext.fill(0);
        }
        await deleteAuthenticatedRecord({
            logicalRecordKey: manifestRecordKey(lineageIdentifier),
            operationDomain: checkpointManifestOperationDomain,
            protection,
            store: input.store,
            transactionLifetimeMilliseconds:
                limits.transactionLifetimeMilliseconds,
        });
        await repairInterruptedPublicationUnlocked(lineageIdentifier);
    };

    const evict: AuthenticatedCheckpointStore['evict'] = async (
        checkpointLineageIdentifier,
    ) => {
        const lineageIdentifier = copyExactBytes(
            checkpointLineageIdentifier,
            identifierByteLength,
            'checkpointLineageIdentifier',
        );
        await runCheckpointLineageExclusive(
            input.store,
            lineageIdentifier,
            () => evictUnlocked(lineageIdentifier),
        );
    };

    return Object.freeze({
        beginOperation,
        copyAuthorityContext: () =>
            copyRuntimeStorageAuthorityContext(protection.authorityContext),
        evict,
        publish,
        repair,
        resume,
    });
};

export { AuthenticatedRuntimeRecordError as AuthenticatedCheckpointStoreError };
export type { AuthenticatedRuntimeRecordErrorCode as AuthenticatedCheckpointStoreErrorCode };
