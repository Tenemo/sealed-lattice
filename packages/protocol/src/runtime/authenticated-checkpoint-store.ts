import { hash512Hex } from '@sealed-lattice/crypto';

import {
    UntrustedStorageTransactionError,
    type UntrustedStorageTransaction,
    type UntrustedStorageTransactionStore,
} from './untrusted-storage-transaction-store.js';

const textEncoder = new TextEncoder();
const fatalTextDecoder = new TextDecoder('utf-8', { fatal: true });
const checkpointIdentifierPattern = /^[A-Za-z0-9_-]{16,128}$/u;
const checkpointRecordMagic = new Uint8Array([0x53, 0x4c, 0x43, 0x50]);
const checkpointRecordVersion = 1;
const manifestRecordKind = 1;
const interruptedPublicationRecordKind = 2;
const attemptIdentifierByteLength = 32;
const bindingDigestByteLength = 64;
const digestByteLength = 64;
const maximumSupportedCheckpointChunkCount = 4_096;
const maximumSupportedCheckpointChunkByteLength = 1_048_576;
const maximumSupportedCheckpointByteLength = 2_147_483_648;
const maximumSupportedSealedRecordByteLength = 1_572_864;
const fixedStorageManifestByteLength =
    checkpointRecordMagic.byteLength +
    1 +
    1 +
    2 +
    attemptIdentifierByteLength +
    bindingDigestByteLength +
    4 +
    4 +
    digestByteLength;
const chunkDescriptorByteLength = 4 + digestByteLength;
const stateChunkDigestDomain =
    'sealed-lattice/runtime/checkpoint-state-chunk/v1';
const orderedStateDigestDomain =
    'sealed-lattice/runtime/checkpoint-state-descriptor/v1';
const checkpointExclusiveLockNamePrefix =
    'sealed-lattice-authenticated-checkpoint-';

type AuthenticatedCheckpointErrorCode =
    | 'AuthenticationFailed'
    | 'BoundsExceeded'
    | 'CleanupFailed'
    | 'CorruptRecord'
    | 'InvalidConfiguration'
    | 'InvalidInput'
    | 'LockUnavailable'
    | 'MissingChunk'
    | 'RestoreFailed'
    | 'ResumeMismatch';

class AuthenticatedCheckpointError extends Error {
    public readonly code: AuthenticatedCheckpointErrorCode;
    public readonly failureCause: unknown;

    public constructor(
        code: AuthenticatedCheckpointErrorCode,
        message: string,
        failureCause?: unknown,
    ) {
        super(message);
        this.name = 'AuthenticatedCheckpointError';
        this.code = code;
        this.failureCause = failureCause;
    }
}

export type AuthenticatedCheckpointScope = Readonly<{
    checkpointIdentifier: string;
    attemptIdentifier: Uint8Array;
    resumeBindingDigest: Uint8Array;
}>;

type CheckpointRecordContextBase = Readonly<{
    checkpointIdentifier: string;
    attemptIdentifier: Uint8Array;
    logicalRecordKey: string;
    resumeBindingDigest: Uint8Array;
}>;

export type AuthenticatedCheckpointRecordContext =
    | (CheckpointRecordContextBase &
          Readonly<{
              recordKind: 'manifest';
          }>)
    | (CheckpointRecordContextBase &
          Readonly<{
              recordKind: 'interruptedPublication';
          }>)
    | (CheckpointRecordContextBase &
          Readonly<{
              recordKind: 'stateChunk';
              chunkIndex: number;
              chunkByteLength: number;
              chunkDigest: Uint8Array;
          }>);

type AuthenticatedCheckpointSealRecord = (input: {
    context: AuthenticatedCheckpointRecordContext;
    plaintext: Uint8Array;
}) => Promise<Uint8Array> | Uint8Array;

type AuthenticatedCheckpointOpenRecord = (input: {
    context: AuthenticatedCheckpointRecordContext;
    sealedBytes: Uint8Array;
}) => Promise<Uint8Array> | Uint8Array;

export type AuthenticatedCheckpointExclusiveLock = <Result>(input: {
    lockName: string;
    operation: () => Promise<Result>;
}) => Promise<Result>;

export const createAuthenticatedCheckpointWebLock = (
    lockManager: LockManager | null | undefined = globalThis.navigator?.locks,
): AuthenticatedCheckpointExclusiveLock => {
    if (lockManager === undefined || lockManager === null) {
        throw new AuthenticatedCheckpointError(
            'InvalidConfiguration',
            'The Web Locks API is required for authenticated checkpoint publication.',
        );
    }

    return async <Result>(input: {
        lockName: string;
        operation: () => Promise<Result>;
    }): Promise<Result> => {
        if (
            input === null ||
            typeof input !== 'object' ||
            typeof input.lockName !== 'string' ||
            typeof input.operation !== 'function' ||
            !input.lockName.startsWith(checkpointExclusiveLockNamePrefix) ||
            !checkpointIdentifierPattern.test(
                input.lockName.slice(checkpointExclusiveLockNamePrefix.length),
            )
        ) {
            throw new AuthenticatedCheckpointError(
                'InvalidInput',
                'checkpoint Web Lock name is not a bounded internally-derived checkpoint name.',
            );
        }
        let callbackEntered = false;
        let operationStarted = false;
        let operationSettled = false;
        let operationRejected = false;
        let operationRejection: unknown;
        let lockValidationFailure: AuthenticatedCheckpointError | undefined;
        try {
            const result = await lockManager.request(
                input.lockName,
                { mode: 'exclusive' },
                async (lock) => {
                    if (callbackEntered) {
                        lockValidationFailure =
                            new AuthenticatedCheckpointError(
                                'LockUnavailable',
                                'The Web Locks API invoked the checkpoint lock callback more than once.',
                            );
                        throw lockValidationFailure;
                    }
                    callbackEntered = true;
                    if (
                        lock?.name !== input.lockName ||
                        lock.mode !== 'exclusive'
                    ) {
                        lockValidationFailure =
                            new AuthenticatedCheckpointError(
                                'LockUnavailable',
                                'The Web Locks API did not grant the requested exclusive checkpoint lock.',
                            );
                        throw lockValidationFailure;
                    }
                    operationStarted = true;
                    try {
                        return await input.operation();
                    } catch (error) {
                        operationRejected = true;
                        operationRejection = error;
                        throw error;
                    } finally {
                        operationSettled = true;
                    }
                },
            );
            if (!callbackEntered || !operationStarted || !operationSettled) {
                throw new AuthenticatedCheckpointError(
                    'LockUnavailable',
                    'The Web Locks API exited without running the complete checkpoint operation.',
                );
            }

            return result;
        } catch (error) {
            if (
                (lockValidationFailure !== undefined &&
                    error === lockValidationFailure) ||
                (operationRejected && error === operationRejection)
            ) {
                throw error;
            }
            throw new AuthenticatedCheckpointError(
                'LockUnavailable',
                'The exclusive checkpoint Web Lock request failed.',
                error,
            );
        }
    };
};

type AuthenticatedCheckpointLimits = Readonly<{
    checkpointChunkByteLength: number;
    maximumCheckpointByteLength: number;
    maximumCheckpointChunkCount: number;
    maximumSealedRecordByteLength: number;
    transactionLifetimeMilliseconds: number;
}>;

type AuthenticatedCheckpointDescriptor = Readonly<{
    chunkCount: number;
    orderedStateDigest: Uint8Array;
    totalByteLength: number;
}>;

type AuthenticatedCheckpointRestorer<Result> = Readonly<{
    acceptChunk(input: {
        bytes: Uint8Array;
        chunkIndex: number;
    }): Promise<void> | void;
    complete(
        descriptor: AuthenticatedCheckpointDescriptor,
    ): Promise<Result> | Result;
    discard(failure: unknown): Promise<void> | void;
}>;

type AuthenticatedCheckpointStoreConfiguration = Readonly<{
    withExclusiveCheckpointLock: AuthenticatedCheckpointExclusiveLock;
    limits: AuthenticatedCheckpointLimits;
    openRecord: AuthenticatedCheckpointOpenRecord;
    sealRecord: AuthenticatedCheckpointSealRecord;
    store: UntrustedStorageTransactionStore;
}>;

type InternalCheckpointScope = Readonly<{
    checkpointIdentifier: string;
    attemptIdentifier: Uint8Array;
    resumeBindingDigest: Uint8Array;
}>;

type ChunkDescriptor = Readonly<{
    byteLength: number;
    digest: Uint8Array;
}>;

type StorageManifest = Readonly<{
    chunks: readonly ChunkDescriptor[];
    orderedStateDigest: Uint8Array;
    scope: InternalCheckpointScope;
    totalByteLength: number;
}>;

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean => {
    if (left.byteLength !== right.byteLength) {
        return false;
    }
    for (let byteIndex = 0; byteIndex < left.byteLength; byteIndex += 1) {
        if (left[byteIndex] !== right[byteIndex]) {
            return false;
        }
    }

    return true;
};

const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const hexToBytes = (hex: string): Uint8Array => {
    if (hex.length % 2 !== 0 || !/^[0-9a-f]+$/u.test(hex)) {
        throw new AuthenticatedCheckpointError(
            'CorruptRecord',
            'checkpoint digest encoding is malformed.',
        );
    }
    const bytes = new Uint8Array(hex.length / 2);
    for (let byteIndex = 0; byteIndex < bytes.byteLength; byteIndex += 1) {
        bytes[byteIndex] = Number.parseInt(
            hex.slice(byteIndex * 2, byteIndex * 2 + 2),
            16,
        );
    }

    return bytes;
};

const encodeUnsigned32 = (value: number): Uint8Array => {
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value, true);

    return bytes;
};

const assertSafePositiveInteger = (value: number, label: string): void => {
    if (!Number.isSafeInteger(value) || value <= 0) {
        throw new AuthenticatedCheckpointError(
            'InvalidConfiguration',
            `${label} must be a positive safe integer.`,
        );
    }
};

const assertLimits = (limits: AuthenticatedCheckpointLimits): void => {
    assertSafePositiveInteger(
        limits.checkpointChunkByteLength,
        'checkpointChunkByteLength',
    );
    assertSafePositiveInteger(
        limits.maximumCheckpointByteLength,
        'maximumCheckpointByteLength',
    );
    assertSafePositiveInteger(
        limits.maximumCheckpointChunkCount,
        'maximumCheckpointChunkCount',
    );
    assertSafePositiveInteger(
        limits.maximumSealedRecordByteLength,
        'maximumSealedRecordByteLength',
    );
    assertSafePositiveInteger(
        limits.transactionLifetimeMilliseconds,
        'transactionLifetimeMilliseconds',
    );
    if (
        limits.checkpointChunkByteLength >
        maximumSupportedCheckpointChunkByteLength
    ) {
        throw new AuthenticatedCheckpointError(
            'InvalidConfiguration',
            `checkpointChunkByteLength must not exceed ${maximumSupportedCheckpointChunkByteLength}.`,
        );
    }
    if (
        limits.maximumCheckpointByteLength >
        maximumSupportedCheckpointByteLength
    ) {
        throw new AuthenticatedCheckpointError(
            'InvalidConfiguration',
            `maximumCheckpointByteLength must not exceed ${maximumSupportedCheckpointByteLength}.`,
        );
    }
    if (
        limits.maximumCheckpointChunkCount >
        maximumSupportedCheckpointChunkCount
    ) {
        throw new AuthenticatedCheckpointError(
            'InvalidConfiguration',
            `maximumCheckpointChunkCount must not exceed ${maximumSupportedCheckpointChunkCount}.`,
        );
    }
    if (
        limits.maximumSealedRecordByteLength >
        maximumSupportedSealedRecordByteLength
    ) {
        throw new AuthenticatedCheckpointError(
            'InvalidConfiguration',
            `maximumSealedRecordByteLength must not exceed ${maximumSupportedSealedRecordByteLength}.`,
        );
    }
    const maximumRepresentableStateByteLength =
        limits.checkpointChunkByteLength * limits.maximumCheckpointChunkCount;
    if (
        !Number.isSafeInteger(maximumRepresentableStateByteLength) ||
        limits.maximumCheckpointByteLength > maximumRepresentableStateByteLength
    ) {
        throw new AuthenticatedCheckpointError(
            'InvalidConfiguration',
            'maximumCheckpointByteLength exceeds the configured chunk capacity.',
        );
    }
    const maximumManifestByteLength =
        fixedStorageManifestByteLength +
        128 +
        chunkDescriptorByteLength * limits.maximumCheckpointChunkCount;
    if (maximumManifestByteLength > limits.maximumSealedRecordByteLength) {
        throw new AuthenticatedCheckpointError(
            'InvalidConfiguration',
            'maximumSealedRecordByteLength cannot contain the largest checkpoint manifest.',
        );
    }
};

const copyScope = (
    scope: AuthenticatedCheckpointScope,
): InternalCheckpointScope => {
    if (!checkpointIdentifierPattern.test(scope.checkpointIdentifier)) {
        throw new AuthenticatedCheckpointError(
            'InvalidInput',
            'checkpointIdentifier must contain 16 through 128 safe ASCII characters.',
        );
    }
    if (
        !(scope.attemptIdentifier instanceof Uint8Array) ||
        scope.attemptIdentifier.byteLength !== attemptIdentifierByteLength
    ) {
        throw new AuthenticatedCheckpointError(
            'InvalidInput',
            `attemptIdentifier must contain exactly ${attemptIdentifierByteLength} bytes.`,
        );
    }
    if (
        !(scope.resumeBindingDigest instanceof Uint8Array) ||
        scope.resumeBindingDigest.byteLength !== bindingDigestByteLength
    ) {
        throw new AuthenticatedCheckpointError(
            'InvalidInput',
            `resumeBindingDigest must contain exactly ${bindingDigestByteLength} bytes.`,
        );
    }

    return {
        checkpointIdentifier: scope.checkpointIdentifier,
        attemptIdentifier: scope.attemptIdentifier.slice(),
        resumeBindingDigest: scope.resumeBindingDigest.slice(),
    };
};

const scopesEqual = (
    left: InternalCheckpointScope,
    right: InternalCheckpointScope,
): boolean =>
    left.checkpointIdentifier === right.checkpointIdentifier &&
    bytesEqual(left.attemptIdentifier, right.attemptIdentifier) &&
    bytesEqual(left.resumeBindingDigest, right.resumeBindingDigest);

const deriveChunkDigest = (chunkIndex: number, bytes: Uint8Array): Uint8Array =>
    hexToBytes(
        hash512Hex(stateChunkDigestDomain, [
            encodeUnsigned32(chunkIndex),
            encodeUnsigned32(bytes.byteLength),
            bytes,
        ]),
    );

const deriveOrderedStateDigest = (
    totalByteLength: number,
    chunks: readonly ChunkDescriptor[],
): Uint8Array => {
    const parts: Uint8Array[] = [
        encodeUnsigned32(totalByteLength),
        encodeUnsigned32(chunks.length),
    ];
    for (let chunkIndex = 0; chunkIndex < chunks.length; chunkIndex += 1) {
        const chunk = chunks[chunkIndex];
        if (chunk === undefined) {
            throw new AuthenticatedCheckpointError(
                'CorruptRecord',
                'checkpoint chunk descriptor is missing.',
            );
        }
        parts.push(
            encodeUnsigned32(chunkIndex),
            encodeUnsigned32(chunk.byteLength),
            chunk.digest,
        );
    }

    return hexToBytes(hash512Hex(orderedStateDigestDomain, parts));
};

const manifestLogicalRecordKey = (scope: InternalCheckpointScope): string =>
    `authenticated-checkpoints/${scope.checkpointIdentifier}/manifest`;

const interruptedPublicationLogicalRecordKey = (
    scope: InternalCheckpointScope,
): string =>
    `authenticated-checkpoints/${scope.checkpointIdentifier}/interrupted-publication`;

const chunkLogicalRecordKey = (
    scope: InternalCheckpointScope,
    chunkIndex: number,
    descriptor: ChunkDescriptor,
): string =>
    `authenticated-checkpoints/${
        scope.checkpointIdentifier
    }/chunks/${bytesToHex(scope.attemptIdentifier)}/${chunkIndex
        .toString()
        .padStart(8, '0')}-${bytesToHex(descriptor.digest)}`;

const checkpointRecordContext = (input: {
    chunkDescriptor?: ChunkDescriptor;
    chunkIndex?: number;
    logicalRecordKey: string;
    recordKind: AuthenticatedCheckpointRecordContext['recordKind'];
    scope: InternalCheckpointScope;
}): AuthenticatedCheckpointRecordContext => {
    const base = {
        attemptIdentifier: input.scope.attemptIdentifier.slice(),
        checkpointIdentifier: input.scope.checkpointIdentifier,
        logicalRecordKey: input.logicalRecordKey,
        resumeBindingDigest: input.scope.resumeBindingDigest.slice(),
    };
    if (input.recordKind === 'stateChunk') {
        if (
            input.chunkIndex === undefined ||
            input.chunkDescriptor === undefined
        ) {
            throw new AuthenticatedCheckpointError(
                'InvalidInput',
                'state chunk record context requires its index and descriptor.',
            );
        }

        return {
            ...base,
            chunkByteLength: input.chunkDescriptor.byteLength,
            chunkDigest: input.chunkDescriptor.digest.slice(),
            chunkIndex: input.chunkIndex,
            recordKind: 'stateChunk',
        };
    }

    return {
        ...base,
        recordKind: input.recordKind,
    };
};

const publicDescriptor = (
    manifest: StorageManifest,
): AuthenticatedCheckpointDescriptor => ({
    chunkCount: manifest.chunks.length,
    orderedStateDigest: manifest.orderedStateDigest.slice(),
    totalByteLength: manifest.totalByteLength,
});

const storageManifestsEqual = (
    left: StorageManifest,
    right: StorageManifest,
): boolean => {
    if (
        !scopesEqual(left.scope, right.scope) ||
        left.totalByteLength !== right.totalByteLength ||
        !bytesEqual(left.orderedStateDigest, right.orderedStateDigest) ||
        left.chunks.length !== right.chunks.length
    ) {
        return false;
    }
    return left.chunks.every((chunk, chunkIndex) => {
        const otherChunk = right.chunks[chunkIndex];
        return (
            chunk.byteLength === otherChunk?.byteLength &&
            bytesEqual(chunk.digest, otherChunk.digest)
        );
    });
};

const encodeStorageManifest = (
    recordKind: number,
    manifest: StorageManifest,
): Uint8Array => {
    const identifierBytes = textEncoder.encode(
        manifest.scope.checkpointIdentifier,
    );
    const bytes = new Uint8Array(
        fixedStorageManifestByteLength +
            identifierBytes.byteLength +
            chunkDescriptorByteLength * manifest.chunks.length,
    );
    const view = new DataView(bytes.buffer);
    let offset = 0;
    bytes.set(checkpointRecordMagic, offset);
    offset += checkpointRecordMagic.byteLength;
    bytes[offset] = checkpointRecordVersion;
    offset += 1;
    bytes[offset] = recordKind;
    offset += 1;
    view.setUint16(offset, identifierBytes.byteLength, true);
    offset += 2;
    bytes.set(identifierBytes, offset);
    offset += identifierBytes.byteLength;
    bytes.set(manifest.scope.attemptIdentifier, offset);
    offset += attemptIdentifierByteLength;
    bytes.set(manifest.scope.resumeBindingDigest, offset);
    offset += bindingDigestByteLength;
    view.setUint32(offset, manifest.totalByteLength, true);
    offset += 4;
    view.setUint32(offset, manifest.chunks.length, true);
    offset += 4;
    bytes.set(manifest.orderedStateDigest, offset);
    offset += digestByteLength;
    for (const chunk of manifest.chunks) {
        view.setUint32(offset, chunk.byteLength, true);
        offset += 4;
        bytes.set(chunk.digest, offset);
        offset += digestByteLength;
    }

    return bytes;
};

const parseStorageManifest = (input: {
    bytes: Uint8Array;
    expectedRecordKind: number;
    expectedScope: InternalCheckpointScope;
    limits: AuthenticatedCheckpointLimits;
}): StorageManifest => {
    const { bytes, expectedRecordKind, expectedScope, limits } = input;
    if (bytes.byteLength < fixedStorageManifestByteLength) {
        throw new AuthenticatedCheckpointError(
            'CorruptRecord',
            'checkpoint manifest is shorter than its fixed header.',
        );
    }
    for (
        let magicByteIndex = 0;
        magicByteIndex < checkpointRecordMagic.byteLength;
        magicByteIndex += 1
    ) {
        if (bytes[magicByteIndex] !== checkpointRecordMagic[magicByteIndex]) {
            throw new AuthenticatedCheckpointError(
                'CorruptRecord',
                'checkpoint manifest has the wrong binary prefix.',
            );
        }
    }
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    let offset = checkpointRecordMagic.byteLength;
    if (bytes[offset] !== checkpointRecordVersion) {
        throw new AuthenticatedCheckpointError(
            'CorruptRecord',
            'checkpoint manifest has an unsupported format version.',
        );
    }
    offset += 1;
    if (bytes[offset] !== expectedRecordKind) {
        throw new AuthenticatedCheckpointError(
            'CorruptRecord',
            'checkpoint manifest has the wrong record kind.',
        );
    }
    offset += 1;
    const identifierByteLength = view.getUint16(offset, true);
    offset += 2;
    if (
        identifierByteLength < 16 ||
        identifierByteLength > 128 ||
        offset +
            identifierByteLength +
            attemptIdentifierByteLength +
            bindingDigestByteLength +
            4 +
            4 +
            digestByteLength >
            bytes.byteLength
    ) {
        throw new AuthenticatedCheckpointError(
            'CorruptRecord',
            'checkpoint manifest identifier length is invalid.',
        );
    }
    const identifierBytes = bytes.slice(offset, offset + identifierByteLength);
    offset += identifierByteLength;
    let checkpointIdentifier: string;
    try {
        checkpointIdentifier = fatalTextDecoder.decode(identifierBytes);
    } catch (error) {
        throw new AuthenticatedCheckpointError(
            'CorruptRecord',
            'checkpoint manifest identifier is not valid UTF-8.',
            error,
        );
    }
    if (
        !checkpointIdentifierPattern.test(checkpointIdentifier) ||
        !bytesEqual(identifierBytes, textEncoder.encode(checkpointIdentifier))
    ) {
        throw new AuthenticatedCheckpointError(
            'CorruptRecord',
            'checkpoint manifest identifier is not canonical safe ASCII.',
        );
    }
    const attemptIdentifier = bytes.slice(
        offset,
        offset + attemptIdentifierByteLength,
    );
    offset += attemptIdentifierByteLength;
    const resumeBindingDigest = bytes.slice(
        offset,
        offset + bindingDigestByteLength,
    );
    offset += bindingDigestByteLength;
    const totalByteLength = view.getUint32(offset, true);
    offset += 4;
    const chunkCount = view.getUint32(offset, true);
    offset += 4;
    if (
        chunkCount === 0 ||
        chunkCount > limits.maximumCheckpointChunkCount ||
        totalByteLength === 0 ||
        totalByteLength > limits.maximumCheckpointByteLength
    ) {
        throw new AuthenticatedCheckpointError(
            'BoundsExceeded',
            'checkpoint manifest exceeds its configured count or size bound.',
        );
    }
    const expectedByteLength =
        fixedStorageManifestByteLength +
        identifierByteLength +
        chunkDescriptorByteLength * chunkCount;
    if (bytes.byteLength !== expectedByteLength) {
        throw new AuthenticatedCheckpointError(
            'CorruptRecord',
            'checkpoint manifest length does not match its chunk count.',
        );
    }
    const orderedStateDigest = bytes.slice(offset, offset + digestByteLength);
    offset += digestByteLength;
    const chunks: ChunkDescriptor[] = [];
    let observedTotalByteLength = 0;
    for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex += 1) {
        const byteLength = view.getUint32(offset, true);
        offset += 4;
        const digest = bytes.slice(offset, offset + digestByteLength);
        offset += digestByteLength;
        const isFinalChunk = chunkIndex === chunkCount - 1;
        if (
            byteLength === 0 ||
            byteLength > limits.checkpointChunkByteLength ||
            (!isFinalChunk && byteLength !== limits.checkpointChunkByteLength)
        ) {
            throw new AuthenticatedCheckpointError(
                'CorruptRecord',
                'checkpoint manifest contains an invalid chunk length.',
            );
        }
        observedTotalByteLength += byteLength;
        if (
            !Number.isSafeInteger(observedTotalByteLength) ||
            observedTotalByteLength > limits.maximumCheckpointByteLength
        ) {
            throw new AuthenticatedCheckpointError(
                'BoundsExceeded',
                'checkpoint manifest total length exceeds its configured bound.',
            );
        }
        chunks.push({ byteLength, digest });
    }
    if (observedTotalByteLength !== totalByteLength) {
        throw new AuthenticatedCheckpointError(
            'CorruptRecord',
            'checkpoint manifest total length does not equal its chunk lengths.',
        );
    }
    const parsedScope = {
        attemptIdentifier,
        checkpointIdentifier,
        resumeBindingDigest,
    };
    if (!scopesEqual(parsedScope, expectedScope)) {
        throw new AuthenticatedCheckpointError(
            'ResumeMismatch',
            'checkpoint manifest does not belong to the requested attempt and resume binding.',
        );
    }
    const expectedOrderedStateDigest = deriveOrderedStateDigest(
        totalByteLength,
        chunks,
    );
    if (!bytesEqual(orderedStateDigest, expectedOrderedStateDigest)) {
        throw new AuthenticatedCheckpointError(
            'CorruptRecord',
            'checkpoint manifest ordered state digest is invalid.',
        );
    }

    return {
        chunks,
        orderedStateDigest,
        scope: parsedScope,
        totalByteLength,
    };
};

export class AuthenticatedCheckpointStore {
    readonly #withExclusiveCheckpointLock: AuthenticatedCheckpointExclusiveLock;
    readonly #limits: AuthenticatedCheckpointLimits;
    readonly #openRecord: AuthenticatedCheckpointOpenRecord;
    readonly #sealRecord: AuthenticatedCheckpointSealRecord;
    readonly #store: UntrustedStorageTransactionStore;
    #exclusiveOperationTail: Promise<void> = Promise.resolve();

    public constructor(
        configuration: AuthenticatedCheckpointStoreConfiguration,
    ) {
        assertLimits(configuration.limits);
        if (typeof configuration.withExclusiveCheckpointLock !== 'function') {
            throw new AuthenticatedCheckpointError(
                'InvalidConfiguration',
                'withExclusiveCheckpointLock must acquire a cross-document exclusive lock.',
            );
        }
        this.#withExclusiveCheckpointLock =
            configuration.withExclusiveCheckpointLock;
        this.#limits = { ...configuration.limits };
        this.#openRecord = configuration.openRecord;
        this.#sealRecord = configuration.sealRecord;
        this.#store = configuration.store;
    }

    public replaceCheckpoint(input: {
        scope: AuthenticatedCheckpointScope;
        stateChunks: AsyncIterable<Uint8Array> | Iterable<Uint8Array>;
    }): Promise<AuthenticatedCheckpointDescriptor> {
        const scope = copyScope(input.scope);

        return this.#runExclusive(scope, async () => {
            await this.#cleanupInterruptedPublication(scope);
            const previousManifest = await this.#readStorageManifest(
                manifestRecordKind,
                scope,
            );
            const transaction = await this.#store.beginTransaction({
                lifetimeMilliseconds:
                    this.#limits.transactionLifetimeMilliseconds,
            });
            let transactionCommitted = false;
            try {
                const chunks: ChunkDescriptor[] = [];
                let totalByteLength = 0;
                let bufferedChunk: Uint8Array | undefined;
                let observedChunkCount = 0;
                for await (const sourceChunk of input.stateChunks) {
                    observedChunkCount += 1;
                    if (
                        observedChunkCount >
                        this.#limits.maximumCheckpointChunkCount
                    ) {
                        throw new AuthenticatedCheckpointError(
                            'BoundsExceeded',
                            'checkpoint source exceeds maximumCheckpointChunkCount.',
                        );
                    }
                    const copiedChunk = this.#copySourceChunk(sourceChunk);
                    if (bufferedChunk !== undefined) {
                        totalByteLength = await this.#stageChunk({
                            bytes: bufferedChunk,
                            chunkIndex: chunks.length,
                            chunks,
                            isFinalChunk: false,
                            scope,
                            totalByteLength,
                            transaction,
                        });
                    }
                    bufferedChunk = copiedChunk;
                }
                if (bufferedChunk === undefined) {
                    throw new AuthenticatedCheckpointError(
                        'InvalidInput',
                        'checkpoint state must contain at least one nonempty chunk.',
                    );
                }
                totalByteLength = await this.#stageChunk({
                    bytes: bufferedChunk,
                    chunkIndex: chunks.length,
                    chunks,
                    isFinalChunk: true,
                    scope,
                    totalByteLength,
                    transaction,
                });
                const manifest: StorageManifest = {
                    chunks,
                    orderedStateDigest: deriveOrderedStateDigest(
                        totalByteLength,
                        chunks,
                    ),
                    scope,
                    totalByteLength,
                };
                const interruptedPublicationKey =
                    interruptedPublicationLogicalRecordKey(scope);
                await this.#stageSealedRecord({
                    context: checkpointRecordContext({
                        logicalRecordKey: interruptedPublicationKey,
                        recordKind: 'interruptedPublication',
                        scope,
                    }),
                    logicalRecordKey: interruptedPublicationKey,
                    plaintext: encodeStorageManifest(
                        interruptedPublicationRecordKind,
                        manifest,
                    ),
                    transaction,
                });
                await transaction.commit();
                transactionCommitted = true;

                const rereadInterruptedPublication =
                    await this.#readStorageManifest(
                        interruptedPublicationRecordKind,
                        scope,
                    );
                if (
                    rereadInterruptedPublication === undefined ||
                    !storageManifestsEqual(
                        manifest,
                        rereadInterruptedPublication,
                    )
                ) {
                    throw new AuthenticatedCheckpointError(
                        'AuthenticationFailed',
                        'checkpoint interrupted-publication record did not authenticate after commit.',
                    );
                }
                for (
                    let chunkIndex = 0;
                    chunkIndex < chunks.length;
                    chunkIndex += 1
                ) {
                    const descriptor = chunks[chunkIndex];
                    if (descriptor === undefined) {
                        throw new AuthenticatedCheckpointError(
                            'CorruptRecord',
                            'checkpoint chunk descriptor is missing after publication.',
                        );
                    }
                    await this.#readRequiredChunk(
                        scope,
                        chunkIndex,
                        descriptor,
                    );
                }

                await this.#publishManifest(manifest, previousManifest);
                const rereadManifest = await this.#readStorageManifest(
                    manifestRecordKind,
                    scope,
                );
                if (
                    rereadManifest === undefined ||
                    !storageManifestsEqual(manifest, rereadManifest)
                ) {
                    throw new AuthenticatedCheckpointError(
                        'AuthenticationFailed',
                        'checkpoint manifest did not authenticate after publication.',
                    );
                }
                if (
                    (await this.#readStorageManifest(
                        interruptedPublicationRecordKind,
                        scope,
                    )) !== undefined
                ) {
                    throw new AuthenticatedCheckpointError(
                        'CleanupFailed',
                        'checkpoint publication retained its interrupted-publication record.',
                    );
                }

                return publicDescriptor(rereadManifest);
            } catch (error) {
                if (!transactionCommitted) {
                    try {
                        await transaction.abort();
                    } catch (cleanupError) {
                        throw new AuthenticatedCheckpointError(
                            'CleanupFailed',
                            'checkpoint staging and transaction cleanup both failed.',
                            [error, cleanupError],
                        );
                    }
                }
                throw error;
            }
        });
    }

    public resumeCheckpoint<Result>(input: {
        restorer: AuthenticatedCheckpointRestorer<Result>;
        scope: AuthenticatedCheckpointScope;
    }): Promise<Result | undefined> {
        const scope = copyScope(input.scope);

        return this.#runExclusive(scope, async () => {
            await this.#cleanupInterruptedPublication(scope);
            const manifest = await this.#readStorageManifest(
                manifestRecordKind,
                scope,
            );
            if (manifest === undefined) {
                return undefined;
            }

            try {
                for (
                    let chunkIndex = 0;
                    chunkIndex < manifest.chunks.length;
                    chunkIndex += 1
                ) {
                    const descriptor = manifest.chunks[chunkIndex];
                    if (descriptor === undefined) {
                        throw new AuthenticatedCheckpointError(
                            'CorruptRecord',
                            'checkpoint manifest omitted a chunk descriptor.',
                        );
                    }
                    const bytes = await this.#readRequiredChunk(
                        scope,
                        chunkIndex,
                        descriptor,
                    );
                    try {
                        await input.restorer.acceptChunk({
                            bytes: bytes.slice(),
                            chunkIndex,
                        });
                    } catch (error) {
                        throw new AuthenticatedCheckpointError(
                            'RestoreFailed',
                            'checkpoint state parser rejected a chunk.',
                            error,
                        );
                    }
                }
                try {
                    return await input.restorer.complete(
                        publicDescriptor(manifest),
                    );
                } catch (error) {
                    throw new AuthenticatedCheckpointError(
                        'RestoreFailed',
                        'checkpoint state parser failed to complete.',
                        error,
                    );
                }
            } catch (error) {
                try {
                    await input.restorer.discard(error);
                } catch (discardError) {
                    throw new AuthenticatedCheckpointError(
                        'RestoreFailed',
                        'checkpoint restore and parser cleanup both failed.',
                        [error, discardError],
                    );
                }
                throw error;
            }
        });
    }

    public cleanupInterruptedPublication(
        scope: AuthenticatedCheckpointScope,
    ): Promise<Readonly<{ removedChunkCount: number }>> {
        const copiedScope = copyScope(scope);

        return this.#runExclusive(copiedScope, async () => ({
            removedChunkCount:
                await this.#cleanupInterruptedPublication(copiedScope),
        }));
    }

    public evictCheckpoint(
        scope: AuthenticatedCheckpointScope,
    ): Promise<Readonly<{ removedChunkCount: number }>> {
        const copiedScope = copyScope(scope);

        return this.#runExclusive(copiedScope, async () => {
            const removedInterruptedChunkCount =
                await this.#cleanupInterruptedPublication(copiedScope);
            const manifest = await this.#readStorageManifest(
                manifestRecordKind,
                copiedScope,
            );
            if (manifest === undefined) {
                return {
                    removedChunkCount: removedInterruptedChunkCount,
                };
            }
            const transaction = await this.#store.beginTransaction({
                lifetimeMilliseconds:
                    this.#limits.transactionLifetimeMilliseconds,
            });
            try {
                await transaction.stageDeletion(
                    manifestLogicalRecordKey(copiedScope),
                );
                for (
                    let chunkIndex = 0;
                    chunkIndex < manifest.chunks.length;
                    chunkIndex += 1
                ) {
                    const descriptor = manifest.chunks[chunkIndex];
                    if (descriptor !== undefined) {
                        await transaction.stageDeletion(
                            chunkLogicalRecordKey(
                                copiedScope,
                                chunkIndex,
                                descriptor,
                            ),
                        );
                    }
                }
                await transaction.commit();
            } catch (error) {
                try {
                    await transaction.abort();
                } catch (cleanupError) {
                    throw new AuthenticatedCheckpointError(
                        'CleanupFailed',
                        'checkpoint eviction and transaction cleanup both failed.',
                        [error, cleanupError],
                    );
                }
                throw error;
            }
            if (
                (await this.#readStorageManifest(
                    manifestRecordKind,
                    copiedScope,
                )) !== undefined
            ) {
                throw new AuthenticatedCheckpointError(
                    'CleanupFailed',
                    'checkpoint manifest remained visible after eviction.',
                );
            }

            return {
                removedChunkCount:
                    removedInterruptedChunkCount + manifest.chunks.length,
            };
        });
    }

    async #publishManifest(
        manifest: StorageManifest,
        previousManifest: StorageManifest | undefined,
    ): Promise<void> {
        const transaction = await this.#store.beginTransaction({
            lifetimeMilliseconds: this.#limits.transactionLifetimeMilliseconds,
        });
        try {
            const manifestKey = manifestLogicalRecordKey(manifest.scope);
            await this.#stageSealedRecord({
                context: checkpointRecordContext({
                    logicalRecordKey: manifestKey,
                    recordKind: 'manifest',
                    scope: manifest.scope,
                }),
                logicalRecordKey: manifestKey,
                plaintext: encodeStorageManifest(manifestRecordKind, manifest),
                transaction,
            });
            await transaction.stageDeletion(
                interruptedPublicationLogicalRecordKey(manifest.scope),
            );
            if (previousManifest !== undefined) {
                const retainedChunkKeys = new Set(
                    manifest.chunks.map((descriptor, chunkIndex) =>
                        chunkLogicalRecordKey(
                            manifest.scope,
                            chunkIndex,
                            descriptor,
                        ),
                    ),
                );
                for (
                    let chunkIndex = 0;
                    chunkIndex < previousManifest.chunks.length;
                    chunkIndex += 1
                ) {
                    const descriptor = previousManifest.chunks[chunkIndex];
                    if (descriptor === undefined) {
                        continue;
                    }
                    const previousChunkKey = chunkLogicalRecordKey(
                        previousManifest.scope,
                        chunkIndex,
                        descriptor,
                    );
                    if (!retainedChunkKeys.has(previousChunkKey)) {
                        await transaction.stageDeletion(previousChunkKey);
                    }
                }
            }
            await transaction.commit();
        } catch (error) {
            try {
                await transaction.abort();
            } catch (cleanupError) {
                throw new AuthenticatedCheckpointError(
                    'CleanupFailed',
                    'checkpoint publication and transaction cleanup both failed.',
                    [error, cleanupError],
                );
            }
            throw error;
        }
    }

    async #cleanupInterruptedPublication(
        scope: InternalCheckpointScope,
    ): Promise<number> {
        const interruptedPublication = await this.#readStorageManifest(
            interruptedPublicationRecordKind,
            scope,
        );
        if (interruptedPublication === undefined) {
            return 0;
        }
        const currentManifest = await this.#readStorageManifest(
            manifestRecordKind,
            scope,
        );
        const retainedChunkKeys = new Set<string>();
        if (currentManifest !== undefined) {
            for (
                let chunkIndex = 0;
                chunkIndex < currentManifest.chunks.length;
                chunkIndex += 1
            ) {
                const descriptor = currentManifest.chunks[chunkIndex];
                if (descriptor !== undefined) {
                    retainedChunkKeys.add(
                        chunkLogicalRecordKey(scope, chunkIndex, descriptor),
                    );
                }
            }
        }
        const chunkKeysToDelete = interruptedPublication.chunks
            .map((descriptor, chunkIndex) =>
                chunkLogicalRecordKey(scope, chunkIndex, descriptor),
            )
            .filter((key) => !retainedChunkKeys.has(key));
        const transaction = await this.#store.beginTransaction({
            lifetimeMilliseconds: this.#limits.transactionLifetimeMilliseconds,
        });
        try {
            for (const chunkKey of chunkKeysToDelete) {
                await transaction.stageDeletion(chunkKey);
            }
            await transaction.stageDeletion(
                interruptedPublicationLogicalRecordKey(scope),
            );
            await transaction.commit();
        } catch (error) {
            try {
                await transaction.abort();
            } catch (cleanupError) {
                throw new AuthenticatedCheckpointError(
                    'CleanupFailed',
                    'interrupted checkpoint cleanup and transaction abort both failed.',
                    [error, cleanupError],
                );
            }
            throw error;
        }
        if (
            (await this.#readStorageManifest(
                interruptedPublicationRecordKind,
                scope,
            )) !== undefined
        ) {
            throw new AuthenticatedCheckpointError(
                'CleanupFailed',
                'interrupted checkpoint record remained visible after cleanup.',
            );
        }

        return chunkKeysToDelete.length;
    }

    async #stageChunk(input: {
        bytes: Uint8Array;
        chunkIndex: number;
        chunks: ChunkDescriptor[];
        isFinalChunk: boolean;
        scope: InternalCheckpointScope;
        totalByteLength: number;
        transaction: UntrustedStorageTransaction;
    }): Promise<number> {
        if (
            input.bytes.byteLength === 0 ||
            input.bytes.byteLength > this.#limits.checkpointChunkByteLength ||
            (!input.isFinalChunk &&
                input.bytes.byteLength !==
                    this.#limits.checkpointChunkByteLength)
        ) {
            throw new AuthenticatedCheckpointError(
                'InvalidInput',
                'checkpoint chunks must be nonempty, with every non-final chunk at the configured length.',
            );
        }
        const nextTotalByteLength =
            input.totalByteLength + input.bytes.byteLength;
        if (
            !Number.isSafeInteger(nextTotalByteLength) ||
            nextTotalByteLength > this.#limits.maximumCheckpointByteLength
        ) {
            throw new AuthenticatedCheckpointError(
                'BoundsExceeded',
                'checkpoint state exceeds maximumCheckpointByteLength.',
            );
        }
        const descriptor = {
            byteLength: input.bytes.byteLength,
            digest: deriveChunkDigest(input.chunkIndex, input.bytes),
        };
        const logicalRecordKey = chunkLogicalRecordKey(
            input.scope,
            input.chunkIndex,
            descriptor,
        );
        await this.#stageSealedRecord({
            context: checkpointRecordContext({
                chunkDescriptor: descriptor,
                chunkIndex: input.chunkIndex,
                logicalRecordKey,
                recordKind: 'stateChunk',
                scope: input.scope,
            }),
            logicalRecordKey,
            plaintext: input.bytes,
            transaction: input.transaction,
        });
        input.chunks.push(descriptor);

        return nextTotalByteLength;
    }

    #copySourceChunk(sourceChunk: Uint8Array): Uint8Array {
        if (!(sourceChunk instanceof Uint8Array)) {
            throw new AuthenticatedCheckpointError(
                'InvalidInput',
                'checkpoint source yielded a value that is not a Uint8Array.',
            );
        }
        try {
            return sourceChunk.slice();
        } catch (error) {
            throw new AuthenticatedCheckpointError(
                'InvalidInput',
                'checkpoint source chunk could not be copied.',
                error,
            );
        }
    }

    async #stageSealedRecord(input: {
        context: AuthenticatedCheckpointRecordContext;
        logicalRecordKey: string;
        plaintext: Uint8Array;
        transaction: UntrustedStorageTransaction;
    }): Promise<void> {
        const plaintext = input.plaintext.slice();
        const sealedBytes = await this.#seal(plaintext, input.context);
        const lease = await input.transaction.issueWriteLease({
            declaredByteLength: sealedBytes.byteLength,
            logicalRecordKey: input.logicalRecordKey,
        });
        await lease.write(sealedBytes);
        await lease.seal(async ({ bytes, logicalRecordKey }) => {
            if (logicalRecordKey !== input.logicalRecordKey) {
                throw new AuthenticatedCheckpointError(
                    'AuthenticationFailed',
                    'checkpoint lease returned the wrong logical record key.',
                );
            }
            const openedPlaintext = await this.#open(bytes, input.context);
            if (!bytesEqual(plaintext, openedPlaintext)) {
                throw new AuthenticatedCheckpointError(
                    'AuthenticationFailed',
                    'sealed checkpoint record did not reopen to its exact plaintext.',
                );
            }
        });
    }

    async #seal(
        plaintext: Uint8Array,
        context: AuthenticatedCheckpointRecordContext,
    ): Promise<Uint8Array> {
        let sealedBytes: Uint8Array;
        try {
            sealedBytes = await this.#sealRecord({
                context: this.#copyRecordContext(context),
                plaintext: plaintext.slice(),
            });
        } catch (error) {
            throw new AuthenticatedCheckpointError(
                'AuthenticationFailed',
                'checkpoint record sealing failed.',
                error,
            );
        }
        if (
            !(sealedBytes instanceof Uint8Array) ||
            sealedBytes.byteLength === 0 ||
            sealedBytes.byteLength > this.#limits.maximumSealedRecordByteLength
        ) {
            throw new AuthenticatedCheckpointError(
                'BoundsExceeded',
                'sealed checkpoint record exceeds its configured byte bound.',
            );
        }

        return sealedBytes.slice();
    }

    async #open(
        sealedBytes: Uint8Array,
        context: AuthenticatedCheckpointRecordContext,
    ): Promise<Uint8Array> {
        if (
            sealedBytes.byteLength === 0 ||
            sealedBytes.byteLength > this.#limits.maximumSealedRecordByteLength
        ) {
            throw new AuthenticatedCheckpointError(
                'BoundsExceeded',
                'stored checkpoint record exceeds its configured sealed byte bound.',
            );
        }
        let plaintext: Uint8Array;
        try {
            plaintext = await this.#openRecord({
                context: this.#copyRecordContext(context),
                sealedBytes: sealedBytes.slice(),
            });
        } catch (error) {
            throw new AuthenticatedCheckpointError(
                'AuthenticationFailed',
                'checkpoint record authentication failed.',
                error,
            );
        }
        if (!(plaintext instanceof Uint8Array)) {
            throw new AuthenticatedCheckpointError(
                'AuthenticationFailed',
                'checkpoint record opener returned a non-byte value.',
            );
        }
        if (plaintext.byteLength > this.#limits.maximumSealedRecordByteLength) {
            throw new AuthenticatedCheckpointError(
                'BoundsExceeded',
                'opened checkpoint record exceeds its configured byte bound.',
            );
        }

        return plaintext.slice();
    }

    async #readStorageManifest(
        recordKind: number,
        scope: InternalCheckpointScope,
    ): Promise<StorageManifest | undefined> {
        const isPublishedManifest = recordKind === manifestRecordKind;
        const logicalRecordKey = isPublishedManifest
            ? manifestLogicalRecordKey(scope)
            : interruptedPublicationLogicalRecordKey(scope);
        const plaintext = await this.#readOpenedRecord(
            logicalRecordKey,
            checkpointRecordContext({
                logicalRecordKey,
                recordKind: isPublishedManifest
                    ? 'manifest'
                    : 'interruptedPublication',
                scope,
            }),
        );
        if (plaintext === undefined) {
            return undefined;
        }

        return parseStorageManifest({
            bytes: plaintext,
            expectedRecordKind: recordKind,
            expectedScope: scope,
            limits: this.#limits,
        });
    }

    async #readRequiredChunk(
        scope: InternalCheckpointScope,
        chunkIndex: number,
        descriptor: ChunkDescriptor,
    ): Promise<Uint8Array> {
        const logicalRecordKey = chunkLogicalRecordKey(
            scope,
            chunkIndex,
            descriptor,
        );
        const plaintext = await this.#readOpenedRecord(
            logicalRecordKey,
            checkpointRecordContext({
                chunkDescriptor: descriptor,
                chunkIndex,
                logicalRecordKey,
                recordKind: 'stateChunk',
                scope,
            }),
        );
        if (plaintext === undefined) {
            throw new AuthenticatedCheckpointError(
                'MissingChunk',
                `checkpoint state chunk ${chunkIndex} is missing.`,
            );
        }
        if (
            plaintext.byteLength !== descriptor.byteLength ||
            !bytesEqual(
                deriveChunkDigest(chunkIndex, plaintext),
                descriptor.digest,
            )
        ) {
            throw new AuthenticatedCheckpointError(
                'CorruptRecord',
                `checkpoint state chunk ${chunkIndex} does not match its authenticated descriptor.`,
            );
        }

        return plaintext;
    }

    async #readOpenedRecord(
        logicalRecordKey: string,
        context: AuthenticatedCheckpointRecordContext,
    ): Promise<Uint8Array | undefined> {
        let authenticatedPlaintext: Uint8Array | undefined;
        const storedBytes = await this.#store.readAuthenticated({
            authenticate: async ({ bytes, logicalRecordKey: observedKey }) => {
                if (observedKey !== logicalRecordKey) {
                    throw new AuthenticatedCheckpointError(
                        'AuthenticationFailed',
                        'checkpoint read returned the wrong logical record key.',
                    );
                }
                authenticatedPlaintext = await this.#open(bytes, context);
            },
            logicalRecordKey,
        });
        if (storedBytes === undefined) {
            return undefined;
        }
        if (authenticatedPlaintext === undefined) {
            throw new AuthenticatedCheckpointError(
                'AuthenticationFailed',
                'checkpoint read completed without authenticated plaintext.',
            );
        }

        return authenticatedPlaintext.slice();
    }

    #copyRecordContext(
        context: AuthenticatedCheckpointRecordContext,
    ): AuthenticatedCheckpointRecordContext {
        if (context.recordKind === 'stateChunk') {
            return {
                ...context,
                attemptIdentifier: context.attemptIdentifier.slice(),
                chunkDigest: context.chunkDigest.slice(),
                resumeBindingDigest: context.resumeBindingDigest.slice(),
            };
        }

        return {
            ...context,
            attemptIdentifier: context.attemptIdentifier.slice(),
            resumeBindingDigest: context.resumeBindingDigest.slice(),
        };
    }

    async #runExclusive<Result>(
        scope: InternalCheckpointScope,
        operation: () => Promise<Result>,
    ): Promise<Result> {
        const previousOperation = this.#exclusiveOperationTail;
        let releaseOperation: (() => void) | undefined;
        this.#exclusiveOperationTail = new Promise<void>((resolve) => {
            releaseOperation = resolve;
        });
        await previousOperation;
        try {
            return await this.#withExclusiveCheckpointLock({
                lockName: `${checkpointExclusiveLockNamePrefix}${scope.checkpointIdentifier}`,
                operation,
            });
        } catch (error) {
            if (
                error instanceof UntrustedStorageTransactionError &&
                error.code === 'AuthenticationFailed' &&
                error.failureCause instanceof AuthenticatedCheckpointError
            ) {
                throw error.failureCause;
            }
            throw error;
        } finally {
            releaseOperation?.();
        }
    }
}
