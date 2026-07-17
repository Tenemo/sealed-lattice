import type { UntrustedStorageTransactionStore } from './store.js';

export const textEncoder = new TextEncoder();
export const fatalTextDecoder = new TextDecoder('utf-8', { fatal: true });
export const maximumLogicalRecordKeyByteLength = 1024;
const identifierByteLength = 32;
export const encodedIdentifierCharacterLength = identifierByteLength * 2;
export const identifierPattern = /^[0-9a-f]{64}$/u;
export const namespacePattern = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;
export const maximumUnsigned64 = 0xffff_ffff_ffff_ffffn;
export const authenticatedRepairHeadRecordVersion = 1;
const authenticatedRepairHeadMagic = Uint8Array.of(0x53, 0x4c, 0x52, 0x48);
const authenticatedRepairHeadFixedByteLength =
    authenticatedRepairHeadMagic.byteLength +
    2 +
    8 +
    identifierByteLength +
    64 +
    64 +
    4;
export const authorizedEmptyHeadDigestDomain = textEncoder.encode(
    'sealed-lattice/authenticated-storage-empty-head/v1',
);
export const storageInstanceIdentityDomain = textEncoder.encode(
    'sealed-lattice/authenticated-storage-instance/v1',
);

export type UntrustedStorageTransactionErrorCode =
    | 'AdapterFailure'
    | 'AuthenticationFailed'
    | 'CleanupFailed'
    | 'Conflict'
    | 'CorruptIndex'
    | 'Expired'
    | 'InvalidState'
    | 'MalformedLength'
    | 'QuotaExceeded';

export class UntrustedStorageTransactionError extends Error {
    public readonly code: UntrustedStorageTransactionErrorCode;
    public readonly failureCause: unknown;

    public constructor(
        code: UntrustedStorageTransactionErrorCode,
        message: string,
        failureCause?: unknown,
    ) {
        super(message);
        this.name = 'UntrustedStorageTransactionError';
        this.code = code;
        this.failureCause = failureCause;
    }
}

export type UntrustedStorageExpectedValue = Readonly<{
    key: string;
    value: Uint8Array | undefined;
}>;

export type UntrustedStorageWrite = Readonly<{
    key: string;
    value: Uint8Array;
}>;

export type UntrustedStorageAtomicMutation = Readonly<{
    expectedValues: readonly UntrustedStorageExpectedValue[];
    writes: readonly UntrustedStorageWrite[];
    deletes: readonly string[];
}>;

/**
 * The adapter owns atomicity and namespace exclusion, not byte trust. A browser
 * adapter must implement applyAtomicMutation with one strict-durability browser
 * transaction and must grant this store exclusive repair authority for its
 * namespace. A rejected applyAtomicMutation promise must guarantee that its
 * mutation did not commit. Reads and writes may return attacker-controlled
 * bytes.
 */
export type UntrustedStorageAdapter = Readonly<{
    read(key: string): Promise<Uint8Array | undefined>;
    write(key: string, value: Uint8Array): Promise<void>;
    delete(key: string): Promise<void>;
    listKeys(prefix: string): Promise<readonly string[]>;
    /**
     * Atomically verifies that none of the current values below indexPrefix
     * reference an objectKey, then deletes every supplied object key. Returns
     * false without deleting anything when a reference is present.
     */
    deleteUnreferencedObjects(input: {
        indexPrefix: string;
        objectKeys: readonly string[];
    }): Promise<boolean>;
    applyAtomicMutation(
        mutation: UntrustedStorageAtomicMutation,
    ): Promise<boolean>;
}>;

export type UntrustedStorageTransactionLimits = Readonly<{
    maximumActiveTransactionCount: number;
    maximumLeaseByteLength: number;
    maximumLeaseCountPerTransaction: number;
    maximumOwnedRecordCount: number;
    maximumStoredValueByteLength: number;
    maximumTransactionByteLength: number;
    maximumTransactionLifetimeMilliseconds: number;
}>;

export type UntrustedStoragePublicationDisposition =
    | 'definitely-not-published'
    | 'published-or-indeterminate';

export type UntrustedStorageAuthenticationInput = Readonly<{
    bytes: Uint8Array;
    logicalRecordKey: string;
}>;

export type UntrustedStorageAuthenticator = (
    input: UntrustedStorageAuthenticationInput,
) => Promise<void> | void;

type UntrustedStorageLeaseState =
    | 'issued'
    | 'writing'
    | 'sealed'
    | 'claimed'
    | 'consumed'
    | 'cancelled';

export type UntrustedStorageWriteLease = Readonly<{
    write(bytes: Uint8Array): Promise<void>;
    seal(authenticate: UntrustedStorageAuthenticator): Promise<void>;
    cancel(): Promise<void>;
    state(): UntrustedStorageLeaseState;
}>;

export type UntrustedStorageTransaction = Readonly<{
    issueWriteLease(input: {
        logicalRecordKey: string;
        declaredByteLength: number;
        expectedCurrentValue?: Uint8Array | null;
    }): Promise<UntrustedStorageWriteLease>;
    stageDeletion(
        logicalRecordKey: string,
        expectedCurrentValue?: Uint8Array | null,
    ): Promise<void>;
    commit(): Promise<void>;
    abort(): Promise<void>;
    closeAfterFailure(
        recordPublicationDisposition?: (
            disposition: UntrustedStoragePublicationDisposition,
        ) => void,
    ): Promise<void>;
}>;

export type UntrustedStorageRepairReport = Readonly<{
    removedCorruptIndexCount: number;
    removedUnreferencedObjectCount: number;
    retainedObjectCount: number;
    storedValueByteLength: number;
}>;

export type UntrustedStorageTransactionStoreOpenResult = Readonly<{
    repairReport: UntrustedStorageRepairReport;
    store: UntrustedStorageTransactionStore;
}>;

export type UntrustedStorageAuthenticatedHeadSnapshot = Readonly<{
    authenticatedHeadDigest: Uint8Array;
    namespaceSequence: bigint;
    storageInstanceIdentity: Uint8Array;
}>;

export type UntrustedStorageExclusiveCapacityReservation = Readonly<{
    copyAuthenticatedLogicalRecordKeys(
        prefix: string,
    ): Promise<readonly string[]>;
    deleteAuthenticatedLogicalRecords(prefix: string): Promise<number>;
    release(): Promise<void>;
}>;

export type UntrustedStorageExclusiveCapacityReservationInput = Readonly<{
    initialLogicalRecordKeyPrefixes: readonly string[];
    maximumAdditionalAuthenticatedRepairHeadPlaintextByteLength: number;
    maximumAdditionalOwnedRecordCount: number;
    maximumAdditionalStoredValueByteLength: number;
    maximumDeletionBatchRecordCount: number;
}>;

export type IdentifierKind = 'lease' | 'transaction';
export type IdentifierFactory = (kind: IdentifierKind) => string;

export type UntrustedStorageTransactionStoreBaseConfiguration = Readonly<{
    adapter: UntrustedStorageAdapter;
    namespace: string;
    limits: UntrustedStorageTransactionLimits;
    createIdentifier?: IdentifierFactory;
    monotonicClockMilliseconds?: () => number;
}>;

export type UntrustedStorageAuthenticatedRepairProtection = Readonly<{
    deriveDigest(bytes: Uint8Array): Promise<Uint8Array> | Uint8Array;
    open(sealedHeadBytes: Uint8Array): Promise<Uint8Array>;
    repairIdentity: Uint8Array;
    seal(headPlaintext: Uint8Array): Promise<Uint8Array>;
}>;

export type UntrustedStorageTransactionStoreConfiguration =
    UntrustedStorageTransactionStoreBaseConfiguration &
        Readonly<{
            authenticatedRepairProtection: UntrustedStorageAuthenticatedRepairProtection;
        }>;

export const positivelyVerifiedRecordBootstrap = Symbol(
    'positively-verified-record-bootstrap',
);

export type PositivelyVerifiedRecordBootstrapConfiguration =
    UntrustedStorageTransactionStoreBaseConfiguration &
        Readonly<{ [positivelyVerifiedRecordBootstrap]: true }>;

export type StoredAuthenticatedRepairHeadRecord = Readonly<{
    lastTransactionIdentifier: string;
    predecessorHeadDigest: string;
    recordVersion: number;
    records: ReadonlyMap<
        string,
        Readonly<{ objectKey: string; sealedValueDigest: string }>
    >;
    repairIdentity: string;
    transitionSequence: bigint;
}>;

export type AuthenticatedRepairPublication = Readonly<{
    head: StoredAuthenticatedRepairHeadRecord;
    sealedHeadBytes: Uint8Array;
}>;

export type AuthenticatedRepairRuntime = {
    currentHead: StoredAuthenticatedRepairHeadRecord | undefined;
    currentSealedHeadBytes: Uint8Array | undefined;
    expectedRepairIdentity: string;
    initialized: boolean;
    readonly protection: UntrustedStorageAuthenticatedRepairProtection;
};

export type LeaseRecord = {
    declaredByteLength: number;
    expectedExistingObjectValue: Uint8Array | undefined;
    expectedIndexValue: Uint8Array | undefined;
    existingObjectKey: string | undefined;
    indexKey: string;
    indexValueGrowthByteLength: number;
    logicalRecordKey: string;
    objectKey: string;
    authenticate: UntrustedStorageAuthenticator | undefined;
    state: UntrustedStorageLeaseState;
};

type DeletionRecord = {
    expectedExistingObjectValue: Uint8Array | undefined;
    expectedIndexValue: Uint8Array | undefined;
    existingObjectKey: string | undefined;
    indexKey: string;
    logicalRecordKey: string;
};

export type TransactionChange =
    | Readonly<{ kind: 'write'; lease: LeaseRecord }>
    | Readonly<{ kind: 'delete'; deletion: DeletionRecord }>;

type TransactionState =
    | 'active'
    | 'aborting'
    | 'aborted'
    | 'closed-after-failure'
    | 'committed-unverified'
    | 'committed';

export type TransactionRecord = {
    authenticatedRepairPublication: AuthenticatedRepairPublication | undefined;
    capacityReservationIdentifier: symbol | undefined;
    changes: Map<string, TransactionChange>;
    expiresAtMilliseconds: number;
    failurePublicationDisposition:
        | UntrustedStoragePublicationDisposition
        | undefined;
    identifier: string;
    pendingCleanupObjectKeys: Set<string>;
    state: TransactionState;
    totalDeclaredByteLength: number;
};

export type ExclusiveCapacityReservationRecord = {
    readonly identifier: symbol;
    readonly logicalRecordKeyPrefixes: Set<string>;
    readonly maximumDeletionBatchRecordCount: number;
    released: boolean;
};

export const isUint8Array = (value: unknown): value is Uint8Array =>
    ArrayBuffer.isView(value) &&
    Object.prototype.toString.call(value) === '[object Uint8Array]';

const hexToExactBytes = (
    encodedBytes: string,
    expectedByteLength: number,
    label: string,
): Uint8Array => {
    if (
        !Number.isInteger(expectedByteLength) ||
        expectedByteLength < 0 ||
        encodedBytes.length !== expectedByteLength * 2 ||
        !/^[0-9a-f]+$/u.test(encodedBytes)
    ) {
        throw new UntrustedStorageTransactionError(
            'AuthenticationFailed',
            `${label} is not canonical lowercase hexadecimal bytes.`,
        );
    }
    const bytes = new Uint8Array(expectedByteLength);
    for (let byteIndex = 0; byteIndex < bytes.byteLength; byteIndex += 1) {
        bytes[byteIndex] = Number.parseInt(
            encodedBytes.slice(byteIndex * 2, byteIndex * 2 + 2),
            16,
        );
    }
    return bytes;
};

const compareBytesLexicographically = (
    left: Uint8Array,
    right: Uint8Array,
): number => {
    const sharedLength = Math.min(left.byteLength, right.byteLength);
    for (let byteIndex = 0; byteIndex < sharedLength; byteIndex += 1) {
        const difference = left[byteIndex] - right[byteIndex];
        if (difference !== 0) {
            return difference;
        }
    }
    return left.byteLength - right.byteLength;
};

export const encodeAuthenticatedRepairHead = (
    head: StoredAuthenticatedRepairHeadRecord,
): Uint8Array => {
    if (
        head.recordVersion !== authenticatedRepairHeadRecordVersion ||
        head.transitionSequence === 0n ||
        head.transitionSequence > maximumUnsigned64 ||
        head.records.size > 0xffff_ffff
    ) {
        throw new UntrustedStorageTransactionError(
            'AuthenticationFailed',
            'authenticated repair head fields are outside the binary profile.',
        );
    }
    const lastTransactionIdentifier = hexToExactBytes(
        head.lastTransactionIdentifier,
        identifierByteLength,
        'authenticated repair transaction identifier',
    );
    const predecessorHeadDigest = hexToExactBytes(
        head.predecessorHeadDigest,
        64,
        'authenticated repair predecessor digest',
    );
    const repairIdentity = hexToExactBytes(
        head.repairIdentity,
        64,
        'authenticated repair identity',
    );
    let previousLogicalRecordKey: Uint8Array | undefined;
    const encodedRecords = [...head.records.entries()].map(
        ([logicalRecordKeyHex, record]) => {
            const logicalRecordKey = hexToExactBytes(
                logicalRecordKeyHex,
                logicalRecordKeyHex.length / 2,
                'authenticated repair logical record key',
            );
            const objectKey = textEncoder.encode(record.objectKey);
            let decodedLogicalRecordKey: string;
            try {
                decodedLogicalRecordKey =
                    fatalTextDecoder.decode(logicalRecordKey);
            } catch (error) {
                throw new UntrustedStorageTransactionError(
                    'AuthenticationFailed',
                    'authenticated repair logical record key is not valid UTF-8.',
                    error,
                );
            }
            if (
                logicalRecordKey.byteLength === 0 ||
                logicalRecordKey.byteLength >
                    maximumLogicalRecordKeyByteLength ||
                objectKey.byteLength === 0 ||
                objectKey.byteLength > 0xffff ||
                !bytesEqual(
                    textEncoder.encode(decodedLogicalRecordKey),
                    logicalRecordKey,
                ) ||
                fatalTextDecoder.decode(objectKey) !== record.objectKey
            ) {
                throw new UntrustedStorageTransactionError(
                    'AuthenticationFailed',
                    'authenticated repair record keys are outside the binary profile.',
                );
            }
            if (
                previousLogicalRecordKey !== undefined &&
                compareBytesLexicographically(
                    previousLogicalRecordKey,
                    logicalRecordKey,
                ) >= 0
            ) {
                throw new UntrustedStorageTransactionError(
                    'AuthenticationFailed',
                    'authenticated repair records are not strictly ordered.',
                );
            }
            previousLogicalRecordKey = logicalRecordKey;
            const sealedValueDigest = hexToExactBytes(
                record.sealedValueDigest,
                64,
                'authenticated repair sealed-value digest',
            );
            return {
                logicalRecordKey,
                objectKey,
                sealedValueDigest,
            };
        },
    );
    let byteLength = authenticatedRepairHeadFixedByteLength;
    for (const record of encodedRecords) {
        byteLength +=
            2 +
            record.logicalRecordKey.byteLength +
            2 +
            record.objectKey.byteLength +
            record.sealedValueDigest.byteLength;
        if (!Number.isSafeInteger(byteLength)) {
            throw new UntrustedStorageTransactionError(
                'MalformedLength',
                'authenticated repair head byte length overflowed.',
            );
        }
    }
    const bytes = new Uint8Array(byteLength);
    const view = new DataView(bytes.buffer);
    let offset = 0;
    bytes.set(authenticatedRepairHeadMagic, offset);
    offset += authenticatedRepairHeadMagic.byteLength;
    view.setUint16(offset, head.recordVersion, true);
    offset += 2;
    view.setBigUint64(offset, head.transitionSequence, true);
    offset += 8;
    bytes.set(lastTransactionIdentifier, offset);
    offset += lastTransactionIdentifier.byteLength;
    bytes.set(predecessorHeadDigest, offset);
    offset += predecessorHeadDigest.byteLength;
    bytes.set(repairIdentity, offset);
    offset += repairIdentity.byteLength;
    view.setUint32(offset, encodedRecords.length, true);
    offset += 4;
    for (const record of encodedRecords) {
        view.setUint16(offset, record.logicalRecordKey.byteLength, true);
        offset += 2;
        bytes.set(record.logicalRecordKey, offset);
        offset += record.logicalRecordKey.byteLength;
        view.setUint16(offset, record.objectKey.byteLength, true);
        offset += 2;
        bytes.set(record.objectKey, offset);
        offset += record.objectKey.byteLength;
        bytes.set(record.sealedValueDigest, offset);
        offset += record.sealedValueDigest.byteLength;
    }
    lastTransactionIdentifier.fill(0);
    predecessorHeadDigest.fill(0);
    repairIdentity.fill(0);
    for (const record of encodedRecords) {
        record.logicalRecordKey.fill(0);
        record.objectKey.fill(0);
        record.sealedValueDigest.fill(0);
    }
    return bytes;
};

export const assertSafeNonNegativeInteger = (
    value: number,
    label: string,
): void => {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new UntrustedStorageTransactionError(
            'MalformedLength',
            `${label} must be a non-negative safe integer.`,
        );
    }
};

export const assertSafePositiveInteger = (
    value: number,
    label: string,
): void => {
    if (!Number.isSafeInteger(value) || value <= 0) {
        throw new UntrustedStorageTransactionError(
            'MalformedLength',
            `${label} must be a positive safe integer.`,
        );
    }
};

export const checkedAdd = (
    left: number,
    right: number,
    label: string,
): number => {
    const result = left + right;
    if (!Number.isSafeInteger(result)) {
        throw new UntrustedStorageTransactionError(
            'MalformedLength',
            `${label} exceeds the safe integer range.`,
        );
    }

    return result;
};

export const bytesEqual = (
    left: Uint8Array | undefined,
    right: Uint8Array | undefined,
): boolean => {
    if (left === undefined || right === undefined) {
        return left === right;
    }
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

export const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

export const createWebCryptoIdentifier: IdentifierFactory = () => {
    const cryptoProvider = globalThis.crypto;
    if (cryptoProvider === undefined) {
        throw new UntrustedStorageTransactionError(
            'AdapterFailure',
            'Web Crypto getRandomValues is required for storage identifiers.',
        );
    }
    const identifierBytes = new Uint8Array(identifierByteLength);
    cryptoProvider.getRandomValues(identifierBytes);

    return bytesToHex(identifierBytes);
};

export const defaultMonotonicClockMilliseconds = (): number => {
    const monotonicClock = globalThis.performance;
    if (monotonicClock === undefined) {
        throw new UntrustedStorageTransactionError(
            'AdapterFailure',
            'A monotonic performance clock is required for storage leases.',
        );
    }

    return monotonicClock.now();
};

export const assertLimits = (
    limits: UntrustedStorageTransactionLimits,
): void => {
    assertSafePositiveInteger(
        limits.maximumActiveTransactionCount,
        'maximumActiveTransactionCount',
    );
    assertSafePositiveInteger(
        limits.maximumLeaseByteLength,
        'maximumLeaseByteLength',
    );
    assertSafePositiveInteger(
        limits.maximumLeaseCountPerTransaction,
        'maximumLeaseCountPerTransaction',
    );
    assertSafePositiveInteger(
        limits.maximumOwnedRecordCount,
        'maximumOwnedRecordCount',
    );
    assertSafePositiveInteger(
        limits.maximumStoredValueByteLength,
        'maximumStoredValueByteLength',
    );
    assertSafePositiveInteger(
        limits.maximumTransactionByteLength,
        'maximumTransactionByteLength',
    );
    assertSafePositiveInteger(
        limits.maximumTransactionLifetimeMilliseconds,
        'maximumTransactionLifetimeMilliseconds',
    );
    if (limits.maximumLeaseByteLength > limits.maximumTransactionByteLength) {
        throw new UntrustedStorageTransactionError(
            'MalformedLength',
            'maximumLeaseByteLength must not exceed maximumTransactionByteLength.',
        );
    }
};

export const assertIdentifier = (
    identifier: string,
    kind: IdentifierKind,
): void => {
    if (typeof identifier !== 'string' || !identifierPattern.test(identifier)) {
        throw new UntrustedStorageTransactionError(
            'AdapterFailure',
            `${kind} identifier must be the canonical lowercase hexadecimal encoding of exactly ${identifierByteLength} bytes.`,
        );
    }
};

export const assertLogicalRecordKey = (
    logicalRecordKey: string,
): Uint8Array => {
    const keyBytes = textEncoder.encode(logicalRecordKey);
    if (
        keyBytes.byteLength === 0 ||
        keyBytes.byteLength > maximumLogicalRecordKeyByteLength ||
        fatalTextDecoder.decode(keyBytes) !== logicalRecordKey
    ) {
        throw new UntrustedStorageTransactionError(
            'MalformedLength',
            `logicalRecordKey must be a well-formed string encoding between 1 and ${maximumLogicalRecordKeyByteLength} UTF-8 bytes.`,
        );
    }

    return keyBytes;
};

export const logicalRecordKeyHex = (logicalRecordKey: string): string =>
    bytesToHex(assertLogicalRecordKey(logicalRecordKey));

export const logicalRecordKeyFromHex = (
    encodedLogicalRecordKey: string,
): string => {
    const encodedByteLength = encodedLogicalRecordKey.length / 2;
    const logicalRecordKeyBytes = hexToExactBytes(
        encodedLogicalRecordKey,
        encodedByteLength,
        'authenticated repair logical record key',
    );
    try {
        const logicalRecordKey = fatalTextDecoder.decode(logicalRecordKeyBytes);
        if (
            !bytesEqual(
                textEncoder.encode(logicalRecordKey),
                logicalRecordKeyBytes,
            ) ||
            logicalRecordKeyHex(logicalRecordKey) !== encodedLogicalRecordKey
        ) {
            throw new UntrustedStorageTransactionError(
                'AuthenticationFailed',
                'authenticated repair logical record key is not canonical UTF-8.',
            );
        }
        return logicalRecordKey;
    } catch (error) {
        if (error instanceof UntrustedStorageTransactionError) {
            throw error;
        }
        throw new UntrustedStorageTransactionError(
            'AuthenticationFailed',
            'authenticated repair logical record key is not valid UTF-8.',
            error,
        );
    } finally {
        logicalRecordKeyBytes.fill(0);
    }
};

export const decodeAuthenticatedRepairHead = (input: {
    bytes: Uint8Array;
    maximumRecordCount: number;
    maximumObjectKeyByteLength: number;
}): StoredAuthenticatedRepairHeadRecord => {
    if (input.bytes.byteLength < authenticatedRepairHeadFixedByteLength) {
        throw new UntrustedStorageTransactionError(
            'AuthenticationFailed',
            'authenticated repair head is truncated.',
        );
    }
    const view = new DataView(
        input.bytes.buffer,
        input.bytes.byteOffset,
        input.bytes.byteLength,
    );
    let offset = 0;
    const readBytes = (byteLength: number, label: string): Uint8Array => {
        if (
            !Number.isSafeInteger(byteLength) ||
            byteLength < 0 ||
            offset + byteLength > input.bytes.byteLength
        ) {
            throw new UntrustedStorageTransactionError(
                'AuthenticationFailed',
                `authenticated repair head ${label} is truncated.`,
            );
        }
        const bytes = input.bytes.slice(offset, offset + byteLength);
        offset += byteLength;
        return bytes;
    };
    const magic = readBytes(authenticatedRepairHeadMagic.byteLength, 'magic');
    if (!bytesEqual(magic, authenticatedRepairHeadMagic)) {
        throw new UntrustedStorageTransactionError(
            'AuthenticationFailed',
            'authenticated repair head has the wrong binary type.',
        );
    }
    const recordVersion = view.getUint16(offset, true);
    offset += 2;
    const transitionSequence = view.getBigUint64(offset, true);
    offset += 8;
    const lastTransactionIdentifier = bytesToHex(
        readBytes(identifierByteLength, 'transaction identifier'),
    );
    const predecessorHeadDigest = bytesToHex(
        readBytes(64, 'predecessor digest'),
    );
    const repairIdentity = bytesToHex(readBytes(64, 'repair identity'));
    const recordCount = view.getUint32(offset, true);
    offset += 4;
    if (
        recordVersion !== authenticatedRepairHeadRecordVersion ||
        transitionSequence === 0n ||
        recordCount > input.maximumRecordCount
    ) {
        throw new UntrustedStorageTransactionError(
            'AuthenticationFailed',
            'authenticated repair head is outside the binary profile.',
        );
    }
    const records = new Map<
        string,
        Readonly<{ objectKey: string; sealedValueDigest: string }>
    >();
    let previousLogicalRecordKey: Uint8Array | undefined;
    for (let recordIndex = 0; recordIndex < recordCount; recordIndex += 1) {
        if (offset + 2 > input.bytes.byteLength) {
            throw new UntrustedStorageTransactionError(
                'AuthenticationFailed',
                'authenticated repair head record key length is truncated.',
            );
        }
        const logicalRecordKeyByteLength = view.getUint16(offset, true);
        offset += 2;
        if (
            logicalRecordKeyByteLength === 0 ||
            logicalRecordKeyByteLength > maximumLogicalRecordKeyByteLength
        ) {
            throw new UntrustedStorageTransactionError(
                'AuthenticationFailed',
                'authenticated repair head record key length is invalid.',
            );
        }
        const logicalRecordKey = readBytes(
            logicalRecordKeyByteLength,
            'logical record key',
        );
        if (
            previousLogicalRecordKey !== undefined &&
            compareBytesLexicographically(
                previousLogicalRecordKey,
                logicalRecordKey,
            ) >= 0
        ) {
            throw new UntrustedStorageTransactionError(
                'AuthenticationFailed',
                'authenticated repair head record inventory is not strictly ordered.',
            );
        }
        let logicalRecordKeyText: string;
        try {
            logicalRecordKeyText = fatalTextDecoder.decode(logicalRecordKey);
        } catch (error) {
            throw new UntrustedStorageTransactionError(
                'AuthenticationFailed',
                'authenticated repair head record key is not valid UTF-8.',
                error,
            );
        }
        if (
            !bytesEqual(
                textEncoder.encode(logicalRecordKeyText),
                logicalRecordKey,
            )
        ) {
            throw new UntrustedStorageTransactionError(
                'AuthenticationFailed',
                'authenticated repair head record key is not canonical UTF-8.',
            );
        }
        if (offset + 2 > input.bytes.byteLength) {
            throw new UntrustedStorageTransactionError(
                'AuthenticationFailed',
                'authenticated repair head object-key length is truncated.',
            );
        }
        const objectKeyByteLength = view.getUint16(offset, true);
        offset += 2;
        if (
            objectKeyByteLength === 0 ||
            objectKeyByteLength > input.maximumObjectKeyByteLength
        ) {
            throw new UntrustedStorageTransactionError(
                'AuthenticationFailed',
                'authenticated repair head object-key length is invalid.',
            );
        }
        const objectKeyBytes = readBytes(objectKeyByteLength, 'object key');
        let objectKey: string;
        try {
            objectKey = fatalTextDecoder.decode(objectKeyBytes);
        } catch (error) {
            throw new UntrustedStorageTransactionError(
                'AuthenticationFailed',
                'authenticated repair head object key is not valid UTF-8.',
                error,
            );
        }
        if (!bytesEqual(textEncoder.encode(objectKey), objectKeyBytes)) {
            throw new UntrustedStorageTransactionError(
                'AuthenticationFailed',
                'authenticated repair head object key is not canonical UTF-8.',
            );
        }
        const decodedLogicalRecordKeyHex = bytesToHex(logicalRecordKey);
        records.set(
            decodedLogicalRecordKeyHex,
            Object.freeze({
                objectKey,
                sealedValueDigest: bytesToHex(
                    readBytes(64, 'sealed-value digest'),
                ),
            }),
        );
        previousLogicalRecordKey = logicalRecordKey;
    }
    if (offset !== input.bytes.byteLength) {
        throw new UntrustedStorageTransactionError(
            'AuthenticationFailed',
            'authenticated repair head has trailing bytes.',
        );
    }
    const head = Object.freeze({
        lastTransactionIdentifier,
        predecessorHeadDigest,
        recordVersion,
        records,
        repairIdentity,
        transitionSequence,
    });
    if (!bytesEqual(input.bytes, encodeAuthenticatedRepairHead(head))) {
        throw new UntrustedStorageTransactionError(
            'AuthenticationFailed',
            'authenticated repair head is not canonically encoded.',
        );
    }

    return head;
};

export const createAuthenticatedRepairRuntime = (
    protection: UntrustedStorageAuthenticatedRepairProtection,
): AuthenticatedRepairRuntime => {
    if (
        !isUint8Array(protection.repairIdentity) ||
        protection.repairIdentity.byteLength !== 64 ||
        protection.repairIdentity.every((byte) => byte === 0) ||
        typeof protection.deriveDigest !== 'function' ||
        typeof protection.open !== 'function' ||
        typeof protection.seal !== 'function'
    ) {
        throw new UntrustedStorageTransactionError(
            'MalformedLength',
            'authenticated repair protection has an invalid identity or callback.',
        );
    }
    const repairIdentity = protection.repairIdentity.slice();
    const expectedRepairIdentity = bytesToHex(repairIdentity);
    const configuredProtection = Object.freeze({
        deriveDigest: protection.deriveDigest,
        open: protection.open,
        repairIdentity,
        seal: protection.seal,
    });

    return {
        currentHead: undefined,
        currentSealedHeadBytes: undefined,
        expectedRepairIdentity,
        initialized: false,
        protection: configuredProtection,
    };
};
