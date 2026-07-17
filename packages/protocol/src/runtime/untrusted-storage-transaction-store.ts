import { sha512 } from '@noble/hashes/sha2.js';

const textEncoder = new TextEncoder();
const fatalTextDecoder = new TextDecoder('utf-8', { fatal: true });
const maximumLogicalRecordKeyByteLength = 1024;
const identifierByteLength = 32;
const encodedIdentifierCharacterLength = identifierByteLength * 2;
const identifierPattern = /^[0-9a-f]{64}$/u;
const namespacePattern = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;
const maximumUnsigned64 = 0xffff_ffff_ffff_ffffn;
const authenticatedRepairHeadRecordVersion = 1;
const authenticatedRepairHeadMagic = Uint8Array.of(0x53, 0x4c, 0x52, 0x48);
const authenticatedRepairHeadFixedByteLength =
    authenticatedRepairHeadMagic.byteLength +
    2 +
    8 +
    identifierByteLength +
    64 +
    64 +
    4;
const authorizedEmptyHeadDigestDomain = textEncoder.encode(
    'sealed-lattice/authenticated-storage-empty-head/v1',
);
const storageInstanceIdentityDomain = textEncoder.encode(
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

type UntrustedStorageExclusiveCapacityReservationInput = Readonly<{
    initialLogicalRecordKeyPrefixes: readonly string[];
    maximumAdditionalAuthenticatedRepairHeadPlaintextByteLength: number;
    maximumAdditionalOwnedRecordCount: number;
    maximumAdditionalStoredValueByteLength: number;
    maximumDeletionBatchRecordCount: number;
}>;

type IdentifierKind = 'lease' | 'transaction';
type IdentifierFactory = (kind: IdentifierKind) => string;

type UntrustedStorageTransactionStoreBaseConfiguration = Readonly<{
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

const positivelyVerifiedRecordBootstrap = Symbol(
    'positively-verified-record-bootstrap',
);

type PositivelyVerifiedRecordBootstrapConfiguration =
    UntrustedStorageTransactionStoreBaseConfiguration &
        Readonly<{ [positivelyVerifiedRecordBootstrap]: true }>;

type StoredAuthenticatedRepairHeadRecord = Readonly<{
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

type AuthenticatedRepairPublication = Readonly<{
    head: StoredAuthenticatedRepairHeadRecord;
    sealedHeadBytes: Uint8Array;
}>;

type AuthenticatedRepairRuntime = {
    currentHead: StoredAuthenticatedRepairHeadRecord | undefined;
    currentSealedHeadBytes: Uint8Array | undefined;
    expectedRepairIdentity: string;
    initialized: boolean;
    readonly protection: UntrustedStorageAuthenticatedRepairProtection;
};

type LeaseRecord = {
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

type TransactionChange =
    | Readonly<{ kind: 'write'; lease: LeaseRecord }>
    | Readonly<{ kind: 'delete'; deletion: DeletionRecord }>;

type TransactionState =
    | 'active'
    | 'aborting'
    | 'aborted'
    | 'closed-after-failure'
    | 'committed-unverified'
    | 'committed';

type TransactionRecord = {
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

type ExclusiveCapacityReservationRecord = {
    readonly identifier: symbol;
    readonly logicalRecordKeyPrefixes: Set<string>;
    readonly maximumDeletionBatchRecordCount: number;
    released: boolean;
};

const isUint8Array = (value: unknown): value is Uint8Array =>
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

const encodeAuthenticatedRepairHead = (
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

const assertSafeNonNegativeInteger = (value: number, label: string): void => {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new UntrustedStorageTransactionError(
            'MalformedLength',
            `${label} must be a non-negative safe integer.`,
        );
    }
};

const assertSafePositiveInteger = (value: number, label: string): void => {
    if (!Number.isSafeInteger(value) || value <= 0) {
        throw new UntrustedStorageTransactionError(
            'MalformedLength',
            `${label} must be a positive safe integer.`,
        );
    }
};

const checkedAdd = (left: number, right: number, label: string): number => {
    const result = left + right;
    if (!Number.isSafeInteger(result)) {
        throw new UntrustedStorageTransactionError(
            'MalformedLength',
            `${label} exceeds the safe integer range.`,
        );
    }

    return result;
};

const bytesEqual = (
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

const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const createWebCryptoIdentifier: IdentifierFactory = () => {
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

const defaultMonotonicClockMilliseconds = (): number => {
    const monotonicClock = globalThis.performance;
    if (monotonicClock === undefined) {
        throw new UntrustedStorageTransactionError(
            'AdapterFailure',
            'A monotonic performance clock is required for storage leases.',
        );
    }

    return monotonicClock.now();
};

const assertLimits = (limits: UntrustedStorageTransactionLimits): void => {
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

const assertIdentifier = (identifier: string, kind: IdentifierKind): void => {
    if (typeof identifier !== 'string' || !identifierPattern.test(identifier)) {
        throw new UntrustedStorageTransactionError(
            'AdapterFailure',
            `${kind} identifier must be the canonical lowercase hexadecimal encoding of exactly ${identifierByteLength} bytes.`,
        );
    }
};

const assertLogicalRecordKey = (logicalRecordKey: string): Uint8Array => {
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

const logicalRecordKeyHex = (logicalRecordKey: string): string =>
    bytesToHex(assertLogicalRecordKey(logicalRecordKey));

const logicalRecordKeyFromHex = (encodedLogicalRecordKey: string): string => {
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

const decodeAuthenticatedRepairHead = (input: {
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

const createAuthenticatedRepairRuntime = (
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

export class UntrustedStorageTransactionStore {
    readonly #adapter: UntrustedStorageAdapter;
    readonly #createIdentifier: IdentifierFactory;
    readonly #limits: UntrustedStorageTransactionLimits;
    readonly #monotonicClockMilliseconds: () => number;
    readonly #rootPrefix: string;
    readonly #indexPrefix: string;
    readonly #maximumIndexValueByteLength: number;
    readonly #maximumOwnedKeyCharacterLength: number;
    readonly #objectPrefix: string;
    readonly #repairHeadKey: string;
    readonly #repairPrefix: string;
    readonly #transactions = new Map<string, TransactionRecord>();
    readonly #issuedIdentifiers: Readonly<Record<IdentifierKind, Set<string>>> =
        {
            lease: new Set<string>(),
            transaction: new Set<string>(),
        };
    #exclusiveCapacityReservation:
        | ExclusiveCapacityReservationRecord
        | undefined;
    #exclusiveOperationTail: Promise<void> = Promise.resolve();
    readonly #authenticatedRepair: AuthenticatedRepairRuntime | undefined;
    readonly #storageInstanceIdentity: Uint8Array | undefined;

    public constructor(
        configuration:
            | UntrustedStorageTransactionStoreConfiguration
            | PositivelyVerifiedRecordBootstrapConfiguration,
    ) {
        if (
            configuration.namespace.length > 64 ||
            !namespacePattern.test(configuration.namespace)
        ) {
            throw new UntrustedStorageTransactionError(
                'MalformedLength',
                'storage namespace must be lowercase kebab-case with at most 64 characters.',
            );
        }
        assertLimits(configuration.limits);
        this.#adapter = configuration.adapter;
        this.#createIdentifier =
            configuration.createIdentifier ?? createWebCryptoIdentifier;
        this.#limits = configuration.limits;
        this.#monotonicClockMilliseconds =
            configuration.monotonicClockMilliseconds ??
            defaultMonotonicClockMilliseconds;
        this.#rootPrefix = `sealed-lattice-runtime-store/${configuration.namespace}/`;
        this.#indexPrefix = `${this.#rootPrefix}indices/`;
        this.#objectPrefix = `${this.#rootPrefix}objects/`;
        this.#repairPrefix = `${this.#rootPrefix}repair/`;
        this.#repairHeadKey = `${this.#repairPrefix}current-head`;
        this.#maximumIndexValueByteLength =
            textEncoder.encode(this.#objectPrefix).byteLength +
            encodedIdentifierCharacterLength +
            1 +
            encodedIdentifierCharacterLength;
        this.#maximumOwnedKeyCharacterLength = Math.max(
            this.#indexPrefix.length + maximumLogicalRecordKeyByteLength * 2,
            this.#maximumIndexValueByteLength,
            this.#repairHeadKey.length,
        );
        this.#authenticatedRepair =
            positivelyVerifiedRecordBootstrap in configuration
                ? undefined
                : createAuthenticatedRepairRuntime(
                      configuration.authenticatedRepairProtection,
                  );
        this.#storageInstanceIdentity =
            this.#authenticatedRepair === undefined
                ? undefined
                : this.#deriveStorageInstanceIdentity(
                      this.#authenticatedRepair.protection.repairIdentity,
                  );
    }

    public copyStorageInstanceIdentity(): Uint8Array {
        if (this.#storageInstanceIdentity === undefined) {
            throw new UntrustedStorageTransactionError(
                'InvalidState',
                'A storage instance identity requires authenticated repair protection.',
            );
        }
        return this.#storageInstanceIdentity.slice();
    }

    public async repair(): Promise<UntrustedStorageRepairReport> {
        return this.#runExclusive(async () => {
            if (this.#transactions.size !== 0) {
                throw new UntrustedStorageTransactionError(
                    'InvalidState',
                    'repair requires exclusive ownership with no live transactions.',
                );
            }

            const authenticatedCleanupCount =
                await this.#ensureAuthenticatedRepairReady();

            const indexKeys = await this.#listedKeys(this.#indexPrefix);
            const objectKeys = await this.#listedKeys(this.#objectPrefix);
            const repairKeys = await this.#listedKeys(this.#repairPrefix);
            if (
                repairKeys.length > 1 ||
                (repairKeys.length === 1 &&
                    repairKeys[0] !== this.#repairHeadKey)
            ) {
                throw new UntrustedStorageTransactionError(
                    'AdapterFailure',
                    'storage repair namespace contains an unexpected record.',
                );
            }
            if (
                indexKeys.length + objectKeys.length + repairKeys.length >
                this.#limits.maximumOwnedRecordCount
            ) {
                throw new UntrustedStorageTransactionError(
                    'QuotaExceeded',
                    'owned storage record count exceeds maximumOwnedRecordCount.',
                );
            }
            const objectKeySet = new Set(objectKeys);
            const referencedObjectToIndexKeys = new Map<string, string[]>();
            const corruptIndexKeys = new Set<string>();

            for (const indexKey of indexKeys) {
                const indexValue =
                    await this.#requiredListedIndexValue(indexKey);
                let objectKey: string;
                try {
                    objectKey = this.#decodeIndexValue(indexValue);
                } catch (error) {
                    if (
                        error instanceof UntrustedStorageTransactionError &&
                        error.code === 'CorruptIndex'
                    ) {
                        corruptIndexKeys.add(indexKey);
                        continue;
                    }
                    throw error;
                }
                if (!objectKeySet.has(objectKey)) {
                    corruptIndexKeys.add(indexKey);
                    continue;
                }
                const referencingIndexKeys =
                    referencedObjectToIndexKeys.get(objectKey) ?? [];
                referencingIndexKeys.push(indexKey);
                referencedObjectToIndexKeys.set(
                    objectKey,
                    referencingIndexKeys,
                );
            }

            for (const referencingIndexKeys of referencedObjectToIndexKeys.values()) {
                if (referencingIndexKeys.length > 1) {
                    for (const indexKey of referencingIndexKeys) {
                        corruptIndexKeys.add(indexKey);
                    }
                }
            }

            if (corruptIndexKeys.size > 0) {
                throw new UntrustedStorageTransactionError(
                    'CorruptIndex',
                    'storage repair found a malformed, dangling, or aliased committed index.',
                );
            }

            const retainedObjectKeys = new Set<string>();
            for (const [
                objectKey,
                referencingIndexKeys,
            ] of referencedObjectToIndexKeys) {
                if (referencingIndexKeys.length === 1) {
                    retainedObjectKeys.add(objectKey);
                }
            }
            const unreferencedObjectKeys = objectKeys.filter(
                (objectKey) => !retainedObjectKeys.has(objectKey),
            );
            const authenticatedHeadIsPresent = repairKeys.length === 1;
            if (!authenticatedHeadIsPresent) {
                await this.#deleteUnreferencedObjects(
                    unreferencedObjectKeys,
                    'repair cleanup',
                );
            }

            return {
                removedCorruptIndexCount: 0,
                removedUnreferencedObjectCount:
                    authenticatedCleanupCount +
                    (authenticatedHeadIsPresent
                        ? 0
                        : unreferencedObjectKeys.length),
                retainedObjectCount: retainedObjectKeys.size,
                storedValueByteLength:
                    await this.#measureStoredValueByteLength(),
            };
        });
    }

    public async reserveExclusiveCapacity(
        input: UntrustedStorageExclusiveCapacityReservationInput,
    ): Promise<UntrustedStorageExclusiveCapacityReservation> {
        const reservation = await this.#runExclusive(async () => {
            await this.#ensureAuthenticatedRepairReady();
            if (
                this.#authenticatedRepair === undefined ||
                this.#authenticatedRepair.currentHead === undefined ||
                this.#authenticatedRepair.currentSealedHeadBytes === undefined
            ) {
                throw new UntrustedStorageTransactionError(
                    'InvalidState',
                    'exclusive capacity reservation requires an authenticated repair head.',
                );
            }
            if (
                this.#exclusiveCapacityReservation !== undefined ||
                this.#transactions.size !== 0
            ) {
                throw new UntrustedStorageTransactionError(
                    'Conflict',
                    'exclusive capacity reservation requires no other reservation or live transaction.',
                );
            }
            assertSafeNonNegativeInteger(
                input.maximumAdditionalAuthenticatedRepairHeadPlaintextByteLength,
                'maximumAdditionalAuthenticatedRepairHeadPlaintextByteLength',
            );
            assertSafeNonNegativeInteger(
                input.maximumAdditionalOwnedRecordCount,
                'maximumAdditionalOwnedRecordCount',
            );
            assertSafeNonNegativeInteger(
                input.maximumAdditionalStoredValueByteLength,
                'maximumAdditionalStoredValueByteLength',
            );
            assertSafePositiveInteger(
                input.maximumDeletionBatchRecordCount,
                'maximumDeletionBatchRecordCount',
            );
            if (
                input.maximumDeletionBatchRecordCount >
                this.#limits.maximumLeaseCountPerTransaction
            ) {
                throw new UntrustedStorageTransactionError(
                    'QuotaExceeded',
                    'exclusive deletion batches exceed maximumLeaseCountPerTransaction.',
                );
            }
            const untrustedLogicalRecordKeyPrefixes: unknown =
                input.initialLogicalRecordKeyPrefixes;
            if (
                !Array.isArray(untrustedLogicalRecordKeyPrefixes) ||
                untrustedLogicalRecordKeyPrefixes.length === 0
            ) {
                throw new UntrustedStorageTransactionError(
                    'MalformedLength',
                    'exclusive capacity reservation requires at least one logical-record prefix.',
                );
            }
            const prefixes = new Set<string>();
            for (const prefix of untrustedLogicalRecordKeyPrefixes) {
                if (typeof prefix !== 'string') {
                    throw new UntrustedStorageTransactionError(
                        'MalformedLength',
                        'exclusive capacity reservation prefixes must be strings.',
                    );
                }
                this.#assertLogicalRecordKeyPrefix(prefix);
                prefixes.add(prefix);
            }
            if (prefixes.size !== untrustedLogicalRecordKeyPrefixes.length) {
                throw new UntrustedStorageTransactionError(
                    'MalformedLength',
                    'exclusive capacity reservation prefixes must be distinct.',
                );
            }

            const repair = this.#authenticatedRepair;
            const currentHead = repair.currentHead;
            const currentSealedHeadBytes = repair.currentSealedHeadBytes;
            if (
                currentHead === undefined ||
                currentSealedHeadBytes === undefined
            ) {
                throw new UntrustedStorageTransactionError(
                    'InvalidState',
                    'exclusive capacity reservation lost its authenticated repair head.',
                );
            }
            const matchingRecordKeys = this.#authenticatedLogicalRecordKeys(
                repair,
                prefixes,
            );
            let matchingStoredValueByteLength = 0;
            for (const logicalRecordKey of matchingRecordKeys) {
                const indexValue = await this.#readOwnedIndexValue(
                    this.#indexKey(logicalRecordKey),
                );
                let objectValue: Uint8Array | undefined;
                try {
                    this.#assertAuthenticatedRepairMapping(
                        logicalRecordKey,
                        indexValue,
                    );
                    if (indexValue === undefined) {
                        throw new UntrustedStorageTransactionError(
                            'AuthenticationFailed',
                            'authenticated capacity inventory references a missing index.',
                        );
                    }
                    const objectKey = this.#decodeIndexValue(indexValue);
                    objectValue = await this.#readOwnedObjectValue(objectKey);
                    if (objectValue === undefined) {
                        throw new UntrustedStorageTransactionError(
                            'AuthenticationFailed',
                            'authenticated capacity inventory references a missing object.',
                        );
                    }
                    await this.#assertAuthenticatedRepairObjectDigest(
                        logicalRecordKey,
                        objectValue,
                    );
                    matchingStoredValueByteLength = checkedAdd(
                        matchingStoredValueByteLength,
                        checkedAdd(
                            indexValue.byteLength,
                            objectValue.byteLength,
                            'authenticated capacity inventory record bytes',
                        ),
                        'authenticated capacity inventory bytes',
                    );
                } finally {
                    indexValue?.fill(0);
                    objectValue?.fill(0);
                }
            }

            const filteredRecords = new Map(currentHead.records);
            for (const logicalRecordKey of matchingRecordKeys) {
                filteredRecords.delete(logicalRecordKeyHex(logicalRecordKey));
            }
            const filteredHead = Object.freeze({
                ...currentHead,
                records: new Map(
                    [...filteredRecords].sort(([left], [right]) =>
                        left.localeCompare(right),
                    ),
                ),
            });
            const currentHeadPlaintext =
                encodeAuthenticatedRepairHead(currentHead);
            const filteredHeadPlaintext =
                encodeAuthenticatedRepairHead(filteredHead);
            const sealedHeadOverheadByteLength =
                currentSealedHeadBytes.byteLength -
                currentHeadPlaintext.byteLength;
            currentHeadPlaintext.fill(0);
            if (sealedHeadOverheadByteLength < 0) {
                filteredHeadPlaintext.fill(0);
                throw new UntrustedStorageTransactionError(
                    'AuthenticationFailed',
                    'authenticated repair protection shortened the canonical head.',
                );
            }
            const reservedHeadByteLength = checkedAdd(
                checkedAdd(
                    filteredHeadPlaintext.byteLength,
                    sealedHeadOverheadByteLength,
                    'reserved authenticated repair head envelope',
                ),
                input.maximumAdditionalAuthenticatedRepairHeadPlaintextByteLength,
                'reserved authenticated repair head bytes',
            );
            filteredHeadPlaintext.fill(0);
            const currentStoredValueByteLength =
                await this.#measureStoredValueByteLength();
            const baselineNonHeadStoredValueByteLength =
                currentStoredValueByteLength -
                matchingStoredValueByteLength -
                currentSealedHeadBytes.byteLength;
            if (baselineNonHeadStoredValueByteLength < 0) {
                throw new UntrustedStorageTransactionError(
                    'AuthenticationFailed',
                    'authenticated capacity inventory exceeds the measured namespace.',
                );
            }
            const requiredStoredValueByteLength = checkedAdd(
                checkedAdd(
                    baselineNonHeadStoredValueByteLength,
                    input.maximumAdditionalStoredValueByteLength,
                    'exclusive stored-value reservation',
                ),
                reservedHeadByteLength,
                'exclusive stored-value reservation',
            );
            const currentOwnedRecordCount = (
                await this.#listedKeys(this.#rootPrefix)
            ).length;
            const baselineOwnedRecordCount =
                currentOwnedRecordCount - matchingRecordKeys.length * 2;
            const requiredOwnedRecordCount = checkedAdd(
                baselineOwnedRecordCount,
                input.maximumAdditionalOwnedRecordCount,
                'exclusive owned-record reservation',
            );
            if (
                requiredStoredValueByteLength >
                    this.#limits.maximumStoredValueByteLength ||
                requiredOwnedRecordCount > this.#limits.maximumOwnedRecordCount
            ) {
                throw new UntrustedStorageTransactionError(
                    'QuotaExceeded',
                    'live storage availability cannot satisfy the exclusive capacity reservation.',
                );
            }
            const record: ExclusiveCapacityReservationRecord = {
                identifier: Symbol('exclusive-capacity-reservation'),
                logicalRecordKeyPrefixes: prefixes,
                maximumDeletionBatchRecordCount:
                    input.maximumDeletionBatchRecordCount,
                released: false,
            };
            this.#exclusiveCapacityReservation = record;
            return record;
        });

        return Object.freeze({
            copyAuthenticatedLogicalRecordKeys: (prefix) =>
                this.#runExclusive(() =>
                    this.#copyExclusiveCapacityReservationRecordKeys(
                        reservation,
                        prefix,
                    ),
                ),
            deleteAuthenticatedLogicalRecords: (prefix) =>
                this.#deleteExclusiveCapacityReservationRecords(
                    reservation,
                    prefix,
                ),
            release: () =>
                this.#runExclusive(() =>
                    this.#releaseExclusiveCapacityReservation(reservation),
                ),
        });
    }

    public async beginTransaction(input: {
        lifetimeMilliseconds: number;
    }): Promise<UntrustedStorageTransaction> {
        return this.#runExclusive(async () => {
            await this.#ensureAuthenticatedRepairReady();
            assertSafePositiveInteger(
                input.lifetimeMilliseconds,
                'lifetimeMilliseconds',
            );
            if (
                input.lifetimeMilliseconds >
                this.#limits.maximumTransactionLifetimeMilliseconds
            ) {
                throw new UntrustedStorageTransactionError(
                    'MalformedLength',
                    'transaction lifetime exceeds maximumTransactionLifetimeMilliseconds.',
                );
            }
            if (
                this.#transactions.size >=
                this.#limits.maximumActiveTransactionCount
            ) {
                throw new UntrustedStorageTransactionError(
                    'QuotaExceeded',
                    'active transaction count exceeds the configured limit.',
                );
            }
            const identifier = this.#issueIdentifier('transaction');
            const objectKeysForIdentifier = await this.#listedKeys(
                `${this.#objectPrefix}${identifier}/`,
            );
            if (objectKeysForIdentifier.length !== 0) {
                throw new UntrustedStorageTransactionError(
                    'AdapterFailure',
                    'transaction identifier collides with stored objects.',
                );
            }
            const now = this.#readMonotonicClockMilliseconds();
            const expiresAtMilliseconds = now + input.lifetimeMilliseconds;
            if (
                !Number.isFinite(expiresAtMilliseconds) ||
                expiresAtMilliseconds > Number.MAX_SAFE_INTEGER
            ) {
                throw new UntrustedStorageTransactionError(
                    'MalformedLength',
                    'transaction expiry exceeds the safe integer range.',
                );
            }
            const transaction: TransactionRecord = {
                authenticatedRepairPublication: undefined,
                capacityReservationIdentifier:
                    this.#exclusiveCapacityReservation?.identifier,
                changes: new Map(),
                expiresAtMilliseconds,
                failurePublicationDisposition: undefined,
                identifier,
                pendingCleanupObjectKeys: new Set(),
                state: 'active',
                totalDeclaredByteLength: 0,
            };
            this.#transactions.set(identifier, transaction);

            return this.#transactionHandle(transaction);
        });
    }

    public async readAuthenticated(input: {
        logicalRecordKey: string;
        authenticate: UntrustedStorageAuthenticator;
    }): Promise<Uint8Array | undefined> {
        return this.#runExclusive(async () => {
            await this.#ensureAuthenticatedRepairReady();
            const indexKey = this.#indexKey(input.logicalRecordKey);
            const indexValue = await this.#readOwnedIndexValue(indexKey);
            this.#assertAuthenticatedRepairMapping(
                input.logicalRecordKey,
                indexValue,
            );
            if (indexValue === undefined) {
                return undefined;
            }
            const objectKey = this.#decodeIndexValue(indexValue);
            const bytes = await this.#readOwnedObjectValue(objectKey);
            if (bytes === undefined) {
                throw new UntrustedStorageTransactionError(
                    'CorruptIndex',
                    'storage index references a missing object.',
                );
            }
            await this.#authenticate(
                input.authenticate,
                input.logicalRecordKey,
                bytes,
            );
            await this.#assertAuthenticatedRepairObjectDigest(
                input.logicalRecordKey,
                bytes,
            );
            const rereadIndexValue = await this.#readOwnedIndexValue(indexKey);
            if (!bytesEqual(indexValue, rereadIndexValue)) {
                throw new UntrustedStorageTransactionError(
                    'Conflict',
                    'storage index changed during authenticated read.',
                );
            }
            await this.#assertAuthenticatedRepairHeadUnchanged();

            return bytes.slice();
        });
    }

    /**
     * Reauthenticates the current committed namespace coordinate. The empty
     * coordinate is explicitly domain-bound; every committed transaction then
     * uses the authenticated repair transition sequence and sealed-head digest.
     */
    public async authenticateCurrentHead(): Promise<UntrustedStorageAuthenticatedHeadSnapshot> {
        return this.#runExclusive(async () => {
            await this.#ensureAuthenticatedRepairReady();
            const repair = this.#authenticatedRepair;
            if (repair === undefined) {
                throw new UntrustedStorageTransactionError(
                    'InvalidState',
                    'authenticated namespace snapshots require authenticated repair protection.',
                );
            }
            await this.#assertAuthenticatedRepairHeadUnchanged();
            const digestInput =
                repair.currentSealedHeadBytes === undefined
                    ? this.#authorizedEmptyHeadDigestInput(repair)
                    : repair.currentSealedHeadBytes.slice();
            let callbackInput: Uint8Array | undefined;
            let derivedDigest: Uint8Array | undefined;
            try {
                callbackInput = digestInput.slice();
                derivedDigest =
                    await repair.protection.deriveDigest(callbackInput);
                if (
                    !isUint8Array(derivedDigest) ||
                    derivedDigest.byteLength !== 64
                ) {
                    throw new UntrustedStorageTransactionError(
                        'AuthenticationFailed',
                        'authenticated namespace head digest has an invalid length.',
                    );
                }
                await this.#assertAuthenticatedRepairHeadUnchanged();
                return Object.freeze({
                    authenticatedHeadDigest: derivedDigest.slice(),
                    namespaceSequence:
                        repair.currentHead?.transitionSequence ?? 0n,
                    storageInstanceIdentity: this.copyStorageInstanceIdentity(),
                });
            } catch (error) {
                if (error instanceof UntrustedStorageTransactionError) {
                    throw error;
                }
                throw new UntrustedStorageTransactionError(
                    'AuthenticationFailed',
                    'authenticated namespace head digest derivation failed.',
                    error,
                );
            } finally {
                digestInput.fill(0);
                callbackInput?.fill(0);
                derivedDigest?.fill(0);
            }
        });
    }

    public async cleanupExpiredTransactions(): Promise<number> {
        return this.#runExclusive(async () => {
            await this.#ensureAuthenticatedRepairReady();
            const now = this.#readMonotonicClockMilliseconds();
            const expiredTransactions = [...this.#transactions.values()]
                .filter(
                    (transaction) =>
                        transaction.state !== 'committed-unverified' &&
                        transaction.state !== 'committed' &&
                        transaction.state !== 'aborted' &&
                        now > transaction.expiresAtMilliseconds,
                )
                .sort((left, right) =>
                    left.identifier.localeCompare(right.identifier),
                );
            for (const transaction of expiredTransactions) {
                await this.#abortTransaction(transaction);
            }

            return expiredTransactions.length;
        });
    }

    #assertLogicalRecordKeyPrefix(prefix: string): void {
        if (typeof prefix !== 'string') {
            throw new UntrustedStorageTransactionError(
                'MalformedLength',
                'logical-record prefix must be a string.',
            );
        }
        const prefixBytes = assertLogicalRecordKey(prefix);
        prefixBytes.fill(0);
    }

    #authenticatedLogicalRecordKeys(
        repair: AuthenticatedRepairRuntime,
        prefixes: ReadonlySet<string>,
        maximumRecordCount = Number.MAX_SAFE_INTEGER,
    ): string[] {
        const head = repair.currentHead;
        if (head === undefined) {
            return [];
        }
        const logicalRecordKeys: string[] = [];
        for (const encodedLogicalRecordKey of head.records.keys()) {
            const logicalRecordKey = logicalRecordKeyFromHex(
                encodedLogicalRecordKey,
            );
            if (
                [...prefixes].some((prefix) =>
                    logicalRecordKey.startsWith(prefix),
                )
            ) {
                logicalRecordKeys.push(logicalRecordKey);
                if (logicalRecordKeys.length === maximumRecordCount) {
                    break;
                }
            }
        }
        return logicalRecordKeys.sort();
    }

    #assertActiveExclusiveCapacityReservation(
        reservation: ExclusiveCapacityReservationRecord,
    ): void {
        if (
            reservation.released ||
            this.#exclusiveCapacityReservation !== reservation
        ) {
            throw new UntrustedStorageTransactionError(
                'InvalidState',
                'exclusive capacity reservation is no longer active.',
            );
        }
    }

    async #copyExclusiveCapacityReservationRecordKeys(
        reservation: ExclusiveCapacityReservationRecord,
        prefix: string,
        maximumRecordCount = Number.MAX_SAFE_INTEGER,
    ): Promise<readonly string[]> {
        this.#assertActiveExclusiveCapacityReservation(reservation);
        this.#assertLogicalRecordKeyPrefix(prefix);
        if (!reservation.logicalRecordKeyPrefixes.has(prefix)) {
            throw new UntrustedStorageTransactionError(
                'InvalidState',
                'authenticated inventory requires an exact registered reservation prefix.',
            );
        }
        await this.#ensureAuthenticatedRepairReady();
        const repair = this.#authenticatedRepair;
        if (repair === undefined) {
            throw new UntrustedStorageTransactionError(
                'InvalidState',
                'authenticated inventory requires authenticated repair protection.',
            );
        }
        await this.#assertAuthenticatedRepairHeadUnchanged();
        return Object.freeze(
            this.#authenticatedLogicalRecordKeys(
                repair,
                new Set([prefix]),
                maximumRecordCount,
            ),
        );
    }

    async #deleteExclusiveCapacityReservationRecords(
        reservation: ExclusiveCapacityReservationRecord,
        prefix: string,
    ): Promise<number> {
        let deletedRecordCount = 0;
        while (true) {
            const logicalRecordKeys = await this.#runExclusive(() =>
                this.#copyExclusiveCapacityReservationRecordKeys(
                    reservation,
                    prefix,
                    reservation.maximumDeletionBatchRecordCount,
                ),
            );
            if (logicalRecordKeys.length === 0) {
                return deletedRecordCount;
            }
            const deletionBatch = logicalRecordKeys;
            const transaction = await this.beginTransaction({
                lifetimeMilliseconds:
                    this.#limits.maximumTransactionLifetimeMilliseconds,
            });
            try {
                for (const logicalRecordKey of deletionBatch) {
                    await transaction.stageDeletion(logicalRecordKey);
                }
                await transaction.commit();
                deletedRecordCount += deletionBatch.length;
            } catch (error) {
                try {
                    await transaction.closeAfterFailure();
                } catch (cleanupError) {
                    throw new UntrustedStorageTransactionError(
                        'CleanupFailed',
                        'authenticated prefix deletion failed and could not close its transaction.',
                        { cleanupError, operationError: error },
                    );
                }
                throw error;
            }
        }
    }

    async #releaseExclusiveCapacityReservation(
        reservation: ExclusiveCapacityReservationRecord,
    ): Promise<void> {
        if (reservation.released) {
            return;
        }
        this.#assertActiveExclusiveCapacityReservation(reservation);
        const ownedTransactions = [...this.#transactions.values()].filter(
            (transaction) =>
                transaction.capacityReservationIdentifier ===
                reservation.identifier,
        );
        for (const transaction of ownedTransactions) {
            await this.#abortTransaction(transaction);
        }
        reservation.released = true;
        reservation.logicalRecordKeyPrefixes.clear();
        this.#exclusiveCapacityReservation = undefined;
    }

    #assertTransactionCapacityReservationAccess(
        transaction: TransactionRecord,
        logicalRecordKey: string,
    ): void {
        const reservation = this.#exclusiveCapacityReservation;
        if (
            transaction.capacityReservationIdentifier === undefined ||
            reservation === undefined ||
            transaction.capacityReservationIdentifier !==
                reservation.identifier ||
            reservation.released
        ) {
            if (
                transaction.capacityReservationIdentifier !== undefined ||
                reservation !== undefined
            ) {
                throw new UntrustedStorageTransactionError(
                    'Conflict',
                    'storage transaction is outside the active exclusive capacity reservation.',
                );
            }
            return;
        }
        if (
            ![...reservation.logicalRecordKeyPrefixes].some((prefix) =>
                logicalRecordKey.startsWith(prefix),
            )
        ) {
            throw new UntrustedStorageTransactionError(
                'Conflict',
                'storage mutation is outside the exclusive capacity reservation prefixes.',
            );
        }
    }

    #transactionHandle(
        transaction: TransactionRecord,
    ): UntrustedStorageTransaction {
        return Object.freeze({
            issueWriteLease: (input: {
                logicalRecordKey: string;
                declaredByteLength: number;
                expectedCurrentValue?: Uint8Array | null;
            }) =>
                this.#runExclusive(() =>
                    this.#issueWriteLease(transaction, input),
                ),
            stageDeletion: (
                logicalRecordKey: string,
                expectedCurrentValue?: Uint8Array | null,
            ) =>
                this.#runExclusive(() =>
                    this.#stageDeletion(
                        transaction,
                        logicalRecordKey,
                        expectedCurrentValue,
                    ),
                ),
            commit: () =>
                this.#runExclusive(() => this.#commitTransaction(transaction)),
            abort: () =>
                this.#runExclusive(() => this.#abortTransaction(transaction)),
            closeAfterFailure: (recordPublicationDisposition) =>
                this.#runExclusive(() =>
                    this.#closeTransactionAfterFailure(
                        transaction,
                        recordPublicationDisposition,
                    ),
                ),
        });
    }

    async #issueWriteLease(
        transaction: TransactionRecord,
        input: {
            logicalRecordKey: string;
            declaredByteLength: number;
            expectedCurrentValue?: Uint8Array | null;
        },
    ): Promise<UntrustedStorageWriteLease> {
        this.#assertActiveTransaction(transaction);
        this.#assertTransactionCapacityReservationAccess(
            transaction,
            input.logicalRecordKey,
        );
        assertSafeNonNegativeInteger(
            input.declaredByteLength,
            'declaredByteLength',
        );
        if (input.declaredByteLength > this.#limits.maximumLeaseByteLength) {
            throw new UntrustedStorageTransactionError(
                'QuotaExceeded',
                'lease byte length exceeds maximumLeaseByteLength.',
            );
        }
        if (
            transaction.changes.size >=
            this.#limits.maximumLeaseCountPerTransaction
        ) {
            throw new UntrustedStorageTransactionError(
                'QuotaExceeded',
                'transaction change count exceeds maximumLeaseCountPerTransaction.',
            );
        }
        if (transaction.changes.has(input.logicalRecordKey)) {
            throw new UntrustedStorageTransactionError(
                'InvalidState',
                'transaction already contains a change for logicalRecordKey.',
            );
        }
        const totalDeclaredByteLength = checkedAdd(
            transaction.totalDeclaredByteLength,
            input.declaredByteLength,
            'transaction declared byte length',
        );
        if (
            totalDeclaredByteLength > this.#limits.maximumTransactionByteLength
        ) {
            throw new UntrustedStorageTransactionError(
                'QuotaExceeded',
                'transaction byte length exceeds maximumTransactionByteLength.',
            );
        }
        const indexKey = this.#indexKey(input.logicalRecordKey);
        const expectedIndexValue = await this.#readOwnedIndexValue(indexKey);
        this.#assertAuthenticatedRepairMapping(
            input.logicalRecordKey,
            expectedIndexValue,
        );
        const existingObjectKey =
            expectedIndexValue === undefined
                ? undefined
                : this.#decodeIndexValue(expectedIndexValue);
        const existingObjectValue =
            existingObjectKey === undefined
                ? undefined
                : await this.#readOwnedObjectValue(existingObjectKey);
        if (
            existingObjectKey !== undefined &&
            existingObjectValue === undefined
        ) {
            throw new UntrustedStorageTransactionError(
                'CorruptIndex',
                'storage index references a missing object.',
            );
        }
        if (existingObjectValue !== undefined) {
            await this.#assertAuthenticatedRepairObjectDigest(
                input.logicalRecordKey,
                existingObjectValue,
            );
        }
        if (
            input.expectedCurrentValue !== undefined &&
            !bytesEqual(
                existingObjectValue,
                input.expectedCurrentValue ?? undefined,
            )
        ) {
            throw new UntrustedStorageTransactionError(
                'Conflict',
                'logical record changed after the caller inspected it.',
            );
        }
        const leaseIdentifier = this.#issueIdentifier('lease');
        const objectKey = `${this.#objectPrefix}${transaction.identifier}/${leaseIdentifier}`;
        if ((await this.#readOwnedObjectValue(objectKey)) !== undefined) {
            throw new UntrustedStorageTransactionError(
                'AdapterFailure',
                'lease identifier collides with a stored object.',
            );
        }
        const indexValueByteLength = textEncoder.encode(objectKey).byteLength;
        const priorIndexValueByteLength = expectedIndexValue?.byteLength ?? 0;
        const lease: LeaseRecord = {
            authenticate: undefined,
            declaredByteLength: input.declaredByteLength,
            expectedExistingObjectValue: existingObjectValue?.slice(),
            expectedIndexValue: expectedIndexValue?.slice(),
            existingObjectKey,
            indexKey,
            indexValueGrowthByteLength: Math.max(
                0,
                indexValueByteLength - priorIndexValueByteLength,
            ),
            logicalRecordKey: input.logicalRecordKey,
            objectKey,
            state: 'issued',
        };
        const prospectiveStoredValueByteLength = checkedAdd(
            await this.#measureStoredValueByteLength(),
            checkedAdd(
                this.#reservedStoredValueByteLength(),
                this.#leaseReservationByteLength(lease),
                'storage reservation',
            ),
            'stored value byte length',
        );
        if (
            prospectiveStoredValueByteLength >
            this.#limits.maximumStoredValueByteLength
        ) {
            throw new UntrustedStorageTransactionError(
                'QuotaExceeded',
                'storage reservation exceeds maximumStoredValueByteLength.',
            );
        }
        transaction.totalDeclaredByteLength = totalDeclaredByteLength;
        transaction.changes.set(input.logicalRecordKey, {
            kind: 'write',
            lease,
        });

        return this.#leaseHandle(transaction, lease);
    }

    #leaseHandle(
        transaction: TransactionRecord,
        lease: LeaseRecord,
    ): UntrustedStorageWriteLease {
        return Object.freeze({
            write: (bytes: Uint8Array) =>
                this.#runExclusive(() =>
                    this.#writeLease(transaction, lease, bytes),
                ),
            seal: (authenticate: UntrustedStorageAuthenticator) =>
                this.#runExclusive(() =>
                    this.#sealLease(transaction, lease, authenticate),
                ),
            cancel: () =>
                this.#runExclusive(() => this.#cancelLease(transaction, lease)),
            state: () => lease.state,
        });
    }

    async #writeLease(
        transaction: TransactionRecord,
        lease: LeaseRecord,
        bytes: Uint8Array,
    ): Promise<void> {
        this.#assertActiveTransaction(transaction);
        if (lease.state !== 'issued') {
            throw new UntrustedStorageTransactionError(
                'InvalidState',
                'lease write requires the issued state.',
            );
        }
        if (bytes.byteLength !== lease.declaredByteLength) {
            throw new UntrustedStorageTransactionError(
                'MalformedLength',
                'lease bytes do not match declaredByteLength.',
            );
        }
        const prospectiveStoredValueByteLength = checkedAdd(
            await this.#measureStoredValueByteLength(),
            this.#reservedStoredValueByteLength(),
            'stored value byte length',
        );
        if (
            prospectiveStoredValueByteLength >
            this.#limits.maximumStoredValueByteLength
        ) {
            throw new UntrustedStorageTransactionError(
                'QuotaExceeded',
                'lease write exceeds maximumStoredValueByteLength.',
            );
        }
        await this.#adapter.write(lease.objectKey, bytes.slice());
        lease.state = 'writing';
    }

    async #sealLease(
        transaction: TransactionRecord,
        lease: LeaseRecord,
        authenticate: UntrustedStorageAuthenticator,
    ): Promise<void> {
        this.#assertActiveTransaction(transaction);
        if (lease.state !== 'writing') {
            throw new UntrustedStorageTransactionError(
                'InvalidState',
                'lease seal requires the writing state.',
            );
        }
        const storedBytes = await this.#requiredLeaseBytes(lease);
        await this.#authenticate(
            authenticate,
            lease.logicalRecordKey,
            storedBytes,
        );
        lease.authenticate = authenticate;
        lease.state = 'sealed';
    }

    async #cancelLease(
        transaction: TransactionRecord,
        lease: LeaseRecord,
    ): Promise<void> {
        if (lease.state === 'cancelled') {
            return;
        }
        this.#assertActiveTransaction(transaction);
        if (lease.state === 'claimed' || lease.state === 'consumed') {
            throw new UntrustedStorageTransactionError(
                'InvalidState',
                'claimed or consumed leases cannot be cancelled.',
            );
        }
        await this.#deleteKeys([lease.objectKey], 'lease cancellation');
        lease.state = 'cancelled';
        transaction.changes.delete(lease.logicalRecordKey);
        transaction.totalDeclaredByteLength -= lease.declaredByteLength;
    }

    async #stageDeletion(
        transaction: TransactionRecord,
        logicalRecordKey: string,
        expectedCurrentValue: Uint8Array | null | undefined,
    ): Promise<void> {
        this.#assertActiveTransaction(transaction);
        this.#assertTransactionCapacityReservationAccess(
            transaction,
            logicalRecordKey,
        );
        if (
            transaction.changes.size >=
            this.#limits.maximumLeaseCountPerTransaction
        ) {
            throw new UntrustedStorageTransactionError(
                'QuotaExceeded',
                'transaction change count exceeds maximumLeaseCountPerTransaction.',
            );
        }
        if (transaction.changes.has(logicalRecordKey)) {
            throw new UntrustedStorageTransactionError(
                'InvalidState',
                'transaction already contains a change for logicalRecordKey.',
            );
        }
        const indexKey = this.#indexKey(logicalRecordKey);
        const expectedIndexValue = await this.#readOwnedIndexValue(indexKey);
        this.#assertAuthenticatedRepairMapping(
            logicalRecordKey,
            expectedIndexValue,
        );
        const existingObjectKey =
            expectedIndexValue === undefined
                ? undefined
                : this.#decodeIndexValue(expectedIndexValue);
        const existingObjectValue =
            existingObjectKey === undefined
                ? undefined
                : await this.#readOwnedObjectValue(existingObjectKey);
        if (
            existingObjectKey !== undefined &&
            existingObjectValue === undefined
        ) {
            throw new UntrustedStorageTransactionError(
                'CorruptIndex',
                'storage index references a missing object.',
            );
        }
        if (existingObjectValue !== undefined) {
            await this.#assertAuthenticatedRepairObjectDigest(
                logicalRecordKey,
                existingObjectValue,
            );
        }
        if (
            expectedCurrentValue !== undefined &&
            !bytesEqual(existingObjectValue, expectedCurrentValue ?? undefined)
        ) {
            throw new UntrustedStorageTransactionError(
                'Conflict',
                'logical record changed after the caller inspected it.',
            );
        }
        transaction.changes.set(logicalRecordKey, {
            kind: 'delete',
            deletion: {
                expectedExistingObjectValue: existingObjectValue?.slice(),
                expectedIndexValue: expectedIndexValue?.slice(),
                existingObjectKey,
                indexKey,
                logicalRecordKey,
            },
        });
    }

    async #prepareAuthenticatedRepairPublication(
        transaction: TransactionRecord,
        changes: readonly TransactionChange[],
    ): Promise<AuthenticatedRepairPublication | undefined> {
        const repair = this.#authenticatedRepair;
        if (repair === undefined) {
            return undefined;
        }
        await this.#assertAuthenticatedRepairHeadUnchanged();
        const records = new Map(repair.currentHead?.records ?? []);
        for (const change of changes) {
            const record =
                change.kind === 'write' ? change.lease : change.deletion;
            const encodedLogicalRecordKey = logicalRecordKeyHex(
                record.logicalRecordKey,
            );
            if (change.kind === 'write') {
                records.set(
                    encodedLogicalRecordKey,
                    Object.freeze({
                        objectKey: change.lease.objectKey,
                        sealedValueDigest:
                            await this.#deriveAuthenticatedRepairDigest(
                                await this.#requiredLeaseBytes(change.lease),
                            ),
                    }),
                );
            } else {
                records.delete(encodedLogicalRecordKey);
            }
        }
        const orderedRecords = new Map(
            [...records.entries()].sort(([left], [right]) =>
                left.localeCompare(right),
            ),
        );
        const previousTransitionSequence =
            repair.currentHead?.transitionSequence ?? 0n;
        if (previousTransitionSequence >= maximumUnsigned64) {
            throw new UntrustedStorageTransactionError(
                'QuotaExceeded',
                'authenticated repair transition sequence is exhausted.',
            );
        }
        const predecessorHeadDigest =
            repair.currentSealedHeadBytes === undefined
                ? '0'.repeat(128)
                : await this.#deriveAuthenticatedRepairDigest(
                      repair.currentSealedHeadBytes,
                  );
        const head = Object.freeze({
            lastTransactionIdentifier: transaction.identifier,
            predecessorHeadDigest,
            recordVersion: authenticatedRepairHeadRecordVersion,
            records: orderedRecords,
            repairIdentity: repair.expectedRepairIdentity,
            transitionSequence: previousTransitionSequence + 1n,
        });
        const sealedHeadBytes = await this.#sealAuthenticatedRepairHead(head);
        const currentStoredValueByteLength =
            await this.#measureStoredValueByteLength();
        const headGrowthByteLength = Math.max(
            0,
            sealedHeadBytes.byteLength -
                (repair.currentSealedHeadBytes?.byteLength ?? 0),
        );
        const indexGrowthByteLength = changes.reduce(
            (total, change) =>
                change.kind === 'write'
                    ? checkedAdd(
                          total,
                          change.lease.indexValueGrowthByteLength,
                          'authenticated repair publication index growth',
                      )
                    : total,
            0,
        );
        if (
            checkedAdd(
                currentStoredValueByteLength,
                checkedAdd(
                    headGrowthByteLength,
                    indexGrowthByteLength,
                    'authenticated repair publication growth',
                ),
                'stored value byte length',
            ) > this.#limits.maximumStoredValueByteLength
        ) {
            sealedHeadBytes.fill(0);
            throw new UntrustedStorageTransactionError(
                'QuotaExceeded',
                'authenticated repair publication exceeds maximumStoredValueByteLength.',
            );
        }
        const currentOwnedKeyCount = (await this.#listedKeys(this.#rootPrefix))
            .length;
        const newIndexCount = changes.filter((change) => {
            const record =
                change.kind === 'write' ? change.lease : change.deletion;
            return (
                change.kind === 'write' &&
                record.expectedIndexValue === undefined
            );
        }).length;
        const deletedIndexCount = changes.filter(
            (change) =>
                change.kind === 'delete' &&
                change.deletion.expectedIndexValue !== undefined,
        ).length;
        const addsRepairHead =
            repair.currentSealedHeadBytes === undefined ? 1 : 0;
        if (
            currentOwnedKeyCount +
                newIndexCount -
                deletedIndexCount +
                addsRepairHead >
            this.#limits.maximumOwnedRecordCount
        ) {
            sealedHeadBytes.fill(0);
            throw new UntrustedStorageTransactionError(
                'QuotaExceeded',
                'authenticated repair publication exceeds maximumOwnedRecordCount.',
            );
        }

        return Object.freeze({ head, sealedHeadBytes });
    }

    async #commitTransaction(transaction: TransactionRecord): Promise<void> {
        if (transaction.state === 'closed-after-failure') {
            throw new UntrustedStorageTransactionError(
                'InvalidState',
                'a transaction closed after failure cannot commit.',
            );
        }
        if (transaction.state === 'committed') {
            await this.#finishCommittedCleanup(transaction);
            return;
        }
        if (transaction.state === 'committed-unverified') {
            await this.#verifyCommittedPublication(transaction);
            transaction.state = 'committed';
            await this.#finishCommittedCleanup(transaction);
            return;
        }
        this.#assertActiveTransaction(transaction);
        const changes = [...transaction.changes.values()];
        if (changes.length === 0) {
            throw new UntrustedStorageTransactionError(
                'InvalidState',
                'empty storage transactions cannot commit.',
            );
        }
        const authenticatedLeaseBytes = new Map<LeaseRecord, Uint8Array>();
        for (const change of changes) {
            if (change.kind === 'write') {
                if (
                    change.lease.state !== 'sealed' ||
                    change.lease.authenticate === undefined
                ) {
                    throw new UntrustedStorageTransactionError(
                        'InvalidState',
                        'every write lease must be sealed before commit.',
                    );
                }
                const leaseBytes = await this.#requiredLeaseBytes(change.lease);
                await this.#authenticate(
                    change.lease.authenticate,
                    change.lease.logicalRecordKey,
                    leaseBytes,
                );
                authenticatedLeaseBytes.set(change.lease, leaseBytes.slice());
            }
        }
        const authenticatedRepairPublication =
            await this.#prepareAuthenticatedRepairPublication(
                transaction,
                changes,
            );
        transaction.authenticatedRepairPublication =
            authenticatedRepairPublication;
        const expectedValues: UntrustedStorageExpectedValue[] = [];
        const writes: UntrustedStorageWrite[] = [];
        const deletes: string[] = [];
        for (const change of changes) {
            const record =
                change.kind === 'write' ? change.lease : change.deletion;
            expectedValues.push({
                key: record.indexKey,
                value: record.expectedIndexValue?.slice(),
            });
            if (change.kind === 'write') {
                change.lease.state = 'claimed';
                expectedValues.push({
                    key: change.lease.objectKey,
                    value: authenticatedLeaseBytes.get(change.lease),
                });
                writes.push({
                    key: change.lease.indexKey,
                    value: textEncoder.encode(change.lease.objectKey),
                });
            } else {
                deletes.push(change.deletion.indexKey);
            }
            if (record.existingObjectKey !== undefined) {
                expectedValues.push({
                    key: record.existingObjectKey,
                    value: record.expectedExistingObjectValue?.slice(),
                });
                transaction.pendingCleanupObjectKeys.add(
                    record.existingObjectKey,
                );
            }
        }
        if (authenticatedRepairPublication !== undefined) {
            expectedValues.push({
                key: this.#repairHeadKey,
                value: this.#authenticatedRepair?.currentSealedHeadBytes?.slice(),
            });
            writes.push({
                key: this.#repairHeadKey,
                value: authenticatedRepairPublication.sealedHeadBytes.slice(),
            });
        }
        let committed: boolean;
        try {
            committed = await this.#adapter.applyAtomicMutation({
                expectedValues,
                writes,
                deletes,
            });
        } catch (error) {
            this.#restoreUncommittedTransaction(changes, transaction);
            throw error;
        }
        if (!committed) {
            this.#restoreUncommittedTransaction(changes, transaction);
            throw new UntrustedStorageTransactionError(
                'Conflict',
                'storage index changed before transaction commit.',
            );
        }
        transaction.state = 'committed-unverified';
        if (authenticatedRepairPublication !== undefined) {
            const repair = this.#authenticatedRepair;
            if (repair === undefined) {
                throw new UntrustedStorageTransactionError(
                    'InvalidState',
                    'authenticated repair protection disappeared after commit.',
                );
            }
            repair.currentHead = authenticatedRepairPublication.head;
            repair.currentSealedHeadBytes =
                authenticatedRepairPublication.sealedHeadBytes.slice();
        }
        await this.#verifyCommittedPublication(transaction);
        transaction.state = 'committed';
        await this.#finishCommittedCleanup(transaction);
    }

    #restoreUncommittedTransaction(
        changes: readonly TransactionChange[],
        transaction: TransactionRecord,
    ): void {
        for (const change of changes) {
            if (change.kind === 'write') {
                change.lease.state = 'sealed';
            }
        }
        transaction.pendingCleanupObjectKeys.clear();
        transaction.authenticatedRepairPublication = undefined;
    }

    async #verifyCommittedPublication(
        transaction: TransactionRecord,
    ): Promise<void> {
        for (const change of transaction.changes.values()) {
            if (change.kind === 'write') {
                const observedIndexValue = await this.#readOwnedIndexValue(
                    change.lease.indexKey,
                );
                if (
                    !bytesEqual(
                        observedIndexValue,
                        textEncoder.encode(change.lease.objectKey),
                    )
                ) {
                    throw new UntrustedStorageTransactionError(
                        'AdapterFailure',
                        'committed storage index failed publication reread.',
                    );
                }
                if (change.lease.authenticate === undefined) {
                    throw new UntrustedStorageTransactionError(
                        'InvalidState',
                        'committed write lease is missing its authenticator.',
                    );
                }
                await this.#authenticate(
                    change.lease.authenticate,
                    change.lease.logicalRecordKey,
                    await this.#requiredLeaseBytes(change.lease),
                );
            } else if (
                (await this.#readOwnedIndexValue(change.deletion.indexKey)) !==
                undefined
            ) {
                throw new UntrustedStorageTransactionError(
                    'AdapterFailure',
                    'deleted storage index remained visible after commit.',
                );
            }
        }
        const authenticatedRepairPublication =
            transaction.authenticatedRepairPublication;
        if (authenticatedRepairPublication !== undefined) {
            const observedSealedHeadBytes =
                await this.#readOwnedRepairHeadValue();
            if (
                !bytesEqual(
                    observedSealedHeadBytes,
                    authenticatedRepairPublication.sealedHeadBytes,
                )
            ) {
                throw new UntrustedStorageTransactionError(
                    'AuthenticationFailed',
                    'committed authenticated repair head failed publication reread.',
                );
            }
            const observedHead = await this.#openAuthenticatedRepairHead(
                authenticatedRepairPublication.sealedHeadBytes,
            );
            const expectedHeadBytes = encodeAuthenticatedRepairHead(
                authenticatedRepairPublication.head,
            );
            const observedHeadBytes =
                encodeAuthenticatedRepairHead(observedHead);
            const headMatches = bytesEqual(
                expectedHeadBytes,
                observedHeadBytes,
            );
            expectedHeadBytes.fill(0);
            observedHeadBytes.fill(0);
            if (!headMatches) {
                throw new UntrustedStorageTransactionError(
                    'AuthenticationFailed',
                    'committed authenticated repair head changed during publication.',
                );
            }
        }
        for (const change of transaction.changes.values()) {
            if (change.kind === 'write') {
                change.lease.state = 'consumed';
            }
        }
    }

    async #finishCommittedCleanup(
        transaction: TransactionRecord,
    ): Promise<void> {
        await this.#deleteKeys(
            [...transaction.pendingCleanupObjectKeys],
            'committed replacement cleanup',
        );
        transaction.pendingCleanupObjectKeys.clear();
        this.#clearTransactionRetainedBytes(transaction);
        this.#transactions.delete(transaction.identifier);
    }

    #clearTransactionRetainedBytes(transaction: TransactionRecord): void {
        for (const change of transaction.changes.values()) {
            const record =
                change.kind === 'write' ? change.lease : change.deletion;
            record.expectedExistingObjectValue?.fill(0);
            record.expectedIndexValue?.fill(0);
        }
        transaction.authenticatedRepairPublication?.sealedHeadBytes.fill(0);
        transaction.authenticatedRepairPublication = undefined;
        transaction.changes.clear();
    }

    async #abortTransaction(transaction: TransactionRecord): Promise<void> {
        if (
            transaction.state === 'aborted' ||
            transaction.state === 'closed-after-failure'
        ) {
            return;
        }
        if (
            transaction.state === 'committed' ||
            transaction.state === 'committed-unverified'
        ) {
            throw new UntrustedStorageTransactionError(
                'InvalidState',
                'a committed transaction cannot abort.',
            );
        }
        transaction.state = 'aborting';
        const stagedObjectKeys = [...transaction.changes.values()]
            .filter(
                (
                    change,
                ): change is Readonly<{
                    kind: 'write';
                    lease: LeaseRecord;
                }> => change.kind === 'write',
            )
            .map((change) => change.lease.objectKey);
        await this.#deleteKeys(stagedObjectKeys, 'transaction abort');
        for (const change of transaction.changes.values()) {
            if (change.kind === 'write') {
                change.lease.state = 'cancelled';
            }
        }
        transaction.state = 'aborted';
        this.#clearTransactionRetainedBytes(transaction);
        this.#transactions.delete(transaction.identifier);
    }

    async #closeTransactionAfterFailure(
        transaction: TransactionRecord,
        recordPublicationDisposition?: (
            disposition: UntrustedStoragePublicationDisposition,
        ) => void,
    ): Promise<void> {
        const publicationDisposition =
            transaction.failurePublicationDisposition ??
            (transaction.state === 'committed' ||
            transaction.state === 'committed-unverified'
                ? 'published-or-indeterminate'
                : 'definitely-not-published');
        transaction.failurePublicationDisposition = publicationDisposition;
        let dispositionReportingFailure: unknown;
        try {
            recordPublicationDisposition?.(publicationDisposition);
        } catch (error) {
            dispositionReportingFailure = error;
        }
        let transactionClosureFailure: unknown;
        try {
            if (
                transaction.state === 'active' ||
                transaction.state === 'aborting'
            ) {
                await this.#abortTransaction(transaction);
            } else if (
                transaction.state === 'committed-unverified' ||
                transaction.state === 'committed'
            ) {
                transaction.state = 'closed-after-failure';
                this.#clearTransactionRetainedBytes(transaction);
                this.#transactions.delete(transaction.identifier);
            }
        } catch (error) {
            transaction.state = 'closed-after-failure';
            this.#clearTransactionRetainedBytes(transaction);
            this.#transactions.delete(transaction.identifier);
            transactionClosureFailure = error;
        }
        if (
            dispositionReportingFailure !== undefined &&
            transactionClosureFailure !== undefined
        ) {
            throw new UntrustedStorageTransactionError(
                'CleanupFailed',
                'transaction failure closure and publication disposition reporting both failed.',
                [dispositionReportingFailure, transactionClosureFailure],
            );
        }
        if (transactionClosureFailure !== undefined) {
            if (transactionClosureFailure instanceof Error) {
                throw transactionClosureFailure;
            }
            throw new UntrustedStorageTransactionError(
                'CleanupFailed',
                'transaction failure closure failed.',
                transactionClosureFailure,
            );
        }
        if (dispositionReportingFailure !== undefined) {
            if (dispositionReportingFailure instanceof Error) {
                throw dispositionReportingFailure;
            }
            throw new UntrustedStorageTransactionError(
                'CleanupFailed',
                'transaction publication disposition reporting failed.',
                dispositionReportingFailure,
            );
        }
    }

    #assertActiveTransaction(transaction: TransactionRecord): void {
        if (
            this.#transactions.get(transaction.identifier) !== transaction ||
            transaction.state !== 'active'
        ) {
            throw new UntrustedStorageTransactionError(
                'InvalidState',
                'storage transaction is not active.',
            );
        }
        if (
            this.#readMonotonicClockMilliseconds() >
            transaction.expiresAtMilliseconds
        ) {
            throw new UntrustedStorageTransactionError(
                'Expired',
                'storage transaction lease has expired.',
            );
        }
    }

    async #ensureAuthenticatedRepairReady(): Promise<number> {
        const repair = this.#authenticatedRepair;
        if (repair === undefined) {
            return 0;
        }
        if (repair.initialized) {
            await this.#assertAuthenticatedRepairHeadUnchanged();
            return 0;
        }

        const indexKeys = await this.#listedKeys(this.#indexPrefix);
        const objectKeys = await this.#listedKeys(this.#objectPrefix);
        const repairKeys = await this.#listedKeys(this.#repairPrefix);
        if (
            indexKeys.length + objectKeys.length + repairKeys.length >
            this.#limits.maximumOwnedRecordCount
        ) {
            throw new UntrustedStorageTransactionError(
                'QuotaExceeded',
                'owned storage record count exceeds maximumOwnedRecordCount.',
            );
        }
        if (
            repairKeys.length > 1 ||
            (repairKeys.length === 1 && repairKeys[0] !== this.#repairHeadKey)
        ) {
            throw new UntrustedStorageTransactionError(
                'AuthenticationFailed',
                'authenticated repair namespace contains an unexpected record.',
            );
        }
        const sealedHeadBytes = await this.#readOwnedRepairHeadValue();
        if (sealedHeadBytes === undefined) {
            if (indexKeys.length !== 0) {
                throw new UntrustedStorageTransactionError(
                    'AuthenticationFailed',
                    'authenticated repair head is missing for committed storage records.',
                );
            }
            await this.#deleteUnreferencedObjects(
                objectKeys,
                'authenticated repair abandoned-write cleanup',
            );
            repair.currentHead = undefined;
            repair.currentSealedHeadBytes = undefined;
            repair.initialized = true;
            return objectKeys.length;
        }

        const head = await this.#openAuthenticatedRepairHead(sealedHeadBytes);
        if (head.repairIdentity !== repair.expectedRepairIdentity) {
            throw new UntrustedStorageTransactionError(
                'AuthenticationFailed',
                'authenticated repair head belongs to another storage authority.',
            );
        }
        if (head.records.size !== indexKeys.length) {
            throw new UntrustedStorageTransactionError(
                'AuthenticationFailed',
                'authenticated repair head does not match the committed storage index count.',
            );
        }
        const referencedObjectKeys = new Set<string>();
        for (const indexKey of indexKeys) {
            const encodedLogicalRecordKey = indexKey.slice(
                this.#indexPrefix.length,
            );
            const expectedRecord = head.records.get(encodedLogicalRecordKey);
            if (expectedRecord === undefined) {
                throw new UntrustedStorageTransactionError(
                    'AuthenticationFailed',
                    'authenticated repair head omits a committed storage index.',
                );
            }
            const indexValue = await this.#requiredListedIndexValue(indexKey);
            const objectKey = this.#decodeIndexValue(indexValue);
            if (objectKey !== expectedRecord.objectKey) {
                throw new UntrustedStorageTransactionError(
                    'AuthenticationFailed',
                    'authenticated repair head conflicts with a committed storage index.',
                );
            }
            const objectValue = await this.#readOwnedObjectValue(objectKey);
            if (objectValue === undefined) {
                throw new UntrustedStorageTransactionError(
                    'AuthenticationFailed',
                    'authenticated repair head references a missing committed object.',
                );
            }
            if (
                (await this.#deriveAuthenticatedRepairDigest(objectValue)) !==
                expectedRecord.sealedValueDigest
            ) {
                throw new UntrustedStorageTransactionError(
                    'AuthenticationFailed',
                    'authenticated repair head detects changed committed object bytes.',
                );
            }
            referencedObjectKeys.add(objectKey);
        }
        const unreferencedObjectKeys = objectKeys.filter(
            (objectKey) => !referencedObjectKeys.has(objectKey),
        );
        await this.#deleteUnreferencedObjects(
            unreferencedObjectKeys,
            'authenticated repair abandoned-write cleanup',
        );
        repair.currentHead = head;
        repair.currentSealedHeadBytes = sealedHeadBytes.slice();
        repair.initialized = true;

        return unreferencedObjectKeys.length;
    }

    #authorizedEmptyHeadDigestInput(
        repair: AuthenticatedRepairRuntime,
    ): Uint8Array {
        return this.#storageBoundDigestInput(
            authorizedEmptyHeadDigestDomain,
            repair.protection.repairIdentity,
        );
    }

    #deriveStorageInstanceIdentity(repairIdentity: Uint8Array): Uint8Array {
        const digestInput = this.#storageBoundDigestInput(
            storageInstanceIdentityDomain,
            repairIdentity,
        );
        try {
            return sha512(digestInput);
        } finally {
            digestInput.fill(0);
        }
    }

    #storageBoundDigestInput(
        domain: Uint8Array,
        repairIdentity: Uint8Array,
    ): Uint8Array {
        const namespaceBytes = textEncoder.encode(this.#rootPrefix);
        const input = new Uint8Array(
            domain.byteLength +
                1 +
                namespaceBytes.byteLength +
                1 +
                repairIdentity.byteLength,
        );
        let offset = 0;
        input.set(domain, offset);
        offset += domain.byteLength;
        input[offset] = 0;
        offset += 1;
        input.set(namespaceBytes, offset);
        offset += namespaceBytes.byteLength;
        input[offset] = 0;
        offset += 1;
        input.set(repairIdentity, offset);
        namespaceBytes.fill(0);
        return input;
    }

    async #assertAuthenticatedRepairHeadUnchanged(): Promise<void> {
        const repair = this.#authenticatedRepair;
        if (repair === undefined || !repair.initialized) {
            return;
        }
        const observedHeadBytes = await this.#readOwnedRepairHeadValue();
        if (!bytesEqual(observedHeadBytes, repair.currentSealedHeadBytes)) {
            throw new UntrustedStorageTransactionError(
                'AuthenticationFailed',
                'authenticated repair head changed outside the committed transaction chain.',
            );
        }
    }

    #assertAuthenticatedRepairMapping(
        logicalRecordKey: string,
        indexValue: Uint8Array | undefined,
    ): void {
        const repair = this.#authenticatedRepair;
        if (repair === undefined) {
            return;
        }
        const expectedRecord = repair.currentHead?.records.get(
            logicalRecordKeyHex(logicalRecordKey),
        );
        const observedObjectKey =
            indexValue === undefined
                ? undefined
                : this.#decodeIndexValue(indexValue);
        if (expectedRecord?.objectKey !== observedObjectKey) {
            throw new UntrustedStorageTransactionError(
                'AuthenticationFailed',
                'logical storage record conflicts with the authenticated repair head.',
            );
        }
    }

    async #assertAuthenticatedRepairObjectDigest(
        logicalRecordKey: string,
        sealedValue: Uint8Array,
    ): Promise<void> {
        const repair = this.#authenticatedRepair;
        if (repair === undefined) {
            return;
        }
        const expectedRecord = repair.currentHead?.records.get(
            logicalRecordKeyHex(logicalRecordKey),
        );
        if (expectedRecord === undefined) {
            throw new UntrustedStorageTransactionError(
                'AuthenticationFailed',
                'authenticated repair head omits an opened committed object.',
            );
        }
        if (
            (await this.#deriveAuthenticatedRepairDigest(sealedValue)) !==
            expectedRecord.sealedValueDigest
        ) {
            throw new UntrustedStorageTransactionError(
                'AuthenticationFailed',
                'opened committed object conflicts with the authenticated repair head.',
            );
        }
    }

    async #openAuthenticatedRepairHead(
        sealedHeadBytes: Uint8Array,
    ): Promise<StoredAuthenticatedRepairHeadRecord> {
        const repair = this.#authenticatedRepair;
        if (repair === undefined) {
            throw new UntrustedStorageTransactionError(
                'InvalidState',
                'authenticated repair protection is not configured.',
            );
        }
        let plaintext: Uint8Array | undefined;
        try {
            plaintext = await repair.protection.open(sealedHeadBytes.slice());
            if (
                !isUint8Array(plaintext) ||
                plaintext.byteLength > this.#limits.maximumStoredValueByteLength
            ) {
                throw new UntrustedStorageTransactionError(
                    'AuthenticationFailed',
                    'authenticated repair head plaintext has an invalid length.',
                );
            }
            return decodeAuthenticatedRepairHead({
                bytes: plaintext,
                maximumRecordCount: this.#limits.maximumOwnedRecordCount,
                maximumObjectKeyByteLength:
                    this.#maximumOwnedKeyCharacterLength,
            });
        } catch (error) {
            if (error instanceof UntrustedStorageTransactionError) {
                throw error;
            }
            throw new UntrustedStorageTransactionError(
                'AuthenticationFailed',
                'authenticated repair head could not be opened.',
                error,
            );
        } finally {
            plaintext?.fill(0);
        }
    }

    async #deriveAuthenticatedRepairDigest(bytes: Uint8Array): Promise<string> {
        const repair = this.#authenticatedRepair;
        if (repair === undefined) {
            throw new UntrustedStorageTransactionError(
                'InvalidState',
                'authenticated repair protection is not configured.',
            );
        }
        let digest: Uint8Array;
        try {
            digest = await repair.protection.deriveDigest(bytes.slice());
        } catch (error) {
            throw new UntrustedStorageTransactionError(
                'AuthenticationFailed',
                'authenticated repair head digest derivation failed.',
                error,
            );
        }
        if (!isUint8Array(digest) || digest.byteLength !== 64) {
            throw new UntrustedStorageTransactionError(
                'AuthenticationFailed',
                'authenticated repair head digest has an invalid length.',
            );
        }

        return bytesToHex(digest);
    }

    async #sealAuthenticatedRepairHead(
        head: StoredAuthenticatedRepairHeadRecord,
    ): Promise<Uint8Array> {
        const repair = this.#authenticatedRepair;
        if (repair === undefined) {
            throw new UntrustedStorageTransactionError(
                'InvalidState',
                'authenticated repair protection is not configured.',
            );
        }
        const plaintext = encodeAuthenticatedRepairHead(head);
        if (plaintext.byteLength > this.#limits.maximumStoredValueByteLength) {
            plaintext.fill(0);
            throw new UntrustedStorageTransactionError(
                'QuotaExceeded',
                'authenticated repair head exceeds the storage quota.',
            );
        }
        try {
            const sealedHeadBytes = await repair.protection.seal(
                plaintext.slice(),
            );
            if (
                !isUint8Array(sealedHeadBytes) ||
                sealedHeadBytes.byteLength === 0 ||
                sealedHeadBytes.byteLength >
                    this.#limits.maximumStoredValueByteLength
            ) {
                throw new UntrustedStorageTransactionError(
                    'QuotaExceeded',
                    'sealed authenticated repair head has an invalid length.',
                );
            }

            return sealedHeadBytes.slice();
        } catch (error) {
            if (error instanceof UntrustedStorageTransactionError) {
                throw error;
            }
            throw new UntrustedStorageTransactionError(
                'AuthenticationFailed',
                'authenticated repair head could not be sealed.',
                error,
            );
        } finally {
            plaintext.fill(0);
        }
    }

    async #requiredLeaseBytes(lease: LeaseRecord): Promise<Uint8Array> {
        const storedBytes = await this.#adapter.read(lease.objectKey);
        if (storedBytes === undefined) {
            throw new UntrustedStorageTransactionError(
                'AdapterFailure',
                'staged lease bytes are missing.',
            );
        }
        if (storedBytes.byteLength !== lease.declaredByteLength) {
            throw new UntrustedStorageTransactionError(
                'MalformedLength',
                'staged lease byte length changed after write.',
            );
        }

        return this.#copyBoundedAdapterValue({
            maximumByteLength: lease.declaredByteLength,
            oversizedErrorCode: 'MalformedLength',
            oversizedMessage: 'staged lease bytes exceed declaredByteLength.',
            value: storedBytes,
        });
    }

    #readMonotonicClockMilliseconds(): number {
        const now = this.#monotonicClockMilliseconds();
        if (!Number.isFinite(now) || now < 0) {
            throw new UntrustedStorageTransactionError(
                'AdapterFailure',
                'monotonic clock returned an invalid value.',
            );
        }

        return now;
    }

    #issueIdentifier(kind: IdentifierKind): string {
        let identifier: string;
        try {
            identifier = this.#createIdentifier(kind);
        } catch (error) {
            if (error instanceof UntrustedStorageTransactionError) {
                throw error;
            }
            throw new UntrustedStorageTransactionError(
                'AdapterFailure',
                `${kind} identifier generation failed.`,
                error,
            );
        }
        assertIdentifier(identifier, kind);
        const issuedIdentifiers = this.#issuedIdentifiers[kind];
        if (issuedIdentifiers.has(identifier)) {
            throw new UntrustedStorageTransactionError(
                'AdapterFailure',
                `${kind} identifier was reused during this store's lifetime.`,
            );
        }
        issuedIdentifiers.add(identifier);

        return identifier;
    }

    async #authenticate(
        authenticate: UntrustedStorageAuthenticator,
        logicalRecordKey: string,
        bytes: Uint8Array,
    ): Promise<void> {
        try {
            await authenticate({
                bytes: bytes.slice(),
                logicalRecordKey,
            });
        } catch (error) {
            throw new UntrustedStorageTransactionError(
                'AuthenticationFailed',
                'stored bytes failed caller-supplied authentication.',
                error,
            );
        }
    }

    #indexKey(logicalRecordKey: string): string {
        return `${this.#indexPrefix}${bytesToHex(
            assertLogicalRecordKey(logicalRecordKey),
        )}`;
    }

    #decodeIndexValue(indexValue: Uint8Array): string {
        let objectKey: string;
        try {
            objectKey = fatalTextDecoder.decode(indexValue);
        } catch (error) {
            throw new UntrustedStorageTransactionError(
                'CorruptIndex',
                'storage index is not valid UTF-8.',
                error,
            );
        }
        if (
            !bytesEqual(indexValue, textEncoder.encode(objectKey)) ||
            !objectKey.startsWith(this.#objectPrefix)
        ) {
            throw new UntrustedStorageTransactionError(
                'CorruptIndex',
                'storage index does not contain a canonical owned object key.',
            );
        }
        const suffix = objectKey.slice(this.#objectPrefix.length);
        const [transactionIdentifier, leaseIdentifier, extraSegment] =
            suffix.split('/');
        if (
            extraSegment !== undefined ||
            transactionIdentifier === undefined ||
            leaseIdentifier === undefined ||
            !identifierPattern.test(transactionIdentifier) ||
            !identifierPattern.test(leaseIdentifier)
        ) {
            throw new UntrustedStorageTransactionError(
                'CorruptIndex',
                'storage index object key has a malformed ownership path.',
            );
        }

        return objectKey;
    }

    #leaseReservationByteLength(lease: LeaseRecord): number {
        return checkedAdd(
            lease.declaredByteLength,
            lease.indexValueGrowthByteLength,
            'lease reservation',
        );
    }

    #reservedStoredValueByteLength(): number {
        let reservedByteLength = 0;
        for (const transaction of this.#transactions.values()) {
            if (transaction.state !== 'active') {
                continue;
            }
            for (const change of transaction.changes.values()) {
                if (change.kind !== 'write') {
                    continue;
                }
                const payloadReservation =
                    change.lease.state === 'issued'
                        ? change.lease.declaredByteLength
                        : 0;
                reservedByteLength = checkedAdd(
                    reservedByteLength,
                    checkedAdd(
                        payloadReservation,
                        change.lease.indexValueGrowthByteLength,
                        'lease reservation',
                    ),
                    'active storage reservations',
                );
            }
        }

        return reservedByteLength;
    }

    async #measureStoredValueByteLength(): Promise<number> {
        const keys = await this.#listedKeys(this.#rootPrefix);
        let byteLength = 0;
        for (const key of keys) {
            const value = await this.#adapter.read(key);
            if (value === undefined) {
                throw new UntrustedStorageTransactionError(
                    'AdapterFailure',
                    'storage adapter listed a missing value.',
                );
            }
            let maximumByteLength: number;
            let oversizedErrorCode: UntrustedStorageTransactionErrorCode;
            let oversizedMessage: string;
            if (key.startsWith(this.#indexPrefix)) {
                maximumByteLength = this.#maximumIndexValueByteLength;
                oversizedErrorCode = 'CorruptIndex';
                oversizedMessage =
                    'storage index exceeds the maximum owned object-key length.';
            } else if (key.startsWith(this.#objectPrefix)) {
                maximumByteLength = this.#limits.maximumLeaseByteLength;
                oversizedErrorCode = 'MalformedLength';
                oversizedMessage =
                    'stored object exceeds maximumLeaseByteLength.';
            } else if (key === this.#repairHeadKey) {
                maximumByteLength = this.#limits.maximumStoredValueByteLength;
                oversizedErrorCode = 'AuthenticationFailed';
                oversizedMessage =
                    'authenticated repair head exceeds maximumStoredValueByteLength.';
            } else {
                throw new UntrustedStorageTransactionError(
                    'AdapterFailure',
                    'storage adapter returned an unknown owned key.',
                );
            }
            const valueByteLength = this.#boundedAdapterValueByteLength({
                maximumByteLength,
                oversizedErrorCode,
                oversizedMessage,
                value,
            });
            byteLength = checkedAdd(
                byteLength,
                valueByteLength,
                'stored value byte length',
            );
            if (byteLength > this.#limits.maximumStoredValueByteLength) {
                throw new UntrustedStorageTransactionError(
                    'QuotaExceeded',
                    'stored values exceed maximumStoredValueByteLength.',
                );
            }
        }

        return byteLength;
    }

    async #listedKeys(prefix: string): Promise<string[]> {
        const listedKeys = await this.#adapter.listKeys(prefix);
        if (
            !Array.isArray(listedKeys) ||
            listedKeys.length > this.#limits.maximumOwnedRecordCount
        ) {
            throw new UntrustedStorageTransactionError(
                'QuotaExceeded',
                'owned storage record count exceeds maximumOwnedRecordCount.',
            );
        }
        const uniqueKeys = new Set<string>();
        for (const key of listedKeys) {
            if (
                typeof key !== 'string' ||
                key.length > this.#maximumOwnedKeyCharacterLength ||
                !key.startsWith(prefix) ||
                uniqueKeys.has(key)
            ) {
                throw new UntrustedStorageTransactionError(
                    'AdapterFailure',
                    'storage adapter returned an invalid key listing.',
                );
            }
            uniqueKeys.add(key);
        }

        return [...uniqueKeys].sort();
    }

    async #requiredListedIndexValue(key: string): Promise<Uint8Array> {
        const value = await this.#readOwnedIndexValue(key);
        if (value === undefined) {
            throw new UntrustedStorageTransactionError(
                'AdapterFailure',
                'storage adapter listed a missing value.',
            );
        }

        return value;
    }

    async #readOwnedIndexValue(key: string): Promise<Uint8Array | undefined> {
        const value = await this.#adapter.read(key);
        if (value === undefined) {
            return undefined;
        }

        return this.#copyBoundedAdapterValue({
            maximumByteLength: this.#maximumIndexValueByteLength,
            oversizedErrorCode: 'CorruptIndex',
            oversizedMessage:
                'storage index exceeds the maximum owned object-key length.',
            value,
        });
    }

    async #readOwnedObjectValue(key: string): Promise<Uint8Array | undefined> {
        const value = await this.#adapter.read(key);
        if (value === undefined) {
            return undefined;
        }

        return this.#copyBoundedAdapterValue({
            maximumByteLength: this.#limits.maximumLeaseByteLength,
            oversizedErrorCode: 'MalformedLength',
            oversizedMessage: 'stored object exceeds maximumLeaseByteLength.',
            value,
        });
    }

    async #readOwnedRepairHeadValue(): Promise<Uint8Array | undefined> {
        const value = await this.#adapter.read(this.#repairHeadKey);
        if (value === undefined) {
            return undefined;
        }

        return this.#copyBoundedAdapterValue({
            maximumByteLength: this.#limits.maximumStoredValueByteLength,
            oversizedErrorCode: 'AuthenticationFailed',
            oversizedMessage:
                'authenticated repair head exceeds maximumStoredValueByteLength.',
            value,
        });
    }

    #copyBoundedAdapterValue(input: {
        maximumByteLength: number;
        oversizedErrorCode: UntrustedStorageTransactionErrorCode;
        oversizedMessage: string;
        value: Uint8Array;
    }): Uint8Array {
        this.#boundedAdapterValueByteLength(input);
        try {
            return input.value.slice();
        } catch (error) {
            throw new UntrustedStorageTransactionError(
                'AdapterFailure',
                'storage adapter returned bytes that could not be copied.',
                error,
            );
        }
    }

    #boundedAdapterValueByteLength(input: {
        maximumByteLength: number;
        oversizedErrorCode: UntrustedStorageTransactionErrorCode;
        oversizedMessage: string;
        value: Uint8Array;
    }): number {
        if (!(input.value instanceof Uint8Array)) {
            throw new UntrustedStorageTransactionError(
                'AdapterFailure',
                'storage adapter returned a value that is not a Uint8Array.',
            );
        }
        if (input.value.byteLength > input.maximumByteLength) {
            throw new UntrustedStorageTransactionError(
                input.oversizedErrorCode,
                input.oversizedMessage,
            );
        }

        return input.value.byteLength;
    }

    async #deleteKeys(
        keys: readonly string[],
        operation: string,
    ): Promise<void> {
        const failedKeys: string[] = [];
        const failures: unknown[] = [];
        for (const key of [...new Set(keys)].sort()) {
            try {
                await this.#adapter.delete(key);
            } catch (error) {
                failedKeys.push(key);
                failures.push(error);
            }
        }
        if (failedKeys.length > 0) {
            throw new UntrustedStorageTransactionError(
                'CleanupFailed',
                `${operation} failed for ${failedKeys.length} storage object(s).`,
                failures,
            );
        }
    }

    async #deleteUnreferencedObjects(
        objectKeys: readonly string[],
        operation: string,
    ): Promise<void> {
        const uniqueObjectKeys = [...new Set(objectKeys)].sort();
        if (uniqueObjectKeys.length === 0) {
            return;
        }
        let deleted: boolean;
        try {
            deleted = await this.#adapter.deleteUnreferencedObjects({
                indexPrefix: this.#indexPrefix,
                objectKeys: uniqueObjectKeys,
            });
        } catch (error) {
            throw new UntrustedStorageTransactionError(
                'CleanupFailed',
                `${operation} failed for ${uniqueObjectKeys.length} storage object(s).`,
                error,
            );
        }
        if (!deleted) {
            throw new UntrustedStorageTransactionError(
                'Conflict',
                `${operation} stopped because a candidate object became committed.`,
            );
        }
    }

    async #runExclusive<Result>(
        operation: () => Promise<Result>,
    ): Promise<Result> {
        const previousOperation = this.#exclusiveOperationTail;
        let releaseOperation: (() => void) | undefined;
        this.#exclusiveOperationTail = new Promise<void>((resolve) => {
            releaseOperation = resolve;
        });
        await previousOperation;
        try {
            return await operation();
        } finally {
            releaseOperation?.();
        }
    }
}

export const openUntrustedStorageTransactionStore = async (
    configuration: UntrustedStorageTransactionStoreConfiguration,
): Promise<UntrustedStorageTransactionStoreOpenResult> => {
    const store = new UntrustedStorageTransactionStore(configuration);
    const repairReport = await store.repair();

    return { repairReport, store };
};

/**
 * Internal bootstrap store for records whose accepting reader positively
 * verifies every retained byte against an external cryptographic commitment.
 * Generic runtime records must use openUntrustedStorageTransactionStore.
 */
export const openPositivelyVerifiedStorageTransactionStore = async (
    configuration: UntrustedStorageTransactionStoreBaseConfiguration,
): Promise<UntrustedStorageTransactionStoreOpenResult> => {
    const store = new UntrustedStorageTransactionStore({
        ...configuration,
        [positivelyVerifiedRecordBootstrap]: true,
    });
    const repairReport = await store.repair();

    return { repairReport, store };
};
