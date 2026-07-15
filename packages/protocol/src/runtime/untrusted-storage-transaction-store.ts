const textEncoder = new TextEncoder();
const fatalTextDecoder = new TextDecoder('utf-8', { fatal: true });
const maximumLogicalRecordKeyByteLength = 1024;
const identifierByteLength = 32;
const encodedIdentifierCharacterLength = identifierByteLength * 2;
const identifierPattern = /^[0-9a-f]{64}$/u;
const hashPattern = /^[0-9a-f]{128}$/u;
const namespacePattern = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;
const canonicalUnsignedDecimalPattern = /^(?:0|[1-9][0-9]*)$/u;
const maximumUnsigned64 = 0xffff_ffff_ffff_ffffn;
const authenticatedRecoveryHeadRecordVersion = 1;

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
 * transaction and must grant this store exclusive recovery authority for its
 * namespace. A rejected applyAtomicMutation promise must guarantee that its
 * mutation did not commit. Reads and writes may return attacker-controlled
 * bytes.
 */
export type UntrustedStorageAdapter = Readonly<{
    read(key: string): Promise<Uint8Array | undefined>;
    write(key: string, value: Uint8Array): Promise<void>;
    delete(key: string): Promise<void>;
    listKeys(prefix: string): Promise<readonly string[]>;
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
    closeAfterFailure(): Promise<void>;
}>;

export type UntrustedStorageRecoveryReport = Readonly<{
    removedCorruptIndexCount: number;
    removedUnreferencedObjectCount: number;
    retainedObjectCount: number;
    storedValueByteLength: number;
}>;

export type UntrustedStorageTransactionStoreOpenResult = Readonly<{
    recoveryReport: UntrustedStorageRecoveryReport;
    store: UntrustedStorageTransactionStore;
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

export type UntrustedStorageAuthenticatedRecoveryProtection = Readonly<{
    deriveDigest(bytes: Uint8Array): Promise<Uint8Array> | Uint8Array;
    open(sealedHeadBytes: Uint8Array): Promise<Uint8Array>;
    recoveryIdentity: Uint8Array;
    seal(headPlaintext: Uint8Array): Promise<Uint8Array>;
}>;

export type UntrustedStorageTransactionStoreConfiguration =
    UntrustedStorageTransactionStoreBaseConfiguration &
        Readonly<{
            authenticatedRecoveryProtection: UntrustedStorageAuthenticatedRecoveryProtection;
        }>;

const positivelyVerifiedRecordBootstrap = Symbol(
    'positively-verified-record-bootstrap',
);

type PositivelyVerifiedRecordBootstrapConfiguration =
    UntrustedStorageTransactionStoreBaseConfiguration &
        Readonly<{ [positivelyVerifiedRecordBootstrap]: true }>;

type StoredAuthenticatedRecoveryHeadRecord = Readonly<{
    lastTransactionIdentifier: string;
    predecessorHeadDigest: string;
    recordVersion: number;
    records: ReadonlyMap<
        string,
        Readonly<{ objectKey: string; sealedValueDigest: string }>
    >;
    recoveryIdentity: string;
    transitionSequence: bigint;
}>;

type AuthenticatedRecoveryPublication = Readonly<{
    head: StoredAuthenticatedRecoveryHeadRecord;
    sealedHeadBytes: Uint8Array;
}>;

type AuthenticatedRecoveryRuntime = {
    currentHead: StoredAuthenticatedRecoveryHeadRecord | undefined;
    currentSealedHeadBytes: Uint8Array | undefined;
    expectedRecoveryIdentity: string;
    initialized: boolean;
    readonly protection: UntrustedStorageAuthenticatedRecoveryProtection;
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
    authenticatedRecoveryPublication:
        | AuthenticatedRecoveryPublication
        | undefined;
    changes: Map<string, TransactionChange>;
    expiresAtMilliseconds: number;
    identifier: string;
    pendingCleanupObjectKeys: Set<string>;
    state: TransactionState;
    totalDeclaredByteLength: number;
};

const hasExactKeys = (
    value: Record<string, unknown>,
    expectedKeys: readonly string[],
): boolean => {
    const keys = Object.keys(value);

    return (
        keys.length === expectedKeys.length &&
        keys.every((key, index) => key === expectedKeys[index])
    );
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
    typeof value === 'object' && value !== null && !Array.isArray(value);

const isUint8Array = (value: unknown): value is Uint8Array =>
    ArrayBuffer.isView(value) &&
    Object.prototype.toString.call(value) === '[object Uint8Array]';

const encodeAuthenticatedRecoveryHead = (
    head: StoredAuthenticatedRecoveryHeadRecord,
): Uint8Array =>
    textEncoder.encode(
        JSON.stringify({
            lastTransactionIdentifier: head.lastTransactionIdentifier,
            predecessorHeadDigest: head.predecessorHeadDigest,
            recordVersion: head.recordVersion,
            records: [...head.records.entries()].map(
                ([encodedLogicalRecordKey, record]) => ({
                    logicalRecordKeyHex: encodedLogicalRecordKey,
                    objectKey: record.objectKey,
                    sealedValueDigest: record.sealedValueDigest,
                }),
            ),
            recoveryIdentity: head.recoveryIdentity,
            transitionSequence: head.transitionSequence.toString(10),
        }),
    );

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
        keyBytes.byteLength > maximumLogicalRecordKeyByteLength
    ) {
        throw new UntrustedStorageTransactionError(
            'MalformedLength',
            `logicalRecordKey must encode between 1 and ${maximumLogicalRecordKeyByteLength} UTF-8 bytes.`,
        );
    }

    return keyBytes;
};

const logicalRecordKeyHex = (logicalRecordKey: string): string =>
    bytesToHex(assertLogicalRecordKey(logicalRecordKey));

const decodeAuthenticatedRecoveryHead = (input: {
    bytes: Uint8Array;
    maximumRecordCount: number;
}): StoredAuthenticatedRecoveryHeadRecord => {
    let value: unknown;
    try {
        value = JSON.parse(fatalTextDecoder.decode(input.bytes));
    } catch (error) {
        throw new UntrustedStorageTransactionError(
            'AuthenticationFailed',
            'authenticated recovery head is not valid JSON.',
            error,
        );
    }
    if (
        !isRecord(value) ||
        !hasExactKeys(value, [
            'lastTransactionIdentifier',
            'predecessorHeadDigest',
            'recordVersion',
            'records',
            'recoveryIdentity',
            'transitionSequence',
        ]) ||
        value.recordVersion !== authenticatedRecoveryHeadRecordVersion ||
        typeof value.lastTransactionIdentifier !== 'string' ||
        !identifierPattern.test(value.lastTransactionIdentifier) ||
        typeof value.predecessorHeadDigest !== 'string' ||
        !hashPattern.test(value.predecessorHeadDigest) ||
        typeof value.recoveryIdentity !== 'string' ||
        !hashPattern.test(value.recoveryIdentity) ||
        typeof value.transitionSequence !== 'string' ||
        !canonicalUnsignedDecimalPattern.test(value.transitionSequence) ||
        !Array.isArray(value.records) ||
        value.records.length > input.maximumRecordCount
    ) {
        throw new UntrustedStorageTransactionError(
            'AuthenticationFailed',
            'authenticated recovery head has a noncanonical shape.',
        );
    }
    const transitionSequence = BigInt(value.transitionSequence);
    if (transitionSequence === 0n || transitionSequence > maximumUnsigned64) {
        throw new UntrustedStorageTransactionError(
            'AuthenticationFailed',
            'authenticated recovery head transition sequence is invalid.',
        );
    }
    const records = new Map<
        string,
        Readonly<{ objectKey: string; sealedValueDigest: string }>
    >();
    let previousLogicalRecordKeyHex: string | undefined;
    for (const record of value.records) {
        if (
            !isRecord(record) ||
            !hasExactKeys(record, [
                'logicalRecordKeyHex',
                'objectKey',
                'sealedValueDigest',
            ]) ||
            typeof record.logicalRecordKeyHex !== 'string' ||
            record.logicalRecordKeyHex.length === 0 ||
            record.logicalRecordKeyHex.length >
                maximumLogicalRecordKeyByteLength * 2 ||
            record.logicalRecordKeyHex.length % 2 !== 0 ||
            !/^[0-9a-f]+$/u.test(record.logicalRecordKeyHex) ||
            typeof record.objectKey !== 'string' ||
            typeof record.sealedValueDigest !== 'string' ||
            !hashPattern.test(record.sealedValueDigest) ||
            (previousLogicalRecordKeyHex !== undefined &&
                record.logicalRecordKeyHex <= previousLogicalRecordKeyHex)
        ) {
            throw new UntrustedStorageTransactionError(
                'AuthenticationFailed',
                'authenticated recovery head record inventory is not canonical.',
            );
        }
        records.set(
            record.logicalRecordKeyHex,
            Object.freeze({
                objectKey: record.objectKey,
                sealedValueDigest: record.sealedValueDigest,
            }),
        );
        previousLogicalRecordKeyHex = record.logicalRecordKeyHex;
    }
    const head = Object.freeze({
        lastTransactionIdentifier: value.lastTransactionIdentifier,
        predecessorHeadDigest: value.predecessorHeadDigest,
        recordVersion: value.recordVersion,
        records,
        recoveryIdentity: value.recoveryIdentity,
        transitionSequence,
    });
    if (!bytesEqual(input.bytes, encodeAuthenticatedRecoveryHead(head))) {
        throw new UntrustedStorageTransactionError(
            'AuthenticationFailed',
            'authenticated recovery head is not canonically encoded.',
        );
    }

    return head;
};

const createAuthenticatedRecoveryRuntime = (
    protection: UntrustedStorageAuthenticatedRecoveryProtection,
): AuthenticatedRecoveryRuntime => {
    if (
        !isUint8Array(protection.recoveryIdentity) ||
        protection.recoveryIdentity.byteLength !== 64 ||
        protection.recoveryIdentity.every((byte) => byte === 0) ||
        typeof protection.deriveDigest !== 'function' ||
        typeof protection.open !== 'function' ||
        typeof protection.seal !== 'function'
    ) {
        throw new UntrustedStorageTransactionError(
            'MalformedLength',
            'authenticated recovery protection has an invalid identity or callback.',
        );
    }
    const recoveryIdentity = protection.recoveryIdentity.slice();
    const expectedRecoveryIdentity = bytesToHex(recoveryIdentity);
    const configuredProtection = Object.freeze({
        deriveDigest: protection.deriveDigest,
        open: protection.open,
        recoveryIdentity,
        seal: protection.seal,
    });

    return {
        currentHead: undefined,
        currentSealedHeadBytes: undefined,
        expectedRecoveryIdentity,
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
    readonly #recoveryHeadKey: string;
    readonly #recoveryPrefix: string;
    readonly #transactions = new Map<string, TransactionRecord>();
    readonly #issuedIdentifiers: Readonly<Record<IdentifierKind, Set<string>>> =
        {
            lease: new Set<string>(),
            transaction: new Set<string>(),
        };
    #exclusiveOperationTail: Promise<void> = Promise.resolve();
    readonly #authenticatedRecovery: AuthenticatedRecoveryRuntime | undefined;

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
        this.#recoveryPrefix = `${this.#rootPrefix}recovery/`;
        this.#recoveryHeadKey = `${this.#recoveryPrefix}current-head`;
        this.#maximumIndexValueByteLength =
            textEncoder.encode(this.#objectPrefix).byteLength +
            encodedIdentifierCharacterLength +
            1 +
            encodedIdentifierCharacterLength;
        this.#maximumOwnedKeyCharacterLength = Math.max(
            this.#indexPrefix.length + maximumLogicalRecordKeyByteLength * 2,
            this.#maximumIndexValueByteLength,
            this.#recoveryHeadKey.length,
        );
        this.#authenticatedRecovery =
            positivelyVerifiedRecordBootstrap in configuration
                ? undefined
                : createAuthenticatedRecoveryRuntime(
                      configuration.authenticatedRecoveryProtection,
                  );
    }

    public async recover(): Promise<UntrustedStorageRecoveryReport> {
        return this.#runExclusive(async () => {
            if (this.#transactions.size !== 0) {
                throw new UntrustedStorageTransactionError(
                    'InvalidState',
                    'recovery requires exclusive ownership with no live transactions.',
                );
            }

            const authenticatedCleanupCount =
                await this.#ensureAuthenticatedRecoveryReady();

            const indexKeys = await this.#listedKeys(this.#indexPrefix);
            const objectKeys = await this.#listedKeys(this.#objectPrefix);
            const recoveryKeys = await this.#listedKeys(this.#recoveryPrefix);
            if (
                recoveryKeys.length > 1 ||
                (recoveryKeys.length === 1 &&
                    recoveryKeys[0] !== this.#recoveryHeadKey)
            ) {
                throw new UntrustedStorageTransactionError(
                    'AdapterFailure',
                    'storage recovery namespace contains an unexpected record.',
                );
            }
            if (
                indexKeys.length + objectKeys.length + recoveryKeys.length >
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
                    'storage recovery found a malformed, dangling, or aliased committed index.',
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
            const authenticatedHeadIsPresent = recoveryKeys.length === 1;
            if (!authenticatedHeadIsPresent) {
                await this.#deleteKeys(
                    unreferencedObjectKeys,
                    'recovery cleanup',
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

    public async beginTransaction(input: {
        lifetimeMilliseconds: number;
    }): Promise<UntrustedStorageTransaction> {
        return this.#runExclusive(async () => {
            await this.#ensureAuthenticatedRecoveryReady();
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
                authenticatedRecoveryPublication: undefined,
                changes: new Map(),
                expiresAtMilliseconds,
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
            await this.#ensureAuthenticatedRecoveryReady();
            const indexKey = this.#indexKey(input.logicalRecordKey);
            const indexValue = await this.#readOwnedIndexValue(indexKey);
            this.#assertAuthenticatedRecoveryMapping(
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
            await this.#assertAuthenticatedRecoveryObjectDigest(
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
            await this.#assertAuthenticatedRecoveryHeadUnchanged();

            return bytes.slice();
        });
    }

    public async cleanupExpiredTransactions(): Promise<number> {
        return this.#runExclusive(async () => {
            await this.#ensureAuthenticatedRecoveryReady();
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
            closeAfterFailure: () =>
                this.#runExclusive(() =>
                    this.#closeTransactionAfterFailure(transaction),
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
        this.#assertAuthenticatedRecoveryMapping(
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
            await this.#assertAuthenticatedRecoveryObjectDigest(
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
        this.#assertAuthenticatedRecoveryMapping(
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
            await this.#assertAuthenticatedRecoveryObjectDigest(
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

    async #prepareAuthenticatedRecoveryPublication(
        transaction: TransactionRecord,
        changes: readonly TransactionChange[],
    ): Promise<AuthenticatedRecoveryPublication | undefined> {
        const recovery = this.#authenticatedRecovery;
        if (recovery === undefined) {
            return undefined;
        }
        await this.#assertAuthenticatedRecoveryHeadUnchanged();
        const records = new Map(recovery.currentHead?.records ?? []);
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
                            await this.#deriveAuthenticatedRecoveryDigest(
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
            recovery.currentHead?.transitionSequence ?? 0n;
        if (previousTransitionSequence >= maximumUnsigned64) {
            throw new UntrustedStorageTransactionError(
                'QuotaExceeded',
                'authenticated recovery transition sequence is exhausted.',
            );
        }
        const predecessorHeadDigest =
            recovery.currentSealedHeadBytes === undefined
                ? '0'.repeat(128)
                : await this.#deriveAuthenticatedRecoveryDigest(
                      recovery.currentSealedHeadBytes,
                  );
        const head = Object.freeze({
            lastTransactionIdentifier: transaction.identifier,
            predecessorHeadDigest,
            recordVersion: authenticatedRecoveryHeadRecordVersion,
            records: orderedRecords,
            recoveryIdentity: recovery.expectedRecoveryIdentity,
            transitionSequence: previousTransitionSequence + 1n,
        });
        const sealedHeadBytes = await this.#sealAuthenticatedRecoveryHead(head);
        const currentStoredValueByteLength =
            await this.#measureStoredValueByteLength();
        const headGrowthByteLength = Math.max(
            0,
            sealedHeadBytes.byteLength -
                (recovery.currentSealedHeadBytes?.byteLength ?? 0),
        );
        const indexGrowthByteLength = changes.reduce(
            (total, change) =>
                change.kind === 'write'
                    ? checkedAdd(
                          total,
                          change.lease.indexValueGrowthByteLength,
                          'authenticated recovery publication index growth',
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
                    'authenticated recovery publication growth',
                ),
                'stored value byte length',
            ) > this.#limits.maximumStoredValueByteLength
        ) {
            sealedHeadBytes.fill(0);
            throw new UntrustedStorageTransactionError(
                'QuotaExceeded',
                'authenticated recovery publication exceeds maximumStoredValueByteLength.',
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
        const addsRecoveryHead =
            recovery.currentSealedHeadBytes === undefined ? 1 : 0;
        if (
            currentOwnedKeyCount +
                newIndexCount -
                deletedIndexCount +
                addsRecoveryHead >
            this.#limits.maximumOwnedRecordCount
        ) {
            sealedHeadBytes.fill(0);
            throw new UntrustedStorageTransactionError(
                'QuotaExceeded',
                'authenticated recovery publication exceeds maximumOwnedRecordCount.',
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
        const authenticatedRecoveryPublication =
            await this.#prepareAuthenticatedRecoveryPublication(
                transaction,
                changes,
            );
        transaction.authenticatedRecoveryPublication =
            authenticatedRecoveryPublication;
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
        if (authenticatedRecoveryPublication !== undefined) {
            expectedValues.push({
                key: this.#recoveryHeadKey,
                value: this.#authenticatedRecovery?.currentSealedHeadBytes?.slice(),
            });
            writes.push({
                key: this.#recoveryHeadKey,
                value: authenticatedRecoveryPublication.sealedHeadBytes.slice(),
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
        if (authenticatedRecoveryPublication !== undefined) {
            const recovery = this.#authenticatedRecovery;
            if (recovery === undefined) {
                throw new UntrustedStorageTransactionError(
                    'InvalidState',
                    'authenticated recovery protection disappeared after commit.',
                );
            }
            recovery.currentHead = authenticatedRecoveryPublication.head;
            recovery.currentSealedHeadBytes =
                authenticatedRecoveryPublication.sealedHeadBytes.slice();
        }
        transaction.state = 'committed-unverified';
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
        transaction.authenticatedRecoveryPublication = undefined;
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
        const authenticatedRecoveryPublication =
            transaction.authenticatedRecoveryPublication;
        if (authenticatedRecoveryPublication !== undefined) {
            const observedSealedHeadBytes =
                await this.#readOwnedRecoveryHeadValue();
            if (
                !bytesEqual(
                    observedSealedHeadBytes,
                    authenticatedRecoveryPublication.sealedHeadBytes,
                )
            ) {
                throw new UntrustedStorageTransactionError(
                    'AuthenticationFailed',
                    'committed authenticated recovery head failed publication reread.',
                );
            }
            const observedHead = await this.#openAuthenticatedRecoveryHead(
                authenticatedRecoveryPublication.sealedHeadBytes,
            );
            const expectedHeadBytes = encodeAuthenticatedRecoveryHead(
                authenticatedRecoveryPublication.head,
            );
            const observedHeadBytes =
                encodeAuthenticatedRecoveryHead(observedHead);
            const headMatches = bytesEqual(
                expectedHeadBytes,
                observedHeadBytes,
            );
            expectedHeadBytes.fill(0);
            observedHeadBytes.fill(0);
            if (!headMatches) {
                throw new UntrustedStorageTransactionError(
                    'AuthenticationFailed',
                    'committed authenticated recovery head changed during publication.',
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
        this.#transactions.delete(transaction.identifier);
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
        this.#transactions.delete(transaction.identifier);
    }

    async #closeTransactionAfterFailure(
        transaction: TransactionRecord,
    ): Promise<void> {
        if (
            transaction.state === 'active' ||
            transaction.state === 'aborting'
        ) {
            try {
                await this.#abortTransaction(transaction);
            } catch (error) {
                transaction.state = 'closed-after-failure';
                this.#transactions.delete(transaction.identifier);
                throw error;
            }
            return;
        }
        if (
            transaction.state === 'committed-unverified' ||
            transaction.state === 'committed'
        ) {
            transaction.state = 'closed-after-failure';
            this.#transactions.delete(transaction.identifier);
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

    async #ensureAuthenticatedRecoveryReady(): Promise<number> {
        const recovery = this.#authenticatedRecovery;
        if (recovery === undefined) {
            return 0;
        }
        if (recovery.initialized) {
            await this.#assertAuthenticatedRecoveryHeadUnchanged();
            return 0;
        }

        const indexKeys = await this.#listedKeys(this.#indexPrefix);
        const objectKeys = await this.#listedKeys(this.#objectPrefix);
        const recoveryKeys = await this.#listedKeys(this.#recoveryPrefix);
        if (
            indexKeys.length + objectKeys.length + recoveryKeys.length >
            this.#limits.maximumOwnedRecordCount
        ) {
            throw new UntrustedStorageTransactionError(
                'QuotaExceeded',
                'owned storage record count exceeds maximumOwnedRecordCount.',
            );
        }
        if (
            recoveryKeys.length > 1 ||
            (recoveryKeys.length === 1 &&
                recoveryKeys[0] !== this.#recoveryHeadKey)
        ) {
            throw new UntrustedStorageTransactionError(
                'AuthenticationFailed',
                'authenticated recovery namespace contains an unexpected record.',
            );
        }
        const sealedHeadBytes = await this.#readOwnedRecoveryHeadValue();
        if (sealedHeadBytes === undefined) {
            if (indexKeys.length !== 0) {
                throw new UntrustedStorageTransactionError(
                    'AuthenticationFailed',
                    'authenticated recovery head is missing for committed storage records.',
                );
            }
            await this.#deleteKeys(
                objectKeys,
                'authenticated recovery abandoned-write cleanup',
            );
            recovery.currentHead = undefined;
            recovery.currentSealedHeadBytes = undefined;
            recovery.initialized = true;
            return objectKeys.length;
        }

        const head = await this.#openAuthenticatedRecoveryHead(sealedHeadBytes);
        if (head.recoveryIdentity !== recovery.expectedRecoveryIdentity) {
            throw new UntrustedStorageTransactionError(
                'AuthenticationFailed',
                'authenticated recovery head belongs to another storage authority.',
            );
        }
        if (head.records.size !== indexKeys.length) {
            throw new UntrustedStorageTransactionError(
                'AuthenticationFailed',
                'authenticated recovery head does not match the committed storage index count.',
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
                    'authenticated recovery head omits a committed storage index.',
                );
            }
            const indexValue = await this.#requiredListedIndexValue(indexKey);
            const objectKey = this.#decodeIndexValue(indexValue);
            if (objectKey !== expectedRecord.objectKey) {
                throw new UntrustedStorageTransactionError(
                    'AuthenticationFailed',
                    'authenticated recovery head conflicts with a committed storage index.',
                );
            }
            const objectValue = await this.#readOwnedObjectValue(objectKey);
            if (objectValue === undefined) {
                throw new UntrustedStorageTransactionError(
                    'AuthenticationFailed',
                    'authenticated recovery head references a missing committed object.',
                );
            }
            if (
                (await this.#deriveAuthenticatedRecoveryDigest(objectValue)) !==
                expectedRecord.sealedValueDigest
            ) {
                throw new UntrustedStorageTransactionError(
                    'AuthenticationFailed',
                    'authenticated recovery head detects changed committed object bytes.',
                );
            }
            referencedObjectKeys.add(objectKey);
        }
        const unreferencedObjectKeys = objectKeys.filter(
            (objectKey) => !referencedObjectKeys.has(objectKey),
        );
        await this.#deleteKeys(
            unreferencedObjectKeys,
            'authenticated recovery abandoned-write cleanup',
        );
        recovery.currentHead = head;
        recovery.currentSealedHeadBytes = sealedHeadBytes.slice();
        recovery.initialized = true;

        return unreferencedObjectKeys.length;
    }

    async #assertAuthenticatedRecoveryHeadUnchanged(): Promise<void> {
        const recovery = this.#authenticatedRecovery;
        if (recovery === undefined || !recovery.initialized) {
            return;
        }
        const observedHeadBytes = await this.#readOwnedRecoveryHeadValue();
        if (!bytesEqual(observedHeadBytes, recovery.currentSealedHeadBytes)) {
            throw new UntrustedStorageTransactionError(
                'AuthenticationFailed',
                'authenticated recovery head changed outside the committed transaction chain.',
            );
        }
    }

    #assertAuthenticatedRecoveryMapping(
        logicalRecordKey: string,
        indexValue: Uint8Array | undefined,
    ): void {
        const recovery = this.#authenticatedRecovery;
        if (recovery === undefined) {
            return;
        }
        const expectedRecord = recovery.currentHead?.records.get(
            logicalRecordKeyHex(logicalRecordKey),
        );
        const observedObjectKey =
            indexValue === undefined
                ? undefined
                : this.#decodeIndexValue(indexValue);
        if (expectedRecord?.objectKey !== observedObjectKey) {
            throw new UntrustedStorageTransactionError(
                'AuthenticationFailed',
                'logical storage record conflicts with the authenticated recovery head.',
            );
        }
    }

    async #assertAuthenticatedRecoveryObjectDigest(
        logicalRecordKey: string,
        sealedValue: Uint8Array,
    ): Promise<void> {
        const recovery = this.#authenticatedRecovery;
        if (recovery === undefined) {
            return;
        }
        const expectedRecord = recovery.currentHead?.records.get(
            logicalRecordKeyHex(logicalRecordKey),
        );
        if (expectedRecord === undefined) {
            throw new UntrustedStorageTransactionError(
                'AuthenticationFailed',
                'authenticated recovery head omits an opened committed object.',
            );
        }
        if (
            (await this.#deriveAuthenticatedRecoveryDigest(sealedValue)) !==
            expectedRecord.sealedValueDigest
        ) {
            throw new UntrustedStorageTransactionError(
                'AuthenticationFailed',
                'opened committed object conflicts with the authenticated recovery head.',
            );
        }
    }

    async #openAuthenticatedRecoveryHead(
        sealedHeadBytes: Uint8Array,
    ): Promise<StoredAuthenticatedRecoveryHeadRecord> {
        const recovery = this.#authenticatedRecovery;
        if (recovery === undefined) {
            throw new UntrustedStorageTransactionError(
                'InvalidState',
                'authenticated recovery protection is not configured.',
            );
        }
        let plaintext: Uint8Array | undefined;
        try {
            plaintext = await recovery.protection.open(sealedHeadBytes.slice());
            if (
                !isUint8Array(plaintext) ||
                plaintext.byteLength > this.#limits.maximumStoredValueByteLength
            ) {
                throw new UntrustedStorageTransactionError(
                    'AuthenticationFailed',
                    'authenticated recovery head plaintext has an invalid length.',
                );
            }
            return decodeAuthenticatedRecoveryHead({
                bytes: plaintext,
                maximumRecordCount: this.#limits.maximumOwnedRecordCount,
            });
        } catch (error) {
            if (error instanceof UntrustedStorageTransactionError) {
                throw error;
            }
            throw new UntrustedStorageTransactionError(
                'AuthenticationFailed',
                'authenticated recovery head could not be opened.',
                error,
            );
        } finally {
            plaintext?.fill(0);
        }
    }

    async #deriveAuthenticatedRecoveryDigest(
        bytes: Uint8Array,
    ): Promise<string> {
        const recovery = this.#authenticatedRecovery;
        if (recovery === undefined) {
            throw new UntrustedStorageTransactionError(
                'InvalidState',
                'authenticated recovery protection is not configured.',
            );
        }
        let digest: Uint8Array;
        try {
            digest = await recovery.protection.deriveDigest(bytes.slice());
        } catch (error) {
            throw new UntrustedStorageTransactionError(
                'AuthenticationFailed',
                'authenticated recovery head digest derivation failed.',
                error,
            );
        }
        if (!isUint8Array(digest) || digest.byteLength !== 64) {
            throw new UntrustedStorageTransactionError(
                'AuthenticationFailed',
                'authenticated recovery head digest has an invalid length.',
            );
        }

        return bytesToHex(digest);
    }

    async #sealAuthenticatedRecoveryHead(
        head: StoredAuthenticatedRecoveryHeadRecord,
    ): Promise<Uint8Array> {
        const recovery = this.#authenticatedRecovery;
        if (recovery === undefined) {
            throw new UntrustedStorageTransactionError(
                'InvalidState',
                'authenticated recovery protection is not configured.',
            );
        }
        const plaintext = encodeAuthenticatedRecoveryHead(head);
        if (plaintext.byteLength > this.#limits.maximumStoredValueByteLength) {
            plaintext.fill(0);
            throw new UntrustedStorageTransactionError(
                'QuotaExceeded',
                'authenticated recovery head exceeds the storage quota.',
            );
        }
        try {
            const sealedHeadBytes = await recovery.protection.seal(
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
                    'sealed authenticated recovery head has an invalid length.',
                );
            }

            return sealedHeadBytes.slice();
        } catch (error) {
            if (error instanceof UntrustedStorageTransactionError) {
                throw error;
            }
            throw new UntrustedStorageTransactionError(
                'AuthenticationFailed',
                'authenticated recovery head could not be sealed.',
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
            } else if (key === this.#recoveryHeadKey) {
                maximumByteLength = this.#limits.maximumStoredValueByteLength;
                oversizedErrorCode = 'AuthenticationFailed';
                oversizedMessage =
                    'authenticated recovery head exceeds maximumStoredValueByteLength.';
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

    async #readOwnedRecoveryHeadValue(): Promise<Uint8Array | undefined> {
        const value = await this.#adapter.read(this.#recoveryHeadKey);
        if (value === undefined) {
            return undefined;
        }

        return this.#copyBoundedAdapterValue({
            maximumByteLength: this.#limits.maximumStoredValueByteLength,
            oversizedErrorCode: 'AuthenticationFailed',
            oversizedMessage:
                'authenticated recovery head exceeds maximumStoredValueByteLength.',
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
    const recoveryReport = await store.recover();

    return { recoveryReport, store };
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
    const recoveryReport = await store.recover();

    return { recoveryReport, store };
};
