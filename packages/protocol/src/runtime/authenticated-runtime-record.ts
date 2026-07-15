import { sha512 } from '@noble/hashes/sha2.js';

import {
    UntrustedStorageTransactionError,
    type UntrustedStorageTransaction,
    type UntrustedStorageAuthenticatedRecoveryProtection,
    type UntrustedStorageTransactionStore,
} from './untrusted-storage-transaction-store.js';

const textEncoder = new TextEncoder();
const runtimeRecordVersion = 1;
const aesGcmNonceByteLength = 12;
const aesGcmTagByteLength = 16;
const hashByteLength = 64;
const participantIdentityByteLength = 64;
const identifierByteLength = 32;
const maximumAesGcmRandomNonceInvocationCount = 0x1_0000_0000;
const authenticatedRecoveryHeadOperationDomain =
    'sealed-lattice/runtime/recovery-head/v1';
const authenticatedRecoveryHeadLogicalRecordKey =
    'runtime/recovery/current-head';
const authenticatedRecoveryIdentityDomain =
    'sealed-lattice/runtime/recovery-identity/v1';

export type RuntimeStorageAuthorityContext = Readonly<{
    actionContextHash: Uint8Array;
    ceremonyContextHash: Uint8Array;
    ownerParticipantIdentity: Uint8Array;
    runtimeBuildManifestHash: Uint8Array;
    suiteIdentifier: Uint8Array;
}>;

export type AuthenticatedRuntimeRecordErrorCode =
    | 'AuthenticationFailed'
    | 'CleanupFailed'
    | 'Conflict'
    | 'EntropyFailure'
    | 'InvalidConfiguration'
    | 'InvalidInput'
    | 'InvalidState'
    | 'MissingRecord'
    | 'ResourceLimit'
    | 'StorageFailure';

export class AuthenticatedRuntimeRecordError extends Error {
    public readonly code: AuthenticatedRuntimeRecordErrorCode;
    public readonly failureCause: unknown;

    public constructor(
        code: AuthenticatedRuntimeRecordErrorCode,
        message: string,
        failureCause?: unknown,
    ) {
        super(message);
        this.name = 'AuthenticatedRuntimeRecordError';
        this.code = code;
        this.failureCause = failureCause;
    }
}

type RuntimeRecordProtection = Readonly<{
    authorityContext: RuntimeStorageAuthorityContext;
    encryptionKey: CryptoKey;
    cryptoProvider: Crypto;
    keySealingState: RuntimeRecordKeySealingState;
    localSealingState: RuntimeRecordLocalSealingState;
    maximumRecordSealingCount: number;
}>;

type RuntimeRecordKeySealingState = {
    issuedNonces: Set<string>;
    sealingCount: number;
};

type RuntimeRecordLocalSealingState = {
    sealingCount: number;
};

const runtimeRecordKeySealingStates = new WeakMap<
    CryptoKey,
    RuntimeRecordKeySealingState
>();

type OpenedRuntimeRecord = Readonly<{
    plaintext: Uint8Array;
    sealedBytes: Uint8Array;
}>;

const isUint8Array = (value: unknown): value is Uint8Array =>
    ArrayBuffer.isView(value) &&
    Object.prototype.toString.call(value) === '[object Uint8Array]';

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
    let difference = 0;
    for (let byteIndex = 0; byteIndex < left.byteLength; byteIndex += 1) {
        difference |= left[byteIndex] ^ right[byteIndex];
    }
    return difference === 0;
};

export const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

export const copyExactBytes = (
    value: unknown,
    byteLength: number,
    label: string,
): Uint8Array => {
    if (!isUint8Array(value) || value.byteLength !== byteLength) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            `${label} must be exactly ${byteLength} bytes.`,
        );
    }
    return value.slice();
};

export const copyBoundedBytes = (
    value: unknown,
    maximumByteLength: number,
    label: string,
    allowEmpty = false,
): Uint8Array => {
    if (
        !isUint8Array(value) ||
        (!allowEmpty && value.byteLength === 0) ||
        value.byteLength > maximumByteLength
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            `${label} has an invalid byte length.`,
        );
    }
    return value.slice();
};

const copyAuthorityContext = (
    context: RuntimeStorageAuthorityContext,
): RuntimeStorageAuthorityContext =>
    Object.freeze({
        actionContextHash: copyExactBytes(
            context.actionContextHash,
            hashByteLength,
            'actionContextHash',
        ),
        ceremonyContextHash: copyExactBytes(
            context.ceremonyContextHash,
            hashByteLength,
            'ceremonyContextHash',
        ),
        ownerParticipantIdentity: copyExactBytes(
            context.ownerParticipantIdentity,
            participantIdentityByteLength,
            'ownerParticipantIdentity',
        ),
        runtimeBuildManifestHash: copyExactBytes(
            context.runtimeBuildManifestHash,
            hashByteLength,
            'runtimeBuildManifestHash',
        ),
        suiteIdentifier: copyExactBytes(
            context.suiteIdentifier,
            hashByteLength,
            'suiteIdentifier',
        ),
    });

const requireEncryptionKey = (key: CryptoKey): void => {
    const algorithm = key.algorithm as Partial<AesKeyAlgorithm>;
    if (
        key.type !== 'secret' ||
        key.extractable ||
        algorithm.name !== 'AES-GCM' ||
        algorithm.length !== 256 ||
        key.usages.length !== 2 ||
        !key.usages.includes('decrypt') ||
        !key.usages.includes('encrypt')
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidConfiguration',
            'Runtime storage requires a non-extractable 256-bit AES-GCM key with only encrypt and decrypt usages.',
        );
    }
};

export const createRuntimeRecordProtection = (input: {
    authorityContext: RuntimeStorageAuthorityContext;
    cryptoProvider?: Crypto;
    encryptionKey: CryptoKey;
    maximumRecordSealingCount: number;
}): RuntimeRecordProtection => {
    const cryptoProvider = input.cryptoProvider ?? globalThis.crypto;
    if (cryptoProvider?.subtle === undefined) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidConfiguration',
            'Runtime storage requires browser Web Crypto.',
        );
    }
    requireEncryptionKey(input.encryptionKey);
    if (
        !Number.isSafeInteger(input.maximumRecordSealingCount) ||
        input.maximumRecordSealingCount <= 0 ||
        input.maximumRecordSealingCount >
            maximumAesGcmRandomNonceInvocationCount
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidConfiguration',
            'maximumRecordSealingCount must be a positive safe integer no greater than the AES-GCM random-nonce invocation ceiling.',
        );
    }
    let keySealingState = runtimeRecordKeySealingStates.get(
        input.encryptionKey,
    );
    if (keySealingState === undefined) {
        keySealingState = { issuedNonces: new Set<string>(), sealingCount: 0 };
        runtimeRecordKeySealingStates.set(input.encryptionKey, keySealingState);
    }
    return Object.freeze({
        authorityContext: copyAuthorityContext(input.authorityContext),
        cryptoProvider,
        encryptionKey: input.encryptionKey,
        keySealingState,
        localSealingState: { sealingCount: 0 },
        maximumRecordSealingCount: input.maximumRecordSealingCount,
    });
};

const concatenateBytes = (parts: readonly Uint8Array[]): Uint8Array => {
    const totalByteLength = parts.reduce(
        (total, part) => total + part.byteLength,
        0,
    );
    if (!Number.isSafeInteger(totalByteLength)) {
        throw new AuthenticatedRuntimeRecordError(
            'ResourceLimit',
            'Runtime record framing exceeds the safe integer range.',
        );
    }
    const bytes = new Uint8Array(totalByteLength);
    let offset = 0;
    for (const part of parts) {
        bytes.set(part, offset);
        offset += part.byteLength;
    }
    return bytes;
};

const copyToArrayBufferView = (bytes: Uint8Array): Uint8Array<ArrayBuffer> => {
    const copied = new Uint8Array(new ArrayBuffer(bytes.byteLength));
    copied.set(bytes);
    return copied;
};

const unsigned16LittleEndian = (value: number): Uint8Array => {
    if (!Number.isInteger(value) || value < 0 || value > 0xffff) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            'A runtime record unsigned-16 value is out of range.',
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
            'A runtime record unsigned-32 value is out of range.',
        );
    }
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value, true);
    return bytes;
};

const encodeVariableBytes = (bytes: Uint8Array): Uint8Array =>
    concatenateBytes([unsigned32LittleEndian(bytes.byteLength), bytes]);

const recordAssociatedData = (input: {
    logicalRecordKey: string;
    operationDomain: string;
    protection: RuntimeRecordProtection;
}): Uint8Array => {
    const logicalRecordKeyBytes = textEncoder.encode(input.logicalRecordKey);
    const operationDomainBytes = textEncoder.encode(input.operationDomain);
    if (
        logicalRecordKeyBytes.byteLength === 0 ||
        operationDomainBytes.byteLength === 0
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            'Runtime record domain and logical key must be nonempty.',
        );
    }
    const { authorityContext } = input.protection;
    return concatenateBytes([
        unsigned16LittleEndian(runtimeRecordVersion),
        encodeVariableBytes(operationDomainBytes),
        authorityContext.runtimeBuildManifestHash,
        authorityContext.suiteIdentifier,
        authorityContext.ceremonyContextHash,
        authorityContext.actionContextHash,
        authorityContext.ownerParticipantIdentity,
        encodeVariableBytes(logicalRecordKeyBytes),
    ]);
};

const sampleRandomBytes = (
    protection: RuntimeRecordProtection,
    byteLength: number,
    issuedValues: Set<string>,
    label: string,
): Uint8Array => {
    const bytes = new Uint8Array(byteLength);
    try {
        protection.cryptoProvider.getRandomValues(bytes);
    } catch (error) {
        throw new AuthenticatedRuntimeRecordError(
            'EntropyFailure',
            `${label} sampling failed.`,
            error,
        );
    }
    const encoded = bytesToHex(bytes);
    if (bytes.every((byte) => byte === 0) || issuedValues.has(encoded)) {
        bytes.fill(0);
        throw new AuthenticatedRuntimeRecordError(
            'EntropyFailure',
            `${label} sampling returned an invalid or reused value.`,
        );
    }
    issuedValues.add(encoded);
    return bytes;
};

export const sampleRuntimeIdentifier = (
    protection: RuntimeRecordProtection,
    issuedIdentifiers: Set<string>,
    label: string,
): Uint8Array =>
    sampleRandomBytes(
        protection,
        identifierByteLength,
        issuedIdentifiers,
        label,
    );

export const sealRuntimeRecord = async (input: {
    logicalRecordKey: string;
    operationDomain: string;
    plaintext: Uint8Array;
    protection: RuntimeRecordProtection;
}): Promise<Uint8Array> => {
    if (
        input.protection.localSealingState.sealingCount >=
        input.protection.maximumRecordSealingCount
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'ResourceLimit',
            'The runtime-record protection reached its configured sealing limit.',
        );
    }
    if (
        input.protection.keySealingState.sealingCount >=
        maximumAesGcmRandomNonceInvocationCount
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'ResourceLimit',
            'The runtime-record key reached the AES-GCM random-nonce invocation ceiling.',
        );
    }
    const plaintext = copyBoundedBytes(
        input.plaintext,
        0xffff_ffff - aesGcmTagByteLength,
        'runtime record plaintext',
        true,
    );
    const nonce = sampleRandomBytes(
        input.protection,
        aesGcmNonceByteLength,
        input.protection.keySealingState.issuedNonces,
        'AES-GCM nonce',
    );
    input.protection.localSealingState.sealingCount += 1;
    input.protection.keySealingState.sealingCount += 1;
    const associatedData = recordAssociatedData(input);
    const cryptoNonce = copyToArrayBufferView(nonce);
    const cryptoAssociatedData = copyToArrayBufferView(associatedData);
    const cryptoPlaintext = copyToArrayBufferView(plaintext);
    try {
        const ciphertext = new Uint8Array(
            await input.protection.cryptoProvider.subtle.encrypt(
                {
                    additionalData: cryptoAssociatedData,
                    iv: cryptoNonce,
                    name: 'AES-GCM',
                    tagLength: 128,
                },
                input.protection.encryptionKey,
                cryptoPlaintext,
            ),
        );
        if (
            ciphertext.byteLength !==
            plaintext.byteLength + aesGcmTagByteLength
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'StorageFailure',
                'AES-GCM returned a runtime record with an unexpected length.',
            );
        }
        return concatenateBytes([
            unsigned16LittleEndian(runtimeRecordVersion),
            nonce,
            unsigned32LittleEndian(ciphertext.byteLength),
            ciphertext,
        ]);
    } catch (error) {
        if (error instanceof AuthenticatedRuntimeRecordError) {
            throw error;
        }
        throw new AuthenticatedRuntimeRecordError(
            'StorageFailure',
            'Runtime record encryption failed.',
            error,
        );
    } finally {
        cryptoAssociatedData.fill(0);
        cryptoNonce.fill(0);
        cryptoPlaintext.fill(0);
        plaintext.fill(0);
    }
};

const openRuntimeRecord = async (input: {
    logicalRecordKey: string;
    operationDomain: string;
    protection: RuntimeRecordProtection;
    sealedBytes: Uint8Array;
}): Promise<Uint8Array> => {
    const sealedBytes = copyBoundedBytes(
        input.sealedBytes,
        0xffff_ffff,
        'sealed runtime record',
    );
    const minimumByteLength =
        2 + aesGcmNonceByteLength + 4 + aesGcmTagByteLength;
    if (sealedBytes.byteLength < minimumByteLength) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'Sealed runtime record is truncated.',
        );
    }
    const view = new DataView(
        sealedBytes.buffer,
        sealedBytes.byteOffset,
        sealedBytes.byteLength,
    );
    const version = view.getUint16(0, true);
    const ciphertextByteLength = view.getUint32(
        2 + aesGcmNonceByteLength,
        true,
    );
    if (
        version !== runtimeRecordVersion ||
        ciphertextByteLength < aesGcmTagByteLength ||
        ciphertextByteLength !== sealedBytes.byteLength - 18
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'Sealed runtime record has noncanonical framing.',
        );
    }
    const nonce = sealedBytes.slice(2, 2 + aesGcmNonceByteLength);
    const ciphertext = sealedBytes.slice(18);
    const associatedData = recordAssociatedData(input);
    const cryptoNonce = copyToArrayBufferView(nonce);
    const cryptoAssociatedData = copyToArrayBufferView(associatedData);
    const cryptoCiphertext = copyToArrayBufferView(ciphertext);
    try {
        return new Uint8Array(
            await input.protection.cryptoProvider.subtle.decrypt(
                {
                    additionalData: cryptoAssociatedData,
                    iv: cryptoNonce,
                    name: 'AES-GCM',
                    tagLength: 128,
                },
                input.protection.encryptionKey,
                cryptoCiphertext,
            ),
        );
    } catch (error) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'Sealed runtime record authentication failed.',
            error,
        );
    } finally {
        cryptoAssociatedData.fill(0);
        cryptoCiphertext.fill(0);
        cryptoNonce.fill(0);
    }
};

export const createRuntimeRecordAuthenticatedRecoveryProtection = (input: {
    authorityContext: RuntimeStorageAuthorityContext;
    cryptoProvider?: Crypto;
    encryptionKey: CryptoKey;
    maximumRecordSealingCount: number;
}): UntrustedStorageAuthenticatedRecoveryProtection => {
    const protection = createRuntimeRecordProtection(input);
    const recoveryIdentity = sha512(
        concatenateBytes([
            encodeVariableBytes(
                textEncoder.encode(authenticatedRecoveryIdentityDomain),
            ),
            protection.authorityContext.runtimeBuildManifestHash,
            protection.authorityContext.suiteIdentifier,
            protection.authorityContext.ceremonyContextHash,
            protection.authorityContext.actionContextHash,
            protection.authorityContext.ownerParticipantIdentity,
        ]),
    );
    const configuredRecoveryIdentity = recoveryIdentity.slice();
    recoveryIdentity.fill(0);

    return Object.freeze({
        deriveDigest: (bytes: Uint8Array): Uint8Array => {
            try {
                return sha512(bytes);
            } finally {
                bytes.fill(0);
            }
        },
        open: async (sealedHeadBytes: Uint8Array): Promise<Uint8Array> => {
            try {
                return await openRuntimeRecord({
                    logicalRecordKey: authenticatedRecoveryHeadLogicalRecordKey,
                    operationDomain: authenticatedRecoveryHeadOperationDomain,
                    protection,
                    sealedBytes: sealedHeadBytes,
                });
            } finally {
                sealedHeadBytes.fill(0);
            }
        },
        recoveryIdentity: configuredRecoveryIdentity,
        seal: async (headPlaintext: Uint8Array): Promise<Uint8Array> => {
            try {
                return await sealRuntimeRecord({
                    logicalRecordKey: authenticatedRecoveryHeadLogicalRecordKey,
                    operationDomain: authenticatedRecoveryHeadOperationDomain,
                    plaintext: headPlaintext,
                    protection,
                });
            } finally {
                headPlaintext.fill(0);
            }
        },
    });
};

export const readRuntimeRecord = async (input: {
    logicalRecordKey: string;
    operationDomain: string;
    protection: RuntimeRecordProtection;
    store: UntrustedStorageTransactionStore;
}): Promise<OpenedRuntimeRecord | undefined> => {
    let authenticatedPlaintext: Uint8Array | undefined;
    let authenticationFailure: unknown;
    let sealedBytes: Uint8Array | undefined;
    try {
        sealedBytes = await input.store.readAuthenticated({
            authenticate: async ({ bytes }) => {
                const plaintext = await openRuntimeRecord({
                    logicalRecordKey: input.logicalRecordKey,
                    operationDomain: input.operationDomain,
                    protection: input.protection,
                    sealedBytes: bytes,
                });
                if (
                    authenticatedPlaintext !== undefined &&
                    !bytesEqual(authenticatedPlaintext, plaintext)
                ) {
                    plaintext.fill(0);
                    throw new AuthenticatedRuntimeRecordError(
                        'AuthenticationFailed',
                        'Repeated runtime-record authentication produced different plaintext.',
                    );
                }
                authenticatedPlaintext?.fill(0);
                authenticatedPlaintext = plaintext;
            },
            logicalRecordKey: input.logicalRecordKey,
        });
    } catch (error) {
        authenticationFailure = error;
    }
    if (authenticationFailure !== undefined) {
        authenticatedPlaintext?.fill(0);
        if (authenticationFailure instanceof AuthenticatedRuntimeRecordError) {
            throw authenticationFailure;
        }
        throw mapStorageError(authenticationFailure);
    }
    if (sealedBytes === undefined) {
        if (authenticatedPlaintext !== undefined) {
            authenticatedPlaintext.fill(0);
            throw new AuthenticatedRuntimeRecordError(
                'StorageFailure',
                'Storage authenticated bytes for a missing runtime record.',
            );
        }
        return undefined;
    }
    if (authenticatedPlaintext === undefined) {
        throw new AuthenticatedRuntimeRecordError(
            'StorageFailure',
            'Storage returned a runtime record without authenticating it.',
        );
    }
    return {
        plaintext: authenticatedPlaintext,
        sealedBytes: sealedBytes.slice(),
    };
};

export const stageRuntimeRecordWrite = async (input: {
    expectedCurrentSealedBytes?: Uint8Array | null;
    logicalRecordKey: string;
    operationDomain: string;
    plaintext: Uint8Array;
    protection: RuntimeRecordProtection;
    transaction: UntrustedStorageTransaction;
}): Promise<Uint8Array> => {
    const sealedBytes = await sealRuntimeRecord(input);
    try {
        const lease = await input.transaction.issueWriteLease({
            declaredByteLength: sealedBytes.byteLength,
            ...(input.expectedCurrentSealedBytes === undefined
                ? {}
                : {
                      expectedCurrentValue:
                          input.expectedCurrentSealedBytes === null
                              ? null
                              : input.expectedCurrentSealedBytes.slice(),
                  }),
            logicalRecordKey: input.logicalRecordKey,
        });
        await lease.write(sealedBytes);
        await lease.seal(({ bytes }) => {
            if (!bytesEqual(bytes, sealedBytes)) {
                throw new AuthenticatedRuntimeRecordError(
                    'AuthenticationFailed',
                    'Staged runtime record differs from the authenticated ciphertext.',
                );
            }
        });
        return sealedBytes.slice();
    } catch (error) {
        if (error instanceof AuthenticatedRuntimeRecordError) {
            throw error;
        }
        throw mapStorageError(error);
    }
};

export const mapStorageError = (
    error: unknown,
): AuthenticatedRuntimeRecordError => {
    if (error instanceof AuthenticatedRuntimeRecordError) {
        return error;
    }
    if (error instanceof UntrustedStorageTransactionError) {
        switch (error.code) {
            case 'AuthenticationFailed':
            case 'CorruptIndex':
                return new AuthenticatedRuntimeRecordError(
                    'AuthenticationFailed',
                    'Untrusted storage authentication failed.',
                    error,
                );
            case 'Conflict':
                return new AuthenticatedRuntimeRecordError(
                    'Conflict',
                    'Untrusted storage changed during a durable operation.',
                    error,
                );
            case 'CleanupFailed':
                return new AuthenticatedRuntimeRecordError(
                    'CleanupFailed',
                    'Untrusted storage cleanup failed.',
                    error,
                );
            case 'Expired':
            case 'QuotaExceeded':
            case 'MalformedLength':
                return new AuthenticatedRuntimeRecordError(
                    'ResourceLimit',
                    'Untrusted storage exceeded an operation limit.',
                    error,
                );
            case 'InvalidState':
                return new AuthenticatedRuntimeRecordError(
                    'InvalidState',
                    'Untrusted storage entered an invalid operation state.',
                    error,
                );
            case 'AdapterFailure':
                break;
        }
    }
    return new AuthenticatedRuntimeRecordError(
        'StorageFailure',
        'The untrusted storage operation failed unexpectedly.',
        error,
    );
};
