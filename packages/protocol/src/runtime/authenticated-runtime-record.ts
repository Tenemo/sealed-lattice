import { hash512Hex } from '@sealed-lattice/crypto/canonical-json';

import {
    UntrustedStorageTransactionError,
    type UntrustedStorageTransaction,
    type UntrustedStorageAuthenticatedRepairProtection,
    type UntrustedStorageTransactionStore,
} from './untrusted-storage-transaction-store.js';

const textEncoder = new TextEncoder();
const fatalTextDecoder = new TextDecoder('utf-8', { fatal: true });
const runtimeRecordVersion = 1;
const aesGcmNonceByteLength = 12;
const aesGcmTagByteLength = 16;
const recordKeyDerivationSaltByteLength = 32;
export const runtimeRecordEnvelopeOverheadByteLength =
    2 + recordKeyDerivationSaltByteLength + 4 + aesGcmTagByteLength;
const hashByteLength = 64;
const participantIdentityByteLength = 64;
const identifierByteLength = 32;
export const maximumRuntimeRecordDerivationCount = 0x1_0000;
const runtimeRecordKeyDerivationDomain = 'sealed-lattice/runtime/record-key/v1';
const authenticatedRepairHeadOperationDomain =
    'sealed-lattice/runtime/repair-head/v1';
const authenticatedRepairHeadLogicalRecordKey = 'runtime/repair/current-head';
const authenticatedRepairIdentityDomain =
    'sealed-lattice/runtime/repair-identity/v1';
const authenticatedRepairHeadDigestDomain =
    'sealed-lattice/runtime/repair-head-digest/v1';

export type RuntimeStorageAuthorityContext = Readonly<{
    actionContextHash: Uint8Array;
    candidateIdentity: Uint8Array;
    ceremonyContextHash: Uint8Array;
    ownerParticipantIdentity: Uint8Array;
    runtimeManifestHash: Uint8Array;
}>;

type AuthenticatedRuntimeRecordErrorCode =
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

declare const runtimeRecordProtectionBrand: unique symbol;

/**
 * Internal key-owning record protection session. The caller supplies exact
 * canonical associated-data bytes, while the session owns root-key access,
 * per-record key derivation, invocation accounting, and envelope authentication.
 * Every successful seal and open must use the fixed canonical envelope profile
 * whose overhead is exported by this module.
 */
export type RuntimeRecordProtectionSession = Readonly<{
    close(): Promise<void> | void;
    openCanonicalEnvelope(input: {
        associatedData: Uint8Array;
        canonicalEnvelope: Uint8Array;
    }): Promise<Uint8Array>;
    sampleIdentifier(input: {
        byteLength: number;
        purpose: string;
    }): Uint8Array;
    sealPlaintext(input: {
        associatedData: Uint8Array;
        plaintext: Uint8Array;
    }): Promise<Uint8Array>;
}>;

export type RuntimeRecordProtection = Readonly<{
    readonly [runtimeRecordProtectionBrand]: true;
}>;

type RuntimeRecordProtectionRecord = {
    authorityContext: RuntimeStorageAuthorityContext;
    releasePromise: Promise<void> | undefined;
    state: 'open' | 'releasing' | 'released';
    session: RuntimeRecordProtectionSession;
};

type RuntimeRecordRootKeyState = {
    issuedKeyDerivationSalts: Set<string>;
    sealingCount: number;
};

type RuntimeRecordLocalSealingState = {
    sealingCount: number;
};

const runtimeRecordRootKeyStates = new WeakMap<
    CryptoKey,
    RuntimeRecordRootKeyState
>();
const runtimeRecordProtectionRecords = new WeakMap<
    object,
    RuntimeRecordProtectionRecord
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

const hashHexToBytes = (hash: string): Uint8Array => {
    if (!/^[0-9a-f]{128}$/u.test(hash)) {
        throw new AuthenticatedRuntimeRecordError(
            'StorageFailure',
            'The shared hash interface returned a malformed digest.',
        );
    }
    return Uint8Array.from({ length: hashByteLength }, (_, byteIndex) =>
        Number.parseInt(hash.slice(byteIndex * 2, byteIndex * 2 + 2), 16),
    );
};

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

export const copyRuntimeStorageAuthorityContext = (
    context: RuntimeStorageAuthorityContext,
): RuntimeStorageAuthorityContext =>
    Object.freeze({
        actionContextHash: copyExactBytes(
            context.actionContextHash,
            hashByteLength,
            'actionContextHash',
        ),
        candidateIdentity: copyExactBytes(
            context.candidateIdentity,
            hashByteLength,
            'candidateIdentity',
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
        runtimeManifestHash: copyExactBytes(
            context.runtimeManifestHash,
            hashByteLength,
            'runtimeManifestHash',
        ),
    });

const requireRecordProtectionRootKey = (key: CryptoKey): void => {
    if (
        key.type !== 'secret' ||
        key.extractable ||
        key.algorithm.name !== 'HKDF' ||
        key.usages.length !== 1 ||
        !key.usages.includes('deriveKey')
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidConfiguration',
            'Runtime storage requires a non-extractable HKDF root key with only deriveKey usage.',
        );
    }
};

const requireRuntimeRecordProtection = (
    protection: RuntimeRecordProtection,
): RuntimeRecordProtectionRecord => {
    const record =
        typeof protection === 'object' && protection !== null
            ? runtimeRecordProtectionRecords.get(protection)
            : undefined;
    if (record === undefined || record.state !== 'open') {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidState',
            'Runtime record protection is unavailable or released.',
        );
    }
    return record;
};

export const createRuntimeRecordProtectionFromSession = (input: {
    authorityContext: RuntimeStorageAuthorityContext;
    session: RuntimeRecordProtectionSession;
}): RuntimeRecordProtection => {
    if (
        typeof input.session?.close !== 'function' ||
        typeof input.session?.openCanonicalEnvelope !== 'function' ||
        typeof input.session?.sampleIdentifier !== 'function' ||
        typeof input.session?.sealPlaintext !== 'function'
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidConfiguration',
            'Runtime record protection requires a complete owned session.',
        );
    }
    const protection = Object.freeze(
        Object.create(null),
    ) as RuntimeRecordProtection;
    runtimeRecordProtectionRecords.set(protection, {
        authorityContext: copyRuntimeStorageAuthorityContext(
            input.authorityContext,
        ),
        releasePromise: undefined,
        state: 'open',
        session: input.session,
    });
    return protection;
};

export const copyRuntimeRecordProtectionAuthorityContext = (
    protection: RuntimeRecordProtection,
): RuntimeStorageAuthorityContext =>
    copyRuntimeStorageAuthorityContext(
        requireRuntimeRecordProtection(protection).authorityContext,
    );

export const releaseRuntimeRecordProtection = (
    protection: RuntimeRecordProtection,
): Promise<void> => {
    const record = runtimeRecordProtectionRecords.get(protection);
    if (record === undefined) {
        return Promise.reject(
            new AuthenticatedRuntimeRecordError(
                'InvalidState',
                'Runtime record protection was not issued by this runtime.',
            ),
        );
    }
    if (record.releasePromise !== undefined) {
        return record.releasePromise;
    }
    if (record.state === 'released') {
        return Promise.resolve();
    }
    record.state = 'releasing';
    record.releasePromise = Promise.resolve()
        .then(() => record.session.close())
        .then(() => {
            record.authorityContext.actionContextHash.fill(0);
            record.authorityContext.candidateIdentity.fill(0);
            record.authorityContext.ceremonyContextHash.fill(0);
            record.authorityContext.ownerParticipantIdentity.fill(0);
            record.authorityContext.runtimeManifestHash.fill(0);
            record.state = 'released';
        })
        .catch((error: unknown) => {
            record.releasePromise = undefined;
            throw error;
        });
    return record.releasePromise;
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

const recordKeyDerivationInfo = (associatedData: Uint8Array): Uint8Array =>
    concatenateBytes([
        encodeVariableBytes(
            textEncoder.encode(runtimeRecordKeyDerivationDomain),
        ),
        encodeVariableBytes(associatedData),
    ]);

const recordAssociatedData = (input: {
    logicalRecordKey: string;
    operationDomain: string;
    protection: RuntimeRecordProtection;
}): Uint8Array => {
    const logicalRecordKeyBytes = textEncoder.encode(input.logicalRecordKey);
    const operationDomainBytes = textEncoder.encode(input.operationDomain);
    if (
        logicalRecordKeyBytes.byteLength === 0 ||
        operationDomainBytes.byteLength === 0 ||
        fatalTextDecoder.decode(logicalRecordKeyBytes) !==
            input.logicalRecordKey ||
        fatalTextDecoder.decode(operationDomainBytes) !== input.operationDomain
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            'Runtime record domain and logical key must be nonempty well-formed strings.',
        );
    }
    const { authorityContext } = requireRuntimeRecordProtection(
        input.protection,
    );
    return concatenateBytes([
        unsigned16LittleEndian(runtimeRecordVersion),
        encodeVariableBytes(operationDomainBytes),
        authorityContext.runtimeManifestHash,
        authorityContext.candidateIdentity,
        authorityContext.ceremonyContextHash,
        authorityContext.actionContextHash,
        authorityContext.ownerParticipantIdentity,
        encodeVariableBytes(logicalRecordKeyBytes),
    ]);
};

const sampleRandomBytes = (
    cryptoProvider: Crypto,
    byteLength: number,
    label: string,
): Uint8Array => {
    const bytes = new Uint8Array(byteLength);
    try {
        cryptoProvider.getRandomValues(bytes);
    } catch (error) {
        throw new AuthenticatedRuntimeRecordError(
            'EntropyFailure',
            `${label} sampling failed.`,
            error,
        );
    }
    return bytes;
};

const deriveRuntimeRecordEncryptionKey = async (input: {
    associatedData: Uint8Array;
    cryptoProvider: Crypto;
    rootKey: CryptoKey;
    salt: Uint8Array;
}): Promise<CryptoKey> => {
    const derivationInfo = recordKeyDerivationInfo(input.associatedData);
    const cryptoDerivationInfo = copyToArrayBufferView(derivationInfo);
    const cryptoSalt = copyToArrayBufferView(input.salt);
    try {
        return await input.cryptoProvider.subtle.deriveKey(
            {
                hash: 'SHA-256',
                info: cryptoDerivationInfo,
                name: 'HKDF',
                salt: cryptoSalt,
            },
            input.rootKey,
            { length: 256, name: 'AES-GCM' },
            false,
            ['decrypt', 'encrypt'],
        );
    } finally {
        cryptoDerivationInfo.fill(0);
        cryptoSalt.fill(0);
        derivationInfo.fill(0);
    }
};

export const sampleRuntimeSecretBytes = (
    protection: RuntimeRecordProtection,
    byteLength: number,
    label: string,
): Uint8Array => {
    if (
        !Number.isSafeInteger(byteLength) ||
        byteLength < 1 ||
        byteLength > 0xffff
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidConfiguration',
            `${label} byte length is outside the runtime secret profile.`,
        );
    }
    const { session } = requireRuntimeRecordProtection(protection);
    let sampled: Uint8Array | undefined;
    try {
        sampled = session.sampleIdentifier({
            byteLength,
            purpose: label,
        });
        if (!isUint8Array(sampled) || sampled.byteLength !== byteLength) {
            throw new AuthenticatedRuntimeRecordError(
                'EntropyFailure',
                `${label} sampling returned an invalid byte length.`,
            );
        }
        return sampled.slice();
    } catch (error) {
        if (error instanceof AuthenticatedRuntimeRecordError) {
            throw error;
        }
        throw new AuthenticatedRuntimeRecordError(
            'EntropyFailure',
            `${label} sampling failed.`,
            error,
        );
    } finally {
        sampled?.fill(0);
    }
};

export const sampleRuntimeIdentifier = (
    protection: RuntimeRecordProtection,
    issuedIdentifiers: Set<string>,
    label: string,
): Uint8Array => {
    const sampled = sampleRuntimeSecretBytes(
        protection,
        identifierByteLength,
        label,
    );
    try {
        const encoded = bytesToHex(sampled);
        if (
            sampled.every((byte) => byte === 0) ||
            issuedIdentifiers.has(encoded)
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'EntropyFailure',
                `${label} sampling returned an invalid or reused value.`,
            );
        }
        issuedIdentifiers.add(encoded);
        return sampled.slice();
    } finally {
        sampled.fill(0);
    }
};

export const sealRuntimeRecord = async (input: {
    logicalRecordKey: string;
    operationDomain: string;
    plaintext: Uint8Array;
    protection: RuntimeRecordProtection;
}): Promise<Uint8Array> => {
    const { session } = requireRuntimeRecordProtection(input.protection);
    const plaintext = copyBoundedBytes(
        input.plaintext,
        0xffff_ffff - runtimeRecordEnvelopeOverheadByteLength,
        'runtime record plaintext',
        true,
    );
    const associatedData = recordAssociatedData(input);
    let canonicalEnvelope: Uint8Array | undefined;
    const sessionAssociatedData = associatedData.slice();
    const sessionPlaintext = plaintext.slice();
    try {
        canonicalEnvelope = await session.sealPlaintext({
            associatedData: sessionAssociatedData,
            plaintext: sessionPlaintext,
        });
        if (
            !isUint8Array(canonicalEnvelope) ||
            canonicalEnvelope.byteLength !==
                plaintext.byteLength +
                    runtimeRecordEnvelopeOverheadByteLength ||
            canonicalEnvelope.byteLength > 0xffff_ffff
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'StorageFailure',
                'The owned runtime-record session returned an invalid canonical envelope.',
            );
        }
        return canonicalEnvelope.slice();
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
        associatedData.fill(0);
        canonicalEnvelope?.fill(0);
        plaintext.fill(0);
        sessionAssociatedData.fill(0);
        sessionPlaintext.fill(0);
    }
};

const openRuntimeRecord = async (input: {
    logicalRecordKey: string;
    operationDomain: string;
    protection: RuntimeRecordProtection;
    sealedBytes: Uint8Array;
}): Promise<Uint8Array> => {
    const { session } = requireRuntimeRecordProtection(input.protection);
    const sealedBytes = copyBoundedBytes(
        input.sealedBytes,
        0xffff_ffff,
        'sealed runtime record',
    );
    const associatedData = recordAssociatedData(input);
    let plaintext: Uint8Array | undefined;
    const sessionAssociatedData = associatedData.slice();
    const sessionCanonicalEnvelope = sealedBytes.slice();
    try {
        plaintext = await session.openCanonicalEnvelope({
            associatedData: sessionAssociatedData,
            canonicalEnvelope: sessionCanonicalEnvelope,
        });
        if (
            !isUint8Array(plaintext) ||
            plaintext.byteLength >
                0xffff_ffff - runtimeRecordEnvelopeOverheadByteLength ||
            sealedBytes.byteLength !==
                plaintext.byteLength + runtimeRecordEnvelopeOverheadByteLength
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                'The owned runtime-record session returned invalid plaintext.',
            );
        }
        return plaintext.slice();
    } catch (error) {
        if (error instanceof AuthenticatedRuntimeRecordError) {
            throw error;
        }
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'Sealed runtime record authentication failed.',
            error,
        );
    } finally {
        associatedData.fill(0);
        plaintext?.fill(0);
        sealedBytes.fill(0);
        sessionAssociatedData.fill(0);
        sessionCanonicalEnvelope.fill(0);
    }
};

const createDerivedAesGcmRuntimeRecordProtectionSession = (input: {
    cryptoProvider?: Crypto;
    rootKey: CryptoKey;
    maximumRecordSealingCount: number;
}): RuntimeRecordProtectionSession => {
    const cryptoProvider = input.cryptoProvider ?? globalThis.crypto;
    if (cryptoProvider?.subtle === undefined) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidConfiguration',
            'Runtime storage requires browser Web Crypto.',
        );
    }
    requireRecordProtectionRootKey(input.rootKey);
    if (
        !Number.isSafeInteger(input.maximumRecordSealingCount) ||
        input.maximumRecordSealingCount <= 0 ||
        input.maximumRecordSealingCount > maximumRuntimeRecordDerivationCount
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidConfiguration',
            'maximumRecordSealingCount must be a positive safe integer no greater than the root-key derivation ceiling.',
        );
    }
    let rootKeyState = runtimeRecordRootKeyStates.get(input.rootKey);
    if (rootKeyState === undefined) {
        rootKeyState = {
            issuedKeyDerivationSalts: new Set<string>(),
            sealingCount: 0,
        };
        runtimeRecordRootKeyStates.set(input.rootKey, rootKeyState);
    }
    const retainedRootKeyState = rootKeyState;
    const localSealingState: RuntimeRecordLocalSealingState = {
        sealingCount: 0,
    };
    const rootKeyReference: { rootKey?: CryptoKey } = {
        rootKey: input.rootKey,
    };
    const requireRootKey = (): CryptoKey => {
        const rootKey = rootKeyReference.rootKey;
        if (rootKey === undefined) {
            throw new AuthenticatedRuntimeRecordError(
                'InvalidState',
                'Runtime record protection was released.',
            );
        }
        return rootKey;
    };

    return Object.freeze({
        close: () => {
            rootKeyReference.rootKey = undefined;
        },
        openCanonicalEnvelope: async ({
            associatedData: untrustedAssociatedData,
            canonicalEnvelope: untrustedCanonicalEnvelope,
        }): Promise<Uint8Array> => {
            const rootKey = requireRootKey();
            const associatedData = copyBoundedBytes(
                untrustedAssociatedData,
                0xffff_ffff,
                'runtime record associated data',
            );
            const canonicalEnvelope = copyBoundedBytes(
                untrustedCanonicalEnvelope,
                0xffff_ffff,
                'sealed runtime record',
            );
            if (
                canonicalEnvelope.byteLength <
                runtimeRecordEnvelopeOverheadByteLength
            ) {
                associatedData.fill(0);
                canonicalEnvelope.fill(0);
                throw new AuthenticatedRuntimeRecordError(
                    'AuthenticationFailed',
                    'Sealed runtime record is truncated.',
                );
            }
            const view = new DataView(
                canonicalEnvelope.buffer,
                canonicalEnvelope.byteOffset,
                canonicalEnvelope.byteLength,
            );
            const version = view.getUint16(0, true);
            const ciphertextByteLength = view.getUint32(
                2 + recordKeyDerivationSaltByteLength,
                true,
            );
            if (
                version !== runtimeRecordVersion ||
                ciphertextByteLength < aesGcmTagByteLength ||
                ciphertextByteLength !==
                    canonicalEnvelope.byteLength -
                        (2 + recordKeyDerivationSaltByteLength + 4)
            ) {
                associatedData.fill(0);
                canonicalEnvelope.fill(0);
                throw new AuthenticatedRuntimeRecordError(
                    'AuthenticationFailed',
                    'Sealed runtime record has noncanonical framing.',
                );
            }
            const keyDerivationSalt = canonicalEnvelope.slice(
                2,
                2 + recordKeyDerivationSaltByteLength,
            );
            const ciphertext = canonicalEnvelope.slice(
                2 + recordKeyDerivationSaltByteLength + 4,
            );
            const fixedNonce = new Uint8Array(aesGcmNonceByteLength);
            const cryptoNonce = copyToArrayBufferView(fixedNonce);
            const cryptoAssociatedData = copyToArrayBufferView(associatedData);
            const cryptoCiphertext = copyToArrayBufferView(ciphertext);
            try {
                const encryptionKey = await deriveRuntimeRecordEncryptionKey({
                    associatedData,
                    cryptoProvider,
                    rootKey,
                    salt: keyDerivationSalt,
                });
                return new Uint8Array(
                    await cryptoProvider.subtle.decrypt(
                        {
                            additionalData: cryptoAssociatedData,
                            iv: cryptoNonce,
                            name: 'AES-GCM',
                            tagLength: 128,
                        },
                        encryptionKey,
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
                associatedData.fill(0);
                canonicalEnvelope.fill(0);
                ciphertext.fill(0);
                cryptoAssociatedData.fill(0);
                cryptoCiphertext.fill(0);
                cryptoNonce.fill(0);
                fixedNonce.fill(0);
                keyDerivationSalt.fill(0);
                untrustedAssociatedData.fill(0);
                untrustedCanonicalEnvelope.fill(0);
            }
        },
        sampleIdentifier: ({ byteLength, purpose }) => {
            requireRootKey();
            return sampleRandomBytes(cryptoProvider, byteLength, purpose);
        },
        sealPlaintext: async ({
            associatedData: untrustedAssociatedData,
            plaintext: untrustedPlaintext,
        }): Promise<Uint8Array> => {
            const rootKey = requireRootKey();
            if (
                localSealingState.sealingCount >=
                input.maximumRecordSealingCount
            ) {
                throw new AuthenticatedRuntimeRecordError(
                    'ResourceLimit',
                    'The runtime-record protection reached its configured sealing limit.',
                );
            }
            if (
                retainedRootKeyState.sealingCount >=
                maximumRuntimeRecordDerivationCount
            ) {
                throw new AuthenticatedRuntimeRecordError(
                    'ResourceLimit',
                    'The runtime-record root key reached its derivation ceiling.',
                );
            }
            const associatedData = copyBoundedBytes(
                untrustedAssociatedData,
                0xffff_ffff,
                'runtime record associated data',
            );
            const plaintext = copyBoundedBytes(
                untrustedPlaintext,
                0xffff_ffff - runtimeRecordEnvelopeOverheadByteLength,
                'runtime record plaintext',
                true,
            );
            const keyDerivationSalt = sampleRandomBytes(
                cryptoProvider,
                recordKeyDerivationSaltByteLength,
                'runtime-record key-derivation salt',
            );
            const encodedSalt = bytesToHex(keyDerivationSalt);
            if (
                retainedRootKeyState.issuedKeyDerivationSalts.has(encodedSalt)
            ) {
                keyDerivationSalt.fill(0);
                associatedData.fill(0);
                plaintext.fill(0);
                throw new AuthenticatedRuntimeRecordError(
                    'EntropyFailure',
                    'Runtime-record key-derivation salt sampling returned a reused value.',
                );
            }
            retainedRootKeyState.issuedKeyDerivationSalts.add(encodedSalt);
            localSealingState.sealingCount += 1;
            retainedRootKeyState.sealingCount += 1;
            const fixedNonce = new Uint8Array(aesGcmNonceByteLength);
            const cryptoNonce = copyToArrayBufferView(fixedNonce);
            const cryptoAssociatedData = copyToArrayBufferView(associatedData);
            const cryptoPlaintext = copyToArrayBufferView(plaintext);
            try {
                const encryptionKey = await deriveRuntimeRecordEncryptionKey({
                    associatedData,
                    cryptoProvider,
                    rootKey,
                    salt: keyDerivationSalt,
                });
                const ciphertext = new Uint8Array(
                    await cryptoProvider.subtle.encrypt(
                        {
                            additionalData: cryptoAssociatedData,
                            iv: cryptoNonce,
                            name: 'AES-GCM',
                            tagLength: 128,
                        },
                        encryptionKey,
                        cryptoPlaintext,
                    ),
                );
                if (
                    ciphertext.byteLength !==
                    plaintext.byteLength + aesGcmTagByteLength
                ) {
                    ciphertext.fill(0);
                    throw new AuthenticatedRuntimeRecordError(
                        'StorageFailure',
                        'AES-GCM returned a runtime record with an unexpected length.',
                    );
                }
                const canonicalEnvelope = concatenateBytes([
                    unsigned16LittleEndian(runtimeRecordVersion),
                    keyDerivationSalt,
                    unsigned32LittleEndian(ciphertext.byteLength),
                    ciphertext,
                ]);
                ciphertext.fill(0);
                return canonicalEnvelope;
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
                associatedData.fill(0);
                cryptoAssociatedData.fill(0);
                cryptoNonce.fill(0);
                cryptoPlaintext.fill(0);
                fixedNonce.fill(0);
                keyDerivationSalt.fill(0);
                plaintext.fill(0);
                untrustedAssociatedData.fill(0);
                untrustedPlaintext.fill(0);
            }
        },
    });
};

export const createRuntimeRecordProtection = (input: {
    authorityContext: RuntimeStorageAuthorityContext;
    cryptoProvider?: Crypto;
    maximumRecordSealingCount: number;
    rootKey: CryptoKey;
}): RuntimeRecordProtection =>
    createRuntimeRecordProtectionFromSession({
        authorityContext: input.authorityContext,
        session: createDerivedAesGcmRuntimeRecordProtectionSession(input),
    });

export const createRuntimeRecordAuthenticatedRepairProtection = (input: {
    authorityContext: RuntimeStorageAuthorityContext;
    cryptoProvider?: Crypto;
    maximumRecordSealingCount: number;
    namespace: string;
    rootKey: CryptoKey;
}): UntrustedStorageAuthenticatedRepairProtection => {
    if (
        input.namespace.length > 64 ||
        !/^[a-z0-9]+(?:-[a-z0-9]+)*$/u.test(input.namespace)
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidConfiguration',
            'Runtime storage namespace must be lowercase kebab-case with at most 64 characters.',
        );
    }
    const protection = createRuntimeRecordProtection(input);
    const authorityContext =
        copyRuntimeRecordProtectionAuthorityContext(protection);
    let repairIdentity: Uint8Array | undefined;
    let configuredRepairIdentity: Uint8Array;
    const namespaceBytes = textEncoder.encode(input.namespace);
    try {
        repairIdentity = hashHexToBytes(
            hash512Hex(authenticatedRepairIdentityDomain, [
                namespaceBytes,
                authorityContext.runtimeManifestHash,
                authorityContext.candidateIdentity,
                authorityContext.ceremonyContextHash,
                authorityContext.actionContextHash,
                authorityContext.ownerParticipantIdentity,
            ]),
        );
        configuredRepairIdentity = repairIdentity.slice();
    } finally {
        authorityContext.actionContextHash.fill(0);
        authorityContext.candidateIdentity.fill(0);
        authorityContext.ceremonyContextHash.fill(0);
        authorityContext.ownerParticipantIdentity.fill(0);
        authorityContext.runtimeManifestHash.fill(0);
        namespaceBytes.fill(0);
        repairIdentity?.fill(0);
    }

    return Object.freeze({
        close: () => releaseRuntimeRecordProtection(protection),
        deriveDigest: (bytes: Uint8Array): Uint8Array => {
            try {
                return hashHexToBytes(
                    hash512Hex(authenticatedRepairHeadDigestDomain, [bytes]),
                );
            } finally {
                bytes.fill(0);
            }
        },
        open: async (sealedHeadBytes: Uint8Array): Promise<Uint8Array> => {
            try {
                return await openRuntimeRecord({
                    logicalRecordKey: authenticatedRepairHeadLogicalRecordKey,
                    operationDomain: authenticatedRepairHeadOperationDomain,
                    protection,
                    sealedBytes: sealedHeadBytes,
                });
            } finally {
                sealedHeadBytes.fill(0);
            }
        },
        repairIdentity: configuredRepairIdentity,
        seal: async (headPlaintext: Uint8Array): Promise<Uint8Array> => {
            try {
                return await sealRuntimeRecord({
                    logicalRecordKey: authenticatedRepairHeadLogicalRecordKey,
                    operationDomain: authenticatedRepairHeadOperationDomain,
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
    let authenticationFailed = false;
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
                authenticatedPlaintext = plaintext;
            },
            logicalRecordKey: input.logicalRecordKey,
        });
    } catch (error) {
        authenticationFailed = true;
        authenticationFailure = error;
    }
    if (authenticationFailed) {
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
