import { hkdf } from '@noble/hashes/hkdf.js';
import { sha384 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import type { ProtocolHash } from '@sealed-lattice/types';

import { canonicalJson, hash512Hex } from './canonical-json.js';
import { deriveCanonicalObjectHash } from './hashes.js';

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const mlKem768SeedByteLength = ml_kem768.lengths.seed!;
const mlKem768PublicKeyByteLength = ml_kem768.lengths.publicKey!;
const mlKem768SecretKeyByteLength = ml_kem768.lengths.secretKey!;
const mlKem768MessageByteLength = ml_kem768.lengths.msg!;
const mlKem768CiphertextByteLength = ml_kem768.lengths.cipherText!;
const aesGcmKeyByteLength = 32;
const aesGcmNonceByteLength = 12;
const aesGcmTagBitLength = 128;
const encryptedEnvelopeAadBindingFieldNames = [
    'ceremonyId',
    'manifestHash',
    'rosterHash',
    'setupParametersHash',
    'setupEpoch',
    'publicMatrixSeedHash',
    'vssCoefficientCommitmentRoot',
    'sourceTrusteeIdentity',
    'sourceTrusteeRosterPosition',
    'recipientIdentity',
    'recipientRosterPosition',
    'sourceTrusteeCommitmentRoot',
    'envelopeSequenceNumber',
    'deliveryPhaseNumber',
    'verificationPhaseNumber',
] as const;

export type PrivateVssMailboxKeyPair = {
    readonly publicKeyBytesHex: string;
    readonly secretKeyBytesHex: string;
    readonly publicKeyHash: ProtocolHash;
};

export type PrivateVssMailboxEncryptionInput = {
    readonly privateEnvelope: unknown;
    readonly privateEnvelopeAad: unknown;
    readonly recipientMailboxPublicKeyBytesHex: string;
    readonly encapsulationRandomnessBytesHex?: string;
    readonly aeadNonceBytesHex?: string;
};

export type PrivateVssMailboxDecryptionInput = {
    readonly encryptedEnvelope: PrivateVssEncryptedEnvelope;
    readonly recipientMailboxSecretKeyBytesHex: string;
};

export type PrivateVssEncryptedEnvelope = Readonly<
    Record<string, unknown> & {
        readonly objectType: 'EncryptedPrivateVssShareEnvelope';
        readonly objectVersion: 1;
        readonly ciphertextContentType: 'private-vss-share-envelope';
        readonly privateEnvelopeHash: ProtocolHash;
        readonly privateEnvelopeAad: unknown;
        readonly privateEnvelopeAadHash: ProtocolHash;
        readonly recipientMailboxPublicKeyHash: ProtocolHash;
        readonly recipientMailboxPublicKeyBytesHash: ProtocolHash;
        readonly kemCiphertextBytesHex: string;
        readonly kemCiphertextHash: ProtocolHash;
        readonly aeadNonceHex: string;
        readonly ciphertextBytesHex: string;
        readonly ciphertextBytesHash: ProtocolHash;
        readonly ciphertextByteLength: number;
        readonly plaintextByteLength: number;
        readonly aeadTagLength: typeof aesGcmTagBitLength;
        readonly encryptedEnvelopeHash: ProtocolHash;
    }
>;

export type PrivateVssMailboxEncryptionResult = {
    readonly encryptedEnvelope: PrivateVssEncryptedEnvelope;
    readonly privateEnvelopeHash: ProtocolHash;
    readonly privateEnvelopeAadHash: ProtocolHash;
};

export type PrivateVssMailboxDecryptionResult = {
    readonly privateEnvelope: unknown;
    readonly privateEnvelopeHash: ProtocolHash;
    readonly privateEnvelopeAadHash: ProtocolHash;
};

const isLowercaseHex = (value: string): boolean =>
    /^[0-9a-f]*$/u.test(value) && value.length % 2 === 0;

const decodeFixedHex = (
    value: string,
    expectedByteLength: number,
    fieldName: string,
): Uint8Array => {
    if (!isLowercaseHex(value)) {
        throw new TypeError(`${fieldName} must be lowercase canonical hex.`);
    }
    const bytes = hexToBytes(value);
    if (bytes.byteLength !== expectedByteLength) {
        throw new TypeError(
            `${fieldName} must be ${String(expectedByteLength)} bytes.`,
        );
    }

    return Uint8Array.from(bytes);
};

const randomBytes = (byteLength: number): Uint8Array => {
    const cryptoProvider = globalThis.crypto;
    if (cryptoProvider === undefined) {
        throw new Error(
            'Private VSS mailbox encryption requires Web Crypto getRandomValues.',
        );
    }
    const bytes = new Uint8Array(byteLength);
    cryptoProvider.getRandomValues(bytes);

    return bytes;
};

const subtleCrypto = (): SubtleCrypto => {
    const subtle = globalThis.crypto?.subtle;
    if (subtle === undefined) {
        throw new Error(
            'Private VSS mailbox encryption requires Web Crypto AES-GCM.',
        );
    }

    return subtle;
};

const arrayBufferFromBytes = (bytes: Uint8Array): ArrayBuffer => {
    const copy = new Uint8Array(bytes.byteLength);
    copy.set(bytes);

    return copy.buffer;
};

const deriveMailboxPublicKeyHash = (publicKeyBytesHex: string): ProtocolHash =>
    deriveCanonicalObjectHash({
        objectType: 'MlKemMailboxPublicKey',
        algorithm: 'ML-KEM-768',
        keyPurpose: 'private-vss-mailbox',
        publicKeyBytesHex,
    });

const hashBytes = (domain: string, bytes: Uint8Array): ProtocolHash =>
    hash512Hex(domain, [bytes]);

const deriveAesGcmKeyBytes = (
    sharedSecret: Uint8Array,
    privateEnvelopeAadHash: ProtocolHash,
    recipientMailboxPublicKeyHash: ProtocolHash,
    kemCiphertextHash: ProtocolHash,
): Uint8Array =>
    hkdf(
        sha384,
        sharedSecret,
        hexToBytes(privateEnvelopeAadHash),
        textEncoder.encode(
            canonicalJson({
                purpose: 'private-vss-mailbox-aes-256-gcm-key',
                privateEnvelopeAadHash,
                recipientMailboxPublicKeyHash,
                kemCiphertextHash,
            }),
        ),
        aesGcmKeyByteLength,
    );

const importAesGcmKey = async (
    keyBytes: Uint8Array,
    keyUsages: readonly KeyUsage[],
): Promise<CryptoKey> =>
    subtleCrypto().importKey(
        'raw',
        arrayBufferFromBytes(keyBytes),
        'AES-GCM',
        false,
        keyUsages,
    );

const aadBindingFields = (
    privateEnvelopeAad: unknown,
): Record<string, unknown> => {
    if (
        typeof privateEnvelopeAad !== 'object' ||
        privateEnvelopeAad === null ||
        Array.isArray(privateEnvelopeAad)
    ) {
        return {};
    }
    const source = privateEnvelopeAad as Readonly<Record<string, unknown>>;

    return Object.fromEntries(
        encryptedEnvelopeAadBindingFieldNames.flatMap((fieldName) =>
            source[fieldName] === undefined
                ? []
                : [[fieldName, source[fieldName]] as const],
        ),
    );
};

export const createPrivateVssMailboxKeyPair = (
    seedBytesHex?: string,
): PrivateVssMailboxKeyPair => {
    const keySeed =
        seedBytesHex === undefined
            ? undefined
            : decodeFixedHex(
                  seedBytesHex,
                  mlKem768SeedByteLength,
                  'seedBytesHex',
              );
    const keyPair = ml_kem768.keygen(keySeed);
    const publicKeyBytesHex = bytesToHex(keyPair.publicKey);
    const secretKeyBytesHex = bytesToHex(keyPair.secretKey);

    return {
        publicKeyBytesHex,
        secretKeyBytesHex,
        publicKeyHash: deriveMailboxPublicKeyHash(publicKeyBytesHex),
    };
};

export const encryptPrivateVssMailboxEnvelope = async (
    input: PrivateVssMailboxEncryptionInput,
): Promise<PrivateVssMailboxEncryptionResult> => {
    const recipientPublicKeyBytes = decodeFixedHex(
        input.recipientMailboxPublicKeyBytesHex,
        mlKem768PublicKeyByteLength,
        'recipientMailboxPublicKeyBytesHex',
    );
    const encapsulationRandomness =
        input.encapsulationRandomnessBytesHex === undefined
            ? randomBytes(mlKem768MessageByteLength)
            : decodeFixedHex(
                  input.encapsulationRandomnessBytesHex,
                  mlKem768MessageByteLength,
                  'encapsulationRandomnessBytesHex',
              );
    const aeadNonce =
        input.aeadNonceBytesHex === undefined
            ? randomBytes(aesGcmNonceByteLength)
            : decodeFixedHex(
                  input.aeadNonceBytesHex,
                  aesGcmNonceByteLength,
                  'aeadNonceBytesHex',
              );
    const privateEnvelopeAadHash = deriveCanonicalObjectHash(
        input.privateEnvelopeAad,
    );
    const privateEnvelopeHash = deriveCanonicalObjectHash(
        input.privateEnvelope,
    );
    const recipientMailboxPublicKeyHash = deriveMailboxPublicKeyHash(
        input.recipientMailboxPublicKeyBytesHex,
    );
    const recipientMailboxPublicKeyBytesHash = hashBytes(
        'sealed-lattice-private-vss-mailbox/ml-kem-768-public-key-v1',
        recipientPublicKeyBytes,
    );
    const kemResult = ml_kem768.encapsulate(
        recipientPublicKeyBytes,
        encapsulationRandomness,
    );
    const kemCiphertextHash = hashBytes(
        'sealed-lattice-private-vss-mailbox/ml-kem-768-ciphertext-v1',
        kemResult.cipherText,
    );
    const aesGcmKeyBytes = deriveAesGcmKeyBytes(
        kemResult.sharedSecret,
        privateEnvelopeAadHash,
        recipientMailboxPublicKeyHash,
        kemCiphertextHash,
    );
    const aesGcmKey = await importAesGcmKey(aesGcmKeyBytes, ['encrypt']);
    // GCM authenticates the canonical-JSON AAD bytes; the AAD protocol hash plus the KEM-ciphertext and recipient-key hashes are folded into HKDF so the symmetric key is bound to this recipient and this encapsulation.
    const aadBytes = textEncoder.encode(
        canonicalJson(input.privateEnvelopeAad),
    );
    const plaintextBytes = textEncoder.encode(
        canonicalJson(input.privateEnvelope),
    );
    const ciphertextBytes = new Uint8Array(
        await subtleCrypto().encrypt(
            {
                name: 'AES-GCM',
                iv: arrayBufferFromBytes(aeadNonce),
                additionalData: arrayBufferFromBytes(aadBytes),
                tagLength: aesGcmTagBitLength,
            },
            aesGcmKey,
            arrayBufferFromBytes(plaintextBytes),
        ),
    );
    const ciphertextBytesHash = hashBytes(
        'sealed-lattice-private-vss-mailbox/aes-256-gcm-ciphertext-v1',
        ciphertextBytes,
    );
    const envelopeWithoutHash = {
        objectType: 'EncryptedPrivateVssShareEnvelope',
        objectVersion: 1,
        ciphertextContentType: 'private-vss-share-envelope',
        ...aadBindingFields(input.privateEnvelopeAad),
        privateEnvelopeHash,
        privateEnvelopeAad: input.privateEnvelopeAad,
        privateEnvelopeAadHash,
        recipientMailboxPublicKeyHash,
        recipientMailboxPublicKeyBytesHash,
        kemCiphertextBytesHex: bytesToHex(kemResult.cipherText),
        kemCiphertextHash,
        aeadNonceHex: bytesToHex(aeadNonce),
        ciphertextBytesHex: bytesToHex(ciphertextBytes),
        ciphertextBytesHash,
        ciphertextByteLength: ciphertextBytes.byteLength,
        plaintextByteLength: plaintextBytes.byteLength,
        aeadTagLength: aesGcmTagBitLength,
    } as const;

    const encryptedEnvelope = {
        ...envelopeWithoutHash,
        encryptedEnvelopeHash: deriveCanonicalObjectHash(envelopeWithoutHash),
    };

    return {
        encryptedEnvelope,
        privateEnvelopeHash,
        privateEnvelopeAadHash,
    };
};

export const decryptPrivateVssMailboxEnvelope = async (
    input: PrivateVssMailboxDecryptionInput,
): Promise<PrivateVssMailboxDecryptionResult> => {
    const secretKeyBytes = decodeFixedHex(
        input.recipientMailboxSecretKeyBytesHex,
        mlKem768SecretKeyByteLength,
        'recipientMailboxSecretKeyBytesHex',
    );
    const kemCiphertextBytes = decodeFixedHex(
        input.encryptedEnvelope.kemCiphertextBytesHex,
        mlKem768CiphertextByteLength,
        'encryptedEnvelope.kemCiphertextBytesHex',
    );
    const aeadNonce = decodeFixedHex(
        input.encryptedEnvelope.aeadNonceHex,
        aesGcmNonceByteLength,
        'encryptedEnvelope.aeadNonceHex',
    );
    if (!isLowercaseHex(input.encryptedEnvelope.ciphertextBytesHex)) {
        throw new TypeError(
            'encryptedEnvelope.ciphertextBytesHex must be lowercase canonical hex.',
        );
    }
    const ciphertextBytes = hexToBytes(
        input.encryptedEnvelope.ciphertextBytesHex,
    );
    const expectedKemCiphertextHash = hashBytes(
        'sealed-lattice-private-vss-mailbox/ml-kem-768-ciphertext-v1',
        kemCiphertextBytes,
    );
    if (
        expectedKemCiphertextHash !== input.encryptedEnvelope.kemCiphertextHash
    ) {
        throw new Error(
            'encryptedEnvelope.kemCiphertextHash does not match kemCiphertextBytesHex.',
        );
    }
    const expectedCiphertextBytesHash = hashBytes(
        'sealed-lattice-private-vss-mailbox/aes-256-gcm-ciphertext-v1',
        ciphertextBytes,
    );
    if (
        expectedCiphertextBytesHash !==
        input.encryptedEnvelope.ciphertextBytesHash
    ) {
        throw new Error(
            'encryptedEnvelope.ciphertextBytesHash does not match ciphertextBytesHex.',
        );
    }
    if (
        ciphertextBytes.byteLength !==
        input.encryptedEnvelope.ciphertextByteLength
    ) {
        throw new Error(
            'encryptedEnvelope.ciphertextByteLength does not match ciphertextBytesHex.',
        );
    }
    const privateEnvelopeAadHash = deriveCanonicalObjectHash(
        input.encryptedEnvelope.privateEnvelopeAad,
    );
    if (
        privateEnvelopeAadHash !==
        input.encryptedEnvelope.privateEnvelopeAadHash
    ) {
        throw new Error(
            'Encrypted private VSS envelope AAD hash does not match its associated-data object.',
        );
    }
    const encryptedEnvelopeWithoutHash = Object.fromEntries(
        Object.entries(input.encryptedEnvelope).filter(
            ([fieldName]) => fieldName !== 'encryptedEnvelopeHash',
        ),
    );
    const expectedEncryptedEnvelopeHash = deriveCanonicalObjectHash(
        encryptedEnvelopeWithoutHash,
    );
    if (
        expectedEncryptedEnvelopeHash !==
        input.encryptedEnvelope.encryptedEnvelopeHash
    ) {
        throw new Error(
            'encryptedEnvelope.encryptedEnvelopeHash does not match the canonical encrypted envelope object.',
        );
    }
    const recipientMailboxPublicKeyHash =
        input.encryptedEnvelope.recipientMailboxPublicKeyHash;
    const sharedSecret = ml_kem768.decapsulate(
        kemCiphertextBytes,
        secretKeyBytes,
    );
    const aesGcmKeyBytes = deriveAesGcmKeyBytes(
        sharedSecret,
        privateEnvelopeAadHash,
        recipientMailboxPublicKeyHash,
        expectedKemCiphertextHash,
    );
    const aesGcmKey = await importAesGcmKey(aesGcmKeyBytes, ['decrypt']);
    const plaintextBytes = new Uint8Array(
        await subtleCrypto().decrypt(
            {
                name: 'AES-GCM',
                iv: arrayBufferFromBytes(aeadNonce),
                additionalData: arrayBufferFromBytes(
                    textEncoder.encode(
                        canonicalJson(
                            input.encryptedEnvelope.privateEnvelopeAad,
                        ),
                    ),
                ),
                tagLength: aesGcmTagBitLength,
            },
            aesGcmKey,
            arrayBufferFromBytes(ciphertextBytes),
        ),
    );
    if (
        plaintextBytes.byteLength !==
        input.encryptedEnvelope.plaintextByteLength
    ) {
        throw new Error(
            'encryptedEnvelope.plaintextByteLength does not match decrypted plaintext.',
        );
    }
    const privateEnvelope = JSON.parse(
        textDecoder.decode(plaintextBytes),
    ) as unknown;
    const privateEnvelopeHash = deriveCanonicalObjectHash(privateEnvelope);
    if (privateEnvelopeHash !== input.encryptedEnvelope.privateEnvelopeHash) {
        throw new Error(
            'Decrypted private VSS envelope hash does not match encryptedEnvelope.privateEnvelopeHash.',
        );
    }

    return {
        privateEnvelope,
        privateEnvelopeHash,
        privateEnvelopeAadHash,
    };
};
