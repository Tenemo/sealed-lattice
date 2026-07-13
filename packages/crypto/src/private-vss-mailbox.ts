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

export type PrivateVssMailboxKeyPair = {
    readonly publicKeyBytesHex: string;
    readonly secretKeyBytesHex: string;
    readonly publicKeyHash: ProtocolHash;
};

export type PrivateVssMailboxEncryptionInput = {
    readonly privateEnvelope: unknown;
    readonly privateEnvelopeAad: unknown;
    readonly recipientMailboxPublicKeyBytesHex: string;
};

export type PrivateVssMailboxDecryptionInput = {
    readonly encryptedEnvelope: PrivateVssEncryptedEnvelope;
    readonly expectedPrivateEnvelopeHash: ProtocolHash;
    readonly expectedEncryptedEnvelopeHash: ProtocolHash;
    readonly recipientMailboxSecretKeyBytesHex: string;
};

export type PrivateVssEncryptedEnvelope = Readonly<
    Record<string, unknown> & {
        readonly objectType: 'EncryptedPrivateVssShareEnvelope';
        readonly privateEnvelopeAad: unknown;
        readonly recipientMailboxPublicKeyHash: ProtocolHash;
        readonly kemCiphertextBytesHex: string;
        readonly aeadNonceHex: string;
        readonly ciphertextBytesHex: string;
    }
>;

export type PrivateVssMailboxEncryptionResult = {
    readonly encryptedEnvelope: PrivateVssEncryptedEnvelope;
    readonly encryptedEnvelopeHash: ProtocolHash;
};

export type PrivateVssMailboxDecryptionResult = {
    readonly privateEnvelope: unknown;
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
    const encapsulationRandomness = randomBytes(mlKem768MessageByteLength);
    const aeadNonce = randomBytes(aesGcmNonceByteLength);
    const privateEnvelopeAadHash = deriveCanonicalObjectHash(
        input.privateEnvelopeAad,
    );
    const recipientMailboxPublicKeyHash = deriveMailboxPublicKeyHash(
        input.recipientMailboxPublicKeyBytesHex,
    );
    const kemResult = ml_kem768.encapsulate(
        recipientPublicKeyBytes,
        encapsulationRandomness,
    );
    const kemCiphertextHash = hashBytes(
        'sealed-lattice-private-vss-mailbox/ml-kem-768-ciphertext',
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
    const encryptedEnvelope = {
        objectType: 'EncryptedPrivateVssShareEnvelope',
        privateEnvelopeAad: input.privateEnvelopeAad,
        recipientMailboxPublicKeyHash,
        kemCiphertextBytesHex: bytesToHex(kemResult.cipherText),
        aeadNonceHex: bytesToHex(aeadNonce),
        ciphertextBytesHex: bytesToHex(ciphertextBytes),
    } as const satisfies PrivateVssEncryptedEnvelope;

    return {
        encryptedEnvelope,
        encryptedEnvelopeHash: deriveCanonicalObjectHash(encryptedEnvelope),
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
        'sealed-lattice-private-vss-mailbox/ml-kem-768-ciphertext',
        kemCiphertextBytes,
    );
    const privateEnvelopeAadHash = deriveCanonicalObjectHash(
        input.encryptedEnvelope.privateEnvelopeAad,
    );
    const expectedEncryptedEnvelopeHash = deriveCanonicalObjectHash(
        input.encryptedEnvelope,
    );
    if (expectedEncryptedEnvelopeHash !== input.expectedEncryptedEnvelopeHash) {
        throw new Error(
            'expectedEncryptedEnvelopeHash does not match the canonical encrypted envelope object.',
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
    const privateEnvelope = JSON.parse(
        textDecoder.decode(plaintextBytes),
    ) as unknown;
    const privateEnvelopeHash = deriveCanonicalObjectHash(privateEnvelope);
    if (privateEnvelopeHash !== input.expectedPrivateEnvelopeHash) {
        throw new Error(
            'Decrypted private VSS envelope hash does not match expectedPrivateEnvelopeHash.',
        );
    }

    return { privateEnvelope };
};
