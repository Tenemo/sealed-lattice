import { hkdf } from '@noble/hashes/hkdf.js';
import { sha384 } from '@noble/hashes/sha2.js';
import { hexToBytes } from '@noble/hashes/utils.js';
import type { ProtocolHash } from '@sealed-lattice/types';

import { canonicalJson, hash512Hex } from '../canonical-json.js';

import {
    aesGcmKeyByteLength,
    textEncoder,
    type LocalTrusteeStateStorageEncryptionInput,
} from './constants-and-types.js';
import { isLowercaseHex } from './validation.js';

export const randomBytes = (byteLength: number): Uint8Array => {
    const cryptoProvider = globalThis.crypto;
    if (cryptoProvider === undefined) {
        throw new Error(
            'Local trustee state storage encryption requires Web Crypto getRandomValues.',
        );
    }
    const bytes = new Uint8Array(byteLength);
    cryptoProvider.getRandomValues(bytes);

    return bytes;
};

export const subtleCrypto = (): SubtleCrypto => {
    const subtle = globalThis.crypto?.subtle;
    if (subtle === undefined) {
        throw new Error(
            'Local trustee state storage encryption requires Web Crypto AES-GCM.',
        );
    }

    return subtle;
};

export const arrayBufferFromBytes = (bytes: Uint8Array): ArrayBuffer => {
    const copy = new Uint8Array(bytes.byteLength);
    copy.set(bytes);

    return copy.buffer;
};

export const hashCanonicalValue = (
    domain: string,
    value: unknown,
): ProtocolHash =>
    hash512Hex(domain, [textEncoder.encode(canonicalJson(value))]);

const hashBytes = (domain: string, bytes: Uint8Array): ProtocolHash =>
    hash512Hex(domain, [bytes]);

// Key commitment: AES-GCM is not key-committing, so a hash of the storage key is
// bound into each sealed record to detect a wrong key and to defend against
// partitioning-oracle attacks. This is a bare hash of the key, so it only hides
// the key when the key is high-entropy. The caller must therefore supply
// `storageKeyBytesHex` as uniformly-random 256-bit device key material (for
// example from a platform keystore), never a password or other low-entropy
// secret; otherwise the stored commitment becomes an offline brute-force oracle
// for the storage key, and hence for the sealed threshold-share material. The
// same requirement applies to `sealedMaterialStorageKeyCommitmentHash` below.
// See SECURITY.md "Correct use".
export const localStateStorageKeyCommitmentHash = (
    storageKeyBytes: Uint8Array,
): ProtocolHash =>
    hashBytes(
        'sealed-lattice-local-trustee-state/storage-key-commitment',
        storageKeyBytes,
    );

export const sealedMaterialStorageKeyCommitmentHash = (
    storageKeyBytes: Uint8Array,
): ProtocolHash =>
    hashBytes(
        'sealed-lattice-local-trustee-state/sealed-material-storage-key-commitment',
        storageKeyBytes,
    );

export const assertStorageKeyCommitment = (
    actualCommitmentHash: string,
    expectedCommitmentHash: ProtocolHash,
    fieldName: string,
): void => {
    if (actualCommitmentHash !== expectedCommitmentHash) {
        throw new Error(`${fieldName} does not match storageKeyBytesHex.`);
    }
};

export const storageAad = (
    setupContext: unknown,
    localStateCommitment: LocalTrusteeStateStorageEncryptionInput['localStateCommitment'],
): Readonly<Record<string, unknown>> => ({
    objectType: 'LocalTrusteeStateStorageAad',
    setupContext,
    localStateCommitment,
    localStateRoot: localStateCommitment.localStateRoot,
    localStateCommitmentHash: hashCanonicalValue(
        'sealed-lattice-local-trustee-state/commitment-hash',
        localStateCommitment,
    ),
});

export const sealedMaterialAad = (
    setupContext: unknown,
    materialClass: 'aggregate-threshold-share-sealed',
    materialRoot: ProtocolHash,
    localStateBinding: Readonly<{
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly thresholdShareCommitmentRecipientRoot: ProtocolHash;
    }>,
): Readonly<Record<string, unknown>> => ({
    objectType: 'LocalTrusteeSetupSealedMaterialAad',
    materialClass,
    materialRoot,
    setupContext,
    trusteeIdentity: localStateBinding.trusteeIdentity,
    trusteeRosterPosition: localStateBinding.trusteeRosterPosition,
    thresholdShareCommitmentRecipientRoot:
        localStateBinding.thresholdShareCommitmentRecipientRoot,
});

// GCM safety comes from per-object key separation: the HKDF salt is the unique object root, so even a repeated random nonce never recurs under the same derived key.
export const deriveAesGcmKeyBytes = (
    storageKeyBytes: Uint8Array,
    localStateRoot: ProtocolHash,
    storageAadHash: ProtocolHash,
): Uint8Array =>
    hkdf(
        sha384,
        storageKeyBytes,
        hexToBytes(localStateRoot),
        textEncoder.encode(
            canonicalJson({
                purpose: 'local-trustee-state-storage-aes-256-gcm-key',
                localStateRoot,
                storageAadHash,
            }),
        ),
        aesGcmKeyByteLength,
    );

export const deriveSealedMaterialAesGcmKeyBytes = (
    storageKeyBytes: Uint8Array,
    materialRoot: ProtocolHash,
    materialAadHash: ProtocolHash,
): Uint8Array =>
    hkdf(
        sha384,
        storageKeyBytes,
        hexToBytes(materialRoot),
        textEncoder.encode(
            canonicalJson({
                purpose: 'local-trustee-setup-sealed-material-aes-256-gcm-key',
                materialRoot,
                materialAadHash,
            }),
        ),
        aesGcmKeyByteLength,
    );

export const decodeCanonicalHex = (
    value: string,
    fieldName: string,
): Uint8Array => {
    if (!isLowercaseHex(value)) {
        throw new TypeError(`${fieldName} must be lowercase canonical hex.`);
    }

    return hexToBytes(value);
};

export const importAesGcmKey = async (
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
