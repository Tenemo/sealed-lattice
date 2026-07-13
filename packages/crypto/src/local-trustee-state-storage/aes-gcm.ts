import { hkdf } from '@noble/hashes/hkdf.js';
import { sha384 } from '@noble/hashes/sha2.js';
import { hexToBytes } from '@noble/hashes/utils.js';
import type { ProtocolHash } from '@sealed-lattice/types';

import { canonicalJson } from '../canonical-json.js';

import {
    aesGcmKeyByteLength,
    textEncoder,
    type LocalTrusteeStateStorageEncryptionInput,
} from './constants-and-types.js';

export const storageAad = (
    setupContext: unknown,
    localStateCommitment: LocalTrusteeStateStorageEncryptionInput['localStateCommitment'],
): Readonly<Record<string, unknown>> => ({
    objectType: 'LocalTrusteeStateStorageAad',
    setupContext,
    localStateCommitment,
});

export const sealedMaterialAad = (
    setupContext: unknown,
    materialRoot: ProtocolHash,
    localStateBinding: Readonly<{
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly thresholdShareCommitmentRecipientRoot: ProtocolHash;
    }>,
): Readonly<Record<string, unknown>> => ({
    objectType: 'LocalTrusteeSetupSealedMaterialAad',
    materialRoot,
    setupContext,
    trusteeIdentity: localStateBinding.trusteeIdentity,
    trusteeRosterPosition: localStateBinding.trusteeRosterPosition,
    thresholdShareCommitmentRecipientRoot:
        localStateBinding.thresholdShareCommitmentRecipientRoot,
});

// The object root and AAD hash separate keys across distinct objects.
// Re-encrypting the same object still requires a fresh random GCM nonce.
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
