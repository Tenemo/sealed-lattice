import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

import { canonicalJson, hash512Hex } from '../canonical-json.js';
import { deriveCanonicalObjectHash } from '../hashes.js';

import {
    arrayBufferFromBytes,
    decodeCanonicalHex,
    deriveAesGcmKeyBytes,
    deriveSealedMaterialAesGcmKeyBytes,
    importAesGcmKey,
    randomBytes,
    sealedMaterialAad,
    storageAad,
    subtleCrypto,
} from './aes-gcm.js';
import {
    aesGcmKeyByteLength,
    aesGcmNonceByteLength,
    aesGcmTagBitLength,
    textDecoder,
    textEncoder,
    type EncryptedLocalTrusteeSetupMaterial,
    type LocalTrusteeSetupSealedMaterialDecryptionInput,
    type LocalTrusteeSetupSealedMaterialDecryptionResult,
    type LocalTrusteeSetupSealedMaterialEncryptionInput,
    type LocalTrusteeSetupSealedMaterialEncryptionResult,
    type LocalTrusteeStateStorageDecryptionInput,
    type LocalTrusteeStateStorageDecryptionResult,
    type LocalTrusteeStateStorageEncryptionInput,
    type LocalTrusteeStateStorageEncryptionResult,
} from './constants-and-types.js';
import {
    assertCommitmentHeader,
    validateLocalStatePlaintext,
    validateSealedMaterial,
} from './envelope-validation.js';
import {
    assertNonEmptyString,
    assertNonNegativeSafeInteger,
    assertProtocolHash,
    assertJsonRecord,
    decodeFixedHex,
} from './validation.js';

export const encryptLocalTrusteeSetupSealedMaterial = async (
    input: LocalTrusteeSetupSealedMaterialEncryptionInput,
): Promise<LocalTrusteeSetupSealedMaterialEncryptionResult> => {
    assertNonEmptyString(input.trusteeIdentity, 'trusteeIdentity');
    assertNonNegativeSafeInteger(
        input.trusteeRosterPosition,
        'trusteeRosterPosition',
    );
    assertProtocolHash(
        input.thresholdShareCommitmentRecipientRoot,
        'thresholdShareCommitmentRecipientRoot',
    );
    const storageKeyBytes = decodeFixedHex(
        input.storageKeyBytesHex,
        aesGcmKeyByteLength,
        'storageKeyBytesHex',
    );
    const nonceBytes = randomBytes(aesGcmNonceByteLength);
    const materialPlaintextJson = canonicalJson(input.materialPlaintext);
    const materialPlaintextBytes = textEncoder.encode(materialPlaintextJson);
    const materialRoot = deriveCanonicalObjectHash(input.materialPlaintext);
    const associatedData = sealedMaterialAad(
        input.setupContext,
        materialRoot,
        input,
    );
    const associatedDataBytes = textEncoder.encode(
        canonicalJson(associatedData),
    );
    const materialAadHash = hash512Hex(
        'sealed-lattice-local-trustee-state/sealed-material-aad-hash',
        [associatedDataBytes],
    );
    const keyBytes = deriveSealedMaterialAesGcmKeyBytes(
        storageKeyBytes,
        materialRoot,
        materialAadHash,
    );
    const key = await importAesGcmKey(keyBytes, ['encrypt']);
    const ciphertextBytes = new Uint8Array(
        await subtleCrypto().encrypt(
            {
                name: 'AES-GCM',
                iv: arrayBufferFromBytes(nonceBytes),
                additionalData: arrayBufferFromBytes(associatedDataBytes),
                tagLength: aesGcmTagBitLength,
            },
            key,
            arrayBufferFromBytes(materialPlaintextBytes),
        ),
    );
    const sealedMaterial = {
        objectType: 'EncryptedLocalTrusteeSetupMaterial',
        materialRoot,
        materialAad: associatedData,
        aeadNonceHex: bytesToHex(nonceBytes),
        ciphertextBytesHex: bytesToHex(ciphertextBytes),
    } as const satisfies EncryptedLocalTrusteeSetupMaterial;

    return {
        sealedMaterial,
        materialRoot,
    };
};

export const decryptLocalTrusteeSetupSealedMaterial = async (
    input: LocalTrusteeSetupSealedMaterialDecryptionInput,
): Promise<LocalTrusteeSetupSealedMaterialDecryptionResult> => {
    assertProtocolHash(input.expectedMaterialRoot, 'expectedMaterialRoot');
    assertCommitmentHeader(input.localStateCommitment);
    const storageKeyBytes = decodeFixedHex(
        input.storageKeyBytesHex,
        aesGcmKeyByteLength,
        'storageKeyBytesHex',
    );
    const sealedMaterial = validateSealedMaterial(
        input.sealedMaterial,
        input.expectedMaterialRoot,
        input.setupContext,
        input.localStateCommitment,
        'sealedMaterial',
    );
    const associatedDataBytes = textEncoder.encode(
        canonicalJson(sealedMaterial.materialAad),
    );
    const materialAadHash = hash512Hex(
        'sealed-lattice-local-trustee-state/sealed-material-aad-hash',
        [associatedDataBytes],
    );
    const keyBytes = deriveSealedMaterialAesGcmKeyBytes(
        storageKeyBytes,
        input.expectedMaterialRoot,
        materialAadHash,
    );
    const key = await importAesGcmKey(keyBytes, ['decrypt']);
    const nonceBytes = decodeFixedHex(
        sealedMaterial.aeadNonceHex,
        aesGcmNonceByteLength,
        'sealedMaterial.aeadNonceHex',
    );
    const ciphertextBytes = hexToBytes(sealedMaterial.ciphertextBytesHex);
    const plaintextBytes = new Uint8Array(
        await subtleCrypto().decrypt(
            {
                name: 'AES-GCM',
                iv: arrayBufferFromBytes(nonceBytes),
                additionalData: arrayBufferFromBytes(associatedDataBytes),
                tagLength: aesGcmTagBitLength,
            },
            key,
            arrayBufferFromBytes(ciphertextBytes),
        ),
    );
    const plaintextJson = textDecoder.decode(plaintextBytes);
    const materialPlaintext: unknown = JSON.parse(plaintextJson);
    if (canonicalJson(materialPlaintext) !== plaintextJson) {
        throw new Error('decrypted sealed material must use canonical JSON.');
    }
    if (
        deriveCanonicalObjectHash(materialPlaintext) !==
        input.expectedMaterialRoot
    ) {
        throw new Error(
            'decrypted sealed material does not match expectedMaterialRoot.',
        );
    }

    return { materialPlaintext };
};

export const encryptLocalTrusteeState = async (
    input: LocalTrusteeStateStorageEncryptionInput,
): Promise<LocalTrusteeStateStorageEncryptionResult> => {
    assertCommitmentHeader(input.localStateCommitment);
    const storageKeyBytes = decodeFixedHex(
        input.storageKeyBytesHex,
        aesGcmKeyByteLength,
        'storageKeyBytesHex',
    );
    const localStatePlaintext = validateLocalStatePlaintext(
        input.localStatePlaintext,
        input.localStateCommitment,
        input.setupContext,
    );
    const nonceBytes = randomBytes(aesGcmNonceByteLength);
    const associatedData = storageAad(
        input.setupContext,
        input.localStateCommitment,
    );
    const associatedDataJson = canonicalJson(associatedData);
    const associatedDataBytes = textEncoder.encode(associatedDataJson);
    const storageAadHash = hash512Hex(
        'sealed-lattice-local-trustee-state/aad-hash',
        [associatedDataBytes],
    );
    const plaintextJson = canonicalJson(localStatePlaintext);
    const plaintextBytes = textEncoder.encode(plaintextJson);
    const keyBytes = deriveAesGcmKeyBytes(
        storageKeyBytes,
        input.localStateCommitment.localStateRoot,
        storageAadHash,
    );
    const key = await importAesGcmKey(keyBytes, ['encrypt']);
    const ciphertextBytes = new Uint8Array(
        await subtleCrypto().encrypt(
            {
                name: 'AES-GCM',
                iv: arrayBufferFromBytes(nonceBytes),
                additionalData: arrayBufferFromBytes(associatedDataBytes),
                tagLength: aesGcmTagBitLength,
            },
            key,
            arrayBufferFromBytes(plaintextBytes),
        ),
    );
    const encryptedLocalState = {
        objectType: 'EncryptedLocalTrusteeSetupState',
        storageAad: associatedData,
        aeadNonceHex: bytesToHex(nonceBytes),
        ciphertextBytesHex: bytesToHex(ciphertextBytes),
    } as const;

    return { encryptedLocalState };
};

export const decryptLocalTrusteeState = async (
    input: LocalTrusteeStateStorageDecryptionInput,
): Promise<LocalTrusteeStateStorageDecryptionResult> => {
    assertProtocolHash(input.expectedLocalStateRoot, 'expectedLocalStateRoot');
    if (
        input.encryptedLocalState.objectType !==
        'EncryptedLocalTrusteeSetupState'
    ) {
        throw new TypeError(
            'encryptedLocalState.objectType must be EncryptedLocalTrusteeSetupState.',
        );
    }
    const actualAssociatedData = assertJsonRecord(
        input.encryptedLocalState.storageAad,
        'encryptedLocalState.storageAad',
    );
    const localStateCommitment = assertJsonRecord(
        actualAssociatedData.localStateCommitment,
        'encryptedLocalState.storageAad.localStateCommitment',
    ) as LocalTrusteeStateStorageEncryptionInput['localStateCommitment'];
    assertCommitmentHeader(localStateCommitment);
    if (localStateCommitment.localStateRoot !== input.expectedLocalStateRoot) {
        throw new Error(
            'encryptedLocalState.storageAad.localStateCommitment.localStateRoot does not match expectedLocalStateRoot.',
        );
    }
    const expectedAssociatedData = storageAad(
        input.setupContext,
        localStateCommitment,
    );
    if (
        canonicalJson(actualAssociatedData) !==
        canonicalJson(expectedAssociatedData)
    ) {
        throw new Error(
            'encryptedLocalState.storageAad does not match setupContext and localStateCommitment.',
        );
    }
    const associatedDataBytes = textEncoder.encode(
        canonicalJson(expectedAssociatedData),
    );
    const storageAadHash = hash512Hex(
        'sealed-lattice-local-trustee-state/aad-hash',
        [associatedDataBytes],
    );
    const storageKeyBytes = decodeFixedHex(
        input.storageKeyBytesHex,
        aesGcmKeyByteLength,
        'storageKeyBytesHex',
    );
    const keyBytes = deriveAesGcmKeyBytes(
        storageKeyBytes,
        input.expectedLocalStateRoot,
        storageAadHash,
    );
    const key = await importAesGcmKey(keyBytes, ['decrypt']);
    const nonceBytes = decodeFixedHex(
        input.encryptedLocalState.aeadNonceHex,
        aesGcmNonceByteLength,
        'encryptedLocalState.aeadNonceHex',
    );
    const ciphertextBytes = decodeCanonicalHex(
        input.encryptedLocalState.ciphertextBytesHex,
        'encryptedLocalState.ciphertextBytesHex',
    );
    const plaintextBytes = new Uint8Array(
        await subtleCrypto().decrypt(
            {
                name: 'AES-GCM',
                iv: arrayBufferFromBytes(nonceBytes),
                additionalData: arrayBufferFromBytes(associatedDataBytes),
                tagLength: aesGcmTagBitLength,
            },
            key,
            arrayBufferFromBytes(ciphertextBytes),
        ),
    );
    const parsedLocalStatePlaintext: unknown = JSON.parse(
        textDecoder.decode(plaintextBytes),
    );
    const localStatePlaintext = validateLocalStatePlaintext(
        parsedLocalStatePlaintext,
        localStateCommitment,
        input.setupContext,
    );

    return { localStatePlaintext };
};
