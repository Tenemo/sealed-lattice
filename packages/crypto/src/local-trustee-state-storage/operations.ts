import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import type { ProtocolHash } from '@sealed-lattice/types';

import { canonicalJson, hash512Hex } from '../canonical-json.js';
import { deriveCanonicalObjectHash } from '../hashes.js';
import {
    arrayBufferFromBytes,
    decodeCanonicalHex,
    importAesGcmKey as importWebCryptoAesGcmKey,
    requireSubtleCrypto,
    webCryptoRandomBytes,
} from '../web-crypto.js';

import {
    deriveAesGcmKeyBytes,
    deriveSealedMaterialAesGcmKeyBytes,
    sealedMaterialAad,
    storageAad,
} from './aes-gcm.js';
import {
    aesGcmKeyByteLength,
    aesGcmNonceByteLength,
    aesGcmTagBitLength,
    textDecoder,
    textEncoder,
    type EncryptedLocalTrusteeSetupMaterial,
    type EncryptedLocalTrusteeSetupState,
    type LocalTrusteeSetupSealedMaterialDecryptionInput,
    type LocalTrusteeSetupSealedMaterialEncryptionInput,
    type LocalTrusteeSetupStateSealedPayload,
    type LocalTrusteeStateStorageDecryptionInput,
    type LocalTrusteeStateStorageEncryptionInput,
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

const webCryptoRandomnessUnavailableMessage =
    'Local trustee state storage encryption requires Web Crypto getRandomValues.';
const webCryptoAesGcmUnavailableMessage =
    'Local trustee state storage encryption requires Web Crypto AES-GCM.';
const randomBytes = (byteLength: number): Uint8Array =>
    webCryptoRandomBytes(byteLength, webCryptoRandomnessUnavailableMessage);
const subtleCrypto = (): SubtleCrypto =>
    requireSubtleCrypto(webCryptoAesGcmUnavailableMessage);
const importAesGcmKey = (
    keyBytes: Uint8Array,
    keyUsages: readonly KeyUsage[],
): Promise<CryptoKey> =>
    importWebCryptoAesGcmKey(
        keyBytes,
        keyUsages,
        webCryptoAesGcmUnavailableMessage,
    );

export const deriveLocalTrusteeSetupStateCommitmentRoot = (
    commitment: Omit<
        LocalTrusteeStateStorageEncryptionInput['localStateCommitment'],
        'localStateRoot'
    >,
): ProtocolHash =>
    deriveCanonicalObjectHash({
        objectType: commitment.objectType,
        setupContextHash: commitment.setupContextHash,
        trusteeIdentity: commitment.trusteeIdentity,
        trusteeRosterPosition: commitment.trusteeRosterPosition,
        thresholdShareCommitmentRecipientRoot:
            commitment.thresholdShareCommitmentRecipientRoot,
        aggregateThresholdShareRoot: commitment.aggregateThresholdShareRoot,
    });

const assertLocalStateCommitmentRoot = (
    commitment: LocalTrusteeStateStorageEncryptionInput['localStateCommitment'],
): void => {
    const expectedRoot = deriveLocalTrusteeSetupStateCommitmentRoot(commitment);
    if (commitment.localStateRoot !== expectedRoot) {
        throw new Error(
            'localStateCommitment.localStateRoot does not match the canonical local state commitment.',
        );
    }
};

export const encryptLocalTrusteeSetupSealedMaterial = async (
    input: LocalTrusteeSetupSealedMaterialEncryptionInput,
): Promise<EncryptedLocalTrusteeSetupMaterial> => {
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
        input.setupContextHash,
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
    return {
        objectType: 'EncryptedLocalTrusteeSetupMaterial',
        materialRoot,
        materialAad: associatedData,
        aeadNonceHex: bytesToHex(nonceBytes),
        ciphertextBytesHex: bytesToHex(ciphertextBytes),
    } as const satisfies EncryptedLocalTrusteeSetupMaterial;
};

export const decryptLocalTrusteeSetupSealedMaterial = async (
    input: LocalTrusteeSetupSealedMaterialDecryptionInput,
): Promise<unknown> => {
    assertProtocolHash(input.expectedMaterialRoot, 'expectedMaterialRoot');
    assertCommitmentHeader(input.localStateCommitment);
    assertLocalStateCommitmentRoot(input.localStateCommitment);
    const storageKeyBytes = decodeFixedHex(
        input.storageKeyBytesHex,
        aesGcmKeyByteLength,
        'storageKeyBytesHex',
    );
    const sealedMaterial = validateSealedMaterial(
        input.sealedMaterial,
        input.expectedMaterialRoot,
        input.setupContextHash,
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

    return materialPlaintext;
};

export const encryptLocalTrusteeState = async (
    input: LocalTrusteeStateStorageEncryptionInput,
): Promise<EncryptedLocalTrusteeSetupState> => {
    assertCommitmentHeader(input.localStateCommitment);
    assertLocalStateCommitmentRoot(input.localStateCommitment);
    const storageKeyBytes = decodeFixedHex(
        input.storageKeyBytesHex,
        aesGcmKeyByteLength,
        'storageKeyBytesHex',
    );
    const localStatePlaintext = validateLocalStatePlaintext(
        input.localStatePlaintext,
        input.localStateCommitment,
        input.setupContextHash,
    );
    const nonceBytes = randomBytes(aesGcmNonceByteLength);
    const associatedData = storageAad(
        input.setupContextHash,
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
    return {
        objectType: 'EncryptedLocalTrusteeSetupState',
        storageAad: associatedData,
        aeadNonceHex: bytesToHex(nonceBytes),
        ciphertextBytesHex: bytesToHex(ciphertextBytes),
    } as const satisfies EncryptedLocalTrusteeSetupState;
};

export const decryptLocalTrusteeState = async (
    input: LocalTrusteeStateStorageDecryptionInput,
): Promise<LocalTrusteeSetupStateSealedPayload> => {
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
    assertLocalStateCommitmentRoot(localStateCommitment);
    if (localStateCommitment.localStateRoot !== input.expectedLocalStateRoot) {
        throw new Error(
            'encryptedLocalState.storageAad.localStateCommitment.localStateRoot does not match expectedLocalStateRoot.',
        );
    }
    const expectedAssociatedData = storageAad(
        input.setupContextHash,
        localStateCommitment,
    );
    if (
        canonicalJson(actualAssociatedData) !==
        canonicalJson(expectedAssociatedData)
    ) {
        throw new Error(
            'encryptedLocalState.storageAad does not match setupContextHash and localStateCommitment.',
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
        input.setupContextHash,
    );

    return localStatePlaintext;
};
