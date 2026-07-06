import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

import { canonicalJson, hash512Hex } from '../canonical-json.js';
import { deriveCanonicalObjectHash } from '../hashes.js';

import {
    arrayBufferFromBytes,
    assertStorageKeyCommitment,
    deriveAesGcmKeyBytes,
    deriveSealedMaterialAesGcmKeyBytes,
    hashBytes,
    hashCanonicalValue,
    importAesGcmKey,
    localStateStorageKeyCommitmentHash,
    randomBytes,
    sealedMaterialAad,
    sealedMaterialStorageKeyCommitmentHash,
    storageAad,
    subtleCrypto,
} from './aes-gcm.js';
import {
    aesGcmKeyByteLength,
    aesGcmNonceByteLength,
    aesGcmTagBitLength,
    localSealedMaterialCiphertextContentType,
    localStateCiphertextContentType,
    localTrusteeSealedMaterialStorageFormat,
    localTrusteeStateStorageFormat,
    textDecoder,
    textEncoder,
    type EncryptedLocalTrusteeSetupMaterial,
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
} from './envelope-validation.js';
import {
    assertNonEmptyString,
    assertNonNegativeSafeInteger,
    assertProtocolHash,
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
    const nonceBytes =
        input.aeadNonceBytesHex === undefined
            ? randomBytes(aesGcmNonceByteLength)
            : decodeFixedHex(
                  input.aeadNonceBytesHex,
                  aesGcmNonceByteLength,
                  'aeadNonceBytesHex',
              );
    const materialPlaintextJson = canonicalJson(input.materialPlaintext);
    const materialPlaintextBytes = textEncoder.encode(materialPlaintextJson);
    const materialRoot = deriveCanonicalObjectHash(input.materialPlaintext);
    const associatedData = sealedMaterialAad(
        input.setupContext,
        input.materialClass,
        materialRoot,
        input,
    );
    const associatedDataBytes = textEncoder.encode(
        canonicalJson(associatedData),
    );
    const materialAadHash = hash512Hex(
        'sealed-lattice-local-trustee-state/sealed-material-aad-hash-v1',
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
    const encryptedMaterialWithoutHash = {
        objectType: 'EncryptedLocalTrusteeSetupMaterial',
        objectVersion: 1,
        storageScheme: localTrusteeSealedMaterialStorageFormat,
        ciphertextContentType: localSealedMaterialCiphertextContentType,
        materialClass: input.materialClass,
        materialRoot,
        materialAad: associatedData,
        materialAadHash,
        keyCommitmentHash:
            sealedMaterialStorageKeyCommitmentHash(storageKeyBytes),
        aeadNonceHex: bytesToHex(nonceBytes),
        ciphertextBytesHex: bytesToHex(ciphertextBytes),
        ciphertextBytesHash: hashBytes(
            'sealed-lattice-local-trustee-state/sealed-material-ciphertext-bytes-v1',
            ciphertextBytes,
        ),
        ciphertextByteLength: ciphertextBytes.byteLength,
        plaintextByteLength: materialPlaintextBytes.byteLength,
        aeadTagLength: aesGcmTagBitLength,
    } as const satisfies Omit<
        EncryptedLocalTrusteeSetupMaterial,
        'encryptedMaterialHash'
    >;
    // Self-hash convention: a record's root is the protocol hash of the same record with its own root field removed; verification strips that field and recomputes.
    const encryptedMaterial = {
        ...encryptedMaterialWithoutHash,
        encryptedMaterialHash: hashCanonicalValue(
            'sealed-lattice-local-trustee-state/sealed-material-envelope-hash-v1',
            encryptedMaterialWithoutHash,
        ),
    } satisfies EncryptedLocalTrusteeSetupMaterial;

    return {
        sealedMaterial: {
            objectType: 'LocalTrusteeSetupStateSealedMaterial',
            objectVersion: 1,
            materialClass: input.materialClass,
            materialRoot,
            ciphertextReference: encryptedMaterial.encryptedMaterialHash,
            encryptedMaterial,
        },
        materialRoot,
        materialPlaintextHash: hash512Hex(
            'sealed-lattice-local-trustee-state/sealed-material-plaintext-hash-v1',
            [materialPlaintextBytes],
        ),
        materialAadHash,
    };
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
        storageKeyBytes,
    );
    const nonceBytes =
        input.aeadNonceBytesHex === undefined
            ? randomBytes(aesGcmNonceByteLength)
            : decodeFixedHex(
                  input.aeadNonceBytesHex,
                  aesGcmNonceByteLength,
                  'aeadNonceBytesHex',
              );
    const associatedData = storageAad(
        input.setupContext,
        input.localStateCommitment,
    );
    const associatedDataJson = canonicalJson(associatedData);
    const associatedDataBytes = textEncoder.encode(associatedDataJson);
    const storageAadHash = hash512Hex(
        'sealed-lattice-local-trustee-state/aad-hash-v1',
        [associatedDataBytes],
    );
    const localStateCommitmentHash = hashCanonicalValue(
        'sealed-lattice-local-trustee-state/commitment-hash-v1',
        input.localStateCommitment,
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
    const envelopeWithoutHash = {
        objectType: 'EncryptedLocalTrusteeSetupState',
        objectVersion: 1,
        storageScheme: localTrusteeStateStorageFormat,
        ciphertextContentType: localStateCiphertextContentType,
        localStateRoot: input.localStateCommitment.localStateRoot,
        localStateCommitmentHash,
        storageAad: associatedData,
        storageAadHash,
        keyCommitmentHash: localStateStorageKeyCommitmentHash(storageKeyBytes),
        aeadNonceHex: bytesToHex(nonceBytes),
        ciphertextBytesHex: bytesToHex(ciphertextBytes),
        ciphertextBytesHash: hashBytes(
            'sealed-lattice-local-trustee-state/ciphertext-bytes-v1',
            ciphertextBytes,
        ),
        ciphertextByteLength: ciphertextBytes.byteLength,
        plaintextByteLength: plaintextBytes.byteLength,
        aeadTagLength: aesGcmTagBitLength,
    } as const;

    return {
        encryptedLocalState: {
            ...envelopeWithoutHash,
            encryptedLocalStateHash: hashCanonicalValue(
                'sealed-lattice-local-trustee-state/envelope-hash-v1',
                envelopeWithoutHash,
            ),
        },
        localStatePlaintextHash: hash512Hex(
            'sealed-lattice-local-trustee-state/plaintext-hash-v1',
            [plaintextBytes],
        ),
        storageAadHash,
    };
};

export const decryptLocalTrusteeState = async (
    input: LocalTrusteeStateStorageDecryptionInput,
): Promise<LocalTrusteeStateStorageDecryptionResult> => {
    assertProtocolHash(input.expectedLocalStateRoot, 'expectedLocalStateRoot');
    if (
        input.encryptedLocalState.storageScheme !==
        localTrusteeStateStorageFormat
    ) {
        throw new TypeError(
            'encryptedLocalState.storageScheme is not supported.',
        );
    }
    if (
        input.encryptedLocalState.ciphertextContentType !==
        localStateCiphertextContentType
    ) {
        throw new TypeError(
            'encryptedLocalState.ciphertextContentType must be local-trustee-setup-state.',
        );
    }
    if (
        input.encryptedLocalState.localStateRoot !==
        input.expectedLocalStateRoot
    ) {
        throw new Error(
            'encryptedLocalState.localStateRoot does not match expectedLocalStateRoot.',
        );
    }
    const envelopeWithoutHash = {
        ...input.encryptedLocalState,
    } as Record<string, unknown>;
    delete envelopeWithoutHash.encryptedLocalStateHash;
    const expectedEnvelopeHash = hashCanonicalValue(
        'sealed-lattice-local-trustee-state/envelope-hash-v1',
        envelopeWithoutHash,
    );
    if (
        input.encryptedLocalState.encryptedLocalStateHash !==
        expectedEnvelopeHash
    ) {
        throw new Error(
            'encryptedLocalState.encryptedLocalStateHash does not match the canonical envelope.',
        );
    }
    const expectedAssociatedData = storageAad(
        input.setupContext,
        input.encryptedLocalState.storageAad
            .localStateCommitment as LocalTrusteeStateStorageEncryptionInput['localStateCommitment'],
    );
    if (
        canonicalJson(input.encryptedLocalState.storageAad) !==
        canonicalJson(expectedAssociatedData)
    ) {
        throw new Error(
            'encryptedLocalState.storageAad does not match setupContext and localStateCommitment.',
        );
    }
    const associatedDataBytes = textEncoder.encode(
        canonicalJson(expectedAssociatedData),
    );
    const expectedAadHash = hash512Hex(
        'sealed-lattice-local-trustee-state/aad-hash-v1',
        [associatedDataBytes],
    );
    if (input.encryptedLocalState.storageAadHash !== expectedAadHash) {
        throw new Error(
            'encryptedLocalState.storageAadHash does not match storageAad.',
        );
    }
    const storageKeyBytes = decodeFixedHex(
        input.storageKeyBytesHex,
        aesGcmKeyByteLength,
        'storageKeyBytesHex',
    );
    assertStorageKeyCommitment(
        input.encryptedLocalState.keyCommitmentHash,
        localStateStorageKeyCommitmentHash(storageKeyBytes),
        'encryptedLocalState.keyCommitmentHash',
    );
    const keyBytes = deriveAesGcmKeyBytes(
        storageKeyBytes,
        input.expectedLocalStateRoot,
        expectedAadHash,
    );
    const key = await importAesGcmKey(keyBytes, ['decrypt']);
    const nonceBytes = decodeFixedHex(
        input.encryptedLocalState.aeadNonceHex,
        aesGcmNonceByteLength,
        'encryptedLocalState.aeadNonceHex',
    );
    const ciphertextBytes = hexToBytes(
        input.encryptedLocalState.ciphertextBytesHex,
    );
    const expectedCiphertextHash = hashBytes(
        'sealed-lattice-local-trustee-state/ciphertext-bytes-v1',
        ciphertextBytes,
    );
    if (
        input.encryptedLocalState.ciphertextBytesHash !== expectedCiphertextHash
    ) {
        throw new Error(
            'encryptedLocalState.ciphertextBytesHash does not match ciphertextBytesHex.',
        );
    }
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
    if (
        plaintextBytes.byteLength !==
        input.encryptedLocalState.plaintextByteLength
    ) {
        throw new Error(
            'decrypted local trustee state byte length does not match plaintextByteLength.',
        );
    }
    const parsedLocalStatePlaintext: unknown = JSON.parse(
        textDecoder.decode(plaintextBytes),
    );
    const localStateCommitment = input.encryptedLocalState.storageAad
        .localStateCommitment as LocalTrusteeStateStorageEncryptionInput['localStateCommitment'];
    assertCommitmentHeader(localStateCommitment);
    const localStatePlaintext = validateLocalStatePlaintext(
        parsedLocalStatePlaintext,
        localStateCommitment,
        input.setupContext,
        storageKeyBytes,
    );

    return {
        localStatePlaintext,
        localStatePlaintextHash: hash512Hex(
            'sealed-lattice-local-trustee-state/plaintext-hash-v1',
            [plaintextBytes],
        ),
        storageAadHash: expectedAadHash,
    };
};
