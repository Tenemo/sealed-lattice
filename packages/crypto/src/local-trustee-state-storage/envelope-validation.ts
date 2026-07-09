import type { ProtocolHash } from '@sealed-lattice/types';

import { canonicalJson, hash512Hex } from '../canonical-json.js';

import {
    assertStorageKeyCommitment,
    decodeCanonicalHex,
    hashCanonicalValue,
    sealedMaterialAad,
    sealedMaterialStorageKeyCommitmentHash,
} from './aes-gcm.js';
import {
    aesGcmNonceByteLength,
    aesGcmTagBitLength,
    encryptedSealedMaterialFieldNames,
    localTrusteeSealedPayloadFieldNames,
    sealedMaterialFieldNames,
    setupContextFieldNames,
    textEncoder,
    type EncryptedLocalTrusteeSetupMaterial,
    type LocalTrusteeSetupStateSealedMaterial,
    type LocalTrusteeSetupStateSealedPayload,
    type LocalTrusteeStateStorageEncryptionInput,
} from './constants-and-types.js';
import {
    assertExactFields,
    assertJsonRecord,
    assertNonEmptyString,
    assertNonNegativeSafeInteger,
    assertProtocolHash,
    decodeFixedHex,
    numberField,
    protocolHashArrayField,
    stringField,
} from './validation.js';

export const assertCommitmentHeader = (
    localStateCommitment: LocalTrusteeStateStorageEncryptionInput['localStateCommitment'],
): void => {
    if (
        localStateCommitment.objectType !== 'LocalTrusteeSetupStateCommitment'
    ) {
        throw new TypeError(
            'localStateCommitment.objectType must be LocalTrusteeSetupStateCommitment.',
        );
    }
    assertProtocolHash(
        localStateCommitment.localStateRoot,
        'localStateCommitment.localStateRoot',
    );
    assertNonEmptyString(
        localStateCommitment.ceremonyId,
        'localStateCommitment.ceremonyId',
    );
    assertProtocolHash(
        localStateCommitment.manifestHash,
        'localStateCommitment.manifestHash',
    );
    assertProtocolHash(
        localStateCommitment.rosterHash,
        'localStateCommitment.rosterHash',
    );
    assertNonEmptyString(
        localStateCommitment.setupEpoch,
        'localStateCommitment.setupEpoch',
    );
    assertNonEmptyString(
        localStateCommitment.trusteeIdentity,
        'localStateCommitment.trusteeIdentity',
    );
    assertNonNegativeSafeInteger(
        localStateCommitment.trusteeRosterPosition,
        'localStateCommitment.trusteeRosterPosition',
    );
    assertProtocolHash(
        localStateCommitment.thresholdShareCommitmentRecipientRoot,
        'localStateCommitment.thresholdShareCommitmentRecipientRoot',
    );
    assertProtocolHash(
        localStateCommitment.aggregateThresholdShareRoot,
        'localStateCommitment.aggregateThresholdShareRoot',
    );
    assertProtocolHash(
        localStateCommitment.issuedVssAcceptanceRoot,
        'localStateCommitment.issuedVssAcceptanceRoot',
    );
    if (!Array.isArray(localStateCommitment.issuedVssComplaintRoots)) {
        throw new TypeError(
            'localStateCommitment.issuedVssComplaintRoots must be an array of protocol hashes.',
        );
    }
    localStateCommitment.issuedVssComplaintRoots.forEach(
        (complaintRoot, complaintRootIndex) => {
            if (typeof complaintRoot !== 'string') {
                throw new TypeError(
                    `localStateCommitment.issuedVssComplaintRoots.${String(complaintRootIndex)} must be a protocol hash.`,
                );
            }
            assertProtocolHash(
                complaintRoot,
                `localStateCommitment.issuedVssComplaintRoots.${String(complaintRootIndex)}`,
            );
        },
    );
};

const assertSetupContextBinding = (
    setupContext: unknown,
    localStateCommitment: LocalTrusteeStateStorageEncryptionInput['localStateCommitment'],
): void => {
    const setupContextRecord = assertJsonRecord(setupContext, 'setupContext');
    for (const fieldName of setupContextFieldNames) {
        if (setupContextRecord[fieldName] !== localStateCommitment[fieldName]) {
            throw new Error(
                `setupContext.${fieldName} must match localStateCommitment.${fieldName}.`,
            );
        }
    }
};

function validateEncryptedSealedMaterialEnvelope(
    value: unknown,
    expectedMaterialClass: 'aggregate-threshold-share-sealed',
    expectedMaterialRoot: ProtocolHash,
    setupContext: unknown,
    localStateCommitment: LocalTrusteeStateStorageEncryptionInput['localStateCommitment'],
    storageKeyBytes: Uint8Array,
    objectPath: string,
): EncryptedLocalTrusteeSetupMaterial {
    const encryptedMaterial = assertJsonRecord(value, objectPath);
    assertExactFields(
        encryptedMaterial,
        encryptedSealedMaterialFieldNames,
        objectPath,
    );
    if (encryptedMaterial.objectType !== 'EncryptedLocalTrusteeSetupMaterial') {
        throw new TypeError(
            `${objectPath}.objectType must be EncryptedLocalTrusteeSetupMaterial.`,
        );
    }
    if (encryptedMaterial.materialClass !== expectedMaterialClass) {
        throw new TypeError(
            `${objectPath}.materialClass must be ${expectedMaterialClass}.`,
        );
    }
    const materialRoot = stringField(
        encryptedMaterial,
        'materialRoot',
        `${objectPath}.materialRoot`,
    );
    assertProtocolHash(materialRoot, `${objectPath}.materialRoot`);
    if (materialRoot !== expectedMaterialRoot) {
        throw new Error(
            `${objectPath}.materialRoot must match the sealed material root.`,
        );
    }
    const expectedMaterialAad = sealedMaterialAad(
        setupContext,
        expectedMaterialClass,
        expectedMaterialRoot,
        localStateCommitment,
    );
    if (
        canonicalJson(encryptedMaterial.materialAad) !==
        canonicalJson(expectedMaterialAad)
    ) {
        throw new Error(`${objectPath}.materialAad does not match bindings.`);
    }
    const materialAadBytes = textEncoder.encode(
        canonicalJson(expectedMaterialAad),
    );
    const expectedMaterialAadHash = hash512Hex(
        'sealed-lattice-local-trustee-state/sealed-material-aad-hash',
        [materialAadBytes],
    );
    if (encryptedMaterial.materialAadHash !== expectedMaterialAadHash) {
        throw new Error(
            `${objectPath}.materialAadHash does not match materialAad.`,
        );
    }
    stringField(
        encryptedMaterial,
        'keyCommitmentHash',
        `${objectPath}.keyCommitmentHash`,
    );
    assertProtocolHash(
        encryptedMaterial.keyCommitmentHash as string,
        `${objectPath}.keyCommitmentHash`,
    );
    assertStorageKeyCommitment(
        encryptedMaterial.keyCommitmentHash as string,
        sealedMaterialStorageKeyCommitmentHash(storageKeyBytes),
        `${objectPath}.keyCommitmentHash`,
    );
    decodeFixedHex(
        stringField(
            encryptedMaterial,
            'aeadNonceHex',
            `${objectPath}.aeadNonceHex`,
        ),
        aesGcmNonceByteLength,
        `${objectPath}.aeadNonceHex`,
    );
    decodeCanonicalHex(
        stringField(
            encryptedMaterial,
            'ciphertextBytesHex',
            `${objectPath}.ciphertextBytesHex`,
        ),
        `${objectPath}.ciphertextBytesHex`,
    );
    assertNonNegativeSafeInteger(
        numberField(encryptedMaterial, 'plaintextByteLength'),
        `${objectPath}.plaintextByteLength`,
    );
    if (encryptedMaterial.aeadTagLength !== aesGcmTagBitLength) {
        throw new TypeError(
            `${objectPath}.aeadTagLength must be ${String(aesGcmTagBitLength)}.`,
        );
    }
    const envelopeWithoutHash = {
        ...encryptedMaterial,
    } as Record<string, unknown>;
    delete envelopeWithoutHash.encryptedMaterialHash;
    const expectedEnvelopeHash = hashCanonicalValue(
        'sealed-lattice-local-trustee-state/sealed-material-envelope-hash',
        envelopeWithoutHash,
    );
    if (encryptedMaterial.encryptedMaterialHash !== expectedEnvelopeHash) {
        throw new Error(
            `${objectPath}.encryptedMaterialHash does not match the canonical sealed material envelope.`,
        );
    }

    return encryptedMaterial as EncryptedLocalTrusteeSetupMaterial;
}

const validateSealedMaterial = (
    value: unknown,
    expectedMaterialClass: LocalTrusteeSetupStateSealedMaterial['materialClass'],
    expectedMaterialRoot: ProtocolHash,
    setupContext: unknown,
    localStateCommitment: LocalTrusteeStateStorageEncryptionInput['localStateCommitment'],
    storageKeyBytes: Uint8Array,
    objectPath: string,
): LocalTrusteeSetupStateSealedMaterial => {
    const material = assertJsonRecord(value, objectPath);
    assertExactFields(material, sealedMaterialFieldNames, objectPath);
    if (material.objectType !== 'LocalTrusteeSetupStateSealedMaterial') {
        throw new TypeError(
            `${objectPath}.objectType must be LocalTrusteeSetupStateSealedMaterial.`,
        );
    }
    if (material.materialClass !== expectedMaterialClass) {
        throw new TypeError(
            `${objectPath}.materialClass must be ${expectedMaterialClass}.`,
        );
    }
    const materialRoot = stringField(
        material,
        'materialRoot',
        `${objectPath}.materialRoot`,
    );
    assertProtocolHash(materialRoot, `${objectPath}.materialRoot`);
    if (materialRoot !== expectedMaterialRoot) {
        throw new Error(
            `${objectPath}.materialRoot must match the local state commitment.`,
        );
    }
    const ciphertextReference = stringField(
        material,
        'ciphertextReference',
        `${objectPath}.ciphertextReference`,
    );
    assertProtocolHash(
        ciphertextReference,
        `${objectPath}.ciphertextReference`,
    );
    const encryptedMaterial = validateEncryptedSealedMaterialEnvelope(
        material.encryptedMaterial,
        expectedMaterialClass,
        expectedMaterialRoot,
        setupContext,
        localStateCommitment,
        storageKeyBytes,
        `${objectPath}.encryptedMaterial`,
    );
    if (ciphertextReference !== encryptedMaterial.encryptedMaterialHash) {
        throw new Error(
            `${objectPath}.ciphertextReference must match encryptedMaterial.encryptedMaterialHash.`,
        );
    }

    return material as LocalTrusteeSetupStateSealedMaterial;
};

export const validateLocalStatePlaintext = (
    localStatePlaintext: unknown,
    localStateCommitment: LocalTrusteeStateStorageEncryptionInput['localStateCommitment'],
    setupContext: unknown,
    storageKeyBytes: Uint8Array,
): LocalTrusteeSetupStateSealedPayload => {
    assertSetupContextBinding(setupContext, localStateCommitment);
    const plaintext = assertJsonRecord(
        localStatePlaintext,
        'localStatePlaintext',
    );
    assertExactFields(
        plaintext,
        localTrusteeSealedPayloadFieldNames,
        'localStatePlaintext',
    );
    if (plaintext.objectType !== 'LocalTrusteeSetupStateSealedPayload') {
        throw new TypeError(
            'localStatePlaintext.objectType must be LocalTrusteeSetupStateSealedPayload.',
        );
    }
    for (const fieldName of setupContextFieldNames) {
        if (plaintext[fieldName] !== localStateCommitment[fieldName]) {
            throw new Error(
                `localStatePlaintext.${fieldName} must match the local state commitment.`,
            );
        }
    }
    const trusteeIdentity = stringField(plaintext, 'trusteeIdentity');
    assertNonEmptyString(
        trusteeIdentity,
        'localStatePlaintext.trusteeIdentity',
    );
    if (trusteeIdentity !== localStateCommitment.trusteeIdentity) {
        throw new Error(
            'localStatePlaintext.trusteeIdentity must match the local state commitment.',
        );
    }
    const trusteeRosterPosition = numberField(
        plaintext,
        'trusteeRosterPosition',
    );
    assertNonNegativeSafeInteger(
        trusteeRosterPosition,
        'localStatePlaintext.trusteeRosterPosition',
    );
    if (trusteeRosterPosition !== localStateCommitment.trusteeRosterPosition) {
        throw new Error(
            'localStatePlaintext.trusteeRosterPosition must match the local state commitment.',
        );
    }
    assertNonNegativeSafeInteger(
        numberField(plaintext, 'deviceEpoch'),
        'localStatePlaintext.deviceEpoch',
    );
    const thresholdShareCommitmentRecipientRoot = stringField(
        plaintext,
        'thresholdShareCommitmentRecipientRoot',
    );
    assertProtocolHash(
        thresholdShareCommitmentRecipientRoot,
        'localStatePlaintext.thresholdShareCommitmentRecipientRoot',
    );
    if (
        thresholdShareCommitmentRecipientRoot !==
        localStateCommitment.thresholdShareCommitmentRecipientRoot
    ) {
        throw new Error(
            'localStatePlaintext.thresholdShareCommitmentRecipientRoot must match the local state commitment.',
        );
    }
    validateSealedMaterial(
        plaintext.sealedAggregateThresholdShare,
        'aggregate-threshold-share-sealed',
        localStateCommitment.aggregateThresholdShareRoot,
        setupContext,
        localStateCommitment,
        storageKeyBytes,
        'localStatePlaintext.sealedAggregateThresholdShare',
    );
    const issuedVssAcceptanceRoots = protocolHashArrayField(
        plaintext,
        'issuedVssAcceptanceRoots',
    );
    if (
        issuedVssAcceptanceRoots.length !== 1 ||
        issuedVssAcceptanceRoots[0] !==
            localStateCommitment.issuedVssAcceptanceRoot
    ) {
        throw new Error(
            'localStatePlaintext.issuedVssAcceptanceRoots must bind the issued VSS acceptance root from the local state commitment.',
        );
    }
    const issuedVssComplaintRoots = protocolHashArrayField(
        plaintext,
        'issuedVssComplaintRoots',
    );
    if (
        canonicalJson(issuedVssComplaintRoots) !==
        canonicalJson(localStateCommitment.issuedVssComplaintRoots)
    ) {
        throw new Error(
            'localStatePlaintext.issuedVssComplaintRoots must match the local state commitment.',
        );
    }

    return plaintext as LocalTrusteeSetupStateSealedPayload;
};
