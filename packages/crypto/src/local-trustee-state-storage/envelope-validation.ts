import type { ProtocolHash } from '@sealed-lattice/types';

import { canonicalJson } from '../canonical-json.js';

import { decodeCanonicalHex, sealedMaterialAad } from './aes-gcm.js';
import {
    aesGcmNonceByteLength,
    encryptedSealedMaterialFieldNames,
    localTrusteeSealedPayloadFieldNames,
    setupContextFieldNames,
    type EncryptedLocalTrusteeSetupMaterial,
    type LocalTrusteeSetupStateSealedMaterial,
    type LocalTrusteeSetupStateSealedPayload,
    type LocalTrusteeStateStorageEncryptionInput,
} from './constants-and-types.js';
import {
    assertJsonRecord,
    assertNonEmptyString,
    assertNonNegativeSafeInteger,
    assertProtocolHash,
    assertRequiredFields,
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

export const validateSealedMaterial = (
    value: unknown,
    expectedMaterialRoot: ProtocolHash,
    setupContext: unknown,
    localStateCommitment: LocalTrusteeStateStorageEncryptionInput['localStateCommitment'],
    objectPath: string,
): LocalTrusteeSetupStateSealedMaterial => {
    assertSetupContextBinding(setupContext, localStateCommitment);
    const encryptedMaterial = assertJsonRecord(value, objectPath);
    assertRequiredFields(
        encryptedMaterial,
        encryptedSealedMaterialFieldNames,
        objectPath,
    );
    if (encryptedMaterial.objectType !== 'EncryptedLocalTrusteeSetupMaterial') {
        throw new TypeError(
            `${objectPath}.objectType must be EncryptedLocalTrusteeSetupMaterial.`,
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
        expectedMaterialRoot,
        localStateCommitment,
    );
    if (
        canonicalJson(encryptedMaterial.materialAad) !==
        canonicalJson(expectedMaterialAad)
    ) {
        throw new Error(`${objectPath}.materialAad does not match bindings.`);
    }
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

    return encryptedMaterial as EncryptedLocalTrusteeSetupMaterial;
};

export const validateLocalStatePlaintext = (
    localStatePlaintext: unknown,
    localStateCommitment: LocalTrusteeStateStorageEncryptionInput['localStateCommitment'],
    setupContext: unknown,
): LocalTrusteeSetupStateSealedPayload => {
    assertSetupContextBinding(setupContext, localStateCommitment);
    const plaintext = assertJsonRecord(
        localStatePlaintext,
        'localStatePlaintext',
    );
    assertRequiredFields(
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
        localStateCommitment.aggregateThresholdShareRoot,
        setupContext,
        localStateCommitment,
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
