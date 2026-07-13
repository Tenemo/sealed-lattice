import type { ProtocolHash } from '@sealed-lattice/types';

import { canonicalJson } from '../canonical-json.js';

import { decodeCanonicalHex } from '../web-crypto.js';

import { sealedMaterialAad } from './aes-gcm.js';
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
    assertProtocolHash(
        localStateCommitment.setupParametersHash,
        'localStateCommitment.setupParametersHash',
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
    validateSealedMaterial(
        plaintext.sealedAggregateThresholdShare,
        localStateCommitment.aggregateThresholdShareRoot,
        setupContext,
        localStateCommitment,
        'localStatePlaintext.sealedAggregateThresholdShare',
    );
    return plaintext as LocalTrusteeSetupStateSealedPayload;
};
