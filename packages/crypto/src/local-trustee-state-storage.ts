import { hkdf } from '@noble/hashes/hkdf.js';
import { sha384 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import type { ProtocolHash } from '@sealed-lattice/types';

import { canonicalJson, hash512Hex } from './canonical-json.js';
import { deriveProtocolHash } from './hashes.js';

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
export const localTrusteeStateStorageProfileId =
    'sealed-lattice-local-trustee-state-aes-256-gcm-hkdf-sha384-v1';
export const localTrusteeSealedMaterialStorageProfileId =
    'sealed-lattice-local-trustee-setup-material-aes-256-gcm-hkdf-sha384-v1';
const localStateCiphertextContentType = 'local-trustee-setup-state';
const localSealedMaterialCiphertextContentType =
    'local-trustee-setup-sealed-material';
const aesGcmKeyByteLength = 32;
const aesGcmNonceByteLength = 12;
const aesGcmTagBitLength = 128;

type JsonRecord = Record<string, unknown>;

export type LocalTrusteeSetupStateSealedMaterialClass =
    'aggregate-threshold-share-sealed';

export type EncryptedLocalTrusteeSetupMaterial = Readonly<
    JsonRecord & {
        readonly objectType: 'EncryptedLocalTrusteeSetupMaterial';
        readonly objectVersion: 1;
        readonly storageProfileId: typeof localTrusteeSealedMaterialStorageProfileId;
        readonly ciphertextContentType: typeof localSealedMaterialCiphertextContentType;
        readonly materialClass: LocalTrusteeSetupStateSealedMaterialClass;
        readonly materialRoot: ProtocolHash;
        readonly materialAad: Readonly<Record<string, unknown>>;
        readonly materialAadHash: ProtocolHash;
        readonly keyCommitmentHash: ProtocolHash;
        readonly aeadNonceHex: string;
        readonly ciphertextBytesHex: string;
        readonly ciphertextBytesHash: ProtocolHash;
        readonly ciphertextByteLength: number;
        readonly plaintextByteLength: number;
        readonly aeadTagLength: typeof aesGcmTagBitLength;
        readonly encryptedMaterialHash: ProtocolHash;
    }
>;

export type LocalTrusteeSetupStateSealedMaterial = Readonly<
    JsonRecord & {
        readonly objectType: 'LocalTrusteeSetupStateSealedMaterial';
        readonly objectVersion: 1;
        readonly materialClass: LocalTrusteeSetupStateSealedMaterialClass;
        readonly materialRoot: ProtocolHash;
        readonly ciphertextReference: ProtocolHash;
        readonly encryptedMaterial: EncryptedLocalTrusteeSetupMaterial;
    }
>;

export type LocalTrusteeSetupStateSealedPayload = Readonly<
    JsonRecord & {
        readonly objectType: 'LocalTrusteeSetupStateSealedPayload';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly setupEpoch: string;
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly deviceEpoch: number;
        readonly thresholdShareCommitmentRecipientRoot: ProtocolHash;
        readonly sealedAggregateThresholdShare: LocalTrusteeSetupStateSealedMaterial;
        readonly issuedVssAcceptanceRoots: readonly ProtocolHash[];
        readonly issuedVssComplaintRoots: readonly ProtocolHash[];
    }
>;

export type LocalTrusteeStateStorageEncryptionInput = {
    readonly localStatePlaintext: LocalTrusteeSetupStateSealedPayload;
    readonly localStateCommitment: Readonly<
        Record<string, unknown> & {
            readonly objectType: 'LocalTrusteeSetupStateCommitment';
            readonly objectVersion: 1;
            readonly setupProfileId: 'CollectiveBgvSetup-v1';
            readonly ceremonyId: string;
            readonly manifestHash: ProtocolHash;
            readonly rosterHash: ProtocolHash;
            readonly setupEpoch: string;
            readonly trusteeIdentity: string;
            readonly trusteeRosterPosition: number;
            readonly thresholdShareCommitmentRecipientRoot: ProtocolHash;
            readonly aggregateThresholdShareRoot: ProtocolHash;
            readonly issuedVssAcceptanceRoot: ProtocolHash;
            readonly issuedVssComplaintRoots: readonly ProtocolHash[];
            readonly localStateRoot: ProtocolHash;
            readonly storageProfile: 'encrypted-local-device-state-required';
            readonly exportPolicy: 'roots-only-no-raw-share-or-opening-export';
        }
    >;
    readonly setupContext: unknown;
    readonly storageKeyBytesHex: string;
    readonly aeadNonceBytesHex?: string;
};

export type LocalTrusteeStateStorageDecryptionInput = {
    readonly encryptedLocalState: EncryptedLocalTrusteeSetupState;
    readonly expectedLocalStateRoot: ProtocolHash;
    readonly setupContext: unknown;
    readonly storageKeyBytesHex: string;
};

export type EncryptedLocalTrusteeSetupState = Readonly<
    Record<string, unknown> & {
        readonly objectType: 'EncryptedLocalTrusteeSetupState';
        readonly objectVersion: 1;
        readonly storageProfileId: typeof localTrusteeStateStorageProfileId;
        readonly ciphertextContentType: typeof localStateCiphertextContentType;
        readonly localStateRoot: ProtocolHash;
        readonly localStateCommitmentHash: ProtocolHash;
        readonly storageAad: Readonly<Record<string, unknown>>;
        readonly storageAadHash: ProtocolHash;
        readonly keyCommitmentHash: ProtocolHash;
        readonly aeadNonceHex: string;
        readonly ciphertextBytesHex: string;
        readonly ciphertextBytesHash: ProtocolHash;
        readonly ciphertextByteLength: number;
        readonly plaintextByteLength: number;
        readonly aeadTagLength: typeof aesGcmTagBitLength;
        readonly encryptedLocalStateHash: ProtocolHash;
    }
>;

export type LocalTrusteeStateStorageEncryptionResult = {
    readonly encryptedLocalState: EncryptedLocalTrusteeSetupState;
    readonly localStatePlaintextHash: ProtocolHash;
    readonly storageAadHash: ProtocolHash;
};

export type LocalTrusteeStateStorageDecryptionResult = {
    readonly localStatePlaintext: LocalTrusteeSetupStateSealedPayload;
    readonly localStatePlaintextHash: ProtocolHash;
    readonly storageAadHash: ProtocolHash;
};

export type LocalTrusteeSetupSealedMaterialEncryptionInput = {
    readonly materialClass: LocalTrusteeSetupStateSealedMaterialClass;
    readonly materialPlaintext: unknown;
    readonly setupContext: unknown;
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly thresholdShareCommitmentRecipientRoot: ProtocolHash;
    readonly storageKeyBytesHex: string;
    readonly aeadNonceBytesHex?: string;
};

export type LocalTrusteeSetupSealedMaterialEncryptionResult = {
    readonly sealedMaterial: LocalTrusteeSetupStateSealedMaterial;
    readonly materialRoot: ProtocolHash;
    readonly materialPlaintextHash: ProtocolHash;
    readonly materialAadHash: ProtocolHash;
};

const protocolHashPattern = /^[0-9a-f]{128}$/u;

const setupContextFieldNames = [
    'ceremonyId',
    'manifestHash',
    'rosterHash',
    'setupEpoch',
] as const;

const localTrusteeSealedPayloadFieldNames = [
    'objectType',
    'objectVersion',
    'setupProfileId',
    'ceremonyId',
    'manifestHash',
    'rosterHash',
    'setupEpoch',
    'trusteeIdentity',
    'trusteeRosterPosition',
    'deviceEpoch',
    'thresholdShareCommitmentRecipientRoot',
    'sealedAggregateThresholdShare',
    'issuedVssAcceptanceRoots',
    'issuedVssComplaintRoots',
] as const;

const sealedMaterialFieldNames = [
    'objectType',
    'objectVersion',
    'materialClass',
    'materialRoot',
    'ciphertextReference',
    'encryptedMaterial',
] as const;

const encryptedSealedMaterialFieldNames = [
    'objectType',
    'objectVersion',
    'storageProfileId',
    'ciphertextContentType',
    'materialClass',
    'materialRoot',
    'materialAad',
    'materialAadHash',
    'keyCommitmentHash',
    'aeadNonceHex',
    'ciphertextBytesHex',
    'ciphertextBytesHash',
    'ciphertextByteLength',
    'plaintextByteLength',
    'aeadTagLength',
    'encryptedMaterialHash',
] as const;

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

const assertProtocolHash = (value: string, fieldName: string): void => {
    if (!protocolHashPattern.test(value)) {
        throw new TypeError(`${fieldName} must be a protocol hash.`);
    }
};

const assertNonNegativeSafeInteger = (
    value: number,
    fieldName: string,
): void => {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new TypeError(
            `${fieldName} must be a non-negative safe integer.`,
        );
    }
};

const assertNonEmptyString = (value: string, fieldName: string): void => {
    if (value.length === 0) {
        throw new TypeError(`${fieldName} must be non-empty.`);
    }
};

const isJsonRecord = (value: unknown): value is JsonRecord =>
    typeof value === 'object' && value !== null && !Array.isArray(value);

const assertJsonRecord = (value: unknown, fieldName: string): JsonRecord => {
    if (!isJsonRecord(value)) {
        throw new TypeError(`${fieldName} must be an object.`);
    }

    return value;
};

const assertExactFields = (
    value: JsonRecord,
    allowedFieldNames: readonly string[],
    objectPath: string,
): void => {
    const allowedFields = new Set(allowedFieldNames);
    for (const fieldName of Object.keys(value)) {
        if (!allowedFields.has(fieldName)) {
            throw new TypeError(
                `${objectPath}.${fieldName} is not allowed by the local trustee state schema.`,
            );
        }
    }
    for (const fieldName of allowedFieldNames) {
        if (!(fieldName in value)) {
            throw new TypeError(
                `${objectPath}.${fieldName} is required by the local trustee state schema.`,
            );
        }
    }
};

const stringField = (
    value: JsonRecord,
    fieldName: string,
    displayName = fieldName,
): string => {
    const fieldValue = value[fieldName];
    if (typeof fieldValue !== 'string') {
        throw new TypeError(`${displayName} must be a string.`);
    }

    return fieldValue;
};

const numberField = (value: JsonRecord, fieldName: string): number => {
    const fieldValue = value[fieldName];
    if (typeof fieldValue !== 'number') {
        throw new TypeError(`${fieldName} must be a number.`);
    }

    return fieldValue;
};

const protocolHashArrayField = (
    value: JsonRecord,
    fieldName: string,
): ProtocolHash[] => {
    const fieldValue = value[fieldName];
    if (!Array.isArray(fieldValue)) {
        throw new TypeError(
            `${fieldName} must be an array of protocol hashes.`,
        );
    }

    return fieldValue.map((item, itemIndex) => {
        if (typeof item !== 'string') {
            throw new TypeError(
                `${fieldName}.${String(itemIndex)} must be a protocol hash.`,
            );
        }
        assertProtocolHash(item, `${fieldName}.${String(itemIndex)}`);

        return item;
    });
};

const randomBytes = (byteLength: number): Uint8Array => {
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

const subtleCrypto = (): SubtleCrypto => {
    const subtle = globalThis.crypto?.subtle;
    if (subtle === undefined) {
        throw new Error(
            'Local trustee state storage encryption requires Web Crypto AES-GCM.',
        );
    }

    return subtle;
};

const arrayBufferFromBytes = (bytes: Uint8Array): ArrayBuffer => {
    const copy = new Uint8Array(bytes.byteLength);
    copy.set(bytes);

    return copy.buffer;
};

const hashCanonicalValue = (domain: string, value: unknown): ProtocolHash =>
    hash512Hex(domain, [textEncoder.encode(canonicalJson(value))]);

const hashBytes = (domain: string, bytes: Uint8Array): ProtocolHash =>
    hash512Hex(domain, [bytes]);

const storageAad = (
    setupContext: unknown,
    localStateCommitment: LocalTrusteeStateStorageEncryptionInput['localStateCommitment'],
): Readonly<Record<string, unknown>> => ({
    objectType: 'LocalTrusteeStateStorageAad',
    objectVersion: 1,
    storageProfileId: localTrusteeStateStorageProfileId,
    ciphertextContentType: localStateCiphertextContentType,
    setupContext,
    localStateCommitment,
    localStateRoot: localStateCommitment.localStateRoot,
    localStateCommitmentHash: hashCanonicalValue(
        'sealed-lattice-local-trustee-state/commitment-hash-v1',
        localStateCommitment,
    ),
});

const sealedMaterialAad = (
    setupContext: unknown,
    materialClass: LocalTrusteeSetupStateSealedMaterialClass,
    materialRoot: ProtocolHash,
    localStateBinding: Readonly<{
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly thresholdShareCommitmentRecipientRoot: ProtocolHash;
    }>,
): Readonly<Record<string, unknown>> => ({
    objectType: 'LocalTrusteeSetupSealedMaterialAad',
    objectVersion: 1,
    storageProfileId: localTrusteeSealedMaterialStorageProfileId,
    ciphertextContentType: localSealedMaterialCiphertextContentType,
    materialClass,
    materialRoot,
    setupContext,
    trusteeIdentity: localStateBinding.trusteeIdentity,
    trusteeRosterPosition: localStateBinding.trusteeRosterPosition,
    thresholdShareCommitmentRecipientRoot:
        localStateBinding.thresholdShareCommitmentRecipientRoot,
});

// GCM safety comes from per-object key separation: the HKDF salt is the unique object root, so even a repeated random nonce never recurs under the same derived key.
const deriveAesGcmKeyBytes = (
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
                storageProfileId: localTrusteeStateStorageProfileId,
                localStateRoot,
                storageAadHash,
            }),
        ),
        aesGcmKeyByteLength,
    );

const deriveSealedMaterialAesGcmKeyBytes = (
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
                storageProfileId: localTrusteeSealedMaterialStorageProfileId,
                materialRoot,
                materialAadHash,
            }),
        ),
        aesGcmKeyByteLength,
    );

const decodeCanonicalHex = (value: string, fieldName: string): Uint8Array => {
    if (!isLowercaseHex(value)) {
        throw new TypeError(`${fieldName} must be lowercase canonical hex.`);
    }

    return hexToBytes(value);
};

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

const assertCommitmentHeader = (
    localStateCommitment: LocalTrusteeStateStorageEncryptionInput['localStateCommitment'],
): void => {
    if (
        localStateCommitment.objectType !== 'LocalTrusteeSetupStateCommitment'
    ) {
        throw new TypeError(
            'localStateCommitment.objectType must be LocalTrusteeSetupStateCommitment.',
        );
    }
    if (localStateCommitment.objectVersion !== 1) {
        throw new TypeError('localStateCommitment.objectVersion must be 1.');
    }
    if (
        localStateCommitment.storageProfile !==
        'encrypted-local-device-state-required'
    ) {
        throw new TypeError(
            'localStateCommitment.storageProfile must require encrypted local device state.',
        );
    }
    if (
        localStateCommitment.exportPolicy !==
        'roots-only-no-raw-share-or-opening-export'
    ) {
        throw new TypeError(
            'localStateCommitment.exportPolicy must forbid raw share and opening export.',
        );
    }
    assertProtocolHash(
        localStateCommitment.localStateRoot,
        'localStateCommitment.localStateRoot',
    );
    if (localStateCommitment.setupProfileId !== 'CollectiveBgvSetup-v1') {
        throw new TypeError(
            'localStateCommitment.setupProfileId must be CollectiveBgvSetup-v1.',
        );
    }
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
    expectedMaterialClass: LocalTrusteeSetupStateSealedMaterialClass,
    expectedMaterialRoot: ProtocolHash,
    setupContext: unknown,
    localStateCommitment: LocalTrusteeStateStorageEncryptionInput['localStateCommitment'],
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
    if (encryptedMaterial.objectVersion !== 1) {
        throw new TypeError(`${objectPath}.objectVersion must be 1.`);
    }
    if (
        encryptedMaterial.storageProfileId !==
        localTrusteeSealedMaterialStorageProfileId
    ) {
        throw new TypeError(`${objectPath}.storageProfileId is not supported.`);
    }
    if (
        encryptedMaterial.ciphertextContentType !==
        localSealedMaterialCiphertextContentType
    ) {
        throw new TypeError(
            `${objectPath}.ciphertextContentType must be local-trustee-setup-sealed-material.`,
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
        'sealed-lattice-local-trustee-state/sealed-material-aad-hash-v1',
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
    decodeFixedHex(
        stringField(
            encryptedMaterial,
            'aeadNonceHex',
            `${objectPath}.aeadNonceHex`,
        ),
        aesGcmNonceByteLength,
        `${objectPath}.aeadNonceHex`,
    );
    const ciphertextBytes = decodeCanonicalHex(
        stringField(
            encryptedMaterial,
            'ciphertextBytesHex',
            `${objectPath}.ciphertextBytesHex`,
        ),
        `${objectPath}.ciphertextBytesHex`,
    );
    const ciphertextByteLength = numberField(
        encryptedMaterial,
        'ciphertextByteLength',
    );
    assertNonNegativeSafeInteger(
        ciphertextByteLength,
        `${objectPath}.ciphertextByteLength`,
    );
    if (ciphertextBytes.byteLength !== ciphertextByteLength) {
        throw new Error(
            `${objectPath}.ciphertextByteLength must match ciphertextBytesHex.`,
        );
    }
    assertNonNegativeSafeInteger(
        numberField(encryptedMaterial, 'plaintextByteLength'),
        `${objectPath}.plaintextByteLength`,
    );
    if (encryptedMaterial.aeadTagLength !== aesGcmTagBitLength) {
        throw new TypeError(
            `${objectPath}.aeadTagLength must be ${String(aesGcmTagBitLength)}.`,
        );
    }
    const expectedCiphertextHash = hashBytes(
        'sealed-lattice-local-trustee-state/sealed-material-ciphertext-bytes-v1',
        ciphertextBytes,
    );
    if (encryptedMaterial.ciphertextBytesHash !== expectedCiphertextHash) {
        throw new Error(
            `${objectPath}.ciphertextBytesHash does not match ciphertextBytesHex.`,
        );
    }
    const envelopeWithoutHash = {
        ...encryptedMaterial,
    } as Record<string, unknown>;
    delete envelopeWithoutHash.encryptedMaterialHash;
    const expectedEnvelopeHash = hashCanonicalValue(
        'sealed-lattice-local-trustee-state/sealed-material-envelope-hash-v1',
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
    objectPath: string,
): LocalTrusteeSetupStateSealedMaterial => {
    const material = assertJsonRecord(value, objectPath);
    assertExactFields(material, sealedMaterialFieldNames, objectPath);
    if (material.objectType !== 'LocalTrusteeSetupStateSealedMaterial') {
        throw new TypeError(
            `${objectPath}.objectType must be LocalTrusteeSetupStateSealedMaterial.`,
        );
    }
    if (material.objectVersion !== 1) {
        throw new TypeError(`${objectPath}.objectVersion must be 1.`);
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
        `${objectPath}.encryptedMaterial`,
    );
    if (ciphertextReference !== encryptedMaterial.encryptedMaterialHash) {
        throw new Error(
            `${objectPath}.ciphertextReference must match encryptedMaterial.encryptedMaterialHash.`,
        );
    }

    return material as LocalTrusteeSetupStateSealedMaterial;
};

const validateLocalStatePlaintext = (
    localStatePlaintext: unknown,
    localStateCommitment: LocalTrusteeStateStorageEncryptionInput['localStateCommitment'],
    setupContext: unknown,
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
    if (plaintext.objectVersion !== 1) {
        throw new TypeError('localStatePlaintext.objectVersion must be 1.');
    }
    if (plaintext.setupProfileId !== 'CollectiveBgvSetup-v1') {
        throw new TypeError(
            'localStatePlaintext.setupProfileId must be CollectiveBgvSetup-v1.',
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
    const materialRoot = deriveProtocolHash(
        'LocalTrusteeSetupStateRoot',
        input.materialPlaintext,
    );
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
        storageProfileId: localTrusteeSealedMaterialStorageProfileId,
        ciphertextContentType: localSealedMaterialCiphertextContentType,
        materialClass: input.materialClass,
        materialRoot,
        materialAad: associatedData,
        materialAadHash,
        // Key commitment: AES-GCM is not key-committing, so a hash of the key is bound to prevent a ciphertext from being opened under a second key (partitioning-oracle defense).
        keyCommitmentHash: hashBytes(
            'sealed-lattice-local-trustee-state/sealed-material-storage-key-commitment-v1',
            storageKeyBytes,
        ),
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
    const localStatePlaintext = validateLocalStatePlaintext(
        input.localStatePlaintext,
        input.localStateCommitment,
        input.setupContext,
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
        storageProfileId: localTrusteeStateStorageProfileId,
        ciphertextContentType: localStateCiphertextContentType,
        localStateRoot: input.localStateCommitment.localStateRoot,
        localStateCommitmentHash,
        storageAad: associatedData,
        storageAadHash,
        keyCommitmentHash: hashBytes(
            'sealed-lattice-local-trustee-state/storage-key-commitment-v1',
            storageKeyBytes,
        ),
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
        input.encryptedLocalState.storageProfileId !==
        localTrusteeStateStorageProfileId
    ) {
        throw new TypeError(
            'encryptedLocalState.storageProfileId is not supported.',
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
