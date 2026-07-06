import type { ProtocolHash } from '@sealed-lattice/types';

export const textEncoder = new TextEncoder();
export const textDecoder = new TextDecoder();
export const localTrusteeStateStorageFormat =
    'sealed-lattice-local-trustee-state-aes-256-gcm-hkdf-sha384-v1';
export const localTrusteeSealedMaterialStorageFormat =
    'sealed-lattice-local-trustee-setup-material-aes-256-gcm-hkdf-sha384-v1';
export const localStateCiphertextContentType = 'local-trustee-setup-state';
export const localSealedMaterialCiphertextContentType =
    'local-trustee-setup-sealed-material';
export const aesGcmKeyByteLength = 32;
export const aesGcmNonceByteLength = 12;
export const aesGcmTagBitLength = 128;

export type JsonRecord = Record<string, unknown>;

export type EncryptedLocalTrusteeSetupMaterial = Readonly<
    JsonRecord & {
        readonly objectType: 'EncryptedLocalTrusteeSetupMaterial';
        readonly storageScheme: typeof localTrusteeSealedMaterialStorageFormat;
        readonly ciphertextContentType: typeof localSealedMaterialCiphertextContentType;
        readonly materialClass: 'aggregate-threshold-share-sealed';
        readonly materialRoot: ProtocolHash;
        readonly materialAad: Readonly<Record<string, unknown>>;
        readonly materialAadHash: ProtocolHash;
        readonly keyCommitmentHash: ProtocolHash;
        readonly aeadNonceHex: string;
        readonly ciphertextBytesHex: string;
        readonly plaintextByteLength: number;
        readonly aeadTagLength: typeof aesGcmTagBitLength;
        readonly encryptedMaterialHash: ProtocolHash;
    }
>;

export type LocalTrusteeSetupStateSealedMaterial = Readonly<
    JsonRecord & {
        readonly objectType: 'LocalTrusteeSetupStateSealedMaterial';
        readonly materialClass: 'aggregate-threshold-share-sealed';
        readonly materialRoot: ProtocolHash;
        readonly ciphertextReference: ProtocolHash;
        readonly encryptedMaterial: EncryptedLocalTrusteeSetupMaterial;
    }
>;

export type LocalTrusteeSetupStateSealedPayload = Readonly<
    JsonRecord & {
        readonly objectType: 'LocalTrusteeSetupStateSealedPayload';
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
        readonly storageScheme: typeof localTrusteeStateStorageFormat;
        readonly ciphertextContentType: typeof localStateCiphertextContentType;
        readonly localStateRoot: ProtocolHash;
        readonly localStateCommitmentHash: ProtocolHash;
        readonly storageAad: Readonly<Record<string, unknown>>;
        readonly storageAadHash: ProtocolHash;
        readonly keyCommitmentHash: ProtocolHash;
        readonly aeadNonceHex: string;
        readonly ciphertextBytesHex: string;
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
    readonly materialClass: 'aggregate-threshold-share-sealed';
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

export const protocolHashPattern = /^[0-9a-f]{128}$/u;

export const setupContextFieldNames = [
    'ceremonyId',
    'manifestHash',
    'rosterHash',
    'setupEpoch',
] as const;

export const localTrusteeSealedPayloadFieldNames = [
    'objectType',
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

export const sealedMaterialFieldNames = [
    'objectType',
    'materialClass',
    'materialRoot',
    'ciphertextReference',
    'encryptedMaterial',
] as const;

export const encryptedSealedMaterialFieldNames = [
    'objectType',
    'storageScheme',
    'ciphertextContentType',
    'materialClass',
    'materialRoot',
    'materialAad',
    'materialAadHash',
    'keyCommitmentHash',
    'aeadNonceHex',
    'ciphertextBytesHex',
    'plaintextByteLength',
    'aeadTagLength',
    'encryptedMaterialHash',
] as const;
