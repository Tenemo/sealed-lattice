import type { ProtocolHash } from '@sealed-lattice/types';

export const textEncoder = new TextEncoder();
export const textDecoder = new TextDecoder();
export const aesGcmKeyByteLength = 32;
export const aesGcmNonceByteLength = 12;
export const aesGcmTagBitLength = 128;

export type JsonRecord = Record<string, unknown>;

export type EncryptedLocalTrusteeSetupMaterial = Readonly<
    JsonRecord & {
        readonly objectType: 'EncryptedLocalTrusteeSetupMaterial';
        readonly materialRoot: ProtocolHash;
        readonly materialAad: Readonly<Record<string, unknown>>;
        readonly aeadNonceHex: string;
        readonly ciphertextBytesHex: string;
    }
>;

export type LocalTrusteeSetupStateSealedMaterial =
    EncryptedLocalTrusteeSetupMaterial;

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
        readonly storageAad: Readonly<Record<string, unknown>>;
        readonly aeadNonceHex: string;
        readonly ciphertextBytesHex: string;
    }
>;

export type LocalTrusteeStateStorageEncryptionResult = {
    readonly encryptedLocalState: EncryptedLocalTrusteeSetupState;
};

export type LocalTrusteeStateStorageDecryptionResult = {
    readonly localStatePlaintext: LocalTrusteeSetupStateSealedPayload;
};

export type LocalTrusteeSetupSealedMaterialEncryptionInput = {
    readonly materialPlaintext: unknown;
    readonly setupContext: unknown;
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly thresholdShareCommitmentRecipientRoot: ProtocolHash;
    readonly storageKeyBytesHex: string;
};

export type LocalTrusteeSetupSealedMaterialEncryptionResult = {
    readonly sealedMaterial: LocalTrusteeSetupStateSealedMaterial;
    readonly materialRoot: ProtocolHash;
};

export type LocalTrusteeSetupSealedMaterialDecryptionInput = {
    readonly sealedMaterial: LocalTrusteeSetupStateSealedMaterial;
    readonly expectedMaterialRoot: ProtocolHash;
    readonly localStateCommitment: LocalTrusteeStateStorageEncryptionInput['localStateCommitment'];
    readonly setupContext: unknown;
    readonly storageKeyBytesHex: string;
};

export type LocalTrusteeSetupSealedMaterialDecryptionResult = {
    readonly materialPlaintext: unknown;
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

export const encryptedSealedMaterialFieldNames = [
    'objectType',
    'materialRoot',
    'materialAad',
    'aeadNonceHex',
    'ciphertextBytesHex',
] as const;
