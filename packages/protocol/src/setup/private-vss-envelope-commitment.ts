import type { ProtocolHash } from '@sealed-lattice/types';

export type PrivateVssEnvelopeAad = Readonly<{
    readonly objectType: 'PrivateVssEnvelopeAad';
    readonly setupContextHash: ProtocolHash;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly vssCoefficientCommitmentRoot: ProtocolHash;
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly recipientIdentity: string;
    readonly recipientRosterPosition: number;
    readonly sourceTrusteeCommitmentRoot: ProtocolHash;
}>;

export type EncryptedPrivateVssShareEnvelope = Readonly<{
    readonly objectType: 'EncryptedPrivateVssShareEnvelope';
    readonly privateEnvelopeAad: PrivateVssEnvelopeAad;
    readonly recipientMailboxPublicKeyHash: ProtocolHash;
    readonly kemCiphertextBytesHex: string;
    readonly aeadNonceHex: string;
    readonly ciphertextBytesHex: string;
}>;

export type PrivateVssEnvelopeCommitment = Readonly<{
    readonly objectType: 'PrivateVssEnvelopeCommitment';
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly recipientIdentity: string;
    readonly recipientRosterPosition: number;
    readonly privateEnvelopeHash: ProtocolHash;
    readonly encryptedEnvelopeHash: ProtocolHash;
    readonly encryptedEnvelope?: EncryptedPrivateVssShareEnvelope;
}>;

export type PrivateVssEnvelopeCommitmentSet = Readonly<{
    readonly objectType: 'PrivateVssEnvelopeCommitmentSet';
    readonly envelopeReferences: readonly PrivateVssEnvelopeCommitment[];
}>;
