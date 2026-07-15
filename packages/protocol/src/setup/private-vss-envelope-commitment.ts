import type { ProtocolHash } from '@sealed-lattice/types';

export type EncryptedPrivateVssShareEnvelope = Readonly<{
    readonly objectType: 'EncryptedPrivateVssShareEnvelope';
    readonly kemCiphertextBytesHex: string;
    readonly aeadNonceHex: string;
    readonly ciphertextBytesHex: string;
}>;

export type PrivateVssEnvelopeCommitment = Readonly<{
    readonly objectType: 'PrivateVssEnvelopeCommitment';
    readonly sourceTrusteeRosterPosition: number;
    readonly recipientRosterPosition: number;
    readonly privateEnvelopeHash: ProtocolHash;
    readonly encryptedEnvelopeHash: ProtocolHash;
    readonly encryptedEnvelope?: EncryptedPrivateVssShareEnvelope;
}>;

export type PrivateVssEnvelopeCommitmentSet = Readonly<{
    readonly objectType: 'PrivateVssEnvelopeCommitmentSet';
    readonly envelopeReferences: readonly PrivateVssEnvelopeCommitment[];
}>;
