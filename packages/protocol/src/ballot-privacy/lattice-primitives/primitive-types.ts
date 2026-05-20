import type {
    ProtocolDigest,
    ReceiverEncryptionPublicKey,
    ReceiverPayload,
    ShareCommitment,
} from '@sealed-lattice/types';

export type DeterministicFixtureRandomness = {
    readonly kind: 'fixture';
    readonly fixtureSeed: string;
    readonly allowFixtureMode: true;
};

export type ProductionRandomness = {
    readonly kind: 'production';
};

export type BallotPrivacyRandomnessSource =
    | DeterministicFixtureRandomness
    | ProductionRandomness;

export type ShareCommitmentOpeningWitness = {
    readonly openingRandomness: readonly number[];
};

export type ReceiverPayloadPlaintextWitness = {
    readonly receiverShareVector: readonly number[];
    readonly shareCommitmentOpening: ShareCommitmentOpeningWitness;
    readonly ceremonyId: string;
    readonly manifestDigest: ProtocolDigest;
    readonly rosterDigest: ProtocolDigest;
    readonly pollSpecDigest: ProtocolDigest;
    readonly voterIdentityDigest: ProtocolDigest;
    readonly receiverIdentity: string;
    readonly receiverRosterPosition: number;
    readonly ballotPackageContextDigest: ProtocolDigest;
};

export type ReceiverEncryptionSecretState = {
    readonly secretVector: readonly (readonly number[])[];
    readonly errorVector: readonly (readonly number[])[];
};

export type ReceiverEncryptionPublicKeyMaterial = {
    readonly publicMatrixSeedDigest: ProtocolDigest;
    readonly publicKeyVector: readonly (readonly number[])[];
};

export type ReceiverEncryptionState = {
    readonly receiverPublicKey: ReceiverEncryptionPublicKey;
    readonly publicKeyMaterial: ReceiverEncryptionPublicKeyMaterial;
    readonly secretState: ReceiverEncryptionSecretState;
};

export type ReceiverEncryptionChunkWitness = {
    readonly chunkIndex: number;
    readonly encryptionRandomnessVector: readonly (readonly number[])[];
    readonly firstNoiseVector: readonly (readonly number[])[];
    readonly secondNoisePolynomial: readonly number[];
};

export type ReceiverEncryptionWitness = {
    readonly chunkWitnesses: readonly ReceiverEncryptionChunkWitness[];
};

export type ReceiverPayloadCiphertextChunk = {
    readonly chunkIndex: number;
    readonly firstCiphertextVector: readonly (readonly number[])[];
    readonly secondCiphertextPolynomial: readonly number[];
};

export type ReceiverPayloadEncryptionResult = {
    readonly receiverPayload: ReceiverPayload;
    readonly ciphertextChunks: readonly ReceiverPayloadCiphertextChunk[];
    readonly plaintextBitLength: number;
    readonly witness: ReceiverEncryptionWitness;
};

export type ShareCommitmentMaterial = {
    readonly shareCommitment: ShareCommitment;
    readonly commitmentPolynomialVector: readonly (readonly string[])[];
    readonly opening: ShareCommitmentOpeningWitness;
};
