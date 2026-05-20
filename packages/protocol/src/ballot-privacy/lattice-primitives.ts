// Public entry point for ballot privacy lattice primitives.
export {
    deriveReceiverPublicMatrix,
    deriveShareCommitmentMessageMatrix,
    deriveShareCommitmentRandomnessMatrix,
} from './lattice-primitives/primitive-contracts.js';
export type {
    ShareCommitmentOpeningWitness,
    ReceiverPayloadPlaintextWitness,
    ReceiverEncryptionSecretState,
} from './lattice-primitives/primitive-contracts.js';
export {
    deriveShareCommitmentBodyDigest,
    createShareCommitmentPolynomialVector,
    addShareCommitmentPolynomialVectors,
    addShareCommitmentOpenings,
    createShareCommitment,
    verifyShareCommitmentWitness,
    generateReceiverState,
} from './lattice-primitives/share-commitments-and-receiver-keys.js';
export {
    verifyReceiverKeyWitness,
    createReceiverKeyProof,
    encryptReceiverPayload,
    verifyReceiverPayloadWitness,
    createFixtureRandomnessSource,
    assertNoFixtureRandomnessInProduction,
    encodeReceiverPayloadPlaintextForTests,
} from './lattice-primitives/receiver-key-proofs-and-encryption.js';
