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
} from './lattice-primitives/share-commitments.js';
export { generateReceiverState } from './lattice-primitives/receiver-keys.js';
export {
    verifyReceiverKeyWitness,
    createReceiverKeyProof,
} from './lattice-primitives/receiver-key-proofs.js';
export {
    encryptReceiverPayload,
    verifyReceiverPayloadWitness,
} from './lattice-primitives/payload-encryption.js';
export {
    createFixtureRandomnessSource,
    assertNoFixtureRandomnessInProduction,
    encodeReceiverPayloadPlaintextForTests,
} from './lattice-primitives/fixture-randomness.js';
