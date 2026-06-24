// Barrel for the evaluation-key proof record builders. The implementation lives
// in the cohesive sub-modules under ./evaluation-key-proof-records/, grouped by
// the domain problem each part solves: shared vocabulary and types, stateless
// encoding and component-vector hashing primitives, the relinearization-round
// and Galois-batch share-record families, the per-trustee succinct evaluation-
// key proofs and their binary proof transport, binary chunked transport of the
// embedded key-switch component vectors, and public evaluation-key assembly
// with its binary material transport. This file keeps the original import path
// and public surface unchanged.
export {
    evaluationKeyShareComponentMaterialEncoding,
    trusteeEvaluationKeyProofFamily,
    type BinaryChunkedEvaluationKeyShareMaterialTransport,
    type BinaryChunkedPublicEvaluationKeyMaterialTransport,
    type EvaluationKeyProofCommonInput,
    type EvaluationKeyShareEmbeddedKeySwitchComponentMaterial,
    type EvaluationKeyShareKeySwitchComponentMaterial,
    type EvaluationKeyShareMaterial,
    type EvaluationKeyShareMaterialTransportInput,
    type EvaluationKeyShareTransportedKeySwitchComponentMaterial,
    type GaloisKeyContributingShareRoot,
    type GaloisKeyRootReference,
    type GaloisKeyShareBatch,
    type GaloisKeyShareBatchContribution,
    type GaloisKeyShareBatchRootReference,
    type GaloisKeyShareBatchesInput,
    type GaloisKeyShareContribution,
    type GaloisKeyShareMaterialRecord,
    type GaloisKeyShareRootReference,
    type KeySwitchComponentVectorEntry,
    type PublicEvaluationKeyMaterialReference,
    type PublicEvaluationKeyMaterialTransportInput,
    type PublicEvaluationKeySet,
    type PublicEvaluationKeySetInput,
    type RelinearizationKeyRootReference,
    type RelinearizationKeyShareRoundOneRecord,
    type RelinearizationKeyShareRoundTwoRecord,
    type RelinearizationKeyShareRounds,
    type RelinearizationKeyShareRoundsInput,
    type RelinearizationRoundOneContribution,
    type RelinearizationRoundTwoContribution,
    type SameSecretProofReference,
    type TransportedEvaluationKeyShareComponentMaterialSet,
    type TransportedEvaluationKeyShareProofMaterialSet,
    type TransportedPublicEvaluationKeyMaterial,
    type TransportedPublicEvaluationKeyMaterialSet,
    type TrusteeEvaluationKeyEmbeddedProofBytes,
    type TrusteeEvaluationKeyProofGenerationOutput,
    type TrusteeEvaluationKeyProofGenerator,
    type TrusteeEvaluationKeyProofRecord,
    type TrusteeEvaluationKeyProofSet,
    type TrusteeEvaluationKeyProofsInput,
    type TrusteeEvaluationKeyStatementContext,
    type TrusteeEvaluationKeyStatementKey,
    type TrusteeEvaluationKeyTransportedProofBytes,
    type TrusteeEvaluationKeyWitnessInput,
} from './evaluation-key-proof-records/constants-and-types.js';
export {
    evaluationKeyShareComponentVectorHash,
    evaluationKeyShareComponentVectorRoot,
} from './evaluation-key-proof-records/encoding.js';
export {
    createGaloisKeyShareBatches,
    createRelinearizationKeyShareRounds,
} from './evaluation-key-proof-records/share-records.js';
export {
    createTrusteeEvaluationKeyProofs,
    transportTrusteeEvaluationKeyProofSet,
    type TrusteeEvaluationKeyProofMaterialTransport,
} from './evaluation-key-proof-records/trustee-proofs.js';
export { createBinaryChunkedEvaluationKeyShareMaterialTransport } from './evaluation-key-proof-records/component-material-transport.js';
export {
    createBinaryChunkedPublicEvaluationKeyMaterialTransport,
    createPublicEvaluationKeySet,
} from './evaluation-key-proof-records/public-evaluation-key.js';
