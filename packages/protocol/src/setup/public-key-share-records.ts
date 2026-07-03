// Barrel for the public-key share record builders. The implementation lives in
// the cohesive sub-modules under ./public-key-share-records/, grouped by the
// domain problem each part solves: shared vocabulary and types, low-level
// encoding helpers, the share/proof statement families, embedded and binary
// chunked share material, collective public-key aggregation, and the succinct
// proof family.
export {
    publicKeyShareProofFamily,
    publicKeyShareMaterialEncoding,
    publicKeyShareMaterialTransportEncoding,
    publicKeyShareMaterialBinaryFormat,
    publicKeyShareCoefficientVectorHashDomain,
    type PublicKeyShareCoefficientVectorHash,
    type PublicKeyShareContributionInput,
    type PublicKeyShareCoefficientVectorMaterial,
    type PublicKeyShareMaterialContributionInput,
    type PublicKeyShareRecord,
    type PublicKeyShareSet,
    type PublicKeyShareProofRecord,
    type PublicKeyShareProofSet,
    type PublicKeyShareMaterialRecord,
    type PublicKeyShareMaterialRootReference,
    type PublicKeyShareMaterialSet,
    type BinaryChunkedPublicKeyShareMaterialSet,
    type SetupTransportedPublicKeyShareMaterial,
    type BinaryChunkedPublicKeyShareMaterialTransport,
    type BinaryChunkedPublicKeyShareMaterialBundle,
    type SetupPackagePublicKeyShareMaterialSet,
    type PublicKeyShareSuccinctEmbeddedProofBytes,
    type PublicKeyShareSuccinctTransportedProofBytes,
    type PublicKeyShareSuccinctProofByteMaterial,
    type PublicKeyShareSuccinctProofMaterial,
    type PublicKeyShareSuccinctProofRecord,
    type PublicKeyShareSuccinctProofSet,
    type CollectivePublicKeySourceShareMaterialRoot,
    type CollectivePublicKeyCoefficientVectorMaterial,
    type CollectivePublicKey,
    type CollectivePublicKeyInput,
    type PublicKeyShareSetInput,
    type PublicKeyShareProofSetInput,
    type PublicKeyShareMaterialSetInput,
    type PublicKeyShareSuccinctProofSetInput,
    type TransportedPublicKeyShareProofMaterialSet,
    type BinaryChunkedPublicKeyShareProofMaterialTransport,
} from './public-key-share-records/constants-and-types.js';
export {
    createPublicKeyShareSet,
    createPublicKeyShareProofSet,
} from './public-key-share-records/share-statement-records.js';
export { createPublicKeyShareMaterialSet } from './public-key-share-records/embedded-material-records.js';
export {
    createBinaryChunkedPublicKeyShareMaterialTransport,
    createBinaryChunkedPublicKeyShareMaterialBundle,
    materialRecordsFromTransportedPublicKeyShareMaterial,
} from './public-key-share-records/binary-material-transport.js';
export {
    createCollectivePublicKey,
    createCollectivePublicKeyFromTransportedPublicKeyShareMaterial,
} from './public-key-share-records/collective-public-key.js';
export {
    createPublicKeyShareSuccinctProofSet,
    createBinaryChunkedPublicKeyShareProofMaterialTransport,
} from './public-key-share-records/succinct-proofs.js';
