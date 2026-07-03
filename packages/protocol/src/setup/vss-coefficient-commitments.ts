// Barrel for the VSS coefficient-commitment record builders. The implementation
// lives in the cohesive sub-modules under ./vss-coefficient-commitments/, grouped
// by the domain problem each part solves: shared vocabulary and types, stateless
// encoding and sampling primitives, per-source-trustee opening-state generation,
// BDLOP commitment value shaping, transported-material decoding, and the
// embedded commitment bundle constructor. The commitments built here are the
// data basis the same-secret proof family opens; the compact VSS commitment
// sets replace them as the transported public setup material.
export {
    setupCommitmentRandomnessWidth,
    acceptedBgvFullRingDegree,
    acceptedBgvSetupQSharePrimes,
    acceptedBgvSetupQShare,
    setupTransportSchemeId,
    setupTransportChunkSizeBytes,
    vssCoefficientCommitmentMaterialBinaryFormat,
    type SetupCommitmentLimbValue,
    type SetupCommitmentValue,
    type VssCoefficientOpeningInput,
    type VssCoefficientOpeningMaterial,
    type VssSourceTrusteeCoefficientOpeningState,
    type VssSourceTrusteeCoefficientOpeningStateReference,
    type VssSourceTrusteeCoefficientOpeningStateProvider,
    type VssOpeningRandomByteSource,
    type VssCoefficientCommitmentRecord,
    type VssSourceTrusteeCoefficientCommitmentRecord,
    type VssCoefficientCommitmentMaterialRecord,
    type VssCoefficientCommitmentSet,
    type VssCoefficientCommitmentMaterialSet,
    type SetupTransportChunk,
    type SetupTransportedVssCoefficientCommitmentMaterial,
    type SetupTransportedVssCoefficientCommitmentMaterialReference,
    type SetupTransportedVssCoefficientCommitmentMaterialLike,
    type BinaryChunkedVssCoefficientCommitmentMaterialSet,
    type SetupPackageVssCoefficientCommitmentMaterialSet,
    type VerifiedVssCoefficientCommitmentMaterial,
    type VssSourceTrusteeOpeningMaterial,
    type VssSourceTrusteeOpeningMaterialReference,
    type VssSourceTrusteeOpeningMaterialSource,
    type VssCoefficientCommitmentBundle,
} from './vss-coefficient-commitments/constants-and-types.js';
export { binaryVssCoefficientCommitmentMaterialByteLength } from './vss-coefficient-commitments/encoding.js';
export {
    createVssSourceTrusteeCoefficientOpeningState,
    createVssSourceTrusteeCoefficientOpeningStateProvider,
} from './vss-coefficient-commitments/opening-state.js';
export { setupCommitmentRootPayload } from './vss-coefficient-commitments/commitment-values.js';
export {
    createBinaryChunkedVssCoefficientCommitmentMaterialTransport,
    materialRecordsFromTransportedVssCoefficientCommitmentMaterial,
} from './vss-coefficient-commitments/binary-transport.js';
export {
    createBinaryChunkedVssCoefficientCommitmentBundle,
    createStreamingBinaryChunkedVssCoefficientCommitmentBundle,
    createVssSourceTrusteeCoefficientCommitmentContribution,
    createVssCoefficientCommitmentBundle,
} from './vss-coefficient-commitments/commitment-bundles.js';
