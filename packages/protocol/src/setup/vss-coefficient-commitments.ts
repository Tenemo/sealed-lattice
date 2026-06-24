// Barrel for the VSS coefficient-commitment record builders. The implementation
// lives in the cohesive sub-modules under ./vss-coefficient-commitments/, grouped
// by the domain problem each part solves: shared vocabulary and types, stateless
// encoding and sampling primitives, per-source-trustee opening-state generation,
// BDLOP commitment value shaping, binary chunked material transport, and the
// commitment bundle constructors. This file keeps the original import path and
// public surface unchanged.
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
    createVssSourceTrusteeCoefficientCommitmentContribution,
    createVssCoefficientCommitmentBundle,
    createBinaryChunkedVssCoefficientCommitmentBundle,
    createStreamingBinaryChunkedVssCoefficientCommitmentBundle,
} from './vss-coefficient-commitments/commitment-bundles.js';
