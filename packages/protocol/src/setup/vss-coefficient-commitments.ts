// These embedded coefficient commitments supply openings for the same-secret
// bridge; transported public setup material uses the VSS commitment sets.
export {
    acceptedBgvSetupQSharePrimes,
    setupCommitmentRandomnessWidth,
    type SetupCommitmentValue,
    type VssCoefficientCommitmentSet,
    type VssCoefficientOpeningInput,
    type VssOpeningRandomByteSource,
    type VssSourceTrusteeCoefficientCommitmentRecord,
    type VssSourceTrusteeCoefficientOpeningState,
} from './vss-coefficient-commitments/constants-and-types.js';
export {
    createVssSourceTrusteeCoefficientOpeningState,
    createVssSourceTrusteeCoefficientOpeningStateProvider,
} from './vss-coefficient-commitments/opening-state.js';
export { createVssCoefficientCommitmentBundle } from './vss-coefficient-commitments/commitment-bundles.js';
