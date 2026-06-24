import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';

// The protocol setup commitment is computed only by the Rust/WASM kernel.
// Tests that assemble VSS coefficient commitments inject this kernel-backed
// computer so the protocol commitment math has a single source of truth.
const transcriptCoreKernel = await loadTranscriptCoreKernel();

export const setupCommitmentComputer: typeof transcriptCoreKernel.computeSetupCommitmentFromOpening =
    (input) => transcriptCoreKernel.computeSetupCommitmentFromOpening(input);
