import type {
    VssCommittedMaterialCommitmentComputer,
    VssCommittedMaterialCommitmentValue,
} from '#packages/protocol/src/setup/vss-commitments';
import type { TranscriptCoreKernel } from '#packages/wasm/src/index';

// The VSS committed-material commitment is computed only by the Rust/WASM
// kernel. Bind the protocol adapter to the caller's kernel so tests use the
// canonical implementation without retaining a second kernel instance.
export const createVssCommittedMaterialCommitmentComputer =
    (kernel: TranscriptCoreKernel): VssCommittedMaterialCommitmentComputer =>
    (input) => {
        const computation = kernel.computeVssCommittedMaterialCommitment(input);

        return {
            commitment:
                computation.commitment as VssCommittedMaterialCommitmentValue,
            commitmentContextHash: computation.commitmentContextHash,
            commitmentRoot: computation.commitmentRoot,
            openingRoot: computation.openingRoot,
        };
    };
