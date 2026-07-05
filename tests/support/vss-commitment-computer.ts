import type {
    SameSecretBridgeProofComputer,
    VssPublicCommitmentComputer,
    VssPublicCommitmentValue,
    VssShareLinkageProofComputer,
} from '#packages/protocol/src/setup/vss-commitments';
import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';

// The VSS commitment and its share-linkage and same-secret bridge proofs
// are computed only by the Rust/WASM kernel. Tests that assemble setup
// material inject these kernel-backed computers so the protocol layer orchestrates
// the assembly while the certified commitment and proof math stay in one place.
const transcriptCoreKernel = await loadTranscriptCoreKernel();

export const vssPublicCommitmentComputer: VssPublicCommitmentComputer = (
    input,
) => {
    const computation =
        transcriptCoreKernel.computeVssPublicCommitmentFromOpening(input);

    // The kernel returns the commitment as an opaque canonical object; at this
    // test-support boundary we know it is the commitment the protocol
    // aggregate builder sums, so bind it to that type.
    return {
        commitment: computation.commitment as VssPublicCommitmentValue,
        commitmentRoot: computation.commitmentRoot,
        openingRoot: computation.openingRoot,
    };
};

export const vssShareLinkageProofComputer: VssShareLinkageProofComputer = (
    input,
) => transcriptCoreKernel.generateVssShareLinkageProof(input);

export const sameSecretBridgeProofComputer: SameSecretBridgeProofComputer = (
    input,
) => transcriptCoreKernel.generateSameSecretBridgeProof(input);
