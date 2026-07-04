import type {
    CompactSameSecretBridgeProofComputer,
    CompactVssCommitmentComputer,
    CompactVssCommitmentValue,
    CompactVssShareLinkageProofComputer,
} from '#packages/protocol/src/setup/compact-vss-commitments';
import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';

// The compact VSS commitment and its share-linkage and same-secret bridge proofs
// are computed only by the Rust/WASM kernel. Tests that assemble compact setup
// material inject these kernel-backed computers so the protocol layer orchestrates
// the assembly while the certified commitment and proof math stay in one place.
const transcriptCoreKernel = await loadTranscriptCoreKernel();

export const compactVssCommitmentComputer: CompactVssCommitmentComputer = (
    input,
) => {
    const computation =
        transcriptCoreKernel.computeCompactVssCommitmentFromOpening(input);

    // The kernel returns the commitment as an opaque canonical object; at this
    // test-support boundary we know it is the compact commitment the protocol
    // aggregate builder sums, so bind it to that type.
    return {
        commitment: computation.commitment as CompactVssCommitmentValue,
        commitmentRoot: computation.commitmentRoot,
        openingRoot: computation.openingRoot,
    };
};

export const compactVssShareLinkageProofComputer: CompactVssShareLinkageProofComputer =
    (input) => transcriptCoreKernel.generateCompactVssShareLinkageProof(input);

export const compactSameSecretBridgeProofComputer: CompactSameSecretBridgeProofComputer =
    (input) => transcriptCoreKernel.generateCompactSameSecretBridgeProof(input);
