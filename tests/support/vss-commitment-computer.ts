import type {
    SameSecretBridgeProofComputer,
    VssPublicCommitmentComputer,
    VssPublicCommitmentValue,
    VssShareLinkageProofComputer,
} from '#packages/protocol/src/setup/vss-commitments';
import type { TranscriptCoreKernel } from '#packages/wasm/src/index';

export type VssCommitmentComputers = {
    readonly vssPublicCommitmentComputer: VssPublicCommitmentComputer;
    readonly vssShareLinkageProofComputer: VssShareLinkageProofComputer;
    readonly sameSecretBridgeProofComputer: SameSecretBridgeProofComputer;
};

// The VSS commitment and its share-linkage and same-secret bridge proofs are
// computed only by the Rust/WASM kernel. Tests that assemble setup material bind
// these kernel-backed computers to a caller-supplied kernel so the protocol
// layer orchestrates the assembly while the certified commitment and proof math
// stay in one place. Binding to a caller-supplied instance (rather than a
// module-level singleton) lets heavy proof generation run on a throwaway kernel
// whose linear memory is reclaimed after the setup package is built.
export const createVssCommitmentComputers = (
    kernel: TranscriptCoreKernel,
): VssCommitmentComputers => ({
    vssPublicCommitmentComputer: (input) => {
        const computation = kernel.computeVssPublicCommitmentFromOpening(input);

        // The kernel returns the commitment as an opaque canonical object; at
        // this test-support boundary we know it is the commitment the protocol
        // aggregate builder sums, so bind it to that type.
        return {
            commitment: computation.commitment as VssPublicCommitmentValue,
            commitmentRoot: computation.commitmentRoot,
            openingRoot: computation.openingRoot,
        };
    },
    vssShareLinkageProofComputer: (input) =>
        kernel.generateVssShareLinkageProof(input),
    sameSecretBridgeProofComputer: (input) =>
        kernel.generateSameSecretBridgeProof(input),
});
