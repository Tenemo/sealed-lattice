import type { SetupProofMaterialChunkSource } from '#packages/protocol/src/setup/setup-proof-material-transport';
import type {
    SameSecretBridgeProofComputer,
    VssAggregateThresholdProofComputer,
    VssCommittedMaterialCommitmentComputer,
    VssCommittedMaterialCommitmentValue,
    VssShareLinkageProofComputer,
} from '#packages/protocol/src/setup/vss-commitments';
import {
    bgvCanonicalStreamFamilies,
    openBgvCanonicalStreamRuntime,
    type TranscriptCoreKernel,
} from '#packages/wasm/src/index';

export type VssCommitmentComputers = {
    readonly vssCommittedMaterialCommitmentComputer: VssCommittedMaterialCommitmentComputer;
    readonly vssAggregateThresholdProofComputer: VssAggregateThresholdProofComputer;
    readonly vssShareLinkageProofComputer: VssShareLinkageProofComputer;
    readonly sameSecretBridgeProofComputer: SameSecretBridgeProofComputer;
    readonly proofMaterialChunkSources: () => readonly SetupProofMaterialChunkSource[];
};

// The VSS committed-material commitment and its share-linkage and same-secret
// bridge proofs are computed only by the Rust/WASM kernel. Tests that assemble
// setup material bind these kernel-backed computers to a caller-supplied kernel
// so the protocol layer orchestrates the assembly while the certified
// commitment and proof math stay in one place. Binding to a caller-supplied
// instance (rather than a module-level singleton) lets heavy proof generation
// run on a throwaway kernel whose linear memory is reclaimed after the setup
// package is built.
export const createVssCommitmentComputers = (
    kernel: TranscriptCoreKernel,
): VssCommitmentComputers => {
    const canonicalStreamRuntime = openBgvCanonicalStreamRuntime({ kernel });
    const storedChunksByMaterialRoot = new Map<
        string,
        readonly ArrayBuffer[]
    >();
    const writeGeneratedProofMaterial = async (
        family: Parameters<
            typeof canonicalStreamRuntime.writeMaterial
        >[0]['family'],
        materialRoot: string,
    ): Promise<Readonly<{ readonly descriptorBytes: Uint8Array }>> => {
        const storedChunks: ArrayBuffer[] = [];
        const descriptorBytes = await canonicalStreamRuntime.writeMaterial({
            emitChunk: ({ bytes, chunkIndex }) => {
                storedChunks[chunkIndex] = bytes.slice(0);
                return Promise.resolve();
            },
            family,
            materialRoot,
        });
        storedChunksByMaterialRoot.set(materialRoot, storedChunks);
        return { descriptorBytes };
    };

    return {
        vssCommittedMaterialCommitmentComputer: (input) => {
            const computation =
                kernel.computeVssCommittedMaterialCommitment(input);

            // The kernel returns the commitment as an opaque canonical object; at
            // this test-support boundary we know it is the committed-material
            // commitment the protocol builders embed, so bind it to that type.
            return {
                commitment:
                    computation.commitment as VssCommittedMaterialCommitmentValue,
                commitmentRoot: computation.commitmentRoot,
                openingRoot: computation.openingRoot,
                commitmentContextHash: computation.commitmentContextHash,
            };
        },
        vssAggregateThresholdProofComputer: async (input) => {
            const generated = kernel.generateVssShareLinkageProof(input);

            return {
                ...generated,
                canonicalMaterial: await writeGeneratedProofMaterial(
                    bgvCanonicalStreamFamilies.vssShareLinkage,
                    generated.proofMaterialRoot,
                ),
            };
        },
        vssShareLinkageProofComputer: async (input) => {
            const generated = kernel.generateVssShareLinkageProof(input);

            return {
                ...generated,
                canonicalMaterial: await writeGeneratedProofMaterial(
                    bgvCanonicalStreamFamilies.vssShareLinkage,
                    generated.proofMaterialRoot,
                ),
            };
        },
        sameSecretBridgeProofComputer: async (input) => {
            const generated = kernel.generateSameSecretBridgeProof(input);

            return {
                ...generated,
                canonicalMaterial: await writeGeneratedProofMaterial(
                    bgvCanonicalStreamFamilies.sameSecretBridge,
                    generated.proofMaterialRoot,
                ),
            };
        },
        proofMaterialChunkSources: () =>
            [...storedChunksByMaterialRoot].map(
                ([proofMaterialRoot, storedChunks]) => ({
                    proofMaterialRoot,
                    pullChunk: ({ chunkIndex }) =>
                        Promise.resolve(storedChunks[chunkIndex]?.slice(0)),
                }),
            ),
    };
};
