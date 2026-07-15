import type { ProtocolHash } from '@sealed-lattice/types';

export type CanonicalProofMaterialChunkPull = (input: {
    readonly abortSignal?: AbortSignal;
    readonly chunkIndex: number;
    readonly expectedByteLength: number;
}) => Promise<ArrayBuffer | undefined>;

export type CanonicalGeneratedSetupProofMaterial = Readonly<{
    readonly descriptorBytes: Uint8Array;
}>;

export type SetupProofMaterialChunkSource = Readonly<{
    readonly proofBytesHash: ProtocolHash;
    readonly pullChunk: CanonicalProofMaterialChunkPull;
}>;

export type TransportedSetupProofMaterial = Readonly<{
    readonly proofBytesHash: ProtocolHash;
    readonly descriptorBytes: Uint8Array;
}>;

export type TransportedSetupProofMaterialSet = Readonly<{
    readonly proofMaterials: readonly TransportedSetupProofMaterial[];
}>;
