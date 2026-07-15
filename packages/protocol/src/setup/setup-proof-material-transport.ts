export type CanonicalProofMaterialChunkPull = (input: {
    readonly abortSignal?: AbortSignal;
    readonly chunkIndex: number;
    readonly expectedByteLength: number;
}) => Promise<ArrayBuffer | undefined>;

export type SetupProofMaterialStream = Readonly<{
    readonly descriptorBytes: Uint8Array;
    readonly pullChunk: CanonicalProofMaterialChunkPull;
}>;

export type SetupProofMaterialStreamSet = Readonly<{
    readonly proofMaterialStreams: readonly SetupProofMaterialStream[];
}>;
