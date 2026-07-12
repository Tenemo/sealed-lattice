import { deriveCanonicalObjectHash, hash512Hex } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import type { JsonRecord } from './common-fields.js';
import { appendVaruint } from './varuint-encoding.js';

export const setupProofTransportChunkSizeBytes = 1_048_576;

const varUintBytes = (value: number): Uint8Array => {
    const outputBytes: number[] = [];
    appendVaruint(outputBytes, value);

    return Uint8Array.from(outputBytes);
};

// Target-decryption material has not migrated to canonical stream transport.
// Keep its legacy framing local to that path while setup proof families rely
// exclusively on the canonical stream descriptor.
export const setupProofMaterialChunkHash = (
    proofFamily: string,
    fullObjectHash: ProtocolHash,
    chunkIndex: number,
    chunk: Uint8Array,
): ProtocolHash =>
    hash512Hex('sealed-lattice/setup/proof-material/chunk', [
        new TextEncoder().encode(proofFamily),
        new TextEncoder().encode(fullObjectHash),
        varUintBytes(chunkIndex),
        chunk,
    ]);

export const setupProofChunkManifestRoot = (
    proofFamily: string,
    chunkHashes: readonly ProtocolHash[],
    fullObjectHash: ProtocolHash,
    totalByteLength: number,
): ProtocolHash =>
    deriveCanonicalObjectHash({
        objectType: 'SetupProofMaterialChunkManifest',
        proofFamily,
        totalByteLength,
        chunkHashes,
        fullObjectHash,
    });

const splitProofBytesIntoChunks = (
    proofBytes: Uint8Array,
): readonly Uint8Array[] => {
    const chunks: Uint8Array[] = [];
    for (
        let chunkStart = 0;
        chunkStart < proofBytes.byteLength;
        chunkStart += setupProofTransportChunkSizeBytes
    ) {
        chunks.push(
            proofBytes.slice(
                chunkStart,
                Math.min(
                    chunkStart + setupProofTransportChunkSizeBytes,
                    proofBytes.byteLength,
                ),
            ),
        );
    }

    return chunks;
};

type SetupProofMaterialTransportMetadata = Readonly<{
    readonly chunks: readonly Uint8Array[];
}>;

type SetupProofMaterialTransportChunk = Readonly<
    JsonRecord & {
        readonly chunkIndex: number;
        readonly bytes: ArrayBuffer;
    }
>;

export const setupProofMaterialRecordTransportFields = <
    ProofBytesEncoding extends string,
>(
    proofMaterialRoot: ProtocolHash,
    proofBytesEncoding: ProofBytesEncoding,
): Readonly<
    JsonRecord & {
        readonly proofBytesEncoding: ProofBytesEncoding;
        readonly proofMaterialRoot: ProtocolHash;
    }
> => ({
    proofBytesEncoding,
    proofMaterialRoot,
});

export const setupTransportedProofMaterialFields = (
    proofMaterialRoot: ProtocolHash,
): Readonly<
    JsonRecord & {
        readonly proofMaterialRoot: ProtocolHash;
    }
> => ({
    proofMaterialRoot,
});

export const setupProofMaterialTransportChunks = (
    metadata: SetupProofMaterialTransportMetadata,
): readonly SetupProofMaterialTransportChunk[] =>
    metadata.chunks.map((chunk, chunkIndex) => ({
        chunkIndex,
        bytes: chunk.slice().buffer,
    }));

export const setupProofMaterialTransportMetadata = (
    proofBytes: Uint8Array,
    emptyProofBytesMessage: string,
): SetupProofMaterialTransportMetadata => {
    const chunks = splitProofBytesIntoChunks(proofBytes);
    if (chunks.length === 0) {
        throw new Error(emptyProofBytesMessage);
    }

    return { chunks };
};

export type TransportedSetupProofMaterialSet<
    ObjectType extends string = string,
> = Readonly<
    JsonRecord & {
        readonly objectType: ObjectType;
        readonly proofFamily: string;
        readonly proofMaterials: readonly JsonRecord[];
    }
>;

export const chunklessSetupProofMaterialSetForVerificationInput = <
    TransportedSet extends TransportedSetupProofMaterialSet | undefined,
>(
    transportedMaterialSet: TransportedSet,
): TransportedSet => {
    if (transportedMaterialSet === undefined) {
        return transportedMaterialSet;
    }
    let strippedAnyChunks = false;
    const proofMaterials = transportedMaterialSet.proofMaterials.map(
        (proofMaterial) => {
            if (
                !Object.prototype.hasOwnProperty.call(
                    proofMaterial,
                    'chunks',
                ) ||
                typeof proofMaterial.proofMaterialRoot !== 'string'
            ) {
                return proofMaterial;
            }
            const { chunks: omittedChunks, ...proofMaterialReference } =
                proofMaterial;
            void omittedChunks;
            strippedAnyChunks = true;

            return proofMaterialReference;
        },
    );

    if (!strippedAnyChunks) {
        return transportedMaterialSet;
    }

    return {
        ...transportedMaterialSet,
        proofMaterials,
    };
};
