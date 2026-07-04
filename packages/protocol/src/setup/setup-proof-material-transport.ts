import {
    deriveCanonicalObjectHash,
    hash512Hex,
    setupProofMaterialFullObjectHashHex,
} from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import {
    assertNonNegativeSafeInteger,
    type JsonRecord,
} from './common-fields.js';

export const setupProofTransportChunkSizeBytes = 1_048_576;

const textEncoder = new TextEncoder();

const bytesToHex = (bytes: Uint8Array): string =>
    [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');

const varUintBytes = (value: number, fieldName: string): Uint8Array => {
    const numericValue = assertNonNegativeSafeInteger(value, fieldName);
    const bytes: number[] = [];
    let remainingValue = numericValue;
    do {
        let byte = remainingValue & 0x7f;
        remainingValue = Math.floor(remainingValue / 128);
        if (remainingValue !== 0) {
            byte |= 0x80;
        }
        bytes.push(byte);
    } while (remainingValue !== 0);

    return Uint8Array.from(bytes);
};

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
    readonly chunkHashes: readonly ProtocolHash[];
    readonly chunkRoot: ProtocolHash;
    readonly totalByteLength: number;
    readonly fullObjectHash: ProtocolHash;
}>;

type SetupProofMaterialTransportChunk = Readonly<
    JsonRecord & {
        readonly chunkIndex: number;
        readonly bytesHex: string;
    }
>;

export const setupProofMaterialReferenceFields = (
    metadata: SetupProofMaterialTransportMetadata,
): JsonRecord => ({
    chunkSizeBytes: setupProofTransportChunkSizeBytes,
    chunkCount: metadata.chunkHashes.length,
    totalByteLength: metadata.totalByteLength,
    fullObjectHash: metadata.fullObjectHash,
    chunkRoot: metadata.chunkRoot,
    chunkHashes: metadata.chunkHashes,
});

export const setupProofMaterialRecordTransportMetadataFields = (
    metadata: SetupProofMaterialTransportMetadata,
): Readonly<
    JsonRecord & {
        readonly proofChunkSizeBytes: typeof setupProofTransportChunkSizeBytes;
        readonly proofChunkCount: number;
        readonly proofTotalByteLength: number;
        readonly proofFullObjectHash: ProtocolHash;
        readonly proofChunkRoot: ProtocolHash;
        readonly proofChunkHashes: readonly ProtocolHash[];
    }
> => ({
    proofChunkSizeBytes: setupProofTransportChunkSizeBytes,
    proofChunkCount: metadata.chunkHashes.length,
    proofTotalByteLength: metadata.totalByteLength,
    proofFullObjectHash: metadata.fullObjectHash,
    proofChunkRoot: metadata.chunkRoot,
    proofChunkHashes: metadata.chunkHashes,
});

export const setupProofMaterialRecordTransportFields = <
    ProofBytesEncoding extends string,
>(
    metadata: SetupProofMaterialTransportMetadata,
    proofMaterialRoot: ProtocolHash,
    proofBytesEncoding: ProofBytesEncoding,
): Readonly<
    JsonRecord & {
        readonly proofBytesEncoding: ProofBytesEncoding;
        readonly proofMaterialRoot: ProtocolHash;
        readonly proofChunkSizeBytes: typeof setupProofTransportChunkSizeBytes;
        readonly proofChunkCount: number;
        readonly proofTotalByteLength: number;
        readonly proofFullObjectHash: ProtocolHash;
        readonly proofChunkRoot: ProtocolHash;
        readonly proofChunkHashes: readonly ProtocolHash[];
    }
> => ({
    proofBytesEncoding,
    proofMaterialRoot,
    ...setupProofMaterialRecordTransportMetadataFields(metadata),
});

export const setupTransportedProofMaterialFields = (
    metadata: SetupProofMaterialTransportMetadata,
    proofMaterialRoot: ProtocolHash,
): Readonly<
    JsonRecord & {
        readonly proofMaterialRoot: ProtocolHash;
        readonly chunkSizeBytes: typeof setupProofTransportChunkSizeBytes;
        readonly chunkCount: number;
        readonly totalByteLength: number;
        readonly fullObjectHash: ProtocolHash;
        readonly chunkHashes: readonly ProtocolHash[];
        readonly chunkRoot: ProtocolHash;
    }
> => ({
    proofMaterialRoot,
    chunkSizeBytes: setupProofTransportChunkSizeBytes,
    chunkCount: metadata.chunkHashes.length,
    totalByteLength: metadata.totalByteLength,
    fullObjectHash: metadata.fullObjectHash,
    chunkHashes: metadata.chunkHashes,
    chunkRoot: metadata.chunkRoot,
});

export const setupProofMaterialTransportChunks = (
    metadata: SetupProofMaterialTransportMetadata,
): readonly SetupProofMaterialTransportChunk[] =>
    metadata.chunks.map((chunk, chunkIndex) => ({
        chunkIndex,
        bytesHex: bytesToHex(chunk),
    }));

// Each chunk hash binds its index and the full-object hash, so chunks cannot be reordered within an object or spliced in from a different proof object.
export const setupProofMaterialChunkHash = (
    proofFamily: string,
    fullObjectHash: ProtocolHash,
    chunkIndex: number,
    chunk: Uint8Array,
): ProtocolHash =>
    hash512Hex('sealed-lattice/setup/proof-material/chunk-v1', [
        textEncoder.encode(proofFamily),
        textEncoder.encode(fullObjectHash),
        varUintBytes(chunkIndex, 'chunkIndex'),
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
        objectVersion: 1,
        proofFamily,
        chunkSizeBytes: setupProofTransportChunkSizeBytes,
        chunkCount: chunkHashes.length,
        totalByteLength,
        chunkHashes,
        fullObjectHash,
    });

export const setupProofMaterialTransportMetadata = (
    proofFamily: string,
    proofBytes: Uint8Array,
    emptyProofBytesMessage: string,
): SetupProofMaterialTransportMetadata => {
    const chunks = splitProofBytesIntoChunks(proofBytes);
    if (chunks.length === 0) {
        throw new Error(emptyProofBytesMessage);
    }
    const totalByteLength = proofBytes.byteLength;
    const fullObjectHash = setupProofMaterialFullObjectHashHex(
        proofFamily,
        totalByteLength,
        chunks,
    );
    const chunkHashes = chunks.map((chunk, chunkIndex) =>
        setupProofMaterialChunkHash(
            proofFamily,
            fullObjectHash,
            chunkIndex,
            chunk,
        ),
    );
    const chunkRoot = setupProofChunkManifestRoot(
        proofFamily,
        chunkHashes,
        fullObjectHash,
        totalByteLength,
    );

    return {
        chunks,
        chunkHashes,
        chunkRoot,
        totalByteLength,
        fullObjectHash,
    };
};

export type TransportedSetupProofMaterialSet<
    ObjectType extends string = string,
> = Readonly<
    JsonRecord & {
        readonly objectType: ObjectType;
        readonly objectVersion: 1;
        readonly proofFamily: string;
        readonly proofMaterials: readonly JsonRecord[];
    }
>;

export type VerifiedSetupProofMaterial = Readonly<
    JsonRecord & {
        readonly objectType: 'VerifiedSetupProofMaterial';
        readonly objectVersion: 1;
        readonly verificationId: string;
        readonly proofFamily: string;
        readonly proofMaterialRoot: ProtocolHash;
        readonly proofBytesEncoding: 'binary-chunked-proof-bytes';
        readonly proofChunkSizeBytes: typeof setupProofTransportChunkSizeBytes;
        readonly proofChunkCount: number;
        readonly proofTotalByteLength: number;
        readonly proofFullObjectHash: ProtocolHash;
        readonly proofChunkRoot: ProtocolHash;
        readonly proofChunkHashes: readonly ProtocolHash[];
    }
>;

export type VerifiedSetupProofMaterialSet = Readonly<
    JsonRecord & {
        readonly objectType: 'VerifiedSetupProofMaterialSet';
        readonly objectVersion: 1;
        readonly proofMaterials: readonly VerifiedSetupProofMaterial[];
    }
>;

export const chunklessSetupProofMaterialSetForVerificationInput = <
    TransportedSet extends TransportedSetupProofMaterialSet | undefined,
>(
    transportedMaterialSet: TransportedSet,
    verifiedSetupProofMaterials: VerifiedSetupProofMaterialSet | undefined,
): TransportedSet => {
    if (
        transportedMaterialSet === undefined ||
        verifiedSetupProofMaterials === undefined
    ) {
        return transportedMaterialSet;
    }

    const verifiedProofMaterialRoots = new Set(
        verifiedSetupProofMaterials.proofMaterials.map(
            (proofMaterial) => proofMaterial.proofMaterialRoot,
        ),
    );
    let strippedAnyChunks = false;
    const proofMaterials = transportedMaterialSet.proofMaterials.map(
        (proofMaterial) => {
            if (
                !Object.prototype.hasOwnProperty.call(
                    proofMaterial,
                    'chunks',
                ) ||
                typeof proofMaterial.proofMaterialRoot !== 'string' ||
                !verifiedProofMaterialRoots.has(proofMaterial.proofMaterialRoot)
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
