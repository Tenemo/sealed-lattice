import { deriveProtocolHash, hash512Hex } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

type JsonRecord = Record<string, unknown>;

export const setupProofTransportChunkSizeBytes = 1_048_576;

const textEncoder = new TextEncoder();

const assertNonNegativeSafeInteger = (
    value: unknown,
    fieldName: string,
): number => {
    if (
        typeof value !== 'number' ||
        !Number.isSafeInteger(value) ||
        value < 0
    ) {
        throw new TypeError(
            `${fieldName} must be a non-negative safe integer.`,
        );
    }

    return value;
};

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
    deriveProtocolHash('SetupProofChunkManifestRoot', {
        objectType: 'SetupProofMaterialChunkManifest',
        objectVersion: 1,
        proofFamily,
        chunkSizeBytes: setupProofTransportChunkSizeBytes,
        chunkCount: chunkHashes.length,
        totalByteLength,
        chunkHashes,
        fullObjectHash,
    });

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
