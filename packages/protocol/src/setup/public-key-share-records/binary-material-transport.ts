import { deriveCanonicalObjectHash, hash512Hex } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import { ChunkedBinaryReader } from '../chunked-binary-reader.js';
import {
    setupTransportChunkSizeBytes,
    setupTransportSchemeId,
} from '../vss-coefficient-commitments.js';
import type { CollectiveBgvSetupContext } from '../vss-share-verification-records.js';

import {
    isJsonRecord,
    publicKeyShareMaterialBinaryFormat,
    publicKeyShareMaterialEncoding,
    publicKeyShareMaterialTransportEncoding,
    publicKeyShareProofFamily,
    type BinaryChunkedPublicKeyShareMaterialBundle,
    type BinaryChunkedPublicKeyShareMaterialSet,
    type BinaryChunkedPublicKeyShareMaterialTransport,
    type JsonRecord,
    type PublicKeyShareCoefficientVectorMaterial,
    type PublicKeyShareMaterialRecord,
    type PublicKeyShareMaterialRootReference,
    type PublicKeyShareMaterialSet,
    type PublicKeyShareMaterialSetInput,
    type PublicKeyShareRecord,
    type PublicKeyShareSet,
    type SetupTransportedPublicKeyShareMaterial,
} from './constants-and-types.js';
import {
    assertPublicKeyShareMaterialInput,
    encodePublicKeyShareMaterial,
    encodePublicKeyShareMaterialRecords,
    publicKeyShareMaterialRecordsFromContributions,
    publicKeyShareMaterialRootReferences,
} from './embedded-material-records.js';
import {
    assertContextMatches,
    bytesFromHex,
    bytesToHex,
    coefficientVectorHash512,
    coefficientVectorToLittleEndianHex,
    contextFields,
    publicKeyShareMaterialBinaryMagic,
} from './encoding.js';
import { publicKeyShareRecordsByRosterPosition } from './share-statement-records.js';

const setupTransportChunkManifestRoot = (input: {
    readonly chunkSizeBytes: number;
    readonly chunkCount: number;
    readonly totalByteLength: number;
    readonly chunkHashes: readonly ProtocolHash[];
    readonly fullObjectHash: ProtocolHash;
}): ProtocolHash =>
    deriveCanonicalObjectHash({
        objectType: 'SetupTransportChunkManifest',
        chunkSizeBytes: input.chunkSizeBytes,
        chunkCount: input.chunkCount,
        totalByteLength: input.totalByteLength,
        chunkHashes: input.chunkHashes,
        fullObjectHash: input.fullObjectHash,
    });

const publicKeyShareMaterialFullObjectHash = (
    totalByteLength: number,
    chunks: readonly Uint8Array[],
): ProtocolHash => {
    const totalLengthBytes = new Uint8Array(8);
    new DataView(totalLengthBytes.buffer).setBigUint64(
        0,
        BigInt(totalByteLength),
        true,
    );

    return hash512Hex(
        'sealed-lattice/setup/public-key-share-material/full-object-v1',
        [totalLengthBytes, ...chunks],
    );
};

const publicKeyShareMaterialChunkHash = (
    fullObjectHash: ProtocolHash,
    chunkIndex: number,
    chunk: Uint8Array,
): ProtocolHash => {
    const chunkIndexBytes = new Uint8Array(8);
    new DataView(chunkIndexBytes.buffer).setBigUint64(
        0,
        BigInt(chunkIndex),
        true,
    );

    return hash512Hex(
        'sealed-lattice/setup/public-key-share-material/chunk-v1',
        [new TextEncoder().encode(fullObjectHash), chunkIndexBytes, chunk],
    );
};

const publicKeyShareMaterialTransportHashes = (
    chunks: readonly Uint8Array[],
): Readonly<{
    readonly fullObjectHash: ProtocolHash;
    readonly chunkHashes: readonly ProtocolHash[];
    readonly chunkRoot: ProtocolHash;
    readonly totalByteLength: number;
}> => {
    if (chunks.length === 0) {
        throw new Error(
            'public-key share material transport requires at least one chunk.',
        );
    }
    const totalByteLength = chunks.reduce(
        (accumulatedLength, chunk, chunkIndex) => {
            if (chunk.byteLength === 0) {
                throw new Error(
                    'public-key share material chunks must be non-empty.',
                );
            }
            if (chunk.byteLength > setupTransportChunkSizeBytes) {
                throw new Error(
                    'public-key share material chunk exceeds the accepted chunk size.',
                );
            }
            if (
                chunkIndex + 1 < chunks.length &&
                chunk.byteLength !== setupTransportChunkSizeBytes
            ) {
                throw new Error(
                    'public-key share material contains a short non-final chunk.',
                );
            }

            return accumulatedLength + chunk.byteLength;
        },
        0,
    );
    const fullObjectHash = publicKeyShareMaterialFullObjectHash(
        totalByteLength,
        chunks,
    );
    const chunkHashes = chunks.map((chunk, chunkIndex) =>
        publicKeyShareMaterialChunkHash(fullObjectHash, chunkIndex, chunk),
    );
    const chunkRoot = setupTransportChunkManifestRoot({
        chunkSizeBytes: setupTransportChunkSizeBytes,
        chunkCount: chunks.length,
        totalByteLength,
        chunkHashes,
        fullObjectHash,
    });

    return {
        fullObjectHash,
        chunkHashes,
        chunkRoot,
        totalByteLength,
    };
};

const binaryChunkedPublicKeyShareMaterialSetFromTransport = (
    input: Readonly<{
        readonly setupContext: CollectiveBgvSetupContext;
        readonly participantCount: number;
        readonly rnsLimbCount: number;
        readonly ringDegree: number;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly publicKeyCrpRoot: ProtocolHash;
        readonly publicAPolynomialRoot: ProtocolHash;
        readonly publicKeyShareSetRoot: ProtocolHash;
        readonly publicKeyShareMaterialRoots: readonly PublicKeyShareMaterialRootReference[];
        readonly chunkCount: number;
        readonly transportHashes: Readonly<{
            readonly fullObjectHash: ProtocolHash;
            readonly chunkRoot: ProtocolHash;
            readonly totalByteLength: number;
        }>;
    }>,
): BinaryChunkedPublicKeyShareMaterialSet => {
    const materialSetWithoutRoot = {
        objectType: 'PublicKeyShareMaterialSet',
        proofFamily: publicKeyShareProofFamily,
        materialEncoding: publicKeyShareMaterialTransportEncoding,
        binaryFormat: publicKeyShareMaterialBinaryFormat,
        ...contextFields(input.setupContext),
        participantCount: input.participantCount,
        rnsLimbCount: input.rnsLimbCount,
        ringDegree: input.ringDegree,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        publicKeyCrpRoot: input.publicKeyCrpRoot,
        publicAPolynomialRoot: input.publicAPolynomialRoot,
        publicKeyShareSetRoot: input.publicKeyShareSetRoot,
        publicKeyShareMaterialRoots: input.publicKeyShareMaterialRoots,
        transport: {
            transportSchemeId: setupTransportSchemeId,
            chunkSizeBytes: setupTransportChunkSizeBytes,
            chunkCount: input.chunkCount,
            totalByteLength: input.transportHashes.totalByteLength,
            fullObjectHash: input.transportHashes.fullObjectHash,
            chunkRoot: input.transportHashes.chunkRoot,
        },
    } as const satisfies Omit<
        BinaryChunkedPublicKeyShareMaterialSet,
        'publicKeyShareMaterialSetRoot'
    >;

    return {
        ...materialSetWithoutRoot,
        publicKeyShareMaterialSetRoot: deriveCanonicalObjectHash(
            materialSetWithoutRoot,
        ),
    } satisfies BinaryChunkedPublicKeyShareMaterialSet;
};

const transportedPublicKeyShareMaterialFromChunks = (
    chunks: readonly Uint8Array[],
): SetupTransportedPublicKeyShareMaterial => {
    const transportHashes = publicKeyShareMaterialTransportHashes(chunks);

    return {
        objectType: 'SetupTransportedPublicKeyShareMaterial',
        binaryFormat: publicKeyShareMaterialBinaryFormat,
        chunkSizeBytes: setupTransportChunkSizeBytes,
        chunkCount: chunks.length,
        totalByteLength: transportHashes.totalByteLength,
        fullObjectHash: transportHashes.fullObjectHash,
        chunkHashes: transportHashes.chunkHashes,
        chunkRoot: transportHashes.chunkRoot,
        chunks: chunks.map((chunk, chunkIndex) => ({
            chunkIndex,
            bytesHex: bytesToHex(chunk),
        })),
    };
};

export const createBinaryChunkedPublicKeyShareMaterialTransport = (
    materialSet: PublicKeyShareMaterialSet,
): BinaryChunkedPublicKeyShareMaterialTransport => {
    if (materialSet.materialEncoding !== publicKeyShareMaterialEncoding) {
        throw new Error(
            'binary public-key share material transport must be built from embedded full public values.',
        );
    }
    const chunks = encodePublicKeyShareMaterial(materialSet);
    const transportedMaterial =
        transportedPublicKeyShareMaterialFromChunks(chunks);
    const binaryMaterialSet =
        binaryChunkedPublicKeyShareMaterialSetFromTransport({
            setupContext: materialSet as unknown as CollectiveBgvSetupContext,
            participantCount: materialSet.participantCount,
            rnsLimbCount: materialSet.rnsLimbCount,
            ringDegree: materialSet.ringDegree,
            publicMatrixSeedHash: materialSet.publicMatrixSeedHash,
            publicKeyCrpRoot: materialSet.publicKeyCrpRoot,
            publicAPolynomialRoot: materialSet.publicAPolynomialRoot,
            publicKeyShareSetRoot: materialSet.publicKeyShareSetRoot,
            publicKeyShareMaterialRoots:
                materialSet.publicKeyShareMaterialRoots,
            chunkCount: transportedMaterial.chunkCount,
            transportHashes: {
                fullObjectHash: transportedMaterial.fullObjectHash,
                chunkRoot: transportedMaterial.chunkRoot,
                totalByteLength: transportedMaterial.totalByteLength,
            },
        });

    return {
        materialSet: binaryMaterialSet,
        transportedPublicKeyShareMaterial: transportedMaterial,
    };
};

export const createBinaryChunkedPublicKeyShareMaterialBundle = (
    input: PublicKeyShareMaterialSetInput,
): BinaryChunkedPublicKeyShareMaterialBundle => {
    assertPublicKeyShareMaterialInput(input);
    const shareMaterialRecords =
        publicKeyShareMaterialRecordsFromContributions(input);
    const chunks = encodePublicKeyShareMaterialRecords({
        participantCount: input.participantCount,
        rnsLimbCount: input.qSharePrimes.length,
        ringDegree: input.ringDegree,
        shareMaterialRecords,
    });
    const transportedMaterial =
        transportedPublicKeyShareMaterialFromChunks(chunks);
    const materialSet = binaryChunkedPublicKeyShareMaterialSetFromTransport({
        setupContext: input.setupContext,
        participantCount: input.participantCount,
        rnsLimbCount: input.qSharePrimes.length,
        ringDegree: input.ringDegree,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        publicKeyCrpRoot: input.publicKeyCrpRoot,
        publicAPolynomialRoot: input.publicAPolynomialRoot,
        publicKeyShareSetRoot: input.publicKeyShares.publicKeyShareSetRoot,
        publicKeyShareMaterialRoots:
            publicKeyShareMaterialRootReferences(shareMaterialRecords),
        chunkCount: transportedMaterial.chunkCount,
        transportHashes: {
            fullObjectHash: transportedMaterial.fullObjectHash,
            chunkRoot: transportedMaterial.chunkRoot,
            totalByteLength: transportedMaterial.totalByteLength,
        },
    });

    return {
        materialSet,
        transportedPublicKeyShareMaterial: transportedMaterial,
    };
};

const transportedPublicKeyShareMaterialChunks = (
    transportedMaterial: SetupTransportedPublicKeyShareMaterial | JsonRecord,
): readonly Uint8Array[] => {
    if (
        transportedMaterial.objectType !==
        'SetupTransportedPublicKeyShareMaterial'
    ) {
        throw new Error(
            'transportedPublicKeyShareMaterial.objectType must be SetupTransportedPublicKeyShareMaterial.',
        );
    }
    if (transportedMaterial.objectVersion !== 1) {
        throw new Error(
            'transportedPublicKeyShareMaterial.objectVersion must be 1.',
        );
    }
    if (
        transportedMaterial.binaryFormat !== publicKeyShareMaterialBinaryFormat
    ) {
        throw new Error(
            'transportedPublicKeyShareMaterial.binaryFormat must match the accepted binary format.',
        );
    }
    if (transportedMaterial.chunkSizeBytes !== setupTransportChunkSizeBytes) {
        throw new Error(
            'transportedPublicKeyShareMaterial.chunkSizeBytes must match the setup transport scheme.',
        );
    }
    if (!Array.isArray(transportedMaterial.chunks)) {
        throw new TypeError(
            'transportedPublicKeyShareMaterial.chunks must be an array.',
        );
    }
    if (transportedMaterial.chunks.length !== transportedMaterial.chunkCount) {
        throw new Error(
            'transportedPublicKeyShareMaterial.chunks length must match chunkCount.',
        );
    }

    const chunkValues: readonly unknown[] = transportedMaterial.chunks;
    return chunkValues.map((chunkValue, expectedChunkIndex) => {
        if (!isJsonRecord(chunkValue)) {
            throw new TypeError(
                'transportedPublicKeyShareMaterial chunks must be objects.',
            );
        }
        if (chunkValue.chunkIndex !== expectedChunkIndex) {
            throw new Error(
                'transportedPublicKeyShareMaterial chunks must be supplied in ascending chunk-index order.',
            );
        }
        if (typeof chunkValue.bytesHex !== 'string') {
            throw new TypeError(
                'transportedPublicKeyShareMaterial chunk bytesHex must be a string.',
            );
        }

        return bytesFromHex(
            chunkValue.bytesHex,
            `transportedPublicKeyShareMaterial.chunks.${String(expectedChunkIndex)}.bytesHex`,
        );
    });
};

const verifyTransportedPublicKeyShareMaterialHashes = (
    transportedMaterial: SetupTransportedPublicKeyShareMaterial | JsonRecord,
    chunks: readonly Uint8Array[],
): void => {
    const hashes = publicKeyShareMaterialTransportHashes(chunks);
    if (
        transportedMaterial.totalByteLength !== hashes.totalByteLength ||
        transportedMaterial.fullObjectHash !== hashes.fullObjectHash ||
        transportedMaterial.chunkRoot !== hashes.chunkRoot ||
        transportedMaterial.chunkCount !== hashes.chunkHashes.length
    ) {
        throw new Error(
            'transported public-key share material hash metadata does not match supplied chunks.',
        );
    }
    const observedChunkHashes = transportedMaterial.chunkHashes;
    if (!Array.isArray(observedChunkHashes)) {
        throw new TypeError(
            'transportedPublicKeyShareMaterial.chunkHashes must be an array.',
        );
    }
    if (observedChunkHashes.length !== hashes.chunkHashes.length) {
        throw new Error(
            'transportedPublicKeyShareMaterial.chunkHashes length must match chunkCount.',
        );
    }
    hashes.chunkHashes.forEach((chunkHash, chunkIndex) => {
        if (observedChunkHashes[chunkIndex] !== chunkHash) {
            throw new Error(
                'transported public-key share material chunk hashes do not match supplied chunks.',
            );
        }
    });
};

type TransportedPublicKeyShareMaterialReaderInput = Readonly<{
    readonly setupContext: CollectiveBgvSetupContext;
    readonly publicKeyShares: PublicKeyShareSet;
    readonly materialSet: BinaryChunkedPublicKeyShareMaterialSet;
    readonly transportedPublicKeyShareMaterial:
        | SetupTransportedPublicKeyShareMaterial
        | JsonRecord;
}>;

const transportedPublicKeyShareMaterialReader = (
    input: TransportedPublicKeyShareMaterialReaderInput,
): Readonly<{
    readonly reader: ChunkedBinaryReader;
    readonly shareRecords: ReadonlyMap<number, PublicKeyShareRecord>;
}> => {
    const chunks = transportedPublicKeyShareMaterialChunks(
        input.transportedPublicKeyShareMaterial,
    );
    verifyTransportedPublicKeyShareMaterialHashes(
        input.transportedPublicKeyShareMaterial,
        chunks,
    );
    const transportHashes = publicKeyShareMaterialTransportHashes(chunks);
    if (
        input.materialSet.materialEncoding !==
            publicKeyShareMaterialTransportEncoding ||
        input.materialSet.binaryFormat !== publicKeyShareMaterialBinaryFormat ||
        input.materialSet.transport.transportSchemeId !==
            setupTransportSchemeId ||
        input.materialSet.transport.chunkSizeBytes !==
            setupTransportChunkSizeBytes ||
        input.materialSet.transport.chunkCount !== chunks.length ||
        input.materialSet.transport.totalByteLength !==
            transportHashes.totalByteLength ||
        input.materialSet.transport.fullObjectHash !==
            transportHashes.fullObjectHash ||
        input.materialSet.transport.chunkRoot !== transportHashes.chunkRoot
    ) {
        throw new Error(
            'binary public-key share material set transport metadata must match the transported material object.',
        );
    }
    assertContextMatches(
        input.setupContext,
        input.materialSet,
        'publicKeyShareMaterial',
    );
    assertContextMatches(
        input.setupContext,
        input.publicKeyShares,
        'publicKeyShares',
    );
    if (
        input.materialSet.publicKeyShareSetRoot !==
        input.publicKeyShares.publicKeyShareSetRoot
    ) {
        throw new Error(
            'binary public-key share material set root binding must match publicKeyShares.',
        );
    }
    const materialSetWithoutRoot = { ...input.materialSet };
    delete (materialSetWithoutRoot as JsonRecord).publicKeyShareMaterialSetRoot;
    if (
        deriveCanonicalObjectHash(materialSetWithoutRoot) !==
        input.materialSet.publicKeyShareMaterialSetRoot
    ) {
        throw new Error(
            'binary public-key share material set root must match the canonical material set.',
        );
    }

    const reader = new ChunkedBinaryReader(chunks);
    const magic = reader.readBytes(
        publicKeyShareMaterialBinaryMagic.byteLength,
        'public-key share material magic',
    );
    if (
        magic.byteLength !== publicKeyShareMaterialBinaryMagic.byteLength ||
        magic.some(
            (byte, index) => byte !== publicKeyShareMaterialBinaryMagic[index],
        )
    ) {
        throw new Error(
            'transported public-key share material binary magic does not match.',
        );
    }
    if (reader.readVaruint('binary version') !== 1) {
        throw new Error(
            'transported public-key share material binary version is unsupported.',
        );
    }
    if (
        reader.readVaruint('participantCount') !==
        input.materialSet.participantCount
    ) {
        throw new Error(
            'transported public-key share material participant count must match material set.',
        );
    }
    if (reader.readVaruint('rnsLimbCount') !== input.materialSet.rnsLimbCount) {
        throw new Error(
            'transported public-key share material RNS limb count must match material set.',
        );
    }
    if (reader.readVaruint('ringDegree') !== input.materialSet.ringDegree) {
        throw new Error(
            'transported public-key share material ringDegree must match material set.',
        );
    }

    const shareRecords = publicKeyShareRecordsByRosterPosition({
        setupContext: input.setupContext,
        participantCount: input.materialSet.participantCount,
        publicKeyShares: input.publicKeyShares,
    });

    return { reader, shareRecords };
};

export const materialRecordsFromTransportedPublicKeyShareMaterial = (
    input: TransportedPublicKeyShareMaterialReaderInput,
): readonly PublicKeyShareMaterialRecord[] => {
    const { reader, shareRecords } =
        transportedPublicKeyShareMaterialReader(input);
    const materialRecords: PublicKeyShareMaterialRecord[] = [];
    const materialRootReferences: PublicKeyShareMaterialRootReference[] = [];
    for (
        let expectedRosterPosition = 0;
        expectedRosterPosition < input.materialSet.participantCount;
        expectedRosterPosition += 1
    ) {
        if (
            reader.readVaruint('trusteeRosterPosition') !==
            expectedRosterPosition
        ) {
            throw new Error(
                'transported public-key share material trustee order is not canonical.',
            );
        }
        const shareRecord = shareRecords.get(expectedRosterPosition);
        if (shareRecord === undefined) {
            throw new Error(
                'transported public-key share material must reference an accepted share record.',
            );
        }
        const shareCoefficientVectorsByLimb =
            shareRecord.shareCoefficientVectorHash512ByLimb.map(
                (shareCoefficientHash, rnsLimbIndex) => {
                    if (reader.readVaruint('rnsLimbIndex') !== rnsLimbIndex) {
                        throw new Error(
                            'transported public-key share material RNS limb order is not canonical.',
                        );
                    }
                    const rnsPrime = reader.readU64('rnsPrime');
                    if (
                        shareCoefficientHash.rnsLimbIndex !== rnsLimbIndex ||
                        shareCoefficientHash.rnsPrime !== rnsPrime ||
                        shareCoefficientHash.component !== 'b_i'
                    ) {
                        throw new Error(
                            'transported public-key share material limb metadata must match publicKeyShares.',
                        );
                    }
                    const coefficients = Array.from(
                        { length: input.materialSet.ringDegree },
                        () => {
                            const coefficient = reader.readU64(
                                'public-key share coefficient',
                            );
                            if (coefficient >= rnsPrime) {
                                throw new Error(
                                    'transported public-key share coefficient is not a canonical residue.',
                                );
                            }

                            return coefficient;
                        },
                    );
                    const coefficientVectorHash =
                        coefficientVectorHash512(coefficients);
                    if (
                        shareCoefficientHash.coefficientVectorHash512 !==
                        coefficientVectorHash
                    ) {
                        throw new Error(
                            'transported public-key share coefficient hash must match publicKeyShares.',
                        );
                    }

                    return {
                        rnsLimbIndex,
                        rnsPrime,
                        component: 'b_i',
                        coefficientByteLength: input.materialSet.ringDegree * 8,
                        coefficientVectorHash512: coefficientVectorHash,
                        coefficientsLeHex:
                            coefficientVectorToLittleEndianHex(coefficients),
                    } as const satisfies PublicKeyShareCoefficientVectorMaterial;
                },
            );
        const materialRecordWithoutRoot = {
            objectType: 'PublicKeyShareMaterial',
            proofFamily: publicKeyShareProofFamily,
            materialEncoding: publicKeyShareMaterialEncoding,
            ...contextFields(input.setupContext),
            trusteeIdentity: shareRecord.trusteeIdentity,
            trusteeRosterPosition: shareRecord.trusteeRosterPosition,
            rnsLimbCount: input.materialSet.rnsLimbCount,
            ringDegree: input.materialSet.ringDegree,
            publicMatrixSeedHash: input.materialSet.publicMatrixSeedHash,
            publicKeyCrpRoot: input.materialSet.publicKeyCrpRoot,
            publicAPolynomialRoot: input.materialSet.publicAPolynomialRoot,
            publicKeyShareRoot: shareRecord.publicKeyShareRoot,
            shareCoefficientVectorsByLimb,
        } as const satisfies Omit<
            PublicKeyShareMaterialRecord,
            'publicKeyShareMaterialRoot'
        >;
        const materialRecord = {
            ...materialRecordWithoutRoot,
            publicKeyShareMaterialRoot: deriveCanonicalObjectHash(
                materialRecordWithoutRoot,
            ),
        } satisfies PublicKeyShareMaterialRecord;
        materialRootReferences.push({
            trusteeIdentity: materialRecord.trusteeIdentity,
            trusteeRosterPosition: materialRecord.trusteeRosterPosition,
            publicKeyShareMaterialRoot:
                materialRecord.publicKeyShareMaterialRoot,
        });
        materialRecords.push(materialRecord);
    }
    if (!reader.isFinished()) {
        throw new Error(
            'transported public-key share material has trailing bytes.',
        );
    }
    if (
        JSON.stringify(materialRootReferences) !==
        JSON.stringify(input.materialSet.publicKeyShareMaterialRoots)
    ) {
        throw new Error(
            'transported public-key share material roots must match material set references.',
        );
    }

    return materialRecords;
};

export { transportedPublicKeyShareMaterialReader };
