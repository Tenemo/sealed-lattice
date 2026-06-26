// Binary chunked transport for VSS coefficient-commitment material: the chunk
// and manifest hashers, the streaming chunk writer and reader, the canonical
// material encoder and decoder, and the transport-set builders that bind the
// material set, the transported object, and the source-trustee commitment
// records together.
import {
    createSetupVssMaterialFullObjectHasher,
    deriveProtocolHash,
    hash512Hex,
    setupVssMaterialFullObjectHashHex,
} from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import {
    BinaryChunkWriter,
    type BinaryChunkWriterFinishResult,
} from '../binary-chunk-writer.js';
import type { CollectiveBgvSetupContext } from '../vss-share-verification-records.js';

import {
    parseSetupCommitmentValue,
    setupCommitmentFullValue,
    setupCommitmentRootPayload,
} from './commitment-values.js';
import {
    setupCommitmentModulusLimbIndices,
    setupCommitmentProfileId,
    setupCommitmentRowCount,
    setupTransportChunkSizeBytes,
    setupTransportProfileId,
    vssCoefficientCommitmentMaterialBinaryFormat,
    vssCoefficientCommitmentMaterialBinaryMagic,
    type BinaryChunkedVssCoefficientCommitmentMaterialSet,
    type BinaryChunkedVssCoefficientCommitmentMaterialTransport,
    type JsonRecord,
    type SetupCommitmentValue,
    type SetupTransportedVssCoefficientCommitmentMaterial,
    type SetupTransportedVssCoefficientCommitmentMaterialReference,
    type SetupTransportedVssCoefficientCommitmentMaterialTemplate,
    type VssCoefficientCommitmentMaterialRecord,
    type VssCoefficientCommitmentMaterialSet,
    type VssCoefficientCommitmentSet,
    type VssSourceTrusteeCoefficientCommitmentRecord,
} from './constants-and-types.js';
import {
    assertHashLike,
    assertJsonRecord,
    assertJsonRecordArray,
    bytesToHex,
    contextFields,
    hexToBytesStrict,
    positiveSafeIntegerField,
    varuintBytes,
} from './encoding.js';

export const setupTransportedVssCoefficientCommitmentMaterialTemplate =
    (input: {
        readonly chunkCount: number;
        readonly totalByteLength: number;
    }): SetupTransportedVssCoefficientCommitmentMaterialTemplate => ({
        objectType: 'SetupTransportedVssCoefficientCommitmentMaterial',
        objectVersion: 1,
        binaryFormat: vssCoefficientCommitmentMaterialBinaryFormat,
        chunkSizeBytes: setupTransportChunkSizeBytes,
        chunkCount: input.chunkCount,
        totalByteLength: input.totalByteLength,
    });

function setupVssMaterialChunkHash(
    chunkIndex: number,
    chunk: Uint8Array,
): ProtocolHash {
    return hash512Hex(
        'sealed-lattice/setup/vss-coefficient-commitment-material/chunk-v1',
        [varuintBytes(chunkIndex), chunk],
    );
}

function setupTransportChunkManifestRoot(input: {
    readonly chunkSizeBytes: number;
    readonly chunkCount: number;
    readonly totalByteLength: number;
    readonly chunkHashes: readonly ProtocolHash[];
    readonly fullObjectHash: ProtocolHash;
}): ProtocolHash {
    return deriveProtocolHash('SetupTransportChunkManifestRoot', {
        objectType: 'SetupTransportChunkManifest',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        transportProfileId: setupTransportProfileId,
        chunkSizeBytes: input.chunkSizeBytes,
        chunkCount: input.chunkCount,
        totalByteLength: input.totalByteLength,
        chunkHashes: input.chunkHashes,
        fullObjectHash: input.fullObjectHash,
    });
}

type VssBinaryChunkWriterOptions = Readonly<{
    readonly expectedTotalByteLength?: number;
    readonly retainChunks?: boolean;
    readonly consumeChunk?: (chunkIndex: number, chunk: Uint8Array) => void;
}>;

type VssBinaryChunkWriterResult = Readonly<{
    readonly transportHashes: Readonly<{
        readonly fullObjectHash: ProtocolHash;
        readonly chunkHashes: readonly ProtocolHash[];
        readonly chunkRoot: ProtocolHash;
        readonly totalByteLength: number;
    }>;
}> &
    BinaryChunkWriterFinishResult;

export const createVssBinaryChunkWriter = (
    options: VssBinaryChunkWriterOptions = {},
): Readonly<{
    readonly writer: BinaryChunkWriter;
    readonly finish: () => VssBinaryChunkWriterResult;
}> => {
    const chunkHashes: ProtocolHash[] = [];
    const fullObjectHasher =
        options.expectedTotalByteLength === undefined
            ? undefined
            : createSetupVssMaterialFullObjectHasher(
                  options.expectedTotalByteLength,
              );
    let finishResult: VssBinaryChunkWriterResult | undefined;
    const writer = new BinaryChunkWriter({
        chunkSizeBytes: setupTransportChunkSizeBytes,
        emptyErrorMessage:
            'binary VSS material transport requires at least one chunk.',
        expectedTotalByteLength: options.expectedTotalByteLength,
        retainChunks: options.retainChunks,
        consumeChunk: (chunkIndex, chunk) => {
            if (chunkIndex !== chunkHashes.length) {
                throw new Error(
                    'binary VSS material chunk indices must be contiguous.',
                );
            }
            chunkHashes.push(setupVssMaterialChunkHash(chunkIndex, chunk));
            fullObjectHasher?.update(chunk);
            options.consumeChunk?.(chunkIndex, chunk);
        },
    });

    return {
        writer,
        finish: () => {
            if (finishResult !== undefined) {
                return finishResult;
            }
            const writerResult = writer.finishWithSummary();
            if (chunkHashes.length !== writerResult.chunkCount) {
                throw new Error(
                    'binary VSS material chunk hashes must match the encoded chunk count.',
                );
            }
            if (
                fullObjectHasher === undefined &&
                writerResult.chunks.length !== writerResult.chunkCount
            ) {
                throw new Error(
                    'binary VSS material full-object hashing requires retained chunks or a streaming hasher.',
                );
            }
            const fullObjectHash =
                fullObjectHasher === undefined
                    ? setupVssMaterialFullObjectHashHex(
                          writerResult.totalByteLength,
                          writerResult.chunks,
                      )
                    : fullObjectHasher.digestHex();
            const chunkRoot = setupTransportChunkManifestRoot({
                chunkSizeBytes: setupTransportChunkSizeBytes,
                chunkCount: writerResult.chunkCount,
                totalByteLength: writerResult.totalByteLength,
                chunkHashes,
                fullObjectHash,
            });
            finishResult = {
                ...writerResult,
                transportHashes: {
                    fullObjectHash,
                    chunkHashes: chunkHashes.slice(),
                    chunkRoot,
                    totalByteLength: writerResult.totalByteLength,
                },
            };

            return finishResult;
        },
    };
};

class BinaryChunkReader {
    private chunkIndex = 0;

    private chunkOffset = 0;

    private bytesRead = 0;

    private readonly totalByteLength: number;

    public constructor(private readonly chunks: readonly Uint8Array[]) {
        if (chunks.length === 0) {
            throw new Error(
                'transported VSS material requires at least one chunk.',
            );
        }
        this.totalByteLength = chunks.reduce(
            (accumulatedLength, chunk) => accumulatedLength + chunk.byteLength,
            0,
        );
    }

    public isFinished(): boolean {
        return this.bytesRead === this.totalByteLength;
    }

    public readBytes(byteLength: number, fieldName: string): Uint8Array {
        const outputBytes = new Uint8Array(byteLength);
        let outputOffset = 0;
        while (outputOffset < byteLength) {
            const chunk = this.chunks[this.chunkIndex];
            if (chunk === undefined) {
                throw new Error(
                    `${fieldName} ended before the binary object was complete.`,
                );
            }
            const availableLength = chunk.byteLength - this.chunkOffset;
            if (availableLength === 0) {
                this.chunkIndex += 1;
                this.chunkOffset = 0;
                continue;
            }
            const copyLength = Math.min(
                byteLength - outputOffset,
                availableLength,
            );
            outputBytes.set(
                chunk.subarray(this.chunkOffset, this.chunkOffset + copyLength),
                outputOffset,
            );
            this.chunkOffset += copyLength;
            this.bytesRead += copyLength;
            outputOffset += copyLength;
        }

        return outputBytes;
    }

    // Reject non-minimal LEB128: multiple byte encodings of the same integer would let crafted chunk bytes decode identically while changing the hashed bytes, breaking the full-object and chunk-root binding.
    public readVaruint(fieldName: string): number {
        let shift = 0;
        let value = 0n;
        const consumedBytes: number[] = [];
        for (let byteIndex = 0; byteIndex < 10; byteIndex += 1) {
            const byte = this.readBytes(1, fieldName)[0];
            if (byte === undefined) {
                throw new Error(`${fieldName} varuint is malformed.`);
            }
            consumedBytes.push(byte);
            const payload = BigInt(byte & 0x7f);
            if (byteIndex === 9 && payload > 1n) {
                throw new Error(`${fieldName} varuint exceeds u64.`);
            }
            value |= payload << BigInt(shift);
            if ((byte & 0x80) === 0) {
                if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
                    throw new Error(
                        `${fieldName} varuint exceeds safe integer.`,
                    );
                }
                const numberValue = Number(value);
                const canonicalBytes = Array.from(varuintBytes(numberValue));
                if (
                    canonicalBytes.length !== consumedBytes.length ||
                    canonicalBytes.some(
                        (canonicalByte, index) =>
                            canonicalByte !== consumedBytes[index],
                    )
                ) {
                    throw new Error(
                        `${fieldName} varuint is not minimally encoded.`,
                    );
                }

                return numberValue;
            }
            shift += 7;
        }

        throw new Error(`${fieldName} varuint is too long.`);
    }

    public readU64(fieldName: string): number {
        const bytes = this.readBytes(8, fieldName);
        let value = 0n;
        for (let byteIndex = 7; byteIndex >= 0; byteIndex -= 1) {
            value = (value << 8n) | BigInt(bytes[byteIndex] ?? 0);
        }
        if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
            throw new Error(`${fieldName} exceeds safe integer.`);
        }

        return Number(value);
    }
}

const transportHashesForChunks = (
    chunks: readonly Uint8Array[],
): Readonly<{
    readonly fullObjectHash: ProtocolHash;
    readonly chunkHashes: readonly ProtocolHash[];
    readonly chunkRoot: ProtocolHash;
    readonly totalByteLength: number;
}> => {
    if (chunks.length === 0) {
        throw new Error(
            'setup transport requires at least one material chunk.',
        );
    }
    const totalByteLength = chunks.reduce(
        (accumulatedLength, chunk, chunkIndex) => {
            if (chunk.byteLength === 0) {
                throw new Error('setup transport chunks must be non-empty.');
            }
            if (chunk.byteLength > setupTransportChunkSizeBytes) {
                throw new Error(
                    'setup transport chunk exceeds the accepted chunk size.',
                );
            }
            if (
                chunkIndex + 1 < chunks.length &&
                chunk.byteLength !== setupTransportChunkSizeBytes
            ) {
                throw new Error(
                    'setup transport contains a short non-final chunk.',
                );
            }

            return accumulatedLength + chunk.byteLength;
        },
        0,
    );
    const fullObjectHash = setupVssMaterialFullObjectHashHex(
        totalByteLength,
        chunks,
    );
    const chunkHashes = chunks.map((chunk, chunkIndex) =>
        setupVssMaterialChunkHash(chunkIndex, chunk),
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

const sortedCoefficientCommitmentMaterialRecords = (
    materialSet: VssCoefficientCommitmentMaterialSet,
): readonly VssCoefficientCommitmentMaterialRecord[] => {
    const recordsByCoordinate = new Map<
        string,
        VssCoefficientCommitmentMaterialRecord
    >();
    materialSet.coefficientCommitments.forEach((materialRecord) => {
        const coordinateKey = [
            materialRecord.sourceTrusteeRosterPosition,
            materialRecord.rnsLimbIndex,
            materialRecord.shamirCoefficientIndex,
        ].join(':');
        if (recordsByCoordinate.has(coordinateKey)) {
            throw new Error(
                'vssCoefficientCommitmentMaterial must not contain duplicate coordinate records.',
            );
        }
        recordsByCoordinate.set(coordinateKey, materialRecord);
    });

    const sortedRecords: VssCoefficientCommitmentMaterialRecord[] = [];
    for (
        let sourceTrusteeRosterPosition = 0;
        sourceTrusteeRosterPosition < materialSet.participantCount;
        sourceTrusteeRosterPosition += 1
    ) {
        for (
            let rnsLimbIndex = 0;
            rnsLimbIndex < materialSet.rnsLimbCount;
            rnsLimbIndex += 1
        ) {
            for (
                let shamirCoefficientIndex = 0;
                shamirCoefficientIndex < materialSet.thresholdDegree;
                shamirCoefficientIndex += 1
            ) {
                const materialRecord = recordsByCoordinate.get(
                    [
                        sourceTrusteeRosterPosition,
                        rnsLimbIndex,
                        shamirCoefficientIndex,
                    ].join(':'),
                );
                if (materialRecord === undefined) {
                    throw new Error(
                        'vssCoefficientCommitmentMaterial must cover every source trustee, RNS limb, and Shamir coefficient.',
                    );
                }
                sortedRecords.push(materialRecord);
            }
        }
    }
    if (sortedRecords.length !== materialSet.materialRecordCount) {
        throw new Error(
            'vssCoefficientCommitmentMaterial.materialRecordCount must match the encoded records.',
        );
    }

    return sortedRecords;
};

export const writeSetupCommitment = (
    writer: BinaryChunkWriter,
    materialRecord: VssCoefficientCommitmentMaterialRecord,
): void => {
    const commitment = parseSetupCommitmentValue(
        materialRecord.commitment,
        'vssCoefficientCommitmentMaterial.coefficientCommitments.commitment',
    );
    const commitmentRoot = deriveProtocolHash(
        'SetupCommitmentRoot',
        setupCommitmentRootPayload(commitment),
    );
    if (commitmentRoot !== materialRecord.commitmentRoot) {
        throw new Error(
            'VSS coefficient commitment material record root must match the encoded setup commitment.',
        );
    }
    if (
        commitment.sourceRnsLimbIndex !== materialRecord.rnsLimbIndex ||
        commitment.sourceMessageModulus !== materialRecord.rnsPrime ||
        commitment.shamirCoefficientIndex !==
            materialRecord.shamirCoefficientIndex
    ) {
        throw new Error(
            'VSS coefficient commitment material coordinate must match the encoded setup commitment.',
        );
    }
    writer.writeVaruint(materialRecord.sourceTrusteeRosterPosition);
    writer.writeVaruint(materialRecord.rnsLimbIndex);
    writer.writeVaruint(materialRecord.shamirCoefficientIndex);
    for (const commitmentModulusIndex of setupCommitmentModulusLimbIndices) {
        const commitmentLimb = commitment.commitmentLimbs.find(
            (candidateLimb) =>
                candidateLimb.commitmentModulusIndex === commitmentModulusIndex,
        );
        if (commitmentLimb === undefined) {
            throw new Error(
                'setup commitment must include every commitment modulus limb.',
            );
        }
        writer.writeVaruint(commitmentModulusIndex);
        writer.writeU64LittleEndian(
            commitmentLimb.modulus,
            'setup commitment modulus limb',
        );
        if (commitmentLimb.rows.length !== setupCommitmentRowCount) {
            throw new Error(
                'setup commitment must include the accepted row count.',
            );
        }
        commitmentLimb.rows.forEach((row, rowIndex) => {
            if (row.length !== commitment.ringDegree) {
                throw new Error(
                    `setup commitment row ${String(rowIndex)} length must match ringDegree.`,
                );
            }
            row.forEach((coefficient) =>
                writer.writeU64LittleEndian(
                    coefficient,
                    'setup commitment coefficient',
                ),
            );
        });
    }
};

export const writeVssCoefficientCommitmentMaterialHeader = (
    writer: BinaryChunkWriter,
    input: Readonly<{
        readonly participantCount: number;
        readonly thresholdDegree: number;
        readonly rnsLimbCount: number;
        readonly ringDegree: number;
    }>,
): void => {
    writer.writeBytes(vssCoefficientCommitmentMaterialBinaryMagic);
    writer.writeVaruint(1);
    writer.writeVaruint(input.participantCount);
    writer.writeVaruint(input.thresholdDegree);
    writer.writeVaruint(input.rnsLimbCount);
    writer.writeVaruint(input.ringDegree);
    writer.writeVaruint(setupCommitmentModulusLimbIndices.length);
    writer.writeVaruint(setupCommitmentRowCount);
};

const encodeVssCoefficientCommitmentMaterial = (
    materialSet: VssCoefficientCommitmentMaterialSet,
): readonly Uint8Array[] => {
    const vssBinaryChunkWriter = createVssBinaryChunkWriter();
    const writer = vssBinaryChunkWriter.writer;
    writeVssCoefficientCommitmentMaterialHeader(writer, materialSet);
    sortedCoefficientCommitmentMaterialRecords(materialSet).forEach(
        (materialRecord) => writeSetupCommitment(writer, materialRecord),
    );

    return vssBinaryChunkWriter.finish().chunks;
};

export const buildBinaryVssCoefficientCommitmentMaterialSet = (
    input: Readonly<{
        readonly setupContext: CollectiveBgvSetupContext;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly vssCoefficientCommitmentRoot: ProtocolHash;
        readonly participantCount: number;
        readonly thresholdDegree: number;
        readonly rnsLimbCount: number;
        readonly ringDegree: number;
        readonly materialRecordCount: number;
        readonly transportHashes: Readonly<{
            readonly fullObjectHash: ProtocolHash;
            readonly chunkRoot: ProtocolHash;
            readonly totalByteLength: number;
        }>;
        readonly chunkCount: number;
    }>,
): BinaryChunkedVssCoefficientCommitmentMaterialSet => {
    const commitmentProfileHash = input.setupContext.commitmentProfileHash;
    assertHashLike(commitmentProfileHash, 'setupContext.commitmentProfileHash');
    const materialSetWithoutRoot = {
        objectType: 'VssCoefficientCommitmentMaterialSet',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        ...contextFields(input.setupContext),
        commitmentProfileId: setupCommitmentProfileId,
        commitmentProfileHash,
        materialEncoding: 'binary-chunked-full-public-setup-commitment-values',
        binaryFormat: vssCoefficientCommitmentMaterialBinaryFormat,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        vssCoefficientCommitmentRoot: input.vssCoefficientCommitmentRoot,
        participantCount: input.participantCount,
        thresholdDegree: input.thresholdDegree,
        rnsLimbCount: input.rnsLimbCount,
        ringDegree: input.ringDegree,
        materialRecordCount: input.materialRecordCount,
        transport: {
            transportProfileId: setupTransportProfileId,
            chunkSizeBytes: setupTransportChunkSizeBytes,
            chunkCount: input.chunkCount,
            totalByteLength: input.transportHashes.totalByteLength,
            fullObjectHash: input.transportHashes.fullObjectHash,
            chunkRoot: input.transportHashes.chunkRoot,
        },
    } as const satisfies Omit<
        BinaryChunkedVssCoefficientCommitmentMaterialSet,
        'vssCoefficientCommitmentMaterialRoot'
    >;

    return {
        ...materialSetWithoutRoot,
        vssCoefficientCommitmentMaterialRoot: deriveProtocolHash(
            'VssCoefficientCommitmentMaterialRoot',
            materialSetWithoutRoot,
        ),
    } satisfies BinaryChunkedVssCoefficientCommitmentMaterialSet;
};

export const transportedVssCoefficientCommitmentMaterialFromChunks = (
    chunks: readonly Uint8Array[],
): SetupTransportedVssCoefficientCommitmentMaterial => {
    const transportHashes = transportHashesForChunks(chunks);

    return {
        objectType: 'SetupTransportedVssCoefficientCommitmentMaterial',
        objectVersion: 1,
        binaryFormat: vssCoefficientCommitmentMaterialBinaryFormat,
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

export const transportedVssCoefficientCommitmentMaterialReferenceFromWriterResult =
    (
        writerResult: VssBinaryChunkWriterResult,
    ): SetupTransportedVssCoefficientCommitmentMaterialReference => ({
        objectType: 'SetupTransportedVssCoefficientCommitmentMaterial',
        objectVersion: 1,
        binaryFormat: vssCoefficientCommitmentMaterialBinaryFormat,
        chunkSizeBytes: setupTransportChunkSizeBytes,
        chunkCount: writerResult.chunkCount,
        totalByteLength: writerResult.totalByteLength,
        fullObjectHash: writerResult.transportHashes.fullObjectHash,
        chunkHashes: writerResult.transportHashes.chunkHashes,
        chunkRoot: writerResult.transportHashes.chunkRoot,
    });

export const createBinaryChunkedVssCoefficientCommitmentMaterialTransport = (
    materialSet: VssCoefficientCommitmentMaterialSet,
): BinaryChunkedVssCoefficientCommitmentMaterialTransport => {
    if (
        materialSet.materialEncoding !== 'full-public-setup-commitment-values'
    ) {
        throw new Error(
            'binary VSS material transport must be built from embedded full public values.',
        );
    }
    const chunks = encodeVssCoefficientCommitmentMaterial(materialSet);
    const transportedMaterial =
        transportedVssCoefficientCommitmentMaterialFromChunks(chunks);
    const binaryMaterialSet = buildBinaryVssCoefficientCommitmentMaterialSet({
        setupContext: materialSet as unknown as CollectiveBgvSetupContext,
        publicMatrixSeedHash: materialSet.publicMatrixSeedHash,
        vssCoefficientCommitmentRoot: materialSet.vssCoefficientCommitmentRoot,
        participantCount: materialSet.participantCount,
        thresholdDegree: materialSet.thresholdDegree,
        rnsLimbCount: materialSet.rnsLimbCount,
        ringDegree: materialSet.ringDegree,
        materialRecordCount: materialSet.materialRecordCount,
        transportHashes: {
            fullObjectHash: transportedMaterial.fullObjectHash,
            chunkRoot: transportedMaterial.chunkRoot,
            totalByteLength: transportedMaterial.totalByteLength,
        },
        chunkCount: transportedMaterial.chunkCount,
    });

    return {
        materialSet: binaryMaterialSet,
        transportedVssCoefficientCommitmentMaterial: transportedMaterial,
    };
};

const transportChunksFromObject = (
    transportedMaterial:
        | SetupTransportedVssCoefficientCommitmentMaterial
        | JsonRecord,
): readonly Uint8Array[] => {
    const materialObject = assertJsonRecord(
        transportedMaterial,
        'transportedVssCoefficientCommitmentMaterial',
    );
    if (
        materialObject.objectType !==
        'SetupTransportedVssCoefficientCommitmentMaterial'
    ) {
        throw new Error(
            'transportedVssCoefficientCommitmentMaterial.objectType must be SetupTransportedVssCoefficientCommitmentMaterial.',
        );
    }
    if (materialObject.objectVersion !== 1) {
        throw new Error(
            'transportedVssCoefficientCommitmentMaterial.objectVersion must be 1.',
        );
    }
    if (
        materialObject.binaryFormat !==
        vssCoefficientCommitmentMaterialBinaryFormat
    ) {
        throw new Error(
            'transported VSS coefficient material must use the accepted binary format.',
        );
    }
    if (materialObject.chunkSizeBytes !== setupTransportChunkSizeBytes) {
        throw new Error(
            'transported VSS coefficient material must use the accepted 1 MiB setup chunk size.',
        );
    }
    const chunkCount = positiveSafeIntegerField(
        materialObject.chunkCount,
        'transportedVssCoefficientCommitmentMaterial.chunkCount',
    );
    const chunkHashes = assertJsonRecordArray(
        (materialObject as SetupTransportedVssCoefficientCommitmentMaterial)
            .chunks,
        'transportedVssCoefficientCommitmentMaterial.chunks',
    );
    if (chunkHashes.length !== chunkCount) {
        throw new Error('transport chunks length must match chunkCount.');
    }

    return chunkHashes.map((chunk, expectedChunkIndex) => {
        if (chunk.chunkIndex !== expectedChunkIndex) {
            throw new Error(
                'transport chunks must be supplied in ascending chunk-index order.',
            );
        }

        return hexToBytesStrict(
            String(chunk.bytesHex),
            `transportedVssCoefficientCommitmentMaterial.chunks.${String(expectedChunkIndex)}.bytesHex`,
        );
    });
};

const verifyTransportObjectHashes = (
    transportedMaterial:
        | SetupTransportedVssCoefficientCommitmentMaterial
        | JsonRecord,
    chunks: readonly Uint8Array[],
): void => {
    const materialObject = assertJsonRecord(
        transportedMaterial,
        'transportedVssCoefficientCommitmentMaterial',
    );
    const hashes = transportHashesForChunks(chunks);
    if (materialObject.totalByteLength !== hashes.totalByteLength) {
        throw new Error(
            'transport totalByteLength must match supplied chunk bytes.',
        );
    }
    if (materialObject.fullObjectHash !== hashes.fullObjectHash) {
        throw new Error(
            'transport fullObjectHash does not match supplied chunk bytes.',
        );
    }
    if (materialObject.chunkRoot !== hashes.chunkRoot) {
        throw new Error(
            'transport chunkRoot does not match the canonical chunk manifest.',
        );
    }
    const observedChunkHashes = materialObject.chunkHashes;
    if (!Array.isArray(observedChunkHashes)) {
        throw new TypeError('transport chunkHashes must be an array.');
    }
    if (observedChunkHashes.length !== hashes.chunkHashes.length) {
        throw new Error('transport chunkHashes length must match chunkCount.');
    }
    hashes.chunkHashes.forEach((chunkHash, chunkIndex) => {
        if (observedChunkHashes[chunkIndex] !== chunkHash) {
            throw new Error(
                'transport chunkHashes do not match supplied chunk bytes.',
            );
        }
    });
};

const readTransportedSetupCommitment = (
    reader: BinaryChunkReader,
    expectedSourceTrusteeRosterPosition: number,
    expectedRnsLimbIndex: number,
    expectedRnsPrime: number,
    expectedShamirCoefficientIndex: number,
    expectedRingDegree: number,
    expectedCommitmentModuli: readonly number[],
): SetupCommitmentValue => {
    if (
        reader.readVaruint('sourceTrusteeRosterPosition') !==
        expectedSourceTrusteeRosterPosition
    ) {
        throw new Error(
            'transported VSS material source trustee order is not canonical.',
        );
    }
    if (reader.readVaruint('rnsLimbIndex') !== expectedRnsLimbIndex) {
        throw new Error(
            'transported VSS material RNS limb order is not canonical.',
        );
    }
    if (
        reader.readVaruint('shamirCoefficientIndex') !==
        expectedShamirCoefficientIndex
    ) {
        throw new Error(
            'transported VSS material Shamir coefficient order is not canonical.',
        );
    }
    const commitmentLimbs = setupCommitmentModulusLimbIndices.map(
        (expectedCommitmentModulusIndex) => {
            if (
                reader.readVaruint('commitmentModulusIndex') !==
                expectedCommitmentModulusIndex
            ) {
                throw new Error(
                    'transported commitment modulus limb order is not canonical.',
                );
            }
            const modulus = reader.readU64('commitment modulus');
            if (
                expectedCommitmentModuli[expectedCommitmentModulusIndex] !==
                modulus
            ) {
                throw new Error(
                    'transported commitment modulus does not match the commitment profile.',
                );
            }
            const rows = Array.from({ length: setupCommitmentRowCount }, () =>
                Array.from({ length: expectedRingDegree }, () => {
                    const coefficient = reader.readU64(
                        'commitment coefficient',
                    );
                    if (coefficient >= modulus) {
                        throw new Error(
                            'transported commitment coefficient is not canonical modulo its limb.',
                        );
                    }

                    return coefficient;
                }),
            );

            return {
                commitmentModulusIndex: expectedCommitmentModulusIndex,
                modulus,
                rows,
            };
        },
    );

    return {
        sourceRnsLimbIndex: expectedRnsLimbIndex,
        sourceMessageModulus: expectedRnsPrime,
        shamirCoefficientIndex: expectedShamirCoefficientIndex,
        ringDegree: expectedRingDegree,
        commitmentLimbs,
    };
};

const sortedSourceTrusteeCommitmentRecords = (
    vssCoefficientCommitments: VssCoefficientCommitmentSet,
): readonly VssSourceTrusteeCoefficientCommitmentRecord[] => {
    const sourceTrusteeRecords = [
        ...vssCoefficientCommitments.sourceTrusteeRecords,
    ].sort(
        (left, right) =>
            left.sourceTrusteeRosterPosition -
            right.sourceTrusteeRosterPosition,
    );
    sourceTrusteeRecords.forEach((sourceTrusteeRecord, expectedPosition) => {
        if (
            sourceTrusteeRecord.sourceTrusteeRosterPosition !== expectedPosition
        ) {
            throw new Error(
                'vssCoefficientCommitments source trustee records must be in contiguous roster order.',
            );
        }
    });

    return sourceTrusteeRecords;
};

export const materialRecordsFromTransportedVssCoefficientCommitmentMaterial = (
    input: Readonly<{
        readonly setupContext: CollectiveBgvSetupContext;
        readonly vssCoefficientCommitments: VssCoefficientCommitmentSet;
        readonly materialSet: BinaryChunkedVssCoefficientCommitmentMaterialSet;
        readonly transportedVssCoefficientCommitmentMaterial:
            | SetupTransportedVssCoefficientCommitmentMaterial
            | JsonRecord;
    }>,
): readonly VssCoefficientCommitmentMaterialRecord[] => {
    const chunks = transportChunksFromObject(
        input.transportedVssCoefficientCommitmentMaterial,
    );
    verifyTransportObjectHashes(
        input.transportedVssCoefficientCommitmentMaterial,
        chunks,
    );
    const materialTransport = input.materialSet.transport;
    const transportedMaterial = assertJsonRecord(
        input.transportedVssCoefficientCommitmentMaterial,
        'transportedVssCoefficientCommitmentMaterial',
    );
    if (
        materialTransport.fullObjectHash !==
            transportedMaterial.fullObjectHash ||
        materialTransport.chunkRoot !== transportedMaterial.chunkRoot ||
        materialTransport.chunkCount !== transportedMaterial.chunkCount ||
        materialTransport.totalByteLength !==
            transportedMaterial.totalByteLength
    ) {
        throw new Error(
            'binary VSS material set transport metadata must match the transported material object.',
        );
    }
    if (
        input.materialSet.vssCoefficientCommitmentRoot !==
        input.vssCoefficientCommitments.vssCoefficientCommitmentRoot
    ) {
        throw new Error(
            'binary VSS material set root binding must match VSS coefficient commitments.',
        );
    }
    const materialRootWithoutRoot = { ...input.materialSet };
    delete (materialRootWithoutRoot as JsonRecord)
        .vssCoefficientCommitmentMaterialRoot;
    if (
        deriveProtocolHash(
            'VssCoefficientCommitmentMaterialRoot',
            materialRootWithoutRoot,
        ) !== input.materialSet.vssCoefficientCommitmentMaterialRoot
    ) {
        throw new Error(
            'binary VSS material set root must match the canonical material set.',
        );
    }

    const sourceTrusteeRecords = sortedSourceTrusteeCommitmentRecords(
        input.vssCoefficientCommitments,
    );
    if (sourceTrusteeRecords.length !== input.materialSet.participantCount) {
        throw new Error(
            'binary VSS material participant count must match VSS coefficient commitments.',
        );
    }
    const reader = new BinaryChunkReader(chunks);
    const expectedCommitmentModuli = setupCommitmentModulusLimbIndices.map(
        (commitmentModulusIndex) => {
            const firstSourceTrusteeRecord = sourceTrusteeRecords[0];
            const coefficientRecord =
                firstSourceTrusteeRecord?.coefficientCommitments.find(
                    (candidateRecord) =>
                        candidateRecord.rnsLimbIndex === commitmentModulusIndex,
                );
            if (coefficientRecord === undefined) {
                throw new Error(
                    'VSS coefficient commitments must expose every commitment modulus limb.',
                );
            }

            return coefficientRecord.rnsPrime;
        },
    );
    const magic = reader.readBytes(8, 'transported VSS material magic');
    if (new TextDecoder().decode(magic) !== 'SLVSSMAT') {
        throw new Error(
            'transported VSS material binary magic does not match.',
        );
    }
    if (reader.readVaruint('binary version') !== 1) {
        throw new Error(
            'transported VSS material binary version is unsupported.',
        );
    }
    if (
        reader.readVaruint('participantCount') !==
        input.materialSet.participantCount
    ) {
        throw new Error(
            'transported VSS material participant count does not match the material set.',
        );
    }
    if (
        reader.readVaruint('thresholdDegree') !==
        input.materialSet.thresholdDegree
    ) {
        throw new Error(
            'transported VSS material threshold degree does not match the material set.',
        );
    }
    if (reader.readVaruint('rnsLimbCount') !== input.materialSet.rnsLimbCount) {
        throw new Error(
            'transported VSS material RNS limb count does not match the material set.',
        );
    }
    if (reader.readVaruint('ringDegree') !== input.materialSet.ringDegree) {
        throw new Error(
            'transported VSS material ring degree does not match the material set.',
        );
    }
    if (
        reader.readVaruint('commitmentLimbCount') !==
        setupCommitmentModulusLimbIndices.length
    ) {
        throw new Error(
            'transported VSS material commitment limb count does not match the commitment profile.',
        );
    }
    if (reader.readVaruint('rowCount') !== setupCommitmentRowCount) {
        throw new Error(
            'transported VSS material row count does not match the commitment profile.',
        );
    }

    const materialRecords: VssCoefficientCommitmentMaterialRecord[] = [];
    for (
        let sourceTrusteeRosterPosition = 0;
        sourceTrusteeRosterPosition < input.materialSet.participantCount;
        sourceTrusteeRosterPosition += 1
    ) {
        const sourceTrusteeRecord =
            sourceTrusteeRecords[sourceTrusteeRosterPosition];
        if (sourceTrusteeRecord === undefined) {
            throw new Error(
                'transport material is missing a source trustee binding.',
            );
        }
        for (
            let rnsLimbIndex = 0;
            rnsLimbIndex < input.materialSet.rnsLimbCount;
            rnsLimbIndex += 1
        ) {
            const coefficientRecordForLimb =
                sourceTrusteeRecord.coefficientCommitments.find(
                    (candidateRecord) =>
                        candidateRecord.rnsLimbIndex === rnsLimbIndex,
                );
            if (coefficientRecordForLimb === undefined) {
                throw new Error(
                    'source trustee record is missing an RNS limb commitment.',
                );
            }
            for (
                let shamirCoefficientIndex = 0;
                shamirCoefficientIndex < input.materialSet.thresholdDegree;
                shamirCoefficientIndex += 1
            ) {
                const commitment = readTransportedSetupCommitment(
                    reader,
                    sourceTrusteeRosterPosition,
                    rnsLimbIndex,
                    coefficientRecordForLimb.rnsPrime,
                    shamirCoefficientIndex,
                    input.materialSet.ringDegree,
                    expectedCommitmentModuli,
                );
                const commitmentRoot = deriveProtocolHash(
                    'SetupCommitmentRoot',
                    setupCommitmentRootPayload(commitment),
                );
                const expectedCommitmentRecord =
                    sourceTrusteeRecord.coefficientCommitments.find(
                        (candidateRecord) =>
                            candidateRecord.rnsLimbIndex === rnsLimbIndex &&
                            candidateRecord.shamirCoefficientIndex ===
                                shamirCoefficientIndex,
                    );
                if (expectedCommitmentRecord === undefined) {
                    throw new Error(
                        'transport material coordinate is absent from the source trustee record.',
                    );
                }
                if (
                    expectedCommitmentRecord.commitmentRoot !== commitmentRoot
                ) {
                    throw new Error(
                        'transported setup commitment material does not match the source trustee commitment root.',
                    );
                }
                materialRecords.push({
                    objectType: 'VssCoefficientCommitmentMaterial',
                    objectVersion: 1,
                    ...contextFields(input.setupContext),
                    sourceTrusteeIdentity:
                        sourceTrusteeRecord.sourceTrusteeIdentity,
                    sourceTrusteeRosterPosition,
                    publicMatrixSeedHash:
                        input.materialSet.publicMatrixSeedHash,
                    rnsLimbIndex,
                    rnsPrime: expectedCommitmentRecord.rnsPrime,
                    shamirCoefficientIndex,
                    commitmentRoot,
                    commitment: setupCommitmentFullValue(commitment),
                });
            }
        }
    }
    if (!reader.isFinished()) {
        throw new Error(
            'transported VSS material has trailing bytes after the final commitment record.',
        );
    }
    if (materialRecords.length !== input.materialSet.materialRecordCount) {
        throw new Error(
            'transported VSS material record count must match the material set.',
        );
    }

    return materialRecords;
};
