import {
    deriveProtocolHash,
    hash512Hex,
    setupProofMaterialFullObjectHashHex,
} from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

type JsonRecord = Record<string, unknown>;

const setupProfileId = 'CollectiveBgvSetup-v1';
const setupProofProfileId = 'SealedLattice-LNP-SetupProof-v1';
const setupProofMaterialTransportEncoding = 'binary-chunked-proof-bytes';
export const setupProofTransportChunkSizeBytes = 1_048_576;

const textEncoder = new TextEncoder();

const protocolHashPattern = /^[0-9a-f]{128}$/u;
const lowercaseHexPattern = /^(?:[0-9a-f]{2})*$/u;
const decimalStringPattern = /^(?:0|[1-9][0-9]*)$/u;

export type SetupProofChallenge = number | string;

export type SetupProofTboxZ34Metadata = Readonly<{
    readonly z34SeedMaterialHash: ProtocolHash;
    readonly z34ChallengeSeedHash: ProtocolHash;
    readonly z34ChallengeTailHash: ProtocolHash;
    readonly z34ChallengeRowDomainHash: ProtocolHash;
    readonly z34ChallengeZ3RowSetHash: ProtocolHash;
    readonly z34ChallengeZ4RowSetHash: ProtocolHash;
    readonly tboxLowerProtocolChallengeHash: ProtocolHash;
    readonly z34Z3CheckWindowHash: ProtocolHash;
    readonly z34Z4CheckWindowHash: ProtocolHash;
    readonly z34Z3L2SquaredDecimal: string;
    readonly z34Z4InfinityNormDecimal: string;
}>;

const setupProofTboxZ34HashFieldNames = [
    'z34SeedMaterialHash',
    'z34ChallengeSeedHash',
    'z34ChallengeTailHash',
    'z34ChallengeRowDomainHash',
    'z34ChallengeZ3RowSetHash',
    'z34ChallengeZ4RowSetHash',
    'tboxLowerProtocolChallengeHash',
    'z34Z3CheckWindowHash',
    'z34Z4CheckWindowHash',
] as const;

const setupProofTboxZ34DecimalFieldNames = [
    'z34Z3L2SquaredDecimal',
    'z34Z4InfinityNormDecimal',
] as const;

const assertProtocolHash = (
    value: unknown,
    fieldName: string,
): ProtocolHash => {
    if (typeof value !== 'string' || !protocolHashPattern.test(value)) {
        throw new TypeError(`${fieldName} must be a protocol hash.`);
    }

    return value;
};

const assertNonEmptyString = (value: unknown, fieldName: string): string => {
    if (typeof value !== 'string' || value.length === 0) {
        throw new TypeError(`${fieldName} must be non-empty.`);
    }

    return value;
};

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

export const assertSetupProofChallenge = (
    value: unknown,
    fieldName: string,
): SetupProofChallenge => {
    if (typeof value === 'number') {
        return assertNonNegativeSafeInteger(value, fieldName);
    }
    if (typeof value === 'string' && decimalStringPattern.test(value)) {
        return value;
    }

    throw new TypeError(
        `${fieldName} must be a non-negative safe integer or canonical decimal string.`,
    );
};

const assertPositiveSafeInteger = (
    value: unknown,
    fieldName: string,
): number => {
    if (
        typeof value !== 'number' ||
        !Number.isSafeInteger(value) ||
        value <= 0
    ) {
        throw new TypeError(`${fieldName} must be a positive safe integer.`);
    }

    return value;
};

const assertDecimalString = (value: unknown, fieldName: string): string => {
    if (typeof value !== 'string' || !decimalStringPattern.test(value)) {
        throw new TypeError(`${fieldName} must be a canonical decimal string.`);
    }

    return value;
};

const hexToBytes = (hex: string, fieldName: string): Uint8Array => {
    if (!lowercaseHexPattern.test(hex)) {
        throw new TypeError(`${fieldName} must be lowercase hex bytes.`);
    }
    const bytes = new Uint8Array(hex.length / 2);
    for (let offset = 0; offset < hex.length; offset += 2) {
        bytes[offset / 2] = Number.parseInt(hex.slice(offset, offset + 2), 16);
    }

    return bytes;
};

const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

export const optionalSetupProofTboxZ34Metadata = (
    value: Readonly<Record<string, unknown>>,
    fieldName: string,
): Partial<SetupProofTboxZ34Metadata> => {
    const metadata: Record<string, string> = {};
    let metadataFieldCount = 0;
    for (const hashFieldName of setupProofTboxZ34HashFieldNames) {
        const fieldValue = value[hashFieldName];
        if (fieldValue !== undefined) {
            metadataFieldCount += 1;
            metadata[hashFieldName] = assertProtocolHash(
                fieldValue,
                `${fieldName}.${hashFieldName}`,
            );
        }
    }
    for (const decimalFieldName of setupProofTboxZ34DecimalFieldNames) {
        const fieldValue = value[decimalFieldName];
        if (fieldValue !== undefined) {
            metadataFieldCount += 1;
            metadata[decimalFieldName] = assertDecimalString(
                fieldValue,
                `${fieldName}.${decimalFieldName}`,
            );
        }
    }
    if (
        metadataFieldCount > 0 &&
        metadataFieldCount !==
            setupProofTboxZ34HashFieldNames.length +
                setupProofTboxZ34DecimalFieldNames.length
    ) {
        throw new TypeError(
            `${fieldName} must provide all z34/tbox metadata fields when any are supplied.`,
        );
    }

    return metadata;
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

const setupProofMaterialChunkHash = (
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

const setupProofChunkManifestRoot = (
    proofFamily: string,
    chunkHashes: readonly ProtocolHash[],
    fullObjectHash: ProtocolHash,
    totalByteLength: number,
): ProtocolHash =>
    deriveProtocolHash('SetupProofChunkManifestRoot', {
        objectType: 'SetupProofMaterialChunkManifest',
        objectVersion: 1,
        setupProofProfileId,
        proofFamily,
        chunkSizeBytes: setupProofTransportChunkSizeBytes,
        chunkCount: chunkHashes.length,
        totalByteLength,
        chunkHashes,
        fullObjectHash,
    });

type SetupProofMaterialTransportOptions<
    TransportedSetObjectType extends string = string,
> = Readonly<{
    readonly proofFamily: string;
    readonly proofBytesHashDomain: string;
    readonly transportedSetObjectType: TransportedSetObjectType;
    readonly transportedObjectType: string;
    readonly transportedObjectHashFieldPrefix?: 'plain' | 'proof';
}>;

export type TransportedSetupProofMaterialSet<
    ObjectType extends string = string,
> = Readonly<
    JsonRecord & {
        readonly objectType: ObjectType;
        readonly objectVersion: 1;
        readonly setupProfileId: typeof setupProfileId;
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: string;
        readonly proofMaterials: readonly JsonRecord[];
    }
>;

type SetupProofMaterialTransportResult<
    ProofMaterial extends object,
    TransportedSetObjectType extends string = string,
> = Readonly<{
    readonly proofMaterials: readonly ProofMaterial[];
    readonly transportedProofMaterial: TransportedSetupProofMaterialSet<TransportedSetObjectType>;
}>;

export const transportSetupProofMaterials = <
    ProofMaterial extends object,
    TransportedSetObjectType extends string,
>(
    proofMaterials: readonly ProofMaterial[],
    options: SetupProofMaterialTransportOptions<TransportedSetObjectType>,
): SetupProofMaterialTransportResult<
    ProofMaterial,
    TransportedSetObjectType
> => {
    const transportedProofMaterials: JsonRecord[] = [];
    const transportedRecords = proofMaterials.map(
        (proofMaterial, proofIndex) => {
            const proofMaterialRecord = proofMaterial as JsonRecord;
            const proofBytesHex = assertNonEmptyString(
                proofMaterialRecord.proofBytesHex,
                `proofMaterials.${String(proofIndex)}.proofBytesHex`,
            );
            const proofBytes = hexToBytes(
                proofBytesHex,
                `proofMaterials.${String(proofIndex)}.proofBytesHex`,
            );
            const proofSizeBytes = assertPositiveSafeInteger(
                proofMaterialRecord.proofSizeBytes,
                `proofMaterials.${String(proofIndex)}.proofSizeBytes`,
            );
            if (proofSizeBytes !== proofBytes.byteLength) {
                throw new Error(
                    `proofMaterials.${String(proofIndex)}.proofSizeBytes must match proofBytesHex.`,
                );
            }
            const proofBytesHash = assertProtocolHash(
                proofMaterialRecord.proofBytesHash,
                `proofMaterials.${String(proofIndex)}.proofBytesHash`,
            );
            const expectedProofBytesHash = hash512Hex(
                options.proofBytesHashDomain,
                [proofBytes],
            );
            if (proofBytesHash !== expectedProofBytesHash) {
                throw new Error(
                    `proofMaterials.${String(proofIndex)}.proofBytesHash must match proofBytesHex before transport.`,
                );
            }
            const chunks = splitProofBytesIntoChunks(proofBytes);
            if (chunks.length === 0) {
                throw new Error(
                    `proofMaterials.${String(proofIndex)}.proofBytesHex must produce at least one transported chunk.`,
                );
            }
            const totalByteLength = chunks.reduce(
                (accumulatedLength, chunk) =>
                    accumulatedLength + chunk.byteLength,
                0,
            );
            const fullObjectHash = setupProofMaterialFullObjectHashHex(
                options.proofFamily,
                totalByteLength,
                chunks,
            );
            const chunkHashes = chunks.map((chunk, chunkIndex) =>
                setupProofMaterialChunkHash(
                    options.proofFamily,
                    fullObjectHash,
                    chunkIndex,
                    chunk,
                ),
            );
            const chunkRoot = setupProofChunkManifestRoot(
                options.proofFamily,
                chunkHashes,
                fullObjectHash,
                totalByteLength,
            );
            const trusteeIdentity = assertNonEmptyString(
                proofMaterialRecord.trusteeIdentity,
                `proofMaterials.${String(proofIndex)}.trusteeIdentity`,
            );
            const trusteeRosterPosition = assertNonNegativeSafeInteger(
                proofMaterialRecord.trusteeRosterPosition,
                `proofMaterials.${String(proofIndex)}.trusteeRosterPosition`,
            );
            const statementHash = assertProtocolHash(
                proofMaterialRecord.statementHash,
                `proofMaterials.${String(proofIndex)}.statementHash`,
            );
            const relationCommitmentHash = assertProtocolHash(
                proofMaterialRecord.relationCommitmentHash,
                `proofMaterials.${String(proofIndex)}.relationCommitmentHash`,
            );
            const tboxCommitmentPrefixHash = assertProtocolHash(
                proofMaterialRecord.tboxCommitmentPrefixHash,
                `proofMaterials.${String(proofIndex)}.tboxCommitmentPrefixHash`,
            );
            const proofMaterialRoot = deriveProtocolHash(
                'SetupProofMaterialRoot',
                {
                    objectType: 'SetupProofMaterialReference',
                    objectVersion: 1,
                    setupProfileId,
                    setupProofProfileId,
                    proofFamily: options.proofFamily,
                    proofBytesEncoding: setupProofMaterialTransportEncoding,
                    trusteeIdentity,
                    trusteeRosterPosition,
                    statementHash,
                    relationCommitmentHash,
                    tboxCommitmentPrefixHash,
                    proofSizeBytes,
                    proofBytesHash,
                    chunkSizeBytes: setupProofTransportChunkSizeBytes,
                    chunkCount: chunkHashes.length,
                    totalByteLength,
                    fullObjectHash,
                    chunkRoot,
                    chunkHashes,
                },
            );
            const transportedProofRecord = {
                ...proofMaterialRecord,
                proofBytesEncoding: setupProofMaterialTransportEncoding,
                proofMaterialRoot,
                proofChunkSizeBytes: setupProofTransportChunkSizeBytes,
                proofChunkCount: chunkHashes.length,
                proofTotalByteLength: totalByteLength,
                proofFullObjectHash: fullObjectHash,
                proofChunkRoot: chunkRoot,
                proofChunkHashes: chunkHashes,
            } as JsonRecord;
            delete transportedProofRecord.proofBytesHex;
            const transportedHashFields =
                options.transportedObjectHashFieldPrefix === 'proof'
                    ? {
                          proofChunkSizeBytes:
                              setupProofTransportChunkSizeBytes,
                          proofChunkCount: chunkHashes.length,
                          proofTotalByteLength: totalByteLength,
                          proofFullObjectHash: fullObjectHash,
                          proofChunkHashes: chunkHashes,
                          proofChunkRoot: chunkRoot,
                      }
                    : {
                          chunkSizeBytes: setupProofTransportChunkSizeBytes,
                          chunkCount: chunkHashes.length,
                          totalByteLength,
                          fullObjectHash,
                          chunkHashes,
                          chunkRoot,
                      };
            transportedProofMaterials.push({
                objectType: options.transportedObjectType,
                objectVersion: 1,
                setupProfileId,
                setupProofProfileId,
                proofFamily: options.proofFamily,
                proofMaterialRoot,
                ...transportedHashFields,
                chunks: chunks.map((chunk, chunkIndex) => ({
                    chunkIndex,
                    bytesHex: bytesToHex(chunk),
                })),
            });

            return transportedProofRecord as unknown as ProofMaterial;
        },
    );

    return {
        proofMaterials: transportedRecords,
        transportedProofMaterial: {
            objectType: options.transportedSetObjectType,
            objectVersion: 1,
            setupProfileId,
            setupProofProfileId,
            proofFamily: options.proofFamily,
            proofMaterials: transportedProofMaterials,
        },
    };
};
