import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import { setupProofTransportChunkSizeBytes } from '../setup-proof-material-transport.js';
import { appendVaruint } from '../varuint-encoding.js';
import type { CollectiveBgvSetupContext } from '../vss-share-verification-records.js';

import {
    publicKeyShareMaterialEncoding,
    publicKeyShareMaterialTransportEncoding,
    publicKeyShareProofFamily,
    type BinaryChunkedPublicKeyShareMaterialBundle,
    type BinaryChunkedPublicKeyShareMaterialBundleInput,
    type BinaryChunkedPublicKeyShareMaterialSet,
    type BinaryChunkedPublicKeyShareMaterialTransport,
    type BinaryChunkedPublicKeyShareMaterialTransportInput,
    type CollectivePublicKeySourceShareMaterialRoot,
    type JsonRecord,
    type PublicKeyShareCoefficientVectorMaterial,
    type PublicKeyShareMaterialChunkSource,
    type PublicKeyShareMaterialRecord,
    type PublicKeyShareMaterialRootReference,
    type PublicKeyShareRecord,
    type PublicKeyShareSet,
} from './constants-and-types.js';
import {
    assertPublicKeyShareMaterialInput,
    createPublicKeyShareMaterialEncodingSource,
    createPublicKeyShareMaterialSetEncodingSource,
    publicKeyShareMaterialRecordsFromContributions,
    publicKeyShareMaterialRootReferences,
} from './embedded-material-records.js';
import {
    assertContextMatches,
    coefficientVectorHash512,
    coefficientVectorToLittleEndianHex,
    contextFields,
    publicKeyShareMaterialBinaryMagic,
} from './encoding.js';
import { publicKeyShareRecordsByRosterPosition } from './share-statement-records.js';

const binaryChunkedPublicKeyShareMaterialSet = (
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
    }>,
): BinaryChunkedPublicKeyShareMaterialSet => {
    const materialSetWithoutRoot = {
        objectType: 'PublicKeyShareMaterialSet',
        proofFamily: publicKeyShareProofFamily,
        materialEncoding: publicKeyShareMaterialTransportEncoding,
        ...contextFields(input.setupContext),
        participantCount: input.participantCount,
        rnsLimbCount: input.rnsLimbCount,
        ringDegree: input.ringDegree,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        publicKeyCrpRoot: input.publicKeyCrpRoot,
        publicAPolynomialRoot: input.publicAPolynomialRoot,
        publicKeyShareSetRoot: input.publicKeyShareSetRoot,
        publicKeyShareMaterialRoots: input.publicKeyShareMaterialRoots,
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

const canonicalDescriptorBytes = (descriptorBytes: Uint8Array): Uint8Array => {
    if (
        !ArrayBuffer.isView(descriptorBytes) ||
        Object.prototype.toString.call(descriptorBytes) !==
            '[object Uint8Array]' ||
        descriptorBytes.byteLength === 0
    ) {
        throw new TypeError(
            'writePublicKeyShareMaterial must return non-empty Uint8Array descriptor bytes.',
        );
    }

    return descriptorBytes.slice();
};

const finishPublicKeyShareMaterialTransport = async (
    materialSet: BinaryChunkedPublicKeyShareMaterialSet,
    encodingSource: Readonly<{
        readonly pullChunk: PublicKeyShareMaterialChunkSource['pullChunk'];
        readonly totalByteLength: number;
    }>,
    writePublicKeyShareMaterial: BinaryChunkedPublicKeyShareMaterialTransportInput['writePublicKeyShareMaterial'],
): Promise<BinaryChunkedPublicKeyShareMaterialTransport> => {
    const descriptorBytes = canonicalDescriptorBytes(
        await writePublicKeyShareMaterial({
            publicKeyShareMaterialSetRoot:
                materialSet.publicKeyShareMaterialSetRoot,
            pullChunk: encodingSource.pullChunk,
            totalByteLength: encodingSource.totalByteLength,
        }),
    );
    const publicKeyShareMaterialChunkSource = {
        publicKeyShareMaterialSetRoot:
            materialSet.publicKeyShareMaterialSetRoot,
        pullChunk: encodingSource.pullChunk,
    } satisfies PublicKeyShareMaterialChunkSource;

    return {
        materialSet,
        transportedPublicKeyShareMaterial: {
            objectType: 'SetupTransportedPublicKeyShareMaterial',
            publicKeyShareMaterialSetRoot:
                materialSet.publicKeyShareMaterialSetRoot,
            descriptorBytes,
        },
        publicKeyShareMaterialChunkSource,
    };
};

export const createBinaryChunkedPublicKeyShareMaterialTransport = async (
    input: BinaryChunkedPublicKeyShareMaterialTransportInput,
): Promise<BinaryChunkedPublicKeyShareMaterialTransport> => {
    if (input.materialSet.materialEncoding !== publicKeyShareMaterialEncoding) {
        throw new Error(
            'binary public-key share material transport must be built from embedded full public values.',
        );
    }
    const materialSet = binaryChunkedPublicKeyShareMaterialSet({
        setupContext: input.materialSet as unknown as CollectiveBgvSetupContext,
        participantCount: input.materialSet.participantCount,
        rnsLimbCount: input.materialSet.rnsLimbCount,
        ringDegree: input.materialSet.ringDegree,
        publicMatrixSeedHash: input.materialSet.publicMatrixSeedHash,
        publicKeyCrpRoot: input.materialSet.publicKeyCrpRoot,
        publicAPolynomialRoot: input.materialSet.publicAPolynomialRoot,
        publicKeyShareSetRoot: input.materialSet.publicKeyShareSetRoot,
        publicKeyShareMaterialRoots:
            input.materialSet.publicKeyShareMaterialRoots,
    });

    return finishPublicKeyShareMaterialTransport(
        materialSet,
        createPublicKeyShareMaterialSetEncodingSource(input.materialSet),
        input.writePublicKeyShareMaterial,
    );
};

export const createBinaryChunkedPublicKeyShareMaterialBundle = async (
    input: BinaryChunkedPublicKeyShareMaterialBundleInput,
): Promise<BinaryChunkedPublicKeyShareMaterialBundle> => {
    assertPublicKeyShareMaterialInput(input);
    const shareMaterialRecords =
        publicKeyShareMaterialRecordsFromContributions(input);
    const materialSet = binaryChunkedPublicKeyShareMaterialSet({
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
    });

    return finishPublicKeyShareMaterialTransport(
        materialSet,
        createPublicKeyShareMaterialEncodingSource({
            participantCount: input.participantCount,
            rnsLimbCount: input.qSharePrimes.length,
            ringDegree: input.ringDegree,
            shareMaterialRecords,
        }),
        input.writePublicKeyShareMaterial,
    );
};

const varuintByteLength = (value: number): number => {
    const bytes: number[] = [];
    appendVaruint(bytes, value);
    return bytes.length;
};

const publicKeyShareMaterialTotalByteLength = (
    materialSet: BinaryChunkedPublicKeyShareMaterialSet,
): number => {
    const headerByteLength =
        publicKeyShareMaterialBinaryMagic.byteLength +
        [
            1,
            materialSet.participantCount,
            materialSet.rnsLimbCount,
            materialSet.ringDegree,
        ].reduce(
            (byteLength, value) => byteLength + varuintByteLength(value),
            0,
        );
    const recordByteLength = Array.from(
        { length: materialSet.participantCount },
        (_unused, trusteeRosterPosition) =>
            varuintByteLength(trusteeRosterPosition) +
            Array.from(
                { length: materialSet.rnsLimbCount },
                (_unusedLimb, rnsLimbIndex) =>
                    varuintByteLength(rnsLimbIndex) +
                    8 +
                    materialSet.ringDegree * 8,
            ).reduce((sum, value) => sum + value, 0),
    ).reduce((sum, value) => sum + value, 0);
    const totalByteLength = headerByteLength + recordByteLength;
    if (!Number.isSafeInteger(totalByteLength) || totalByteLength <= 0) {
        throw new Error(
            'public-key share material byte length is outside the JavaScript safe integer range.',
        );
    }

    return totalByteLength;
};

class PublicKeyShareMaterialStreamReader {
    private chunk?: Uint8Array;
    private chunkIndex = 0;
    private chunkOffset = 0;
    private consumedByteLength = 0;

    public constructor(
        private readonly pullChunk: PublicKeyShareMaterialChunkSource['pullChunk'],
        private readonly totalByteLength: number,
    ) {}

    public async readBytes(
        byteLength: number,
        fieldName: string,
    ): Promise<Uint8Array> {
        if (
            !Number.isSafeInteger(byteLength) ||
            byteLength < 0 ||
            this.consumedByteLength + byteLength > this.totalByteLength
        ) {
            throw new Error(
                `${fieldName} ended before the binary object was complete.`,
            );
        }
        const output = new Uint8Array(byteLength);
        let outputOffset = 0;
        while (outputOffset < output.length) {
            await this.requireChunk(fieldName);
            const chunk = this.chunk;
            if (chunk === undefined) {
                throw new Error(
                    `${fieldName} ended before the binary object was complete.`,
                );
            }
            const copyByteLength = Math.min(
                chunk.byteLength - this.chunkOffset,
                output.length - outputOffset,
            );
            output.set(
                chunk.subarray(
                    this.chunkOffset,
                    this.chunkOffset + copyByteLength,
                ),
                outputOffset,
            );
            this.chunkOffset += copyByteLength;
            this.consumedByteLength += copyByteLength;
            outputOffset += copyByteLength;
        }

        return output;
    }

    public async readVaruint(fieldName: string): Promise<number> {
        let shift = 0n;
        let value = 0n;
        const consumed: number[] = [];
        for (let byteIndex = 0; byteIndex < 10; byteIndex += 1) {
            const byte = (await this.readBytes(1, fieldName))[0];
            if (byte === undefined) {
                throw new Error(`${fieldName} ended before its varuint.`);
            }
            consumed.push(byte);
            value |= BigInt(byte & 0x7f) << shift;
            if ((byte & 0x80) === 0) {
                if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
                    throw new Error(
                        `${fieldName} does not fit a safe integer.`,
                    );
                }
                const numericValue = Number(value);
                const canonical: number[] = [];
                appendVaruint(canonical, numericValue);
                if (
                    canonical.length !== consumed.length ||
                    canonical.some(
                        (canonicalByte, index) =>
                            canonicalByte !== consumed[index],
                    )
                ) {
                    throw new Error(
                        `${fieldName} binary varuint is not minimally encoded.`,
                    );
                }
                return numericValue;
            }
            shift += 7n;
        }

        throw new Error(`${fieldName} binary varuint is too long.`);
    }

    public async readUnsigned64(fieldName: string): Promise<number> {
        const bytes = await this.readBytes(8, fieldName);
        const value = new DataView(
            bytes.buffer,
            bytes.byteOffset,
            bytes.byteLength,
        ).getBigUint64(0, true);
        if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
            throw new Error(`${fieldName} does not fit a safe integer.`);
        }
        return Number(value);
    }

    public async finish(): Promise<void> {
        if (this.consumedByteLength !== this.totalByteLength) {
            throw new Error(
                'transported public-key share material ended before the canonical object was complete.',
            );
        }
        this.releaseChunk();
        const trailingChunk = await this.pullChunk({
            chunkIndex: this.chunkIndex,
            expectedByteLength: 0,
        });
        if (trailingChunk !== undefined) {
            new Uint8Array(trailingChunk).fill(0);
            throw new Error(
                'transported public-key share material has trailing chunks.',
            );
        }
    }

    public dispose(): void {
        this.releaseChunk();
    }

    private async requireChunk(fieldName: string): Promise<void> {
        if (
            this.chunk !== undefined &&
            this.chunkOffset < this.chunk.byteLength
        ) {
            return;
        }
        this.releaseChunk();
        const remainingByteLength =
            this.totalByteLength - this.consumedByteLength;
        const expectedByteLength = Math.min(
            setupProofTransportChunkSizeBytes,
            remainingByteLength,
        );
        const chunkBuffer = await this.pullChunk({
            chunkIndex: this.chunkIndex,
            expectedByteLength,
        });
        if (
            chunkBuffer === undefined ||
            Object.prototype.toString.call(chunkBuffer) !==
                '[object ArrayBuffer]' ||
            chunkBuffer.byteLength !== expectedByteLength
        ) {
            throw new Error(
                `${fieldName} source returned a malformed canonical chunk.`,
            );
        }
        this.chunk = new Uint8Array(chunkBuffer);
        this.chunkIndex += 1;
        this.chunkOffset = 0;
    }

    private releaseChunk(): void {
        this.chunk?.fill(0);
        this.chunk = undefined;
        this.chunkOffset = 0;
    }
}

type TransportedPublicKeyShareMaterialReaderInput = Readonly<{
    readonly setupContext: CollectiveBgvSetupContext;
    readonly publicKeyShares: PublicKeyShareSet;
    readonly materialSet: BinaryChunkedPublicKeyShareMaterialSet;
    readonly publicKeyShareMaterialChunkSource: PublicKeyShareMaterialChunkSource;
}>;

const transportedPublicKeyShareMaterialReader = async (
    input: TransportedPublicKeyShareMaterialReaderInput,
): Promise<
    Readonly<{
        readonly reader: PublicKeyShareMaterialStreamReader;
        readonly shareRecords: ReadonlyMap<number, PublicKeyShareRecord>;
    }>
> => {
    if (
        input.materialSet.materialEncoding !==
            publicKeyShareMaterialTransportEncoding ||
        input.publicKeyShareMaterialChunkSource
            .publicKeyShareMaterialSetRoot !==
            input.materialSet.publicKeyShareMaterialSetRoot ||
        typeof input.publicKeyShareMaterialChunkSource.pullChunk !== 'function'
    ) {
        throw new Error(
            'public-key share material source must match the binary material-set root.',
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

    const reader = new PublicKeyShareMaterialStreamReader(
        input.publicKeyShareMaterialChunkSource.pullChunk,
        publicKeyShareMaterialTotalByteLength(input.materialSet),
    );
    try {
        const magic = await reader.readBytes(
            publicKeyShareMaterialBinaryMagic.byteLength,
            'public-key share material magic',
        );
        if (
            magic.some(
                (byte, index) =>
                    byte !== publicKeyShareMaterialBinaryMagic[index],
            )
        ) {
            throw new Error(
                'transported public-key share material binary magic does not match.',
            );
        }
        if ((await reader.readVaruint('binary version')) !== 1) {
            throw new Error(
                'transported public-key share material binary version is unsupported.',
            );
        }
        if (
            (await reader.readVaruint('participantCount')) !==
            input.materialSet.participantCount
        ) {
            throw new Error(
                'transported public-key share material participant count must match material set.',
            );
        }
        if (
            (await reader.readVaruint('rnsLimbCount')) !==
            input.materialSet.rnsLimbCount
        ) {
            throw new Error(
                'transported public-key share material RNS limb count must match material set.',
            );
        }
        if (
            (await reader.readVaruint('ringDegree')) !==
            input.materialSet.ringDegree
        ) {
            throw new Error(
                'transported public-key share material ringDegree must match material set.',
            );
        }
    } catch (error) {
        reader.dispose();
        throw error;
    }

    return {
        reader,
        shareRecords: publicKeyShareRecordsByRosterPosition({
            setupContext: input.setupContext,
            participantCount: input.materialSet.participantCount,
            publicKeyShares: input.publicKeyShares,
        }),
    };
};

export const aggregateTransportedPublicKeyShareMaterial = async (
    input: TransportedPublicKeyShareMaterialReaderInput,
): Promise<
    Readonly<{
        readonly sourceShareMaterialRoots: readonly CollectivePublicKeySourceShareMaterialRoot[];
        readonly aggregateCoefficientsByLimb: readonly (readonly number[])[];
    }>
> => {
    const { reader, shareRecords } =
        await transportedPublicKeyShareMaterialReader(input);
    try {
        const materialRootReferences: PublicKeyShareMaterialRootReference[] =
            [];
        const sourceShareMaterialRoots: CollectivePublicKeySourceShareMaterialRoot[] =
            [];
        const aggregateCoefficientsByLimb = Array.from(
            { length: input.materialSet.rnsLimbCount },
            () => Array.from({ length: input.materialSet.ringDegree }, () => 0),
        );
        for (
            let expectedRosterPosition = 0;
            expectedRosterPosition < input.materialSet.participantCount;
            expectedRosterPosition += 1
        ) {
            if (
                (await reader.readVaruint('trusteeRosterPosition')) !==
                expectedRosterPosition
            ) {
                throw new Error(
                    'transported public-key share material trustee order is not canonical.',
                );
            }
            const shareRecord = shareRecords.get(expectedRosterPosition);
            if (shareRecord === undefined) {
                throw new Error(
                    'transported public-key share material must reference a supplied share record.',
                );
            }
            const shareCoefficientVectorsByLimb: PublicKeyShareCoefficientVectorMaterial[] =
                [];
            for (
                let rnsLimbIndex = 0;
                rnsLimbIndex <
                shareRecord.shareCoefficientVectorHash512ByLimb.length;
                rnsLimbIndex += 1
            ) {
                const shareCoefficientHash =
                    shareRecord.shareCoefficientVectorHash512ByLimb[
                        rnsLimbIndex
                    ];
                if (
                    shareCoefficientHash === undefined ||
                    (await reader.readVaruint('rnsLimbIndex')) !== rnsLimbIndex
                ) {
                    throw new Error(
                        'transported public-key share material RNS limb order is not canonical.',
                    );
                }
                const rnsPrime = await reader.readUnsigned64('rnsPrime');
                if (
                    shareCoefficientHash.rnsLimbIndex !== rnsLimbIndex ||
                    shareCoefficientHash.rnsPrime !== rnsPrime ||
                    shareCoefficientHash.component !== 'b_i'
                ) {
                    throw new Error(
                        'transported public-key share material limb metadata must match publicKeyShares.',
                    );
                }
                const aggregateCoefficients =
                    aggregateCoefficientsByLimb[rnsLimbIndex];
                if (aggregateCoefficients === undefined) {
                    throw new Error(
                        'transported public-key share aggregate limb is missing.',
                    );
                }
                const coefficients: number[] = [];
                for (
                    let coefficientIndex = 0;
                    coefficientIndex < input.materialSet.ringDegree;
                    coefficientIndex += 1
                ) {
                    const coefficient = await reader.readUnsigned64(
                        'public-key share coefficient',
                    );
                    if (coefficient >= rnsPrime) {
                        throw new Error(
                            'transported public-key share coefficient is not a canonical residue.',
                        );
                    }
                    coefficients.push(coefficient);
                    aggregateCoefficients[coefficientIndex] =
                        (aggregateCoefficients[coefficientIndex] +
                            coefficient) %
                        rnsPrime;
                }
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
                shareCoefficientVectorsByLimb.push({
                    rnsLimbIndex,
                    rnsPrime,
                    component: 'b_i',
                    coefficientByteLength: input.materialSet.ringDegree * 8,
                    coefficientVectorHash512: coefficientVectorHash,
                    coefficientsLeHex:
                        coefficientVectorToLittleEndianHex(coefficients),
                });
            }
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
            const publicKeyShareMaterialRoot = deriveCanonicalObjectHash(
                materialRecordWithoutRoot,
            );
            materialRootReferences.push({
                trusteeIdentity: shareRecord.trusteeIdentity,
                trusteeRosterPosition: shareRecord.trusteeRosterPosition,
                publicKeyShareMaterialRoot,
            });
            sourceShareMaterialRoots.push({
                trusteeIdentity: shareRecord.trusteeIdentity,
                trusteeRosterPosition: shareRecord.trusteeRosterPosition,
                publicKeyShareRoot: shareRecord.publicKeyShareRoot,
                publicKeyShareMaterialRoot,
            });
        }
        await reader.finish();
        if (
            JSON.stringify(materialRootReferences) !==
            JSON.stringify(input.materialSet.publicKeyShareMaterialRoots)
        ) {
            throw new Error(
                'transported public-key share material roots must match material set references.',
            );
        }

        return {
            sourceShareMaterialRoots,
            aggregateCoefficientsByLimb,
        };
    } finally {
        reader.dispose();
    }
};
