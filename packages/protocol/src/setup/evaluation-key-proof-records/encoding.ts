import { deriveProtocolHash, hash512Hex } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import { setupProofProfileId } from '../same-secret-consistency-records.js';
import { setupProofTransportChunkSizeBytes } from '../setup-proof-material-transport.js';

import {
    type EvaluationKeyShareMaterial,
    type EvaluationKeyShareProofFamily,
    type JsonRecord,
    evaluationKeyShareComponentMaterialChunkHashDomain,
    evaluationKeyShareComponentMaterialEncoding,
    evaluationKeyShareComponentMaterialFullObjectHashDomain,
    evaluationKeyShareComponentVectorHashDomain,
    textEncoder,
} from './constants-and-types.js';

const protocolHashPattern = /^[0-9a-f]{128}$/u;
const lowercaseHexPattern = /^[0-9a-f]+$/u;

export const assertProtocolHash = (value: string, fieldName: string): void => {
    if (!protocolHashPattern.test(value)) {
        throw new TypeError(`${fieldName} must be a protocol hash.`);
    }
};

export const assertPositiveSafeInteger = (
    value: number,
    fieldName: string,
): void => {
    if (!Number.isSafeInteger(value) || value <= 0) {
        throw new TypeError(`${fieldName} must be a positive safe integer.`);
    }
};

export const assertNonNegativeSafeInteger = (
    value: number,
    fieldName: string,
): void => {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new TypeError(
            `${fieldName} must be a non-negative safe integer.`,
        );
    }
};

export const assertNonEmptyString = (
    value: string,
    fieldName: string,
): void => {
    if (value.length === 0) {
        throw new TypeError(`${fieldName} must be non-empty.`);
    }
};

export const assertLowercaseHex = (value: string, fieldName: string): void => {
    if (!lowercaseHexPattern.test(value)) {
        throw new TypeError(`${fieldName} must be lowercase hex.`);
    }
};

export const assertJsonRecord = (
    value: unknown,
    fieldName: string,
): JsonRecord => {
    if (value === null || Array.isArray(value) || typeof value !== 'object') {
        throw new TypeError(`${fieldName} must be a JSON object.`);
    }

    return value as JsonRecord;
};

export const stringRecordField = (
    record: JsonRecord,
    fieldName: string,
    objectPath: string,
): string => {
    const value = record[fieldName];
    if (typeof value !== 'string' || value.length === 0) {
        throw new TypeError(`${objectPath}.${fieldName} must be non-empty.`);
    }

    return value;
};

export const nonNegativeIntegerRecordField = (
    record: JsonRecord,
    fieldName: string,
    objectPath: string,
): number => {
    const value = record[fieldName];
    if (
        typeof value !== 'number' ||
        !Number.isSafeInteger(value) ||
        value < 0
    ) {
        throw new TypeError(
            `${objectPath}.${fieldName} must be a non-negative safe integer.`,
        );
    }

    return value;
};

export const bytesFromHex = (hex: string, fieldName: string): Uint8Array => {
    if (!/^(?:[0-9a-f]{2})*$/u.test(hex)) {
        throw new TypeError(`${fieldName} must be lowercase hex bytes.`);
    }
    const bytes = new Uint8Array(hex.length / 2);
    for (let byteIndex = 0; byteIndex < bytes.length; byteIndex += 1) {
        bytes[byteIndex] = Number.parseInt(
            hex.slice(byteIndex * 2, byteIndex * 2 + 2),
            16,
        );
    }

    return bytes;
};

export const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const proofRandomnessByteLength = 64;

const defaultProofRandomBytes = (byteLength: number): Uint8Array => {
    const cryptoProvider = globalThis.crypto;
    if (cryptoProvider === undefined) {
        throw new Error(
            'Trustee evaluation-key proof generation requires Web Crypto getRandomValues.',
        );
    }
    const bytes = new Uint8Array(byteLength);
    cryptoProvider.getRandomValues(bytes);

    return bytes;
};

export const freshProofRandomnessHex = (): string => {
    const bytes = defaultProofRandomBytes(proofRandomnessByteLength);
    if (bytes.byteLength !== proofRandomnessByteLength) {
        throw new Error(
            'proof randomness byte source must return exactly 64 bytes.',
        );
    }

    return bytesToHex(bytes);
};

const appendVaruint = (outputBytes: number[], value: number): void => {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new TypeError(
            'binary varuint value must be a non-negative safe integer.',
        );
    }
    let remainingValue = value;
    do {
        let byte = remainingValue & 0x7f;
        remainingValue = Math.floor(remainingValue / 128);
        if (remainingValue !== 0) {
            byte |= 0x80;
        }
        outputBytes.push(byte);
    } while (remainingValue !== 0);
};

const varUintBytes = (value: number): Uint8Array => {
    const outputBytes: number[] = [];
    appendVaruint(outputBytes, value);

    return Uint8Array.from(outputBytes);
};

export const coefficientVectorFromLittleEndianHex = (
    coefficientsLeHex: string,
    expectedCoefficientCount: number,
    fieldName: string,
): readonly number[] => {
    const coefficientBytes = bytesFromHex(coefficientsLeHex, fieldName);
    if (coefficientBytes.byteLength !== expectedCoefficientCount * 8) {
        throw new Error(`${fieldName} byte length must match ringDegree.`);
    }

    return Array.from(
        { length: expectedCoefficientCount },
        (_unused, coefficientIndex) => {
            let coefficient = 0n;
            for (let byteOffset = 7; byteOffset >= 0; byteOffset -= 1) {
                coefficient <<= 8n;
                coefficient |= BigInt(
                    coefficientBytes[coefficientIndex * 8 + byteOffset] ?? 0,
                );
            }
            if (coefficient > BigInt(Number.MAX_SAFE_INTEGER)) {
                throw new Error(
                    `${fieldName} contains a coefficient outside the JavaScript safe integer range.`,
                );
            }

            return Number(coefficient);
        },
    );
};

const coefficientVectorBytes = (
    coefficients: readonly number[],
): Uint8Array => {
    const bytes = new Uint8Array(coefficients.length * 8);
    coefficients.forEach((coefficient, coefficientIndex) => {
        if (!Number.isSafeInteger(coefficient) || coefficient < 0) {
            throw new TypeError(
                'evaluation-key component coefficient must be a non-negative safe integer.',
            );
        }
        let remainingValue = BigInt(coefficient);
        for (let byteIndex = 0; byteIndex < 8; byteIndex += 1) {
            bytes[coefficientIndex * 8 + byteIndex] = Number(
                remainingValue & 0xffn,
            );
            remainingValue >>= 8n;
        }
    });

    return bytes;
};

export const evaluationKeyShareComponentVectorHash = (
    coefficients: readonly number[],
): ProtocolHash =>
    hash512Hex(evaluationKeyShareComponentVectorHashDomain, [
        coefficientVectorBytes(coefficients),
    ]);

export const u64LittleEndianBytes = (
    value: number,
    fieldName: string,
): Uint8Array => {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new TypeError(
            `${fieldName} must be a non-negative safe integer.`,
        );
    }
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, BigInt(value), true);

    return bytes;
};

export const evaluationKeyShareComponentVectorRoot = (
    proofFamily: EvaluationKeyShareProofFamily,
    keySwitchDomain: string,
    keySwitchSeedHex: string,
    level: number,
    ringDegree: number,
    componentVectors: readonly JsonRecord[],
): ProtocolHash =>
    deriveProtocolHash('EvaluationKeyShareComponentVectorRoot', {
        objectType: 'EvaluationKeyShareComponentVectorSet',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId,
        proofFamily,
        keySwitchDomain,
        keySwitchSeedHex,
        level,
        ringDegree,
        digitCount: level + 1,
        rnsLimbCount: level + 1,
        componentVectors,
    });

const evaluationKeyShareComponentMaterialFullObjectHash = (
    proofFamily: EvaluationKeyShareProofFamily,
    totalByteLength: number,
    chunks: readonly Uint8Array[],
): ProtocolHash =>
    hash512Hex(evaluationKeyShareComponentMaterialFullObjectHashDomain, [
        textEncoder.encode(proofFamily),
        varUintBytes(totalByteLength),
        ...chunks,
    ]);

const evaluationKeyShareComponentMaterialChunkHash = (
    proofFamily: EvaluationKeyShareProofFamily,
    fullObjectHash: ProtocolHash,
    chunkIndex: number,
    chunk: Uint8Array,
): ProtocolHash =>
    hash512Hex(evaluationKeyShareComponentMaterialChunkHashDomain, [
        textEncoder.encode(proofFamily),
        textEncoder.encode(fullObjectHash),
        varUintBytes(chunkIndex),
        chunk,
    ]);

type ComponentMaterialTransportHashes = Readonly<{
    readonly fullObjectHash: ProtocolHash;
    readonly chunkHashes: readonly ProtocolHash[];
    readonly chunkRoot: ProtocolHash;
    readonly totalByteLength: number;
}>;

export const evaluationKeyShareComponentMaterialTransportHashes = (
    proofFamily: EvaluationKeyShareProofFamily,
    chunks: readonly Uint8Array[],
): ComponentMaterialTransportHashes => {
    const totalByteLength = chunks.reduce(
        (byteLength, chunk) => byteLength + chunk.byteLength,
        0,
    );
    const fullObjectHash = evaluationKeyShareComponentMaterialFullObjectHash(
        proofFamily,
        totalByteLength,
        chunks,
    );
    const chunkHashes = chunks.map((chunk, chunkIndex) =>
        evaluationKeyShareComponentMaterialChunkHash(
            proofFamily,
            fullObjectHash,
            chunkIndex,
            chunk,
        ),
    );
    const chunkRoot = deriveProtocolHash(
        'EvaluationKeyShareComponentMaterialChunkRoot',
        {
            objectType: 'EvaluationKeyShareComponentMaterialChunkManifest',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            setupProofProfileId,
            proofFamily,
            keySwitchMaterialEncoding:
                evaluationKeyShareComponentMaterialEncoding,
            chunkSizeBytes: setupProofTransportChunkSizeBytes,
            chunkCount: chunkHashes.length,
            totalByteLength,
            chunkHashes,
            fullObjectHash,
        },
    );

    return {
        fullObjectHash,
        chunkHashes,
        chunkRoot,
        totalByteLength,
    };
};

export const evaluationKeyShareComponentMaterialReferenceRoot = (
    proofFamily: EvaluationKeyShareProofFamily,
    shareMaterial: EvaluationKeyShareMaterial,
    trusteeIdentity: string,
    trusteeRosterPosition: number,
    level: number,
    transportHashes: ComponentMaterialTransportHashes,
): ProtocolHash =>
    deriveProtocolHash('EvaluationKeyShareComponentMaterialRoot', {
        objectType: 'EvaluationKeyShareComponentMaterialReference',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId,
        proofFamily,
        keySwitchMaterialEncoding: evaluationKeyShareComponentMaterialEncoding,
        trusteeIdentity,
        trusteeRosterPosition,
        keySwitchDomain: shareMaterial.keySwitchDomain,
        keySwitchSeedHex: shareMaterial.keySwitchSeedHex,
        level,
        ringDegree: shareMaterial.ringDegree,
        digitCount: level + 1,
        rnsLimbCount: level + 1,
        keySwitchComponentVectorRoot:
            shareMaterial.keySwitchComponentVectorRoot,
        chunkSizeBytes: setupProofTransportChunkSizeBytes,
        chunkCount: transportHashes.chunkHashes.length,
        totalByteLength: transportHashes.totalByteLength,
        fullObjectHash: transportHashes.fullObjectHash,
        chunkRoot: transportHashes.chunkRoot,
        chunkHashes: transportHashes.chunkHashes,
    });
