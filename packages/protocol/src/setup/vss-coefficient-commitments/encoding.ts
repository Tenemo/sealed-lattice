// Stateless encoding, assertion, hashing, and sampling primitives shared across
// the VSS coefficient-commitment builders: integer and hex guards, centered
// ternary and uniform residue sampling, the little-endian coefficient vector
// encoding and its hash, varuint helpers, the setup-context field projection,
// and the binary material byte-length accounting.
import { hash512Hex } from '@sealed-lattice/crypto';

export { contextFields, setupContextFieldNames } from '../common-fields.js';

import {
    setupCommitmentModulusLimbIndices,
    setupCommitmentRandomnessWidth,
    setupCommitmentRowCount,
    vssCoefficientCommitmentMaterialBinaryMagic,
    type JsonRecord,
    type VssOpeningRandomByteSource,
} from './constants-and-types.js';

const twoToTheSixtyFourth = 1n << 64n;

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

export const defaultRandomBytes: VssOpeningRandomByteSource = (byteLength) => {
    const cryptoProvider = globalThis.crypto;
    if (cryptoProvider === undefined) {
        throw new Error(
            'VSS coefficient opening generation requires Web Crypto getRandomValues.',
        );
    }
    const bytes = new Uint8Array(byteLength);
    cryptoProvider.getRandomValues(bytes);

    return bytes;
};

export class RandomByteSampler {
    private buffer = new Uint8Array(0);

    private offset = 0;

    public constructor(
        private readonly randomBytes: VssOpeningRandomByteSource,
    ) {}

    public take(byteLength: number): Uint8Array {
        if (this.buffer.byteLength - this.offset < byteLength) {
            const requestedByteLength = Math.max(byteLength, 4096);
            const nextBuffer = this.randomBytes(requestedByteLength);
            if (nextBuffer.byteLength !== requestedByteLength) {
                throw new Error(
                    'randomBytes must return exactly the requested byte length.',
                );
            }
            this.buffer = Uint8Array.from(nextBuffer);
            this.offset = 0;
        }
        const bytes = this.buffer.subarray(
            this.offset,
            this.offset + byteLength,
        );
        this.offset += byteLength;

        return bytes;
    }
}

export const assertHashLike = (value: string, fieldName: string): void => {
    if (!/^[0-9a-f]{128}$/u.test(value)) {
        throw new TypeError(
            `${fieldName} must be a 512-bit lowercase hex hash.`,
        );
    }
};

export const assertResidueVector = (
    coefficients: readonly number[],
    modulus: number,
    ringDegree: number,
    fieldName: string,
): void => {
    if (coefficients.length !== ringDegree) {
        throw new Error(`${fieldName} length must match ringDegree.`);
    }
    coefficients.forEach((coefficient, coefficientIndex) => {
        if (
            !Number.isSafeInteger(coefficient) ||
            coefficient < 0 ||
            coefficient >= modulus
        ) {
            throw new TypeError(
                `${fieldName}.${String(coefficientIndex)} must be a residue below the declared modulus.`,
            );
        }
    });
};

export const assertRandomness = (
    randomnessByColumn: readonly (readonly number[])[],
    ringDegree: number,
    fieldName: string,
): void => {
    if (randomnessByColumn.length !== setupCommitmentRandomnessWidth) {
        throw new Error(
            `${fieldName} must contain the selected randomness width.`,
        );
    }
    randomnessByColumn.forEach((randomnessColumn, randomnessColumnIndex) => {
        if (randomnessColumn.length !== ringDegree) {
            throw new Error(
                `${fieldName}.${String(randomnessColumnIndex)} length must match ringDegree.`,
            );
        }
        randomnessColumn.forEach((coefficient, coefficientIndex) => {
            if (
                !Number.isSafeInteger(coefficient) ||
                coefficient < -1 ||
                coefficient > 1
            ) {
                throw new TypeError(
                    `${fieldName}.${String(randomnessColumnIndex)}.${String(coefficientIndex)} must be centered ternary.`,
                );
            }
        });
    });
};

export const centeredIntegerToResidue = (
    value: number,
    modulus: number,
): number => {
    const modulusWide = BigInt(modulus);
    const residue = BigInt(value) % modulusWide;

    return Number(residue < 0n ? residue + modulusWide : residue);
};

const coefficientVectorBytes = (
    coefficients: readonly number[],
): Uint8Array => {
    const bytes = new Uint8Array(coefficients.length * 8);
    coefficients.forEach((coefficient, coefficientIndex) => {
        let value = BigInt(coefficient);
        for (let byteIndex = 0; byteIndex < 8; byteIndex += 1) {
            bytes[coefficientIndex * 8 + byteIndex] = Number(value & 0xffn);
            value >>= 8n;
        }
    });

    return bytes;
};

export const coefficientVectorHash512 = (
    coefficients: readonly number[],
    domain: string,
): string => hash512Hex(domain, [coefficientVectorBytes(coefficients)]);

const hexToBytes = (hex: string): Uint8Array => {
    const bytes = new Uint8Array(hex.length / 2);
    for (let index = 0; index < bytes.length; index += 1) {
        bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
    }

    return bytes;
};

const littleEndianU64 = (bytes: Uint8Array): bigint => {
    let value = 0n;
    for (let byteIndex = bytes.length - 1; byteIndex >= 0; byteIndex -= 1) {
        value = (value << 8n) | BigInt(bytes[byteIndex] ?? 0);
    }

    return value;
};

const reduceUnbiasedU64 = (
    value: bigint,
    modulus: number,
): number | undefined => {
    const modulusWide = BigInt(modulus);
    const limit = twoToTheSixtyFourth - (twoToTheSixtyFourth % modulusWide);
    if (value >= limit) {
        return undefined;
    }

    return Number(value % modulusWide);
};

const randomLittleEndianU64 = (sampler: RandomByteSampler): bigint =>
    littleEndianU64(sampler.take(8));

const sampleUniformResidue = (
    sampler: RandomByteSampler,
    modulus: number,
): number => {
    while (true) {
        const residue = reduceUnbiasedU64(
            randomLittleEndianU64(sampler),
            modulus,
        );
        if (residue !== undefined) {
            return residue;
        }
    }
};

const sampleCenteredTernary = (sampler: RandomByteSampler): -1 | 0 | 1 => {
    while (true) {
        const candidateByte = sampler.take(1)[0];
        if (candidateByte === undefined) {
            throw new Error('random byte sampler returned an empty byte.');
        }
        if (candidateByte < 255) {
            const residue = candidateByte % 3;

            return residue === 0 ? -1 : residue === 1 ? 0 : 1;
        }
    }
};

export const sampleCenteredTernaryVector = (
    sampler: RandomByteSampler,
    ringDegree: number,
): (-1 | 0 | 1)[] =>
    Array.from({ length: ringDegree }, () => sampleCenteredTernary(sampler));

export const sampleUniformResidueVector = (
    sampler: RandomByteSampler,
    modulus: number,
    ringDegree: number,
): number[] =>
    Array.from({ length: ringDegree }, () =>
        sampleUniformResidue(sampler, modulus),
    );

export const sampleCommitmentOpeningRandomness = (
    sampler: RandomByteSampler,
    ringDegree: number,
): readonly (readonly number[])[] =>
    Array.from({ length: setupCommitmentRandomnessWidth }, () =>
        sampleCenteredTernaryVector(sampler, ringDegree),
    );

export const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

export const hexToBytesStrict = (
    hex: string,
    fieldName: string,
): Uint8Array => {
    if (!/^(?:[0-9a-f]{2})*$/u.test(hex)) {
        throw new TypeError(`${fieldName} must be lowercase hex bytes.`);
    }

    return hexToBytes(hex);
};

export const assertJsonRecord = (
    value: unknown,
    fieldName: string,
): JsonRecord => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new TypeError(`${fieldName} must be an object.`);
    }

    return value as JsonRecord;
};

export const assertJsonRecordArray = (
    value: unknown,
    fieldName: string,
): readonly JsonRecord[] => {
    if (!Array.isArray(value)) {
        throw new TypeError(`${fieldName} must be an array.`);
    }

    return value.map((entry, entryIndex) =>
        assertJsonRecord(entry, `${fieldName}.${String(entryIndex)}`),
    );
};

const appendVaruint = (outputBytes: number[], value: number): void => {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new TypeError(
            'varuint values must be non-negative safe integers.',
        );
    }
    let remainingValue = value;
    for (;;) {
        let byte = remainingValue & 0x7f;
        remainingValue = Math.floor(remainingValue / 128);
        if (remainingValue !== 0) {
            byte |= 0x80;
        }
        outputBytes.push(byte);
        if (remainingValue === 0) {
            break;
        }
    }
};

export const varuintBytes = (value: number): Uint8Array => {
    const outputBytes: number[] = [];
    appendVaruint(outputBytes, value);

    return Uint8Array.from(outputBytes);
};

const varuintByteLength = (value: number): number =>
    varuintBytes(value).byteLength;

const setupCommitmentBinaryRecordByteLength = (ringDegree: number): number => {
    if (
        !Number.isSafeInteger(ringDegree) ||
        ringDegree <= 0 ||
        ringDegree > Number.MAX_SAFE_INTEGER
    ) {
        throw new TypeError('ringDegree must be a positive safe integer.');
    }
    const rowCoefficientBytes = setupCommitmentRowCount * ringDegree * 8;
    const commitmentLimbBytes = 1 + 8 + rowCoefficientBytes;

    return 3 + setupCommitmentModulusLimbIndices.length * commitmentLimbBytes;
};

export const binaryVssCoefficientCommitmentMaterialByteLength = (input: {
    readonly participantCount: number;
    readonly thresholdDegree: number;
    readonly rnsLimbCount: number;
    readonly ringDegree: number;
}): number => {
    const headerByteLength =
        vssCoefficientCommitmentMaterialBinaryMagic.byteLength +
        varuintByteLength(1) +
        varuintByteLength(input.participantCount) +
        varuintByteLength(input.thresholdDegree) +
        varuintByteLength(input.rnsLimbCount) +
        varuintByteLength(input.ringDegree) +
        varuintByteLength(setupCommitmentModulusLimbIndices.length) +
        varuintByteLength(setupCommitmentRowCount);
    const materialRecordCount =
        input.participantCount * input.rnsLimbCount * input.thresholdDegree;
    const recordByteLength = setupCommitmentBinaryRecordByteLength(
        input.ringDegree,
    );

    return headerByteLength + materialRecordCount * recordByteLength;
};

export const positiveSafeIntegerField = (
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

export const nonNegativeSafeIntegerField = (
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
