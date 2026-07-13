export {
    assertNonNegativeSafeInteger,
    assertPositiveSafeInteger,
    contextFields,
    setupContextFieldNames,
} from '../common-fields.js';

import {
    setupCommitmentRandomnessWidth,
    type VssOpeningRandomByteSource,
} from './constants-and-types.js';

const twoToTheSixtyFourth = 1n << 64n;

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
