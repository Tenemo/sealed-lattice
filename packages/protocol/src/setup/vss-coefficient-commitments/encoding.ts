export {
    assertNonEmptyString,
    assertNonNegativeSafeInteger,
    assertPositiveSafeInteger,
    assertProtocolHash,
} from '../common-fields.js';

import {
    setupCommitmentHidingErrorWidth,
    setupCommitmentHidingSecretWidth,
    setupCommitmentModulusLimbCount,
    setupCommitmentRandomnessCoefficientBound,
    setupCommitmentRandomnessWidth,
} from './constants-and-types.js';

type VssOpeningRandomByteSource = (byteLength: number) => Uint8Array;

class VssOpeningEntropyError extends Error {
    public readonly failureCause: unknown;

    public constructor(failureCause: unknown) {
        super(
            'VSS coefficient opening generation failed because Web Crypto getRandomValues failed.',
        );
        this.name = 'VssOpeningEntropyError';
        this.failureCause = failureCause;
    }
}

const twoToTheSixtyFourth = 1n << 64n;
export const maximumPrivateSamplerCandidateDrawsPerOutput = 64;

export const webCryptoRandomBytes: VssOpeningRandomByteSource = (
    byteLength,
) => {
    const cryptoProvider = globalThis.crypto;
    if (cryptoProvider === undefined) {
        throw new Error(
            'VSS coefficient opening generation requires Web Crypto getRandomValues.',
        );
    }
    const bytes = new Uint8Array(byteLength);
    try {
        cryptoProvider.getRandomValues(bytes);
    } catch (error) {
        throw new VssOpeningEntropyError(error);
    }

    return bytes;
};

export class RandomByteSampler {
    private buffer = new Uint8Array(0);

    private offset = 0;

    public constructor(
        private readonly randomBytes: VssOpeningRandomByteSource,
    ) {}

    public take(byteLength: number): Uint8Array {
        if (!Number.isSafeInteger(byteLength) || byteLength <= 0) {
            throw new TypeError(
                'sample byte length must be a positive integer.',
            );
        }
        const bytes = new Uint8Array(byteLength);
        let writtenByteLength = 0;
        while (writtenByteLength < byteLength) {
            if (this.offset === this.buffer.byteLength) {
                const requestedByteLength = Math.max(
                    byteLength - writtenByteLength,
                    4096,
                );
                const nextBuffer = this.randomBytes(requestedByteLength);
                if (
                    !(nextBuffer instanceof Uint8Array) ||
                    nextBuffer.byteLength !== requestedByteLength
                ) {
                    throw new Error(
                        'randomBytes must return exactly the requested byte length.',
                    );
                }
                this.buffer = Uint8Array.from(nextBuffer);
                this.offset = 0;
            }
            const copiedByteLength = Math.min(
                byteLength - writtenByteLength,
                this.buffer.byteLength - this.offset,
            );
            bytes.set(
                this.buffer.subarray(
                    this.offset,
                    this.offset + copiedByteLength,
                ),
                writtenByteLength,
            );
            writtenByteLength += copiedByteLength;
            this.offset += copiedByteLength;
        }

        return bytes;
    }
}

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
        const coefficientBound = setupCommitmentRandomnessCoefficientBound(
            randomnessColumnIndex,
        );
        if (coefficientBound === undefined) {
            throw new Error(
                `${fieldName}.${String(randomnessColumnIndex)} is outside the selected randomness profile.`,
            );
        }
        if (randomnessColumn.length !== ringDegree) {
            throw new Error(
                `${fieldName}.${String(randomnessColumnIndex)} length must match ringDegree.`,
            );
        }
        randomnessColumn.forEach((coefficient, coefficientIndex) => {
            if (
                !Number.isSafeInteger(coefficient) ||
                coefficient < -coefficientBound ||
                coefficient > coefficientBound
            ) {
                const distributionDescription =
                    randomnessColumnIndex <
                    setupCommitmentHidingSecretWidth
                        ? 'purpose-11 centered ternary'
                        : 'purpose-12 centered ternary';
                throw new TypeError(
                    `${fieldName}.${String(randomnessColumnIndex)}.${String(coefficientIndex)} must be within the ${distributionDescription} support.`,
                );
            }
        });
    });
};

export const assertRandomnessByCommitmentLimb = (
    randomnessByCommitmentLimb: readonly (readonly (readonly number[])[])[],
    ringDegree: number,
    fieldName: string,
): void => {
    if (
        randomnessByCommitmentLimb.length !==
        setupCommitmentModulusLimbCount
    ) {
        throw new Error(
            `${fieldName} must contain one independent opening tape per commitment modulus limb.`,
        );
    }
    randomnessByCommitmentLimb.forEach(
        (randomnessByColumn, commitmentLimbPosition) => {
            assertRandomness(
                randomnessByColumn,
                ringDegree,
                `${fieldName}.${String(commitmentLimbPosition)}`,
            );
        },
    );
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
    for (
        let candidateDraw = 0;
        candidateDraw < maximumPrivateSamplerCandidateDrawsPerOutput;
        candidateDraw += 1
    ) {
        const residue = reduceUnbiasedU64(
            randomLittleEndianU64(sampler),
            modulus,
        );
        if (residue !== undefined) {
            return residue;
        }
    }

    throw new Error('private sampler exhausted its candidate-draw ceiling.');
};

const sampleCenteredTernary = (sampler: RandomByteSampler): -1 | 0 | 1 => {
    for (
        let candidateDraw = 0;
        candidateDraw < maximumPrivateSamplerCandidateDrawsPerOutput;
        candidateDraw += 1
    ) {
        const candidateByte = sampler.take(1)[0];
        if (candidateByte === undefined) {
            throw new Error('random byte sampler returned an empty byte.');
        }
        if (candidateByte < 255) {
            const residue = candidateByte % 3;

            return residue === 0 ? -1 : residue === 1 ? 0 : 1;
        }
    }

    throw new Error('private sampler exhausted its candidate-draw ceiling.');
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
    Object.freeze([
        ...Array.from({ length: setupCommitmentHidingSecretWidth }, () =>
            sampleCenteredTernaryVector(sampler, ringDegree),
        ),
        ...Array.from({ length: setupCommitmentHidingErrorWidth }, () =>
            sampleCenteredTernaryVector(sampler, ringDegree),
        ),
    ]);
