import { canonicalJson, hash512 } from '@sealed-lattice/crypto';

import { receiverEncryptionCenteredBinomialEta } from '../protocol-parameters.js';

import type { BallotPrivacyRandomnessSource } from './primitive-types.js';

const textEncoder = new TextEncoder();

const unsignedWordModulus = 1n << 64n;

export const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const canonicalBytes = (value: unknown): Uint8Array =>
    textEncoder.encode(canonicalJson(value));

export const canonicalEqual = (
    leftValue: unknown,
    rightValue: unknown,
): boolean => canonicalJson(leftValue) === canonicalJson(rightValue);

const deriveBytes = (
    domain: string,
    payload: unknown,
    byteLength: number,
): Uint8Array => {
    const output = new Uint8Array(byteLength);
    let outputOffset = 0;
    let blockCounter = 0;
    while (outputOffset < byteLength) {
        const block = hash512(domain, [
            canonicalBytes({
                blockCounter,
                payload,
            }),
        ]);
        const bytesToCopy = Math.min(block.length, byteLength - outputOffset);
        output.set(block.subarray(0, bytesToCopy), outputOffset);
        outputOffset += bytesToCopy;
        blockCounter += 1;
    }

    return output;
};

const readLittleEndianWord = (
    bytes: Uint8Array,
    byteOffset: number,
): bigint => {
    let value = 0n;
    for (let wordByteIndex = 0; wordByteIndex < 8; wordByteIndex += 1) {
        value |=
            BigInt(bytes[byteOffset + wordByteIndex] ?? 0) <<
            BigInt(8 * wordByteIndex);
    }

    return value;
};

export const deriveUniformBigInt = (
    domain: string,
    payload: unknown,
    modulus: bigint,
): bigint => {
    // Rejection sampling to avoid modulo bias when expanding a hash into a uniform
    // field/ring element: discard 64-bit words >= 2^64 - (2^64 mod modulus), so the
    // accepted range is an exact multiple of `modulus`.
    const rejectionLimit =
        unsignedWordModulus - (unsignedWordModulus % modulus);
    let blockCounter = 0;
    for (;;) {
        const block = deriveBytes(domain, { blockCounter, payload }, 64);
        for (
            let byteOffset = 0;
            byteOffset + 8 <= block.length;
            byteOffset += 8
        ) {
            const candidate = readLittleEndianWord(block, byteOffset);
            if (candidate < rejectionLimit) {
                return candidate % modulus;
            }
        }
        blockCounter += 1;
    }
};

export const deriveUniformNumber = (
    domain: string,
    payload: unknown,
    modulus: number,
): number => Number(deriveUniformBigInt(domain, payload, BigInt(modulus)));

export const resolveRandomBytes = (
    randomnessSource: BallotPrivacyRandomnessSource,
    domain: string,
    payload: unknown,
    byteLength: number,
): Uint8Array => {
    if (randomnessSource.kind === 'fixture') {
        if (
            !randomnessSource.allowFixtureMode ||
            randomnessSource.fixtureSeed.length === 0
        ) {
            throw new RangeError(
                'Deterministic fixture randomness requires an explicit non-empty fixture seed and fixture-mode acknowledgement.',
            );
        }

        return deriveBytes(
            domain,
            { fixtureSeed: randomnessSource.fixtureSeed, payload },
            byteLength,
        );
    }

    const cryptoProvider = globalThis.crypto;
    if (
        cryptoProvider === undefined ||
        typeof cryptoProvider.getRandomValues !== 'function'
    ) {
        throw new Error(
            'Production ballot privacy randomness requires Web Crypto getRandomValues.',
        );
    }
    const bytes = new Uint8Array(byteLength);
    cryptoProvider.getRandomValues(bytes);

    return bytes;
};

// CBD_2 centered-binomial sampler for Module-LWE secret/error/noise: popcount(low 2
// bits) - popcount(high 2 bits) of a 4-bit nibble, giving output in -2..+2. nibbleOffset
// 0 vs 4 yields two samples per byte.
const sampleCenteredBinomialCoefficient = (
    byteValue: number,
    nibbleOffset: number,
): number => {
    const nibble = (byteValue >> nibbleOffset) & 0x0f;
    const positiveWeight = (nibble & 0x01) + ((nibble >> 1) & 0x01);
    const negativeWeight = ((nibble >> 2) & 0x01) + ((nibble >> 3) & 0x01);

    return positiveWeight - negativeWeight;
};

export const sampleCenteredBinomialVector = (
    randomnessSource: BallotPrivacyRandomnessSource,
    domain: string,
    payload: unknown,
    vectorLength: number,
    polynomialDegree: number,
): readonly (readonly number[])[] => {
    if (receiverEncryptionCenteredBinomialEta !== 2) {
        throw new RangeError(
            'Only centered-binomial eta=2 is supported by this profile.',
        );
    }
    const coefficientCount = vectorLength * polynomialDegree;
    const bytes = resolveRandomBytes(
        randomnessSource,
        domain,
        payload,
        Math.ceil(coefficientCount / 2),
    );
    const polynomials: number[][] = [];
    let coefficientIndex = 0;
    for (let vectorIndex = 0; vectorIndex < vectorLength; vectorIndex += 1) {
        const polynomial: number[] = [];
        for (
            let coefficientOffset = 0;
            coefficientOffset < polynomialDegree;
            coefficientOffset += 1
        ) {
            const byteValue = bytes[Math.floor(coefficientIndex / 2)] ?? 0;
            polynomial.push(
                sampleCenteredBinomialCoefficient(
                    byteValue,
                    coefficientIndex % 2 === 0 ? 0 : 4,
                ),
            );
            coefficientIndex += 1;
        }
        polynomials.push(polynomial);
    }

    return polynomials;
};
