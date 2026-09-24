import { describe, expect, it } from 'vitest';

import { candidateBgvParameterInputs } from '#tests/candidate-bgv-parameter-model.js';
import {
    publicEncryptedSharingModelConstants,
    verifyPublicEncryptedSharingModel,
} from '#tests/public-encrypted-sharing-model.js';

const ternaryValues = [-1n, 0n, 1n] as const;
const maximumTernaryMagnitude = 1n;
const productionRingDegree =
    candidateBgvParameterInputs.polynomialModulusDegree;
const participantCount = candidateBgvParameterInputs.participantCount;

// Every vector in {-1, 0, 1}^length.
const ternaryVectors = (length: number): bigint[][] =>
    length === 0
        ? [[]]
        : ternaryVectors(length - 1).flatMap((prefix) =>
              ternaryValues.map((value) => [...prefix, value]),
          );

// One coefficient of a product in Z[X]/(X^N + 1), where X^N wraps to -1.
const negacyclicCoefficient = (
    left: readonly bigint[],
    right: readonly bigint[],
    index: number,
): bigint => {
    let coefficient = 0n;
    left.forEach((leftValue, leftIndex) => {
        const rightIndex = index - leftIndex;
        coefficient +=
            rightIndex >= 0
                ? leftValue * right[rightIndex]
                : -leftValue * right[rightIndex + right.length];
    });
    return coefficient;
};

// Nearest multiple of the scale, with ties rounding up.
const decode = (value: bigint, scale: bigint): bigint =>
    (2n * value + scale) / (2n * scale);

const binaryDigitCount = (value: bigint): bigint => {
    let digitCount = 0n;
    while (1n << digitCount <= value) digitCount += 1n;
    return digitCount;
};

// Under pk = -a*s + e, the ciphertext (pk*u + e1 + scale*m, a*u + e2)
// decrypts to scale*m plus the noise e*u + e1 + e2*s. Each of the N terms in
// one coefficient of e*u or e2*s has magnitude at most B^2.
const singleCiphertextNoiseBound =
    2n * productionRingDegree * maximumTernaryMagnitude ** 2n +
    maximumTernaryMagnitude;
// A recipient's aggregate adds one such noise per contributor.
const aggregateNoiseBound =
    BigInt(participantCount) * singleCiphertextNoiseBound;

// The first prime p = 1 (mod 2N) with p > 2 * aggregate bound, found by
// scanning every integer above the bound against a sieve of Eratosthenes.
const findEncodingScale = (): bigint => {
    const transformOrder = 2n * productionRingDegree;
    const sieveLimit = Number(4n * aggregateNoiseBound);
    const composite = new Uint8Array(sieveLimit + 1);
    for (let factor = 2; factor * factor <= sieveLimit; factor += 1) {
        if (composite[factor] === 1) continue;
        for (
            let multiple = factor * factor;
            multiple <= sieveLimit;
            multiple += factor
        ) {
            composite[multiple] = 1;
        }
    }
    for (
        let candidate = Number(2n * aggregateNoiseBound) + 1;
        candidate <= sieveLimit;
        candidate += 1
    ) {
        if (
            BigInt(candidate) % transformOrder === 1n &&
            composite[candidate] === 0
        ) {
            return BigInt(candidate);
        }
    }
    throw new Error('The sieve holds no transform prime above the bound.');
};

describe('public encrypted sharing model', () => {
    it('attains the one-ciphertext noise bound exactly over every small ternary ring', () => {
        for (const ringDegree of [1, 2]) {
            let maximumNoiseMagnitude = 0n;
            for (const assignment of ternaryVectors(5 * ringDegree)) {
                const ringElement = (position: number): bigint[] =>
                    assignment.slice(
                        position * ringDegree,
                        (position + 1) * ringDegree,
                    );
                const keyError = ringElement(0);
                const coins = ringElement(1);
                const firstError = ringElement(2);
                const secondError = ringElement(3);
                const secret = ringElement(4);
                for (let index = 0; index < ringDegree; index += 1) {
                    const noise =
                        negacyclicCoefficient(keyError, coins, index) +
                        firstError[index] +
                        negacyclicCoefficient(secondError, secret, index);
                    const magnitude = noise < 0n ? -noise : noise;
                    if (magnitude > maximumNoiseMagnitude) {
                        maximumNoiseMagnitude = magnitude;
                    }
                }
            }
            expect(maximumNoiseMagnitude).toBe(
                2n * BigInt(ringDegree) * maximumTernaryMagnitude ** 2n +
                    maximumTernaryMagnitude,
            );
        }
    });

    it('decodes the attained production worst case and misdecodes it at a scale of twice the bound', () => {
        // With e all ones and u = (1, -1, ..., -1), every term of coefficient
        // zero of e*u is +1, and likewise for e2*s. Every contributor can
        // choose these coins against the same recipient key.
        const ones = Array.from(
            { length: Number(productionRingDegree) },
            () => 1n,
        );
        const aligned = ones.map((_one, index) => (index === 0 ? 1n : -1n));
        const worstSingleNoise =
            negacyclicCoefficient(ones, aligned, 0) +
            1n +
            negacyclicCoefficient(ones, aligned, 0);
        expect(worstSingleNoise).toBe(singleCiphertextNoiseBound);
        const worstAggregateNoise = BigInt(participantCount) * worstSingleNoise;
        const share = 12_345n;
        const scale = findEncodingScale();
        expect(decode(scale * share + worstAggregateNoise, scale)).toBe(share);
        expect(decode(scale * share - worstAggregateNoise, scale)).toBe(share);
        // At a scale of exactly twice the bound the worst case rounds away,
        // so the scale gate must be strict.
        const boundaryScale = 2n * aggregateNoiseBound;
        expect(
            decode(boundaryScale * share + worstAggregateNoise, boundaryScale),
        ).toBe(share + 1n);
    });

    it('derives the production scale and every structural count independently', () => {
        const encodingScale = findEncodingScale();
        // Release needs shares from at least f + 1 participants, for
        // f = floor((n - 1) / 3), and never fewer than 2; the subsets are
        // counted over every roster bit mask with that many members.
        const threshold = Math.max(
            Math.floor((participantCount - 1) / 3) + 1,
            2,
        );
        let authorizedSubsetCount = 0;
        for (let mask = 0; mask < 1 << participantCount; mask += 1) {
            let memberCount = 0;
            for (let bits = mask; bits !== 0; bits &= bits - 1) {
                memberCount += 1;
            }
            if (memberCount === threshold) authorizedSubsetCount += 1;
        }
        const census = verifyPublicEncryptedSharingModel();
        // The toy reuses the production scale, which stays correct at any
        // negacyclic power-of-two degree up to the production degree.
        expect(census.toyRingDegree).toBeGreaterThanOrEqual(2);
        expect(census.toyRingDegree & (census.toyRingDegree - 1)).toBe(0);
        expect(BigInt(census.toyRingDegree)).toBeLessThanOrEqual(
            productionRingDegree,
        );
        expect(census).toEqual({
            aggregateCiphertextsChecked: participantCount,
            authorizedReconstructionSubsetsChecked: authorizedSubsetCount,
            contributorRecipientCiphertextsChecked:
                participantCount * participantCount,
            productionAggregateNoiseCoefficientBound: aggregateNoiseBound,
            productionShareEncodingScale: encodingScale,
            productionShareEncodingScaleBitLength:
                binaryDigitCount(encodingScale),
            productionSingleCiphertextNoiseCoefficientBound:
                singleCiphertextNoiseBound,
            // Adding the scale to a coefficient moves the decoded share by one.
            tamperedCiphertextChangedShare: true,
            toyRingDegree: expect.any(Number) as number,
        });
        expect(publicEncryptedSharingModelConstants).toEqual({
            maximumSmallCoefficientMagnitude: maximumTernaryMagnitude,
            productionAggregateNoiseCoefficientBound: aggregateNoiseBound,
            productionParticipantCount: BigInt(participantCount),
            productionPolynomialModulusDegree: productionRingDegree,
            productionShareEncodingScale: encodingScale,
            productionShareEncodingScaleBitLength:
                binaryDigitCount(encodingScale),
            productionSingleCiphertextNoiseCoefficientBound:
                singleCiphertextNoiseBound,
        });
    });
});
