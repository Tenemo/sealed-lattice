import { describe, expect, it } from 'vitest';

import { compileBoundedIntegerSharingPrivacyCensus } from '#tests/bounded-integer-sharing-privacy-model.js';
import { candidateBgvParameterInputs } from '#tests/candidate-bgv-parameter-model.js';
import { publicEncryptedSharingModelConstants } from '#tests/public-encrypted-sharing-model.js';

const polynomialModulusDegree =
    candidateBgvParameterInputs.polynomialModulusDegree;
const participantCount = BigInt(candidateBgvParameterInputs.participantCount);
// n >= 3f + 1 participants tolerate f = floor((n - 1) / 3) corrupt ones.
const maximumCorruptParticipantCount = (participantCount - 1n) / 3n;
// HLS25 Section 5.1 samples secrets from the uniform ternary distribution, so
// a share secret has coefficients of magnitude at most 1 and two secrets
// differ by at most 2 in each coefficient.
const ternaryCoefficientBound = 1n;
const secretDifferenceCoefficientMagnitude = 2n * ternaryCoefficientBound;
// Design operands of the sharing construction: participants evaluate at the
// monomials Z^j of the reduced ring Z[Z]/(Z^8 + 1), the privacy target is
// 2^-96 statistical distance, and the plaintext prime has the form m 2^64 + 1.
const reducedRingDegree = 8;
const statisticalPrivacyBitLength = 96n;
const sharePlaintextTransformExponent = 64n;

const absolute = (value: bigint): bigint => (value < 0n ? -value : value);
const maximum = (left: bigint, right: bigint): bigint =>
    left > right ? left : right;

const modularPower = (
    base: bigint,
    exponent: bigint,
    modulus: bigint,
): bigint => {
    let result = 1n;
    let square = base % modulus;
    for (let remaining = exponent; remaining > 0n; remaining /= 2n) {
        if (remaining % 2n === 1n) result = (result * square) % modulus;
        square = (square * square) % modulus;
    }
    return result;
};

const binomialCoefficient = (setSize: bigint, subsetSize: bigint): bigint => {
    let result = 1n;
    for (let index = 0n; index < subsetSize; index += 1n) {
        result = (result * (setSize - index)) / (index + 1n);
    }
    return result;
};

const ceilingLog2 = (value: bigint): bigint => {
    let exponent = 0n;
    while (1n << exponent < value) exponent += 1n;
    return exponent;
};

const twoAdicValuation = (value: bigint): bigint => {
    let valuation = 0n;
    while ((value >> valuation) % 2n === 0n) valuation += 1n;
    return valuation;
};

// The smallest number of bits that holds value, found by exact shifts.
const bitLengthByShifting = (value: bigint): bigint => {
    let bitLength = 0n;
    while (value >> bitLength > 0n) bitLength += 1n;
    return bitLength;
};

// X^exponent times vector in Z[X]/(X^degree + 1): a cyclic shift in which
// every wrap past the degree flips the sign, because X^degree = -1.
const multiplyByMonomial = (
    vector: readonly bigint[],
    exponent: number,
): bigint[] => {
    const degree = vector.length;
    const reducedExponent =
        ((exponent % (2 * degree)) + 2 * degree) % (2 * degree);
    const result = Array.from({ length: degree }, () => 0n);
    vector.forEach((coefficient, index) => {
        const shiftedIndex = index + reducedExponent;
        result[shiftedIndex % degree] =
            Math.floor(shiftedIndex / degree) % 2 === 0
                ? coefficient
                : -coefficient;
    });
    return result;
};

// The vanishing basis prod_{i in S} (1 - Z^-i Y) has, as its Y^k coefficient,
// (-1)^k times the sum of Z^-sum(T) over the k-subsets T of S. This expands
// those elementary symmetric sums directly instead of multiplying factors.
const nonconstantBasisMonomialExponents = (
    corruptPositions: readonly number[],
): number[][] => {
    const exponentsByDegree = corruptPositions.map((): number[] => []);
    for (
        let subsetMask = 1;
        subsetMask < 1 << corruptPositions.length;
        subsetMask += 1
    ) {
        const subset = corruptPositions.filter(
            (_position, index) => (subsetMask & (1 << index)) !== 0,
        );
        exponentsByDegree[subset.length - 1].push(
            -subset.reduce((sum, position) => sum + position, 0),
        );
    }
    return exponentsByDegree;
};

// The sum over nonconstant basis coefficients of the one-norm of that
// coefficient times vector. Signs of whole coefficients cannot change it.
const translationOneNorm = (
    exponentsByDegree: readonly (readonly number[])[],
    vector: readonly bigint[],
): bigint =>
    exponentsByDegree.reduce((total, exponents) => {
        const product = Array.from({ length: vector.length }, () => 0n);
        for (const exponent of exponents) {
            multiplyByMonomial(vector, exponent).forEach((value, index) => {
                product[index] += value;
            });
        }
        return (
            total +
            product.reduce(
                (sum, coefficient) => sum + absolute(coefficient),
                0n,
            )
        );
    }, 0n);

const enumerateReducedRingViewMaxima = (): Readonly<{
    corruptSubsetCount: bigint;
    maximumBasisNonconstantOneNorm: bigint;
    maximumBlockTranslationOneNorm: bigint;
}> => {
    const unitVector = Array.from(
        { length: reducedRingDegree },
        (_unused, index) => (index === 0 ? 1n : 0n),
    );
    // Negating a vector keeps every one-norm, so the first sign stays positive.
    const signVectors = Array.from(
        { length: 1 << (reducedRingDegree - 1) },
        (_unused, signMask) =>
            Array.from({ length: reducedRingDegree }, (_unused2, index) =>
                index > 0 && (signMask & (1 << (index - 1))) !== 0 ? -1n : 1n,
            ),
    );
    let corruptSubsetCount = 0n;
    let maximumBasisNonconstantOneNorm = 0n;
    let maximumUnitSignTranslationOneNorm = 0n;
    for (
        let corruptMask = 0;
        corruptMask < 1 << Number(participantCount);
        corruptMask += 1
    ) {
        const corruptPositions = Array.from(
            { length: Number(participantCount) },
            (_unused, position) => position,
        ).filter((position) => (corruptMask & (1 << position)) !== 0);
        if (BigInt(corruptPositions.length) > maximumCorruptParticipantCount) {
            continue;
        }
        corruptSubsetCount += 1n;
        const exponentsByDegree =
            nonconstantBasisMonomialExponents(corruptPositions);
        maximumBasisNonconstantOneNorm = maximum(
            maximumBasisNonconstantOneNorm,
            translationOneNorm(exponentsByDegree, unitVector),
        );
        for (const signVector of signVectors) {
            maximumUnitSignTranslationOneNorm = maximum(
                maximumUnitSignTranslationOneNorm,
                translationOneNorm(exponentsByDegree, signVector),
            );
        }
    }
    return {
        corruptSubsetCount,
        maximumBasisNonconstantOneNorm,
        // A one-norm of a linear image is convex, so its maximum over the
        // difference box [-2, 2]^8 sits at a vertex, which is twice a sign
        // vector.
        maximumBlockTranslationOneNorm:
            secretDifferenceCoefficientMagnitude *
            maximumUnitSignTranslationOneNorm,
    };
};

const reducedRingViewMaxima = enumerateReducedRingViewMaxima();

// Production evaluates at X^(stride j) with stride N / 8. Basis coefficients
// then preserve the stride residue classes of a ring element, and each class
// is one copy of the reduced ring, so the production maximum is the reduced
// maximum times the class count. The hybrid translates every contribution.
const reducedRingBlockCount =
    polynomialModulusDegree / BigInt(reducedRingDegree);
const maximumHybridTranslationOneNorm =
    participantCount *
    reducedRingBlockCount *
    reducedRingViewMaxima.maximumBlockTranslationOneNorm;
// Shifting a uniform variable on [-B, B] by t moves it |t| / (2B + 1) in
// statistical distance, so a translation of one-norm T costs at most
// T / (2B + 1). That is at most 2^-96 exactly when 2B + 1 >= T 2^96.
const requiredSamplingDenominator =
    maximumHybridTranslationOneNorm << statisticalPrivacyBitLength;
const coefficientSamplingBound =
    1n << (ceilingLog2(requiredSamplingDenominator - 1n) - 1n);
// Release needs max(f + 1, 2) shares, so the sharing polynomial has one
// fewer masking coefficient. Monomial evaluation points permute coefficients
// up to sign, so each masking coefficient adds at most B to a share
// coefficient.
const releaseThreshold =
    maximumCorruptParticipantCount + 1n > 2n
        ? maximumCorruptParticipantCount + 1n
        : 2n;
const perContributionShareCoefficientBound =
    ternaryCoefficientBound +
    (releaseThreshold - 1n) * coefficientSamplingBound;
const sharePlaintextMinimumSpan =
    2n * participantCount * perContributionShareCoefficientBound + 1n;

describe('bounded integer sharing privacy model', () => {
    const census = compileBoundedIntegerSharingPrivacyCensus();

    it('checks every corrupt view up to the Byzantine bound', () => {
        let closedFormSubsetCount = 0n;
        for (
            let subsetSize = 0n;
            subsetSize <= maximumCorruptParticipantCount;
            subsetSize += 1n
        ) {
            closedFormSubsetCount += binomialCoefficient(
                participantCount,
                subsetSize,
            );
        }
        expect(reducedRingViewMaxima.corruptSubsetCount).toBe(
            closedFormSubsetCount,
        );
        expect(BigInt(census.corruptSubsetsChecked)).toBe(
            closedFormSubsetCount,
        );
    });

    it('matches a direct expansion of every vanishing basis', () => {
        // Each Y^k coefficient sums C(f, k) signed monomials, so the triangle
        // inequality caps the nonconstant one-norm at 2^f - 1. Corrupt sets
        // whose monomials never cancel attain it.
        expect(reducedRingViewMaxima.maximumBasisNonconstantOneNorm).toBe(
            (1n << maximumCorruptParticipantCount) - 1n,
        );
        expect(census.maximumBasisNonconstantOneNorm).toBe(
            reducedRingViewMaxima.maximumBasisNonconstantOneNorm,
        );
        expect(census.maximumBlockTranslationOneNorm).toBe(
            reducedRingViewMaxima.maximumBlockTranslationOneNorm,
        );
    });

    it('lifts the reduced-ring maximum to production and every contribution', () => {
        expect(census.productionInterpolationPointExponentStride).toBe(
            reducedRingBlockCount,
        );
        expect(census.reducedRingBlockCount).toBe(reducedRingBlockCount);
        expect(census.maximumProductionTranslationOneNormPerContribution).toBe(
            reducedRingBlockCount *
                reducedRingViewMaxima.maximumBlockTranslationOneNorm,
        );
        expect(census.maximumHybridTranslationOneNorm).toBe(
            maximumHybridTranslationOneNorm,
        );
    });

    it('takes the smallest power-of-two sampling bound that meets the privacy target', () => {
        expect(census.statisticalPrivacyBitLength).toBe(
            statisticalPrivacyBitLength,
        );
        expect(census.coefficientSamplingBound).toBe(coefficientSamplingBound);
        expect(2n * coefficientSamplingBound + 1n).toBeGreaterThanOrEqual(
            requiredSamplingDenominator,
        );
        // Half the bound would give 2 (B / 2) + 1 = B + 1, which falls short.
        expect(coefficientSamplingBound + 1n).toBeLessThan(
            requiredSamplingDenominator,
        );
    });

    it('bounds share coefficients by the ternary secret plus every masking term', () => {
        expect(census.perContributionShareCoefficientBound).toBe(
            perContributionShareCoefficientBound,
        );
        expect(census.aggregateShareCoefficientBound).toBe(
            participantCount * perContributionShareCoefficientBound,
        );
        expect(census.sharePlaintextMinimumSpan).toBe(
            sharePlaintextMinimumSpan,
        );
        expect(census.sharePlaintextSpanBitLength).toBe(
            bitLengthByShifting(sharePlaintextMinimumSpan),
        );
    });

    it('certifies the share plaintext modulus as the first Proth prime above the span', () => {
        const transformFactor = 1n << sharePlaintextTransformExponent;
        // The smallest odd multiplier whose Proth number reaches the span.
        let firstMultiplier =
            (sharePlaintextMinimumSpan - 1n + transformFactor - 1n) /
            transformFactor;
        if (firstMultiplier % 2n === 0n) firstMultiplier += 1n;
        expect(firstMultiplier * transformFactor + 1n).toBeGreaterThanOrEqual(
            sharePlaintextMinimumSpan,
        );
        expect((firstMultiplier - 2n) * transformFactor + 1n).toBeLessThan(
            sharePlaintextMinimumSpan,
        );
        const multiplier = census.sharePlaintextPrimeMultiplier;
        const modulus = census.sharePlaintextModulus;
        expect(modulus).toBe(multiplier * transformFactor + 1n);
        expect(modulus).toBeGreaterThanOrEqual(sharePlaintextMinimumSpan);
        // Proth: m 2^k + 1 with m odd and m < 2^k is prime when some a has
        // a^((p - 1) / 2) = -1 modulo p. The modulus is 1 modulo 8, so 2 is a
        // quadratic residue and never certifies. It is 2 modulo 3, so by
        // quadratic reciprocity 3 is a nonresidue and certifies it.
        expect(multiplier % 2n).toBe(1n);
        expect(multiplier).toBeLessThan(transformFactor);
        expect(modulus % 8n).toBe(1n);
        expect(modulus % 3n).toBe(2n);
        expect(modularPower(3n, (modulus - 1n) / 2n, modulus)).toBe(
            modulus - 1n,
        );
        expect(census.sharePlaintextPrimeWitness).toBe(3n);
        // Every skipped odd multiplier fails a base-3 Fermat test, which
        // proves its Proth number composite, so no smaller prime was missed.
        const unrefutedSkippedMultipliers: bigint[] = [];
        for (
            let skipped = firstMultiplier;
            skipped < multiplier;
            skipped += 2n
        ) {
            const candidate = skipped * transformFactor + 1n;
            if (modularPower(3n, candidate - 1n, candidate) === 1n) {
                unrefutedSkippedMultipliers.push(skipped);
            }
        }
        expect(unrefutedSkippedMultipliers).toEqual([]);
        expect(census.sharePlaintextPrimeCandidateCount).toBe(
            (multiplier - firstMultiplier) / 2n + 1n,
        );
        expect(census.sharePlaintextTransformExponent).toBe(
            twoAdicValuation(modulus - 1n),
        );
        expect(census.sharePlaintextTransformExponent).toBe(
            sharePlaintextTransformExponent,
        );
        expect((modulus - 1n) % (2n * polynomialModulusDegree)).toBe(0n);
        expect(census.sharePlaintextModulusBitLength).toBe(
            bitLengthByShifting(modulus),
        );
    });

    it('scales the plaintext prime by the separately derived encoding scale', () => {
        const shareEncryptionModulus =
            census.sharePlaintextModulus *
            publicEncryptedSharingModelConstants.productionShareEncodingScale;
        expect(census.shareEncryptionModulus).toBe(shareEncryptionModulus);
        expect(census.shareEncryptionModulusBitLength).toBe(
            bitLengthByShifting(shareEncryptionModulus),
        );
    });
});
