import assert from 'node:assert/strict';

import { integerLimbConvolutionMagnitudeBound } from '#tests/exact-integer-convolution-model.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { setupGaussianParameters } from '#tests/setup-randomness-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';
import type { SupportedProfile } from '#tests/supported-profile-model.js';

// Bounds for b = -a*s + e, with centered a, ||s||_1 <= support and
// |e| <= errorBound. No assumption on the distribution of a or s is used.
export const boundSourceKeyArithmetic = (
    modulus: bigint,
    radix: bigint,
    support: bigint,
    errorBound: bigint,
) => {
    if (
        modulus < 3n ||
        modulus % 2n !== 1n ||
        radix < 2n ||
        (radix & (radix - 1n)) !== 0n ||
        support < 1n ||
        errorBound < 0n ||
        errorBound >= radix
    )
        throw new RangeError('Invalid original-source arithmetic operands.');
    let limbs = 1;
    let leadingScale = 1n;
    while (modulus >= leadingScale * radix) {
        leadingScale *= radix;
        limbs++;
    }
    const leadingModulusDigit = modulus / leadingScale;
    const maximumLimbProduct = support * (radix - 1n);
    const maximumRawLimb = maximumLimbProduct + errorBound;
    const maximumNormalizationCarry = support + 1n;
    const maximumRawInteger = support * (modulus / 2n) + errorBound;
    const maximumPrefix = maximumRawInteger / leadingScale;
    const maximumQuotientEstimate = maximumPrefix / leadingModulusDigit;
    const maximumQuotient = (maximumRawInteger + modulus / 2n) / modulus;
    const maximumWitnessCarry = support + maximumQuotient + 2n;
    const maximumWitnessRow =
        (support + maximumQuotient + 1n) * (radix - 1n) +
        errorBound +
        maximumWitnessCarry;
    return {
        limbs,
        leadingModulusDigit,
        maximumLimbProduct,
        maximumRawLimb,
        maximumNormalizationCarry,
        maximumRawInteger,
        maximumPrefix,
        maximumQuotientEstimate,
        maximumQuotient,
        maximumWitnessCarry,
        maximumWitnessRow,
    };
};

// Checks every value-dependent arithmetic refusal on the scalar original
// source path against its pinned integer, reduction and witness contracts.
// This is not an allocation bound or a proof for other setup equations.
export const compileSourceArithmeticBounds = (profile: SupportedProfile) => {
    const radix = 1n << 96n;
    const support = fixedModulusBfvInputs.secretSupportWeight;
    const errorBound = -BigInt(setupGaussianParameters.minimum);
    const row = boundSourceKeyArithmetic(
        profile.ciphertext.modulus,
        radix,
        support,
        errorBound,
    );
    const transformModulus = compileSmallLimbProofFieldCensus().modulus;
    assert.equal(
        row.maximumLimbProduct,
        integerLimbConvolutionMagnitudeBound(radix, support, transformModulus),
    );
    assert.ok(setupGaussianParameters.minimum >= -(1 << 6));
    assert.ok(setupGaussianParameters.maximum < 1 << 6);
    assert.ok(BigInt(setupGaussianParameters.maximum) <= errorBound);
    assert.ok(row.limbs <= 16);
    assert.ok(row.leadingModulusDigit > 65_536n);
    assert.ok(row.maximumQuotientEstimate < 1n << 16n);
    assert.ok(row.maximumQuotientEstimate < row.leadingModulusDigit);
    assert.ok(row.maximumQuotient < 1n << 15n);
    assert.ok(row.maximumWitnessCarry < 1n << 15n);
    const signedLimit = 1n << 127n;
    assert.ok(row.maximumRawLimb + row.maximumNormalizationCarry < signedLimit);
    assert.ok((row.maximumNormalizationCarry + 1n) * radix - 1n < signedLimit);
    assert.ok(((1n << 16n) - 1n) * row.leadingModulusDigit < signedLimit);
    assert.ok(radix * row.maximumQuotientEstimate < signedLimit);
    assert.ok(row.maximumWitnessRow < signedLimit);
    return row;
};

// num-bigint 0.5.1 normalizes a heap vector's logical length, then changes
// its allocation only when that length is below floor(capacity / 2).
// This counts that predicate on uniform centered residues. Uniformity is
// a separate premise, not a property of arbitrary ciphertext coefficients.
export const normalizationShrinkResidues = (
    modulus: bigint,
    digitBits: number,
    capacity: number,
) => {
    if (
        modulus < 3n ||
        modulus % 2n !== 1n ||
        !Number.isSafeInteger(digitBits) ||
        digitBits < 1 ||
        digitBits > 64 ||
        !Number.isSafeInteger(capacity) ||
        capacity < 2
    )
        throw new RangeError(
            'Invalid centered-coefficient allocation operands.',
        );
    const shrinkMagnitudeBits =
        BigInt(digitBits) * (BigInt(capacity) / 2n - 1n);
    const smallResidues = (1n << (shrinkMagnitudeBits + 1n)) - 1n;
    return {
        shrinkMagnitudeBits,
        affectedResidues: smallResidues < modulus ? smallResidues : modulus,
    };
};

// Scalar from_digits packs each 96-bit FHE limb into u32 words and reserves
// one final word. The pinned Rust RawVec retains that requested capacity.
// b[0] has uniform coefficient marginals only after independent source
// randomness and uniform common-polynomial comparisons have been justified.
export const compileSourceCoefficientAllocation = (
    profile: SupportedProfile,
) => {
    const modulus = profile.ciphertext.modulus;
    const modulusBits = modulus.toString(2).length;
    const constructorWords = 3 * Math.ceil(modulusBits / 96) + 1;
    const { shrinkMagnitudeBits, affectedResidues } =
        normalizationShrinkResidues(modulus, 32, constructorWords);
    const coefficientCount = fixedModulusBfvInputs.polynomialDegree;
    const unionNumerator = coefficientCount * affectedResidues;
    let exceptionBits = 0n;
    while (unionNumerator << (exceptionBits + 1n) <= modulus) exceptionBits++;
    return {
        modulus,
        modulusBits,
        constructorWords,
        shrinkMagnitudeBits,
        coefficientCount,
        unionNumerator,
        exceptionBits,
    };
};
