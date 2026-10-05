import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import type { SupportedProfile } from '#tests/supported-profile-model.js';

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
