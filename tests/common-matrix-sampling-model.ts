import { auxiliaryInputEncryptionParameters } from '#tests/auxiliary-input-encryption-parameters.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';
import type { SupportedProfile } from '#tests/supported-profile-model.js';

export const uniformWordResidueDistance = (modulus: bigint, bits: number) => {
    if (!Number.isSafeInteger(bits) || bits < 1 || bits > 4096)
        throw new RangeError('Invalid common-matrix sample width.');
    const space = 1n << BigInt(bits);
    if (modulus < 2n || modulus > space)
        throw new RangeError('The sample space does not cover the modulus.');
    const remainder = space % modulus;
    return {
        numerator: remainder * (modulus - remainder),
        denominator: modulus * space,
    };
};

export const boundedResidueFiberWord = (
    modulus: bigint,
    wordBits: bigint,
    residue: bigint,
    randomWord: bigint,
    randomBits: bigint,
) => {
    if (
        wordBits < 1n ||
        wordBits > 4096n ||
        randomBits < 1n ||
        randomBits > 8192n
    )
        throw new RangeError('Invalid finite sampling width.');
    const space = 1n << wordBits;
    if (
        modulus < 2n ||
        modulus > space ||
        residue < 0n ||
        residue >= modulus ||
        randomWord < 0n ||
        randomWord >= 1n << randomBits
    )
        throw new RangeError('Invalid residue-fiber input.');
    const count = (space - 1n - residue) / modulus + 1n;
    return residue + modulus * (randomWord % count);
};

// Every sampled coefficient is a whole number of 64-bit words.
// Registration fixes the common share polynomial before the roster, and so
// the profile, is known. The share and auxiliary families therefore use one
// profile-independent width, the least whose distance is at most half the
// allocation. The FHE width is the least one whose complete distance, with
// those families, is at most 2^-128.
const commonMatrixSampling = {
    wordBits: 64,
    distanceAllocationBits: 128,
} as const;
const sharingModulus = compileSmallLimbProofFieldCensus().modulus * 998244353n;
const auxiliaryPolynomialCount = 2n;
// r(Q-r) <= Q^2/4; tensorization adds the coefficient distances.
const fixedFamilyDistanceNumerator =
    fixedModulusBfvInputs.polynomialDegree * sharingModulus +
    auxiliaryPolynomialCount *
        auxiliaryInputEncryptionParameters.degree *
        auxiliaryInputEncryptionParameters.modulus;
export const fixedFamilyBitsPerCoefficient = (() => {
    let bits: number = commonMatrixSampling.wordBits;
    while (
        fixedFamilyDistanceNumerator <<
            BigInt(commonMatrixSampling.distanceAllocationBits + 1) >
        4n << BigInt(bits)
    )
        bits += commonMatrixSampling.wordBits;
    return bits;
})();

export function compileCommonMatrixInitializationCensus(
    profile: SupportedProfile,
) {
    const matrix = compileCommonMatrixSamplingCensus(profile);
    // Preserve the previously analysed one-pass fibre sampler's extra width.
    const extraSamplingBits =
        256n + BigInt((matrix.coefficientCount - 1n).toString(2).length);
    const families = [
        {
            name: 'FHE',
            polynomials: matrix.fhePolynomialCount,
            degree: fixedModulusBfvInputs.polynomialDegree,
            modulus: profile.ciphertext.modulus,
            bitsPerCoefficient: matrix.fheBitsPerCoefficient,
        },
        {
            name: 'Sharing',
            polynomials: 1n,
            degree: fixedModulusBfvInputs.polynomialDegree,
            modulus: sharingModulus,
            bitsPerCoefficient: fixedFamilyBitsPerCoefficient,
        },
        {
            name: 'Auxiliary',
            polynomials: auxiliaryPolynomialCount,
            degree: auxiliaryInputEncryptionParameters.degree,
            modulus: auxiliaryInputEncryptionParameters.modulus,
            bitsPerCoefficient: fixedFamilyBitsPerCoefficient,
        },
    ].map((family) => {
        const maximumFibreSize =
                ((1n << BigInt(family.bitsPerCoefficient)) +
                    family.modulus -
                    1n) /
                family.modulus,
            randomBitsPerCoefficient =
                BigInt(maximumFibreSize.toString(2).length) + extraSamplingBits,
            coefficients = family.polynomials * family.degree;
        return {
            ...family,
            coefficients,
            maximumFibreSize,
            randomBitsPerCoefficient,
            randomBits: coefficients * randomBitsPerCoefficient,
            randomBytes: coefficients * ((randomBitsPerCoefficient + 7n) / 8n),
            programmedPrefixBytes:
                (coefficients * BigInt(family.bitsPerCoefficient)) / 8n,
        };
    });
    return {
        extraSamplingBits,
        families,
        coefficientCount: matrix.coefficientCount,
        programmedInputs: families.reduce(
            (sum, value) => sum + value.polynomials,
            0n,
        ),
        programmedPrefixBytes: matrix.expandedSampleBytes,
        randomBits: families.reduce((sum, value) => sum + value.randomBits, 0n),
        randomBytes: families.reduce(
            (sum, value) => sum + value.randomBytes,
            0n,
        ),
        biasNumerator: matrix.coefficientCount,
        biasDenominator: 4n << extraSamplingBits,
    };
}

export const compileCommonMatrixSamplingCensus = (
    profile: SupportedProfile,
) => {
    const degree = fixedModulusBfvInputs.polynomialDegree;
    // KLSW setup contains a, u, and one independent gadget vector per
    // automorphism. The current ranking consumes one unit automorphism.
    const fhePolynomialCount = (2n + 1n) * profile.gadgetLength;
    const auxiliaryDegree = auxiliaryInputEncryptionParameters.degree;
    const coefficientCount =
        fhePolynomialCount * degree +
        degree +
        auxiliaryPolynomialCount * auxiliaryDegree;
    const fheDistanceNumerator =
        fhePolynomialCount * degree * profile.ciphertext.modulus;
    const fixedBits = BigInt(fixedFamilyBitsPerCoefficient);
    // Over the common denominator 4*2^(fheBits+fixedBits).
    const completeNumerator = (fheBits: number) =>
        (fheDistanceNumerator << fixedBits) +
        (fixedFamilyDistanceNumerator << BigInt(fheBits));
    let fheBitsPerCoefficient: number = commonMatrixSampling.wordBits;
    while (
        completeNumerator(fheBitsPerCoefficient) <<
            BigInt(commonMatrixSampling.distanceAllocationBits) >
        4n << (BigInt(fheBitsPerCoefficient) + fixedBits)
    )
        fheBitsPerCoefficient += commonMatrixSampling.wordBits;
    const distanceUpperNumerator = completeNumerator(fheBitsPerCoefficient);
    const distanceUpperDenominator =
        4n << (BigInt(fheBitsPerCoefficient) + fixedBits);
    let distanceBits = 0;
    while (
        distanceUpperNumerator << BigInt(distanceBits + 1) <=
        distanceUpperDenominator
    )
        distanceBits++;
    return {
        fheBitsPerCoefficient,
        fixedFamilyBitsPerCoefficient,
        fhePolynomialCount,
        coefficientCount,
        expandedSampleBytes:
            (fhePolynomialCount * degree * BigInt(fheBitsPerCoefficient) +
                (degree + auxiliaryPolynomialCount * auxiliaryDegree) *
                    fixedBits) /
            8n,
        distanceUpperNumerator,
        distanceUpperDenominator,
        distanceBits,
    };
};
