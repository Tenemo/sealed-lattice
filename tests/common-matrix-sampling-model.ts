import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';

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

export const compileCommonMatrixSamplingCensus = () => {
    const bitsPerCoefficient = 1024;
    const degree = fixedModulusBfvInputs.polynomialDegree;
    let gadgetLength = 0n;
    for (
        let covered = 1n;
        covered < fixedModulusBfvInputs.ciphertextModulus;
        covered *= fixedModulusBfvInputs.gadgetBase
    )
        gadgetLength++;
    // KLSW setup contains a, u, and one independent gadget vector per
    // automorphism. The current ranking consumes one unit automorphism.
    const fhePolynomialCount = (2n + 1n) * gadgetLength;
    const sharingModulus =
        compileSmallLimbProofFieldCensus().modulus * 998244353n;
    const auxiliaryDegree = 4096n;
    const auxiliaryModulus = 257n * 101n * (1n << 20n) + 1n;
    const coefficientCount =
        fhePolynomialCount * degree + degree + auxiliaryDegree;
    const distanceUpperNumerator =
        fhePolynomialCount * degree * fixedModulusBfvInputs.ciphertextModulus +
        degree * sharingModulus +
        auxiliaryDegree * auxiliaryModulus;
    // r(Q-r) <= Q^2/4; tensorization adds the coefficient distances.
    const distanceUpperDenominator = 4n << BigInt(bitsPerCoefficient);
    let distanceBits = 0;
    while (
        distanceUpperNumerator << BigInt(distanceBits + 1) <=
        distanceUpperDenominator
    )
        distanceBits++;
    return {
        bitsPerCoefficient,
        fhePolynomialCount,
        coefficientCount,
        expandedSampleBytes: coefficientCount * BigInt(bitsPerCoefficient / 8),
        distanceUpperNumerator,
        distanceUpperDenominator,
        distanceBits,
    };
};
