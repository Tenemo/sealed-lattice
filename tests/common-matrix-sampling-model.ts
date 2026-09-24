import { auxiliaryInputEncryptionParameters } from '#tests/auxiliary-input-encryption-parameters.js';
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

export function compileCommonMatrixInitializationCensus() {
    const matrix = compileCommonMatrixSamplingCensus();
    // Preserve the previously analysed one-pass fibre sampler's extra width.
    const extraSamplingBits =
        256n + BigInt((matrix.coefficientCount - 1n).toString(2).length);
    const families = [
        {
            name: 'FHE',
            polynomials: matrix.fhePolynomialCount,
            degree: fixedModulusBfvInputs.polynomialDegree,
            modulus: fixedModulusBfvInputs.ciphertextModulus,
        },
        {
            name: 'Sharing',
            polynomials: 1n,
            degree: fixedModulusBfvInputs.polynomialDegree,
            modulus: compileSmallLimbProofFieldCensus().modulus * 998244353n,
        },
        {
            name: 'Auxiliary',
            polynomials: 1n,
            degree: auxiliaryInputEncryptionParameters.degree,
            modulus: auxiliaryInputEncryptionParameters.modulus,
        },
    ].map((family) => {
        const maximumFibreSize =
                ((1n << BigInt(matrix.bitsPerCoefficient)) +
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
                (coefficients * BigInt(matrix.bitsPerCoefficient)) / 8n,
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
    const auxiliaryDegree = auxiliaryInputEncryptionParameters.degree;
    const auxiliaryModulus = auxiliaryInputEncryptionParameters.modulus;
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
