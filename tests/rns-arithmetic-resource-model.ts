import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';

// Pinned fhe.rs NttOperator owns four N-element u64 tables. Context::new
// constructs every shorter modulus context recursively, without sharing them.
export const compileRnsArithmeticResourceCensus = () => {
    const degree = fixedModulusBfvInputs.polynomialDegree;
    const bits = BigInt(
        fixedModulusBfvInputs.ciphertextModulus.toString(2).length,
    );
    const basePrimes = 15n;
    const multiplicationPrimes = basePrimes + (bits + 60n + 61n) / 62n;
    const tableBytesPerPrime = 4n * degree * 8n;
    const recursiveTableBytes =
        (tableBytesPerPrime *
            multiplicationPrimes *
            (multiplicationPrimes + 1n)) /
        2n;
    const exactProductPrimes = (2n * bits + 16n + 1n + 57n) / 58n;
    const flatTableBytes = tableBytesPerPrime * exactProductPrimes;
    const coefficientWords = (bits + 63n) / 64n;
    const canonicalPolynomialBytes = coefficientWords * 8n * degree;
    const externalProductPrimes = 18n;
    const gadgetLength = 6n;
    const cachedMultiplicationKeyBytes =
        4n * gadgetLength * externalProductPrimes * degree * 8n;
    return {
        degree,
        basePrimes,
        multiplicationPrimes,
        tableBytesPerPrime,
        recursiveTableBytes,
        exactProductPrimes,
        flatTableBytes,
        coefficientWords,
        canonicalPolynomialBytes,
        cachedMultiplicationKeyBytes,
    };
};
