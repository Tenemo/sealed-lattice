import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import type { SupportedProfile } from '#tests/supported-profile-model.js';

const transformPrimeBits = 58n;
const transformPrimeShift = 32n;

const modularPower = (
    base: bigint,
    exponent: bigint,
    modulus: bigint,
): bigint => {
    let result = 1n;
    let factor = base % modulus;
    for (let remaining = exponent; remaining > 0n; remaining >>= 1n) {
        if ((remaining & 1n) === 1n) result = (result * factor) % modulus;
        factor = (factor * factor) % modulus;
    }
    return result;
};

// The exact arithmetic's transform primes in the order it takes them: the
// decreasing numbers odd * 2^32 + 1 below 2^58 that Proth's theorem
// certifies with witness three.
const transformPrimes: bigint[] = [];
const transformPrime = (index: number): bigint => {
    while (transformPrimes.length <= index) {
        const below =
            transformPrimes[transformPrimes.length - 1] ??
            1n << transformPrimeBits;
        let odd = (((below - 1n) >> transformPrimeShift) - 1n) | 1n;
        for (; ; odd -= 2n) {
            const candidate = (odd << transformPrimeShift) + 1n;
            if (
                candidate < below &&
                modularPower(3n, (candidate - 1n) / 2n, candidate) ===
                    candidate - 1n
            ) {
                transformPrimes.push(candidate);
                break;
            }
        }
    }
    return transformPrimes[index];
};
export const researchTransformPrime = transformPrime;

// The least number of leading transform primes whose product exceeds a
// centered bound, from which an exact product lifts.
const primeCount = (bound: bigint): bigint => {
    let product = 1n;
    for (let index = 0; ; index++) {
        product *= transformPrime(index);
        if (product > bound) return BigInt(index + 1);
    }
};

// Pinned fhe.rs NttOperator owns four N-element u64 tables. Context::new
// constructs every shorter modulus context recursively, without sharing them.
export const compileRnsArithmeticResourceCensus = (
    profile: SupportedProfile,
) => {
    const degree = fixedModulusBfvInputs.polynomialDegree;
    const modulus = profile.ciphertext.modulus;
    const bits = BigInt(modulus.toString(2).length);
    const basePrimes = 15n;
    const multiplicationPrimes = basePrimes + (bits + 60n + 61n) / 62n;
    const tableBytesPerPrime = 4n * degree * 8n;
    const recursiveTableBytes =
        (tableBytesPerPrime *
            multiplicationPrimes *
            (multiplicationPrimes + 1n)) /
        2n;
    // Ciphertext tensors bound each coefficient by N times the square of
    // half the modulus, and gadget external products by N times the gadget
    // length, the largest digit and half the modulus; each bound is doubled
    // to lift centered values.
    const half = modulus / 2n;
    const gadgetLength = profile.gadgetLength;
    const exactProductPrimes = primeCount(2n * degree * half * half);
    const externalProductPrimes = primeCount(
        2n *
            gadgetLength *
            degree *
            (fixedModulusBfvInputs.gadgetBase - 1n) *
            half,
    );
    const flatTableBytes = tableBytesPerPrime * exactProductPrimes;
    const coefficientWords = (bits + 63n) / 64n;
    const canonicalPolynomialBytes = coefficientWords * 8n * degree;
    const cachedMultiplicationKeyBytes =
        4n * gadgetLength * externalProductPrimes * degree * 8n;
    return {
        degree,
        basePrimes,
        multiplicationPrimes,
        tableBytesPerPrime,
        recursiveTableBytes,
        exactProductPrimes,
        externalProductPrimes,
        flatTableBytes,
        coefficientWords,
        canonicalPolynomialBytes,
        cachedMultiplicationKeyBytes,
    };
};
