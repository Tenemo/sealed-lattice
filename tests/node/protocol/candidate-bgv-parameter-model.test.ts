import { describe, expect, it } from 'vitest';

import {
    candidateBgvParameterInputs,
    compileCandidateBgvParameterCensus,
    validateBgvModulusPrimeInventory,
} from '#tests/candidate-bgv-parameter-model.js';

type BgvModulusPrimeInventory = Parameters<
    typeof validateBgvModulusPrimeInventory
>[0];

const auxiliaryModulusPrimeFactors =
    candidateBgvParameterInputs.auxiliaryModulusPrimeFactors;
const ciphertextModulusPrimeFactors =
    candidateBgvParameterInputs.ciphertextModulusPrimeFactors;
const retainedBottomPrimeCount =
    candidateBgvParameterInputs.retainedBottomPrimeCount;

// HLS25 Table 1 (Params II) evaluates over the ring degree N = 2^15. A
// negacyclic transform of that degree needs roots of unity of order 2N.
const polynomialModulusDegree = 2n ** 15n;
const transformOrder = 2n * polynomialModulusDegree;

// The layout retains three primes near 2^55, spends one prime near 2^34 on
// each consumed level, and reserves two auxiliary primes near 2^60.
const retainedPrimeNominalBitLength = 55n;
const levelPrimeNominalBitLength = 34n;
const auxiliaryPrimeNominalBitLength = 60n;

const notPrimeMessage = 'A modulus prime factor is not prime.';

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

const isPrimeByTrialDivision = (value: bigint): boolean => {
    if (value < 2n) return false;
    if (value % 2n === 0n) return value === 2n;
    for (let divisor = 3n; divisor * divisor <= value; divisor += 2n) {
        if (value % divisor === 0n) return false;
    }
    return true;
};

const firstPrimes = (count: number): bigint[] => {
    const primes: bigint[] = [];
    for (let candidate = 2n; primes.length < count; candidate += 1n) {
        if (isPrimeByTrialDivision(candidate)) primes.push(candidate);
    }
    return primes;
};

const firstTwelvePrimes = firstPrimes(12);

// One strong-probable-prime round. The test uses it only to certify that a
// hostile composite really passes the named bases.
const isStrongProbablePrime = (value: bigint, base: bigint): boolean => {
    let oddPart = value - 1n;
    let twoAdicValuation = 0n;
    while (oddPart % 2n === 0n) {
        oddPart /= 2n;
        twoAdicValuation += 1n;
    }
    let power = modularPower(base, oddPart, value);
    if (power === 1n) return true;
    for (let squaring = 0n; squaring < twoAdicValuation; squaring += 1n) {
        if (power === value - 1n) return true;
        power = (power * power) % value;
    }
    return false;
};

const countLeadingStrongProbablePrimeBases = (value: bigint): number => {
    const firstFailure = firstTwelvePrimes.findIndex(
        (base) => !isStrongProbablePrime(value, base),
    );
    return firstFailure === -1 ? firstTwelvePrimes.length : firstFailure;
};

const distinctPrimeFactorsByTrialDivision = (value: bigint): bigint[] => {
    const primeFactors: bigint[] = [];
    let remaining = value;
    for (let divisor = 2n; divisor * divisor <= remaining; divisor += 1n) {
        if (remaining % divisor !== 0n) continue;
        primeFactors.push(divisor);
        while (remaining % divisor === 0n) remaining /= divisor;
    }
    if (remaining > 1n) primeFactors.push(remaining);
    return primeFactors;
};

// Lucas: a witness whose order modulo value is exactly value - 1 proves that
// value is prime. This is a different theorem from Miller-Rabin.
const hasLucasPrimalityCertificate = (value: bigint): boolean => {
    const orderPrimeFactors = distinctPrimeFactorsByTrialDivision(value - 1n);
    for (let witness = 2n; witness <= 100n; witness += 1n) {
        if (modularPower(witness, value - 1n, value) !== 1n) return false;
        if (
            orderPrimeFactors.every(
                (primeFactor) =>
                    modularPower(witness, (value - 1n) / primeFactor, value) !==
                    1n,
            )
        ) {
            return true;
        }
    }
    return false;
};

const ceilingLog2 = (value: bigint): bigint => {
    let exponent = 0n;
    while (1n << exponent < value) exponent += 1n;
    return exponent;
};

const product = (values: readonly bigint[]): bigint =>
    values.reduce((result, value) => result * value, 1n);

// The cofactor left after dividing out every divisor exactly once, or
// undefined as soon as one division is inexact.
const cofactorAfterExactDivision = (
    value: bigint,
    divisors: readonly bigint[],
): bigint | undefined =>
    divisors.reduce<bigint | undefined>(
        (remaining, divisor) =>
            remaining !== undefined && remaining % divisor === 0n
                ? remaining / divisor
                : undefined,
        value,
    );

const expectBinade = (value: bigint, exponent: bigint): void => {
    expect(value).toBeGreaterThanOrEqual(1n << exponent);
    expect(value).toBeLessThan(1n << (exponent + 1n));
};

const inventoryWithCiphertextFactors = (
    ciphertextFactors: readonly bigint[],
): BgvModulusPrimeInventory => ({
    auxiliaryModulusPrimeFactors,
    ciphertextModulusPrimeFactors: ciphertextFactors,
    polynomialModulusDegree,
});

// With degree one the transform congruence only asks for an odd factor, which
// isolates the primality decision from the residue class of the factor.
const degreeOneInventory = (factor: bigint): BgvModulusPrimeInventory => ({
    auxiliaryModulusPrimeFactors: [],
    ciphertextModulusPrimeFactors: [factor],
    polynomialModulusDegree: 1n,
});

describe('candidate BGV parameter model', () => {
    it('pins the HLS25 ring degree and one ciphertext prime per consumed level', () => {
        // The ranking graph evaluates its comparison polynomial by
        // Paterson-Stockmeyer with 24 baby steps. The polynomial covers the
        // supported twenty ballots of scores 1 to 10, so total differences lie
        // in [-180, 180] and it has degree 360. Baby steps reach depth
        // ceil(log2 24) = 5, giant steps up to (x^24)^15 add ceil(log2 15) = 4,
        // each block times its giant step adds 1, and raising the ranks to
        // powers up to optionCount - 1 = 9 adds ceil(log2 9) = 4.
        const comparisonPolynomialDegree = 2n * 9n * 20n;
        const babyStepCount = 24n;
        const multiplicativeDepth =
            ceilingLog2(babyStepCount) +
            ceilingLog2(comparisonPolynomialDegree / babyStepCount) +
            1n +
            ceilingLog2(BigInt(candidateBgvParameterInputs.optionCount) - 1n);
        const census = compileCandidateBgvParameterCensus();
        expect(census.polynomialModulusDegree).toBe(polynomialModulusDegree);
        expect(census.multiplicativeDepth).toBe(multiplicativeDepth);
        expect(census.ciphertextModulusLimbCount).toBe(
            retainedBottomPrimeCount + multiplicativeDepth,
        );
        expect(BigInt(ciphertextModulusPrimeFactors.length)).toBe(
            retainedBottomPrimeCount + multiplicativeDepth,
        );
    });

    it('recovers each modulus as the exact product of its pinned primes', () => {
        const census = compileCandidateBgvParameterCensus();
        expect(
            cofactorAfterExactDivision(
                census.ciphertextModulus,
                ciphertextModulusPrimeFactors,
            ),
        ).toBe(1n);
        expect(
            cofactorAfterExactDivision(
                census.auxiliaryModulus,
                auxiliaryModulusPrimeFactors,
            ),
        ).toBe(1n);
        expect(
            cofactorAfterExactDivision(census.combinedModulus, [
                ...ciphertextModulusPrimeFactors,
                ...auxiliaryModulusPrimeFactors,
            ]),
        ).toBe(1n);
    });

    it('derives each modulus bit length from the nominal prime sizes', () => {
        const retainedFactors = ciphertextModulusPrimeFactors.slice(
            0,
            Number(retainedBottomPrimeCount),
        );
        const levelFactors = ciphertextModulusPrimeFactors.slice(
            Number(retainedBottomPrimeCount),
        );
        const nominalFactorGroups: readonly Readonly<{
            factors: readonly bigint[];
            nominalBitLength: bigint;
        }>[] = [
            {
                factors: retainedFactors,
                nominalBitLength: retainedPrimeNominalBitLength,
            },
            {
                factors: levelFactors,
                nominalBitLength: levelPrimeNominalBitLength,
            },
            {
                factors: auxiliaryModulusPrimeFactors,
                nominalBitLength: auxiliaryPrimeNominalBitLength,
            },
        ];
        for (const { factors, nominalBitLength } of nominalFactorGroups) {
            for (const factor of factors) {
                const offset = factor - (1n << nominalBitLength);
                expect(offset < 0n ? -offset : offset).toBeLessThan(
                    1n << (nominalBitLength - 10n),
                );
            }
        }
        // A product whose nominal exponents sum to E has bit length E + 1
        // exactly when it lies in [2^E, 2^(E + 1)).
        const retainedExponent =
            BigInt(retainedFactors.length) * retainedPrimeNominalBitLength;
        const ciphertextExponent =
            retainedExponent +
            BigInt(levelFactors.length) * levelPrimeNominalBitLength;
        const auxiliaryExponent =
            BigInt(auxiliaryModulusPrimeFactors.length) *
            auxiliaryPrimeNominalBitLength;
        const census = compileCandidateBgvParameterCensus();
        expectBinade(product(retainedFactors), retainedExponent);
        expect(census.retainedBottomModulusBitLength).toBe(
            retainedExponent + 1n,
        );
        expectBinade(census.ciphertextModulus, ciphertextExponent);
        expect(census.ciphertextModulusBitLength).toBe(ciphertextExponent + 1n);
        expectBinade(census.auxiliaryModulus, auxiliaryExponent);
        expect(census.auxiliaryModulusBitLength).toBe(auxiliaryExponent + 1n);
        expectBinade(
            census.combinedModulus,
            ciphertextExponent + auxiliaryExponent,
        );
        expect(census.combinedModulusBitLength).toBe(
            ciphertextExponent + auxiliaryExponent + 1n,
        );
    });

    it('accepts the pinned inventory, whose primes carry Lucas certificates', () => {
        const factors = [
            ...auxiliaryModulusPrimeFactors,
            ...ciphertextModulusPrimeFactors,
        ];
        expect(
            factors.filter((factor) => !hasLucasPrimalityCertificate(factor)),
        ).toEqual([]);
        expect(
            factors.filter((factor) => (factor - 1n) % transformOrder !== 0n),
        ).toEqual([]);
        const ascendingFactors = [...factors].sort((left, right) =>
            left < right ? -1 : left > right ? 1 : 0,
        );
        expect(
            ascendingFactors.filter(
                (factor, index) =>
                    index > 0 && ascendingFactors[index - 1] === factor,
            ),
        ).toEqual([]);
        expect(() =>
            validateBgvModulusPrimeInventory(candidateBgvParameterInputs),
        ).not.toThrow();
    });

    it('agrees with a sieve on every odd factor below ten thousand', () => {
        const sieveLimit = 10_000;
        const isSievedPrime = Array.from(
            { length: sieveLimit },
            (_unused, value) => value >= 2,
        );
        for (let divisor = 2; divisor * divisor < sieveLimit; divisor += 1) {
            if (!isSievedPrime[divisor]) continue;
            for (
                let multiple = divisor * divisor;
                multiple < sieveLimit;
                multiple += divisor
            ) {
                isSievedPrime[multiple] = false;
            }
        }
        const sievedOddPrimes: number[] = [];
        const acceptedOddFactors: number[] = [];
        const refusalMessages = new Set<string>();
        for (let value = 1; value < sieveLimit; value += 2) {
            if (isSievedPrime[value]) sievedOddPrimes.push(value);
            try {
                validateBgvModulusPrimeInventory(
                    degreeOneInventory(BigInt(value)),
                );
                acceptedOddFactors.push(value);
            } catch (error) {
                if (!(error instanceof Error)) throw error;
                refusalMessages.add(error.message);
            }
        }
        expect(acceptedOddFactors).toEqual(sievedOddPrimes);
        expect([...refusalMessages]).toEqual([notPrimeMessage]);
    });

    it('refuses transform-friendly composites that pass weaker primality tests', () => {
        // Chernick's (6k + 1)(12k + 1)(18k + 1) with three prime factors is a
        // Carmichael number, so every coprime base passes a Fermat test.
        // Taking k as a multiple of 2^14 makes it congruent to 1 modulo 2N.
        const chernickParameter = 84n << 14n;
        const chernickFactors = [6n, 12n, 18n].map(
            (multiplier) => multiplier * chernickParameter + 1n,
        );
        expect(chernickFactors.every(isPrimeByTrialDivision)).toBe(true);
        const carmichaelNumber = product(chernickFactors);
        expect(
            firstTwelvePrimes.filter(
                (base) =>
                    modularPower(
                        base,
                        carmichaelNumber - 1n,
                        carmichaelNumber,
                    ) !== 1n,
            ),
        ).toEqual([]);
        expect(countLeadingStrongProbablePrimeBases(carmichaelNumber)).toBe(0);
        // p(2p - 1) with p congruent to 1 modulo 2N stays congruent to 1. This
        // one passes strong rounds for the first seven prime bases, so only
        // base 19 and later expose it.
        const smallerStrongPseudoprimeFactor = 3_353_685n * transformOrder + 1n;
        const strongPseudoprime =
            smallerStrongPseudoprimeFactor *
            (2n * smallerStrongPseudoprimeFactor - 1n);
        expect(countLeadingStrongProbablePrimeBases(strongPseudoprime)).toBe(7);
        const levelPrimeProduct = product(
            ciphertextModulusPrimeFactors.slice(-2),
        );
        for (const composite of [
            levelPrimeProduct,
            carmichaelNumber,
            strongPseudoprime,
        ]) {
            expect(composite % transformOrder).toBe(1n);
            expect(() =>
                validateBgvModulusPrimeInventory(
                    inventoryWithCiphertextFactors([
                        ...ciphertextModulusPrimeFactors,
                        composite,
                    ]),
                ),
            ).toThrow(notPrimeMessage);
        }
    });

    it('needs each later prime base for composites that pass the earlier ones', () => {
        // Each composite passes strong rounds for exactly the first
        // fooledBaseCount prime bases, so a validation that stopped before the
        // next base would accept it.
        const leadingBaseStrongPseudoprimes = [
            { factors: [23n, 89n], fooledBaseCount: 1 },
            { factors: [829n, 1_657n], fooledBaseCount: 2 },
            { factors: [2_251n, 11_251n], fooledBaseCount: 3 },
            { factors: [151n, 751n, 28_351n], fooledBaseCount: 4 },
            { factors: [6_763n, 10_627n, 29_947n], fooledBaseCount: 5 },
            { factors: [1_303n, 16_927n, 157_543n], fooledBaseCount: 6 },
            { factors: [10_670_053n, 32_010_157n], fooledBaseCount: 8 },
            { factors: [149_491n, 747_451n, 34_233_211n], fooledBaseCount: 11 },
        ];
        for (const {
            factors,
            fooledBaseCount,
        } of leadingBaseStrongPseudoprimes) {
            const composite = product(factors);
            expect(countLeadingStrongProbablePrimeBases(composite)).toBe(
                fooledBaseCount,
            );
            expect(() =>
                validateBgvModulusPrimeInventory(degreeOneInventory(composite)),
            ).toThrow(notPrimeMessage);
        }
    });

    it('refuses factors at or above a composite that all twelve bases pass', () => {
        // This composite passes a strong round for every prime base up to 37,
        // so twelve bases cannot certify a factor at or above it.
        const twelveBaseStrongPseudoprime = 399_165_290_221n * 798_330_580_441n;
        expect(
            countLeadingStrongProbablePrimeBases(twelveBaseStrongPseudoprime),
        ).toBe(12);
        const validateAtBound = (): void =>
            validateBgvModulusPrimeInventory(
                degreeOneInventory(twelveBaseStrongPseudoprime),
            );
        expect(validateAtBound).toThrow(RangeError);
        expect(validateAtBound).toThrow(
            'A modulus prime factor is outside the proven Miller-Rabin range.',
        );
        // One below the bound is inside the proven range and is refused only
        // because it is even.
        expect(() =>
            validateBgvModulusPrimeInventory(
                degreeOneInventory(twelveBaseStrongPseudoprime - 1n),
            ),
        ).toThrow(notPrimeMessage);
    });

    it('refuses a prime that supports only the cyclic transform of length N', () => {
        const halfTransformPrime =
            (1n << 34n) + 3n * polynomialModulusDegree + 1n;
        expect(isPrimeByTrialDivision(halfTransformPrime)).toBe(true);
        expect(halfTransformPrime % polynomialModulusDegree).toBe(1n);
        expect(halfTransformPrime % transformOrder).toBe(
            polynomialModulusDegree + 1n,
        );
        expect(() =>
            validateBgvModulusPrimeInventory(
                inventoryWithCiphertextFactors([
                    ...ciphertextModulusPrimeFactors,
                    halfTransformPrime,
                ]),
            ),
        ).toThrow(
            'A modulus prime factor does not support the negacyclic transform.',
        );
    });

    it('refuses a prime repeated within or across the factor lists', () => {
        const repeatedFactorMessage =
            'The modulus prime factors are not pairwise distinct.';
        expect(() =>
            validateBgvModulusPrimeInventory(
                inventoryWithCiphertextFactors([
                    ...ciphertextModulusPrimeFactors,
                    ciphertextModulusPrimeFactors[3],
                ]),
            ),
        ).toThrow(repeatedFactorMessage);
        expect(() =>
            validateBgvModulusPrimeInventory(
                inventoryWithCiphertextFactors([
                    ...ciphertextModulusPrimeFactors,
                    auxiliaryModulusPrimeFactors[0],
                ]),
            ),
        ).toThrow(repeatedFactorMessage);
    });

    it('refuses a nonpositive polynomial modulus degree', () => {
        for (const degree of [0n, -polynomialModulusDegree]) {
            const validateWithDegree = (): void =>
                validateBgvModulusPrimeInventory({
                    auxiliaryModulusPrimeFactors,
                    ciphertextModulusPrimeFactors,
                    polynomialModulusDegree: degree,
                });
            expect(validateWithDegree).toThrow(RangeError);
            expect(validateWithDegree).toThrow(
                'The polynomial modulus degree must be positive.',
            );
        }
    });

    it('compiles the census only from a valid inventory with one prime per level', () => {
        const levelMismatchMessage =
            'The exact ciphertext-prime inventory disagrees with the graph.';
        const sparePrime = (1n << 34n) + 108n * transformOrder + 1n;
        expect(isPrimeByTrialDivision(sparePrime)).toBe(true);
        expect(() =>
            compileCandidateBgvParameterCensus({
                ...candidateBgvParameterInputs,
                ciphertextModulusPrimeFactors:
                    ciphertextModulusPrimeFactors.slice(0, -1),
            }),
        ).toThrow(levelMismatchMessage);
        expect(() =>
            compileCandidateBgvParameterCensus({
                ...candidateBgvParameterInputs,
                ciphertextModulusPrimeFactors: [
                    ...ciphertextModulusPrimeFactors,
                    sparePrime,
                ],
            }),
        ).toThrow(levelMismatchMessage);
        expect(() =>
            compileCandidateBgvParameterCensus({
                ...candidateBgvParameterInputs,
                ciphertextModulusPrimeFactors: [
                    ...ciphertextModulusPrimeFactors.slice(0, -1),
                    sparePrime * sparePrime,
                ],
            }),
        ).toThrow(notPrimeMessage);
    });
});
