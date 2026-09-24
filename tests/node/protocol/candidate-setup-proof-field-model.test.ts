import { describe, expect, it } from 'vitest';

import {
    candidateSetupProofFieldCertificate,
    compileCandidateSetupProofFieldCensus,
} from '#tests/candidate-setup-proof-field-model.js';
import { compileFheKeyIntegerEmbeddingBounds } from '#tests/fhe-key-integer-embedding-model.js';

type SetupProofFieldCertificate = NonNullable<
    Parameters<typeof compileCandidateSetupProofFieldCensus>[0]
>;

// HLS25 Table 1 (Params II) evaluates over the ring degree N = 2^15, so the
// proof field needs roots of unity of order 2N for the negacyclic transform.
const transformOrder = 2n * 2n ** 15n;

const pinnedCertificate = candidateSetupProofFieldCertificate;
const invalidWitnessMessage = 'A Pocklington witness is invalid.';
const invalidFactorizationMessage =
    'The proof-field base factorization is invalid.';

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
// value is prime. It needs one witness for all prime factors of value - 1,
// unlike the per-factor Pocklington witnesses of the model.
const findLucasWitness = (
    value: bigint,
    orderPrimeFactors: readonly bigint[],
): bigint | undefined => {
    for (let witness = 2n; witness <= 100n; witness += 1n) {
        if (
            modularPower(witness, value - 1n, value) === 1n &&
            orderPrimeFactors.every(
                (primeFactor) =>
                    modularPower(witness, (value - 1n) / primeFactor, value) !==
                    1n,
            )
        ) {
            return witness;
        }
    }
    return undefined;
};

const twoAdicValuation = (value: bigint): bigint => {
    let valuation = 0n;
    while ((value >> valuation) % 2n === 0n) valuation += 1n;
    return valuation;
};

// The smallest number of unitBitLength-bit units that holds value.
const unitCountFor = (value: bigint, unitBitLength: bigint): bigint => {
    let unitCount = 0n;
    while (value >> (unitCount * unitBitLength) > 0n) unitCount += 1n;
    return unitCount;
};

// The smallest base whose power plus one reaches minimumModulus.
const smallestBaseReaching = (
    minimumModulus: bigint,
    exponent: bigint,
): bigint => {
    let upper = 1n;
    while (upper ** exponent + 1n < minimumModulus) upper *= 2n;
    let lower = upper / 2n;
    while (upper - lower > 1n) {
        const middle = (lower + upper) / 2n;
        if (middle ** exponent + 1n < minimumModulus) lower = middle;
        else upper = middle;
    }
    return upper;
};

const compileWith = (certificate: SetupProofFieldCertificate) => (): void => {
    compileCandidateSetupProofFieldCensus(certificate);
};

describe('candidate setup-proof field model', () => {
    it('certifies the pinned field with a Lucas primitive root', () => {
        const { basePrimeFactors, modulus, powerBase, powerExponent } =
            pinnedCertificate;
        // Five squarings raise the base to the power 2^5.
        let power = powerBase;
        for (let squaring = 0; squaring < 5; squaring += 1) power *= power;
        expect(modulus).toBe(power + 1n);
        // modulus - 1 is a power of the base, so both share prime divisors.
        const orderPrimeFactors =
            distinctPrimeFactorsByTrialDivision(powerBase);
        expect(basePrimeFactors).toEqual(orderPrimeFactors);
        expect(findLucasWitness(modulus, orderPrimeFactors)).toBeDefined();
        const census = compileCandidateSetupProofFieldCensus();
        expect(census.modulus).toBe(modulus);
        expect(census.powerBase).toBe(powerBase);
        expect(census.powerExponent).toBe(2n ** 5n);
        expect(powerExponent).toBe(2n ** 5n);
        expect(census.basePrimeFactorCount).toBe(
            BigInt(orderPrimeFactors.length),
        );
        // Pocklington needs one witness for each prime dividing modulus - 1.
        expect(census.pocklingtonWitnessCount).toBe(
            BigInt(orderPrimeFactors.length),
        );
    });

    it('chooses the smallest base whose prime field clears the key-embedding bound', () => {
        const minimumModulus =
            compileFheKeyIntegerEmbeddingBounds().minimumProofFieldModulus;
        const { powerBase, powerExponent } = pinnedCertificate;
        const smallestReachingBase = smallestBaseReaching(
            minimumModulus,
            powerExponent,
        );
        expect(smallestReachingBase).toBeLessThan(powerBase);
        expect(compileCandidateSetupProofFieldCensus().modulus).toBeGreaterThan(
            minimumModulus,
        );
        // An odd base gives an even modulus. Every smaller even base fails a
        // base-3 Fermat test, which proves its field modulus composite.
        const unrefutedSmallerBases: bigint[] = [];
        for (let base = smallestReachingBase; base < powerBase; base += 1n) {
            const candidate = base ** powerExponent + 1n;
            if (
                candidate % 2n === 1n &&
                modularPower(3n, candidate - 1n, candidate) === 1n
            ) {
                unrefutedSmallerBases.push(base);
            }
        }
        expect(unrefutedSmallerBases).toEqual([]);
    });

    it('derives the bit, byte, and limb widths from exact powers of two', () => {
        const census = compileCandidateSetupProofFieldCensus();
        const { modulus } = pinnedCertificate;
        expect(census.modulusBitLength).toBe(unitCountFor(modulus, 1n));
        expect(census.modulusByteLength).toBe(unitCountFor(modulus, 8n));
        expect(census.limbByteLength).toBe(8n * unitCountFor(modulus, 64n));
    });

    it('supports the negacyclic transform of the HLS25 ring degree', () => {
        const { modulus } = pinnedCertificate;
        expect(compileCandidateSetupProofFieldCensus().transformOrder).toBe(
            transformOrder,
        );
        // modulus - 1 = base^32 and the base is twice an odd number.
        expect(twoAdicValuation(modulus - 1n)).toBe(32n);
        expect((modulus - 1n) % transformOrder).toBe(0n);
    });

    it('refuses the composite Fermat number 2^32 + 1 under every witness', () => {
        // 2^32 + 1 = 641 * 6700417 passes the Fermat condition for base 2, so
        // only the Pocklington coprimality condition refuses that witness.
        const compositeFermatNumber = 641n * 6_700_417n;
        expect(compositeFermatNumber).toBe(2n ** 32n + 1n);
        expect(
            modularPower(2n, compositeFermatNumber - 1n, compositeFermatNumber),
        ).toBe(1n);
        for (let witness = 2n; witness <= 100n; witness += 1n) {
            expect(
                compileWith({
                    basePrimeFactors: [2n],
                    modulus: compositeFermatNumber,
                    pocklingtonWitnesses: [witness],
                    powerBase: 2n,
                    powerExponent: 32n,
                }),
            ).toThrow(invalidWitnessMessage);
        }
    });

    it('refuses a witness that is a quadratic residue for the prime two', () => {
        // The modulus is 1 modulo 8, so 2 is a quadratic residue, the power
        // 2^((modulus - 1) / 2) is 1, and its gcd condition fails.
        expect(pinnedCertificate.modulus % 8n).toBe(1n);
        expect(
            compileWith({
                ...pinnedCertificate,
                pocklingtonWitnesses: [2n, 2n, 2n],
            }),
        ).toThrow(invalidWitnessMessage);
    });

    it('refuses a malformed power representation or base factorization', () => {
        expect(
            compileWith({
                ...pinnedCertificate,
                modulus: pinnedCertificate.modulus + 2n,
            }),
        ).toThrow('The proof-field power representation is wrong.');
        // 14 * 105929 equals the base, but 14 is not prime.
        expect(
            compileWith({
                ...pinnedCertificate,
                basePrimeFactors: [14n, 105_929n],
                pocklingtonWitnesses: [3n, 2n],
            }),
        ).toThrow(invalidFactorizationMessage);
        expect(
            compileWith({
                ...pinnedCertificate,
                basePrimeFactors: [2n, 7n],
            }),
        ).toThrow(invalidFactorizationMessage);
        expect(
            compileWith({
                ...pinnedCertificate,
                pocklingtonWitnesses: [3n, 2n],
            }),
        ).toThrow('A Pocklington certificate entry is absent.');
    });

    it('refuses certified prime fields without the transform root or embedding size', () => {
        // Both certificates below are valid, so only the later checks refuse
        // them. 2^8 + 1 is prime, but 2N does not divide 2^8.
        expect(
            compileWith({
                basePrimeFactors: [2n],
                modulus: 257n,
                pocklingtonWitnesses: [3n],
                powerBase: 2n,
                powerExponent: 8n,
            }),
        ).toThrow('The proof field lacks the required transform root.');
        // The former proof field is prime but lies below the bound on
        // bounded integer key-equation residuals.
        const formerBasePrimeFactors = [2n, 137n, 3_911n];
        const formerBase = formerBasePrimeFactors.reduce(
            (product, factor) => product * factor,
            1n,
        );
        const formerModulus = formerBase ** 32n + 1n;
        expect(formerModulus).toBeLessThan(
            compileFheKeyIntegerEmbeddingBounds().minimumProofFieldModulus,
        );
        expect(
            compileWith({
                basePrimeFactors: formerBasePrimeFactors,
                modulus: formerModulus,
                pocklingtonWitnesses: [3n, 2n, 2n],
                powerBase: formerBase,
                powerExponent: 32n,
            }),
        ).toThrow('The proof field can wrap a bounded FHE key equation.');
    });
});
