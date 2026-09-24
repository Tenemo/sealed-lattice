import { compilePackedRankingEvaluationGraph } from '#tests/exact-ranking-model.js';

export const candidateBgvParameterInputs = {
    auxiliaryModulusPrimeFactors: [
        1_152_921_504_606_584_833n,
        1_152_921_504_608_747_521n,
    ],
    ciphertextModulusPrimeFactors: [
        36_028_797_019_488_257n,
        36_028_797_020_209_153n,
        36_028_797_017_456_641n,
        17_179_672_577n,
        17_180_262_401n,
        17_179_410_433n,
        17_180_393_473n,
        17_181_442_049n,
        17_183_014_913n,
        17_176_854_529n,
        17_183_408_129n,
        17_183_932_417n,
        17_175_674_881n,
        17_174_691_841n,
        17_185_570_817n,
        17_186_357_249n,
        17_173_774_337n,
    ],
    optionCount: 10,
    participantCount: 10,
    polynomialModulusDegree: 32_768n,
    retainedBottomPrimeCount: 3n,
    topCount: 10,
} as const;

type BgvModulusPrimeInventory = Readonly<{
    auxiliaryModulusPrimeFactors: readonly bigint[];
    ciphertextModulusPrimeFactors: readonly bigint[];
    polynomialModulusDegree: bigint;
}>;

type CandidateBgvParameterInputs = BgvModulusPrimeInventory &
    Readonly<{
        optionCount: number;
        participantCount: number;
        retainedBottomPrimeCount: bigint;
        topCount: number;
    }>;

export type CandidateBgvParameterCensus = Readonly<{
    auxiliaryModulus: bigint;
    auxiliaryModulusBitLength: bigint;
    ciphertextModulus: bigint;
    ciphertextModulusBitLength: bigint;
    ciphertextModulusLimbCount: bigint;
    combinedModulus: bigint;
    combinedModulusBitLength: bigint;
    multiplicativeDepth: bigint;
    polynomialModulusDegree: bigint;
    retainedBottomModulusBitLength: bigint;
}>;

// Miller-Rabin with the first twelve prime bases is exact below the smallest
// strong pseudoprime to all of them, 318665857834031151167461 (Sorenson and
// Webster, Strong pseudoprimes to twelve prime bases, Mathematics of
// Computation 86, 2017). Larger factors are refused rather than trusted.
const millerRabinBases = [
    2n,
    3n,
    5n,
    7n,
    11n,
    13n,
    17n,
    19n,
    23n,
    29n,
    31n,
    37n,
] as const;
const millerRabinExactnessBound = 318_665_857_834_031_151_167_461n;

const product = (values: readonly bigint[]): bigint =>
    values.reduce((result, value) => result * value, 1n);

const bitLength = (value: bigint): bigint => BigInt(value.toString(2).length);

const exponentiate = (
    base: bigint,
    exponent: bigint,
    modulus: bigint,
): bigint => {
    let result = 1n;
    let factor = base % modulus;
    let remaining = exponent;
    while (remaining > 0n) {
        if ((remaining & 1n) === 1n) result = (result * factor) % modulus;
        factor = (factor * factor) % modulus;
        remaining >>= 1n;
    }
    return result;
};

const isPrimeByMillerRabin = (value: bigint): boolean => {
    if (value < 2n) return false;
    for (const base of millerRabinBases) {
        if (value % base === 0n) return value === base;
    }
    let oddPart = value - 1n;
    let twoAdicValuation = 0n;
    while ((oddPart & 1n) === 0n) {
        oddPart >>= 1n;
        twoAdicValuation += 1n;
    }
    return millerRabinBases.every((base) => {
        let power = exponentiate(base, oddPart, value);
        if (power === 1n || power === value - 1n) return true;
        for (let squaring = 1n; squaring < twoAdicValuation; squaring += 1n) {
            power = (power * power) % value;
            if (power === value - 1n) return true;
        }
        return false;
    });
};

// Negacyclic NTT arithmetic modulo X^N + 1 needs a primitive 2N-th root of
// unity modulo every factor, so each factor must be congruent to 1 modulo 2N.
// Residue-number-system limbs also need pairwise distinct prime moduli.
export const validateBgvModulusPrimeInventory = (
    inventory: BgvModulusPrimeInventory,
): void => {
    if (inventory.polynomialModulusDegree < 1n) {
        throw new RangeError('The polynomial modulus degree must be positive.');
    }
    const transformOrder = 2n * inventory.polynomialModulusDegree;
    const factors = [
        ...inventory.auxiliaryModulusPrimeFactors,
        ...inventory.ciphertextModulusPrimeFactors,
    ];
    for (const factor of factors) {
        if (factor >= millerRabinExactnessBound) {
            throw new RangeError(
                'A modulus prime factor is outside the proven Miller-Rabin range.',
            );
        }
        if (!isPrimeByMillerRabin(factor)) {
            throw new Error('A modulus prime factor is not prime.');
        }
        if (factor % transformOrder !== 1n) {
            throw new Error(
                'A modulus prime factor does not support the negacyclic transform.',
            );
        }
    }
    if (new Set(factors).size !== factors.length) {
        throw new Error('The modulus prime factors are not pairwise distinct.');
    }
};

export const compileCandidateBgvParameterCensus = (
    inputs: CandidateBgvParameterInputs = candidateBgvParameterInputs,
): CandidateBgvParameterCensus => {
    validateBgvModulusPrimeInventory(inputs);
    const graph = compilePackedRankingEvaluationGraph(
        inputs.participantCount,
        inputs.optionCount,
        inputs.topCount,
        24,
        Number(inputs.retainedBottomPrimeCount),
    );
    const multiplicativeDepth = BigInt(graph.multiplicativeDepth);
    const expectedCiphertextModulusPrimeCount =
        inputs.retainedBottomPrimeCount + multiplicativeDepth;
    if (
        BigInt(inputs.ciphertextModulusPrimeFactors.length) !==
        expectedCiphertextModulusPrimeCount
    ) {
        throw new Error(
            'The exact ciphertext-prime inventory disagrees with the graph.',
        );
    }
    const ciphertextModulus = product(inputs.ciphertextModulusPrimeFactors);
    const auxiliaryModulus = product(inputs.auxiliaryModulusPrimeFactors);
    const combinedModulus = ciphertextModulus * auxiliaryModulus;
    const retainedBottomModulus = product(
        inputs.ciphertextModulusPrimeFactors.slice(
            0,
            Number(inputs.retainedBottomPrimeCount),
        ),
    );
    return {
        auxiliaryModulus,
        auxiliaryModulusBitLength: bitLength(auxiliaryModulus),
        ciphertextModulus,
        ciphertextModulusBitLength: bitLength(ciphertextModulus),
        ciphertextModulusLimbCount: expectedCiphertextModulusPrimeCount,
        combinedModulus,
        combinedModulusBitLength: bitLength(combinedModulus),
        multiplicativeDepth,
        polynomialModulusDegree: inputs.polynomialModulusDegree,
        retainedBottomModulusBitLength: bitLength(retainedBottomModulus),
    };
};
