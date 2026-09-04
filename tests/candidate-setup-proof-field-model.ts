import { candidateBgvParameterInputs } from '#tests/candidate-bgv-parameter-model.js';
import { compileFheKeyIntegerEmbeddingBounds } from '#tests/fhe-key-integer-embedding-model.js';

const proofFieldBase = 1_483_006n;
const proofFieldExponent = 32n;
const proofFieldModulus =
    299_621_559_211_013_091_364_546_708_655_190_169_722_660_291_316_894_719_225_100_534_155_954_439_701_789_301_642_161_448_967_767_089_671_055_896_202_076_303_958_039_151_890_113_095_580_560_144_473_563_147_565_511_867_054_706_497_038_835_257_011_139_066_447_527_937n;
const basePrimeFactors = [2n, 7n, 105_929n] as const;
const pocklingtonWitnesses = [3n, 2n, 2n] as const;

const absolute = (value: bigint): bigint => (value < 0n ? -value : value);
const greatestCommonDivisor = (left: bigint, right: bigint): bigint => {
    let first = absolute(left);
    let second = absolute(right);
    while (second !== 0n) [first, second] = [second, first % second];
    return first;
};
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
const isPrimeByTrialDivision = (value: bigint): boolean => {
    if (value < 2n) return false;
    for (let divisor = 2n; divisor * divisor <= value; divisor += 1n) {
        if (value % divisor === 0n) return false;
    }
    return true;
};

export type CandidateSetupProofFieldCensus = Readonly<{
    basePrimeFactorCount: bigint;
    modulus: bigint;
    modulusBitLength: bigint;
    modulusByteLength: bigint;
    limbByteLength: bigint;
    pocklingtonWitnessCount: bigint;
    powerBase: bigint;
    powerExponent: bigint;
    transformOrder: bigint;
}>;

export const compileCandidateSetupProofFieldCensus =
    (): CandidateSetupProofFieldCensus => {
        if (proofFieldBase ** proofFieldExponent + 1n !== proofFieldModulus) {
            throw new Error('The proof-field power representation is wrong.');
        }
        const factoredBase = basePrimeFactors.reduce(
            (product, factor) => product * factor,
            1n,
        );
        if (
            factoredBase !== proofFieldBase ||
            basePrimeFactors.some((factor) => !isPrimeByTrialDivision(factor))
        ) {
            throw new Error('The proof-field base factorization is invalid.');
        }
        const factoredModulusMinusOne = basePrimeFactors.reduce(
            (product, factor) => product * factor ** proofFieldExponent,
            1n,
        );
        if (
            factoredModulusMinusOne !== proofFieldModulus - 1n ||
            factoredModulusMinusOne ** 2n <= proofFieldModulus
        ) {
            throw new Error(
                'The Pocklington factored divisor is insufficient.',
            );
        }
        for (let index = 0; index < basePrimeFactors.length; index += 1) {
            const primeFactor = basePrimeFactors[index];
            const witness = pocklingtonWitnesses[index];
            if (primeFactor === undefined || witness === undefined) {
                throw new Error('A Pocklington certificate entry is absent.');
            }
            if (
                exponentiate(
                    witness,
                    proofFieldModulus - 1n,
                    proofFieldModulus,
                ) !== 1n ||
                greatestCommonDivisor(
                    exponentiate(
                        witness,
                        (proofFieldModulus - 1n) / primeFactor,
                        proofFieldModulus,
                    ) - 1n,
                    proofFieldModulus,
                ) !== 1n
            ) {
                throw new Error('A Pocklington witness is invalid.');
            }
        }
        const transformOrder =
            2n * candidateBgvParameterInputs.polynomialModulusDegree;
        if ((proofFieldModulus - 1n) % transformOrder !== 0n) {
            throw new Error(
                'The proof field lacks the required transform root.',
            );
        }
        const modulusBitLength = BigInt(proofFieldModulus.toString(2).length);
        if (
            proofFieldModulus <
            compileFheKeyIntegerEmbeddingBounds().minimumProofFieldModulus
        ) {
            throw new Error(
                'The proof field can wrap a bounded FHE key equation.',
            );
        }
        return {
            basePrimeFactorCount: BigInt(basePrimeFactors.length),
            modulus: proofFieldModulus,
            modulusBitLength,
            modulusByteLength: (modulusBitLength + 7n) / 8n,
            limbByteLength: ((modulusBitLength + 63n) / 64n) * 8n,
            pocklingtonWitnessCount: BigInt(pocklingtonWitnesses.length),
            powerBase: proofFieldBase,
            powerExponent: proofFieldExponent,
            transformOrder,
        };
    };
