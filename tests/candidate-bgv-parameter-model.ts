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

const product = (values: readonly bigint[]): bigint =>
    values.reduce((result, value) => result * value, 1n);

const bitLength = (value: bigint): bigint => BigInt(value.toString(2).length);

export const compileCandidateBgvParameterCensus =
    (): CandidateBgvParameterCensus => {
        const graph = compilePackedRankingEvaluationGraph(
            candidateBgvParameterInputs.participantCount,
            candidateBgvParameterInputs.optionCount,
            candidateBgvParameterInputs.topCount,
            24,
            Number(candidateBgvParameterInputs.retainedBottomPrimeCount),
        );
        const multiplicativeDepth = BigInt(graph.multiplicativeDepth);
        const expectedCiphertextModulusPrimeCount =
            candidateBgvParameterInputs.retainedBottomPrimeCount +
            multiplicativeDepth;
        if (
            BigInt(
                candidateBgvParameterInputs.ciphertextModulusPrimeFactors
                    .length,
            ) !== expectedCiphertextModulusPrimeCount
        ) {
            throw new Error(
                'The exact ciphertext-prime inventory disagrees with the graph.',
            );
        }
        const ciphertextModulus = product(
            candidateBgvParameterInputs.ciphertextModulusPrimeFactors,
        );
        const auxiliaryModulus = product(
            candidateBgvParameterInputs.auxiliaryModulusPrimeFactors,
        );
        const combinedModulus = ciphertextModulus * auxiliaryModulus;
        const retainedBottomModulus = product(
            candidateBgvParameterInputs.ciphertextModulusPrimeFactors.slice(
                0,
                Number(candidateBgvParameterInputs.retainedBottomPrimeCount),
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
            polynomialModulusDegree:
                candidateBgvParameterInputs.polynomialModulusDegree,
            retainedBottomModulusBitLength: bitLength(retainedBottomModulus),
        };
    };
