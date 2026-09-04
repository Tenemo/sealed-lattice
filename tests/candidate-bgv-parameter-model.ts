import { compilePackedRankingEvaluationGraph } from '#tests/exact-ranking-model.js';

export const candidateBgvParameterInputs = {
    auxiliaryModulusBitLength: 120n,
    consumedLevelPrimeBitLength: 34n,
    optionCount: 10,
    participantCount: 10,
    polynomialModulusDegree: 32_768n,
    retainedBottomPrimeBitLength: 55n,
    retainedBottomPrimeCount: 4n,
    topCount: 10,
} as const;

export type CandidateBgvParameterCensus = Readonly<{
    auxiliaryModulusBitLength: bigint;
    ciphertextModulusBitLength: bigint;
    ciphertextModulusLimbCount: bigint;
    combinedModulusBitLength: bigint;
    multiplicativeDepth: bigint;
    polynomialModulusDegree: bigint;
    retainedBottomModulusBitLength: bigint;
}>;

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
        const retainedBottomModulusBitLength =
            candidateBgvParameterInputs.retainedBottomPrimeCount *
            candidateBgvParameterInputs.retainedBottomPrimeBitLength;
        const ciphertextModulusBitLength =
            retainedBottomModulusBitLength +
            multiplicativeDepth *
                candidateBgvParameterInputs.consumedLevelPrimeBitLength;
        return {
            auxiliaryModulusBitLength:
                candidateBgvParameterInputs.auxiliaryModulusBitLength,
            ciphertextModulusBitLength,
            ciphertextModulusLimbCount:
                candidateBgvParameterInputs.retainedBottomPrimeCount +
                multiplicativeDepth,
            combinedModulusBitLength:
                ciphertextModulusBitLength +
                candidateBgvParameterInputs.auxiliaryModulusBitLength,
            multiplicativeDepth,
            polynomialModulusDegree:
                candidateBgvParameterInputs.polynomialModulusDegree,
            retainedBottomModulusBitLength,
        };
    };
