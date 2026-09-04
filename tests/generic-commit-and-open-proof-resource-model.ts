import { compileThresholdKeyAggregationResourceLowerBound } from '#tests/threshold-key-aggregation-resource-model.js';

// Pinned CDGORRSZ17 Section 7.3 and optimized Unruh/ZKB++ proof formula.
const quantumSecurityParallelRepetitionCount = 438n;
const proofBitsPerBinaryMultiplicationGate =
    2n * quantumSecurityParallelRepetitionCount;

// Pinned HLS25 large-profile operands and its setup-share witness layout.
const polynomialModulusDegree = 32_768n;
const residueNumberSystemLimbCount = 16n;
const participantCount = 10n;
const minimumAutomorphismKeyCount = 1n;

const publicProtocolCorpusPlanningTargetByteLength = 2_147_483_648n;
const publicProtocolCorpusVarianceNumerator = 3n;
const publicProtocolCorpusVarianceDenominator = 2n;

export type GenericCommitAndOpenProofResourceCensus = Readonly<{
    boundedCoefficientCountPerSetupContribution: bigint;
    boundedRingElementCountPerSetupContribution: bigint;
    combinedSetupAndProofSubtotalByteLength: bigint;
    exceedsPublicCorpusVarianceCeiling: boolean;
    minimumProofCorpusByteLength: bigint;
    minimumProofSizePerSetupContributionByteLength: bigint;
    proofBitsPerBinaryMultiplicationGate: bigint;
    quantumSecurityParallelRepetitionCount: bigint;
}>;

export const compileGenericCommitAndOpenProofResourceCensus =
    (): GenericCommitAndOpenProofResourceCensus => {
        // One secret, one auxiliary secret, one encryption error, three
        // relinearization-error vectors, and one minimum automorphism-error
        // vector. The model optimistically charges only one binary
        // multiplication for each coefficient's non-linear bound check.
        const boundedRingElementCountPerSetupContribution =
            3n +
            (3n + minimumAutomorphismKeyCount) * residueNumberSystemLimbCount;
        const boundedCoefficientCountPerSetupContribution =
            boundedRingElementCountPerSetupContribution *
            polynomialModulusDegree;
        const minimumProofSizePerSetupContributionBitLength =
            boundedCoefficientCountPerSetupContribution *
            proofBitsPerBinaryMultiplicationGate;
        if (minimumProofSizePerSetupContributionBitLength % 8n !== 0n) {
            throw new Error('The proof-size subtotal is not byte aligned.');
        }
        const minimumProofSizePerSetupContributionByteLength =
            minimumProofSizePerSetupContributionBitLength / 8n;
        const minimumProofCorpusByteLength =
            participantCount * minimumProofSizePerSetupContributionByteLength;
        const combinedSetupAndProofSubtotalByteLength =
            compileThresholdKeyAggregationResourceLowerBound()
                .minimumPublicSetupCorpusByteLength +
            minimumProofCorpusByteLength;
        const publicCorpusVarianceCeiling =
            (publicProtocolCorpusPlanningTargetByteLength *
                publicProtocolCorpusVarianceNumerator) /
            publicProtocolCorpusVarianceDenominator;

        return {
            boundedCoefficientCountPerSetupContribution,
            boundedRingElementCountPerSetupContribution,
            combinedSetupAndProofSubtotalByteLength,
            exceedsPublicCorpusVarianceCeiling:
                combinedSetupAndProofSubtotalByteLength >
                publicCorpusVarianceCeiling,
            minimumProofCorpusByteLength,
            minimumProofSizePerSetupContributionByteLength,
            proofBitsPerBinaryMultiplicationGate,
            quantumSecurityParallelRepetitionCount,
        };
    };
