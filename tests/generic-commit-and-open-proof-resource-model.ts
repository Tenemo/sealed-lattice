import { compileThresholdKeyAggregationResourceLowerBound } from '#tests/threshold-key-aggregation-resource-model.js';

// Pinned CDGORRSZ17 Section 7.3 and optimized Unruh/ZKB++ proof formula.
const quantumSecurityParallelRepetitionCount = 438n;
const proofBitsPerBinaryMultiplicationGate =
    2n * quantumSecurityParallelRepetitionCount;

// The ring degree and setup-share witness layout follow HLS25. The exact limb
// count comes from the release-capable screening tuple in the setup model.
const polynomialModulusDegree = 32_768n;
const participantCount = 10n;
const minimumAutomorphismKeyCount = 1n;

const publicProtocolCorpusPlanningTargetByteLength = 2_147_483_648n;
const publicProtocolCorpusVarianceNumerator = 3n;
const publicProtocolCorpusVarianceDenominator = 2n;

export type GenericCommitAndOpenProofResourceCensus = Readonly<{
    boundedCoefficientCountPerSetupContribution: bigint;
    boundedRingElementCountPerSetupContribution: bigint;
    combinedSetupAndProofSubtotalByteLength: bigint;
    exceedsSetupTransferVarianceCeiling: boolean;
    minimumProofCorpusByteLength: bigint;
    minimumProofSizePerSetupContributionByteLength: bigint;
    proofBitsPerBinaryMultiplicationGate: bigint;
    quantumSecurityParallelRepetitionCount: bigint;
}>;

export const compileGenericCommitAndOpenProofResourceCensus =
    (): GenericCommitAndOpenProofResourceCensus => {
        const thresholdKeyResources =
            compileThresholdKeyAggregationResourceLowerBound();
        // KLSW24 has two secrets and four error vectors for its three
        // relinearization vectors and one automorphism. Encryption reuses b[0].
        // The model optimistically charges only one binary
        // multiplication for each coefficient's non-linear bound check.
        const boundedRingElementCountPerSetupContribution =
            2n +
            (3n + minimumAutomorphismKeyCount) *
                thresholdKeyResources.ciphertextModulusLimbCount;
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
            thresholdKeyResources.minimumSetupTransferCorpusByteLength +
            minimumProofCorpusByteLength;
        const setupTransferVarianceCeiling =
            (publicProtocolCorpusPlanningTargetByteLength *
                publicProtocolCorpusVarianceNumerator) /
            publicProtocolCorpusVarianceDenominator;

        return {
            boundedCoefficientCountPerSetupContribution,
            boundedRingElementCountPerSetupContribution,
            combinedSetupAndProofSubtotalByteLength,
            exceedsSetupTransferVarianceCeiling:
                combinedSetupAndProofSubtotalByteLength >
                setupTransferVarianceCeiling,
            minimumProofCorpusByteLength,
            minimumProofSizePerSetupContributionByteLength,
            proofBitsPerBinaryMultiplicationGate,
            quantumSecurityParallelRepetitionCount,
        };
    };
