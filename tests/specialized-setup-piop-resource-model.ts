import { compileCandidateBgvParameterCensus } from '#tests/candidate-bgv-parameter-model.js';
import { compilePublicEncryptedSharingProofResourceCensus } from '#tests/public-encrypted-sharing-proof-resource-model.js';
import { compileThresholdKeyAggregationResourceLowerBound } from '#tests/threshold-key-aggregation-resource-model.js';

const normBoundDecompositionLength = 1n;
const specializedLinearCheckCount = 2n;
const specializedRowCheckCount = 2n;

const ceilingDivide = (numerator: bigint, denominator: bigint): bigint =>
    (numerator + denominator - 1n) / denominator;

const nextPowerOfTwo = (value: bigint): bigint => {
    let result = 1n;
    while (result < value) result *= 2n;
    return result;
};

export type SpecializedSetupPiopResourceCensus = Readonly<{
    encodedOracleByteLengthPerContributor: bigint;
    encodedOracleFieldElementCountPerContributor: bigint;
    fitsSetupStoragePlanningTarget: boolean;
    fitsSetupTransferVarianceCeiling: boolean;
    maximumStreamingRowByteLength: bigint;
    merkleAuthenticationByteLengthPerContributor: bigint;
    optimisticProofByteLengthPerContributor: bigint;
    optimisticTenProofCorpusByteLength: bigint;
    polynomialOracleCountPerContributor: bigint;
    publicInputWitnessOracleAndMerkleByteLengthPerContributor: bigint;
    queryFieldElementCountPerContributor: bigint;
    randomizedEncodingOracleCountPerContributor: bigint;
    randomizedEncodingPolynomialLength: bigint;
}>;

export const compileSpecializedSetupPiopResourceCensus =
    (): SpecializedSetupPiopResourceCensus => {
        const genericProof = compilePublicEncryptedSharingProofResourceCensus();
        const resources = compileThresholdKeyAggregationResourceLowerBound();
        const ringDegree =
            compileCandidateBgvParameterCensus().polynomialModulusDegree;
        if (ringDegree <= 0n) {
            throw new Error('The candidate ring degree is absent.');
        }
        const sharingCoefficientCount =
            genericProof.binaryDecompositionRingElementCountPerContributor /
            genericProof.sharingCoefficientDecompositionBitLength;
        const originalWitnessRingElementCount =
            genericProof.ternaryRingElementCountPerContributor +
            sharingCoefficientCount;

        // HLS25 randomized encodings need one coefficient-form and one
        // transform-form polynomial for every bounded witness and nonconstant
        // sharing coefficient. One extra evaluation point gives one-query HVZK.
        const randomizedEncodingPolynomialLength = ringDegree + 1n;
        const randomizedEncodingOracleCountPerContributor =
            2n * originalWitnessRingElementCount;
        const normProofOracleCount =
            genericProof.ternaryRingElementCountPerContributor *
                normBoundDecompositionLength +
            3n +
            genericProof.binaryDecompositionRingElementCountPerContributor +
            3n;
        const linearCheckOracleElementCount =
            specializedLinearCheckCount *
            (2n * randomizedEncodingPolynomialLength + 2n * ringDegree);
        const rowCheckOracleElementCount =
            specializedRowCheckCount * randomizedEncodingPolynomialLength;
        const encodedOracleFieldElementCountPerContributor =
            (randomizedEncodingOracleCountPerContributor +
                normProofOracleCount) *
                randomizedEncodingPolynomialLength +
            linearCheckOracleElementCount +
            rowCheckOracleElementCount;
        const polynomialOracleCountPerContributor =
            randomizedEncodingOracleCountPerContributor +
            normProofOracleCount +
            2n * specializedLinearCheckCount +
            specializedRowCheckCount;

        // HLS25 query formulas: one norm check over every bounded vector, one
        // batched coefficient/transform linear check, one automorphism check,
        // and two row checks over the combined relation.
        const normQueryCount =
            genericProof.ternaryRingElementCountPerContributor *
                normBoundDecompositionLength +
            genericProof.ternaryRingElementCountPerContributor +
            1n +
            genericProof.binaryDecompositionRingElementCountPerContributor +
            sharingCoefficientCount +
            1n;
        const transformQueryCount = 2n * originalWitnessRingElementCount + 3n;
        const automorphismQueryCount = 5n;
        const rowQueryCount =
            specializedRowCheckCount * (originalWitnessRingElementCount + 1n);
        const queryFieldElementCountPerContributor =
            normQueryCount +
            transformQueryCount +
            automorphismQueryCount +
            rowQueryCount;

        const fieldElementByteLength = ceilingDivide(
            genericProof.proofFieldElementBitLength,
            8n,
        );
        const hashOutputByteLength = ceilingDivide(
            genericProof.randomOracleOutputBitLength,
            8n,
        );
        const merkleDepth = BigInt(
            Math.ceil(Math.log2(Number(randomizedEncodingPolynomialLength))),
        );
        const merkleAuthenticationByteLengthPerContributor =
            queryFieldElementCountPerContributor *
            merkleDepth *
            hashOutputByteLength;
        const optimisticProofByteLengthPerContributor =
            queryFieldElementCountPerContributor * fieldElementByteLength +
            merkleAuthenticationByteLengthPerContributor +
            polynomialOracleCountPerContributor * hashOutputByteLength;
        const encodedOracleByteLengthPerContributor =
            encodedOracleFieldElementCountPerContributor *
            fieldElementByteLength;
        const merkleTreeByteLength =
            2n *
            nextPowerOfTwo(randomizedEncodingPolynomialLength) *
            hashOutputByteLength;
        const publicInputWitnessOracleAndMerkleByteLengthPerContributor =
            genericProof.publicInputByteLengthPerContributor +
            originalWitnessRingElementCount *
                ringDegree *
                fieldElementByteLength +
            encodedOracleByteLengthPerContributor +
            merkleTreeByteLength;
        const setupStoragePlanningTargetByteLength = 2_147_483_648n;

        return {
            encodedOracleByteLengthPerContributor,
            encodedOracleFieldElementCountPerContributor,
            fitsSetupStoragePlanningTarget:
                publicInputWitnessOracleAndMerkleByteLengthPerContributor <=
                setupStoragePlanningTargetByteLength,
            fitsSetupTransferVarianceCeiling:
                optimisticProofByteLengthPerContributor <=
                resources.availablePublicEncryptedSharingProofPerContributorByteLength,
            maximumStreamingRowByteLength:
                randomizedEncodingPolynomialLength * fieldElementByteLength,
            merkleAuthenticationByteLengthPerContributor,
            optimisticProofByteLengthPerContributor,
            optimisticTenProofCorpusByteLength:
                10n * optimisticProofByteLengthPerContributor,
            polynomialOracleCountPerContributor,
            publicInputWitnessOracleAndMerkleByteLengthPerContributor,
            queryFieldElementCountPerContributor,
            randomizedEncodingOracleCountPerContributor,
            randomizedEncodingPolynomialLength,
        };
    };
