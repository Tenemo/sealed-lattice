import { compilePackedRankingEvaluationGraph } from '#tests/exact-ranking-model.js';

// Pinned source operands from HLS25, Table 1 and the setup-share formula
// following Table 2. They describe the N=2^15, 865-bit, 16-limb profile.
const polynomialModulusDegree = 32_768n;
const coefficientModulusBitLength = 865n;
const residueNumberSystemLimbCount = 16n;
const participantCount = 10n;
const maximumCorruptParticipantCount = 3n;
const minimumAutomorphismKeyCount = 1n;
const minimumCommitmentSecurityRowCount = 1n;

const ceilingDivide = (numerator: bigint, denominator: bigint): bigint =>
    (numerator + denominator - 1n) / denominator;

export type ThresholdKeyAggregationResourceLowerBound = Readonly<{
    aggregateRelinearizationKeyLiveByteLength: bigint;
    aggregateUnitRotationKeyLiveByteLength: bigint;
    completionEvaluationDataLiveByteLength: bigint;
    coefficientCommitmentCorpusByteLength: bigint;
    coefficientCommitmentRingElementCountPerContributor: bigint;
    minimumEvaluationLiveByteLengthWithRelinearizationKey: bigint;
    minimumPublicSetupCorpusByteLength: bigint;
    minimumRemoteEncryptedSharingPayloadByteLength: bigint;
    oneCoefficientCommitmentByteLength: bigint;
    onePublicKeyContributionByteLength: bigint;
    oneSerializedRingElementByteLength: bigint;
    publicKeyContributionCorpusByteLength: bigint;
    publicKeyContributionRingElementCount: bigint;
}>;

export const compileThresholdKeyAggregationResourceLowerBound =
    (): ThresholdKeyAggregationResourceLowerBound => {
        const oneSerializedRingElementByteLength = ceilingDivide(
            polynomialModulusDegree * coefficientModulusBitLength,
            8n,
        );
        const oneLiveRingElementByteLength =
            polynomialModulusDegree * residueNumberSystemLimbCount * 8n;

        // One encryption component, three gadget vectors for linear
        // relinearization, and one gadget vector for the minimum possible
        // automorphism-key inventory.
        const publicKeyContributionRingElementCount =
            (3n + minimumAutomorphismKeyCount) * residueNumberSystemLimbCount +
            1n;
        const onePublicKeyContributionByteLength =
            publicKeyContributionRingElementCount *
            oneSerializedRingElementByteLength;
        const publicKeyContributionCorpusByteLength =
            participantCount * onePublicKeyContributionByteLength;

        // BDLOP18 commits to the degree-f sharing polynomial as f+1 ring
        // messages. Its commitment contains n+ell ring elements; this uses
        // the impossible-to-improve structural minimum n=1 and omits proof
        // messages and commitment randomness.
        const coefficientCommitmentRingElementCountPerContributor =
            minimumCommitmentSecurityRowCount +
            maximumCorruptParticipantCount +
            1n;
        const oneCoefficientCommitmentByteLength =
            coefficientCommitmentRingElementCountPerContributor *
            oneSerializedRingElementByteLength;
        const coefficientCommitmentCorpusByteLength =
            participantCount * oneCoefficientCommitmentByteLength;

        // Each contributor must privately deliver one full-ring Shamir
        // evaluation to every other participant. Any encryption, framing,
        // opening, or proof can only increase this payload floor.
        const remoteSharingCount = participantCount * (participantCount - 1n);
        const minimumRemoteEncryptedSharingPayloadByteLength =
            remoteSharingCount * oneSerializedRingElementByteLength;
        const minimumPublicSetupCorpusByteLength =
            publicKeyContributionCorpusByteLength +
            minimumRemoteEncryptedSharingPayloadByteLength +
            coefficientCommitmentCorpusByteLength;

        const aggregateRelinearizationKeyLiveByteLength =
            3n * residueNumberSystemLimbCount * oneLiveRingElementByteLength;
        const aggregateUnitRotationKeyLiveByteLength =
            residueNumberSystemLimbCount * oneLiveRingElementByteLength;
        const completionEvaluationDataLiveByteLength = BigInt(
            compilePackedRankingEvaluationGraph(10, 10, 10)
                .scheduledPeakCiphertextByteLength,
        );
        const minimumEvaluationLiveByteLengthWithRelinearizationKey =
            completionEvaluationDataLiveByteLength +
            aggregateRelinearizationKeyLiveByteLength;

        return {
            aggregateRelinearizationKeyLiveByteLength,
            aggregateUnitRotationKeyLiveByteLength,
            completionEvaluationDataLiveByteLength,
            coefficientCommitmentCorpusByteLength,
            coefficientCommitmentRingElementCountPerContributor,
            minimumEvaluationLiveByteLengthWithRelinearizationKey,
            minimumPublicSetupCorpusByteLength,
            minimumRemoteEncryptedSharingPayloadByteLength,
            oneCoefficientCommitmentByteLength,
            onePublicKeyContributionByteLength,
            oneSerializedRingElementByteLength,
            publicKeyContributionCorpusByteLength,
            publicKeyContributionRingElementCount,
        };
    };
