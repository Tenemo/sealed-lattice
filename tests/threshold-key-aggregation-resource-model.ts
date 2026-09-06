import { compileBoundedIntegerSharingPrivacyCensus } from '#tests/bounded-integer-sharing-privacy-model.js';
import {
    candidateBgvParameterInputs,
    compileCandidateBgvParameterCensus,
} from '#tests/candidate-bgv-parameter-model.js';
import { compilePackedRankingEvaluationGraph } from '#tests/exact-ranking-model.js';
import { publicEncryptedSharingModelConstants } from '#tests/public-encrypted-sharing-model.js';

// The ring degree and plaintext modulus come from the HLS25 large profile.
// The candidate modulus layout retains three approximately 55-bit primes after
// the verified depth-14 graph and assigns one approximately 34-bit prime to
// each consumed level. The two approximately 60-bit auxiliary primes follow
// the pinned Lattigo BGV evaluation-key layout.
// This is a resource-screening tuple, not an approved security parameter set.
const minimumAutomorphismKeyCount = 1n;
const minimumCommitmentSecurityRowCount = 1n;
const minimumCommitmentRandomnessRingElementCount = 3n;

const ceilingDivide = (numerator: bigint, denominator: bigint): bigint =>
    (numerator + denominator - 1n) / denominator;

export type ThresholdKeyAggregationResourceLowerBound = Readonly<{
    aggregateRelinearizationKeyLiveByteLength: bigint;
    aggregateUnitRotationKeyLiveByteLength: bigint;
    auxiliaryModulusBitLength: bigint;
    availableCompactOpeningProofCorpusByteLength: bigint;
    availableCompactOpeningProofPerCarrierByteLength: bigint;
    availablePublicEncryptedSharingProofBudgetByteLength: bigint;
    availablePublicEncryptedSharingProofPerContributorByteLength: bigint;
    candidateCiphertextModulusBitLength: bigint;
    ciphertextModulusLimbCount: bigint;
    candidateCombinedModulusBitLength: bigint;
    completionEvaluationDataLiveByteLength: bigint;
    coefficientCommitmentCorpusByteLength: bigint;
    coefficientCommitmentRingElementCountPerContributor: bigint;
    exceedsWebAssemblyAbsoluteMemoryBound: boolean;
    exceedsWebAssemblyAbsoluteMemoryBoundWithAllEvaluationKeys: boolean;
    minimumEvaluationLiveByteLengthWithAllEvaluationKeys: bigint;
    exceedsSetupTransferVarianceCeiling: boolean;
    minimumEvaluationLiveByteLengthWithRelinearizationKey: bigint;
    minimumPrivateCarrierRingElementCount: bigint;
    minimumPublicEncryptedShareCiphertextRingElementCount: bigint;
    minimumPublicEncryptedShareCorpusByteLength: bigint;
    minimumPublicEncryptedSharingSetupCorpusByteLength: bigint;
    minimumRemoteSharePayloadByteLength: bigint;
    minimumSetupTransferCorpusByteLength: bigint;
    oneKeyPassPerOperationReadByteLength: bigint;
    minimumRemotePrivateSharingPayloadByteLength: bigint;
    coefficientCommitmentByteLengthPerContributor: bigint;
    onePublicKeyContributionByteLength: bigint;
    oneSerializedRingElementByteLength: bigint;
    oneSerializedShareEncryptionRingElementByteLength: bigint;
    privateOpeningOverheadByteLength: bigint;
    publicKeyContributionCorpusByteLength: bigint;
    publicKeyContributionRingElementCount: bigint;
    shareEncryptionAggregateNoiseCoefficientBound: bigint;
    shareEncryptionModulusBitLength: bigint;
    shareEncryptionPublicKeyCorpusByteLength: bigint;
    shareEncodingScale: bigint;
    scheduledPeakCiphertextAndCurrentEvaluationKeyByteLength: bigint;
    setupTransferVarianceCeilingByteLength: bigint;
    streamingMemoryHeadroomBeforeScratchByteLength: bigint;
    webAssemblyAbsoluteMemoryBoundByteLength: bigint;
}>;

export const compileThresholdKeyAggregationResourceLowerBound =
    (): ThresholdKeyAggregationResourceLowerBound => {
        const candidateParameters = compileCandidateBgvParameterCensus();
        const boundedIntegerSharing =
            compileBoundedIntegerSharingPrivacyCensus();
        const polynomialModulusDegree =
            candidateParameters.polynomialModulusDegree;
        const participantCount = BigInt(
            candidateBgvParameterInputs.participantCount,
        );
        const maximumCorruptParticipantCount = BigInt(
            Math.floor((candidateBgvParameterInputs.participantCount - 1) / 3),
        );
        const evaluationGraph = compilePackedRankingEvaluationGraph(
            candidateBgvParameterInputs.participantCount,
            candidateBgvParameterInputs.optionCount,
            candidateBgvParameterInputs.topCount,
            24,
            Number(candidateBgvParameterInputs.retainedBottomPrimeCount),
        );
        const candidateCiphertextModulusBitLength =
            candidateParameters.ciphertextModulusBitLength;
        const oneSerializedRingElementByteLength = ceilingDivide(
            polynomialModulusDegree * candidateCiphertextModulusBitLength,
            8n,
        );
        const residueNumberSystemLimbCount =
            candidateParameters.ciphertextModulusLimbCount;
        const oneLiveRingElementByteLength =
            polynomialModulusDegree * residueNumberSystemLimbCount * 8n;

        // KLSW24 Section 4.1 publishes (b, d, v, h): encryption reuses b[0],
        // and each required automorphism contributes one h vector. HLS25
        // equations (5) and (6) are two DIFFERENT automorphisms, not two
        // components of one key. Its separate encryption key is not used here.
        const publicKeyContributionRingElementCount =
            (3n + minimumAutomorphismKeyCount) * residueNumberSystemLimbCount;
        const onePublicKeyContributionByteLength =
            publicKeyContributionRingElementCount *
            oneSerializedRingElementByteLength;
        const publicKeyContributionCorpusByteLength =
            participantCount * onePublicKeyContributionByteLength;

        // A private evaluation opening must not reveal every coefficient.
        // Commit each of the f+1 coefficients separately with the smallest
        // BDLOP18 computationally hiding layout: one security row, one message
        // row, and three opening-randomness ring elements.
        const coefficientCommitmentRingElementCountPerContributor =
            (maximumCorruptParticipantCount + 1n) *
            (minimumCommitmentSecurityRowCount + 1n);
        const coefficientCommitmentByteLengthPerContributor =
            coefficientCommitmentRingElementCountPerContributor *
            oneSerializedRingElementByteLength;
        const coefficientCommitmentCorpusByteLength =
            participantCount * coefficientCommitmentByteLengthPerContributor;

        // Each contributor privately delivers one full-ring sharing evaluation
        // plus the linearly combined three-element BDLOP18 opening to every
        // other participant. Encryption and framing only increase this floor.
        const minimumPrivateCarrierRingElementCount =
            1n + minimumCommitmentRandomnessRingElementCount;
        const remoteSharingCount = participantCount * (participantCount - 1n);
        const minimumRemoteSharePayloadByteLength =
            remoteSharingCount * oneSerializedRingElementByteLength;
        const privateOpeningOverheadByteLength =
            remoteSharingCount *
            minimumCommitmentRandomnessRingElementCount *
            oneSerializedRingElementByteLength;
        const minimumRemotePrivateSharingPayloadByteLength =
            remoteSharingCount *
            minimumPrivateCarrierRingElementCount *
            oneSerializedRingElementByteLength;
        const minimumSetupTransferCorpusByteLength =
            publicKeyContributionCorpusByteLength +
            minimumRemotePrivateSharingPayloadByteLength +
            coefficientCommitmentCorpusByteLength;

        // A public verifiable-sharing replacement needs at least a two-ring
        // ciphertext for every contributor-recipient share, including the
        // self-share so each holder has one canonical aggregate ciphertext.
        // The exact candidate share modulus is tightly bit-packed. Recipient
        // proofs, framing, and implementation copies are omitted.
        const minimumPublicEncryptedShareCiphertextRingElementCount = 2n;
        const oneSerializedShareEncryptionRingElementByteLength = ceilingDivide(
            polynomialModulusDegree *
                boundedIntegerSharing.shareEncryptionModulusBitLength,
            8n,
        );
        const publicEncryptedSharingCount = participantCount * participantCount;
        const minimumPublicEncryptedShareCorpusByteLength =
            publicEncryptedSharingCount *
            minimumPublicEncryptedShareCiphertextRingElementCount *
            oneSerializedShareEncryptionRingElementByteLength;
        const shareEncryptionPublicKeyCorpusByteLength =
            participantCount *
            oneSerializedShareEncryptionRingElementByteLength;
        const minimumPublicEncryptedSharingSetupCorpusByteLength =
            publicKeyContributionCorpusByteLength +
            minimumPublicEncryptedShareCorpusByteLength +
            shareEncryptionPublicKeyCorpusByteLength;

        const aggregateRelinearizationKeyLiveByteLength =
            3n * residueNumberSystemLimbCount * oneLiveRingElementByteLength;
        const aggregateUnitRotationKeyLiveByteLength =
            residueNumberSystemLimbCount * oneLiveRingElementByteLength;
        const completionEvaluationDataLiveByteLength = BigInt(
            evaluationGraph.scheduledPeakCiphertextByteLength,
        );
        const minimumEvaluationLiveByteLengthWithRelinearizationKey =
            completionEvaluationDataLiveByteLength +
            aggregateRelinearizationKeyLiveByteLength;
        const minimumEvaluationLiveByteLengthWithAllEvaluationKeys =
            minimumEvaluationLiveByteLengthWithRelinearizationKey +
            aggregateUnitRotationKeyLiveByteLength;
        const oneKeyPassPerOperationReadByteLength =
            BigInt(
                evaluationGraph.relinearizationKeyRingLimbReadCount +
                    evaluationGraph.rotationKeyRingLimbReadCount,
            ) *
            polynomialModulusDegree *
            8n;
        const scheduledPeakCiphertextAndCurrentEvaluationKeyByteLength = BigInt(
            evaluationGraph.scheduledPeakCiphertextAndCurrentEvaluationKeyByteLength,
        );

        const setupTransferVarianceCeilingByteLength = 3_221_225_472n;
        const webAssemblyAbsoluteMemoryBoundByteLength = 671_088_640n;
        const availableCompactOpeningProofCorpusByteLength =
            setupTransferVarianceCeilingByteLength -
            publicKeyContributionCorpusByteLength -
            coefficientCommitmentCorpusByteLength -
            minimumRemoteSharePayloadByteLength;
        const availablePublicEncryptedSharingProofBudgetByteLength =
            setupTransferVarianceCeilingByteLength -
            minimumPublicEncryptedSharingSetupCorpusByteLength;

        return {
            aggregateRelinearizationKeyLiveByteLength,
            aggregateUnitRotationKeyLiveByteLength,
            auxiliaryModulusBitLength:
                candidateParameters.auxiliaryModulusBitLength,
            availableCompactOpeningProofCorpusByteLength,
            availableCompactOpeningProofPerCarrierByteLength:
                availableCompactOpeningProofCorpusByteLength /
                remoteSharingCount,
            availablePublicEncryptedSharingProofBudgetByteLength,
            availablePublicEncryptedSharingProofPerContributorByteLength:
                availablePublicEncryptedSharingProofBudgetByteLength /
                participantCount,
            candidateCiphertextModulusBitLength,
            ciphertextModulusLimbCount: residueNumberSystemLimbCount,
            candidateCombinedModulusBitLength:
                candidateParameters.combinedModulusBitLength,
            completionEvaluationDataLiveByteLength,
            coefficientCommitmentCorpusByteLength,
            coefficientCommitmentRingElementCountPerContributor,
            exceedsSetupTransferVarianceCeiling:
                minimumSetupTransferCorpusByteLength >
                setupTransferVarianceCeilingByteLength,
            exceedsWebAssemblyAbsoluteMemoryBound:
                minimumEvaluationLiveByteLengthWithRelinearizationKey >
                webAssemblyAbsoluteMemoryBoundByteLength,
            exceedsWebAssemblyAbsoluteMemoryBoundWithAllEvaluationKeys:
                minimumEvaluationLiveByteLengthWithAllEvaluationKeys >
                webAssemblyAbsoluteMemoryBoundByteLength,
            minimumEvaluationLiveByteLengthWithAllEvaluationKeys,
            minimumEvaluationLiveByteLengthWithRelinearizationKey,
            minimumPrivateCarrierRingElementCount,
            minimumPublicEncryptedShareCiphertextRingElementCount,
            minimumPublicEncryptedShareCorpusByteLength,
            minimumPublicEncryptedSharingSetupCorpusByteLength,
            minimumRemoteSharePayloadByteLength,
            minimumSetupTransferCorpusByteLength,
            oneKeyPassPerOperationReadByteLength,
            minimumRemotePrivateSharingPayloadByteLength,
            coefficientCommitmentByteLengthPerContributor,
            onePublicKeyContributionByteLength,
            oneSerializedRingElementByteLength,
            oneSerializedShareEncryptionRingElementByteLength,
            privateOpeningOverheadByteLength,
            publicKeyContributionCorpusByteLength,
            publicKeyContributionRingElementCount,
            shareEncryptionAggregateNoiseCoefficientBound:
                publicEncryptedSharingModelConstants.productionAggregateNoiseCoefficientBound,
            shareEncryptionModulusBitLength:
                boundedIntegerSharing.shareEncryptionModulusBitLength,
            shareEncryptionPublicKeyCorpusByteLength,
            shareEncodingScale:
                publicEncryptedSharingModelConstants.productionShareEncodingScale,
            scheduledPeakCiphertextAndCurrentEvaluationKeyByteLength,
            setupTransferVarianceCeilingByteLength,
            streamingMemoryHeadroomBeforeScratchByteLength:
                webAssemblyAbsoluteMemoryBoundByteLength -
                scheduledPeakCiphertextAndCurrentEvaluationKeyByteLength,
            webAssemblyAbsoluteMemoryBoundByteLength,
        };
    };
