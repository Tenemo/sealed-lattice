import { describe, expect, it } from 'vitest';

import { compileThresholdKeyAggregationResourceLowerBound } from '#tests/threshold-key-aggregation-resource-model.js';

describe('threshold key aggregation resource model', () => {
    it('derives an optimistic setup and evaluator floor from pinned operands', () => {
        expect(compileThresholdKeyAggregationResourceLowerBound()).toEqual({
            aggregateRelinearizationKeyLiveByteLength: 254_803_968n,
            aggregateUnitRotationKeyLiveByteLength: 84_934_656n,
            auxiliaryModulusBitLength: 120n,
            availableCompactOpeningProofCorpusByteLength: 655_491_072n,
            availableCompactOpeningProofPerCarrierByteLength: 7_283_234n,
            availablePublicEncryptedSharingProofBudgetByteLength:
                1_016_266_752n,
            availablePublicEncryptedSharingProofPerContributorByteLength:
                101_626_675n,
            candidateCiphertextModulusBitLength: 696n,
            candidateCombinedModulusBitLength: 816n,
            ciphertextModulusLimbCount: 18n,
            completionEvaluationDataLiveByteLength: 440_409_039n,
            coefficientCommitmentByteLengthPerContributor: 22_806_528n,
            coefficientCommitmentCorpusByteLength: 228_065_280n,
            coefficientCommitmentRingElementCountPerContributor: 8n,
            exceedsSetupTransferVarianceCeiling: true,
            exceedsWebAssemblyAbsoluteMemoryBound: true,
            minimumEvaluationLiveByteLengthWithRelinearizationKey: 695_213_007n,
            minimumPrivateCarrierRingElementCount: 4n,
            minimumPublicEncryptedShareCiphertextRingElementCount: 2n,
            minimumPublicEncryptedShareCorpusByteLength: 117_964_800n,
            minimumPublicEncryptedSharingSetupCorpusByteLength: 2_204_958_720n,
            minimumRemoteSharePayloadByteLength: 256_573_440n,
            minimumRemotePrivateSharingPayloadByteLength: 1_026_293_760n,
            minimumSetupTransferCorpusByteLength: 3_335_454_720n,
            oneKeyPassPerOperationReadByteLength: 7_132_676_096n,
            onePublicKeyContributionByteLength: 208_109_568n,
            oneSerializedRingElementByteLength: 2_850_816n,
            oneSerializedShareEncryptionRingElementByteLength: 589_824n,
            privateOpeningOverheadByteLength: 769_720_320n,
            publicKeyContributionCorpusByteLength: 2_081_095_680n,
            publicKeyContributionRingElementCount: 73n,
            shareEncryptionAggregateNoiseCoefficientBound: 655_370n,
            shareEncryptionModulusBitLength: 144n,
            shareEncryptionPublicKeyCorpusByteLength: 5_898_240n,
            shareEncodingScale: 1_376_257n,
            scheduledPeakCiphertextAndCurrentEvaluationKeyByteLength:
                440_409_039n,
            setupTransferVarianceCeilingByteLength: 3_221_225_472n,
            streamingMemoryHeadroomBeforeScratchByteLength: 230_679_601n,
            webAssemblyAbsoluteMemoryBoundByteLength: 671_088_640n,
        });
    });
});
