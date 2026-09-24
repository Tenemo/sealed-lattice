import { describe, expect, it } from 'vitest';

import { compileThresholdKeyAggregationResourceLowerBound } from '#tests/threshold-key-aggregation-resource-model.js';

describe('threshold key aggregation resource model', () => {
    it('counts the four KLSW vectors with encryption reusing the first coordinate', () => {
        const resources = compileThresholdKeyAggregationResourceLowerBound();
        const vectors = ['b', 'd', 'v', 'h'];
        const gadgetLength = 3n + 14n;
        const ringDegree = 32_768n;
        // Independent transcription of KLSW24 Sections 4.1 and 4.4.
        expect(resources.publicKeyContributionRingElementCount).toBe(
            BigInt(vectors.length) * gadgetLength,
        );
        expect(resources.onePublicKeyContributionByteLength).toBe(
            (4n * gadgetLength * ringDegree * 642n) / 8n,
        );
        expect(resources.aggregateUnitRotationKeyLiveByteLength).toBe(
            gadgetLength * gadgetLength * ringDegree * 8n,
        );
        expect(resources.aggregateRelinearizationKeyLiveByteLength).toBe(
            3n * gadgetLength * gadgetLength * ringDegree * 8n,
        );
    });

    it('derives an optimistic setup and evaluator floor from pinned operands', () => {
        expect(compileThresholdKeyAggregationResourceLowerBound()).toEqual({
            aggregateRelinearizationKeyLiveByteLength: 227_278_848n,
            aggregateUnitRotationKeyLiveByteLength: 75_759_616n,
            auxiliaryModulusBitLength: 121n,
            availableCompactOpeningProofCorpusByteLength: 986_038_272n,
            availableCompactOpeningProofPerCarrierByteLength: 10_955_980n,
            availablePublicEncryptedSharingProofBudgetByteLength:
                1_309_212_672n,
            availablePublicEncryptedSharingProofPerContributorByteLength:
                130_921_267n,
            candidateCiphertextModulusBitLength: 642n,
            candidateCombinedModulusBitLength: 762n,
            ciphertextModulusLimbCount: 17n,
            completionEvaluationDataLiveByteLength: 407_378_895n,
            coefficientCommitmentByteLengthPerContributor: 21_037_056n,
            coefficientCommitmentCorpusByteLength: 210_370_560n,
            coefficientCommitmentRingElementCountPerContributor: 8n,
            exceedsSetupTransferVarianceCeiling: false,
            exceedsWebAssemblyAbsoluteMemoryBound: false,
            exceedsWebAssemblyAbsoluteMemoryBoundWithAllEvaluationKeys: true,
            minimumEvaluationLiveByteLengthWithAllEvaluationKeys: 710_417_359n,
            minimumEvaluationLiveByteLengthWithRelinearizationKey: 634_657_743n,
            minimumPrivateCarrierRingElementCount: 4n,
            minimumPublicEncryptedShareCiphertextRingElementCount: 2n,
            minimumPublicEncryptedShareCorpusByteLength: 117_964_800n,
            minimumPublicEncryptedSharingSetupCorpusByteLength: 1_912_012_800n,
            minimumRemoteSharePayloadByteLength: 236_666_880n,
            minimumRemotePrivateSharingPayloadByteLength: 946_667_520n,
            minimumSetupTransferCorpusByteLength: 2_945_187_840n,
            oneKeyPassPerOperationReadByteLength: 6_025_379_840n,
            onePublicKeyContributionByteLength: 178_814_976n,
            oneSerializedRingElementByteLength: 2_629_632n,
            oneSerializedShareEncryptionRingElementByteLength: 589_824n,
            privateOpeningOverheadByteLength: 710_000_640n,
            publicKeyContributionCorpusByteLength: 1_788_149_760n,
            publicKeyContributionRingElementCount: 68n,
            shareEncryptionAggregateNoiseCoefficientBound: 655_370n,
            shareEncryptionModulusBitLength: 144n,
            shareEncryptionPublicKeyCorpusByteLength: 5_898_240n,
            shareEncodingScale: 1_376_257n,
            scheduledPeakCiphertextAndCurrentEvaluationKeyByteLength:
                407_378_895n,
            setupTransferVarianceCeilingByteLength: 3_221_225_472n,
            streamingMemoryHeadroomBeforeScratchByteLength: 263_709_745n,
            webAssemblyAbsoluteMemoryBoundByteLength: 671_088_640n,
        });
    });
});
