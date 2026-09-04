import { describe, expect, it } from 'vitest';

import { compileThresholdKeyAggregationResourceLowerBound } from '#tests/threshold-key-aggregation-resource-model.js';

describe('threshold key aggregation resource model', () => {
    it('derives an optimistic setup and evaluator floor from pinned operands', () => {
        expect(compileThresholdKeyAggregationResourceLowerBound()).toEqual({
            aggregateRelinearizationKeyLiveByteLength: 201_326_592n,
            aggregateUnitRotationKeyLiveByteLength: 67_108_864n,
            completionEvaluationDataLiveByteLength: 351_804_593n,
            coefficientCommitmentCorpusByteLength: 177_152_000n,
            coefficientCommitmentRingElementCountPerContributor: 5n,
            minimumEvaluationLiveByteLengthWithRelinearizationKey: 553_131_185n,
            minimumPublicSetupCorpusByteLength: 2_799_001_600n,
            minimumRemoteEncryptedSharingPayloadByteLength: 318_873_600n,
            oneCoefficientCommitmentByteLength: 17_715_200n,
            onePublicKeyContributionByteLength: 230_297_600n,
            oneSerializedRingElementByteLength: 3_543_040n,
            publicKeyContributionCorpusByteLength: 2_302_976_000n,
            publicKeyContributionRingElementCount: 65n,
        });
    });
});
