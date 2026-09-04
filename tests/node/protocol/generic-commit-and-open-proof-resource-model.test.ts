import { describe, expect, it } from 'vitest';

import { compileGenericCommitAndOpenProofResourceCensus } from '#tests/generic-commit-and-open-proof-resource-model.js';

describe('generic commit-and-open proof resource model', () => {
    it('rejects direct ZKB++ compilation of the large setup relation', () => {
        expect(compileGenericCommitAndOpenProofResourceCensus()).toEqual({
            boundedCoefficientCountPerSetupContribution: 2_457_600n,
            boundedRingElementCountPerSetupContribution: 75n,
            combinedSetupAndProofSubtotalByteLength: 6_026_526_720n,
            exceedsSetupTransferVarianceCeiling: true,
            minimumProofCorpusByteLength: 2_691_072_000n,
            minimumProofSizePerSetupContributionByteLength: 269_107_200n,
            proofBitsPerBinaryMultiplicationGate: 876n,
            quantumSecurityParallelRepetitionCount: 438n,
        });
    });
});
