import { describe, expect, it } from 'vitest';

import { compileGenericCommitAndOpenProofResourceCensus } from '#tests/generic-commit-and-open-proof-resource-model.js';

describe('generic commit-and-open proof resource model', () => {
    it('rejects direct ZKB++ compilation of the large setup relation', () => {
        expect(compileGenericCommitAndOpenProofResourceCensus()).toEqual({
            boundedCoefficientCountPerSetupContribution: 2_293_760n,
            boundedRingElementCountPerSetupContribution: 70n,
            combinedSetupAndProofSubtotalByteLength: 4_423_680_000n,
            exceedsSetupTransferVarianceCeiling: true,
            minimumProofCorpusByteLength: 2_511_667_200n,
            minimumProofSizePerSetupContributionByteLength: 251_166_720n,
            proofBitsPerBinaryMultiplicationGate: 876n,
            quantumSecurityParallelRepetitionCount: 438n,
        });
    });
});
