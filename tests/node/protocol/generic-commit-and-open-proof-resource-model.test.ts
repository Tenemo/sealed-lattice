import { describe, expect, it } from 'vitest';

import { compileGenericCommitAndOpenProofResourceCensus } from '#tests/generic-commit-and-open-proof-resource-model.js';

describe('generic commit-and-open proof resource model', () => {
    it('rejects direct ZKB++ compilation of the large setup relation', () => {
        expect(compileGenericCommitAndOpenProofResourceCensus()).toEqual({
            boundedCoefficientCountPerSetupContribution: 2_195_456n,
            boundedRingElementCountPerSetupContribution: 67n,
            combinedSetupAndProofSubtotalByteLength: 5_203_025_920n,
            exceedsPublicCorpusVarianceCeiling: true,
            minimumProofCorpusByteLength: 2_404_024_320n,
            minimumProofSizePerSetupContributionByteLength: 240_402_432n,
            proofBitsPerBinaryMultiplicationGate: 876n,
            quantumSecurityParallelRepetitionCount: 438n,
        });
    });
});
