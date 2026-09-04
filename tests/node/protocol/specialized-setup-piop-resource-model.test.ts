import { describe, expect, it } from 'vitest';

import { compileSpecializedSetupPiopResourceCensus } from '#tests/specialized-setup-piop-resource-model.js';

describe('specialized setup PIOP resource model', () => {
    it('screens the HLS-shaped oracle layout and BCS openings', () => {
        expect(compileSpecializedSetupPiopResourceCensus()).toEqual({
            encodedOracleByteLengthPerContributor: 2_018_570_048n,
            encodedOracleFieldElementCountPerContributor: 22_938_296n,
            fitsSetupStoragePlanningTarget: false,
            fitsSetupTransferVarianceCeiling: true,
            maximumStreamingRowByteLength: 2_883_672n,
            merkleAuthenticationByteLengthPerContributor: 590_976n,
            optimisticProofByteLengthPerContributor: 706_320n,
            optimisticTenProofCorpusByteLength: 7_063_200n,
            polynomialOracleCountPerContributor: 696n,
            publicInputWitnessOracleAndMerkleByteLengthPerContributor:
                2_560_978_752n,
            queryFieldElementCountPerContributor: 1_026n,
            randomizedEncodingOracleCountPerContributor: 220n,
            randomizedEncodingPolynomialLength: 32_769n,
        });
    });
});
