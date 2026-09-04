import { describe, expect, it } from 'vitest';

import { compilePublicEncryptedSharingProofResourceCensus } from '#tests/public-encrypted-sharing-proof-resource-model.js';

describe('public encrypted sharing proof resource model', () => {
    it('screens an optimistic direct Ligero compiler against the setup budget', () => {
        expect(compilePublicEncryptedSharingProofResourceCensus()).toEqual({
            binaryDecompositionConstraintCountPerContributor: 11_698_176n,
            binaryDecompositionRingElementCountPerContributor: 357n,
            boundedCoefficientCountPerContributor: 15_204_352n,
            boundedRingElementCountPerContributor: 464n,
            encodedProofOracleByteLengthPerContributor: 23_685_758_976n,
            encodedProofOracleFieldElementCountPerContributor: 269_156_352n,
            exceedsSetupStorageVarianceCeiling: true,
            expandedBoundedWitnessByteLengthPerContributor: 1_346_633_728n,
            fitsSetupProofBudgetBeforeFixedHashAndLiftingConstant: true,
            interactiveSoundnessBitLength: 224n,
            ligeroCodeDimension: 65_536n,
            ligeroCodeLength: 196_608n,
            ligeroMessageBlockLength: 65_152n,
            ligeroQueryCount: 383n,
            ligeroRepetitionCount: 1n,
            ligeroWitnessRowCount: 341n,
            linearConstraintCountPerContributor: 3_506_176n,
            optimisticCircuitConstraintCountPerContributor: 22_216_704n,
            optimisticLigeroProofByteLengthPerContributor: 74_378_926n,
            optimisticTenProofCorpusByteLength: 743_789_260n,
            proofFieldElementBitLength: 697n,
            proofBudgetRemainingByteLengthPerContributor: 27_247_749n,
            publicInputByteLengthPerContributor: 220_495_872n,
            publicInputPlusExpandedWitnessByteLengthPerContributor:
                1_567_129_600n,
            randomOracleOutputBitLength: 288n,
            sharingCoefficientDecompositionBitLength: 119n,
            ternaryConstraintCountPerContributor: 7_012_352n,
            ternaryRingElementCountPerContributor: 107n,
        });
    });
});
