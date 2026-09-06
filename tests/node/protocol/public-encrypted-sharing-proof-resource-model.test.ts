import { describe, expect, it } from 'vitest';

import { compilePublicEncryptedSharingProofResourceCensus } from '#tests/public-encrypted-sharing-proof-resource-model.js';

describe('public encrypted sharing proof resource model', () => {
    it('screens an optimistic direct Ligero compiler against the setup budget', () => {
        expect(compilePublicEncryptedSharingProofResourceCensus()).toEqual({
            binaryDecompositionConstraintCountPerContributor: 11_698_176n,
            binaryDecompositionRingElementCountPerContributor: 357n,
            binaryEndpointConstraintCountPerContributor: 98_304n,
            boundedCoefficientCountPerContributor: 15_040_512n,
            boundedRingElementCountPerContributor: 459n,
            encodedProofOracleByteLengthPerContributor: 21_948_334_080n,
            encodedProofOracleFieldElementCountPerContributor: 264_437_760n,
            exceedsSetupStorageVarianceCeiling: true,
            expandedBoundedWitnessByteLengthPerContributor: 1_256_521_728n,
            fitsSetupProofBudgetBeforeFixedHashAndLiftingConstant: true,
            interactiveSoundnessBitLength: 224n,
            ligeroCodeDimension: 65_536n,
            ligeroCodeLength: 196_608n,
            ligeroMessageBlockLength: 65_145n,
            ligeroQueryCount: 383n,
            ligeroRepetitionCount: 1n,
            ligeroWitnessRowCount: 335n,
            linearConstraintCountPerContributor: 3_342_336n,
            optimisticCircuitConstraintCountPerContributor: 21_823_488n,
            optimisticLigeroProofByteLengthPerContributor: 69_369_183n,
            optimisticTenProofCorpusByteLength: 693_691_830n,
            proofFieldElementBitLength: 657n,
            proofBudgetRemainingByteLengthPerContributor: 61_552_084n,
            publicInputByteLengthPerContributor: 191_201_280n,
            publicInputPlusExpandedWitnessByteLengthPerContributor:
                1_447_723_008n,
            randomOracleOutputBitLength: 288n,
            sharingCoefficientDecompositionBitLength: 119n,
            ternaryConstraintCountPerContributor: 6_684_672n,
            ternaryRingElementCountPerContributor: 102n,
        });
    });
});
