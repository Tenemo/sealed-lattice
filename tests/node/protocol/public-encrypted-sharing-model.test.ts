import { describe, expect, it } from 'vitest';

import { verifyPublicEncryptedSharingModel } from '#tests/public-encrypted-sharing-model.js';

describe('public encrypted sharing model', () => {
    it('aggregates every encrypted share and reconstructs every authorized subset', () => {
        expect(verifyPublicEncryptedSharingModel()).toEqual({
            aggregateCiphertextsChecked: 10,
            authorizedReconstructionSubsetsChecked: 210,
            contributorRecipientCiphertextsChecked: 100,
            productionAggregateNoiseCoefficientBound: 655_370n,
            productionShareEncodingScale: 1_376_257n,
            productionShareEncodingScaleBitLength: 21n,
            productionSingleCiphertextNoiseCoefficientBound: 65_537n,
            tamperedCiphertextChangedShare: true,
            toyRingDegree: 4,
        });
    });
});
