import { describe, expect, it } from 'vitest';

import { verifyThresholdKeyAggregationModel } from '#tests/threshold-key-aggregation-model.js';

describe('threshold key aggregation model', () => {
    it('preserves linear evaluation-key equations and every release subset', () => {
        expect(verifyThresholdKeyAggregationModel()).toEqual({
            aggregatePublicKeyEquationCount: 4,
            authorizedReleaseSetCount: 210,
            coefficientModulus: 65_537n,
            gadgetLength: 3,
            maximumScaledReconstructionCoefficientOneNorm: 44n,
            maximumSimulationCoefficientOneNorm: 8n,
            monomialInterpolationPointCount: 10,
            participantCount: 10,
            releaseEquationCount: 210,
            releaseThreshold: 4,
            ringDegree: 8,
            tamperedShareChangedReconstruction: true,
            wrongTargetChangedPartialDecryption: true,
        });
    });
});
