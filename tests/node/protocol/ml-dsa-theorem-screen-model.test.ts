import { describe, expect, it } from 'vitest';

import {
    mlDsa65Parameters,
    publishedDilithiumComparison,
    screenSelfTargetReduction,
} from '#tests/ml-dsa-theorem-screen-model.js';

describe('the SelfTargetMSIS-to-MLWE parameter condition', () => {
    it('does not transfer the published reduction to standard ML-DSA-65', () => {
        const result = screenSelfTargetReduction(mlDsa65Parameters);
        expect(result.splitModulusCondition).toBe(true);
        expect(result.signatureVectorBound).toBe(724481n);
        expect(result.errorCoefficient).toBe(4451211264n);
        expect(result.strictUpperBound).toBe(261888n);
        expect(result.maximumAuxiliaryError).toBe(0n);
    });

    it('admits the auxiliary error used by the independently published comparison', () => {
        const result = screenSelfTargetReduction(publishedDilithiumComparison);
        expect(result.splitModulusCondition).toBe(true);
        expect(result.signatureVectorBound).toBe(2137089n);
        // Table 2 uses auxiliary error 4 for this proposed parameter set.
        expect(4n * result.errorCoefficient).toBeLessThan(
            result.strictUpperBound,
        );
        expect(result.maximumAuxiliaryError).toBe(8n);
    });

    it('preserves the strict boundary rather than rounding a forbidden error upward', () => {
        const parameters = {
            ...mlDsa65Parameters,
            polynomialDegree: 1n,
            rowCount: 1n,
            columnCount: 1n,
            secretCoefficientBound: 1n,
            challengeWeight: 1n,
            roundingBits: 1n,
            maskingBound: 2n,
            roundingBound: 1n,
        };
        // The coefficient is 2*4*1*(1+1+1)=24. At floor(q/32)=48,
        // auxiliary error 2 gives equality and must be excluded.
        expect(
            screenSelfTargetReduction({ ...parameters, modulus: 1537n })
                .maximumAuxiliaryError,
        ).toBe(1n);
        expect(
            screenSelfTargetReduction({ ...parameters, modulus: 1569n })
                .maximumAuxiliaryError,
        ).toBe(2n);
    });
});
