import { describe, expect, it } from 'vitest';

import { compileCandidateSetupProofFieldCensus } from '#tests/candidate-setup-proof-field-model.js';
import { compileFheKeyIntegerEmbeddingBounds } from '#tests/fhe-key-integer-embedding-model.js';

describe('FHE key integer embedding', () => {
    it('rejects a false key equation that aliases in the former proof field', () => {
        const formerProofField = 1_071_614n ** 32n + 1n;
        const bounds = compileFheKeyIntegerEmbeddingBounds();
        // Secret and error zero require b=0 for ANY common a. These centered
        // b and bounded quotient instead make b-Q*z equal the former field.
        const falsePublicCoefficient =
            formerProofField - bounds.ciphertextModulus;
        const quotient = -1n;
        expect(falsePublicCoefficient).toBeGreaterThan(0n);
        expect(falsePublicCoefficient).toBeLessThan(
            bounds.ciphertextModulus / 2n,
        );
        expect(-quotient).toBeLessThanOrEqual(bounds.maximumQuotientMagnitude);
        const discrepancy =
            falsePublicCoefficient - bounds.ciphertextModulus * quotient;
        expect(discrepancy % formerProofField).toBe(0n);
        expect(falsePublicCoefficient % bounds.ciphertextModulus).not.toBe(0n);
        expect(
            discrepancy % compileCandidateSetupProofFieldCensus().modulus,
        ).not.toBe(0n);
    });

    it('contains every bounded integer residual strictly inside the new field', () => {
        const bounds = compileFheKeyIntegerEmbeddingBounds();
        const field = compileCandidateSetupProofFieldCensus();
        expect(bounds.maximumQuotientMagnitude).toBe(16_385n);
        expect(bounds.quotientRingElementCountPerContributor).toBe(68n);
        expect(field.modulus).toBeGreaterThanOrEqual(
            bounds.minimumProofFieldModulus,
        );
        for (const numerator of [
            -bounds.maximumNumeratorMagnitude,
            0n,
            bounds.maximumNumeratorMagnitude,
        ]) {
            for (const quotient of [
                -bounds.maximumQuotientMagnitude,
                0n,
                bounds.maximumQuotientMagnitude,
            ]) {
                const residual =
                    numerator - bounds.ciphertextModulus * quotient;
                expect(
                    residual > -field.modulus && residual < field.modulus,
                ).toBe(true);
                expect(residual % field.modulus === 0n).toBe(residual === 0n);
            }
        }
        const actualIntegerNumerator = 2n * bounds.ciphertextModulus;
        expect(
            (actualIntegerNumerator - 2n * bounds.ciphertextModulus) %
                field.modulus,
        ).toBe(0n);
    });
});
