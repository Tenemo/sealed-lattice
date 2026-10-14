import { describe, expect, it } from 'vitest';

import {
    mlDsa65EncodedSizes,
    mlDsa65Parameters,
    mlDsa65Sizes,
} from '#tests/ml-dsa-65-parameters.js';

// FIPS 204 Table 2, ML-DSA-65 sizes in bytes.
const publishedMlDsa65Sizes = {
    publicKeyBytes: 1952n,
    privateKeyBytes: 4032n,
    signatureBytes: 3309n,
};

describe('the ML-DSA-65 operand transcription', () => {
    it('reproduces the FIPS 204 Table 2 key and signature sizes', () => {
        expect(mlDsa65Sizes).toEqual(publishedMlDsa65Sizes);
        // The sizes see q only through its bit length and omit tau. FIPS 204
        // section 2.3 states q = 2^23 - 2^13 + 1, and Table 1 states
        // beta = tau*eta = 196 and gamma2 = (q-1)/32.
        expect(mlDsa65Parameters.modulus).toBe((1n << 23n) - (1n << 13n) + 1n);
        expect(
            mlDsa65Parameters.challengeWeight *
                mlDsa65Parameters.secretCoefficientBound,
        ).toBe(196n);
        expect(32n * mlDsa65Parameters.roundingBound).toBe(
            mlDsa65Parameters.modulus - 1n,
        );
    });

    it('refuses a mistranscribed operand through the published sizes', () => {
        // gamma1 = 2^17 and eta = 2 are entries of other Table 1 columns.
        expect(
            mlDsa65EncodedSizes({
                ...mlDsa65Parameters,
                maskingBound: 1n << 17n,
            }).signatureBytes,
        ).not.toBe(publishedMlDsa65Sizes.signatureBytes);
        expect(
            mlDsa65EncodedSizes({ ...mlDsa65Parameters, roundingBits: 12n })
                .publicKeyBytes,
        ).not.toBe(publishedMlDsa65Sizes.publicKeyBytes);
        expect(
            mlDsa65EncodedSizes({
                ...mlDsa65Parameters,
                secretCoefficientBound: 2n,
            }).privateKeyBytes,
        ).not.toBe(publishedMlDsa65Sizes.privateKeyBytes);
        expect(
            mlDsa65EncodedSizes({
                ...mlDsa65Parameters,
                rowCount: 5n,
                columnCount: 6n,
            }).publicKeyBytes,
        ).not.toBe(publishedMlDsa65Sizes.publicKeyBytes);
    });
});
