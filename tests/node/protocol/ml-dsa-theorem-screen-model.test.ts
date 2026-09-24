import { describe, expect, it } from 'vitest';

import {
    mlDsa65ChallengeSeedBytes,
    mlDsa65Parameters,
    publishedDilithiumComparison,
    screenSelfTargetReduction,
} from '#tests/ml-dsa-theorem-screen-model.js';

// FIPS 204 Table 1 bounds the ML-DSA-65 hint weight by omega = 55. The screen
// does not use omega, so this test states it.
const mlDsa65HintWeight = 55n;
// FIPS 204 Table 2, ML-DSA-65 sizes in bytes.
const publishedMlDsa65Sizes = {
    publicKeyBytes: 1952n,
    privateKeyBytes: 4032n,
    signatureBytes: 3309n,
};

const bitLength = (value: bigint): bigint => BigInt(value.toString(2).length);

// FIPS 204 Algorithms 22, 24 and 26 output 32 + 32k(bitlen(q-1)-d),
// 128 + 32((k+l)bitlen(2 eta)+dk) and lambda/4 + 32l(1+bitlen(gamma1-1))
// + omega + k bytes. Beyond the seeds and the hint, a packed polynomial takes
// n/8 = 32 bytes per bit of coefficient width.
const encodedSizes = (parameters: typeof mlDsa65Parameters) => {
    const polynomialBytes = (coefficientBits: bigint): bigint =>
        (parameters.polynomialDegree * coefficientBits) / 8n;
    return {
        publicKeyBytes:
            32n +
            parameters.rowCount *
                polynomialBytes(
                    bitLength(parameters.modulus - 1n) -
                        parameters.roundingBits,
                ),
        privateKeyBytes:
            32n +
            32n +
            64n +
            (parameters.rowCount + parameters.columnCount) *
                polynomialBytes(
                    bitLength(2n * parameters.secretCoefficientBound),
                ) +
            parameters.rowCount * polynomialBytes(parameters.roundingBits),
        signatureBytes:
            mlDsa65ChallengeSeedBytes +
            parameters.columnCount *
                polynomialBytes(1n + bitLength(parameters.maskingBound - 1n)) +
            mlDsa65HintWeight +
            parameters.rowCount,
    };
};

describe('the ML-DSA-65 operand transcription', () => {
    it('reproduces the FIPS 204 Table 2 key and signature sizes', () => {
        expect(encodedSizes(mlDsa65Parameters)).toEqual(publishedMlDsa65Sizes);
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

    it('rejects a mistranscribed operand through the published sizes', () => {
        // gamma1 = 2^17 and eta = 2 are entries of other Table 1 columns.
        expect(
            encodedSizes({ ...mlDsa65Parameters, maskingBound: 1n << 17n })
                .signatureBytes,
        ).not.toBe(publishedMlDsa65Sizes.signatureBytes);
        expect(
            encodedSizes({ ...mlDsa65Parameters, roundingBits: 12n })
                .publicKeyBytes,
        ).not.toBe(publishedMlDsa65Sizes.publicKeyBytes);
        expect(
            encodedSizes({ ...mlDsa65Parameters, secretCoefficientBound: 2n })
                .privateKeyBytes,
        ).not.toBe(publishedMlDsa65Sizes.privateKeyBytes);
        expect(
            encodedSizes({
                ...mlDsa65Parameters,
                rowCount: 5n,
                columnCount: 6n,
            }).publicKeyBytes,
        ).not.toBe(publishedMlDsa65Sizes.publicKeyBytes);
    });
});

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
