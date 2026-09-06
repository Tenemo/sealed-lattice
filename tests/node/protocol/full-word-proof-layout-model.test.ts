import { describe, expect, it } from 'vitest';

import { auxiliaryInputEncryptionParameters } from '#tests/auxiliary-input-encryption-parameters.js';
import {
    compileFullWordProofLayout,
    proverInterpolationAlias,
} from '#tests/full-word-proof-layout-model.js';
import { compileWideChallengeCompilerCensus } from '#tests/wide-challenge-compiler-model.js';

describe('full word-proof layout and theorem operands', () => {
    it('matches the emitted header and leaf shapes', () => {
        const layout = compileFullWordProofLayout();
        expect(layout.foldCount).toBe(17);
        expect(layout.headerBytes).toBe(
            4n + 128n + 192n + 48n + 20n * 128n + 16n * 64n + 48n,
        );
        expect(layout.firstWidth).toBe(366n * 16n + 48n);
        expect(layout.secondWidth).toBe(380n * 48n);
        expect(layout.proverInterpolationPoints).toBe(131072);
        expect(
            layout.expandedFirstOracleBytes + layout.expandedSecondOracleBytes,
        ).toBe(262144n * (5904n + 18240n));
        expect(layout.maximumProofBytes).toBeLessThan(67_108_864n);
    });
    it('charges the actual lookup, affine, batching, and first-fold events', () => {
        const census = compileWideChallengeCompilerCensus();
        expect(census.lookupEntryCount).toBe(378n * 65536n);
        expect(census.lookupRootDegree).toBe(379n * 65536n - 1n);
        expect(census.correlatedRowCount).toBe(2n * 1172n);
        expect(census.batchingAndFirstFoldNumerator).toBe(2345n * 262144n);
        expect(census.ordinaryAlgebraicNumerator).toBe(
            census.batchingAndFirstFoldNumerator,
        );
    });
    it('exhibits the degree alias that full-domain verification must reject', () => {
        const result = proverInterpolationAlias();
        expect(new Set(result.points).size).toBe(32);
        expect(result.evenAgreement).toBe(true);
        expect(result.oddDifference.every((value) => value !== 0n)).toBe(true);
    });
    it('gives an auxiliary key with no bounded witness when its common matrix is zero', () => {
        const modulus = auxiliaryInputEncryptionParameters.modulus;
        expect(modulus).toBeGreaterThan(128n);
        for (let error = -64n; error < 64n; error++)
            expect((((64n - error) % modulus) + modulus) % modulus).not.toBe(
                0n,
            );
    });
});
