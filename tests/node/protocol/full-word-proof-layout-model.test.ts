import { describe, expect, it } from 'vitest';

import {
    compileBallotWordProofLayout,
    compileFullWordProofLayout,
    compileLinkedReleaseWordProofLayout,
    proverInterpolationAlias,
} from '#tests/full-word-proof-layout-model.js';
import { completionProfile } from '#tests/supported-profile-model.js';
import { compileWideChallengeCompilerCensus } from '#tests/wide-challenge-compiler-model.js';

describe('full word-proof layout and theorem operands', () => {
    it('accounts for the emitted linked ballot rows and public operator values', () => {
        const layout = compileBallotWordProofLayout(completionProfile());
        expect(layout.headerBytes).toBe(4004n);
        expect(layout.firstWidth).toBe(33n * 16n + 48n);
        expect(layout.secondWidth).toBe(34n * 48n);
        // The FHE and auxiliary adjoints and the score column, not the 32
        // columns' every row.
        expect(layout.residentPublicOperatorBytes).toBe(
            (65536n + 4096n + 65536n) * 48n,
        );
        expect(
            compileLinkedReleaseWordProofLayout(completionProfile())
                .residentPublicOperatorBytes,
        ).toBe(2n * 65536n * 48n);
        // One 64-byte salt seed for each of the three oracle trees and the
        // sixteen folded layers' trees, and twenty 128-byte message salts.
        expect(layout.treeCount).toBe(19n);
        expect(layout.saltSeedBytes).toBe(19n * 64n);
        expect(layout.minimumRequestedRandomBytes).toBe(
            19n * 64n + 20n * 128n + (33n + 96n + 66n + 50n) * 65536n,
        );
        expect(layout.minimumRequestedRandomBytes).toBeGreaterThan(
            layout.saltSeedBytes + layout.proverMaskBytes,
        );
        expect(layout.maximumMultiproofBytes).toBeGreaterThan(8_388_608n);
        expect(layout.maximumMultiproofBytes).toBeLessThan(
            layout.maximumProofBytes,
        );
        expect(layout.maximumCachedNodeDigestBytes).toBeLessThan(2_097_152n);
    });

    it('matches the emitted header and leaf shapes', () => {
        const layout = compileFullWordProofLayout(completionProfile());
        expect(layout.foldCount).toBe(17);
        expect(layout.headerBytes).toBe(
            4n + 128n + 192n + 48n + 20n * 128n + 16n * 64n + 48n,
        );
        expect(layout.firstWidth).toBe(356n * 16n + 48n);
        expect(layout.secondWidth).toBe(377n * 48n);
        expect(layout.proverInterpolationPoints).toBe(131072);
        expect(
            layout.expandedFirstOracleBytes + layout.expandedSecondOracleBytes,
        ).toBe(262144n * (5744n + 18096n));
        expect(layout.maximumProofBytes).toBeLessThan(67_108_864n);
        expect(layout.maximumMultiproofBytes).toBeLessThan(
            layout.maximumProofBytes,
        );
        expect(layout.maximumCachedNodeDigestBytes).toBeLessThan(2_097_152n);
    });
    it('charges the actual lookup, affine, batching, and first-fold events', () => {
        const census = compileWideChallengeCompilerCensus(completionProfile());
        expect(census.lookupEntryCount).toBe(375n * 65536n);
        expect(census.lookupRootDegree).toBe(376n * 65536n - 1n);
        expect(census.correlatedRowCount).toBe(2n * (734n + 413n));
        expect(census.batchingAndFirstFoldNumerator).toBe(2295n * 262144n);
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
});
