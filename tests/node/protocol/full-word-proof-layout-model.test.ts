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
        expect(layout.headerBytes).toBe(3936n);
        expect(layout.firstWidth).toBe(31n * 16n + 48n);
        expect(layout.secondWidth).toBe(33n * 48n);
        // The FHE and auxiliary adjoints and the score column, not the 30
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
            19n * 64n + 20n * 128n + (31n + 96n + 64n + 50n) * 65536n,
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
            64n + 192n + 48n + 20n * 128n + 16n * 64n + 48n + 64n + 48n * 280n,
        );
        expect(layout.firstWidth).toBe(446n * 16n + 48n);
        expect(layout.secondWidth).toBe(479n * 48n);
        expect(layout.proverInterpolationPoints).toBe(131072);
        expect(
            layout.expandedFirstOracleBytes + layout.expandedSecondOracleBytes,
        ).toBe(262144n * (7184n + 22992n));
        expect(layout.maximumProofBytes).toBeLessThan(0xffff_fffbn);
        expect(layout.maximumMultiproofBytes).toBeLessThan(
            layout.maximumProofBytes,
        );
        expect(layout.maximumCachedNodeDigestBytes).toBeLessThan(2_097_152n);
    });
    it('charges the actual lookup, affine, batching, and first-fold events', () => {
        const census = compileWideChallengeCompilerCensus(completionProfile());
        expect(census.lookupEntryCount).toBe(477n * 65536n);
        expect(census.lookupRootDegree).toBe(478n * 65536n - 1n);
        expect(census.correlatedRowCount).toBe(2n * (926n + 518n + 2n * 280n));
        expect(census.batchingAndFirstFoldNumerator).toBe(
            (2888n + 4n * 280n) * 262144n + (17n ** 7n * 262144n ** 2n) / 512n,
        );
        expect(census.ordinaryAlgebraicNumerator).toBe(
            census.batchingAndFirstFoldNumerator,
        );
    });
    it('exhibits the degree alias that full-domain verification must refuse', () => {
        const result = proverInterpolationAlias();
        expect(new Set(result.points).size).toBe(32);
        expect(result.evenAgreement).toBe(true);
        expect(result.oddDifference.every((value) => value !== 0n)).toBe(true);
    });
});
