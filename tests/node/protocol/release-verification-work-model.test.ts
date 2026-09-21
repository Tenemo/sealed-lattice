import { describe, expect, it } from 'vitest';

import { compileReleaseVerificationWorkload } from '#tests/release-verification-work-model.js';

const attempts = (
    replayedCandidates: bigint,
    changedEnvelopes = 0n,
    changedProofBodies = 0n,
) => ({ replayedCandidates, changedEnvelopes, changedProofBodies });

describe('public release verification work', () => {
    it('counts full retry work without counting replay as a new proof oracle point', () => {
        const result = compileReleaseVerificationWorkload(attempts(3n, 2n, 1n));
        // The emitted verifier has seventeen folds: twenty rounds plus the
        // final verifier message, one context, two plain digests and one body.
        expect(result.perAttempt.minimumProofCoreQueries).toBe(
            21n + 20n + 20n + 1n,
        );
        expect(result.perAttempt.minimumKnownHashCalls).toBe(65n);
        expect(result.totals.minimumKnownHashCalls).toBe(390n);
        expect(result.totals.plainStatementDigestPasses).toBe(12n);
        expect(result.totals.completedBodyDigestPasses).toBe(6n);
        expect(result.totals.envelopeVerificationCalls).toBe(6n);
        expect(result.totals.commonPolynomialCalls).toBe(6n);
        expect(result.distinctProofOracleInputs).toBeNull();
        expect(result.lifetimeAttemptLimit).toBeNull();
        expect(result.completeSignatureAndCommonPolynomialHashWork).toBeNull();
    });

    it('keeps candidate changes distinct even when their executed core counts match', () => {
        const replay = compileReleaseVerificationWorkload(attempts(4n));
        const envelopes = compileReleaseVerificationWorkload(attempts(0n, 4n));
        const proofs = compileReleaseVerificationWorkload(attempts(0n, 0n, 4n));
        expect(replay.totals).toEqual(envelopes.totals);
        expect(proofs.totals).toEqual(envelopes.totals);
        expect(replay.attempts).not.toEqual(envelopes.attempts);
        expect(proofs.attempts).not.toEqual(envelopes.attempts);
    });

    it('crosses the allocation using mandatory calls without confusing an upper bound with a witness', () => {
        const single = compileReleaseVerificationWorkload(attempts(1n));
        const below = compileReleaseVerificationWorkload(
            attempts(single.firstAttemptCountExceedingCoreLowerBound - 1n),
        );
        const above = compileReleaseVerificationWorkload(
            attempts(single.firstAttemptCountExceedingCoreLowerBound),
        );
        expect(below.totals.minimumProofCoreQueries).toBeLessThanOrEqual(
            1n << 32n,
        );
        expect(above.totals.minimumProofCoreQueries).toBeGreaterThan(1n << 32n);
        const covered = compileReleaseVerificationWorkload(
            attempts(single.maximumAttemptsCoveredByCoreUpperBound),
        );
        expect(covered.totals.maximumProofCoreQueries).toBeLessThanOrEqual(
            1n << 32n,
        );
        expect(single.maximumAttemptsCoveredByCoreUpperBound).toBeLessThan(
            single.firstAttemptCountExceedingCoreLowerBound,
        );
    });

    it('handles empty and symbolic large workloads with exact arithmetic', () => {
        const empty = compileReleaseVerificationWorkload(attempts(0n));
        expect(Object.values(empty.totals).every((value) => value === 0n)).toBe(
            true,
        );
        const count = 1n << 80n;
        const large = compileReleaseVerificationWorkload(attempts(count));
        expect(large.totals.minimumKnownHashCalls).toBe(65n * count);
        expect(large.lifetimeAttemptLimit).toBeNull();
    });

    it('refuses negative candidate populations', () => {
        for (const counts of [
            attempts(-1n),
            attempts(0n, -1n),
            attempts(0n, 0n, -1n),
        ])
            expect(() => compileReleaseVerificationWorkload(counts)).toThrow(
                RangeError,
            );
    });
});
