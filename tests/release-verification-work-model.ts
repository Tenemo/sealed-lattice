import { compileProofVerifierQueryCensus } from '#tests/proof-verifier-query-model.js';
import { proofCompilerCaps } from '#tests/wide-challenge-compiler-model.js';

interface ReleaseVerificationAttempts {
    readonly replayedCandidates: bigint;
    readonly changedEnvelopes: bigint;
    readonly changedProofBodies: bigint;
}

// The prefix already holds a verified certificate/context and a valid relation
// body. A corrupt author can sign an envelope with the wrong body identity.
// Its proof completes before final authentication refuses the share; the
// context survives, permitting another public verification attempt.
export const compileReleaseVerificationWorkload = (
    attempts: ReleaseVerificationAttempts,
) => {
    for (const count of Object.values(attempts))
        if (typeof count !== 'bigint' || count < 0n)
            throw new RangeError(
                'Verification counts must be nonnegative integers.',
            );
    const count =
        attempts.replayedCandidates +
        attempts.changedEnvelopes +
        attempts.changedProofBodies;
    const proof = compileProofVerifierQueryCensus();
    const minimumProofCoreQueries = BigInt(
        proof.verifierMessageQueries +
            proof.chainStateQueries +
            proof.messageRootQueries +
            proof.contextQueries +
            proof.statementDigestQueries,
    );
    const maximumProofCoreQueries = BigInt(proof.maximumCoreQueries);
    const completedBodyDigestPasses = 1n;
    // Every attempt's calls are oracle calls of the experiment, which the
    // query cap bounds together with the adversary's.
    const queryCap = proofCompilerCaps.adversaryQueries;
    return {
        attempts: { ...attempts },
        count,
        perAttempt: {
            minimumProofCoreQueries,
            maximumProofCoreQueries,
            completedBodyDigestPasses,
            minimumKnownHashCalls:
                minimumProofCoreQueries + completedBodyDigestPasses,
        },
        totals: {
            minimumProofCoreQueries: count * minimumProofCoreQueries,
            maximumProofCoreQueries: count * maximumProofCoreQueries,
            completedBodyDigestPasses: count * completedBodyDigestPasses,
            minimumKnownHashCalls:
                count * (minimumProofCoreQueries + completedBodyDigestPasses),
            envelopeVerificationCalls: count,
            commonPolynomialCalls: count,
        },
        queryCap,
        // These compare only the proof core with the whole query cap, before
        // subtracting other charged work. They are neither runtime limits nor
        // full-wrapper bounds.
        maximumAttemptsCoveredByCoreUpperBound:
            queryCap / maximumProofCoreQueries,
        firstAttemptCountExceedingCoreLowerBound:
            queryCap / minimumProofCoreQueries + 1n,
        // Repeated execution is not necessarily a new random-oracle point.
        // Changed envelopes with a fixed body still reuse the proof inputs.
        distinctProofOracleInputs: null,
        lifetimeAttemptLimit: null,
        completeSignatureAndCommonPolynomialHashWork: null,
    };
};
