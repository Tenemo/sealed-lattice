import { compileProofVerifierQueryCensus } from '#tests/proof-verifier-query-model.js';
import { compileWideChallengeCompilerCensus } from '#tests/wide-challenge-compiler-model.js';

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
            proof.contextQueries,
    );
    const maximumProofCoreQueries = BigInt(proof.maximumCoreQueries);
    // The caller computes the raw statement digest and StatementStream checks
    // it independently. The role-bound context hash is already in the core.
    const plainStatementDigestPasses = 2n;
    const completedBodyDigestPasses = 1n;
    const selectedVerificationQueryBudget =
        compileWideChallengeCompilerCensus().verificationBudget;
    return {
        attempts: { ...attempts },
        count,
        perAttempt: {
            minimumProofCoreQueries,
            maximumProofCoreQueries,
            plainStatementDigestPasses,
            completedBodyDigestPasses,
            minimumKnownHashCalls:
                minimumProofCoreQueries +
                plainStatementDigestPasses +
                completedBodyDigestPasses,
        },
        totals: {
            minimumProofCoreQueries: count * minimumProofCoreQueries,
            maximumProofCoreQueries: count * maximumProofCoreQueries,
            plainStatementDigestPasses: count * plainStatementDigestPasses,
            completedBodyDigestPasses: count * completedBodyDigestPasses,
            minimumKnownHashCalls:
                count *
                (minimumProofCoreQueries +
                    plainStatementDigestPasses +
                    completedBodyDigestPasses),
            envelopeVerificationCalls: count,
            commonPolynomialCalls: count,
        },
        selectedVerificationQueryBudget,
        // These compare only the proof core with the selected conditional
        // allocation, before subtracting other charged work. They are neither
        // runtime limits nor full-wrapper bounds.
        maximumAttemptsCoveredByCoreUpperBound:
            selectedVerificationQueryBudget / maximumProofCoreQueries,
        firstAttemptCountExceedingCoreLowerBound:
            selectedVerificationQueryBudget / minimumProofCoreQueries + 1n,
        // Repeated execution is not necessarily a new random-oracle point.
        // Changed envelopes with a fixed body still reuse the proof inputs.
        distinctProofOracleInputs: null,
        lifetimeAttemptLimit: null,
        completeSignatureAndCommonPolynomialHashWork: null,
    };
};
