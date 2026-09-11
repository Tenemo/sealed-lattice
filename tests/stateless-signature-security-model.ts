import { adaptiveWotsBound } from '#tests/adaptive-wots-model.js';
import { hashGraphCollisionBound } from '#tests/hash-graph-model.js';
import { labelledKeyedXofBound } from '#tests/labelled-keyed-xof-model.js';
import { multiKeyTargetBound } from '#tests/multi-key-target-model.js';
import { stagedPreimageBound } from '#tests/staged-preimage-model.js';
import { compileStatelessSignatureWork } from '#tests/stateless-signature-work-model.js';

type Fraction = Readonly<{ numerator: bigint; denominator: bigint }>;
const fraction = (numerator: bigint, denominator: bigint): Fraction => {
    let left = numerator,
        right = denominator;
    while (right !== 0n) [left, right] = [right, left % right];
    return { numerator: numerator / left, denominator: denominator / left };
};

// Conditional ideal signature screen. The query input must cover the actual
// attack and every wrapper/hash evaluation, including the final verifier.
// One-shot message caps come from protocol state, not the roster size.
// The ideal event decomposition is separate from fixed-XOF/vault security
// and efficient simulation of every oracle used by a concrete reduction.
export const statelessSignatureSecurityScreen = (
    queries: bigint,
    credentials: bigint,
    messagesPerCredential: bigint,
) => {
    if (queries < 0n || credentials < 1n || messagesPerCredential < 0n)
        throw new RangeError('Invalid signature screen operands.');
    const work = compileStatelessSignatureWork(),
        domain = 1n << (8n * work.nodeBytes);
    const keyed = labelledKeyedXofBound(queries, credentials, domain, domain),
        message = multiKeyTargetBound({
            publicQueries: queries,
            credentials,
            requestsPerCredential: messagesPerCredential,
            randomizerDomain: domain,
            coinDomain: domain,
            instances: 1n << work.totalHeight,
            leavesPerTree: work.forestLeaves,
            trees: work.forestTrees,
        });
    const terms = {
        keyedFunctions: keyed.bound,
        messageTargets: message.hedgedBound,
        graphCollision: hashGraphCollisionBound(queries, domain),
        wotsEndpoints: adaptiveWotsBound(queries, work.winternitz - 1n, domain)
            .bound,
        forestPreimage: stagedPreimageBound(queries, domain, domain).bound,
    };
    const raw = Object.values(terms).reduce(
        (sum, term) =>
            fraction(
                sum.numerator * term.denominator +
                    term.numerator * sum.denominator,
                sum.denominator * term.denominator,
            ),
        fraction(0n, 1n),
    );
    const bound = raw.numerator < raw.denominator ? raw : fraction(1n, 1n);
    // Exact floor of -log2(bound), with no floating-point rounding.
    let securityBits = 0n;
    while (bound.numerator << (securityBits + 1n) <= bound.denominator)
        securityBits++;
    return {
        queries,
        credentials,
        messagesPerCredential,
        terms,
        bound,
        securityBits,
    };
};
