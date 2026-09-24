import { describe, expect, it } from 'vitest';

import { statelessSignatureSecurityScreen } from '#tests/stateless-signature-security-model.js';

type Rational = Readonly<{ numerator: bigint; denominator: bigint }>;

const rational = (numerator: bigint, denominator = 1n): Rational => ({
    numerator,
    denominator,
});
const sum = (...terms: readonly Rational[]): Rational =>
    terms.reduce(
        (total, term) =>
            rational(
                total.numerator * term.denominator +
                    term.numerator * total.denominator,
                total.denominator * term.denominator,
            ),
        rational(0n),
    );
const atMostOne = (value: Rational): Rational =>
    value.numerator < value.denominator ? value : rational(1n);
const expectSameRational = (actual: Rational, expected: Rational): void => {
    expect(actual.numerator * expected.denominator).toBe(
        expected.numerator * actual.denominator,
    );
};

// FIPS 205 Table 2, SLH-DSA-SHAKE-256f: n = 32, h = 68, a = 9, k = 35 and
// lg_w = 4. Hash values range over 2^(8n), and a FORS digest selects one of
// 2^h instances and one of t = 2^a leaves in each of k trees.
const hashValueCount = 1n << (8n * 32n);
const forestInstanceCount = 1n << 68n;
const forestLeafCount = 1n << 9n;
const forestTreeCount = 35n;
const chainSteps = (1n << 4n) - 1n;
const uniformHit = rational(1n, hashValueCount);

// HK22 Theorem 4 (from HRS16) bounds a Q-query average search at density
// lambda by 8 lambda (Q+1)^2. Each public query costs two search queries, so
// Q = 2q gives 32 (q+1/2)^2 lambda, HK22 Lemma 5's operand at 2^-n.
const averageSearch = (publicQueries: bigint, density: Rational): Rational =>
    rational(
        32n * (2n * publicQueries + 1n) ** 2n * density.numerator,
        4n * density.denominator,
    );
// Union bound over groups * C(size, 2) pairs of independent uniform values.
const pairCollision = (groups: bigint, size: bigint): Rational =>
    rational(groups * size * (size - 1n), 2n * hashValueCount);
// Projection and the triangle inequality give sqrt(p) <= sqrt(p_staged) + D,
// and (u + v)^2 <= 2u^2 + 2v^2 doubles both parts.
const commonSuccess = (
    stagedSuccess: Rational,
    squaredDistance: Rational,
): Rational => {
    const total = sum(stagedSuccess, squaredDistance);
    return rational(2n * total.numerator, total.denominator);
};
// No primary source states the next two constants. They restate this
// repository's hybrid norm bound, squared distance 4 q^2/2^(8n) per hidden
// uniform point, and its square-grid bound min(1, 5/(2A)) with
// A = floor(2^(8n)/(2m)^2) for m hidden-point queries.
const squaredStateDistance = (
    publicQueries: bigint,
    hiddenPoints: bigint,
): Rational =>
    rational(4n * publicQueries ** 2n * hiddenPoints, hashValueCount);
const hiddenPointAdvantage = (pointQueries: bigint): Rational => {
    if (pointQueries === 0n) return rational(0n);
    const spacing = hashValueCount / (2n * pointQueries) ** 2n;
    return spacing === 0n
        ? rational(1n)
        : atMostOne(rational(5n, 2n * spacing));
};

const closedFormTerms = (
    queries: bigint,
    credentials: bigint,
    messagesPerCredential: bigint,
) => {
    // r digests with m_I on instance I reveal at most m_I leaves in each of
    // its trees, covering at most sum_I m_I^k <= r^k of the 2^h t^k
    // instance and leaf choices. SPHINCS+ R3.1 gives the per-instance form
    // (1 - (1 - 1/t)^gamma)^k <= (gamma/t)^k.
    const digestChoices =
        forestInstanceCount * forestLeafCount ** forestTreeCount;
    const coveredDigests = messagesPerCredential ** forestTreeCount;
    const coverage = rational(
        coveredDigests < digestChoices ? coveredDigests : digestChoices,
        digestChoices,
    );
    const chainQueries = queries + chainSteps;
    return {
        // Labels collide pairwise; each public XOF query costs two
        // hidden-point queries.
        keyedFunctions: atMostOne(
            sum(
                pairCollision(1n, credentials),
                hiddenPointAdvantage(2n * queries),
            ),
        ),
        // Output randomizers and private coins each repeat within a
        // credential.
        messageTargets: atMostOne(
            sum(
                pairCollision(credentials, messagesPerCredential),
                commonSuccess(
                    averageSearch(queries, coverage),
                    squaredStateDistance(queries, messagesPerCredential),
                ),
                pairCollision(credentials, messagesPerCredential),
            ),
        ),
        graphCollision: atMostOne(averageSearch(queries, uniformHit)),
        // Verifying the selected chain adds w - 1 queries.
        wotsEndpoints: atMostOne(
            commonSuccess(
                averageSearch(chainQueries, uniformHit),
                squaredStateDistance(chainQueries, 1n),
            ),
        ),
        // The staged success also admits guessing the unopened preimage.
        forestPreimage: atMostOne(
            commonSuccess(
                sum(averageSearch(queries, uniformHit), uniformHit),
                squaredStateDistance(queries, 1n),
            ),
        ),
    };
};

// floor(-log2(n/d)) for 0 < n <= d. With b = bitlen(d) - bitlen(n),
// 2^(b-1) < d/n < 2^(b+1), so the floor is b exactly when n * 2^b <= d.
const floorNegativeBinaryLogarithm = (value: Rational): bigint => {
    const bits = BigInt(
        value.denominator.toString(2).length -
            value.numerator.toString(2).length,
    );
    return value.numerator << bits <= value.denominator ? bits : bits - 1n;
};

describe('Conditional complete ideal signature accounting', () => {
    it('recomputes every event term from its closed form', () => {
        for (const [queries, credentials, messagesPerCredential] of [
            [0n, 1n, 1n],
            [1n, 2n, 2n],
            [1n << 80n, 10n, 10n],
            [1n << 80n, 10n, 16n],
            [1n << 90n, 10n, 10n],
            [1n << 80n, 1n << 80n, 10n],
            [1n << 80n, 10n, 512n],
            [1n << 126n, 1n, 1n],
        ] as const) {
            const value = statelessSignatureSecurityScreen(
                queries,
                credentials,
                messagesPerCredential,
            );
            const terms = closedFormTerms(
                queries,
                credentials,
                messagesPerCredential,
            );
            for (const name of [
                'keyedFunctions',
                'messageTargets',
                'graphCollision',
                'wotsEndpoints',
                'forestPreimage',
            ] as const)
                expectSameRational(value.terms[name], terms[name]);
            const bound = atMostOne(sum(...Object.values(terms)));
            expectSameRational(value.bound, bound);
            expect(value.securityBits).toBe(
                floorNegativeBinaryLogarithm(bound),
            );
        }
    });
    it('matches hand-derived terms and security bits', () => {
        // q = 1, C = 2, r = 2 and N = 2^256. The hidden-point grid spacing
        // is N/(2*2)^2 = 2^252, and C*r(r-1)/2 = 2 pairs may repeat.
        const small = statelessSignatureSecurityScreen(1n, 2n, 2n);
        // 2*1/(2N) + 5/(2*2^252).
        expectSameRational(
            small.terms.keyedFunctions,
            rational(41n, hashValueCount),
        );
        // 2/N + 2/N + 2*4*1*2/N + 2*8*3^2*2^35/(2^68*2^315).
        expectSameRational(
            small.terms.messageTargets,
            sum(rational(20n, hashValueCount), rational(144n, 1n << 348n)),
        );
        // 8*3^2/N.
        expectSameRational(
            small.terms.graphCollision,
            rational(72n, hashValueCount),
        );
        // Q = 1 + 15: 16*33^2/N + 8*16^2/N.
        expectSameRational(
            small.terms.wotsEndpoints,
            rational(19_472n, hashValueCount),
        );
        // 16*3^2/N + 8*1^2/N + 2/N.
        expectSameRational(
            small.terms.forestPreimage,
            rational(154n, hashValueCount),
        );
        // The total is 19759/N plus 144/2^348, and 2^14 < 19759 < 2^15.
        expect(small.securityBits).toBe(241n);

        // At q = 2^80 the keyed, message, graph, WOTS and forest terms are
        // near 5, 10, 4, 9 and 9 times 2^-93, so their sum lies in
        // (32, 64] * 2^-93 = (2^-88, 2^-87].
        const evaluated = statelessSignatureSecurityScreen(1n << 80n, 10n, 10n);
        expect(evaluated.bound.numerator << 88n).toBeGreaterThan(
            evaluated.bound.denominator,
        );
        expect(evaluated.bound.numerator << 87n).toBeLessThanOrEqual(
            evaluated.bound.denominator,
        );
        expect(evaluated.securityBits).toBe(87n);
    });
    it('exposes sensitivity to the signing cap and complete query count', () => {
        const queries = 1n << 80n;
        expect(
            statelessSignatureSecurityScreen(queries, 10n, 15n).securityBits,
        ).toBeGreaterThanOrEqual(80n);
        expect(
            statelessSignatureSecurityScreen(queries, 10n, 16n).securityBits,
        ).toBeLessThan(80n);
        expect(
            statelessSignatureSecurityScreen(1n << 90n, 10n, 10n).securityBits,
        ).toBeLessThan(80n);
        expect(
            statelessSignatureSecurityScreen(queries, 10n, 512n).bound,
        ).toEqual({ numerator: 1n, denominator: 1n });
    });
    it('does not collapse credential population into the one-message cap', () => {
        const one = statelessSignatureSecurityScreen(1n << 80n, 1n, 10n),
            many = statelessSignatureSecurityScreen(1n << 80n, 1n << 80n, 10n);
        expect(many.terms.graphCollision).toEqual(one.terms.graphCollision);
        expect(many.terms.wotsEndpoints).toEqual(one.terms.wotsEndpoints);
        expect(many.terms.forestPreimage).toEqual(one.terms.forestPreimage);
        expect(many.bound.numerator * one.bound.denominator).toBeGreaterThan(
            one.bound.numerator * many.bound.denominator,
        );
        expect(() => statelessSignatureSecurityScreen(1n, 0n, 1n)).toThrow(
            RangeError,
        );
    });
});
