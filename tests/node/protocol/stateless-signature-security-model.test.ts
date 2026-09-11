import { describe, expect, it } from 'vitest';

import { statelessSignatureSecurityScreen } from '#tests/stateless-signature-security-model.js';

describe('Conditional complete ideal signature accounting', () => {
    it('sums the distinct event bounds with exact rational arithmetic', () => {
        const value = statelessSignatureSecurityScreen(1n << 80n, 10n, 10n);
        // Independent unreduced common-denominator sum of the primitive terms.
        const terms = Object.values(value.terms),
            denominator = terms.reduce(
                (product, term) => product * term.denominator,
                1n,
            ),
            numerator = terms.reduce(
                (sum, term) =>
                    sum + term.numerator * (denominator / term.denominator),
                0n,
            );
        expect(value.bound.numerator * denominator).toBe(
            numerator * value.bound.denominator,
        );
        expect(value.bound.numerator << value.securityBits).toBeLessThanOrEqual(
            value.bound.denominator,
        );
        expect(
            value.bound.numerator << (value.securityBits + 1n),
        ).toBeGreaterThan(value.bound.denominator);
        expect(value.securityBits).toBeGreaterThanOrEqual(80n);
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
