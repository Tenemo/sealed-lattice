import { describe, expect, it } from 'vitest';

import { isCanonicalCenteredPolynomial } from '#tests/canonical-polynomial-model.js';

describe('canonical centered polynomial', () => {
    it('accepts exactly the coefficients from -(q - 1) / 2 to (q - 1) / 2', () => {
        for (const modulus of [3n, 7681n, (1n << 127n) - 1n]) {
            const half = (modulus - 1n) / 2n;
            expect(
                isCanonicalCenteredPolynomial([-half, 0n, half], 3, modulus),
            ).toBe(true);
            expect(
                isCanonicalCenteredPolynomial([half + 1n, 0n, 0n], 3, modulus),
            ).toBe(false);
            expect(
                isCanonicalCenteredPolynomial([0n, 0n, -half - 1n], 3, modulus),
            ).toBe(false);
        }
    });

    it('refuses another coefficient count and an even modulus', () => {
        expect(isCanonicalCenteredPolynomial([0n, 0n], 3, 7n)).toBe(false);
        expect(isCanonicalCenteredPolynomial([0n, 0n, 0n, 0n], 3, 7n)).toBe(
            false,
        );
        expect(() => isCanonicalCenteredPolynomial([0n], 1, 8n)).toThrow(
            'odd modulus',
        );
    });
});
