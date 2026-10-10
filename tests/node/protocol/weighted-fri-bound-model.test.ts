import { describe, expect, it } from 'vitest';

import { compileWeightedFriBound } from '#tests/weighted-fri-bound-model.js';

describe('weighted FRI transition arithmetic', () => {
    it('checks the agreement premise exactly at the current threshold', () => {
        const value = compileWeightedFriBound(1n << 18n, 193n, 256n);
        expect(value.analysisParameter).toBe(8n);
        expect(193n ** 2n * 512n).toBeGreaterThan(289n * 256n ** 2n);
        expect(value.thresholdLeft).toBeGreaterThanOrEqual(
            value.thresholdRight,
        );
        expect(() => compileWeightedFriBound(1n << 18n, 192n, 256n)).toThrow(
            'agreement premise',
        );
        for (const domain of [0n, 2n, 6n])
            expect(() => compileWeightedFriBound(domain, 193n, 256n)).toThrow(
                'domain',
            );
    });

    it('upper-bounds both source expressions without floating square roots', () => {
        for (const domain of [16n, 1n << 18n, 1n << 20n]) {
            const value = compileWeightedFriBound(domain, 193n, 256n);
            const m = 8n;
            for (const fold of value.folds) {
                expect(fold.weightDenominator * fold.targetDomainSize).toBe(
                    domain,
                );
                // Square the literal Theorem 7.2 terms at rate 1/2. This
                // independent comparison does not reuse the rational shortcut.
                const firstSquaredNumerator =
                    (2n * m + 1n) ** 14n * fold.targetDomainSize ** 4n * 8n;
                const firstSquaredDenominator = 2n ** 14n * 9n;
                expect(
                    fold.first.numerator ** 2n * firstSquaredDenominator,
                ).toBeGreaterThanOrEqual(
                    firstSquaredNumerator * fold.first.denominator ** 2n,
                );
                const secondSquared =
                    (2n * m + 1n) ** 2n * (domain + 1n) ** 2n * 2n;
                expect(fold.second.numerator ** 2n).toBeGreaterThanOrEqual(
                    secondSquared * fold.second.denominator ** 2n,
                );
                expect(fold.second).toEqual({
                    numerator: 51n * (domain + 1n),
                    denominator: 2n,
                });
                for (const term of [fold.first, fold.second]) {
                    expect(
                        fold.upper.numerator * term.denominator,
                    ).toBeGreaterThanOrEqual(
                        term.numerator * fold.upper.denominator,
                    );
                    expect(
                        value.ceiling * term.denominator,
                    ).toBeGreaterThanOrEqual(term.numerator);
                }
            }
            expect((value.ceiling - 1n) * value.upper.denominator).toBeLessThan(
                value.upper.numerator,
            );
        }
        // With a larger original domain the late weight term dominates,
        // even though the target fold has only two points.
        const late = compileWeightedFriBound(1n << 20n, 193n, 256n).folds.slice(
            -1,
        )[0];
        expect(late.upper).toEqual(late.second);
    });

    it('charges the first fold at the original domain size', () => {
        const domain = 1n << 18n;
        const value = compileWeightedFriBound(domain, 193n, 256n);
        expect(value.folds).toHaveLength(17);
        expect(value.ceiling).toBe((17n ** 7n * domain ** 2n) / 512n);
        expect(value.ceiling).toBeGreaterThan(domain);
    });
});
