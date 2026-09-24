import { describe, expect, it } from 'vitest';

import { delayedPointDisclosure } from '#tests/delayed-point-disclosure-model.js';
import {
    groverDecisionProbability,
    squareGridWeights,
    unrevealedPointQueryBound,
    undetectabilityCollectionViews,
    idealCollectionPreimageBound,
} from '#tests/unrevealed-point-query-model.js';

type Fraction = { numerator: bigint; denominator: bigint };
const sum = (values: Fraction[]) =>
    values.reduce(
        (a, b) => ({
            numerator:
                a.numerator * b.denominator + b.numerator * a.denominator,
            denominator: a.denominator * b.denominator,
        }),
        { numerator: 0n, denominator: 1n },
    );
const atMost = (a: Fraction, b: Fraction) =>
    a.numerator * b.denominator <= b.numerator * a.denominator;

describe('Unrevealed-point query bound', () => {
    it('matches both undetectability worlds with adaptive collection preprocessing', () => {
        const value = undetectabilityCollectionViews();
        for (const view of value.views) {
            expect(view.uniform * value.simulatedSamples).toBe(
                view.zeroPointOracle * value.originalSamples,
            );
            expect(view.image * value.simulatedSamples).toBe(
                view.onePointOracle * value.originalSamples,
            );
            const [first, target, second, collection, reply, table] =
                JSON.parse(view.view) as number[];
            expect(target).toBe(1 + first);
            expect(collection).toBe(2 - first);
            expect(collection).not.toBe(target);
            expect(collection).not.toBe(0);
            expect(reply).toBe(
                Math.floor(table / 2 ** (2 * collection + second)) % 2,
            );
        }
        // The full-function view can distinguish an output outside the image.
        // This control prevents an accidentally identical pair of experiments.
        const outside = value.views.find(
            (entry) => entry.view === '[1,2,0,1,0,0]',
        );
        expect(outside).toMatchObject({
            uniform: 1n,
            image: 0n,
            zeroPointOracle: 8n,
            onePointOracle: 0n,
        });
    });
    it('reproduces all monomials and bounds every binary grid assignment', () => {
        for (const size of [64n, 257n])
            for (const degree of [2, 4, 6]) {
                const weights = squareGridWeights(size, degree);
                for (let power = 0; power <= degree; power++) {
                    const value = sum(
                        weights.map(({ node, weight }) => ({
                            numerator: weight.numerator * node ** BigInt(power),
                            denominator: weight.denominator,
                        })),
                    );
                    expect(value.numerator).toBe(value.denominator);
                }
                const limit = unrevealedPointQueryBound(
                    BigInt(degree / 2),
                    size,
                ).bound;
                for (let mask = 0; mask < 2 ** (degree + 1); mask++) {
                    const value = sum(
                        weights.map(({ weight }, index) => ({
                            numerator:
                                weight.numerator * BigInt((mask >> index) & 1),
                            denominator: weight.denominator,
                        })),
                    );
                    const difference = {
                        numerator:
                            value.numerator -
                            BigInt(mask & 1) * value.denominator,
                        denominator: value.denominator,
                    };
                    if (difference.numerator < 0n)
                        difference.numerator = -difference.numerator;
                    expect(atMost(difference, limit)).toBe(true);
                }
            }
    });
    it('matches exact query-and-diffusion probabilities throughout the domain', () => {
        expect(groverDecisionProbability(64, 1, 1)).toEqual({
            numerator: 63n,
            denominator: 1024n,
        });
        for (const size of [64, 256])
            for (const queries of [1, 2, 3]) {
                const weights = squareGridWeights(BigInt(size), 2 * queries);
                const reconstructed = sum(
                    weights.map(({ node, weight }) => {
                        const probability = groverDecisionProbability(
                            size,
                            Number(node),
                            queries,
                        );
                        return {
                            numerator: weight.numerator * probability.numerator,
                            denominator:
                                weight.denominator * probability.denominator,
                        };
                    }),
                );
                const expected = groverDecisionProbability(size, 1, queries);
                expect(reconstructed.numerator * expected.denominator).toBe(
                    expected.numerator * reconstructed.denominator,
                );
                expect(
                    atMost(
                        expected,
                        unrevealedPointQueryBound(BigInt(queries), BigInt(size))
                            .bound,
                    ),
                ).toBe(true);
                for (let marked = 0; marked <= size; marked++) {
                    const value = groverDecisionProbability(
                        size,
                        marked,
                        queries,
                    );
                    expect(
                        value.numerator >= 0n &&
                            value.numerator <= value.denominator,
                    ).toBe(true);
                }
            }
    });
    it('does not apply when the oracle point is disclosed later', () => {
        const revealed = delayedPointDisclosure(64, 0).advantage;
        expect(
            atMost(revealed, unrevealedPointQueryBound(1n, 4096n).bound),
        ).toBe(false);
    });
    it('handles the cryptographic scale without materializing its grid', () => {
        const value = unrevealedPointQueryBound(2n * (1n << 80n), 1n << 256n);
        expect(value.spacing).toBe(1n << 92n);
        expect(value.bound).toEqual({ numerator: 5n, denominator: 1n << 93n });
        expect(unrevealedPointQueryBound(0n, 1n).bound).toEqual({
            numerator: 0n,
            denominator: 1n,
        });
        expect(unrevealedPointQueryBound(2n, 16n).bound).toEqual({
            numerator: 1n,
            denominator: 1n,
        });
        expect(() => unrevealedPointQueryBound(-1n, 16n)).toThrow(RangeError);
        expect(() => squareGridWeights(15n, 4)).toThrow(RangeError);
    });
    it('charges the additional preimage check before the undetectability reduction', () => {
        const value = idealCollectionPreimageBound(1n, 4096n);
        expect(value.undetectability.queries).toBe(4n);
        expect(value.undetectability.bound).toEqual({
            numerator: 5n,
            denominator: 128n,
        });
        expect(value.independentTargetSearch).toEqual({
            numerator: 9n,
            denominator: 512n,
        });
        expect(value.bound).toEqual({ numerator: 29n, denominator: 512n });
        expect(idealCollectionPreimageBound(10n, 16n).bound).toEqual({
            numerator: 1n,
            denominator: 1n,
        });
        expect(() => idealCollectionPreimageBound(-1n, 4096n)).toThrow(
            RangeError,
        );
    });
});
