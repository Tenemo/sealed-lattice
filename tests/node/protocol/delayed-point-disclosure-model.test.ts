import { describe, expect, it } from 'vitest';

import {
    compileDelayedDisclosureBounds,
    noPublicQuerySliceCoupling,
    delayedPointDisclosure,
    delayedSliceReprogramming,
} from '#tests/delayed-point-disclosure-model.js';

describe('Delayed disclosure of an oracle point', () => {
    it('preserves every complete oracle view with only keyed preprocessing', () => {
        const value = noPublicQuerySliceCoupling();
        expect(value.views.length).toBe(512);
        const collectionMessages = new Set<number>();
        for (const entry of value.views) {
            expect(entry.original * value.replacedSamples).toBe(
                entry.replaced * value.originalSamples,
            );
            const [first, message, second, parameter, table] = JSON.parse(
                entry.view,
            ) as number[];
            // Independently recover both keyed replies from the disclosed row.
            const row = Math.floor(table / 16 ** parameter) % 16;
            expect(first).toBe(row % 2);
            expect(message).toBe(first);
            expect(second).toBe(Math.floor(row / 2 ** (2 + message)) % 2);
            collectionMessages.add(message);
        }
        expect([...collectionMessages].sort()).toEqual([0, 1]);
    });
    it('violates the quadratic point bound with one ordinary XOR query', () => {
        for (let point = 0; point < 64; point++) {
            const value = delayedPointDisclosure(8, point);
            expect(value.zeroProbability).toEqual({
                numerator: 49n,
                denominator: 256n,
            });
            expect(value.markedProbability).toEqual({
                numerator: 1225n,
                denominator: 4096n,
            });
            expect(value.advantage).toEqual({
                numerator: 441n,
                denominator: 4096n,
            });
            expect(value.proposedQuadraticBound).toEqual({
                numerator: 1n,
                denominator: 16n,
            });
        }
    });
    it('matches an independent closed form and the norm bound', () => {
        for (const squareRoot of [2, 4, 8, 16, 32, 64])
            for (const point of [0, 1, squareRoot * squareRoot - 1]) {
                const value = delayedPointDisclosure(squareRoot, point),
                    size = BigInt(value.size),
                    root = BigInt(squareRoot);
                expect(value.advantage.numerator * size * size).toBe(
                    value.advantage.denominator * (root - 1n) * (size - 1n),
                );
                expect(value.advantage.numerator * root).toBeLessThanOrEqual(
                    2n * value.advantage.denominator,
                );
            }
    });
    it('also violates the claimed slice-switch bound while counting both hash queries', () => {
        for (const point of [0, 1, 2047, 4095])
            for (const pattern of [0, 1, 2, 3]) {
                const value = delayedSliceReprogramming(64, point, pattern);
                expect(value.publicHashQueries).toBe(2);
                expect(value.advantage).toEqual({
                    numerator: 257985n,
                    denominator: 33554432n,
                });
                expect(value.proposedQuadraticBound).toEqual({
                    numerator: 1n,
                    denominator: 256n,
                });
                expect(
                    value.advantage.numerator *
                        value.proposedQuadraticBound.denominator,
                ).toBeGreaterThan(
                    value.proposedQuadraticBound.numerator *
                        value.advantage.denominator,
                );
            }
    });
    it('rejects invalid controls instead of normalizing a different experiment', () => {
        expect(() => delayedPointDisclosure(3, 0)).toThrow(RangeError);
        expect(() => delayedPointDisclosure(4, 16)).toThrow(RangeError);
        expect(() => delayedSliceReprogramming(4, 0, 4)).toThrow(RangeError);
    });
    it('accounts for both the search probability and the amplitude cross term', () => {
        const value = compileDelayedDisclosureBounds(3n, 2n, 12, 10);
        expect(value.squaredDistance).toEqual({
            numerator: 1n,
            denominator: 16n,
        });
        expect(value.idealSearch).toEqual({
            numerator: 49n,
            denominator: 512n,
        });
        expect(value.correctedSuccessUpper).toEqual({
            numerator: 81n,
            denominator: 256n,
        });
        expect(
            compileDelayedDisclosureBounds(0n, 0n, 4, 4).correctedSuccessUpper,
        ).toEqual({ numerator: 1n, denominator: 2n });
        const noPreprocessing = compileDelayedDisclosureBounds(3n, 0n, 12, 10);
        expect(noPreprocessing.squaredDistance.numerator).toBe(0n);
        expect(noPreprocessing.correctedSuccessUpper).toEqual({
            numerator: 49n,
            denominator: 512n,
        });
        expect(() => compileDelayedDisclosureBounds(1n, 2n, 256, 256)).toThrow(
            RangeError,
        );
        // Unit states (3,4)/5 and (5,12)/13, projected onto coordinate zero.
        // Direct exact arithmetic shows why p_ideal + D^2 is insufficient.
        const commonDenominator = 4225n,
            realSuccess = 9n * 169n,
            idealSuccess = 25n * 25n;
        const squaredDistance = 14n ** 2n + (-8n) ** 2n;
        expect(realSuccess).toBeGreaterThan(idealSuccess + squaredDistance);
        expect(realSuccess).toBeLessThanOrEqual(
            2n * idealSuccess + 2n * squaredDistance,
        );
        expect(realSuccess).toBeLessThanOrEqual(commonDenominator);
    });
});
