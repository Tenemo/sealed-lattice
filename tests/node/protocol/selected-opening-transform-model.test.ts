import { describe, expect, it } from 'vitest';

import {
    compileSelectedOpeningTransformCensus,
    directlyEvaluateOpeningModel,
    evaluateSelectedOpeningModel,
} from '#tests/selected-opening-transform-model.js';

describe('requested opening transforms', () => {
    it('matches direct polynomial evaluation for every small subset', () => {
        for (const length of [2, 4, 8]) {
            for (const coefficients of [
                Array<bigint>(length).fill(0n),
                Array<bigint>(length).fill(16n),
                Array.from({ length }, (_, index) =>
                    BigInt((index * index + 3) % 17),
                ),
            ]) {
                for (let mask = 0; mask < 1 << length; mask++) {
                    const indices = Array.from(
                        { length },
                        (_, index) => index,
                    ).filter((index) => (mask & (1 << index)) !== 0);
                    expect(
                        evaluateSelectedOpeningModel(coefficients, indices),
                    ).toEqual(
                        indices.map((index) =>
                            directlyEvaluateOpeningModel(coefficients, index),
                        ),
                    );
                }
                const repeated = [length - 1, 0, length - 1];
                expect(
                    evaluateSelectedOpeningModel(coefficients, repeated),
                ).toEqual(
                    repeated.map((index) =>
                        directlyEvaluateOpeningModel(coefficients, index),
                    ),
                );
            }
        }
    });
    it('refuses invalid input without changing coefficients', () => {
        const coefficients = [0n, 16n];
        for (const indices of [[-1], [2], [0.5], [NaN]])
            expect(() =>
                evaluateSelectedOpeningModel(coefficients, indices),
            ).toThrow();
        expect(() => evaluateSelectedOpeningModel([17n, 0n], [0])).toThrow();
        expect(coefficients).toEqual([0n, 16n]);
    });
    it('bounds full-domain selection work and scalar selector payloads', () => {
        const model = compileSelectedOpeningTransformCensus();
        expect(model.maximumSelectedBranches).toBeLessThan(
            model.fullButterflies,
        );
        expect(
            model.maximumSelectionPairBytes +
                model.maximumSelectionIndexBytes +
                model.maximumSelectedExtensionOutputBytes,
        ).toBeLessThan(1_048_576n);
    });
});
