import { describe, expect, it } from 'vitest';

import { compileReductionConstructorPrice } from '#tests/security-margin/constructor-price.js';
import {
    compileReductionWork,
    constructionPopulation,
    fixedReductionComponentBounds,
    reductionPopulationLimit,
    slopeReductionComponentBounds,
} from '#tests/security-margin/reduction-work.js';

describe('complete reduction constructor pricing', () => {
    it('fits independently rounded bounds for every constructed component', () => {
        const price = compileReductionConstructorPrice();
        for (const [name, work] of Object.entries(price.fixed)) {
            expect(work).toBeGreaterThan(0n);
            expect(work).toBeLessThanOrEqual(
                fixedReductionComponentBounds[
                    name as keyof typeof fixedReductionComponentBounds
                ],
            );
        }
        for (const [name, multiplier] of Object.entries(price.slope)) {
            expect(multiplier).toBeGreaterThan(0n);
            expect(multiplier).toBeLessThanOrEqual(
                slopeReductionComponentBounds[
                    name as keyof typeof slopeReductionComponentBounds
                ],
            );
        }
        expect(price.fixedExternalQueries).toBeLessThan(1n << 29n);
        expect(price.originalMemory).toBeLessThan(1n << 175n);
        expect(() => compileReductionConstructorPrice(0n)).toThrow();
    });

    it('dominates the complete literal formulas beyond the reference population', () => {
        for (const population of [
            1n,
            constructionPopulation - 1n,
            constructionPopulation,
            constructionPopulation + 1n,
            37n,
            401n,
            1n << 64n,
            reductionPopulationLimit(),
        ]) {
            const constructed = compileReductionConstructorPrice(population);
            const envelope = compileReductionWork(population);
            expect(constructed.fixedWork).toBeLessThanOrEqual(
                envelope.fixedWork,
            );
            expect(constructed.workSlope).toBeLessThanOrEqual(
                envelope.workSlope,
            );
            expect(constructed.fixedExternalQueries).toBeLessThanOrEqual(
                envelope.fixedExternalQueries,
            );
            expect(constructed.originalMemory).toBeLessThanOrEqual(
                envelope.originalMemory,
            );
        }
    });

    it('preserves the affine query count and charges every changed origin', () => {
        const before = compileReductionConstructorPrice(19n);
        const reference = compileReductionConstructorPrice(20n);
        const after = compileReductionConstructorPrice(21n);
        expect(
            after.fixedExternalQueries - reference.fixedExternalQueries,
        ).toBe(reference.fixedExternalQueries - before.fixedExternalQueries);
        expect(after.fixed.descriptorRouting).toBeGreaterThan(
            reference.fixed.descriptorRouting,
        );
        expect(after.fixed.publicColumnTrees).toBeGreaterThan(
            reference.fixed.publicColumnTrees,
        );
        expect(after.fixed.statements).toBeGreaterThan(
            reference.fixed.statements,
        );
        expect(after.slope.alternativeRecovery).toBeGreaterThan(
            reference.slope.alternativeRecovery,
        );
    });
});
