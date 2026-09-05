import { describe, expect, it } from 'vitest';

import { compileByteCarryLiftingCensus } from '#tests/byte-carry-lifting-model.js';

describe('integer byte and carry lifting', () => {
    it('preserves the full congruence and excludes a field alias with bounded carries', () => {
        const census = compileByteCarryLiftingCensus();
        expect(census.positiveIntegerEquations).toBe(32 * 8 * 7);
        expect(census.maximumCarry).toBeLessThan(census.carryBound);
        expect(census.maximumQuotient).toBeLessThan(census.quotientBound);
        expect(census.residualBound).toBeLessThan(census.field);
        // With radix 2^96, the independently known prime has high digit
        // 2^32-1. The modular cheat therefore needs its negative as a carry.
        expect(census.largestCheatingCarry).toBe((1n << 32n) - 1n);
        expect(census.largestCheatingCarry).toBeGreaterThan(census.carryBound);
        expect(census.outOfRangeCarries).toBe(1);
        expect(census.aliasIntegerResidual).toBe(census.field);
        expect(census.aliasIntegerResidual).not.toBe(0n);
    });
});
