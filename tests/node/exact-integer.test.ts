import { describe, expect, it } from 'vitest';

import {
    absolute,
    binomial,
    bitLength,
    byteLength,
    ceilingDivide,
    littleEndian,
    maximum,
} from '#tests/exact-integer.js';

describe('exact integer helpers', () => {
    it('measure zero, powers of two and their predecessors', () => {
        expect(bitLength(0n)).toBe(0);
        expect(byteLength(0n)).toBe(0);
        for (const exponent of [0, 1, 7, 8, 63, 64, 255]) {
            const power = 1n << BigInt(exponent);
            expect(bitLength(power)).toBe(exponent + 1);
            expect(bitLength(power - 1n)).toBe(exponent);
            expect(byteLength(power)).toBe(Math.ceil((exponent + 1) / 8));
        }
        expect(() => bitLength(-1n)).toThrow(RangeError);
        expect(() => byteLength(-256n)).toThrow(RangeError);
    });

    it('divide up, compare and count subsets exactly', () => {
        expect(ceilingDivide(0n, 7n)).toBe(0n);
        expect(ceilingDivide(14n, 7n)).toBe(2n);
        expect(ceilingDivide(15n, 7n)).toBe(3n);
        expect(() => ceilingDivide(1n, 0n)).toThrow(RangeError);
        expect(() => ceilingDivide(-1n, 7n)).toThrow(RangeError);
        expect(absolute(-5n)).toBe(5n);
        expect(absolute(5n)).toBe(5n);
        expect(maximum([-3n, 2n, 1n])).toBe(2n);
        expect(maximum([-3n])).toBe(-3n);
        expect(() => maximum([])).toThrow(RangeError);
        // Pascal's rule over a full row checks every coefficient.
        for (let count = 1n; count < 40n; count++)
            expect(binomial(40n, count)).toBe(
                binomial(39n, count - 1n) + binomial(39n, count),
            );
        expect(binomial(40n, 0n)).toBe(1n);
        expect(binomial(40n, 40n)).toBe(1n);
        expect(binomial(6, 2)).toBe(15n);
        expect(binomial(4n, 5n)).toBe(0n);
        expect(binomial(64n, 32n)).toBe(1_832_624_140_942_590_534n);
        expect(() => binomial(4n, -1n)).toThrow(RangeError);
        expect(() => binomial(-4, 1)).toThrow(RangeError);
        expect(() => binomial(4.5, 1)).toThrow(RangeError);
    });

    it('write exactly the requested little-endian width', () => {
        expect([...littleEndian(0x0102n, 3)]).toEqual([2, 1, 0]);
        expect([...littleEndian(255, 1)]).toEqual([255]);
        expect([...littleEndian(0n, 0)]).toEqual([]);
        expect(() => littleEndian(256n, 1)).toThrow(RangeError);
        expect(() => littleEndian(-1n, 4)).toThrow(RangeError);
    });
});
