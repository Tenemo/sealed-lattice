import { describe, expect, it } from 'vitest';

import {
    compileProofFieldReductionCensus,
    foldProofFieldLimbs,
} from '#tests/proof-field-reduction-model.js';

describe('bounded proof-field reduction', () => {
    it('agrees with direct integer remainder for every four-limb reduced instance', () => {
        const radix = 16n,
            offset = 2n,
            modulus = 225n;
        const failures: bigint[][] = [];
        for (let input = 0n; input < radix ** 4n; input++) {
            const limbs = [
                input % radix,
                (input / radix) % radix,
                (input / radix ** 2n) % radix,
                input / radix ** 3n,
            ] as const;
            const value = foldProofFieldLimbs(limbs, radix, offset);
            if (
                value.value !== input % modulus ||
                value.firstHigh < 0n ||
                value.firstHigh > 5n ||
                value.secondHigh < 0n ||
                value.secondHigh > 1n ||
                value.finalHigh < 0n ||
                value.finalHigh >= radix
            )
                failures.push([
                    input,
                    value.value,
                    value.firstHigh,
                    value.secondHigh,
                    value.finalHigh,
                ]);
        }
        expect(failures).toEqual([]);
    });

    it('derives the machine-width bounds from the current field owner', () => {
        const value = compileProofFieldReductionCensus();
        expect(value.maximumSmallFactor).toBe(17688n);
        expect(value.maximumFirstHigh).toBe(17821n);
        expect(value.maximumSecondHigh).toBe(1n);
        expect(value.maximumCarriedFinalHigh).toBe(2370325n);
        expect(value.maximumSmallFactor).toBeLessThan(1n << 16n);
        expect(value.maximumFirstHigh).toBeLessThan(1n << 16n);
        expect(value.maximumCarriedFinalHigh).toBeLessThan(value.radix);
    });

    it('checks full-width boundary products against independent big integers', () => {
        const { radix, offset, modulus } = compileProofFieldReductionCensus();
        const edges = [
            0n,
            1n,
            radix - 1n,
            radix,
            radix + 1n,
            modulus - 2n,
            modulus - 1n,
        ];
        for (const left of edges)
            for (const right of edges) {
                const product = left * right;
                const limbs = [
                    product % radix,
                    (product / radix) % radix,
                    (product / radix ** 2n) % radix,
                    product / radix ** 3n,
                ] as const;
                expect(foldProofFieldLimbs(limbs, radix, offset).value).toBe(
                    product % modulus,
                );
            }
    });
});
