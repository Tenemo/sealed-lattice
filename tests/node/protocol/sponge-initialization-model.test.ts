import { describe, expect, it } from 'vitest';

import {
    boundedResidueFiberWord,
    compileFixedSpongeInitializationCensus,
    forcePermutationMappings,
    squeezingCapacityCondition,
    staticSpongeConditioningBound,
} from '#tests/sponge-initialization-model.js';

function* permutations(
    remaining: readonly number[],
    prefix: readonly number[] = [],
): Generator<readonly number[]> {
    if (remaining.length === 0) {
        yield prefix;
        return;
    }
    for (let position = 0; position < remaining.length; position++)
        yield* permutations(
            remaining.filter((_, index) => index !== position),
            [...prefix, remaining[position]],
        );
}

describe('fixed-input sponge initialization', () => {
    it('samples valid fibers in fixed work and bounds its extra distribution bias', () => {
        const counts = new Map<bigint, bigint>();
        for (let residue = 0n; residue < 5n; residue++)
            for (let random = 0n; random < 32n; random++) {
                const word = boundedResidueFiberWord(
                    5n,
                    4n,
                    residue,
                    random,
                    5n,
                );
                expect(word % 5n).toBe(residue);
                expect(word).toBeLessThan(16n);
                counts.set(word, (counts.get(word) ?? 0n) + 1n);
            }
        const absoluteDifference = [...counts].reduce((sum, [word, count]) => {
            const difference = count * 3n - (word % 5n === 0n ? 24n : 32n);
            return sum + (difference < 0n ? -difference : difference);
        }, 0n);
        // Both laws use denominator 480; half the absolute difference is 1/60.
        expect(absoluteDifference).toBe(16n);
        expect(absoluteDifference * 60n).toBe(2n * 480n);
    });
    it('covers the emitted common-vector seeds with distinct one-block inputs and complete output prefixes', () => {
        const value = compileFixedSpongeInitializationCensus();
        expect(value.rateBits).toBe(1088n);
        expect(value.capacityBits).toBe(512n);
        expect(value.seeds.map(({ label }) => label)).toEqual([
            ...Array.from({ length: 6 }, (_, index) =>
                ['a', 'u', 'k'].map((part) => `common-fhe-${part}-${index}`),
            ).flat(),
            'common-share',
            'common-auxiliary',
        ]);
        expect(value.outputBlocks).toBe(19n * 61681n + 3856n);
        for (const seed of value.seeds) {
            expect(seed.message.length).toBeLessThan(136);
            expect(seed.paddedInput.subarray(136)).toEqual(Buffer.alloc(64));
            expect(seed.paddedInput[seed.message.length]).toBe(0x1f);
            expect(seed.paddedInput[135]).toBe(0x80);
            expect(seed.outputBlocks * 1088n).toBeGreaterThanOrEqual(
                seed.outputBits,
            );
            expect((seed.outputBlocks - 1n) * 1088n).toBeLessThan(
                seed.outputBits,
            );
        }
        expect(value.conditioningBound.numerator << 400n).toBeLessThan(
            value.conditioningBound.denominator,
        );
    });
    it('forces constraints uniformly while preserving earlier mappings', () => {
        const counts = new Map<string, number>();
        for (const permutation of permutations([0, 1, 2, 3, 4, 5, 6, 7])) {
            const result = forcePermutationMappings(permutation, [
                [0, 4],
                [1, 6],
            ]);
            expect(result[0]).toBe(4);
            expect(result[1]).toBe(6);
            const key = result.join(',');
            counts.set(key, (counts.get(key) ?? 0) + 1);
        }
        // Six remaining images can be permuted freely. Every constrained
        // permutation has eight times seven preimages under forced swaps.
        expect(counts.size).toBe(720);
        expect([...counts.values()]).toEqual(Array<number>(720).fill(56));
    });

    it('has the derived conditioning probability and uniform rate strings for distinct seeds and repeated squeezing', () => {
        for (const chains of [
            [
                { start: 0, length: 1 },
                { start: 1, length: 1 },
            ],
            [{ start: 0, length: 2 }],
        ]) {
            const rates = new Map<string, bigint>();
            let total = 0n,
                good = 0n;
            for (const permutation of permutations([0, 1, 2, 3, 4, 5, 6, 7])) {
                total++;
                const values = squeezingCapacityCondition(
                    permutation,
                    2,
                    chains,
                );
                if (values === undefined) continue;
                good++;
                const key = values.join(',');
                rates.set(key, (rates.get(key) ?? 0n) + 1n);
            }
            // The exact conditional draw probabilities are 6/8 followed by 4/7.
            expect(good * 8n * 7n).toBe(total * 6n * 4n);
            expect([...rates.keys()].sort()).toEqual([
                '0,0',
                '0,1',
                '1,0',
                '1,1',
            ]);
            expect([...rates.values()]).toEqual(
                Array<bigint>(4).fill(good / 4n),
            );
            const bound = staticSpongeConditioningBound(1n, 2n, 2n);
            expect((total - good) * bound.denominator).toBeLessThanOrEqual(
                total * bound.numerator,
            );
        }
    });

    it('refuses colliding constraints and impossible capacity populations', () => {
        expect(() =>
            forcePermutationMappings(
                [0, 1, 2, 3],
                [
                    [0, 1],
                    [0, 2],
                ],
            ),
        ).toThrow(RangeError);
        expect(() =>
            forcePermutationMappings(
                [0, 1, 2, 3],
                [
                    [0, 2],
                    [1, 2],
                ],
            ),
        ).toThrow(RangeError);
        expect(() => staticSpongeConditioningBound(1n, 2n, 4n)).toThrow(
            RangeError,
        );
        expect(staticSpongeConditioningBound(1n, 2n, 0n).numerator).toBe(0n);
    });
});
