import { describe, expect, it } from 'vitest';

import { compileHashRowCheckpointCensus } from '#tests/hash-row-checkpoint-model.js';

describe('encrypted proof-row hash checkpoints', () => {
    it('bounds encrypted chunks and accounts for every retained row', () => {
        for (const count of [1, 2, 4095, 4096, 4097, 262143, 262144]) {
            const model = compileHashRowCheckpointCensus(count);
            expect(model.serializedStateBytes).toBe(201n);
            expect(model.maximumSealedChunkBytes).toBeLessThan(1_048_576n);
            let offset = 0;
            let bytes = 0n;
            let blocks = 1n;
            const intervals: [bigint, bigint][] = [];
            while (offset < count) {
                const remaining = Math.min(count - offset, 4096);
                const payload = remaining * 201;
                bytes += BigInt(payload + 16);
                const first = (BigInt(offset) << 32n) + 1n;
                const last = first + BigInt(Math.ceil(payload / 16));
                expect(first).toBeGreaterThan(0n);
                expect(last - first).toBeLessThan(1n << 32n);
                intervals.push([first, last]);
                blocks += last - first + 1n;
                offset += remaining;
            }
            for (let index = 1; index < intervals.length; index++)
                expect(intervals[index - 1][1]).toBeLessThan(
                    intervals[index][0],
                );
            expect(bytes).toBe(model.sealedBytes);
            expect(blocks).toBe(model.distinctAesBlockInputs);
            expect(BigInt(intervals.length)).toBe(model.chunkCount);
        }
    });

    it('refuses invalid counts before proportional work', () => {
        for (const count of [0, -1, 1.5, 262145, Infinity, NaN])
            expect(() => compileHashRowCheckpointCensus(count)).toThrow();
    });
});
