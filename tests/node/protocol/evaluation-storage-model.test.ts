import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import {
    compileEvaluationStorage,
    compileRankingProgramModel,
    compileScalarEvaluationCapacity,
} from '#tests/evaluation-storage-model.js';
import {
    rustIntegerConstant,
    stripRustComments,
} from '#tests/node/rust-source.js';
import { deriveSupportedProfile } from '#tests/supported-profile-model.js';

describe('scalar evaluation storage schedule', () => {
    it('reproduces the independently pinned native completion program and every requested prefix schedule', () => {
        const profile = deriveSupportedProfile(10, 10);
        const complete = compileRankingProgramModel(profile);
        expect(complete.identity).toBe(
            '10edd939fb4f0d0decc6f446ba3194f2dfacf7640b3c3993a4808b7fbedb9423c523c16f22e1a27810400f539f184874e79940b730ebb13e761979c7fc65671a',
        );
        expect(complete.instructions).toHaveLength(304);
        for (let top = 1; top < 10; top++) {
            const selected = compileRankingProgramModel(profile, top);
            // Each additional rank needs one rotation and one addition.
            expect(selected.instructions).toHaveLength(304 - 2 * (10 - top));
            expect(selected.identity).not.toBe(complete.identity);
        }
        expect(() => compileRankingProgramModel(profile, 0)).toThrow('prefix');
        expect(() => compileRankingProgramModel(profile, 11)).toThrow('prefix');
        const largest = compileRankingProgramModel(
            deriveSupportedProfile(20, 20),
        );
        expect(largest.identity).toBe(
            'cef6e51e5f8a023041e02d2bcb016921e26a94df0c9426a7165c95b1d6b9376def5b49485a24fdcd8dee0d5168ee3dfc5949034771e5b1f6f810498b096c0322',
        );
        expect(largest.instructions).toHaveLength(598);
    });

    it.each([
        {
            n: 10,
            capacities: [22, 22, 16, 22, 20, 22, 19],
            primes: [27n, 16n, 14n],
            job: 15_828_000n,
        },
        {
            n: 20,
            capacities: [19, 19, 13, 19, 17, 19, 16],
            primes: [31n, 18n, 16n],
            job: 15_844_384n,
        },
    ])(
        'keeps the source-derived scalar capacities at $n',
        ({ n, capacities, primes, job }) => {
            const result = compileScalarEvaluationCapacity(
                deriveSupportedProfile(n, n),
            );
            expect(result.capacities).toEqual(capacities);
            expect([
                result.rns.exactProductPrimes,
                result.rns.externalProductPrimes,
                result.rns.keyProductPrimes,
            ]).toEqual(primes);
            expect(result.jobBytes).toBe(job);
            expect(result.rankingCacheBytes).toBe(2n * 65536n * 4n);
            const engine = readFileSync(
                'crates/protocol-research/encrypted-ranking/src/ranking.rs',
                'utf8',
            );
            const memory = stripRustComments(
                readFileSync(
                    'crates/protocol-research/encrypted-ranking/src/ranking-memory.rs',
                    'utf8',
                ),
            );
            const storage = readFileSync(
                'crates/protocol-research/encrypted-ranking/src/ranking-storage.rs',
                'utf8',
            );
            for (const [name, value] of [
                ['MEMORY_BYTES', 402_653_184n],
                ['RUNTIME_RESERVE_BYTES', 67_108_864n],
                ['TRANSFER_RESERVE_BYTES', 2_097_152n],
                ['TRANSFORM_TABLES', 2n],
                ['KEPT_SOURCES', 3n],
            ] as const)
                expect(rustIntegerConstant(memory, name), name).toBe(value);
            expect(storage).toContain(
                '.max_by_key(|index| (next_use(**index), **index))',
            );
            expect(engine).toContain('reloads.len() + 1');
        },
    );

    it.each([
        {
            n: 10,
            count: 304,
            writes: 0,
            reloads: 0,
            drops: 0,
            step: 21,
            stored: [],
            keyMiB: 288n,
            valueMiB: 12n,
            peakMiB: 288n,
        },
        {
            n: 20,
            count: 598,
            writes: 8,
            reloads: 14,
            drops: 6,
            step: 285,
            stored: [63, 119, 187, 188, 254],
            keyMiB: 360n,
            valueMiB: 14n,
            peakMiB: 430n,
        },
    ])(
        'matches independently reviewed creation/reload/retirement trace at $n',
        (expected) => {
            const result = compileEvaluationStorage(
                deriveSupportedProfile(expected.n, expected.n),
            );
            expect(result.program.instructions).toHaveLength(expected.count);
            expect([
                result.spillCount,
                result.reloadCount,
                result.dropCount,
            ]).toEqual([expected.writes, expected.reloads, expected.drops]);
            expect(result.peak?.step).toBe(expected.step);
            expect(result.peak?.stored).toEqual(expected.stored);
            expect(result.peak?.keyBytes).toBe(expected.keyMiB * 1024n ** 2n);
            expect(result.capacity.storedValueBytes).toBe(
                expected.valueMiB * 1024n ** 2n,
            );
            expect(result.peakBytes).toBe(expected.peakMiB * 1024n ** 2n);
            expect(result.events[result.events.length - 1].stored).toEqual([]);
            const duplicateWrites: number[] = [],
                observed = new Set<number>();
            for (const event of result.events) {
                for (const node of event.spills) {
                    if (observed.has(node)) duplicateWrites.push(node);
                    observed.add(node);
                }
                // Reloads and resident-only drops do not remove durable copies.
                expect(event.reloads.every((node) => observed.has(node))).toBe(
                    true,
                );
                expect(event.drops.every((node) => observed.has(node))).toBe(
                    true,
                );
                event.retired.forEach((node) => observed.delete(node));
                expect([...observed].sort((a, b) => a - b)).toEqual(
                    event.stored,
                );
            }
            expect(duplicateWrites).toEqual([]);
            expect(result.keyBankWriteBytes).toBe(
                ((expected.keyMiB * 5n) / 2n) * 1024n ** 2n,
            );
        },
    );

    it('separates a small scratch variance from the largest-profile architecture screen', () => {
        const smaller = compileEvaluationStorage(
            deriveSupportedProfile(10, 10),
        );
        const larger = compileEvaluationStorage(deriveSupportedProfile(20, 20));
        expect(smaller.peakBytes - smaller.scratchPlanningBytes).toBe(
            32n * 1024n ** 2n,
        );
        expect(smaller.peakBytes).toBeLessThan(
            smaller.scratchVarianceCeilingBytes,
        );
        expect(larger.peakBytes - larger.scratchVarianceCeilingBytes).toBe(
            46n * 1024n ** 2n,
        );
    });
});
