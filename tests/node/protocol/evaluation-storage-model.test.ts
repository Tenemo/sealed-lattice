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
            '017f859de532edf89af14dc72c7aea96b7917da7ffdebb01b4a853cf087d7d48d747640bc29f8a201fd5f699612f13de57dec36a18ded4d883deec289d3ac421',
        );
        expect(complete.instructions).toHaveLength(284);
        for (let top = 1; top < 10; top++) {
            const selected = compileRankingProgramModel(profile, top);
            expect(
                selected.instructions.map(({ operation, inputs }) => ({
                    operation,
                    inputs,
                })),
            ).toEqual(
                complete.instructions.map(({ operation, inputs }) => ({
                    operation,
                    inputs,
                })),
            );
            expect(selected.identity).not.toBe(complete.identity);
        }
        expect(() => compileRankingProgramModel(profile, 0)).toThrow('prefix');
        expect(() => compileRankingProgramModel(profile, 11)).toThrow('prefix');
    });

    it.each([
        {
            n: 10,
            capacities: [19, 19, 13, 19, 17, 19, 16],
            primes: [31n, 18n, 16n],
            job: 15_844_384n,
        },
        {
            n: 20,
            capacities: [17, 17, 11, 17, 15, 17, 15],
            primes: [34n, 20n, 18n],
            job: 15_852_576n,
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
            count: 284,
            writes: 5,
            reloads: 6,
            drops: 1,
            step: 130,
            stored: [43, 98, 99],
            keyMiB: 216n,
            valueMiB: 14n,
            peakMiB: 258n,
        },
        {
            n: 20,
            count: 558,
            writes: 11,
            reloads: 29,
            drops: 18,
            step: 285,
            stored: [56, 59, 63, 84, 119, 187, 188, 254],
            keyMiB: 280n,
            valueMiB: 15n,
            peakMiB: 400n,
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
            2n * 1024n ** 2n,
        );
        expect(smaller.peakBytes).toBeLessThan(
            smaller.scratchVarianceCeilingBytes,
        );
        expect(larger.peakBytes - larger.scratchVarianceCeilingBytes).toBe(
            16n * 1024n ** 2n,
        );
    });
});
