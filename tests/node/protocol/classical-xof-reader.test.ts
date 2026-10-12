import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
    compileClassicalReaderOracleBudget,
    compileClassicalXofReaderBudget,
    shakePermutationGateCharge,
} from '#tests/oracle-budget-model.js';
import { shadowOracleDomainWork } from '#tests/oracle-domain-model.js';

// A byte-by-byte reference sponge counter, separate from the budget formula.
const referencePermutations = (
    inputBytes: number,
    outputBytes: number,
    rate: number,
) => {
    let occupied = 0,
        permutations = 0;
    for (let byte = 0; byte < inputBytes; byte++) {
        if (++occupied === rate) {
            permutations++;
            occupied = 0;
        }
    }
    // Byte-aligned SHAKE's suffix and final padding fit one remaining block.
    permutations++;
    let available = rate;
    for (let byte = 0; byte < outputBytes; byte++) {
        if (available === 0) {
            permutations++;
            available = rate;
        }
        available--;
    }
    return BigInt(permutations);
};

const prefixCache = (
    suppliedInput: Buffer,
    rate: number,
    oracle: (input: Buffer, length: number) => Buffer,
) => {
    // The native seed input may be cleared after its reader is initialized.
    const input = Buffer.from(suppliedInput);
    const absorption = Math.floor(input.length / rate) + 1;
    let prefix: Buffer = Buffer.alloc(0);
    let highWater = 0;
    const queries: number[] = [];
    const reader = (initial = 0) => {
        let cursor = initial;
        return {
            read(length: number) {
                if (length === 0) return Buffer.alloc(0);
                const end = cursor + length;
                if (end > prefix.length) {
                    let capacity = rate * absorption;
                    while (capacity < end) capacity *= 2;
                    prefix = oracle(input, capacity);
                    expect(prefix.length).toBe(capacity);
                    queries.push(capacity);
                }
                const result = Buffer.from(prefix.subarray(cursor, end));
                cursor = end;
                highWater = Math.max(highWater, cursor);
                return result;
            },
            clone: () => reader(cursor),
        };
    };
    return { reader: reader(), queries, highWater: () => highWater };
};

describe('classical XOF reader prefix caching', () => {
    it('matches direct SHAKE through partial blocks, mutable caller buffers and cursor clones', () => {
        for (const [algorithm, rate] of [
            ['shake128', 168],
            ['shake256', 136],
        ] as const)
            for (const inputBytes of [0, rate - 1, rate, rate + 1, 2048]) {
                const input = Buffer.from(
                    Array.from(
                        { length: inputBytes },
                        (_, index) => index % 251,
                    ),
                );
                const original = Buffer.from(input);
                const hash = (bytes: Buffer, length: number) =>
                    createHash(algorithm, { outputLength: length })
                        .update(bytes)
                        .digest();
                const cache = prefixCache(input, rate, hash);
                input.fill(255);
                expect(cache.reader.read(0).length).toBe(0);
                expect(cache.queries).toEqual([]);
                const first = cache.reader.read(1);
                expect(first).toEqual(hash(original, 1));
                first.fill(0);
                const clone = cache.reader.clone();
                const middle = cache.reader.read(rate);
                const later = cache.reader.read(2 * rate + 1);
                expect(Buffer.concat([middle, later])).toEqual(
                    hash(original, 3 * rate + 2).subarray(1),
                );
                expect(clone.read(1)).toEqual(hash(original, 2).subarray(1));
                expect(clone.read(4 * rate)).toEqual(
                    hash(original, 4 * rate + 2).subarray(2),
                );
                const restarted = prefixCache(original, rate, hash);
                expect(restarted.reader.read(4 * rate + 2)).toEqual(
                    hash(original, 4 * rate + 2),
                );
                const bound = compileClassicalXofReaderBudget(
                    BigInt(8 * inputBytes),
                    BigInt(8 * cache.highWater()),
                    BigInt(8 * rate) as 1088n | 1344n,
                );
                expect(bound.minimumReferencePermutations).toBe(
                    referencePermutations(inputBytes, cache.highWater(), rate),
                );
                const queried = cache.queries.reduce(
                    (sum, length) =>
                        sum + referencePermutations(inputBytes, length, rate),
                    0n,
                );
                expect(queried).toBeLessThanOrEqual(
                    bound.prefixQueryPermutationsUpperBound,
                );
                expect(BigInt(cache.queries.length)).toBeLessThanOrEqual(
                    bound.maximumPrefixQueries,
                );
            }
    });

    it('amortizes every possible growth level against both input absorption and output', () => {
        for (const rate of [1088n, 1344n] as const)
            for (const input of [
                0n,
                rate - 7n,
                rate - 6n,
                rate - 5n,
                31n * rate,
            ])
                for (const output of [
                    0n,
                    1n,
                    rate,
                    rate + 1n,
                    9n * rate,
                    33n * rate,
                    1025n * rate,
                ]) {
                    const bound = compileClassicalXofReaderBudget(
                        input,
                        output,
                        rate,
                    );
                    let padding = input + 5n;
                    while (padding % rate !== rate - 1n) padding++;
                    const absorption = (padding + 1n) / rate;
                    let capacity = rate * absorption;
                    let queries = 0n,
                        cost = 0n,
                        totalBlocks = 0n;
                    if (output > 0n)
                        for (;;) {
                            queries++;
                            totalBlocks += capacity / rate;
                            cost += absorption + capacity / rate - 1n;
                            if (capacity >= output) break;
                            capacity *= 2n;
                        }
                    expect(bound.absorptionPermutations).toBe(absorption);
                    expect(bound.maximumPrefixQueries).toBe(queries);
                    expect(bound.prefixQueryPermutationsUpperBound).toBe(cost);
                    expect(cost).toBeLessThanOrEqual(
                        5n * bound.minimumReferencePermutations,
                    );
                    expect(queries).toBeLessThanOrEqual(
                        bound.minimumReferencePermutations,
                    );
                    expect(bound.maximumCachedBits).toBeLessThanOrEqual(
                        2n * rate * bound.minimumReferencePermutations,
                    );
                    expect(
                        bound.maximumOverlappingCacheBits,
                    ).toBeLessThanOrEqual(
                        3n * rate * bound.minimumReferencePermutations,
                    );
                    expect(totalBlocks).toBeLessThanOrEqual(cost);
                }
        const unread = compileClassicalXofReaderBudget(1088n, 0n, 1088n);
        expect(unread.minimumReferencePermutations).toBe(2n);
        expect(unread.prefixQueryPermutationsUpperBound).toBe(0n);
        expect(() => compileClassicalXofReaderBudget(-1n, 0n, 1088n)).toThrow();
        expect(() => compileClassicalXofReaderBudget(0n, -1n, 1088n)).toThrow();
    });

    it('does not reabsorb the whole prefix for each byte or each cloned cursor', () => {
        const rate = 136,
            length = 1024 * rate - 1;
        const hash = (input: Buffer, count: number) =>
            createHash('shake256', { outputLength: count })
                .update(input)
                .digest();
        const cache = prefixCache(Buffer.alloc(0), rate, hash);
        cache.reader.read(length);
        const initialQueries = cache.queries.length;
        for (let repeat = 0; repeat < 128; repeat++)
            cache.reader.clone().read(1);
        expect(cache.queries.length).toBe(initialQueries);
        const bound = compileClassicalXofReaderBudget(
            0n,
            BigInt(8 * (length + 1)),
            1088n,
        );
        const separatelyRequeriedClones =
            128n * referencePermutations(0, length + 1, rate);
        expect(separatelyRequeriedClones).toBeGreaterThan(
            5n * bound.minimumReferencePermutations,
        );
        const bytewise = prefixCache(Buffer.alloc(0), rate, hash);
        let repeatedFullPrefixes = 0n;
        for (let read = 1; read <= 2048; read++) {
            bytewise.reader.read(1);
            repeatedFullPrefixes += referencePermutations(0, read, rate);
        }
        const original = referencePermutations(0, 2048, rate);
        expect(repeatedFullPrefixes).toBeGreaterThan(5n * original);
        expect(
            bytewise.queries.reduce(
                (sum, count) => sum + referencePermutations(0, count, rate),
                0n,
            ),
        ).toBeLessThanOrEqual(5n * original);
    });

    it('requires a fixed effective stream rather than silently reusing cached data after programming', () => {
        let epoch = 0;
        const oracle = (_input: Buffer, length: number) =>
            Buffer.alloc(length, epoch);
        const original = prefixCache(Buffer.of(1), 136, oracle);
        expect(original.reader.read(1)).toEqual(Buffer.of(0));
        epoch = 1;
        const newEpoch = prefixCache(Buffer.of(1), 136, oracle);
        expect(original.reader.read(1)).not.toEqual(newEpoch.reader.read(1));
    });

    it('covers the actual prefix-query circuits beside complete-input calls without pricing other work as free', () => {
        const readers = [
            { input: 135n * 8n, output: 65537n * 8n, rate: 1088n as const },
            { input: 2048n * 8n, output: 100000n * 8n, rate: 1088n as const },
        ];
        const runs = [
            {
                count: 7n,
                inputCapacity: 19n,
                outputCapacity: 3n,
                activeShadows: [0],
                replacements: [],
            },
        ];
        let reference = 7n;
        for (const reader of readers) {
            const bound = compileClassicalXofReaderBudget(
                reader.input,
                reader.output,
                reader.rate,
            );
            reference += bound.minimumReferencePermutations;
            let capacity = reader.rate * bound.absorptionPermutations;
            for (let query = 0n; query < bound.maximumPrefixQueries; query++) {
                runs.push({
                    count: 1n,
                    inputCapacity: reader.input,
                    outputCapacity: capacity,
                    activeShadows: [0],
                    replacements: [],
                });
                capacity *= 2n;
            }
        }
        const bound = compileClassicalReaderOracleBudget(
            reference * shakePermutationGateCharge,
            512n,
            0n,
            1n,
        );
        const actual = shadowOracleDomainWork(runs, 512n, [5n]);
        expect(actual.queryGates).toBeLessThanOrEqual(
            bound.shadowQueryGatesUpperBound,
        );
        expect(bound.maximumLogicalQueries).toBe(reference);
        expect(bound.maximumLengthPermutations).toBe(5n * reference);
        expect(
            compileClassicalReaderOracleBudget(0n, 512n)
                .shadowQueryGatesUpperBound,
        ).toBe(0n);
        expect(() => compileClassicalReaderOracleBudget(-1n, 512n)).toThrow();
    });
});
