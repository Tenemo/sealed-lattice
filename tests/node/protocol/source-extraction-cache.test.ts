import { describe, expect, it } from 'vitest';

import {
    compileSourceCacheInsert,
    compileSourceCacheLookup,
    runCleanCircuit,
    sourceCacheWork,
} from '#tests/compressed-oracle-model.js';

const bits = (value: number, width: number) =>
    Array.from({ length: width }, (_, bit) => (value >> bit) & 1);
const integer = (value: Uint8Array) =>
    value.reduce((sum, bit, index) => sum + bit * 2 ** index, 0);
const cleanGates = (circuit: ReturnType<typeof compileSourceCacheLookup>) =>
    BigInt(2 * circuit.gates.length + circuit.output.length);

describe('source extraction cache accounting', () => {
    it('preserves the first result, including no match, across every small request history', () => {
        const keyBits = 2;
        const valueBits = 3;
        const rowBits = keyBits + valueBits + 1;
        const lookup = Array.from({ length: 4 }, (_, capacity) =>
            compileSourceCacheLookup(capacity, keyBits, valueBits),
        );
        const insert = compileSourceCacheInsert(keyBits, valueBits);
        // Zero models a decoded no-match/invalid result. A valid cached
        // value has its own high validity bit, separate from cache presence.
        const requests = [
            [0, 0],
            [0, 5],
            [1, 0],
            [1, 6],
            [2, 0],
            [2, 7],
        ];
        for (let encoded = 0; encoded < requests.length ** 4; encoded++) {
            let remaining = encoded;
            let cache = new Uint8Array(0);
            const expected = new Map<number, number>();
            let extractions = 0;
            for (let step = 0; step < 4; step++) {
                const [key, candidate] = requests[remaining % requests.length];
                remaining = Math.floor(remaining / requests.length);
                const result = runCleanCircuit(
                    lookup[step],
                    Uint8Array.from([...bits(key, keyBits), ...cache]),
                );
                const hit = result[valueBits];
                expect(hit).toBe(Number(expected.has(key)));
                expect(integer(result.subarray(0, valueBits))).toBe(
                    expected.get(key) ?? 0,
                );
                if (!hit) {
                    extractions++;
                    expected.set(key, candidate);
                }
                const row = runCleanCircuit(
                    insert,
                    Uint8Array.from([
                        hit,
                        ...bits(candidate, valueBits),
                        ...bits(key, keyBits),
                    ]),
                );
                expect(row[rowBits - 1]).toBe(1 - hit);
                expect(row).toEqual(
                    hit
                        ? new Uint8Array(rowBits)
                        : Uint8Array.from([
                              ...bits(candidate, valueBits),
                              ...bits(key, keyBits),
                              1,
                          ]),
                );
                cache = Uint8Array.from([...cache, ...row]);
                expect(extractions).toBe(expected.size);
            }
            expect(cache.length).toBe(4 * rowBits);
        }
    });

    it('copies cleanly into nonzero registers without changing the source rows', () => {
        const keyBits = 3;
        const valueBits = 4;
        const row = (key: number, value: number, occupied: number) => [
            ...bits(value, valueBits),
            ...bits(key, keyBits),
            occupied,
        ];
        const lookup = compileSourceCacheLookup(3, keyBits, valueBits);
        const source = Uint8Array.from([
            ...bits(3, keyBits),
            ...row(3, 14, 0),
            ...row(3, 0, 1),
            ...row(5, 12, 1),
        ]);
        const output = Uint8Array.of(1, 0, 1, 0, 1);
        const before = output.slice();
        expect(runCleanCircuit(lookup, source, output)).toEqual(
            Uint8Array.of(1, 0, 1, 0, 0),
        );
        expect(runCleanCircuit(lookup, source, output)).toEqual(before);
    });

    it('prices the complete growing scan and fresh row at every request', () => {
        for (const keyBits of [1, 3, 9])
            for (const valueBits of [1, 5, 12])
                for (const requests of [0, 1, 2, 7]) {
                    let lookup = 0n;
                    let insert = 0n;
                    let initialized = 0n;
                    for (let prior = 0; prior < requests; prior++) {
                        lookup += cleanGates(
                            compileSourceCacheLookup(prior, keyBits, valueBits),
                        );
                        insert += cleanGates(
                            compileSourceCacheInsert(keyBits, valueBits),
                        );
                        initialized += BigInt(keyBits + valueBits + 1);
                    }
                    const work = sourceCacheWork(
                        BigInt(requests),
                        BigInt(keyBits),
                        BigInt(valueBits),
                    );
                    expect(work.lookupGates).toBe(lookup);
                    expect(work.insertionGates).toBe(insert);
                    expect(work.initializationGates).toBe(initialized);
                    expect(work.maximumRetainedBits).toBe(initialized);
                    expect(work.totalGates).toBe(lookup + insert + initialized);
                }
    });

    it('refuses negative request bounds and empty key or value registers', () => {
        expect(() => sourceCacheWork(-1n, 1n, 1n)).toThrow();
        expect(() => compileSourceCacheLookup(1, 0, 1)).toThrow();
        expect(() => compileSourceCacheInsert(1, 0)).toThrow();
    });
});
