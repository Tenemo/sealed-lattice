import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { stripTypeScriptTypes } from 'node:module';
import { createContext, Script } from 'node:vm';

import { describe, expect, it } from 'vitest';

import {
    compileOraclePrefixReplacement,
    compileSparseRouting,
    sparseRoutingWork,
} from '#tests/compressed-oracle-model.js';

describe('sparse-router circuit construction', () => {
    it('keeps full replacement-record validation visible even when no record fits the query', () => {
        const gateCounts: number[] = [];
        for (const length of [16, 4096]) {
            const input = new Uint8Array(length);
            const originalEvery = input.every.bind(input);
            let inspected = 0;
            input.every = (predicate, thisArgument) =>
                originalEvery((value, index, array) => {
                    inspected++;
                    return predicate.call(thisArgument, value, index, array);
                });
            const record = { input, prefix: Uint8Array.of(1) };
            const compiled = compileOraclePrefixReplacement(0, 1, [record]);
            expect(inspected).toBe(length);
            gateCounts.push(compiled.circuit.gates.length);
            // Ignoring this record during gate emission cannot remove the
            // constructor's real non-bit rejection or its scan cost.
            input[length - 1] = 2;
            inspected = 0;
            expect(() =>
                compileOraclePrefixReplacement(0, 1, [record]),
            ).toThrow();
            expect(inspected).toBe(length);
        }
        expect(gateCounts[0]).toBe(gateCounts[1]);
    });

    it('constructs row-index arrays linearly in their width while preserving the gate program', async () => {
        const source = await readFile(
            'tests/compressed-oracle-model.ts',
            'utf8',
        );
        const javascript = stripTypeScriptTypes(
            source
                .replace(/^import assert from 'node:assert\/strict';\r?$/mu, '')
                .replace(/^export /gmu, ''),
            { mode: 'transform' },
        );
        let words = 0;
        // Count real Array.from results in an isolated evaluation. No gate,
        // wire, predicate, or circuit output is overridden by this observer.
        const countedArray = new Proxy(Array, {
            get(target, property, receiver) {
                if (property !== 'from')
                    return Reflect.get(target, property, receiver) as unknown;
                return (...args: Parameters<typeof Array.from>) => {
                    const result = Reflect.apply(Array.from, Array, args);
                    words += result.length;
                    return result;
                };
            },
        });
        const compile = new Script(
            javascript + '\ncompileSparseRouting;',
        ).runInContext(
            createContext({ assert, Array: countedArray }),
        ) as typeof compileSparseRouting;
        for (const capacity of [0, 1, 4, 16])
            for (const inputBits of [1, 7, 32])
                for (const outputBits of [1, 16, 128]) {
                    words = 0;
                    const actual = compile(capacity, inputBits, outputBits);
                    const work = sparseRoutingWork(
                        BigInt(capacity),
                        BigInt(inputBits),
                        BigInt(outputBits),
                    );
                    // The other two Array.from calls build the query wires
                    // and the selected output/presence wires.
                    expect(BigInt(words - inputBits - outputBits - 1)).toBe(
                        work.constructorTupleIndexWords,
                    );
                    expect(JSON.stringify(actual)).toBe(
                        JSON.stringify(
                            compileSparseRouting(
                                capacity,
                                inputBits,
                                outputBits,
                            ),
                        ),
                    );
                    const oldExtra = BigInt(
                        (capacity + 1) *
                            outputBits *
                            (inputBits + outputBits + 1),
                    );
                    expect(oldExtra).toBeGreaterThan(0n);
                    expect(work.constructorTupleIndexWords).toBeLessThan(
                        work.removeGates + work.insertGates,
                    );
                }
    });
});
