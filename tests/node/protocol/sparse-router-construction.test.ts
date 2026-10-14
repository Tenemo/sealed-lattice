import { describe, expect, it, vi } from 'vitest';

import { compileOraclePrefixReplacement } from '#tests/compressed-oracle/oracle-access.js';
import {
    compileSparseRouting,
    sparseRoutingWork,
} from '#tests/compressed-oracle/sparse-routing.js';

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

    it('constructs row-index arrays linearly in their width while preserving the gate program', () => {
        let words = 0;
        // Observe only this synchronous construction, restoring Array.from
        // before assertions or any other test work runs.
        const compile = (
            ...parameters: Parameters<typeof compileSparseRouting>
        ) => {
            const arrayFrom = Array.from;
            const observer = vi.spyOn(Array, 'from').mockImplementation(
                new Proxy(arrayFrom, {
                    apply(target, receiver, argumentsList) {
                        const result = Reflect.apply(
                            target,
                            receiver,
                            argumentsList,
                        ) as unknown[];
                        words += result.length;
                        return result;
                    },
                }),
            );
            try {
                return compileSparseRouting(...parameters);
            } finally {
                observer.mockRestore();
            }
        };
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
