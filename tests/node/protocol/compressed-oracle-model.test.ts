import { describe, expect, it } from 'vitest';

import {
    compileLocalOracleUpdate,
    compilePrefixCopy,
    compileLabelledHashExtraction,
    compileSparseRouting,
    sparseExtractionWork,
    sparseOracleQuerySchedule,
    sparseRoutingWork,
    prefixOracleWork,
    prefixOracleQueriesPerAccess,
    labelledHashExtractionWork,
    verifyLocalOracleUpdate,
    verifySparseRouting,
    verifySparseSelection,
    verifyPrefixOracleWrapper,
    verifyLabelledHashExtraction,
} from '#tests/compressed-oracle-model.js';

describe('Compressed oracle implementation', () => {
    it('preserves coherent prefix reads and clears all unrequested output', () => {
        for (const bits of [1, 2]) {
            const result = verifyPrefixOracleWrapper(bits);
            expect(result.maximumError).toBeLessThan(1e-12);
            expect(BigInt(result.fullValueQueriesPerLogicalQuery)).toBe(
                prefixOracleQueriesPerAccess,
            );
            expect(
                result.discardedTail.every(
                    (value) => value.badMinusProbability >= 0.25,
                ),
            ).toBe(true);
        }
        const copy = compilePrefixCopy(512),
            work = prefixOracleWork(3n, 64n, 512n);
        expect(work.copyGates).toBe(
            BigInt(2 * copy.circuit.gates.length + 512),
        );
        expect(work.copyWorkQubits).toBe(
            BigInt(copy.circuit.wires - copy.circuit.inputs),
        );
        expect(work.fullValueQueries).toBe(6n);
        expect(work.queryGates).toBe(
            sparseOracleQuerySchedule(6n, 64n, 512n).queryGates +
                3n * work.copyGates,
        );
    });

    it('extracts the committed prefix while retaining the entire stream value', () => {
        const result = verifyLabelledHashExtraction(2, 2, 2, 1, 1);
        expect(result.cases).toBeGreaterThan(0);
        const emitted = compileLabelledHashExtraction(2, 2, 2, 1, 1),
            work = labelledHashExtractionWork(2n, 2n, 2n, 1n, 1n);
        expect(BigInt(result.extractionGates)).toBe(work.extractionGates);
        expect(BigInt(emitted.wires + emitted.output.length)).toBe(
            work.extractionQubits,
        );
        // The predicate ignores one output bit, so each accepted prefix has
        // two full-value preimages. Its normalized probability is unchanged.
        for (let prefix = 0; prefix < 2; prefix++)
            expect(
                [0, 1, 2, 3].filter((value) => value % 2 === prefix),
            ).toHaveLength(2);
    });
    it('cleans lookup work and preserves canonical arrays across every bounded insertion and deletion', () => {
        for (const [capacity, inputBits, outputBits] of [
            [0, 2, 1],
            [1, 2, 1],
            [2, 2, 1],
            [1, 1, 2],
        ]) {
            const result = verifySparseRouting(capacity, inputBits, outputBits);
            expect(result.cases).toBeGreaterThan(0);
            expect(result.updates).toBeGreaterThan(result.cases);
        }
    });

    it('matches the independent local oracle matrix and detects retained presence information', () => {
        for (const outputBits of [1, 2, 3]) {
            const result = verifyLocalOracleUpdate(outputBits);
            expect(result.maximumError).toBeLessThan(1e-12);
            expect(result.cleanTwoQueryError).toBeLessThan(1e-24);
            expect(result.retainedPresenceError).toBeGreaterThan(0.2);
        }
        expect(verifyLocalOracleUpdate(1).retainedPresenceError).toBeCloseTo(
            0.5,
            12,
        );
    });

    it('selects the first active relation match and charges predicate uncomputation', () => {
        for (const capacity of [0, 1, 2]) {
            const result = verifySparseSelection(capacity, 2, 1);
            expect(result.cases).toBeGreaterThan(0);
            const cost = sparseExtractionWork(BigInt(capacity), 2n, 7n);
            expect(cost.extractionGates).toBe(
                BigInt(result.cleanSelectionGates) + 14n * BigInt(capacity),
            );
        }
    });

    it('computes labelled hash predicates and clears them before classical extraction', () => {
        for (const capacity of [0, 1, 2])
            for (const labelBits of [0, 1, 2]) {
                const result = verifyLabelledHashExtraction(
                    capacity,
                    2,
                    1,
                    labelBits,
                );
                expect(result.cases).toBeGreaterThan(0);
                expect(BigInt(result.extractionGates)).toBe(
                    labelledHashExtractionWork(
                        BigInt(capacity),
                        2n,
                        1n,
                        BigInt(labelBits),
                    ).extractionGates,
                );
            }
        const emitted = compileLabelledHashExtraction(3, 64, 512, 16);
        expect(BigInt(2 * emitted.gates.length + 65)).toBe(
            labelledHashExtractionWork(3n, 64n, 512n, 16n).extractionGates,
        );
        expect(BigInt(emitted.wires + emitted.output.length)).toBe(
            labelledHashExtractionWork(3n, 64n, 512n, 16n).extractionQubits,
        );
        expect(
            labelledHashExtractionWork(3n, 64n, 512n, 16n).measuredQubits,
        ).toBe(65n);
    });

    it('derives the gate and space formulas from every emitted Boolean operation', () => {
        for (const capacity of [0, 1, 2, 5, 16])
            for (const inputBits of [1, 2, 7, 64])
                for (const outputBits of [1, 2, 8, 16]) {
                    const circuit = compileSparseRouting(
                            capacity,
                            inputBits,
                            outputBits,
                        ),
                        work = sparseRoutingWork(
                            BigInt(capacity),
                            BigInt(inputBits),
                            BigInt(outputBits),
                        );
                    expect(work.removeGates).toBe(
                        BigInt(circuit.remove.gates.length),
                    );
                    expect(work.insertGates).toBe(
                        BigInt(circuit.insert.gates.length),
                    );
                    expect(work.routingGates).toBe(
                        BigInt(circuit.routingGates),
                    );
                    expect(work.routingQubits).toBe(
                        BigInt(
                            inputBits +
                                2 * circuit.databaseBits +
                                Math.max(
                                    circuit.remove.wires -
                                        circuit.remove.inputs,
                                    circuit.insert.wires -
                                        circuit.insert.inputs,
                                ),
                        ),
                    );
                }
        for (const outputBits of [1, 2, 8, 512])
            expect(
                BigInt(compileLocalOracleUpdate(outputBits).gates.length),
            ).toBe(
                sparseRoutingWork(0n, 1n, BigInt(outputBits)).localUpdateGates,
            );
        for (const queries of [0, 1, 2, 8]) {
            let sum = 0n;
            for (let prior = 0; prior < queries; prior++)
                sum += BigInt(
                    compileSparseRouting(prior, 7, 8).roundTripRoutingGates +
                        compileLocalOracleUpdate(8).gates.length,
                );
            expect(
                sparseOracleQuerySchedule(BigInt(queries), 7n, 8n).queryGates,
            ).toBe(sum);
        }
    });
});
