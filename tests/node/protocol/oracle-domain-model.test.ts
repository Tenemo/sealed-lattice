import { describe, expect, it } from 'vitest';

import {
    compileOracleCellController,
    oracleCellControllerWork,
    prefixOracleWork,
    runOracleCellController,
} from '#tests/compressed-oracle-model.js';
import {
    oracleDomainCells,
    oracleDomainWork,
    verifyOracleDomainAdapter,
} from '#tests/oracle-domain-model.js';

describe('Full-domain oracle adapter', () => {
    it('preserves exact message lengths, coherent cleanup and every bounded stream assignment', () => {
        const result = verifyOracleDomainAdapter();
        expect(result.controllerCases).toBeGreaterThan(1000);
        expect(result.streamCases).toBeGreaterThan(1000);
        expect(result.completeStreamTables).toBe(64);
    });

    it('keeps cell identities stable when caller capacities grow', () => {
        expect(oracleDomainCells(0n, 0n, 2n)).toEqual([]);
        expect(oracleDomainCells(3n, 5n, 2n)).toEqual(
            [1n, 2n, 4n].flatMap((inputClassUpper) => [
                { inputClassUpper, outputStart: 0n, outputSize: 2n },
                { inputClassUpper, outputStart: 2n, outputSize: 2n },
                { inputClassUpper, outputStart: 4n, outputSize: 4n },
            ]),
        );
        const large = oracleDomainCells(9n, 17n, 2n);
        for (const cell of oracleDomainCells(3n, 5n, 2n))
            expect(large).toContainEqual(cell);
    });

    it('distinguishes all bounded messages including trailing zeroes across buffer shapes', () => {
        const identities = new Set<string>();
        for (let length = 0; length <= 4; length++) {
            const upper = length <= 1 ? 1 : 2 ** Math.ceil(Math.log2(length));
            for (let message = 0; message < 2 ** length; message++) {
                const shapes: string[] = [];
                for (const capacity of [4, 5, 8]) {
                    const raw = Uint8Array.from(
                        { length: capacity },
                        (_, bit) =>
                            bit < length
                                ? Math.floor(message / 2 ** bit) % 2
                                : 1,
                    );
                    const result = runOracleCellController(
                        compileOracleCellController(capacity, 1, upper, 0, 1),
                        raw,
                        length,
                        1,
                    );
                    const current = `${upper}:${result.encodedInput.join('')}`;
                    shapes.push(current);
                }
                expect(shapes).toEqual(Array<string>(3).fill(shapes[0]));
                expect(identities.has(shapes[0])).toBe(false);
                identities.add(shapes[0]);
            }
        }
        expect(identities.size).toBe(31);
    });

    it('prices all emitted controller operations including compute and uncompute', () => {
        for (const m of [0, 1, 3, 8, 31])
            for (const r of [0, 1, 4, 9])
                for (const cell of oracleDomainCells(
                    BigInt(m),
                    BigInt(r),
                    2n,
                )) {
                    const compiled = compileOracleCellController(
                            m,
                            r,
                            Number(cell.inputClassUpper),
                            Number(cell.outputStart),
                            Number(cell.outputSize),
                        ),
                        work = oracleCellControllerWork(
                            BigInt(m),
                            BigInt(r),
                            cell.inputClassUpper,
                            cell.outputStart,
                            cell.outputSize,
                        );
                    expect(work.computeAndUncomputeGates).toBe(
                        BigInt(
                            4 * compiled.circuit.gates.length +
                                2 * compiled.circuit.output.length,
                        ),
                    );
                    expect(work.controllerQubits).toBe(
                        BigInt(
                            compiled.circuit.wires +
                                compiled.circuit.output.length,
                        ),
                    );
                }
    });

    it('retains database capacity across changing query shapes and accounts for every cell', () => {
        const runs = [
                { count: 2n, inputCapacity: 1n, outputCapacity: 1n },
                { count: 3n, inputCapacity: 2n, outputCapacity: 2n },
            ],
            work = oracleDomainWork(runs, 1n);
        expect(
            work.cells.map((cell) => [
                cell.inputClassUpper,
                cell.outputStart,
                cell.queries,
            ]),
        ).toEqual([
            [1n, 0n, 5n],
            [1n, 1n, 3n],
            [2n, 0n, 3n],
            [2n, 1n, 3n],
        ]);
        const expectedPrefix =
            prefixOracleWork(5n, 2n, 1n).queryGates +
            prefixOracleWork(3n, 2n, 1n).queryGates +
            2n * prefixOracleWork(3n, 3n, 1n).queryGates;
        expect(work.prefixGates).toBe(expectedPrefix);
        expect(work.fullValueQueries).toBe(28n);
        expect(work.queryGates).toBe(expectedPrefix + work.controllerGates);
        const separate = runs.reduce(
            (sum, run) => sum + oracleDomainWork([run], 1n).queryGates,
            0n,
        );
        expect(work.queryGates).toBeGreaterThan(separate);
        expect(work.maximumQubits).toBeGreaterThan(work.databaseQubits);
        expect(
            oracleDomainWork(
                [{ count: 0n, inputCapacity: 2n, outputCapacity: 2n }],
                1n,
            ).queryGates,
        ).toBe(0n);
    });

    it('rejects invalid shapes instead of changing the domain', () => {
        expect(() => oracleDomainCells(-1n, 1n, 1n)).toThrow();
        expect(() => oracleDomainCells(1n, -1n, 1n)).toThrow();
        expect(() => oracleDomainCells(1n, 1n, 0n)).toThrow();
        expect(() =>
            oracleDomainWork(
                [{ count: -1n, inputCapacity: 1n, outputCapacity: 1n }],
                1n,
            ),
        ).toThrow();
        expect(() => compileOracleCellController(3, 2, 3, 0, 2)).toThrow();
        expect(() => compileOracleCellController(3, 2, 4, -1, 2)).toThrow();
    });
});
