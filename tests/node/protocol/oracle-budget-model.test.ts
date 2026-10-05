import { describe, expect, it } from 'vitest';

import {
    compileOraclePermutationBudget,
    shakeQueryPermutations,
} from '#tests/oracle-budget-model.js';
import {
    oracleDomainWork,
    programmedOracleDomainWork,
} from '#tests/oracle-domain-model.js';

describe('Declared maximum-length oracle work', () => {
    it('counts padding and the first squeeze block at both SHAKE rate boundaries', () => {
        for (const rate of [1088n, 1344n] as const)
            for (const input of [
                0n,
                rate - 7n,
                rate - 6n,
                rate - 5n,
                rate,
                2n * rate,
            ])
                for (const output of [
                    1n,
                    rate - 1n,
                    rate,
                    rate + 1n,
                    2n * rate,
                    2n * rate + 1n,
                ]) {
                    // Append the suffix and first padding bit, pad to the last
                    // rate bit, then append the final one. Squeeze separately.
                    let padded = input + 4n + 1n;
                    while (padded % rate !== rate - 1n) padded++;
                    let expected = (padded + 1n) / rate;
                    let remaining = output;
                    while (remaining > rate) {
                        expected++;
                        remaining -= rate;
                    }
                    const actual = shakeQueryPermutations(input, output, rate);
                    expect(actual).toBe(expected);
                    expect(input + output).toBeLessThanOrEqual(
                        2n * rate * actual,
                    );
                }
        expect(() => shakeQueryPermutations(0n, 0n, 1088n)).toThrow();
    });

    it('bounds persistent circuits for mixed widths, prefixes and replacement records', () => {
        const schedules = [
            [{ count: 7n, inputCapacity: 0n, outputCapacity: 1n }],
            [{ count: 1n << 40n, inputCapacity: 256n, outputCapacity: 512n }],
            [{ count: 1n << 40n, inputCapacity: 1082n, outputCapacity: 1088n }],
            [
                { count: 8n, inputCapacity: 1n << 22n, outputCapacity: 512n },
                { count: 3000n, inputCapacity: 1n, outputCapacity: 1n },
                { count: 2n, inputCapacity: 4096n, outputCapacity: 1n << 20n },
                { count: 3000n, inputCapacity: 0n, outputCapacity: 2n },
            ],
        ];
        for (const runs of schedules)
            for (const chunk of [1n, 2n, 512n, 2048n])
                for (const records of [
                    [],
                    [
                        { inputBits: 0n, prefixBits: 3n },
                        { inputBits: 256n, prefixBits: 1024n },
                    ],
                ]) {
                    const permutations = runs.reduce(
                        (sum, run) =>
                            sum +
                            run.count *
                                shakeQueryPermutations(
                                    run.inputCapacity,
                                    run.outputCapacity,
                                    1088n,
                                ),
                        0n,
                    );
                    const bound = compileOraclePermutationBudget(
                        permutations,
                        chunk,
                        BigInt(records.length),
                    );
                    const base = oracleDomainWork(runs, chunk);
                    const programmed = programmedOracleDomainWork(
                        runs,
                        chunk,
                        records,
                    );
                    const visitedBits = base.cells.reduce(
                        (sum, cell) =>
                            sum +
                            cell.queries *
                                (cell.inputClassUpper + cell.outputSize + 2n),
                        0n,
                    );
                    expect(visitedBits).toBeLessThanOrEqual(
                        bound.componentBitVisitsUpperBound,
                    );
                    expect(base.queryGates).toBeLessThanOrEqual(
                        bound.baseQueryGatesUpperBound,
                    );
                    expect(programmed.queryGates).toBeLessThanOrEqual(
                        bound.programmedQueryGatesUpperBound,
                    );
                }
    });

    it('keeps empty budgets empty and refuses invalid budgets', () => {
        const empty = compileOraclePermutationBudget(0n, 512n, 19n);
        expect(empty.baseQueryGatesUpperBound).toBe(0n);
        expect(empty.programmedQueryGatesUpperBound).toBe(0n);
        expect(() => compileOraclePermutationBudget(-1n, 512n)).toThrow();
        expect(() => compileOraclePermutationBudget(1n, 0n)).toThrow();
        expect(() => compileOraclePermutationBudget(1n, 512n, -1n)).toThrow();
    });
});
