import { describe, expect, it } from 'vitest';

import {
    compileFullCircuitOracleBudget,
    compileOraclePermutationBudget,
    fullCircuitQueryEnvelope,
    shakePermutationGateCharge,
    shakeQueryPermutations,
} from '#tests/oracle-budget-model.js';
import {
    oracleDomainWork,
    programmedOracleDomainWork,
    shadowOracleDomainWork,
} from '#tests/oracle-domain-model.js';

describe('Declared maximum-length oracle work', () => {
    it('covers correlated lengths without assuming the input and output maxima share a branch', () => {
        for (const rate of [1088n, 1344n] as const)
            for (const slots of [1n, 2n, 5n, 31n]) {
                const envelope = fullCircuitQueryEnvelope(slots, rate);
                // These branches each cost p permutations, but their two
                // maxima together cost 2*p-1. An average cannot bound them.
                const branches = [
                    { input: rate * slots - 6n, output: 1n },
                    { input: 0n, output: rate * slots },
                ];
                for (const branch of branches)
                    expect(
                        shakeQueryPermutations(
                            branch.input,
                            branch.output,
                            rate,
                        ),
                    ).toBe(slots);
                expect(
                    shakeQueryPermutations(
                        envelope.inputCapacity,
                        envelope.outputCapacity,
                        rate,
                    ),
                ).toBe(2n * slots - 1n);
                for (let absorb = 1n; absorb <= slots; absorb++)
                    for (
                        let squeeze = 1n;
                        absorb + squeeze - 1n <= slots;
                        squeeze++
                    ) {
                        expect(rate * absorb - 6n).toBeLessThanOrEqual(
                            envelope.inputCapacity,
                        );
                        expect(rate * squeeze).toBeLessThanOrEqual(
                            envelope.outputCapacity,
                        );
                    }
            }
        expect(() => fullCircuitQueryEnvelope(0n, 1088n)).toThrow();
    });

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

    it('prices every shadow across opening stages and includes complete nested background work', () => {
        const runs = [
            {
                count: 17n,
                inputCapacity: 31n,
                outputCapacity: 4n,
                activeShadows: [0, 1, 2],
                replacements: [],
            },
            {
                count: 5n,
                inputCapacity: 8192n,
                outputCapacity: 4096n,
                activeShadows: [1, 2],
                replacements: [{ inputBits: 31n, prefixBits: 4n }],
            },
            {
                count: 1n << 20n,
                inputCapacity: 2n,
                outputCapacity: 1n,
                activeShadows: [2],
                replacements: [{ inputBits: 31n, prefixBits: 4n }],
            },
        ];
        const slots = runs.reduce(
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
        const charged = slots * 1600n * 24n;
        const bound = compileFullCircuitOracleBudget(charged, 512n, 1n, 3n);
        const actual = shadowOracleDomainWork(runs, 512n, [7n, 19n, 29n]);
        expect(shakePermutationGateCharge).toBe(1600n * 24n);
        expect(bound.maximumLogicalQueries).toBe(slots);
        expect(actual.queryGates).toBeLessThanOrEqual(
            bound.shadowQueryGatesUpperBound,
        );
        expect(actual.queryGates).toBeGreaterThan(
            actual.base.queryGates + actual.copyGates,
        );
        // A smaller-than-one-permutation budget cannot contain a nonempty
        // reference SHAKE call. Extra gates never silently buy another call.
        const low = compileFullCircuitOracleBudget(38399n, 512n, 3n, 5n);
        expect(low.maximumLogicalQueries).toBe(0n);
        expect(low.shadowQueryGatesUpperBound).toBe(0n);
        expect(() => compileFullCircuitOracleBudget(-1n, 512n)).toThrow();
        expect(() =>
            compileOraclePermutationBudget(1n, 512n, 0n, -1n),
        ).toThrow();
    });
});
