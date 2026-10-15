import { describe, expect, it } from 'vitest';

import {
    fullCircuitQueryEnvelope,
    shakeQueryPermutations,
} from '#tests/oracle-budget-model.js';

describe('declared maximum-length oracle work', () => {
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
});
