import { describe, expect, it } from 'vitest';

import { compileBallotRandomnessBudget } from '#tests/ballot-randomness-budget-model.js';

describe('bounded ballot randomness', () => {
    it('budgets actual buffered calls and both encrypted-message samplers', () => {
        const budget = compileBallotRandomnessBudget();
        const proofMinimum =
            (4n * 262144n - 4n) * 128n +
            20n * 128n +
            (33n + 96n + 66n + 50n) * 65536n;
        expect(budget.extraProofReads).toBe(3n);
        expect(budget.maximumProofBytes).toBe(proofMinimum + 3n * 65536n);
        expect(budget.gaussianBytes).toBe(2n * (65536n + 4096n) * 20n);
        expect(budget.sparseBytes).toBe(4n * (2048n + 512n));
        expect(budget.maximumEncryptionBytes).toBe(43n * 65536n);
        expect(budget.totalRandomBytes).toBe(153290752n);
        expect(budget.exhaustionBits).toBeGreaterThanOrEqual(128n);
        expect(budget.exhaustionBound.numerator << 128n).toBeLessThanOrEqual(
            1n << budget.exhaustionBound.denominatorBits,
        );
    });

    it('independently exhausts the buffered-rejection implication in small streams', () => {
        for (const requests of [[1], [2], [3], [1, 2], [2, 3]]) {
            const block = 2;
            const minimum = requests.reduce(
                (sum, request) => sum + Math.ceil(request / block) * block,
                0,
            );
            const capacity = minimum + block;
            let minimumRejectedOnExhaustion = capacity;
            let exhaustedCases = 0;
            for (let mask = 0; mask < 2 ** capacity; mask++) {
                let cursor = 0;
                let rejected = 0;
                let exhausted = false;
                for (const request of requests) {
                    let accepted = 0;
                    while (accepted < request) {
                        if (cursor + block > capacity) {
                            exhausted = true;
                            break;
                        }
                        for (let index = 0; index < block; index++) {
                            if (accepted < request) {
                                if ((mask & (1 << (cursor + index))) === 0)
                                    accepted++;
                                else rejected++;
                            }
                        }
                        cursor += block;
                    }
                    if (exhausted) break;
                }
                if (exhausted) {
                    exhaustedCases++;
                    minimumRejectedOnExhaustion = Math.min(
                        minimumRejectedOnExhaustion,
                        rejected,
                    );
                }
            }
            expect(exhaustedCases).toBeGreaterThan(0);
            expect(minimumRejectedOnExhaustion).toBeGreaterThanOrEqual(2);
        }
    });

    it('bounds sparse-sampler exhaustion against an exact small-state recurrence', () => {
        for (const degree of [4, 8]) {
            for (let support = 1; support < degree; support++) {
                const draws = 2 * support;
                let counts = [1n, ...Array<bigint>(support).fill(0n)];
                for (let draw = 0; draw < draws; draw++) {
                    const next = Array<bigint>(support + 1).fill(0n);
                    for (let selected = 0; selected <= support; selected++) {
                        if (selected === support)
                            next[selected] += counts[selected] * BigInt(degree);
                        else {
                            next[selected] +=
                                counts[selected] * BigInt(selected);
                            next[selected + 1] +=
                                counts[selected] * BigInt(degree - selected);
                        }
                    }
                    counts = next;
                }
                const failing = counts
                    .slice(0, support)
                    .reduce((sum, value) => sum + value, 0n);
                const factorial = (value: bigint): bigint =>
                    value < 2n ? 1n : value * factorial(value - 1n);
                const combinations =
                    factorial(BigInt(draws)) /
                    (factorial(BigInt(support + 1)) *
                        factorial(BigInt(support - 1)));
                const numerator =
                    combinations * BigInt(support - 1) ** BigInt(support + 1);
                expect(
                    failing * BigInt(degree) ** BigInt(support + 1),
                ).toBeLessThanOrEqual(
                    numerator * BigInt(degree) ** BigInt(draws),
                );
            }
        }
    });
});
