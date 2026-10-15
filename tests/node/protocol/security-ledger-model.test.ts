import { describe, expect, it } from 'vitest';

import {
    addRationals,
    atMost,
    ceilingSquareRoot,
    rational,
    rationalCeilingLog2,
} from '#tests/security-ledger/rational.js';
import {
    compileErrorEnvelope,
    compileErrorGroups,
    compileSecurityLedger,
    compileSecurityOperands,
    ledgerGroupBudget,
    ledgerGroups,
    securityProofEnvelope,
    validatePricedRoleShape,
} from '#tests/security-ledger-model.js';
import {
    maximumExperimentGates,
    minimumReductionWork,
} from '#tests/security-margin/reduction-work.js';

describe('full128-bit composition ledger', () => {
    it('computes exact integer square roots and base-two logarithms', () => {
        for (const [value, root] of [
            [0n, 0n],
            [1n, 1n],
            [2n, 2n],
            [4n, 2n],
            [5n, 3n],
            [(1n << 64n) ** 2n, 1n << 64n],
            [(1n << 64n) ** 2n + 1n, (1n << 64n) + 1n],
        ] as const)
            expect(ceilingSquareRoot(value)).toBe(root);
        expect(() => ceilingSquareRoot(-1n)).toThrow();
        expect(rationalCeilingLog2(rational(1n))).toBe(0n);
        expect(rationalCeilingLog2(rational(1n, 2n))).toBe(-1n);
        expect(rationalCeilingLog2(rational(1n, 3n))).toBe(-1n);
        expect(rationalCeilingLog2(rational(3n, 2n))).toBe(1n);
        expect(rationalCeilingLog2(rational(1n, 1n << 300n))).toBe(-300n);
        expect(
            rationalCeilingLog2(rational((1n << 300n) + 1n, 1n << 300n)),
        ).toBe(1n);
        expect(() => rationalCeilingLog2(rational(0n))).toThrow();
        expect(() => rational(1n, 0n)).toThrow();
        expect(() => rational(-1n)).toThrow();
    });
    it('rejects any role that exceeds a separately priced constructor dimension', () => {
        const boundary = {
            columns: securityProofEnvelope.columns,
            lookups: securityProofEnvelope.lookups,
            oracles: securityProofEnvelope.oracles,
            affineRows: 1n << 32n,
        };
        expect(() => validatePricedRoleShape(boundary)).not.toThrow();
        for (const key of Object.keys(boundary) as (keyof typeof boundary)[])
            expect(() =>
                validatePricedRoleShape({
                    ...boundary,
                    [key]: boundary[key] + 1n,
                }),
            ).toThrow();
        for (const key of ['columns', 'oracles'] as const)
            expect(() =>
                validatePricedRoleShape({ ...boundary, [key]: 0n }),
            ).toThrow();
    });
    it('allocates the whole target once and preserves all explicit sampler terms', () => {
        const budget = addRationals(...ledgerGroups.map(ledgerGroupBudget));
        expect(budget.numerator).toBe(budget.denominator);
        const operands = compileSecurityOperands();
        expect(operands.queries).toBe(704n);
        expect(
            securityProofEnvelope.programmedPrefixBits,
        ).toBeGreaterThanOrEqual(8n * 1048576n);
        expect(operands.maximumSourceFamilies).toBeGreaterThan(1n);
        expect(atMost(operands.sharingRatio, rational(5n, 8n))).toBe(true);
        expect(atMost(operands.releaseRatio, rational(1n, 8n))).toBe(true);
    }, 60000);
    it('satisfies every chronological endpoint and representative interior work', () => {
        const rows = compileSecurityLedger();
        const population = rows.reduce(
            (minimum, row) =>
                row.criterion.binding.limit < minimum
                    ? row.criterion.binding.limit
                    : minimum,
            rows[0].criterion.binding.limit,
        );
        // The owner accepted this suite's limit of 37 original honest
        // registrations; a model change that lowers it returns to the owner.
        expect(population).toBeGreaterThanOrEqual(37n);
        for (const row of rows)
            expect(row.stressTest.binding.limit).toBeLessThanOrEqual(
                row.criterion.binding.limit,
            );
        for (const original of [1n, 20n, population]) {
            const checks = [
                ...compileErrorEnvelope(original),
                ...[1n << 64n, 1n << 96n].map((work) => ({
                    work,
                    ...compileErrorGroups(original, work),
                })),
            ];
            for (const check of checks) {
                const target = rational(check.work, 1n << 128n);
                for (const [group, value] of [
                    ['Purpose authentication', check.authentication],
                    ['Identity collisions', check.identity],
                    ['Statistical terms', check.statistical],
                ] as const) {
                    const allocation = ledgerGroupBudget(group);
                    expect(
                        atMost(
                            value,
                            rational(
                                target.numerator * allocation.numerator,
                                target.denominator * allocation.denominator,
                            ),
                        ),
                    ).toBe(true);
                }
            }
            for (const check of checks.filter(
                (value) => value.work < minimumReductionWork,
            ))
                expect(check.statistical.numerator).toBe(0n);
        }
        expect(() => compileErrorGroups(0n, 1n)).toThrow();
        expect(() =>
            compileErrorGroups(1n, maximumExperimentGates + 1n),
        ).toThrow();
    }, 60000);
});
