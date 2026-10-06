import { describe, expect, it } from 'vitest';

import {
    budgetSplitBits,
    ceilingLog2,
    compileSecurityMarginScreen,
    fheAttackScreens,
    fheKnownAttackFloor,
    oracleSimulationGates,
    oracleSimulationVariants,
    requiredFheAssumptionBits,
    securityTargetBits,
} from '#tests/security-margin-screen-model.js';
import { listSupportedProfiles } from '#tests/supported-profile-model.js';

// Pascal's triangle, independent of the models' multiplicative binomials.
const pascal = (rows: number) => {
    const triangle: bigint[][] = [[1n]];
    for (let row = 1; row <= rows; row++) {
        const previous = triangle[row - 1];
        triangle.push(
            Array.from({ length: row + 1 }, (_, column) =>
                column === 0 || column === row
                    ? 1n
                    : previous[column - 1] + previous[column],
            ),
        );
    }
    return triangle;
};

describe('FHE security margin screen', () => {
    const screen = compileSecurityMarginScreen();

    it('rounds base-two logarithms up exactly at and around powers of two', () => {
        expect(ceilingLog2(1n)).toBe(0n);
        expect(ceilingLog2(8n)).toBe(3n);
        expect(ceilingLog2(9n)).toBe(4n);
        expect(ceilingLog2(1n, 2n)).toBe(-1n);
        expect(ceilingLog2(3n, 2n)).toBe(1n);
        expect(ceilingLog2((1n << 200n) + 1n)).toBe(201n);
        expect(budgetSplitBits).toBe(3n);
    });

    it('counts the selected-key and expanded ballot comparisons from the frozen thresholds', () => {
        const triangle = pascal(40);
        const moduli = new Set(
            listSupportedProfiles().map(
                (profile) => profile.ciphertext.modulus,
            ),
        );
        expect(screen.map((row) => row.participantCount)).toEqual(
            Array.from({ length: 18 }, (_, index) => index + 3),
        );
        for (const row of screen) {
            const participants = row.participantCount;
            const faults = Math.floor((participants - 1) / 3);
            const selected = Math.max(faults + 1, 2);
            // f departures must leave d eligible authors.
            const eligible = selected + faults;
            const sets = triangle[eligible][selected];
            expect(row.selectedPositionSets).toBe(sets);
            expect(row.sharedFheModulusGuesses).toBe(BigInt(moduli.size));
            // Each start-ordinal, position-set and modulus guess pays two
            // key comparisons and one ballot comparison over n messages.
            expect(row.comparisons).toBe(
                row.honestRegistrations *
                    sets *
                    BigInt(moduli.size) *
                    (2n + BigInt(participants)),
            );
            const largest = Math.max(
                ...listSupportedProfiles()
                    .filter(
                        (profile) => profile.participantCount === participants,
                    )
                    .map((profile) => profile.ciphertext.bits),
            );
            expect(row.modulusBits).toBe(BigInt(largest));
        }
    });

    it('is decided at the largest covered cost because the reduction ratio does not fall', () => {
        const row = screen[screen.length - 1];
        const exponents = Array.from(
            { length: 11 },
            (_, index) => securityTargetBits - 4n * BigInt(10 - index),
        );
        for (const variant of oracleSimulationVariants) {
            const required = exponents.map((exponent) => {
                const gates = 1n << exponent;
                return requiredFheAssumptionBits(
                    row.comparisons,
                    oracleSimulationGates(
                        variant,
                        gates,
                        row.sourceMaskScopes,
                        row.resumeFactor,
                    ),
                    gates,
                );
            });
            for (let index = 1; index < required.length; index++)
                expect(required[index]).toBeGreaterThanOrEqual(
                    required[index - 1],
                );
            expect(required[required.length - 1]).toBe(
                row.requirements.find((value) => value.variant === variant)!
                    .requiredBits,
            );
        }
    });

    it('agrees with a floating-point evaluation of the same requirement', () => {
        for (const row of screen)
            for (const requirement of row.requirements) {
                const ratio = 1 + Number(requirement.simulationGates) / 2 ** 80;
                const exact =
                    80 +
                    3 +
                    Math.log2(Number(row.comparisons)) +
                    Math.log2(ratio);
                // Away from an integer boundary the rounding agrees.
                expect(Math.abs(exact - Math.round(exact))).toBeGreaterThan(
                    1e-6,
                );
                expect(requirement.requiredBits).toBe(BigInt(Math.ceil(exact)));
            }
    });

    it('orders the nested oracle interfaces by their required level', () => {
        for (const row of screen) {
            expect(row.resumeFactor).toBeGreaterThan(5n);
            for (let index = 1; index < row.requirements.length; index++) {
                const [smaller, larger] = row.requirements.slice(
                    index - 1,
                    index + 1,
                );
                expect(smaller.simulationGates).toBeLessThan(
                    larger.simulationGates,
                );
                expect(smaller.requiredBits).toBeLessThanOrEqual(
                    larger.requiredBits,
                );
            }
            // The quadratic routing term grows with the square of the
            // conversion factor's permutation budget.
            const [, , readers, resumed] = row.requirements;
            const growth =
                Number(resumed.simulationGates) /
                Number(readers.simulationGates);
            const factorSquared = (Number(row.resumeFactor) / 5) ** 2;
            expect(growth).toBeGreaterThan(factorSquared * 0.9);
            expect(growth).toBeLessThan(factorSquared * 1.1);
        }
    });

    it('covers a modulus only with screens of the same model at the same or a larger modulus', () => {
        const at960 = fheKnownAttackFloor(960n);
        expect(at960.primal.modulusBits).toBe(960n);
        expect(at960.primal.costModel).toBe('quantum');
        expect(at960.classicalPrimal.modulusBits).toBe(960n);
        expect(at960.classicalPrimal.costModel).toBe('classical');
        expect(at960.floor.attack).toBe('dual hybrid');
        expect(at960.floor.modulusBits).toBe(992n);
        const at800 = fheKnownAttackFloor(800n);
        expect(at800.primal.modulusBits).toBe(896n);
        expect(at800.classicalPrimal.modulusBits).toBe(928n);
        // The floor is the cheapest quantum screen covering each attack.
        const quantumAt992 = fheAttackScreens.filter(
            (value) =>
                value.costModel === 'quantum' &&
                value.modulusBits === 992n &&
                value.attack !== 'primal hybrid',
        );
        expect(at800.floor.log2Cost).toBe(
            Math.min(
                ...quantumAt992.map((value) => value.log2Cost),
                at800.primal.log2Cost,
            ),
        );
        // Classical sieving costs more than the quantum model's.
        for (const modulusBits of [928n, 960n, 992n]) {
            const { primal, classicalPrimal } =
                fheKnownAttackFloor(modulusBits);
            expect(classicalPrimal.modulusBits).toBe(primal.modulusBits);
            expect(classicalPrimal.log2Cost).toBeGreaterThan(primal.log2Cost);
        }
        expect(() => fheKnownAttackFloor(993n)).toThrow();
    });

    it('records that the current FHE comparisons exceed the quantum 960-bit primal estimate at the largest rosters', () => {
        for (const participants of [19, 20]) {
            const row = screen.find(
                (value) => value.participantCount === participants,
            )!;
            expect(row.modulusBits).toBe(960n);
            const shadows = row.requirements.find(
                (value) => value.variant === 'commitment shadows',
            )!;
            expect(Number(shadows.requiredBits)).toBeGreaterThan(
                row.primal.log2Cost,
            );
            expect(shadows.marginToPrimal).toBeLessThan(0);
            // The classical estimate still leaves a positive screen margin,
            // which the resumed-hash conversion mostly consumes.
            for (const value of row.requirements)
                expect(value.marginToClassicalPrimal).toBeGreaterThan(0);
            expect(
                row.requirements[row.requirements.length - 1]
                    .marginToClassicalPrimal,
            ).toBeLessThan(10);
        }
    });
});
