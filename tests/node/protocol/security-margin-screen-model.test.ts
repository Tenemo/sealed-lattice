import { describe, expect, it } from 'vitest';

import {
    fheKnownAttackFloor,
    latticeAssumptionGroups,
    latticeGroupFloors,
} from '#tests/security-margin/attack-screens.js';
import {
    compileLatticePopulationLimits,
    largestPopulationWithin,
} from '#tests/security-margin/population-limits.js';
import {
    compileReductionWork,
    maximumExperimentGates,
    minimumReductionWork,
    originalQueryDivisor,
    reductionMetadataFits,
    reductionPopulationLimit,
} from '#tests/security-margin/reduction-work.js';
import { latticeRequirementAt } from '#tests/security-margin-screen-model.js';
import { deriveSupportedProfile } from '#tests/supported-profile-model.js';
import { proofCompilerCaps } from '#tests/wide-challenge-compiler-model.js';

describe('population-dependent complete reduction', () => {
    it('finds exact monotone boundaries including zero and the derived ceiling', () => {
        expect(
            largestPopulationWithin((population) => population <= 7n, 100n),
        ).toBe(7n);
        expect(largestPopulationWithin(() => false, 100n)).toBe(0n);
        expect(largestPopulationWithin(() => true, 100n)).toBe(100n);
        const limit = reductionPopulationLimit();
        expect(limit).toBeGreaterThan(1n << 64n);
        expect(reductionMetadataFits(limit)).toBe(true);
        expect(reductionMetadataFits(limit + 1n)).toBe(false);
        expect(
            2n * maximumExperimentGates +
                originalQueryDivisor *
                    compileReductionWork(limit).fixedExternalQueries,
        ).toBeLessThanOrEqual(
            originalQueryDivisor * proofCompilerCaps.adversaryQueries,
        );
        expect(() => compileReductionWork(0n)).toThrow();
    });
    it('retains initialization, rounding and query growth above the reference bank', () => {
        for (const population of [1n, 20n, 21n, 37n, 1000n, 1n << 64n]) {
            const row = compileReductionWork(population);
            for (const work of [
                minimumReductionWork,
                1n << 80n,
                maximumExperimentGates,
            ])
                expect(
                    row.fixedWork + row.workSlope * work,
                ).toBeLessThanOrEqual(row.uniformLateSlope * work);
        }
        for (const population of [21n, 37n, 1000n, 1n << 64n])
            expect(
                compileReductionWork(population).fixedExternalQueries,
            ).toBeGreaterThan(compileReductionWork(20n).fixedExternalQueries);
    });
    it('checks each group boundary with the complete full-interval requirement', () => {
        const checks = latticeAssumptionGroups.flatMap((group) =>
            compileLatticePopulationLimits(group).flatMap((row) =>
                (['criterion', 'stressTest'] as const).map((kind) => {
                    const bound = row[kind],
                        profile = deriveSupportedProfile(
                            row.participantCount,
                            bound.optionCount,
                        );
                    const floor = BigInt(
                        Math.floor(
                            latticeGroupFloors(
                                group,
                                BigInt(profile.ciphertext.bits),
                            )[kind].log2Cost,
                        ),
                    );
                    return { group, profile, bound, floor };
                }),
            ),
        );
        for (const { group, profile, bound, floor } of checks.filter(
            (check) => check.bound.honestRegistrations > 0n,
        ))
            expect(
                latticeRequirementAt(group, profile, bound.honestRegistrations)
                    .requiredBits,
            ).toBeLessThanOrEqual(floor);
        for (const { group, profile, bound, floor } of checks.filter(
            (check) => !check.bound.metadataLimited,
        ))
            expect(
                latticeRequirementAt(
                    group,
                    profile,
                    bound.honestRegistrations + 1n,
                ).requiredBits,
            ).toBeGreaterThan(floor);
        expect(fheKnownAttackFloor(880n).criterion.attack).toBe(
            'primal hybrid',
        );
        expect(fheKnownAttackFloor(880n).stressTest.log2Cost).toBeLessThan(
            fheKnownAttackFloor(880n).criterion.log2Cost,
        );
        expect(() => fheKnownAttackFloor(881n)).toThrow();
    }, 60000);
});
