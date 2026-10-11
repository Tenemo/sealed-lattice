import { describe, expect, it } from 'vitest';

import { compileSourceDomainOracleBudget } from '#tests/oracle-budget-model.js';
import { compileRegistrationSourceExtractionWork } from '#tests/registration-source-randomness-model.js';
import {
    budgetSplitBits,
    ceilingLog2,
    compileSecurityMarginScreen,
    criterionAttacks,
    decisiveExperimentGates,
    fheAttackScreens,
    fheKnownAttackFloor,
    compileFhePopulationLimits,
    reductionGates,
    reductionVariants,
    registrationSourceInputBits,
    requiredFheAssumptionBits,
    securityTargetBits,
    sourceDomainRequirementAt,
    supportedLevelBits,
    unpricedWorkAllowance,
} from '#tests/security-margin-screen-model.js';
import {
    deriveSupportedProfile,
    listSupportedProfiles,
    type SupportedProfile,
} from '#tests/supported-profile-model.js';

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

const permutationCharge = 24n * 1600n;

// Experiments at which a reduction ratio could peak: the smallest, powers of
// two, slot intervals' first gate counts, the first slot of each of the
// widest length widths and of every eighth narrower one, the decisive
// experiment and the target. A length width grows when
// 4*1344*factor*slots + 2*512 + 3 reaches the next power of two.
const sampledExperiments = (factors: readonly bigint[]) => {
    const target = 1n << securityTargetBits;
    const experiments = new Set([1n, decisiveExperimentGates, target]);
    for (let exponent = 8n; exponent <= securityTargetBits; exponent += 8n)
        experiments.add(1n << exponent);
    for (
        let exponent = 0n;
        permutationCharge << exponent <= target;
        exponent += 4n
    )
        experiments.add(permutationCharge << exponent);
    for (const factor of factors) {
        const perSlot = 4n * 1344n * factor;
        const widest = BigInt(
            (perSlot * (target / permutationCharge) + 1027n).toString(2).length,
        );
        for (let width = 12n; width <= widest; width++) {
            if (width < widest - 7n && width % 8n !== 0n) continue;
            const slots =
                ((1n << (width - 1n)) - 1027n + perSlot - 1n) / perSlot;
            if (slots > 0n && slots * permutationCharge <= target)
                experiments.add(slots * permutationCharge);
        }
    }
    return [...experiments];
};

// Whether an experiment's reduction ratio (T + W) / T stays within the
// decisive experiment's, compared exactly.
const withinDecisiveRatio = (
    experiment: bigint,
    work: bigint,
    decisiveWork: bigint,
) =>
    (experiment + work) * decisiveExperimentGates <=
    (decisiveExperimentGates + decisiveWork) * experiment;

const profilesOf = (participantCount: number): readonly SupportedProfile[] =>
    listSupportedProfiles().filter(
        (profile) => profile.participantCount === participantCount,
    );

describe('FHE security margin screen', () => {
    const screen = compileSecurityMarginScreen();
    const limits = compileFhePopulationLimits();

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
            // The row is the option count that leaves the least further work
            // within its own criterion level, the largest modulus among
            // equals.
            const profiles = profilesOf(participants);
            expect(
                profiles.some(
                    (profile) =>
                        profile.optionCount === row.optionCount &&
                        BigInt(profile.ciphertext.bits) === row.modulusBits,
                ),
            ).toBe(true);
            for (const profile of profiles) {
                const modulusBits = BigInt(profile.ciphertext.bits);
                const at = sourceDomainRequirementAt(
                    profile,
                    row.honestRegistrations,
                );
                const allowance = unpricedWorkAllowance(
                    at.comparisons,
                    at.reductionGates,
                    supportedLevelBits(
                        fheKnownAttackFloor(modulusBits).criterion,
                    ),
                );
                expect(allowance).toBeGreaterThanOrEqual(
                    row.criterionAllowance,
                );
                expect(
                    allowance > row.criterionAllowance ||
                        modulusBits <= row.modulusBits,
                ).toBe(true);
            }
        }
    });

    it('is decided at the largest whole-slot experiment within the target', () => {
        const target = 1n << securityTargetBits;
        expect(decisiveExperimentGates % permutationCharge).toBe(0n);
        expect(decisiveExperimentGates).toBeLessThanOrEqual(target);
        expect(decisiveExperimentGates + permutationCharge).toBeGreaterThan(
            target,
        );
        for (const row of screen)
            for (const variant of reductionVariants) {
                const decisiveWork = reductionGates(
                    variant,
                    decisiveExperimentGates,
                    row.operands,
                );
                for (const experiment of sampledExperiments([
                    2n,
                    5n,
                    row.operands.resumeFactor,
                ]))
                    expect(
                        withinDecisiveRatio(
                            experiment,
                            reductionGates(variant, experiment, row.operands),
                            decisiveWork,
                        ),
                    ).toBe(true);
                // The target fills the same slots, so the same work over a
                // larger experiment gives it the smaller ratio.
                expect(reductionGates(variant, target, row.operands)).toBe(
                    decisiveWork,
                );
            }
    });

    it('keeps the fixed work below the decisive ratio at every population limit', () => {
        // At a limit the requirement is closest to the next whole bit, so
        // the source cache and the extractions' fixed work, whose share grows
        // as the experiment shrinks, have the least room there.
        for (const row of limits)
            for (const limit of [row.criterion, row.stressTest]) {
                const profile = deriveSupportedProfile(
                    row.participantCount,
                    limit.optionCount,
                );
                const at = sourceDomainRequirementAt(
                    profile,
                    limit.honestRegistrations,
                );
                const fixed = reductionGates(
                    'source-domain reduction',
                    0n,
                    at.operands,
                );
                expect(fixed > at.operands.sourceCacheGates).toBe(
                    at.operands.corruptSourceExtractions > 0n,
                );
                for (const experiment of sampledExperiments([
                    at.operands.resumeFactor < 5n
                        ? 5n
                        : at.operands.resumeFactor,
                ])) {
                    const work = reductionGates(
                        'source-domain reduction',
                        experiment,
                        at.operands,
                    );
                    expect(
                        withinDecisiveRatio(
                            experiment,
                            work,
                            at.reductionGates,
                        ),
                    ).toBe(true);
                    expect(
                        requiredFheAssumptionBits(
                            at.comparisons,
                            work,
                            experiment,
                        ),
                    ).toBeLessThanOrEqual(limit.levelBits);
                }
            }
    });

    it('agrees with a floating-point evaluation of the same requirement', () => {
        for (const row of screen)
            for (const requirement of row.requirements) {
                const ratio = 1 + Number(requirement.reductionGates) / 2 ** 80;
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
            expect(row.operands.resumeFactor).toBeGreaterThan(5n);
            for (let index = 1; index < row.requirements.length; index++) {
                const [smaller, larger] = row.requirements.slice(
                    index - 1,
                    index + 1,
                );
                expect(smaller.reductionGates).toBeLessThan(
                    larger.reductionGates,
                );
                expect(smaller.requiredBits).toBeLessThanOrEqual(
                    larger.requiredBits,
                );
            }
            // The quadratic routing term grows with the square of the
            // conversion factor's permutation budget.
            const named = (variant: string) =>
                row.requirements.find((value) => value.variant === variant)!;
            const readers = named('commitment shadows and readers');
            const resumed = named('commitment shadows and resumed hashes');
            const growth =
                Number(resumed.reductionGates) / Number(readers.reductionGates);
            const factorSquared = (Number(row.operands.resumeFactor) / 5) ** 2;
            expect(growth).toBeGreaterThan(factorSquared * 0.9);
            expect(growth).toBeLessThan(factorSquared * 1.1);
        }
    });

    it('charges a forwarded oracle only the comparison count and the budget split', () => {
        for (const row of screen) {
            const forwarded = row.requirements.find(
                (value) => value.variant === 'forwarded oracle',
            )!;
            expect(forwarded.reductionGates).toBe(0n);
            // The bit length of comparisons - 1 is the smallest k with
            // comparisons <= 2^k.
            expect(forwarded.requiredBits).toBe(
                80n + 3n + BigInt((row.comparisons - 1n).toString(2).length),
            );
            // Even the quantum stress test leaves it a positive margin.
            expect(forwarded.marginToStressTest).toBeGreaterThan(0);
        }
    });

    it('puts every registration-source input in one dyadic class', () => {
        const lengths = registrationSourceInputBits();
        const coefficientBits = 8n * 65_536n;
        const modulusBytes = [
            ...new Set(
                listSupportedProfiles().map((profile) =>
                    BigInt(Math.ceil(profile.ciphertext.bits / 8)),
                ),
            ),
        ].sort((left, right) => (left < right ? -1 : 1));
        // The framing carries the modulus once, and each coefficient has one
        // sign byte and the modulus bytes.
        const perModulusByte = 8n + coefficientBits;
        const framing =
            lengths[0] - coefficientBits - perModulusByte * modulusBytes[0];
        expect(lengths).toEqual(
            modulusBytes.map(
                (bytes) => framing + coefficientBits + perModulusByte * bytes,
            ),
        );
        expect(framing).toBeGreaterThan(8n * 1952n);
        expect(framing).toBeLessThan(8n * 4096n);
        for (const bits of lengths) {
            expect(bits).toBeGreaterThan(1n << 25n);
            expect(bits).toBeLessThanOrEqual(1n << 26n);
        }
    });

    it('restricts the quadratic database term to calls that can reach a registration source', () => {
        const lengths = registrationSourceInputBits();
        const gates = 1n << securityTargetBits;
        const permutations = (2n * gates) / (24n * 1600n);
        const minimumCall = (lengths[0] + 6n + 1343n) / 1344n;
        const calls = permutations / minimumCall;
        const lengthBits = BigInt(
            (4n * 1344n * permutations + 2n * 512n + 3n).toString(2).length,
        );
        const budget = compileSourceDomainOracleBudget(gates, 512n, lengths);
        expect(budget.minimumSourceCallPermutations).toBe(minimumCall);
        expect(budget.sourceCallsUpperBound).toBe(calls);
        expect(budget.sourceInputClassBits).toBe(1n << 26n);
        for (const row of screen) {
            const shadows = row.operands.sourceMaskScopes;
            // Programmed and shadow databases each hold one source class; the
            // entry term dominates the per-call and controller terms.
            const leading =
                (16n + 4n * shadows) *
                59n *
                calls ** 2n *
                lengthBits *
                ((1n << 26n) + 2n);
            const priced = compileSourceDomainOracleBudget(
                gates,
                512n,
                lengths,
                0n,
                shadows,
            ).shadowQueryGatesUpperBound;
            expect(priced).toBeGreaterThan(leading);
            expect(Number(priced) / Number(leading)).toBeLessThan(1.1);
            // The full-domain database keeps an entry per permutation of the
            // whole experiment, which the shortest source call alone exceeds.
            expect(
                reductionGates('commitment shadows', gates, row.operands) /
                    priced,
            ).toBeGreaterThan(minimumCall);
        }
    });

    it('prices the complete source-domain reduction around its query circuits', () => {
        const lengths = registrationSourceInputBits();
        const gates = 1n << securityTargetBits;
        const slots = gates / permutationCharge;
        for (const row of screen) {
            const { operands } = row;
            const factor = operands.resumeFactor;
            const records = operands.honestProofScopes;
            const shadows = operands.sourceMaskScopes;
            const circuits = compileSourceDomainOracleBudget(
                gates,
                512n,
                lengths,
                0n,
                shadows,
            );
            const complete = compileSourceDomainOracleBudget(
                gates,
                512n,
                lengths,
                records,
                shadows,
                factor,
            );
            // The conversions enlarge only the forwarded calls: the source
            // calls and their database capacity stay the coherent calls'.
            expect(complete.sourceCallsUpperBound).toBe(
                circuits.sourceCallsUpperBound,
            );
            expect(complete.sourceComponentCapacityUpperBound).toBe(
                4n * circuits.sourceCallsUpperBound,
            );
            // Every forwarded call is made twice around the replacement copy.
            expect(complete.forwardedCallGatesUpperBound).toBe(
                2n * factor * slots * permutationCharge,
            );
            // Each programmed record compares and substitutes in the
            // replacement copy of every converted permutation.
            const withoutRecords = compileSourceDomainOracleBudget(
                gates,
                512n,
                lengths,
                0n,
                shadows,
                factor,
            );
            expect(
                complete.shadowQueryGatesUpperBound -
                    withoutRecords.shadowQueryGatesUpperBound,
            ).toBe(
                factor *
                    slots *
                    records *
                    (10n + 10n * complete.lengthBitsUpperBound + 20n * 1344n),
            );
            // Each corrupt registration-source extraction scans the source
            // component's capacity and decodes the coordinate it finds.
            const extraction = compileRegistrationSourceExtractionWork(
                row.participantCount,
                row.optionCount,
                complete.sourceComponentCapacityUpperBound,
                operands.corruptSourceExtractions,
            ).maximumPreparedSelectionAndDecodingGates;
            const source = row.requirements.find(
                (value) => value.variant === 'source-domain reduction',
            )!;
            expect(source.reductionGates).toBe(
                complete.shadowQueryGatesUpperBound +
                    complete.forwardedCallGatesUpperBound +
                    extraction +
                    operands.sourceCacheGates,
            );
            // The forwarded calls, extractions and cache are negligible next
            // to the query circuits.
            expect(
                Number(
                    source.reductionGates - complete.shadowQueryGatesUpperBound,
                ) / Number(complete.shadowQueryGatesUpperBound),
            ).toBeLessThan(2 ** -40);
            // The unpriced record creation may take far more than the
            // experiment's own work before the criterion falls.
            expect(row.criterionAllowance).toBe(
                unpricedWorkAllowance(
                    row.comparisons,
                    source.reductionGates,
                    supportedLevelBits(row.criterion),
                ),
            );
            expect(row.criterionAllowance).toBeGreaterThan(gates << 100n);
            expect(
                requiredFheAssumptionBits(
                    row.comparisons,
                    source.reductionGates + row.criterionAllowance,
                ),
            ).toBe(supportedLevelBits(row.criterion));
            expect(
                requiredFheAssumptionBits(
                    row.comparisons,
                    source.reductionGates + row.criterionAllowance + 1n,
                ),
            ).toBeGreaterThan(supportedLevelBits(row.criterion));
        }
    });

    it('never lowers the requirement as the population grows', () => {
        // The limit search relies on this, so compare the exact quantity the
        // requirement rounds, comparisons times the decisive experiment's
        // reduced cost, at the smallest and largest option counts.
        for (const [participants, options] of [
            [4, 2],
            [4, 20],
            [20, 2],
            [20, 20],
        ]) {
            const profile = deriveSupportedProfile(participants, options);
            let previous = 0n;
            for (
                let population = BigInt(participants);
                population < 1n << 34n;
                population = (3n * population) / 2n + 1n
            ) {
                const at = sourceDomainRequirementAt(profile, population);
                const scaled =
                    at.comparisons *
                    (decisiveExperimentGates + at.reductionGates);
                expect(scaled).toBeGreaterThanOrEqual(previous);
                previous = scaled;
            }
        }
    });

    it('solves for the smallest population limit over every option count', () => {
        expect(limits.map((row) => row.participantCount)).toEqual(
            screen.map((row) => row.participantCount),
        );
        for (const row of limits) {
            for (const [limit, floor] of [
                [row.criterion, 'criterion'],
                [row.stressTest, 'stressTest'],
            ] as const) {
                const levelOf = (profile: SupportedProfile) =>
                    supportedLevelBits(
                        fheKnownAttackFloor(BigInt(profile.ciphertext.bits))[
                            floor
                        ],
                    );
                const binding = deriveSupportedProfile(
                    row.participantCount,
                    limit.optionCount,
                );
                expect(BigInt(binding.ciphertext.bits)).toBe(limit.modulusBits);
                expect(limit.levelBits).toBe(levelOf(binding));
                // Every option count stays within its own level at the
                // limit, and the least further work any of them absorbs is
                // the reported allowance.
                let least: bigint | undefined;
                for (const profile of profilesOf(row.participantCount)) {
                    const at = sourceDomainRequirementAt(
                        profile,
                        limit.honestRegistrations,
                    );
                    expect(at.requiredBits).toBeLessThanOrEqual(
                        levelOf(profile),
                    );
                    const allowance = unpricedWorkAllowance(
                        at.comparisons,
                        at.reductionGates,
                        levelOf(profile),
                    );
                    if (least === undefined || allowance < least)
                        least = allowance;
                }
                expect(limit.allowance).toBe(least);
                // One more registration crosses the binding option count's
                // level.
                const beyond = sourceDomainRequirementAt(
                    binding,
                    limit.honestRegistrations + 1n,
                );
                expect(beyond.requiredBits).toBeGreaterThan(limit.levelBits);
                expect(
                    unpricedWorkAllowance(
                        beyond.comparisons,
                        beyond.reductionGates,
                        limit.levelBits,
                    ),
                ).toBeLessThan(0n);
                // At its limit the binding option count keeps only the room
                // below one more registration, which varies, yet every level
                // still absorbs unpriced record creation far beyond the
                // experiment's own work.
                expect(limit.allowance).toBeGreaterThan(
                    1n << (securityTargetBits + 50n),
                );
            }
            // The comparisons and the commitment shadows both grow with the
            // population, so the requirement rises two bits per doubling and
            // the two limits differ by about the square root of their level
            // gap, whichever option counts bind them.
            const expected =
                2 **
                (Number(row.criterion.levelBits - row.stressTest.levelBits) /
                    2);
            const ratio =
                Number(row.criterion.honestRegistrations) /
                Number(row.stressTest.honestRegistrations);
            expect(ratio / expected).toBeGreaterThan(0.99);
            expect(ratio / expected).toBeLessThan(1.01);
            expect(row.stressTest.honestRegistrations).toBeGreaterThan(
                BigInt(row.participantCount),
            );
        }
    });

    it('decides the criterion with classical screens of every estimator attack', () => {
        const largest = BigInt(
            Math.max(
                ...listSupportedProfiles().map(
                    (profile) => profile.ciphertext.bits,
                ),
            ),
        );
        const classical = fheAttackScreens.filter(
            (value) => value.costModel === 'classical',
        );
        for (const attack of criterionAttacks)
            expect(
                classical.some(
                    (value) =>
                        value.attack === attack && value.modulusBits >= largest,
                ),
            ).toBe(true);
        // Each floor is the cheapest screen of its model that covers the
        // modulus from the same or a larger one, for each attack.
        const cheapest = (
            costModel: 'classical' | 'quantum',
            modulusBits: bigint,
        ) => {
            const covering = fheAttackScreens.filter(
                (value) =>
                    value.costModel === costModel &&
                    value.modulusBits >= modulusBits,
            );
            return Math.min(
                ...[...new Set(covering.map((value) => value.attack))].map(
                    (attack) =>
                        covering
                            .filter((value) => value.attack === attack)
                            .sort((left, right) =>
                                left.modulusBits < right.modulusBits ? -1 : 1,
                            )[0].log2Cost,
                ),
            );
        };
        for (const modulusBits of [800n, 928n, 960n]) {
            const { criterion, stressTest } = fheKnownAttackFloor(modulusBits);
            expect(criterion.costModel).toBe('classical');
            expect(criterion.log2Cost).toBe(cheapest('classical', modulusBits));
            expect(stressTest.costModel).toBe('quantum');
            expect(stressTest.log2Cost).toBe(cheapest('quantum', modulusBits));
            expect(criterion.log2Cost).toBeGreaterThan(stressTest.log2Cost);
        }
        const at960 = fheKnownAttackFloor(960n);
        expect(at960.criterion.attack).toBe('primal hybrid');
        expect(at960.criterion.modulusBits).toBe(960n);
        expect(at960.stressTest.attack).toBe('dual hybrid');
        expect(at960.stressTest.modulusBits).toBe(992n);
        // Classical sieving costs more than the quantum model's.
        const paired = fheAttackScreens
            .filter((value) => value.costModel === 'quantum')
            .flatMap((quantum) =>
                classical
                    .filter(
                        (value) =>
                            value.attack === quantum.attack &&
                            value.modulusBits === quantum.modulusBits,
                    )
                    .map((matching) => [quantum, matching] as const),
            );
        expect(paired.length).toBeGreaterThanOrEqual(3);
        for (const [quantum, matching] of paired)
            expect(matching.log2Cost).toBeGreaterThan(quantum.log2Cost);
        expect(() => fheKnownAttackFloor(993n)).toThrow();
    });

    it('records the margins of the priced reductions at the largest rosters', () => {
        for (const participants of [19, 20]) {
            const row = screen.find(
                (value) => value.participantCount === participants,
            )!;
            expect(row.modulusBits).toBe(960n);
            const named = (variant: string) =>
                row.requirements.find((value) => value.variant === variant)!;
            for (const value of row.requirements)
                expect(value.marginToCriterion).toBeGreaterThan(0);
            // Restricting simulation to the registration-source domain keeps
            // a positive margin even under the quantum stress test.
            const source = named('source-domain reduction');
            expect(source.marginToStressTest).toBeGreaterThan(0);
            expect(source.marginToCriterion).toBeGreaterThan(30);
            // Implementing the whole function exceeds the stress test, and
            // the resumed-hash conversion consumes most of the criterion
            // margin.
            expect(named('commitment shadows').marginToStressTest).toBeLessThan(
                0,
            );
            expect(
                named('commitment shadows and resumed hashes')
                    .marginToCriterion,
            ).toBeLessThan(10);
        }
    });
});
