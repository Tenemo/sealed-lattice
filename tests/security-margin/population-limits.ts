import assert from 'node:assert/strict';

import {
    type LatticeAssumptionGroup,
    latticeGroupFloors,
} from '#tests/security-margin/attack-screens.js';
import {
    supportedLevelBits,
    unpricedWorkAllowance,
} from '#tests/security-margin/reduction-work.js';
import {
    profilesByParticipantCount,
    latticeRequirementAt,
} from '#tests/security-margin-screen-model.js';
import { type SupportedProfile } from '#tests/supported-profile-model.js';

// Population searches stop here; a group still within its level at this
// population has no limit below it.
export const populationSearchCap = 1n << 64n;

// The largest population at most the search cap for which a requirement that
// never falls as the population grows stays within its level. Doubling, or a
// population already known to exceed the level, and then bisection find it.
// Zero when one registration already exceeds the level; undefined when the
// cap itself stays within it.
export const largestPopulationWithin = (
    within: (population: bigint) => boolean,
    exceeding?: bigint,
): bigint | undefined => {
    let low = 0n;
    let high = exceeding ?? 1n;
    if (exceeding === undefined) {
        if (within(populationSearchCap)) return undefined;
        while (within(high)) {
            low = high;
            high *= 2n;
        }
    }
    while (high - low > 1n) {
        const middle = (low + high) / 2n;
        if (within(middle)) low = middle;
        else high = middle;
    }
    return low;
};

// A lattice group's own limit on the original honest registrations of a
// poll of each participant count, whatever its option count: the smallest
// over those option counts of the largest population whose priced
// source-domain requirement stays within the profile's own criterion level,
// and likewise within its quantum stress-test level. A profile that stays
// within its level at the smallest limit so far cannot lower it, so only the
// others are searched. At each limit, the further reduction work that every
// option count's level still absorbs bounds the unpriced record creation. A
// limit is undefined when no profile has one below the search cap, and a
// floor without a finite screen imposes none.
const solveLatticePopulationLimits = (group: LatticeAssumptionGroup) =>
    profilesByParticipantCount().map(({ participantCount, profiles }) => {
        const limit = (floor: 'criterion' | 'stressTest') => {
            const levelOf = (profile: SupportedProfile) => {
                const screen = latticeGroupFloors(
                    group,
                    BigInt(profile.ciphertext.bits),
                )[floor];
                return screen === undefined
                    ? undefined
                    : supportedLevelBits(screen);
            };
            let binding:
                | Readonly<{
                      profile: SupportedProfile;
                      levelBits: bigint;
                      honestRegistrations: bigint;
                  }>
                | undefined;
            for (const profile of profiles) {
                const levelBits = levelOf(profile);
                if (levelBits === undefined) continue;
                const within = (population: bigint) =>
                    latticeRequirementAt(group, profile, population)
                        .requiredBits <= levelBits;
                if (
                    binding !== undefined &&
                    within(binding.honestRegistrations)
                )
                    continue;
                const honestRegistrations = largestPopulationWithin(
                    within,
                    binding?.honestRegistrations,
                );
                if (honestRegistrations === undefined) continue;
                binding = { profile, levelBits, honestRegistrations };
            }
            if (binding === undefined) return undefined;
            assert.ok(
                binding.honestRegistrations > 0n,
                'One registration already exceeds the supported level.',
            );
            const { honestRegistrations } = binding;
            const allowance = profiles
                .map((profile) => {
                    const levelBits = levelOf(profile);
                    if (levelBits === undefined) return undefined;
                    const { comparisons, reductionGates: gates } =
                        latticeRequirementAt(
                            group,
                            profile,
                            honestRegistrations,
                        );
                    return unpricedWorkAllowance(comparisons, gates, levelBits);
                })
                .filter((value) => value !== undefined)
                .reduce((least, value) => (value < least ? value : least));
            return {
                optionCount: binding.profile.optionCount,
                modulusBits: BigInt(binding.profile.ciphertext.bits),
                levelBits: binding.levelBits,
                honestRegistrations,
                allowance,
            };
        };
        return {
            participantCount,
            criterion: limit('criterion'),
            stressTest: limit('stressTest'),
        };
    });

// Each group's limits are solved once.
const latticePopulationLimits = new Map<
    LatticeAssumptionGroup,
    ReturnType<typeof solveLatticePopulationLimits>
>();

export const compileLatticePopulationLimits = (
    group: LatticeAssumptionGroup,
) => {
    let limits = latticePopulationLimits.get(group);
    if (limits === undefined) {
        limits = solveLatticePopulationLimits(group);
        latticePopulationLimits.set(group, limits);
    }
    return limits;
};

// The FHE comparisons' own limits, which every participant count has.
export const compileFhePopulationLimits = () =>
    compileLatticePopulationLimits('FHE Ring-LWE').map((row) => {
        assert.ok(row.criterion !== undefined && row.stressTest !== undefined);
        return {
            participantCount: row.participantCount,
            criterion: row.criterion,
            stressTest: row.stressTest,
        };
    });
