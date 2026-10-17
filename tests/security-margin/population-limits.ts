import assert from 'node:assert/strict';

import {
    latticeGroupFloors,
    type LatticeAssumptionGroup,
} from '#tests/security-margin/attack-screens.js';
import {
    reductionPopulationLimit,
    supportedLevelBits,
} from '#tests/security-margin/reduction-work.js';
import {
    latticeRequirementAt,
    profilesByParticipantCount,
} from '#tests/security-margin-screen-model.js';

// The finite ceiling is derived from the constructed384-bit representation.
// A reported boundary is checked at H and H+1; zero is a valid stress result.
export const largestPopulationWithin = (
    within: (population: bigint) => boolean,
    maximum = reductionPopulationLimit(),
) => {
    assert.ok(maximum >= 1n);
    if (!within(1n)) return 0n;
    if (within(maximum)) return maximum;
    let lower = 1n,
        upper = 2n;
    while (upper < maximum && within(upper)) {
        lower = upper;
        upper *= 2n;
    }
    if (upper > maximum) upper = maximum;
    while (lower + 1n < upper) {
        const middle = (lower + upper) / 2n;
        if (within(middle)) lower = middle;
        else upper = middle;
    }
    return lower;
};

const cache = new Map<LatticeAssumptionGroup, ReturnType<typeof solve>>();
const solve = (group: LatticeAssumptionGroup) =>
    profilesByParticipantCount().map(({ participantCount, profiles }) => {
        const column = (kind: 'criterion' | 'stressTest') => {
            let result:
                | {
                      optionCount: number;
                      modulusBits: bigint;
                      levelBits: bigint;
                      honestRegistrations: bigint;
                      metadataLimited: boolean;
                  }
                | undefined;
            for (const profile of profiles) {
                const levelBits = supportedLevelBits(
                    latticeGroupFloors(group, BigInt(profile.ciphertext.bits))[
                        kind
                    ],
                );
                const within = (population: bigint) =>
                    latticeRequirementAt(group, profile, population)
                        .requiredBits <= levelBits;
                if (
                    result !== undefined &&
                    within(result.honestRegistrations || 1n)
                )
                    continue;
                const honestRegistrations = largestPopulationWithin(
                    within,
                    result?.honestRegistrations || reductionPopulationLimit(),
                );
                result = {
                    optionCount: profile.optionCount,
                    modulusBits: BigInt(profile.ciphertext.bits),
                    levelBits,
                    honestRegistrations,
                    metadataLimited:
                        honestRegistrations === reductionPopulationLimit(),
                };
                if (honestRegistrations === 0n) break;
            }
            assert.ok(result !== undefined);
            return result;
        };
        return {
            participantCount,
            criterion: column('criterion'),
            stressTest: column('stressTest'),
        };
    });

export const compileLatticePopulationLimits = (
    group: LatticeAssumptionGroup,
) => {
    let result = cache.get(group);
    if (result === undefined) {
        result = solve(group);
        cache.set(group, result);
    }
    return result;
};
