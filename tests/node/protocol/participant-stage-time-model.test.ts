import { describe, expect, it } from 'vitest';

import { measureContributionPreparationStage } from '#tests/participant-stage-time-model.js';

const observations = [
    { name: 'roster', milliseconds: 60_000 },
    { name: 'checkpoint', milliseconds: 140_000 },
    { name: 'body', milliseconds: 740_000 },
    { name: 'confirmation', milliseconds: 4_000 },
    { name: 'published-confirmation', milliseconds: 2_000 },
];

describe('complete contribution-stage timing', () => {
    it('includes roster work that changes an apparent timing pass into a failure', () => {
        const value = measureContributionPreparationStage(observations);
        expect(value.activeMilliseconds).toBe(946_000);
        expect(value.activeMilliseconds).toBeGreaterThan(900_000);
        expect(value.activeMilliseconds - 60_000).toBeLessThan(900_000);
        expect(value.recoveryMilliseconds).toBe(0);
    });

    it('counts actual coalesced work once and records a delivery recovery separately', () => {
        expect(
            measureContributionPreparationStage([
                ...observations.slice(2),
                { name: 'roster-and-checkpoint', milliseconds: 150_000 },
                { name: 'pending-delivery', milliseconds: 3_000 },
            ]),
        ).toEqual({ activeMilliseconds: 896_000, recoveryMilliseconds: 3_000 });
    });

    it('requires every operation even when the remaining subtotal is under the limit', () => {
        for (const missing of observations)
            expect(() =>
                measureContributionPreparationStage(
                    observations.filter((value) => value !== missing),
                ),
            ).toThrow('Required same-stage work was not measured');
        expect(() => measureContributionPreparationStage([])).toThrow();
    });

    it('rejects duplicate, ambiguous, unrecognized, or incomplete measurements', () => {
        for (const extra of [
            observations[0],
            { name: 'roster-and-checkpoint', milliseconds: 200_000 },
            { name: 'unclassified-work', milliseconds: 1 },
        ])
            expect(() =>
                measureContributionPreparationStage([...observations, extra]),
            ).toThrow();
        for (const milliseconds of [undefined, NaN, Infinity, -1])
            expect(() =>
                measureContributionPreparationStage([
                    ...observations.slice(0, -1),
                    { name: 'published-confirmation', milliseconds },
                ]),
            ).toThrow('A controller duration is missing or invalid');
    });

    it('accepts zero-duration clock granularity but rejects sum overflow', () => {
        expect(
            measureContributionPreparationStage(
                observations.map(({ name }) => ({ name, milliseconds: 0 })),
            ).activeMilliseconds,
        ).toBe(0);
        expect(() =>
            measureContributionPreparationStage(
                observations.map(({ name }) => ({
                    name,
                    milliseconds: Number.MAX_VALUE,
                })),
            ),
        ).toThrow('The summed duration is not finite');
    });
});
