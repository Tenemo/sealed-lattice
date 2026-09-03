import { describe, expect, it } from 'vitest';

import {
    buildExternalCeremonyVisitSchedule,
    countExternalCeremonyVisits,
    externalCeremonyScenarioDefinitions,
} from '#tools/ci/external-chrome-ceremony-driver.js';

describe('external Chrome ceremony schedule', () => {
    it('matches the ordinary join-counted graphs', () => {
        const scenarios = externalCeremonyScenarioDefinitions();
        const topTen = scenarios.find(
            (scenario) =>
                scenario.identifier === 'complete-top-count-10-recovery',
        );
        const topOne = scenarios.find(
            (scenario) => scenario.identifier === 'complete-top-count-1',
        );
        const empty = scenarios.find(
            (scenario) => scenario.identifier === 'submitted-but-unusable',
        );
        const allAbstain = scenarios.find(
            (scenario) => scenario.identifier === 'all-abstain',
        );
        const privatePreparationStateLoss = scenarios.find(
            (scenario) =>
                scenario.identifier ===
                'private-preparation-consumption-state-loss',
        );
        expect(topTen).toBeDefined();
        expect(topOne).toBeDefined();
        expect(empty).toBeDefined();
        expect(allAbstain).toBeDefined();
        expect(privatePreparationStateLoss).toBeDefined();
        expect(
            countExternalCeremonyVisits(
                buildExternalCeremonyVisitSchedule(topTen!),
            ),
        ).toEqual([6, 7, 8, 7, 7, 6, 6, 6, 6, 10]);
        for (const scenario of [topOne!, empty!]) {
            expect(
                countExternalCeremonyVisits(
                    buildExternalCeremonyVisitSchedule(scenario),
                ),
            ).toEqual([6, 6, 6, 6, 6, 6, 6, 6, 6, 5]);
        }
        expect(
            countExternalCeremonyVisits(
                buildExternalCeremonyVisitSchedule(allAbstain!),
            ),
        ).toEqual([5, 5, 5, 5, 5, 5, 5, 5, 5, 4]);
        expect(
            countExternalCeremonyVisits(
                buildExternalCeremonyVisitSchedule(
                    privatePreparationStateLoss!,
                ),
            ),
        ).toEqual([2, 2, 2, 2, 2, 4, 2, 2, 2, 1]);
    });

    it('covers every durable crash hook without exceeding ten visits', () => {
        const scenarios = externalCeremonyScenarioDefinitions();
        const recoveryScenario = scenarios.find(
            (scenario) => scenario.recoveryAndHostileCoverage,
        );
        const stateLossScenario = scenarios.find(
            (scenario) =>
                scenario.identifier ===
                'private-preparation-consumption-state-loss',
        );
        expect(recoveryScenario).toBeDefined();
        expect(stateLossScenario).toBeDefined();
        const schedule = buildExternalCeremonyVisitSchedule(recoveryScenario!);
        const stateLossSchedule = buildExternalCeremonyVisitSchedule(
            stateLossScenario!,
        );
        expect(
            new Set(
                [...schedule, ...stateLossSchedule].flatMap((visit) =>
                    visit.crashBoundary === undefined
                        ? []
                        : [visit.crashBoundary],
                ),
            ),
        ).toEqual(
            new Set([
                'preparation-consume',
                'source-bind',
                'tally-generation-initialize',
                'tally-chunk-persist',
                'tally-activation-publish',
                'tally-evaluation-initialize',
                'tally-evaluation-step',
                'tally-terminal-persist',
            ]),
        );
        expect(Math.max(...countExternalCeremonyVisits(schedule))).toBe(10);
        expect(
            stateLossSchedule.some(
                (visit) => visit.expectPendingSourceRefusal === true,
            ),
        ).toBe(true);
        expect(
            schedule.some((visit) => visit.action === 'evaluation-repair'),
        ).toBe(true);
        expect(
            schedule.some((visit) => visit.action === 'state-loss-probe'),
        ).toBe(true);
        expect(schedule.some((visit) => visit.action === 'reclaim')).toBe(true);
    });
});
