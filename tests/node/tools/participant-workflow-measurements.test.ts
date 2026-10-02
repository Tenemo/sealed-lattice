import { describe, expect, it } from 'vitest';

import {
    summarizeParticipantWorkflow,
    type ParticipantOperationMeasurement,
} from '#tools/ci/participant-workflow-measurements.js';

const ordinary = (): ParticipantOperationMeasurement[] => {
    const operations: ParticipantOperationMeasurement[] = [];
    for (let position = 0; position < 3; position++)
        for (const operation of [
            'create',
            'confirm',
            'ballot',
            'close',
            'release',
        ]) {
            const started = operations.length * 10;
            operations.push({
                position,
                operation,
                started,
                finished: started + 6,
            });
        }
    operations.push({
        position: 2,
        operation: 'result',
        started: 150,
        finished: 158,
        memory: { workerBytes: 100, helperBytes: 70, arenaBytes: 30 },
        evaluationMemory: { workerBytes: 120, helperBytes: 80, arenaBytes: 40 },
    });
    return operations;
};

describe('complete participant workflow measurements', () => {
    it('charges the combined result and combined instance memory, and distinguishes wall time from active work', () => {
        const measured = summarizeParticipantWorkflow(ordinary(), 3, true);
        expect(measured.activeMilliseconds).toBe(98);
        expect(measured.sequentialCompletionMilliseconds).toBe(158);
        expect(
            measured.participants.map(
                (participant) => participant.activeMilliseconds,
            ),
        ).toEqual([30, 30, 38]);
        expect(measured.participants[2].stages).toEqual({
            registration: 6,
            'roster and confirmation': 6,
            ballot: 6,
            closing: 6,
            release: 6,
            result: 8,
        });
        expect(measured.participants[2].maximumStageMilliseconds).toBe(8);
        expect(
            measured.participants.map(
                (participant) => participant.combinedWorkerHelperArenaBytes,
            ),
        ).toEqual([null, null, 240]);
    });
    it('never labels concurrent cohort wall time as sequential completion', () => {
        const concurrent = ordinary().map((operation) => ({
            ...operation,
            started: 0,
            finished: 6,
        }));
        expect(() => summarizeParticipantWorkflow(concurrent, 3, true)).toThrow(
            'overlap',
        );
        const measured = summarizeParticipantWorkflow(concurrent, 3, false);
        expect(measured.sequentialCompletionMilliseconds).toBeNull();
        expect(measured.cohortWallMilliseconds).toBe(6);
        expect(measured.activeMilliseconds).toBe(96);
    });
    it("takes each participant's largest combined instance memory and refuses malformed memory reports", () => {
        const operations = ordinary().map((operation) => ({
            ...operation,
            memory: operation.memory ?? {
                workerBytes: operation.started,
                helperBytes: operation.position,
                arenaBytes: 1,
            },
        }));
        expect(
            summarizeParticipantWorkflow(operations, 3, true).participants.map(
                (participant) => participant.combinedWorkerHelperArenaBytes,
            ),
        ).toEqual([41, 92, 240]);
        for (const malformed of [-1, 0.5, NaN, 2 ** 53]) {
            expect(() =>
                summarizeParticipantWorkflow(
                    operations.map((operation) =>
                        operation.position === 1 &&
                        operation.operation === 'ballot'
                            ? {
                                  ...operation,
                                  memory: {
                                      ...operation.memory,
                                      helperBytes: malformed,
                                  },
                              }
                            : operation,
                    ),
                    3,
                    true,
                ),
            ).toThrow();
            expect(() =>
                summarizeParticipantWorkflow(
                    operations.map((operation) =>
                        operation.evaluationMemory === undefined
                            ? operation
                            : {
                                  ...operation,
                                  evaluationMemory: {
                                      ...operation.evaluationMemory,
                                      arenaBytes: malformed,
                                  },
                              },
                    ),
                    3,
                    true,
                ),
            ).toThrow();
        }
    });
    it('refuses an unmeasured result, missing participant work, unclassified operations and invalid intervals', () => {
        expect(() =>
            summarizeParticipantWorkflow(ordinary().slice(0, -1), 3, true),
        ).toThrow('The combined result was not measured.');
        expect(() =>
            summarizeParticipantWorkflow(
                ordinary().filter(
                    (operation) => operation.operation !== 'release',
                ),
                3,
                true,
            ),
        ).toThrow('An ordinary participant stage was not measured: release');
        expect(() =>
            summarizeParticipantWorkflow(
                [
                    ...ordinary(),
                    {
                        position: 1,
                        operation: 'status',
                        started: 160,
                        finished: 161,
                    },
                ],
                3,
                true,
            ),
        ).toThrow('Unclassified ordinary operation: status');
        expect(() =>
            summarizeParticipantWorkflow(
                [
                    ...ordinary(),
                    {
                        position: 0,
                        operation: 'result',
                        started: 200,
                        finished: NaN,
                    },
                ],
                3,
                true,
            ),
        ).toThrow();
    });
});
