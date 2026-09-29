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
        operation: 'archive',
        started: 150,
        finished: 158,
        memory: { workerBytes: 100, helperBytes: 70, arenaBytes: 30 },
        evaluationMemory: { workerBytes: 120, helperBytes: 80, arenaBytes: 40 },
    });
    return operations;
};

describe('complete participant workflow measurements', () => {
    it('charges archiving and combined instance memory, and distinguishes wall time from active work', () => {
        const measured = summarizeParticipantWorkflow(ordinary(), 3, true);
        expect(measured.activeMilliseconds).toBe(98);
        expect(measured.sequentialCompletionMilliseconds).toBe(158);
        expect(
            measured.participants.map(
                (participant) => participant.activeMilliseconds,
            ),
        ).toEqual([30, 30, 38]);
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
    it('includes archive memory within each worker lifetime and leaves incomplete historical totals unknown', () => {
        const operations = ordinary().map((operation) => ({
            ...operation,
            memory: {
                workerBytes: 10,
                helperBytes: 1,
                arenaBytes: 1,
                ...operation.memory,
                archiveBytes: operation.operation === 'archive' ? 80 : 0,
            },
            ...(operation.evaluationMemory === undefined
                ? {}
                : {
                      evaluationMemory: {
                          ...operation.evaluationMemory,
                          archiveBytes: 12,
                      },
                  }),
        }));
        const measured = summarizeParticipantWorkflow(operations, 3, true);
        expect(
            measured.participants.map(
                (participant) => participant.completeKernelHelperArenaBytes,
            ),
        ).toEqual([12, 12, 280]);
        expect(measured.participants[2].combinedWorkerHelperArenaBytes).toBe(
            240,
        );
        expect(
            summarizeParticipantWorkflow(ordinary(), 3, true).participants[2]
                .completeKernelHelperArenaBytes,
        ).toBeNull();
        expect(() =>
            summarizeParticipantWorkflow(
                operations.map((operation) => ({
                    ...operation,
                    memory: { ...operation.memory, archiveBytes: -1 },
                })),
                3,
                true,
            ),
        ).toThrow();
    });
    it('refuses omitted archiving, missing participant work and invalid intervals', () => {
        expect(() =>
            summarizeParticipantWorkflow(ordinary().slice(0, -1), 3, true),
        ).toThrow('archiving');
        expect(() =>
            summarizeParticipantWorkflow(
                ordinary().filter(
                    (operation) => operation.operation !== 'release',
                ),
                3,
                true,
            ),
        ).toThrow('not measured');
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
