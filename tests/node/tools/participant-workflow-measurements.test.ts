import { describe, expect, it } from 'vitest';

import {
    summarizeParticipantWorkflow,
    type ParticipantOperationMeasurement,
} from '#tools/ci/participant-workflow-measurements.js';

const ordinary = (recovery = false): ParticipantOperationMeasurement[] => {
    const operations: ParticipantOperationMeasurement[] = [];
    const sessions = new Map<string, number>();
    let nextSession = 0;
    let clock = 0;
    const add = (
        position: number,
        stages: number[],
        operation: string,
        generation: number,
        duration = 1,
        outcome: ParticipantOperationMeasurement['outcome'] = 'completed',
    ) => {
        const identity = position + ':' + stages[stages.length - 1];
        if (!sessions.has(identity)) sessions.set(identity, nextSession++);
        operations.push({
            id: operations.length,
            position,
            stages,
            operation,
            generation,
            started: clock,
            finished: clock + duration,
            outcome,
            session: sessions.get(identity)!,
        });
        clock += duration + 2;
    };
    for (const position of [0, 1, 2]) {
        add(position, [0], 'create', 1);
        add(position, [0], 'publish', 1);
    }
    add(0, [1], 'propose-roster', 3);
    add(0, [1], 'publish', 3);
    add(0, [1], 'confirm', 4);
    add(0, [1], 'contribute', 4);
    if (recovery) add(0, [2], 'select-setup', 4, 7, 'pending');
    for (const position of [1, 2]) {
        add(position, [1], 'accept-roster', 3);
        add(position, [1], 'confirm', 4);
        if (position === 1) {
            if (recovery) {
                add(position, [1], 'contribute', 4, 5, 'interrupted');
                sessions.set('1:1', nextSession++);
            }
            add(position, [1], 'contribute', 4);
        } else if (recovery) add(position, [1], 'contribute', 4, 3, 'refused');
    }
    add(0, [2], 'select-setup', 4);
    add(1, [2], 'endorse-setup', 4);
    add(2, [2], 'endorse-setup', 4);
    for (const position of [0, 1, 2]) {
        add(position, [3], 'verify-setup', 12);
        add(position, [3], 'ballot', 17);
    }
    add(1, [4], 'close', 17);
    add(2, [4], 'close', 17);
    add(0, [4], 'close', 19);
    add(1, [4], 'close', 21);
    add(2, [4], 'close', 21);
    add(0, [4, 5], 'close', 22, 19);
    for (const position of [0, 1, 2]) add(position, [5], 'target', 24);
    for (const position of [0, 1, 2]) add(position, [6], 'release', 29);
    for (const position of [0, 1, 2]) add(position, [7], 'result', 29);
    return operations;
};

describe('explicit participant productive-visit trace', () => {
    it('checks the actual stage path and bounds crossing close work without counting it twice cumulatively', () => {
        const operations = ordinary();
        const measured = summarizeParticipantWorkflow(operations, 3, true);
        // Thirty-nine calls: thirty-eight cost one unit, final close costs nineteen.
        expect(operations).toHaveLength(39);
        expect(measured.activeMilliseconds).toBe(57);
        expect(
            measured.participants.map(
                (participant) => participant.activeMilliseconds,
            ),
        ).toEqual([32, 13, 12]);
        expect(
            measured.participants.map(
                (participant) => participant.productiveVisits,
            ),
        ).toEqual([8, 8, 8]);
        const organizer = measured.participants[0];
        expect(organizer.visits[4].activeMillisecondsUpperBound).toBe(20);
        expect(organizer.visits[5].activeMillisecondsUpperBound).toBe(20);
        expect(organizer.maximumVisitUpperBoundMilliseconds).toBe(20);
        expect(
            organizer.visits.reduce(
                (sum, visit) => sum + visit.activeMillisecondsUpperBound,
                0,
            ),
        ).toBe(51);
        const selection = measured.operations.find(
            (operation) => operation.operation === 'select-setup',
        )!;
        expect(selection.dependencies).toContain(
            operations.find(
                (operation) =>
                    operation.position === 1 &&
                    operation.operation === 'contribute',
            )!.id,
        );
        expect(
            measured.operations.filter(
                (operation) => operation.operation === 'result',
            ),
        ).toHaveLength(3);
    });
    it('charges pending and interrupted work to the original stages across browser sessions', () => {
        const measured = summarizeParticipantWorkflow(ordinary(true), 3, true);
        expect(measured.activeMilliseconds).toBe(72);
        expect(
            measured.participants[0].visits[2].activeMillisecondsUpperBound,
        ).toBe(8);
        expect(
            measured.participants[1].visits[1].activeMillisecondsUpperBound,
        ).toBe(8);
        expect(measured.participants[1].visits[1].sessions).toHaveLength(2);
        expect(
            measured.participants[2].visits[1].activeMillisecondsUpperBound,
        ).toBe(5);
        expect(
            measured.participants.map(
                (participant) => participant.productiveVisits,
            ),
        ).toEqual([8, 8, 8]);
    });
    it('does not infer preparation stages from their shared generation or generic publish operation', () => {
        const operations = ordinary();
        const wrong = operations.map((operation) =>
            operation.operation === 'contribute'
                ? { ...operation, stages: [2] }
                : operation,
        );
        expect(() => summarizeParticipantWorkflow(wrong, 3, true)).toThrow(
            'explicit stage',
        );
        const missing = operations.filter(
            (operation) =>
                !(
                    operation.position === 0 &&
                    operation.operation === 'publish' &&
                    operation.generation === 3
                ),
        );
        expect(() => summarizeParticipantWorkflow(missing, 3, true)).toThrow(
            'roster',
        );
    });
    it('refuses missing peer-message frontiers and a participant whose target or outcome was omitted', () => {
        for (const predicate of [
            (operation: ParticipantOperationMeasurement) =>
                operation.operation === 'endorse-setup' &&
                operation.position === 2,
            (operation: ParticipantOperationMeasurement) =>
                operation.operation === 'target' && operation.position === 2,
            (operation: ParticipantOperationMeasurement) =>
                operation.operation === 'result' && operation.position === 1,
        ])
            expect(() =>
                summarizeParticipantWorkflow(
                    ordinary().filter((operation) => !predicate(operation)),
                    3,
                    true,
                ),
            ).toThrow();
        const noOffer = ordinary().map((operation) =>
            operation.operation === 'contribute' && operation.position === 1
                ? { ...operation, outcome: 'pending' as const }
                : operation,
        );
        expect(() => summarizeParticipantWorkflow(noOffer, 3, true)).toThrow(
            'Incomplete message frontier: offer',
        );
    });
    it('keeps status work in its current stage without creating a visit or a message frontier', () => {
        const operations = ordinary();
        const final = operations[operations.length - 1];
        operations.push({
            ...final,
            id: operations.length,
            operation: 'status',
            started: final.finished + 1,
            finished: final.finished + 4,
        });
        const measured = summarizeParticipantWorkflow(operations, 3, true);
        expect(measured.activeMilliseconds).toBe(60);
        expect(measured.participants[2].productiveVisits).toBe(8);
        expect(
            measured.operations[measured.operations.length - 1].dependencies,
        ).toEqual([]);
    });
    it('preserves instance-memory accounting and rejects overlap, ambiguous sessions and malformed measurements', () => {
        const operations = ordinary();
        const final = operations[operations.length - 1];
        operations[operations.length - 1] = {
            ...final,
            memory: { workerBytes: 100, helperBytes: 70, arenaBytes: 30 },
            evaluationMemory: {
                workerBytes: 120,
                helperBytes: 80,
                arenaBytes: 40,
            },
        };
        expect(
            summarizeParticipantWorkflow(operations, 3, true).participants[2]
                .combinedWorkerHelperArenaBytes,
        ).toBe(240);
        expect(
            summarizeParticipantWorkflow(operations, 3, false)
                .sequentialCompletionMilliseconds,
        ).toBeNull();
        for (const invalid of [
            { ...final, id: operations[0].id },
            { ...final, session: operations[0].session },
            { ...final, started: 0 },
            { ...final, finished: NaN },
            {
                ...final,
                memory: { workerBytes: -1, helperBytes: 0, arenaBytes: 0 },
            },
            { ...final, stages: [6, 7] },
        ])
            expect(() =>
                summarizeParticipantWorkflow(
                    [...operations.slice(0, -1), invalid],
                    3,
                    true,
                ),
            ).toThrow();
    });
});
