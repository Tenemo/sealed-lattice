import assert from 'node:assert/strict';

export type ParticipantOperationMeasurement = Readonly<{
    position: number;
    operation: string;
    started: number;
    finished: number;
    generation?: number;
    memory?: Readonly<{
        workerBytes: number;
        helperBytes: number;
        arenaBytes: number;
    }>;
    evaluationMemory?: Readonly<{
        workerBytes: number;
        helperBytes: number;
        arenaBytes: number;
    }>;
}>;

// Charge refetches and separate API calls to the productive stage they
// serve. The organizer's proposal and target signature share a stage.
// These are accounting groups, not a measured visit partition: adjacent
// stages can coalesce when their dependencies are already available.
const stage = ({ operation, generation }: ParticipantOperationMeasurement) => {
    if (operation === 'create' || (operation === 'publish' && generation === 1))
        return 'registration';
    if (
        ['propose-roster', 'accept-roster', 'publish', 'confirm'].includes(
            operation,
        )
    )
        return 'roster and confirmation';
    if (operation === 'contribute') return 'contribution offers';
    if (operation === 'select-setup' || operation === 'endorse-setup')
        return 'setup selection';
    if (operation === 'verify-setup' || operation === 'ballot') return 'ballot';
    if (operation === 'close')
        return generation === 22 ? 'certification' : 'closing';
    if (operation === 'target') return 'certification';
    if (operation === 'release') return 'release';
    if (operation === 'result') return 'result';
    throw new Error('Unclassified ordinary operation: ' + operation);
};

export const summarizeParticipantWorkflow = (
    operations: readonly ParticipantOperationMeasurement[],
    participants: number,
    sequential: boolean,
) => {
    assert.ok(
        operations.length > 0 &&
            Number.isSafeInteger(participants) &&
            participants >= 3,
    );
    const ordered = [...operations].sort(
        (left, right) => left.started - right.started,
    );
    let lastFinished = -Infinity;
    let activeMilliseconds = 0;
    type ParticipantTotals = {
        activeMilliseconds: number;
        stages: Record<string, number>;
        combinedWorkerHelperArenaBytes: number | undefined;
    };
    const byParticipant = Array.from(
        { length: participants },
        (): ParticipantTotals => ({
            activeMilliseconds: 0,
            stages: {},
            combinedWorkerHelperArenaBytes: undefined,
        }),
    );
    for (const operation of ordered) {
        assert.ok(
            Number.isInteger(operation.position) &&
                operation.position >= 0 &&
                operation.position < participants,
        );
        assert.ok(
            Number.isFinite(operation.started) &&
                Number.isFinite(operation.finished) &&
                operation.finished >= operation.started,
        );
        if (sequential)
            assert.ok(
                operation.started >= lastFinished,
                'Participant operations overlap in a sequential run.',
            );
        lastFinished = Math.max(lastFinished, operation.finished);
        const milliseconds = operation.finished - operation.started;
        const participant = byParticipant[operation.position];
        const name = stage(operation);
        participant.stages[name] =
            (participant.stages[name] ?? 0) + milliseconds;
        participant.activeMilliseconds += milliseconds;
        activeMilliseconds += milliseconds;
        for (const memory of [operation.memory, operation.evaluationMemory]) {
            if (memory === undefined) continue;
            const values = [
                memory.workerBytes,
                memory.helperBytes,
                memory.arenaBytes,
            ];
            assert.ok(
                values.every(
                    (value) => Number.isSafeInteger(value) && value >= 0,
                ),
            );
            participant.combinedWorkerHelperArenaBytes = Math.max(
                participant.combinedWorkerHelperArenaBytes ?? 0,
                values.reduce((sum, value) => sum + value, 0),
            );
        }
    }
    for (const participant of byParticipant)
        for (const required of [
            'registration',
            'roster and confirmation',
            'ballot',
            'closing',
            'release',
        ])
            assert.ok(
                required in participant.stages,
                'An ordinary participant stage was not measured: ' + required,
            );
    assert.ok(
        operations.some((operation) => operation.operation === 'result'),
        'The combined result was not measured.',
    );
    const workflowMilliseconds = lastFinished - ordered[0].started;
    return {
        activeMilliseconds,
        cohortWallMilliseconds: workflowMilliseconds,
        sequentialCompletionMilliseconds: sequential
            ? workflowMilliseconds
            : null,
        participants: byParticipant.map((participant, position) => ({
            position,
            activeMilliseconds: participant.activeMilliseconds,
            stages: participant.stages,
            maximumStageMilliseconds: Math.max(
                ...Object.values(participant.stages),
            ),
            combinedWorkerHelperArenaBytes:
                participant.combinedWorkerHelperArenaBytes ?? null,
        })),
        scope: 'Successful ordinary operations, including the combined result. Stage totals are accounting groups, not a measured visit partition: adjacent stages can coalesce, so the maximum stage is not the maximum visit. Browser launch and human delays are not part of active operation time. Combined worker/helper/arena memory covers participant-module linear memory in the worker and its helpers plus their shared arena. Separate evaluation and continuation workers run successively, so their totals are compared rather than added. These are module high-water totals; sampled browser-process memory additionally includes JavaScript and browser allocations.',
    };
};
