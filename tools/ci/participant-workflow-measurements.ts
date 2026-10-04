import assert from 'node:assert/strict';

import { preparationStagePath } from '#tests/setup-selection-model.js';
import { compileThresholdCompletionProfile } from '#tests/threshold-completion-model.js';

export type ParticipantOperationMeasurement = Readonly<{
    id: number;
    position: number;
    operation: string;
    session: number;
    stages: readonly number[];
    outcome: 'completed' | 'pending' | 'refused' | 'stopped' | 'interrupted';
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

// This is a trace of an ordinary clear-certified schedule, not protocol
// authority. Every dependency below names a completed SDK invocation; the
// owning runtime still verifies all actual bytes and signatures itself.
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
    const thresholds = compileThresholdCompletionProfile(participants);
    const paths = Array.from({ length: participants }, (_, position) =>
        preparationStagePath('clear-certified', position === 0),
    );
    const ordered = [...operations].sort(
        (left, right) => left.started - right.started,
    );
    const identifiers = new Set<number>();
    const sessions = new Map<number, number>();
    const published = new Map<string, ParticipantOperationMeasurement>();
    const latest = new Array<number>(participants).fill(-Infinity);
    const finishedStages = Array.from(
        { length: participants },
        () => new Set<number>(),
    );
    const byParticipant = paths.map((path) => ({
        activeMilliseconds: 0,
        attempts: 0,
        combinedWorkerHelperArenaBytes: undefined as number | undefined,
        visits: path.map((stage) => ({
            stage: stage.name,
            operationIds: [] as number[],
            sessions: new Set<number>(),
            activeMillisecondsUpperBound: 0,
        })),
    }));
    const allowed = [
        ['create', 'publish'],
        ['propose-roster', 'accept-roster', 'publish', 'confirm', 'contribute'],
        ['select-setup', 'endorse-setup'],
        ['verify-setup', 'ballot'],
        ['close'],
        ['close', 'target'],
        ['release'],
        ['result'],
    ];
    const traced = [];
    let lastFinished = -Infinity;
    let activeMilliseconds = 0;
    const key = (kind: string, position: number) => kind + ':' + position;
    for (const operation of ordered) {
        const { position, stages, outcome } = operation;
        assert.ok(
            Number.isInteger(operation.id) &&
                operation.id >= 0 &&
                !identifiers.has(operation.id),
            'Duplicate or invalid operation identity.',
        );
        identifiers.add(operation.id);
        assert.ok(
            Number.isInteger(position) &&
                position >= 0 &&
                position < participants,
        );
        assert.ok(
            Number.isInteger(operation.session) && operation.session >= 0,
        );
        assert.ok(
            !sessions.has(operation.session) ||
                sessions.get(operation.session) === position,
            'A browser session changed original participant.',
        );
        sessions.set(operation.session, position);
        assert.ok(
            Number.isFinite(operation.started) &&
                Number.isFinite(operation.finished) &&
                operation.finished >= operation.started,
        );
        assert.ok(
            operation.started >= latest[position],
            'One participant has overlapping operations.',
        );
        if (sequential)
            assert.ok(
                operation.started >= lastFinished,
                'Participant operations overlap in a sequential run.',
            );
        latest[position] = operation.finished;
        lastFinished = Math.max(lastFinished, operation.finished);
        assert.ok(
            [
                'completed',
                'pending',
                'refused',
                'stopped',
                'interrupted',
            ].includes(outcome),
        );
        const crossing =
            position === 0 &&
            operation.operation === 'close' &&
            stages.length === 2 &&
            stages[0] === 4 &&
            stages[1] === 5;
        assert.ok(
            stages.length === 1 || crossing,
            'Only organizer close may span adjacent measured stages.',
        );
        for (const stage of stages) {
            assert.ok(
                Number.isInteger(stage) &&
                    stage >= 0 &&
                    stage < paths[position].length,
            );
            assert.ok(
                operation.operation === 'status' ||
                    allowed[stage].includes(operation.operation),
                'Operation does not belong to its explicit stage.',
            );
            for (let prior = 0; prior < stage; prior++)
                assert.ok(
                    finishedStages[position].has(prior) ||
                        (crossing && prior === 4),
                    'A participant skipped an unfinished stage.',
                );
            assert.ok(
                !finishedStages[position].has(stage + 1),
                'An ordinary participant returned to an earlier stage.',
            );
        }
        const dependencies: number[] = [];
        const requireEvent = (name: string) => {
            const predecessor = published.get(name);
            assert.ok(
                predecessor && predecessor.finished <= operation.started,
                'Missing completed message frontier: ' + name,
            );
            dependencies.push(predecessor.id);
        };
        const requireCount = (kind: string, count: number, omit?: number) => {
            const ready = [...published].filter(
                ([name, producer]) =>
                    name.startsWith(kind + ':') &&
                    producer.position !== omit &&
                    producer.finished <= operation.started,
            );
            assert.ok(
                ready.length >= count,
                'Incomplete message frontier: ' + kind,
            );
            for (const [, producer] of ready) dependencies.push(producer.id);
        };
        const mark = (name: string) => published.set(name, operation);
        const stage = stages[stages.length - 1];
        if (outcome === 'completed' && operation.operation !== 'status') {
            switch (operation.operation) {
                case 'create':
                    assert.equal(stage, 0);
                    if (position !== 0) requireEvent(key('registration', 0));
                    mark(key('created', position));
                    break;
                case 'publish':
                    if (stage === 0) {
                        requireEvent(key('created', position));
                        mark(key('registration', position));
                        finishedStages[position].add(0);
                    } else {
                        assert.equal(position, 0);
                        requireEvent('proposed-roster');
                        mark('roster');
                    }
                    break;
                case 'propose-roster':
                    assert.equal(position, 0);
                    requireCount('registration', participants);
                    mark('proposed-roster');
                    break;
                case 'accept-roster':
                    assert.notEqual(position, 0);
                    requireEvent('roster');
                    mark(key('accepted-roster', position));
                    break;
                case 'confirm':
                    requireEvent(
                        position === 0
                            ? 'roster'
                            : key('accepted-roster', position),
                    );
                    mark(key('confirmed', position));
                    finishedStages[position].add(1);
                    break;
                case 'contribute':
                    requireEvent(key('confirmed', position));
                    mark(key('offer', position));
                    break;
                case 'select-setup':
                    assert.equal(position, 0);
                    requireEvent(key('confirmed', position));
                    requireCount('offer', thresholds.resultReleaseThreshold);
                    mark('selection');
                    // select-setup performs proposal readback and endorsement
                    // inside the same maintained worker invocation.
                    mark(key('endorsement', position));
                    finishedStages[position].add(2);
                    break;
                case 'endorse-setup':
                    requireEvent(key('confirmed', position));
                    requireEvent('selection');
                    mark(key('endorsement', position));
                    finishedStages[position].add(2);
                    break;
                case 'verify-setup':
                    requireCount(
                        'endorsement',
                        thresholds.inventoryCertificateThreshold,
                    );
                    assert.equal(operation.generation, 12);
                    mark(key('setup', position));
                    break;
                case 'ballot':
                    requireEvent(key('setup', position));
                    assert.equal(operation.generation, 17);
                    mark(key('ballot', position));
                    finishedStages[position].add(3);
                    break;
                case 'close':
                    requireCount('ballot', participants);
                    if (crossing) {
                        requireEvent('close-intent');
                        requireCount(
                            'response',
                            thresholds.inventoryCertificateThreshold - 1,
                            0,
                        );
                        assert.equal(operation.generation, 22);
                        mark('close-proposal');
                        finishedStages[position].add(4);
                    } else if (position === 0 && operation.generation === 19) {
                        mark('close-intent');
                    } else if (position !== 0 && operation.generation === 21) {
                        requireEvent('close-intent');
                        mark(key('response', position));
                        finishedStages[position].add(4);
                    } else
                        assert.equal(
                            operation.generation,
                            17,
                            'Unexpected ordinary close progress.',
                        );
                    break;
                case 'target':
                    requireEvent('close-proposal');
                    assert.equal(operation.generation, 24);
                    mark(key('target', position));
                    finishedStages[position].add(5);
                    break;
                case 'release':
                    requireCount(
                        'target',
                        thresholds.inventoryCertificateThreshold,
                    );
                    requireEvent(key('target', position));
                    assert.equal(operation.generation, 29);
                    mark(key('release', position));
                    finishedStages[position].add(6);
                    break;
                case 'result':
                    requireCount('release', thresholds.resultReleaseThreshold);
                    requireEvent(key('release', position));
                    finishedStages[position].add(7);
                    break;
            }
        }
        const milliseconds = operation.finished - operation.started;
        const participant = byParticipant[position];
        participant.attempts++;
        participant.activeMilliseconds += milliseconds;
        activeMilliseconds += milliseconds;
        for (const index of stages) {
            const visit = participant.visits[index];
            visit.operationIds.push(operation.id);
            visit.sessions.add(operation.session);
            visit.activeMillisecondsUpperBound += milliseconds;
        }
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
        traced.push({ ...operation, dependencies: [...new Set(dependencies)] });
    }
    for (const [position, stages] of finishedStages.entries())
        assert.equal(
            stages.size,
            paths[position].length,
            'An ordinary participant did not complete every measured stage.',
        );
    const workflowMilliseconds = lastFinished - ordered[0].started;
    return {
        schema: 'explicit-clear-stage-trace/1',
        activeMilliseconds,
        cohortWallMilliseconds: workflowMilliseconds,
        sequentialCompletionMilliseconds: sequential
            ? workflowMilliseconds
            : null,
        operations: traced,
        participants: byParticipant.map((participant, position) => ({
            position,
            activeMilliseconds: participant.activeMilliseconds,
            attempts: participant.attempts,
            productiveVisits: participant.visits.length,
            browserSessions: new Set(
                participant.visits.flatMap((visit) => [...visit.sessions]),
            ).size,
            visits: participant.visits.map((visit) => ({
                ...visit,
                sessions: [...visit.sessions],
            })),
            maximumVisitUpperBoundMilliseconds: Math.max(
                ...participant.visits.map(
                    (visit) => visit.activeMillisecondsUpperBound,
                ),
            ),
            combinedWorkerHelperArenaBytes:
                participant.combinedWorkerHelperArenaBytes ?? null,
        })),
        scope: 'Explicit ordinary clear-certified stage traversal with completed SDK-message frontiers. Every attempted invocation, including pending, refusal and interrupted work, is counted once in active totals. Browser sessions and productive stages are separate. The organizer close invocation spanning response collection and proposal is charged in full to both adjacent visit upper bounds, never twice to cumulative totals; these are conservative per-visit bounds, not exact within-call partitions or a minimum visit claim. Browser launch, queueing and human delays are outside invocation active time. Module memory totals compare successive evaluation/continuation workers rather than adding them; sampled browser-process memory includes additional allocations. These diagnostics create no protocol authority.',
    };
};
