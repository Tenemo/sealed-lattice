import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { parseArgs } from 'node:util';

import { repositoryRoot, toolArguments } from '#tools/ci/command-line.js';
import {
    readEvidenceRenewalRecord,
    stepPassed,
} from '#tools/ci/evidence-renewal-record.js';
import { runWithLocalRunLog } from '#tools/ci/local-run-log.js';
import {
    participantOperationEvents,
    readRunEvents,
    readRunJson,
    type ParticipantRunResult,
    type ParticipantTransferTotals,
    type RunSummary,
} from '#tools/ci/participant-run-files.js';

// Projects a renewal's ordinary ten-participant, ten-option sequential scalar
// workflow from this host to a slower device: the largest uniform slowdown
// each completion limit tolerates at several goodputs.
const usage =
    'Usage: project-participant-phone-time.ts --renewal=<renewal run directory or record file>';

// The owner's completion limits for the qualification tuple.
const limits = {
    visitSeconds: 15 * 60,
    participantSeconds: 30 * 60,
    sequentialSeconds: 5 * 60 * 60,
};
// Application-payload goodputs in decimal megabits per second.
const goodputs = [20, 50, 100, 200];
const round = (value: number) => Math.round(value * 100) / 100;

export const payloadSeconds = (bytes: number, megabits: number) =>
    (bytes * 8) / (megabits * 1e6);

// Additive: the device spends the slowdown times this host's bound and then
// moves the payload. Overlap: transfer hides entirely behind the work.
export const tolerableSlowdown = (
    seconds: number,
    bytes: number,
    limit: number,
    megabits: number,
) => ({
    additive: round((limit - payloadSeconds(bytes, megabits)) / seconds),
    overlap:
        payloadSeconds(bytes, megabits) > limit ? 0 : round(limit / seconds),
});

// The row that binds first under the additive model, with the smallest
// overlap tolerance over all rows.
export const bindingSlowdown = <Row>(
    rows: readonly Row[],
    seconds: (row: Row) => number,
    bytes: (row: Row) => number,
    limit: number,
    megabits: number,
) => {
    assert.ok(rows.length > 0, 'A projection needs at least one row.');
    const ranked = rows
        .map((row) => ({
            row,
            ...tolerableSlowdown(seconds(row), bytes(row), limit, megabits),
        }))
        .sort((left, right) => left.additive - right.additive);
    return {
        additive: ranked[0].additive,
        overlap: Math.min(...ranked.map((entry) => entry.overlap)),
        row: ranked[0].row,
    };
};

const digest = async (file: string) =>
    createHash('sha512')
        .update(await readFile(file))
        .digest('hex');

const main = async (): Promise<void> => {
    const commandLineArguments = process.argv.slice(2);
    const { values } = parseArgs({
        args: [...toolArguments(commandLineArguments)],
        options: { renewal: { type: 'string' } },
        strict: true,
    });
    if (values.renewal === undefined) throw new Error(usage);
    const renewal = path.resolve(values.renewal);
    await runWithLocalRunLog(
        {
            commandLineArguments,
            scriptName: 'project-phone-time',
        },
        async (log) => {
            const record = (await readEvidenceRenewalRecord(renewal)).get(
                'ordinary',
            );
            assert.ok(
                record !== undefined &&
                    stepPassed(record) &&
                    record.run !== undefined,
                'The renewal records no passed ordinary run.',
            );
            const run = record.run;
            const runDirectoryPath = path.join(repositoryRoot, run);
            const summary = await readRunJson<RunSummary>(
                runDirectoryPath,
                'summary.json',
            );
            const result = await readRunJson<ParticipantRunResult>(
                runDirectoryPath,
                'result.json',
            );
            const workflow = result.workflow;
            assert.equal(summary.result, 'passed');
            assert.ok(workflow !== undefined, 'The run reports no workflow.');
            assert.equal(result.participantCount, 10);
            assert.equal(result.optionCount, 10);
            assert.equal(result.topCount, 10);
            assert.equal(result.scalar, true);
            assert.equal(result.sequential, true);
            assert.equal(result.recovery, false);
            assert.equal((result.interruptions ?? []).length, 0);
            const positions = Array.from(
                { length: result.participantCount },
                (_unused, position) => position,
            );
            const operationEvents = participantOperationEvents(
                await readRunEvents(runDirectoryPath),
            );
            const operations = workflow.operations;
            assert.equal(operationEvents.length, operations.length);
            // Operation events follow the report's operation order; each
            // carries its participant's cumulative origin counters after it
            // ended.
            const cumulative = new Map<number, ParticipantTransferTotals>();
            for (const [index, operation] of operations.entries()) {
                const event = operationEvents[index];
                assert.equal(event.position, operation.position);
                assert.equal(event.operation, operation.operation);
                assert.ok(
                    Math.abs(
                        operation.finished -
                            operation.started -
                            event.milliseconds,
                    ) < 50,
                );
                assert.equal(event.originTransfer.incompleteExchanges, 0);
                assert.equal(event.originTransfer.unknownRequestLengths, 0);
                if (operation.memory !== undefined)
                    assert.equal(operation.memory.helpers, 0);
                cumulative.set(operation.id, event.originTransfer);
            }
            const payload = new Map<number, number>();
            for (const position of positions) {
                const own = operations
                    .filter((operation) => operation.position === position)
                    .sort((left, right) => left.finished - right.finished);
                let previous = { receivedPayloadBytes: 0, sentPayloadBytes: 0 };
                for (const operation of own) {
                    const current = cumulative.get(operation.id);
                    assert.ok(current !== undefined);
                    const received =
                        current.receivedPayloadBytes -
                        previous.receivedPayloadBytes;
                    const sent =
                        current.sentPayloadBytes - previous.sentPayloadBytes;
                    assert.ok(received >= 0 && sent >= 0);
                    payload.set(operation.id, received + sent);
                    previous = current;
                }
                const counter = result.transfers[position];
                assert.equal(
                    previous.receivedPayloadBytes + previous.sentPayloadBytes,
                    counter.receivedPayloadBytes + counter.sentPayloadBytes,
                );
            }
            const participants = workflow.participants;
            assert.deepEqual(
                participants.map((participant) => participant.position),
                positions,
            );
            const operationName = (identifier: number) => {
                const operation = operations.find(
                    (candidate) => candidate.id === identifier,
                );
                assert.ok(operation !== undefined);
                return operation.operation;
            };
            const operationPayload = (identifier: number) => {
                const bytes = payload.get(identifier);
                assert.ok(bytes !== undefined);
                return bytes;
            };
            const visits = participants.flatMap((participant) =>
                participant.visits.map((visit) => ({
                    position: participant.position,
                    stage: visit.stage,
                    operations: visit.operationIds.map(operationName),
                    activeSecondsUpperBound:
                        visit.activeMillisecondsUpperBound / 1000,
                    // An operation charged to two adjacent visit bounds is
                    // charged to both visits' payloads as well.
                    payloadBytes: visit.operationIds.reduce(
                        (sum, identifier) => sum + operationPayload(identifier),
                        0,
                    ),
                })),
            );
            const participantRows = participants.map((participant) => {
                const counter = result.transfers[participant.position];
                return {
                    position: participant.position,
                    productiveVisits: participant.productiveVisits,
                    activeSecondsUpperBound:
                        participant.activeMillisecondsUpperBound / 1000,
                    payloadBytes:
                        counter.receivedPayloadBytes + counter.sentPayloadBytes,
                };
            });
            const sequential = {
                completionSeconds:
                    workflow.sequentialCompletionMilliseconds / 1000,
                activeSecondsUpperBound:
                    workflow.activeMillisecondsUpperBound / 1000,
                payloadBytes: participantRows.reduce(
                    (sum, row) => sum + row.payloadBytes,
                    0,
                ),
            };
            assert.ok(
                sequential.completionSeconds >=
                    sequential.activeSecondsUpperBound,
            );
            const projection = goodputs.map((megabits) => {
                const visit = bindingSlowdown(
                    visits,
                    (row) => row.activeSecondsUpperBound,
                    (row) => row.payloadBytes,
                    limits.visitSeconds,
                    megabits,
                );
                const participant = bindingSlowdown(
                    participantRows,
                    (row) => row.activeSecondsUpperBound,
                    (row) => row.payloadBytes,
                    limits.participantSeconds,
                    megabits,
                );
                return {
                    goodputMegabitsPerSecond: megabits,
                    tolerableSlowdown: {
                        visit: {
                            ...visit,
                            row: {
                                position: visit.row.position,
                                stage: visit.row.stage,
                            },
                        },
                        participant: {
                            ...participant,
                            row: { position: participant.row.position },
                        },
                        sequential: tolerableSlowdown(
                            sequential.completionSeconds,
                            sequential.payloadBytes,
                            limits.sequentialSeconds,
                            megabits,
                        ),
                    },
                    payloadMinutes: {
                        heaviestParticipant: round(
                            Math.max(
                                ...participantRows.map((row) =>
                                    payloadSeconds(row.payloadBytes, megabits),
                                ),
                            ) / 60,
                        ),
                        sequential: round(
                            payloadSeconds(sequential.payloadBytes, megabits) /
                                60,
                        ),
                    },
                };
            });
            await writeFile(
                path.join(log.runDirectoryPath, 'evidence.json'),
                JSON.stringify(
                    {
                        run,
                        inputs: {
                            'result.json': await digest(
                                path.join(runDirectoryPath, 'result.json'),
                            ),
                            'events.jsonl': await digest(
                                path.join(runDirectoryPath, 'events.jsonl'),
                            ),
                        },
                        runtimeIdentity: result.runtimeIdentity,
                        host: {
                            processor: os.cpus()[0]?.model.trim(),
                            logicalProcessors: os.cpus().length,
                        },
                        placement: record.placement ?? null,
                        limits,
                        sequential,
                        participants: participantRows,
                        visits,
                        projection,
                    },
                    null,
                    2,
                ) + '\n',
                { flag: 'wx' },
            );
            for (const row of projection)
                process.stdout.write(JSON.stringify(row) + '\n');
            process.stdout.write(log.runDirectoryPath + '\n');
        },
    );
};

if (import.meta.main) await main();
