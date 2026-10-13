import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

import type { WorkerResult } from '#packages/sdk/src/participant/worker/runtime/worker-messages.js';
import { compileOperationProofDraws } from '#tests/operation-seed-model.js';
import type { ActiveLocalRunLog } from '#tools/ci/local-run-log.js';
import { type Relay } from '#tools/ci/participant-browser-relay.js';
import {
    type CohortState,
    type ParticipantOperation,
    operationMilliseconds,
    cpuProfileEntries,
    requireScalarMemory,
    type InParticipantBrowser,
} from '#tools/ci/participant-cohort-state.js';
import {
    type CpuProfileSummary,
    summarizeCpuTrace,
} from '#tools/ci/participant-cpu-profile.js';
import type { ParticipantOperationMeasurement } from '#tools/ci/participant-workflow-measurements.js';

export const createParticipantRequests = async ({
    profiling,
    log,
    inBrowser,
    measureWorkflow,
    participantCount,
    measuredStages,
    browserSessions,
    ordinaryOperations,
    relay,
    transfers,
    cleanup,
    scalar,
    proofDraws,
}: Readonly<{
    profiling: boolean;
    log: ActiveLocalRunLog;
    inBrowser: InParticipantBrowser;
    measureWorkflow: CohortState['measureWorkflow'];
    participantCount: number;
    measuredStages: CohortState['measuredStages'];
    browserSessions: CohortState['browserSessions'];
    ordinaryOperations: CohortState['ordinaryOperations'];
    relay: Relay;
    transfers: CohortState['transfers'];
    cleanup: CohortState['cleanup'];
    scalar: boolean;
    proofDraws: ReturnType<typeof compileOperationProofDraws>;
}>) => {
    let nextMeasuredOperation = 0;
    // With profiling, each operation's summary of CPU samples, in
    // the order the operations ended.
    const cpuProfileDirectory = profiling
        ? path.join(log.runDirectoryPath, 'cpu-profiles')
        : undefined;
    if (cpuProfileDirectory !== undefined) await mkdir(cpuProfileDirectory);
    let profiledOperations = 0;
    const recoveryOperations = new Map<number, string>();
    // Runs one operation in a participant's page, or in a copy of its
    // private state.
    const request = async (
        position: number,
        operation: ParticipantOperation,
        parameters: Record<string, unknown> = {},
        copy?: string,
    ) =>
        inBrowser(position, copy, async (chrome) => {
            const started = performance.now();
            const measured =
                measureWorkflow &&
                copy === undefined &&
                position < participantCount
                    ? {
                          id: nextMeasuredOperation++,
                          position,
                          operation,
                          started,
                          stages: [...measuredStages[position]],
                          session: browserSessions.get(chrome)!,
                      }
                    : undefined;
            const recordAttempt = (
                outcome: ParticipantOperationMeasurement['outcome'],
                details?: Record<string, unknown>,
            ) => {
                if (measured === undefined) return;
                const resources = (details ?? {}) as Pick<
                    ParticipantOperationMeasurement,
                    'generation' | 'memory' | 'evaluationMemory'
                >;
                const entry = {
                    ...measured,
                    finished: performance.now(),
                    outcome,
                    generation: resources.generation,
                    memory: resources.memory,
                    evaluationMemory: resources.evaluationMemory,
                };
                ordinaryOperations.push(entry);
                log.writeEvent({
                    eventType: 'participant-visit-attempt',
                    details: entry,
                });
            };
            const beforeReads = new Map(relay?.reads[position]);
            const publicRecordReads = () =>
                [...(relay?.reads[position] ?? [])].flatMap(
                    ([route, value]) => {
                        const before = beforeReads.get(route);
                        const requests =
                            value.requests - (before?.requests ?? 0);
                        return requests === 0
                            ? []
                            : [
                                  {
                                      route,
                                      requests,
                                      bytes: value.bytes - (before?.bytes ?? 0),
                                  },
                              ];
                    },
                );
            const recovery =
                copy === undefined && recoveryOperations.has(position);
            const interruptedOperation = recovery
                ? recoveryOperations.get(position)
                : undefined;
            // The deadline ends with its operation so that no timer
            // outlives the run.
            const deadline = new AbortController();
            const evaluation = async () =>
                (await Promise.race([
                    chrome.evaluate(
                        `window.runParticipant(${JSON.stringify(operation)}, ${JSON.stringify(parameters)})`,
                    ),
                    delay(operationMilliseconds, undefined, {
                        signal: deadline.signal,
                    }).then(() => {
                        throw new Error('Participant operation deadline.');
                    }),
                ])) as WorkerResult;
            let result: WorkerResult;
            let cpuProfile: CpuProfileSummary | undefined;
            try {
                if (cpuProfileDirectory === undefined)
                    result = await evaluation();
                else {
                    const traced = await chrome.trace(evaluation);
                    result = traced.result;
                    cpuProfile = summarizeCpuTrace(
                        traced.events,
                        cpuProfileEntries,
                    );
                }
            } catch (error) {
                recordAttempt('interrupted');
                log.writeEvent({
                    eventType: 'participant-interrupted-operation',
                    details: {
                        position,
                        operation,
                        ...(copy === undefined ? {} : { copy }),
                        milliseconds: performance.now() - started,
                        recovery,
                        interruptedOperation,
                        originTransfer: { ...transfers[position] },
                        publicRecordReads: publicRecordReads(),
                    },
                });
                throw cleanup.guardFailure ?? error;
            } finally {
                deadline.abort();
            }
            assert.ok(result.status !== 'evaluated');
            recordAttempt(
                result.status,
                result.status === 'completed' ? result.details : undefined,
            );
            if (cleanup.guardFailure !== undefined) throw cleanup.guardFailure;
            if (scalar && result.status === 'completed')
                requireScalarMemory(result.details);
            const milliseconds = performance.now() - started;
            if (
                recovery &&
                result.status === 'completed' &&
                operation !== 'status'
            )
                recoveryOperations.delete(position);
            // A ballot or release generated in this visit drew the
            // modelled proof randomness.
            if (
                result.status === 'completed' &&
                result.details.proofRandomBytes !== undefined
            )
                assert.equal(
                    BigInt(result.details.proofRandomBytes as number),
                    operation === 'cast-ballot'
                        ? proofDraws.ballot
                        : proofDraws.release,
                    `${operation} at position ${String(position)} drew other proof randomness.`,
                );
            log.writeEvent({
                eventType: 'participant-operation',
                details: {
                    position,
                    ...(copy === undefined ? {} : { copy }),
                    operation,
                    milliseconds,
                    recovery,
                    interruptedOperation,
                    originTransfer: { ...transfers[position] },
                    publicRecordReads: publicRecordReads(),
                    result,
                },
            });
            if (cpuProfile !== undefined && cpuProfileDirectory !== undefined)
                await writeFile(
                    path.join(
                        cpuProfileDirectory,
                        `${String(++profiledOperations).padStart(4, '0')}-${String(position)}${copy === undefined ? '' : '-' + copy}-${operation}.json`,
                    ),
                    JSON.stringify(
                        {
                            position,
                            ...(copy === undefined ? {} : { copy }),
                            operation,
                            status: result.status,
                            milliseconds,
                            ...cpuProfile,
                        },
                        null,
                        2,
                    ) + '\n',
                    { flag: 'wx' },
                );
            return result;
        });
    const run = async (
        position: number,
        operation: ParticipantOperation,
        parameters: Record<string, unknown> = {},
    ) => {
        const result = await request(position, operation, parameters);
        assert.ok(
            result.status === 'completed',
            `${operation} at position ${String(position)}: ${JSON.stringify(result)}`,
        );
        return result.details;
    };
    const expectStatus = async (
        position: number,
        operation: ParticipantOperation,
        status: WorkerResult['status'],
        parameters: Record<string, unknown> = {},
    ) => {
        const result = await request(position, operation, parameters);
        assert.equal(
            result.status,
            status,
            `${operation} at position ${String(position)}: ${JSON.stringify(result)}`,
        );
    };
    return { request, recoveryOperations, run, expectStatus };
};
export type ParticipantRequests = Awaited<
    ReturnType<typeof createParticipantRequests>
>;
