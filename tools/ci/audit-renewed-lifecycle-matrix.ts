import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { readdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { parseArgs } from 'node:util';

import { thresholdProfileFor } from '#tests/threshold-completion-model.js';
import { participantRuntimeIdentity } from '#tools/ci/build-participant-module.js';
import { repositoryRoot, toolArguments } from '#tools/ci/command-line.js';
import {
    readEvidenceRenewalRecord,
    stepPassed,
    type EvidenceRenewalStepRecord,
} from '#tools/ci/evidence-renewal-record.js';
import {
    evidenceRenewalSteps,
    lifecycleMatrixStepNames,
    stepScriptArguments,
} from '#tools/ci/evidence-renewal-steps.js';
import {
    runArtifactDirectoryPath,
    runWithLocalRunLog,
} from '#tools/ci/local-run-log.js';
import { readParticipantArtifactResources } from '#tools/ci/participant-artifact-resources.js';
import {
    participantOperationEvents,
    readRunEvents,
    readRunJson,
    type ParticipantRunResult,
    type RunEvent,
    type RunMetadata,
    type RunSummary,
} from '#tools/ci/participant-run-files.js';

// Verifies that every lifecycle case, the paired completion-profile workloads
// and the largest departure cohort of a renewal passed on the renewed
// checkout's runtime with its exact compiled sources, and binds the desktop
// check that passed on that checkout.
const usage =
    'Usage: audit-renewed-lifecycle-matrix.ts --renewal=<renewal run directory or record file> --checkout=<renewed checkout>';

const digest = (bytes: Uint8Array) =>
    createHash('sha512').update(bytes).digest('hex');
const maximum = (values: readonly number[]) => {
    assert.ok(
        values.length > 0 &&
            values.every((value) => Number.isFinite(value) && value >= 0),
    );
    return Math.max(...values);
};
const completionPositions = Array.from(
    { length: 10 },
    (_unused, position) => position,
);

type ActionReceipt = {
    position: number;
    operation: string;
    receivedPayloadBytes: number;
};

// Each operation event carries its origin's cumulative counters when the
// operation ended, so consecutive differences charge every request between
// two operations, page and module bootstrap included, to the later one.
// Summing all invocations of one operation name per participant charges the
// organizer's two publications and both close invocations as one action,
// which can only overstate an action.
export const receivedByAction = (
    events: readonly RunEvent[],
): readonly ActionReceipt[] => {
    const previous = new Map<number, number>();
    const actions = new Map<string, ActionReceipt>();
    for (const {
        position,
        operation,
        originTransfer,
    } of participantOperationEvents(events)) {
        const received = originTransfer.receivedPayloadBytes;
        const delta = received - (previous.get(position) ?? 0);
        assert.ok(
            Number.isSafeInteger(delta) && delta >= 0,
            `Participant ${String(position)}'s received counter decreased.`,
        );
        previous.set(position, received);
        const key = `${String(position)}:${operation}`;
        const action = actions.get(key) ?? {
            position,
            operation,
            receivedPayloadBytes: 0,
        };
        action.receivedPayloadBytes += delta;
        actions.set(key, action);
    }
    return [...actions.values()].sort(
        (left, right) => right.receivedPayloadBytes - left.receivedPayloadBytes,
    );
};

type FileAllocationSummary = Readonly<{
    directories: Readonly<
        Record<string, Readonly<{ peakAllocatedBytes: number }>>
    >;
}>;

const completionMeasurements = async (
    runDirectoryPath: string,
    result: ParticipantRunResult,
    events: readonly RunEvent[],
    recovery: boolean,
) => {
    const allocation = await readRunJson<FileAllocationSummary>(
        runDirectoryPath,
        'file-allocation-summary.json',
    );
    const workflow = result.workflow;
    assert.ok(workflow !== undefined, 'The run reports no workflow.');
    const participants = workflow.participants;
    assert.deepEqual(
        participants
            .map((participant) => participant.position)
            .sort((left, right) => left - right),
        completionPositions,
    );
    for (const position of completionPositions)
        for (const operation of ['sign-target', 'release', 'compute-result'])
            assert.ok(
                workflow.operations.some(
                    (entry) =>
                        entry.position === position &&
                        entry.operation === operation &&
                        entry.outcome === 'completed',
                ),
                `Participant ${String(position)} did not complete ${operation}.`,
            );
    for (const operation of workflow.operations)
        if (operation.memory !== undefined)
            assert.equal(operation.memory.helpers, 0);
    let retired: readonly number[] = [];
    const interruptions = result.interruptions ?? [];
    if (recovery) {
        assert.deepEqual(
            interruptions.map((entry) => [entry.position, entry.operation]),
            [
                [0, 'contribute'],
                [0, 'cast-ballot'],
                [0, 'sign-target'],
                [0, 'release'],
            ],
        );
        assert.equal(result.independentOutcome?.details?.memory?.helpers, 0);
        const readers = events.filter(
            (event) =>
                event.eventType === 'participant-recovery-public-outcome',
        );
        assert.equal(readers.length, 1);
        const reader = readers[0].details as Readonly<{
            independentOutcome: Readonly<{ status: string }>;
            retiredOriginalParticipants: readonly number[];
        }>;
        retired = reader.retiredOriginalParticipants;
        assert.deepEqual(
            [...retired].sort((left, right) => left - right),
            completionPositions,
        );
        assert.equal(reader.independentOutcome.status, 'completed');
    } else assert.equal(interruptions.length, 0);
    const transfer = result.transfers.slice(0, 10);
    assert.equal(transfer.length, 10);
    assert.ok(
        transfer.every(
            (entry) =>
                entry.incompleteExchanges === 0 &&
                entry.unknownRequestLengths === 0,
        ),
    );
    const originalActions = receivedByAction(events).filter(
        (action) => action.position < 10,
    );
    // Requests after a participant's last operation are absent from its
    // receipts, so the receipts never exceed the run's transfer totals.
    for (const position of completionPositions) {
        const charged = originalActions
            .filter((action) => action.position === position)
            .reduce((sum, action) => sum + action.receivedPayloadBytes, 0);
        assert.ok(charged <= transfer[position].receivedPayloadBytes);
    }
    const physicalProfiles = Object.entries(allocation.directories)
        .filter(([name]) => /^participant-[0-9]$/u.test(name))
        .map(([, value]) => value);
    assert.equal(physicalProfiles.length, 10);
    const sampledResources = (result.sampledResources ?? []).slice(0, 10);
    const measurements = {
        sequentialCompletionMilliseconds:
            workflow.sequentialCompletionMilliseconds,
        maximumParticipantActiveUpperBoundMilliseconds: maximum(
            participants.map((entry) => entry.activeMillisecondsUpperBound),
        ),
        maximumVisitActiveUpperBoundMilliseconds: maximum(
            participants.map(
                (entry) => entry.maximumVisitUpperBoundMilliseconds,
            ),
        ),
        productiveVisits: participants.map((entry) => entry.productiveVisits),
        maximumReportedWorkerBytes: maximum(
            participants.map((entry) => entry.combinedWorkerHelperArenaBytes),
        ),
        largestActionReceipts: originalActions.slice(0, 3),
        maximumCumulativeReceivedPayloadBytes: maximum(
            transfer.map((entry) => entry.receivedPayloadBytes),
        ),
        maximumSentPayloadBytes: maximum(
            transfer.map((entry) => entry.sentPayloadBytes),
        ),
        totalSentPayloadBytes: transfer.reduce(
            (sum, entry) => sum + entry.sentPayloadBytes,
            0,
        ),
        maximumSampledOriginStorageBytes: maximum(
            sampledResources.map((entry) => entry.originStorageBytes),
        ),
        maximumObservedProfileAllocatedBytes: maximum(
            physicalProfiles.map((entry) => entry.peakAllocatedBytes),
        ),
        observedTransportAllocatedBytes:
            allocation.directories['public transport'].peakAllocatedBytes,
        sampledParticipantResources: sampledResources,
        standaloneMilliseconds: result.standaloneMilliseconds ?? null,
    };
    return { measurements, retired };
};

// The outcome each named lifecycle case must show. The run's arguments are
// already its step's, so the values they or the harness's own literals fix
// are not checked again.
const auditCase = async (
    name: string,
    runDirectoryPath: string,
    result: ParticipantRunResult,
    events: readonly RunEvent[],
) => {
    const interruptions = result.interruptions ?? [];
    const stateLosses = result.stateLosses ?? [];
    switch (name) {
        case 'result':
        case 'combined':
            assert.equal(result.result?.kind, 'result');
            assert.ok(interruptions.length > 0 && stateLosses.length > 0);
            return undefined;
        case 'no-result':
        case 'empty':
            assert.equal(result.result?.kind, 'no-result');
            assert.ok(interruptions.length > 0 && stateLosses.length > 0);
            if (name === 'empty')
                assert.equal(
                    participantOperationEvents(events).filter(
                        (event) =>
                            event.operation === 'cast-ballot' &&
                            event.result?.status === 'completed',
                    ).length,
                    0,
                );
            return undefined;
        case 'rosters':
            assert.notDeepEqual(result.results?.first, result.results?.second);
            for (const origin of [1, 4])
                for (const family of [
                    'registrations',
                    'target votes',
                    'release shares',
                ])
                    assert.ok(
                        (result.crossRosterProbes ?? []).some(
                            (probe) =>
                                probe.origin === origin &&
                                probe.family === family &&
                                probe.served > 0 &&
                                typeof probe.detail === 'string',
                        ),
                        `Origin ${String(origin)} refused no cross-roster ${family}.`,
                    );
            return undefined;
        case 'departure':
        case 'unselected':
        case 'selection':
            assert.equal(result.independentOutcome?.status, 'completed');
            return undefined;
        case 'publication':
            assert.ok(
                result.publicationFaultEvidence !== undefined &&
                    result.publicationRecoveryEvidence !== undefined &&
                    result.incompleteResponseEvidence !== undefined,
            );
            assert.equal(result.independentOutcome?.status, 'completed');
            return undefined;
        case 'preparation':
            assert.ok(interruptions.length > 0 && stateLosses.length > 0);
            assert.ok(
                result.sourceCustody !== undefined &&
                    result.sourceRefusals !== undefined,
            );
            return undefined;
        case 'departures':
        case 'largest-departures': {
            // Members other than the organizer, as many as the roster
            // tolerates, leave for good at distinct stages; the remaining
            // members complete and a fresh outcome verifier checks the outcome.
            const participantCount = name === 'departures' ? 7 : 20;
            const { maximumCorruptParticipantCount: tolerated } =
                thresholdProfileFor(participantCount);
            const schedule = result.departureSchedule ?? [];
            assert.equal(schedule.length, tolerated);
            const departed = schedule.map((entry) => entry.position);
            assert.ok(
                departed.every(
                    (position) => position > 0 && position < participantCount,
                ),
            );
            assert.equal(new Set(departed).size, tolerated);
            assert.equal(
                new Set(schedule.map((entry) => entry.boundary)).size,
                tolerated,
            );
            assert.equal(result.independentOutcome?.status, 'completed');
            return undefined;
        }
        case 'ordinary':
            return completionMeasurements(
                runDirectoryPath,
                result,
                events,
                false,
            );
        case 'recovery':
        case 'completion-recovery':
            assert.deepEqual(
                interruptions.map((entry) => entry.operation),
                ['contribute', 'cast-ballot', 'sign-target', 'release'],
            );
            assert.equal(result.independentOutcome?.status, 'completed');
            assert.deepEqual(
                result.independentOutcome?.details?.identifiers,
                result.identifiers,
            );
            if (name === 'recovery') return undefined;
            return completionMeasurements(
                runDirectoryPath,
                result,
                events,
                true,
            );
        default:
            throw new Error(`The audit has no checks for the ${name} case.`);
    }
};

// A run ran the renewed checkout's runtime when its own source manifest and
// archived module and worker recompute the checkout's runtime identity and
// its archived SDK entry has the checkout's digest.
export const auditArchivedRuntime = async (
    runDirectoryPath: string,
    checkout: Readonly<{
        identity: Readonly<{ runtime: string }>;
        sdkDigest: string;
    }>,
) => {
    const run = path.basename(runDirectoryPath),
        artifacts = runArtifactDirectoryPath(runDirectoryPath);
    const [manifest, module, worker, entry] = await Promise.all([
        readFile(path.join(runDirectoryPath, 'source-manifest.json')),
        ...['participant.wasm', 'worker.js', 'index.js'].map((file) =>
            readFile(path.join(artifacts, file)),
        ),
    ]);
    assert.equal(
        participantRuntimeIdentity(manifest, module, worker).runtime,
        checkout.identity.runtime,
        `${run} ran another runtime than the renewed checkout's.`,
    );
    assert.equal(
        digest(entry),
        checkout.sdkDigest,
        `${run} ran another SDK entry than the renewed checkout's.`,
    );
    return {
        compiledInputs: (
            JSON.parse(manifest.toString('utf8')) as {
                files: readonly unknown[];
            }
        ).files.length,
        runtime: [
            { file: 'participant.wasm', sha512: digest(module) },
            { file: 'worker.js', sha512: digest(worker) },
            { file: 'index.js', sha512: digest(entry) },
        ],
    };
};

type VitestResults = Readonly<{
    numFailedTests: number;
    numPassedTests: number;
    numTotalTests: number;
}>;

const main = async (): Promise<void> => {
    const commandLineArguments = process.argv.slice(2);
    const { values } = parseArgs({
        args: [...toolArguments(commandLineArguments)],
        options: {
            checkout: { type: 'string' },
            renewal: { type: 'string' },
        },
        strict: true,
    });
    if (values.renewal === undefined || values.checkout === undefined)
        throw new Error(usage);
    const renewal = path.resolve(values.renewal);
    const checkout = path.resolve(values.checkout);
    await runWithLocalRunLog(
        {
            commandLineArguments,
            scriptName: 'audit-renewed-lifecycle-matrix',
        },
        async (log) => {
            const records = await readEvidenceRenewalRecord(renewal);
            const passedRun = (name: string): string => {
                const record: EvidenceRenewalStepRecord | undefined =
                    records.get(name);
                assert.ok(
                    record !== undefined &&
                        stepPassed(record) &&
                        record.run !== undefined,
                    `The renewal records no passed run of ${name}.`,
                );
                return record.run;
            };
            const resources = readParticipantArtifactResources((file) =>
                readFileSync(path.join(checkout, file)),
            );
            const reports = [];
            for (const name of lifecycleMatrixStepNames) {
                const step = evidenceRenewalSteps.find(
                    (candidate) => candidate.name === name,
                );
                assert.ok(step !== undefined);
                const run = passedRun(name);
                const runDirectoryPath = path.join(repositoryRoot, run);
                const summary = await readRunJson<RunSummary>(
                    runDirectoryPath,
                    'summary.json',
                );
                const result = await readRunJson<ParticipantRunResult>(
                    runDirectoryPath,
                    'result.json',
                );
                const metadata = await readRunJson<RunMetadata>(
                    runDirectoryPath,
                    'metadata.json',
                );
                const events = await readRunEvents(runDirectoryPath);
                assert.equal(summary.result, 'passed');
                // The run is the step's case, with the runs it names.
                assert.deepEqual(
                    toolArguments(metadata.commandLineArguments),
                    stepScriptArguments(step, passedRun),
                    `The ${name} run ran other arguments than its step.`,
                );
                const completion = await auditCase(
                    name,
                    runDirectoryPath,
                    result,
                    events,
                );
                const { compiledInputs, runtime } = await auditArchivedRuntime(
                    runDirectoryPath,
                    resources,
                );
                // Chrome's backing-store opening histograms per launch; an
                // open status other than an on-disk success is reported.
                const openStatuses = events
                    .filter(
                        (event) =>
                            event.eventType ===
                            'participant-backing-store-openings',
                    )
                    .map(
                        (event) =>
                            (
                                event.details as Readonly<{
                                    histograms: Readonly<
                                        Record<
                                            string,
                                            Readonly<Record<string, number>>
                                        >
                                    >;
                                }>
                            ).histograms[
                                'WebCore.IndexedDB.BackingStore.OpenStatus'
                            ] ?? {},
                    );
                reports.push({
                    name: step.description,
                    run,
                    sourceCommit: summary.repositoryCommitHash,
                    compiledInputs,
                    runtime,
                    backingStoreOpeningEvents: openStatuses.length,
                    backingStoreOpenFailures: openStatuses.filter((status) =>
                        Object.keys(status).some((bucket) => bucket !== '1'),
                    ),
                    ...(completion === undefined ? {} : { completion }),
                });
            }
            const check = passedRun('desktop-check');
            const checkDirectoryPath = path.join(repositoryRoot, check);
            assert.equal(
                (
                    await readRunJson<RunSummary>(
                        checkDirectoryPath,
                        'summary.json',
                    )
                ).result,
                'passed',
            );
            const tests = [];
            for (const file of await readdir(
                path.join(checkDirectoryPath, 'vitest-results'),
            )) {
                if (!file.endsWith('.json')) continue;
                const results = await readRunJson<VitestResults>(
                    checkDirectoryPath,
                    path.join('vitest-results', file),
                );
                assert.equal(results.numFailedTests, 0);
                assert.equal(results.numPassedTests, results.numTotalTests);
                tests.push({ file, passed: results.numPassedTests });
            }
            assert.ok(tests.length > 0, 'The desktop check reports no tests.');
            await writeFile(
                path.join(log.runDirectoryPath, 'evidence.json'),
                JSON.stringify(
                    {
                        commit: execFileSync('git', ['rev-parse', 'HEAD'], {
                            cwd: checkout,
                            encoding: 'utf8',
                        }).trim(),
                        runtimeIdentity: resources.identity.runtime,
                        check,
                        tests,
                        reports,
                    },
                    null,
                    2,
                ) + '\n',
                { flag: 'wx' },
            );
            process.stdout.write(log.runDirectoryPath + '\n');
        },
    );
};

if (import.meta.main) await main();
