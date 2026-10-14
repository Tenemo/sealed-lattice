import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
    mkdir,
    mkdtemp,
    readdir,
    readFile,
    rm,
    stat,
    symlink,
    writeFile,
} from 'node:fs/promises';
import path from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
    auditArchivedRuntime,
    receivedByAction,
} from '#tools/ci/audit-renewed-lifecycle-matrix.js';
import { participantRuntimeIdentity } from '#tools/ci/build-participant-module.js';
import { repositoryRoot } from '#tools/ci/command-line.js';
import {
    listChildRuns,
    readEvidenceRenewalRecord,
    recordedStepEventType,
    repositoryRelativeRun,
    type EvidenceRenewalStepRecord,
} from '#tools/ci/evidence-renewal-record.js';
import {
    evidenceRenewalSteps,
    lifecycleMatrixStepNames,
    requiredSteps,
    stepScriptArguments,
    validateEvidenceRenewalSteps,
    type EvidenceRenewalStep,
} from '#tools/ci/evidence-renewal-steps.js';
import {
    busyProcessors,
    estimateProbeSlowdown,
    parseProcessTimes,
    selectMonitorOptions,
} from '#tools/ci/monitor-host-contention.js';
import {
    bindingSlowdown,
    payloadSeconds,
    tolerableSlowdown,
} from '#tools/ci/project-participant-phone-time.js';
import { removeDirectoryLinks } from '#tools/ci/renewal-worktree.js';
import {
    formatRenewalSummary,
    planEvidenceRenewal,
} from '#tools/ci/run-evidence-renewal.js';

const commit = 'a'.repeat(40);
const digest = (bytes: Uint8Array) =>
    createHash('sha512').update(bytes).digest('hex');
const runOfStep = (name: string) =>
    `logs/2026-10-12/2026-10-12T00-00-00.000Z-${name}`;
const stepRecord = (
    name: string,
    overrides: Partial<EvidenceRenewalStepRecord> = {},
): EvidenceRenewalStepRecord => {
    const step = evidenceRenewalSteps.find(
        (candidate) => candidate.name === name,
    );
    const run = step?.run === undefined ? undefined : runOfStep(name);
    return {
        name,
        exitCode: 0,
        startedAtIso: '2026-10-12T00:00:00.000Z',
        finishedAtIso: '2026-10-12T00:01:00.000Z',
        commit,
        runs: run === undefined ? [] : [run],
        ...(run === undefined ? {} : { run }),
        ...overrides,
    };
};
const recordsThrough = (lastPassed: string) => {
    const records = new Map<string, EvidenceRenewalStepRecord>();
    for (const step of evidenceRenewalSteps) {
        records.set(step.name, stepRecord(step.name));
        if (step.name === lastPassed) break;
    }
    return records;
};
const stepNames = (steps: readonly EvidenceRenewalStep[]) =>
    steps.map((step) => step.name);
const operationEvent = (
    position: number,
    operation: string,
    receivedPayloadBytes: number,
) => ({
    eventType: 'participant-operation',
    details: {
        milliseconds: 1,
        operation,
        originTransfer: {
            incompleteExchanges: 0,
            receivedPayloadBytes,
            sentPayloadBytes: 0,
            unknownRequestLengths: 0,
        },
        position,
    },
});

describe('evidence renewal steps', () => {
    it('accepts the renewal steps, whose research arguments all parse', () => {
        expect(() =>
            validateEvidenceRenewalSteps(evidenceRenewalSteps),
        ).not.toThrow();
        expect(evidenceRenewalSteps[0].preparesCheckout).toBe(true);
        const audit = evidenceRenewalSteps.find(
            (step) => step.name === 'audit',
        );
        assert.ok(audit !== undefined);
        expect(requiredSteps(audit)).toEqual([
            ...lifecycleMatrixStepNames,
            'desktop-check',
        ]);
    });

    it('lists every inconsistency of a step list', () => {
        const steps: EvidenceRenewalStep[] = [
            {
                name: 'Bad_Name',
                description: 'x',
                command: { script: 'build' },
            },
            { name: 'first', description: 'x', command: { script: 'build' } },
            { name: 'first', description: 'x', command: { script: 'build' } },
            {
                name: 'prepare',
                description: 'x',
                command: { script: 'build' },
                preparesCheckout: true,
            },
            {
                name: 'forward',
                description: 'x',
                command: {
                    script: 'research:protocol',
                    arguments: ['scalar-fhe-key-source', { run: 'later' }],
                },
                run: 'research:protocol',
            },
            { name: 'runless', description: 'x', command: { script: 'build' } },
            {
                name: 'reference',
                description: 'x',
                command: {
                    script: 'research:participant:built',
                    arguments: [
                        '4',
                        '2',
                        'no-result',
                        { run: 'runless', prefix: '--foreign-poll=' },
                    ],
                },
                run: 'research:participant',
            },
            {
                name: 'monitored',
                description: 'x',
                command: { script: 'build' },
                monitored: true,
            },
            {
                name: 'missing-tool',
                description: 'x',
                command: { tool: 'tools/ci/absent-tool.ts', requires: [] },
            },
            {
                name: 'bad-cohort',
                description: 'x',
                command: {
                    script: 'research:participant:built',
                    arguments: ['4', '2', '--recovery'],
                },
                run: 'research:participant',
            },
            {
                name: 'bad-case',
                description: 'x',
                command: {
                    script: 'research:protocol',
                    arguments: ['native-unknown'],
                },
                run: 'research:protocol',
            },
        ];
        expect(() => validateEvidenceRenewalSteps(steps)).toThrow(
            [
                'The evidence renewal steps are inconsistent:',
                'Bad_Name: a step name is kebab-case.',
                'first: the name repeats.',
                'prepare: a step that prepares the checkout precedes every other step.',
                'forward: needs later, which does not precede it.',
                'reference: names the run of runless, which creates none.',
                'monitored: only a timing step is monitored.',
                'missing-tool: the tool tools/ci/absent-tool.ts does not exist.',
                'bad-cohort: Recovery measurements require an ordinary plain cohort.',
                'bad-case: No protocol research case matches the selector.',
            ].join('\n'),
        );
        expect(() => validateEvidenceRenewalSteps([])).toThrow(
            'The evidence renewal has no steps.',
        );
    });

    it('substitutes the runs that a step names', () => {
        const noResult = evidenceRenewalSteps.find(
            (step) => step.name === 'no-result',
        );
        assert.ok(noResult !== undefined);
        expect(requiredSteps(noResult)).toEqual(['result']);
        expect(stepScriptArguments(noResult, runOfStep)).toEqual([
            '4',
            '2',
            'no-result',
            '--scalar',
            `--foreign-poll=${runOfStep('result')}`,
            '--base-port=42380',
        ]);
    });
});

describe('evidence renewal plan', () => {
    it('runs every step without a resumed record', () => {
        expect(planEvidenceRenewal(evidenceRenewalSteps, {})).toEqual({
            carried: [],
            run: evidenceRenewalSteps,
        });
        expect(
            planEvidenceRenewal(evidenceRenewalSteps, { from: 'build' }).run,
        ).toEqual(evidenceRenewalSteps);
    });

    it('resumes at the first step the record has not passed and prepares the checkout again', () => {
        const resumed = recordsThrough('departures');
        resumed.set('ordinary', stepRecord('ordinary', { exitCode: 1 }));
        const plan = planEvidenceRenewal(evidenceRenewalSteps, { resumed });
        const ordinary = stepNames(evidenceRenewalSteps).indexOf('ordinary');
        expect(stepNames(plan.run)).toEqual([
            'build',
            ...stepNames(evidenceRenewalSteps.slice(ordinary)),
        ]);
        expect(plan.carried.map((record) => record.name)).toEqual(
            stepNames(evidenceRenewalSteps.slice(1, ordinary)),
        );
    });

    it('carries the passed steps before a named step', () => {
        const resumed = recordsThrough('projection');
        const plan = planEvidenceRenewal(evidenceRenewalSteps, {
            from: 'audit',
            resumed,
        });
        expect(stepNames(plan.run)).toEqual(['build', 'audit', 'projection']);
        expect(plan.carried).toHaveLength(evidenceRenewalSteps.length - 3);
        expect(plan.carried).not.toContainEqual(stepRecord('build'));
    });

    it('refuses a start that the record cannot support', () => {
        const resumed = recordsThrough('projection');
        expect(() =>
            planEvidenceRenewal(evidenceRenewalSteps, { from: 'absent-step' }),
        ).toThrow('No step is named absent-step');
        expect(() =>
            planEvidenceRenewal(evidenceRenewalSteps, { from: 'audit' }),
        ).toThrow('--from needs --resume');
        expect(() =>
            planEvidenceRenewal(evidenceRenewalSteps, { resumed }),
        ).toThrow('passed every step');
        const failedEarlier = new Map(resumed);
        failedEarlier.set(
            'native-empty',
            stepRecord('native-empty', { failure: 'The run did not pass.' }),
        );
        expect(() =>
            planEvidenceRenewal(evidenceRenewalSteps, {
                from: 'audit',
                resumed: failedEarlier,
            }),
        ).toThrow(
            'The resumed renewal has no passed record of native-empty, which precedes audit.',
        );
        const runless = new Map(resumed);
        runless.set('result', {
            ...stepRecord('result'),
            run: undefined,
            runs: [],
        });
        expect(() =>
            planEvidenceRenewal(evidenceRenewalSteps, {
                from: 'audit',
                resumed: runless,
            }),
        ).toThrow(
            'The resumed record of result names no research:participant run.',
        );
    });
    it('refuses to carry a run that no longer exists', () => {
        const resumed = recordsThrough('projection');
        const deleted = runOfStep('result');
        expect(() =>
            planEvidenceRenewal(evidenceRenewalSteps, {
                from: 'audit',
                resumed,
                runExists: (run) => run !== deleted,
            }),
        ).toThrow(
            `The resumed record of result names runs that no longer exist: ${deleted}.`,
        );
        expect(
            planEvidenceRenewal(evidenceRenewalSteps, {
                from: 'audit',
                resumed,
                runExists: () => true,
            }).carried,
        ).toHaveLength(evidenceRenewalSteps.length - 3);
    });
});

describe('evidence renewal summary', () => {
    const name = '2026-10-12T01-00-00.000Z-research-evidence-renewal';
    const runDirectoryPath = path.join(
        repositoryRoot,
        'logs',
        '2026-10-12',
        name,
    );
    const resume = `--resume=${path.join('logs', '2026-10-12', name)}`;
    const record = `Renewal record: ${path.join(runDirectoryPath, 'renewal-record.json')}`;
    const statusOf = (summary: string, step: string) =>
        new RegExp(
            `^  (PASSED|FAILED|CARRIED|NOT RUN) +${step}(?: |$)`,
            'mu',
        ).exec(summary)?.[1];

    it('reports every step and how to resume after a failed step', () => {
        const failure = stepRecord('participant-module', {
            exitCode: 1,
            failure: 'The participant module tests failed.',
        });
        const summary = formatRenewalSummary({
            carried: new Set(['rust-fast']),
            cleanupFailures: [],
            failed: evidenceRenewalSteps.find(
                (step) => step.name === 'participant-module',
            ),
            interrupted: true,
            outcomes: new Map([
                [
                    'build',
                    {
                        durationMilliseconds: 65_000,
                        record: stepRecord('build'),
                        recentOutput: [],
                    },
                ],
                [
                    'participant-module',
                    {
                        durationMilliseconds: 5_000,
                        record: failure,
                        recentOutput: ['1 failed', '2 passed'],
                    },
                ],
            ]),
            records: new Map([
                ['build', stepRecord('build')],
                ['rust-fast', stepRecord('rust-fast')],
                ['participant-module', failure],
            ]),
            runDirectoryPath,
        });
        expect(statusOf(summary, 'build')).toBe('PASSED');
        expect(statusOf(summary, 'rust-fast')).toBe('CARRIED');
        expect(statusOf(summary, 'participant-module')).toBe('FAILED');
        expect(statusOf(summary, 'smoke-pack')).toBe('NOT RUN');
        expect(summary).toMatch(/ build +1m 05s\n/u);
        expect(summary).toContain(
            [
                'participant-module failed with exit code 1.',
                'The participant module tests failed.',
                'Recent output:',
                '1 failed',
                '2 passed',
                `Full output: ${path.join(runDirectoryPath, 'output.log')} (command participant-module)`,
                `Resume with ${resume}`,
                record,
                '',
            ].join('\n'),
        );
        // The failure, not the interrupt, says how to resume.
        expect(summary).not.toContain('interrupted');
    });

    it('says how to resume an interrupted renewal and reports cleanup failures', () => {
        const summary = formatRenewalSummary({
            carried: new Set(),
            cleanupFailures: ['The worktree at W could not be removed: busy'],
            interrupted: true,
            outcomes: new Map(),
            records: new Map([['build', stepRecord('build')]]),
            runDirectoryPath,
        });
        expect(statusOf(summary, 'build')).toBe('PASSED');
        expect(statusOf(summary, 'rust-fast')).toBe('NOT RUN');
        expect(summary).toContain(
            [
                `The renewal was interrupted; resume with ${resume}`,
                'The worktree at W could not be removed: busy',
                record,
                '',
            ].join('\n'),
        );
        expect(summary).not.toContain('failed with exit code');
    });
});

describe('evidence renewal records', () => {
    const temporaryRoot = path.resolve('temp');
    let root: string;
    beforeEach(async () => {
        await mkdir(temporaryRoot, { recursive: true });
        root = await mkdtemp(
            path.join(temporaryRoot, 'evidence-renewal-test-'),
        );
    });
    afterEach(async () => {
        assert.ok(root.startsWith(temporaryRoot + path.sep));
        await rm(root, { recursive: true, force: true });
    });

    it('reads the latest record of each step from a renewal run, ignoring a line still being written', async () => {
        const renewal = path.join(root, 'renewal');
        await mkdir(renewal);
        const event = (details: unknown, eventType = recordedStepEventType) =>
            JSON.stringify({ details, eventType }) + '\n';
        await writeFile(
            path.join(renewal, 'events.jsonl'),
            event({ name: 'unrelated' }, 'renewal-plan') +
                event(stepRecord('rust-fast', { exitCode: 1 })) +
                event(stepRecord('rust-fast')) +
                event(stepRecord('participant-module')) +
                '{"details":{"name":"smoke-pack"',
        );
        const records = await readEvidenceRenewalRecord(renewal);
        expect([...records.keys()]).toEqual([
            'rust-fast',
            'participant-module',
        ]);
        expect(records.get('rust-fast')).toEqual(stepRecord('rust-fast'));
    });

    it('reads a record file and refuses malformed records', async () => {
        const recordFile = path.join(root, 'record.json');
        const steps = [stepRecord('rust-fast'), stepRecord('build')];
        await writeFile(recordFile, JSON.stringify({ steps }));
        expect([
            ...(await readEvidenceRenewalRecord(recordFile)).values(),
        ]).toEqual(steps);
        for (const [malformed, problem] of [
            [
                { ...stepRecord('rust-fast'), commit: 'abc' },
                'commit is not a commit',
            ],
            [
                { ...stepRecord('rust-fast'), runs: ['temp/run'] },
                'runs is not a repository run directory',
            ],
            [
                { ...stepRecord('rust-fast'), runs: [] },
                'run is not one of its runs',
            ],
            [
                { ...stepRecord('rust-fast'), exitCode: 0.5 },
                'exitCode is not an integer',
            ],
            [
                { ...stepRecord('rust-fast'), finishedAtIso: 'later' },
                'finishedAtIso is not a time',
            ],
        ] as const) {
            await writeFile(recordFile, JSON.stringify({ steps: [malformed] }));
            await expect(readEvidenceRenewalRecord(recordFile)).rejects.toThrow(
                problem,
            );
        }
        await writeFile(recordFile, JSON.stringify({ records: [] }));
        await expect(readEvidenceRenewalRecord(recordFile)).rejects.toThrow(
            'lists no steps',
        );
    });

    it('relates run directories to the repository root', () => {
        expect(
            repositoryRelativeRun(
                root,
                path.join(root, 'logs', '2026-10-12', 'run'),
            ),
        ).toBe('logs/2026-10-12/run');
        expect(() =>
            repositoryRelativeRun(root, path.join(root, 'temp', 'run')),
        ).toThrow("is not a run directory of this repository's logs");
    });

    it('finds the runs a renewal started across a date boundary by their parent', async () => {
        const renewal = path.join(
            root,
            'logs',
            '2026-10-12',
            '2026-10-12T23-59-00.000Z-research-evidence-renewal',
        );
        // A worktree reaches the same run directory through its own path.
        const renewalThroughWorktree = path.join(
            root,
            'worktree',
            'logs',
            '2026-10-12',
            path.basename(renewal),
        );
        const run = async (
            date: string,
            name: string,
            metadata: string | undefined,
        ) => {
            const directory = path.join(root, 'logs', date, name);
            await mkdir(directory, { recursive: true });
            if (metadata !== undefined)
                await writeFile(
                    path.join(directory, 'metadata.json'),
                    metadata,
                );
        };
        const child = (parent: string, scriptName: string) =>
            JSON.stringify({ parentRunDirectoryPath: parent, scriptName });
        await run(
            '2026-10-12',
            '2026-10-12T23-59-58.000Z-research-participant',
            child(renewal, 'research:participant'),
        );
        await run(
            '2026-10-12',
            '2026-10-12T23-59-59.500Z-research-participant',
            child(renewal, 'research:participant'),
        );
        await run(
            '2026-10-13',
            '2026-10-13T00-00-10.000Z-research-protocol',
            child(renewalThroughWorktree, 'research:protocol'),
        );
        await run(
            '2026-10-13',
            '2026-10-13T00-00-11.000Z-check',
            child(path.join(root, 'logs', '2026-10-13', 'other'), 'check'),
        );
        await run('2026-10-13', '2026-10-13T00-00-12.000Z-starting', undefined);
        await run('2026-10-13', '2026-10-13T00-00-13.000Z-torn', '{"parent');
        expect(
            await listChildRuns({
                parentRunDirectoryPath: renewal,
                repositoryRoot: root,
                since: new Date('2026-10-12T23:59:59.000Z'),
                until: new Date('2026-10-13T12:00:00.000Z'),
            }),
        ).toEqual([
            {
                run: 'logs/2026-10-12/2026-10-12T23-59-59.500Z-research-participant',
                scriptName: 'research:participant',
            },
            {
                run: 'logs/2026-10-13/2026-10-13T00-00-10.000Z-research-protocol',
                scriptName: 'research:protocol',
            },
        ]);
    });

    it('removes links without following them and keeps a directory that replaced one', async () => {
        const target = path.join(root, 'shared');
        await mkdir(target);
        await writeFile(path.join(target, 'kept.txt'), 'kept');
        const worktree = path.join(root, 'worktree');
        await mkdir(worktree);
        const link = path.join(worktree, 'logs');
        await symlink(target, link, 'junction');
        await removeDirectoryLinks([link, path.join(worktree, 'absent')]);
        await expect(stat(link)).rejects.toMatchObject({ code: 'ENOENT' });
        expect(await readdir(target)).toEqual(['kept.txt']);
        const replaced = path.join(worktree, 'temp');
        await mkdir(replaced);
        await writeFile(path.join(replaced, 'own.txt'), 'own');
        await expect(removeDirectoryLinks([replaced])).rejects.toThrow(
            'is no longer a link',
        );
        expect(await readFile(path.join(replaced, 'own.txt'), 'utf8')).toBe(
            'own',
        );
    });

    it('accepts a run whose archived runtime recomputes the checkout runtime, and refuses an added source, another worker and another SDK entry', async () => {
        const run = path.join(root, 'logs', '2026-10-12', 'run');
        const artifacts = path.join(
            root,
            'temp',
            'run-artifacts',
            '2026-10-12',
            'run',
        );
        const manifest = (files: readonly string[]) =>
            Buffer.from(
                JSON.stringify({
                    files: files.map((file) => ({
                        file,
                        sha512: digest(Buffer.from(file)),
                        bytes: file.length,
                    })),
                }),
            );
        const [module, worker, entry] = ['module', 'worker', 'entry'].map(
            (text) => Buffer.from(text),
        );
        await mkdir(run, { recursive: true });
        await mkdir(artifacts, { recursive: true });
        await writeFile(
            path.join(run, 'source-manifest.json'),
            manifest(['a.ts', 'b.ts']),
        );
        for (const [file, bytes] of [
            ['participant.wasm', module],
            ['worker.js', worker],
            ['index.js', entry],
        ] as const)
            await writeFile(path.join(artifacts, file), bytes);
        const checkout = (
            sources: readonly string[],
            checkoutWorker = worker,
            checkoutEntry = entry,
        ) => ({
            identity: participantRuntimeIdentity(
                manifest(sources),
                module,
                checkoutWorker,
            ),
            sdkDigest: digest(checkoutEntry),
        });
        expect(
            await auditArchivedRuntime(run, checkout(['a.ts', 'b.ts'])),
        ).toEqual({
            compiledInputs: 2,
            runtime: [
                { file: 'participant.wasm', sha512: digest(module) },
                { file: 'worker.js', sha512: digest(worker) },
                { file: 'index.js', sha512: digest(entry) },
            ],
        });
        for (const other of [
            checkout(['a.ts', 'b.ts', 'c.ts']),
            checkout(['a.ts', 'b.ts'], Buffer.from('other worker')),
        ])
            await expect(auditArchivedRuntime(run, other)).rejects.toThrow(
                "run ran another runtime than the renewed checkout's.",
            );
        await expect(
            auditArchivedRuntime(
                run,
                checkout(['a.ts', 'b.ts'], worker, Buffer.from('other entry')),
            ),
        ).rejects.toThrow(
            "run ran another SDK entry than the renewed checkout's.",
        );
    });
});

describe('evidence renewal measurements', () => {
    it('charges each participant action the payload received since its previous operation', () => {
        expect(
            receivedByAction([
                operationEvent(0, 'contribute', 100),
                { eventType: 'participant-recovery-public-outcome' },
                operationEvent(1, 'contribute', 40),
                operationEvent(0, 'publish', 260),
                operationEvent(0, 'contribute', 300),
            ]),
        ).toEqual([
            { position: 0, operation: 'publish', receivedPayloadBytes: 160 },
            { position: 0, operation: 'contribute', receivedPayloadBytes: 140 },
            { position: 1, operation: 'contribute', receivedPayloadBytes: 40 },
        ]);
        expect(() =>
            receivedByAction([
                operationEvent(0, 'contribute', 100),
                operationEvent(0, 'release', 99),
            ]),
        ).toThrow("Participant 0's received counter decreased.");
    });

    it('projects the slowdown each limit tolerates under both transfer models', () => {
        // 12.5 MB moves in one second at 100 decimal megabits per second.
        expect(payloadSeconds(12_500_000, 100)).toBe(1);
        expect(tolerableSlowdown(100, 60 * 12_500_000, 900, 100)).toEqual({
            additive: 8.4,
            overlap: 9,
        });
        expect(tolerableSlowdown(100, 1000 * 12_500_000, 900, 100)).toEqual({
            additive: -1,
            overlap: 0,
        });
        const rows = [
            { name: 'light', seconds: 100, bytes: 0 },
            { name: 'heavy', seconds: 50, bytes: 400 * 12_500_000 },
            { name: 'slow', seconds: 300, bytes: 0 },
        ];
        expect(
            bindingSlowdown(
                rows,
                (row) => row.seconds,
                (row) => row.bytes,
                900,
                100,
            ),
        ).toEqual({ additive: 3, overlap: 3, row: rows[2] });
        expect(() =>
            bindingSlowdown(
                [],
                () => 1,
                () => 0,
                900,
                100,
            ),
        ).toThrow('at least one row');
    });

    it('estimates the probe slowdown from its median and fastest repetitions', () => {
        expect(
            estimateProbeSlowdown([300, 100, 200], [1.5, 1, 2], 100),
        ).toEqual({
            longMilliseconds: [300, 100, 200],
            medianMilliseconds: 200,
            uncontendedEstimateMilliseconds: 100,
            slowdown: 2,
        });
        expect(() => estimateProbeSlowdown([], [1], 100)).toThrow(
            'long and short repetitions',
        );
    });

    it('splits processor time between own and other processes present in both readings', () => {
        const previous = parseProcessTimes(
            [
                '0|System Idle Process|50|0',
                '4|chrome.exe|1|1',
                '8|game.exe|10|0',
                '12|old.exe|5|0',
                '16|clock.exe|9|0',
                'malformed line',
            ].join('\r\n'),
            0,
        );
        const current = parseProcessTimes(
            [
                '0|System Idle Process|90|0',
                '4|chrome.exe|3|1',
                '8|game.exe|11|0',
                '12|new.exe|7|0',
                '16|clock.exe|8|0',
            ].join('\n'),
            2000,
        );
        expect(busyProcessors(previous, current)).toEqual({
            ownProcessors: 1,
            otherProcessors: 0.5,
        });
        expect(() => busyProcessors(current, current)).toThrow(
            'must advance in time',
        );
    });

    it('requires a label, a stop file and the checkouts whose processes are own', () => {
        expect(
            selectMonitorOptions([
                '--',
                '--label=ordinary',
                '--stop-file=temp/ordinary.stop',
                '--own-path=.',
                '--own-path=temp/worktree',
            ]),
        ).toEqual({
            label: 'ordinary',
            ownPaths: [path.resolve('.'), path.resolve('temp/worktree')],
            stopFile: path.resolve('temp/ordinary.stop'),
        });
        for (const values of [
            ['--stop-file=a', '--own-path=.'],
            ['--label=Ordinary', '--stop-file=a', '--own-path=.'],
            ['--label=ordinary', '--own-path=.'],
            ['--label=ordinary', '--stop-file=a'],
        ])
            expect(() => selectMonitorOptions(values)).toThrow('Usage:');
    });
});
