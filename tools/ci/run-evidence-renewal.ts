import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { setTimeout as delay } from 'node:timers/promises';
import { parseArgs, stripVTControlCharacters } from 'node:util';

import { repositoryRoot, toolArguments } from '#tools/ci/command-line.js';
import {
    createPackageManagerCommand,
    runCommandAndCaptureOutput,
    runCommandsInSeries,
    type CommandInvocation,
} from '#tools/ci/command-runner.js';
import {
    listChildRuns,
    readEvidenceRenewalRecord,
    recordedStepEventType,
    repositoryRelativeRun,
    stepPassed,
    type EvidenceRenewalStepRecord,
} from '#tools/ci/evidence-renewal-record.js';
import {
    evidenceRenewalSteps,
    stepScriptArguments,
    validateEvidenceRenewalSteps,
    type EvidenceRenewalStep,
} from '#tools/ci/evidence-renewal-steps.js';
import {
    runWithLocalRunLog,
    type ActiveLocalRunLog,
} from '#tools/ci/local-run-log.js';
import { guardProcessTreeMemory } from '#tools/ci/process-tree-memory.js';
import {
    describeProcessorPlacement,
    parseProcessorPlacement,
    placeCommand,
    type ProcessorPlacement,
} from '#tools/ci/processor-placement.js';
import { acquireEvidenceRenewalLock } from '#tools/ci/protocol-research-lock.js';
import {
    createRenewalWorktree,
    type RenewalWorktree,
} from '#tools/ci/renewal-worktree.js';

// Renews the development evidence one step at a time and stops at the first
// failure. Each step's outcome is an event of this run, so a stopped renewal
// resumes from its run directory.
const usage = [
    'Usage: pnpm run research:evidence-renewal -- [option...]',
    '',
    '  --plan                                     Print the steps to carry and run, then stop.',
    '  --resume=<run directory or record file>    Carry the passed steps of an earlier renewal.',
    '  --from=<step>                              With --resume, run from this step instead of the first one the record has not passed.',
    '  --worktree=<commit>                        Renew a detached worktree of the commit instead of this checkout.',
    '  --timing-placement=<mask>:<priority>       Hold the paired timing workloads and their monitors in a Windows job object.',
    '  --background-placement=<mask>:<priority>   Hold the largest cohort in a Windows job object.',
    '',
    'A placement is a hexadecimal affinity mask and below-normal, normal or above-normal, such as 0xAAAA:above-normal.',
].join('\n');

type PlacementRole = NonNullable<EvidenceRenewalStep['placement']>;

const stepLimitMilliseconds = 6 * 60 * 60_000;
const memorySampleIntervalMilliseconds = 30_000;
const monitorReadyLimitMilliseconds = 5 * 60_000;
const monitorStopLimitMilliseconds = 10 * 60_000;
const recentOutputLineLimit = 40;
const monitorScriptName = 'monitor-host-contention';

type EvidenceRenewalPlan = Readonly<{
    carried: readonly EvidenceRenewalStepRecord[];
    run: readonly EvidenceRenewalStep[];
}>;

// Without a resumed record, every step runs. With one, the steps before the
// starting step are carried from it and must have passed; the starting step
// is `from` or the first step the record has not passed. A step that
// prepares the checkout runs in every invocation.
export const planEvidenceRenewal = (
    steps: readonly EvidenceRenewalStep[],
    input: Readonly<{
        from?: string;
        resumed?: ReadonlyMap<string, EvidenceRenewalStepRecord>;
    }>,
): EvidenceRenewalPlan => {
    const names = steps.map((step) => step.name);
    if (input.from !== undefined && !names.includes(input.from))
        throw new Error(
            `No step is named ${input.from}; the steps are ${names.join(', ')}.`,
        );
    const resumed = input.resumed;
    if (resumed === undefined) {
        if (input.from !== undefined && input.from !== names[0])
            throw new Error(
                '--from needs --resume, whose record supplies the steps before it.',
            );
        return { carried: [], run: steps };
    }
    const passed = (step: EvidenceRenewalStep) => {
        const record = resumed.get(step.name);
        return record !== undefined && stepPassed(record);
    };
    const start =
        input.from === undefined
            ? steps.findIndex(
                  (step) => step.preparesCheckout !== true && !passed(step),
              )
            : names.indexOf(input.from);
    if (start === -1)
        throw new Error(
            'The resumed renewal passed every step, so none remains to run.',
        );
    const carried: EvidenceRenewalStepRecord[] = [];
    for (const step of steps.slice(0, start)) {
        if (step.preparesCheckout === true) continue;
        const record = resumed.get(step.name);
        if (record === undefined || !stepPassed(record))
            throw new Error(
                `The resumed renewal has no passed record of ${step.name}, which precedes ${names[start]}.`,
            );
        if (step.run !== undefined && record.run === undefined)
            throw new Error(
                `The resumed record of ${step.name} names no ${step.run} run.`,
            );
        carried.push(record);
    }
    return {
        carried,
        run: [
            ...steps
                .slice(0, start)
                .filter((step) => step.preparesCheckout === true),
            ...steps.slice(start),
        ],
    };
};

const selectRenewalOptions = (commandLineArguments: readonly string[]) => {
    const { values } = parseArgs({
        args: [...toolArguments(commandLineArguments)],
        options: {
            'background-placement': { type: 'string' },
            from: { type: 'string' },
            plan: { type: 'boolean' },
            resume: { type: 'string' },
            'timing-placement': { type: 'string' },
            worktree: { type: 'string' },
        },
        strict: true,
    });
    return values;
};

const describePlacement = (placement: ProcessorPlacement | undefined) => {
    if (placement === undefined) return 'unplaced';
    const { affinityMask, priority } = describeProcessorPlacement(placement);
    return `${affinityMask}:${priority}`;
};

const formatDuration = (milliseconds: number): string => {
    const seconds = Math.round(milliseconds / 1000);
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    if (hours > 0)
        return `${String(hours)}h ${String(minutes).padStart(2, '0')}m`;
    if (minutes > 0)
        return `${String(minutes)}m ${String(seconds % 60).padStart(2, '0')}s`;
    return `${String(seconds)}s`;
};

const errorMessage = (error: unknown): string =>
    error instanceof Error ? error.message : String(error);

// The last lines a command printed, without terminal control sequences.
class RecentOutput {
    readonly #lines: string[] = [];
    #pending = '';

    append(chunk: string): void {
        const lines = `${this.#pending}${chunk}`.split(/\r\n|\n|\r/u);
        this.#pending = lines.pop() ?? '';
        for (const line of lines) this.#push(line);
    }

    snapshot(): readonly string[] {
        this.#push(this.#pending);
        this.#pending = '';
        return [...this.#lines];
    }

    #push(line: string): void {
        const plainLine = stripVTControlCharacters(line);
        if (plainLine.trim().length === 0) return;
        this.#lines.push(plainLine);
        if (this.#lines.length > recentOutputLineLimit) this.#lines.shift();
    }
}

type RenewalContext = Readonly<{
    checkoutRoot: string;
    commit: string;
    memoryLimit: number;
    monitorDirectory: string;
    placements: Readonly<Partial<Record<PlacementRole, ProcessorPlacement>>>;
    records: Map<string, EvidenceRenewalStepRecord>;
    attributedRuns: Set<string>;
    runLog: ActiveLocalRunLog;
}>;

const runOf = (
    records: ReadonlyMap<string, EvidenceRenewalStepRecord>,
    name: string,
): string => {
    const run = records.get(name)?.run;
    if (run === undefined)
        throw new Error(`The renewal records no run of ${name}.`);
    return run;
};

const stepInvocation = (
    step: EvidenceRenewalStep,
    context: RenewalContext,
): CommandInvocation => {
    if ('tool' in step.command)
        return {
            ...createPackageManagerCommand(
                step.description,
                [
                    'exec',
                    'tsx',
                    path.join(repositoryRoot, step.command.tool),
                    `--renewal=${context.runLog.runDirectoryPath}`,
                    ...(step.command.checkout === true
                        ? [`--checkout=${context.checkoutRoot}`]
                        : []),
                ],
                { logFileSlug: step.name },
            ),
            workingDirectoryPath: repositoryRoot,
        };
    const scriptArguments = stepScriptArguments(step, (name) =>
        runOf(context.records, name),
    );
    return {
        ...createPackageManagerCommand(
            step.description,
            [
                'run',
                step.command.script,
                ...(scriptArguments.length === 0
                    ? []
                    : ['--', ...scriptArguments]),
            ],
            { logFileSlug: step.name },
        ),
        workingDirectoryPath: context.checkoutRoot,
    };
};

// Starts the host-contention monitor under the step's placement and waits
// for its first probe. Its stop ends the sampling, waits for the last probe
// and refuses a failed monitor.
const startMonitor = async (
    step: EvidenceRenewalStep,
    placement: ProcessorPlacement,
    context: RenewalContext,
): Promise<{ readonly stop: () => Promise<void> }> => {
    await mkdir(context.monitorDirectory, { recursive: true });
    const stopFile = path.join(context.monitorDirectory, `${step.name}.stop`);
    const readyFile = `${stopFile}.ready`;
    const controller = new AbortController();
    const invocation: CommandInvocation = {
        ...createPackageManagerCommand(
            `Host-contention monitor around ${step.name}`,
            [
                'exec',
                'tsx',
                path.join(
                    repositoryRoot,
                    'tools/ci/monitor-host-contention.ts',
                ),
                `--label=${step.name}`,
                `--stop-file=${stopFile}`,
                ...[...new Set([repositoryRoot, context.checkoutRoot])].map(
                    (ownPath) => `--own-path=${ownPath}`,
                ),
            ],
            { logFileSlug: `${step.name}-monitor` },
        ),
        workingDirectoryPath: repositoryRoot,
    };
    let settled = false;
    const finished = runCommandAndCaptureOutput(
        placeCommand(invocation, placement),
        { runLog: context.runLog, signal: controller.signal },
    ).finally(() => {
        settled = true;
    });
    const failure = async (problem: string) => {
        controller.abort(new Error(problem));
        const result = await finished.catch((error: unknown) => ({
            stderr: errorMessage(error),
            stdout: '',
        }));
        const output = `${result.stdout}\n${result.stderr}`.trim();
        return new Error(
            output.length === 0 ? problem : `${problem}\n${output}`,
        );
    };
    const deadline = performance.now() + monitorReadyLimitMilliseconds;
    while (!existsSync(readyFile)) {
        if (settled)
            throw await failure(
                `The host-contention monitor for ${step.name} ended before its first probe.`,
            );
        if (performance.now() > deadline)
            throw await failure(
                `The host-contention monitor for ${step.name} gave no first probe within five minutes.`,
            );
        await delay(1000);
    }
    return {
        stop: async () => {
            await writeFile(stopFile, '');
            const timer = setTimeout(
                () =>
                    controller.abort(
                        new Error('The monitor outlasted its stop limit.'),
                    ),
                monitorStopLimitMilliseconds,
            );
            try {
                const result = await finished;
                if (result.exitCode !== 0 || result.terminationSignal !== null)
                    throw new Error(
                        `The host-contention monitor for ${step.name} failed:\n${`${result.stdout}\n${result.stderr}`.trim()}`,
                    );
            } finally {
                clearTimeout(timer);
                await rm(stopFile, { force: true });
                await rm(readyFile, { force: true });
            }
        },
    };
};

type StepOutcome = Readonly<{
    durationMilliseconds: number;
    record: EvidenceRenewalStepRecord;
    recentOutput: readonly string[];
}>;

const runStep = async (
    step: EvidenceRenewalStep,
    context: RenewalContext,
): Promise<StepOutcome> => {
    const startedAt = new Date();
    const started = performance.now();
    const placement =
        step.placement === undefined
            ? undefined
            : context.placements[step.placement];
    const failures: string[] = [];
    const recent = new RecentOutput();
    let exitCode = 1;
    let peakProcessTreeBytes = 0;
    let invocation: CommandInvocation | undefined;
    try {
        invocation = stepInvocation(step, context);
    } catch (error) {
        failures.push(errorMessage(error));
    }
    context.runLog.writeEvent({
        details: {
            name: step.name,
            ...(invocation === undefined
                ? {}
                : {
                      arguments: invocation.args,
                      command: invocation.command,
                      workingDirectoryPath: invocation.workingDirectoryPath,
                  }),
            ...(placement === undefined
                ? {}
                : { placement: describeProcessorPlacement(placement) }),
        },
        eventType: 'renewal-step-started',
    });
    let monitor: { readonly stop: () => Promise<void> } | undefined;
    if (
        invocation !== undefined &&
        step.monitored === true &&
        placement !== undefined
    ) {
        try {
            monitor = await startMonitor(step, placement, context);
        } catch (error) {
            failures.push(errorMessage(error));
        }
    }
    if (invocation !== undefined && failures.length === 0) {
        const controller = new AbortController();
        const timer = setTimeout(
            () =>
                controller.abort({
                    classification: 'lane-timeout',
                    limitMilliseconds: stepLimitMilliseconds,
                }),
            stepLimitMilliseconds,
        );
        let guard: { readonly stop: () => Promise<void> } | undefined;
        try {
            exitCode = await runCommandsInSeries(
                [
                    placement === undefined
                        ? invocation
                        : placeCommand(invocation, placement),
                ],
                {
                    observer: {
                        onCommandOutput: ({ chunk }) => recent.append(chunk),
                        onCommandStart: ({ processIdentifier }) => {
                            if (processIdentifier === undefined) return;
                            guard = guardProcessTreeMemory({
                                processIdentifier,
                                memoryLimit: context.memoryLimit,
                                exceededMessage: `${step.name} exceeded the renewal's process-tree memory limit of ${String(context.memoryLimit)} bytes.`,
                                sampleIntervalMilliseconds:
                                    memorySampleIntervalMilliseconds,
                                onSample: (bytes) => {
                                    peakProcessTreeBytes = Math.max(
                                        peakProcessTreeBytes,
                                        bytes,
                                    );
                                    context.runLog.writeEvent({
                                        details: {
                                            bytes,
                                            memoryLimit: context.memoryLimit,
                                            name: step.name,
                                        },
                                        eventType: 'renewal-memory-sample',
                                    });
                                },
                                abort: (reason) => {
                                    failures.push(errorMessage(reason));
                                    controller.abort(reason);
                                },
                            });
                        },
                    },
                    outputMode: 'capture',
                    runLog: context.runLog,
                    signal: controller.signal,
                },
            );
        } catch (error) {
            failures.push(errorMessage(error));
        } finally {
            clearTimeout(timer);
            await guard?.stop();
        }
        if (
            (
                controller.signal.reason as
                    { classification?: unknown } | undefined
            )?.classification === 'lane-timeout'
        )
            failures.push(
                `${step.name} exceeded its ${formatDuration(stepLimitMilliseconds)} limit.`,
            );
    }
    if (monitor !== undefined) {
        try {
            await monitor.stop();
        } catch (error) {
            failures.push(errorMessage(error));
        }
    }
    const children = (
        await listChildRuns({
            parentRunDirectoryPath: context.runLog.runDirectoryPath,
            repositoryRoot,
            since: new Date(startedAt.getTime() - 1000),
        })
    ).filter((child) => !context.attributedRuns.has(child.run));
    for (const child of children) context.attributedRuns.add(child.run);
    const monitorRuns = children.filter(
        (child) => child.scriptName === monitorScriptName,
    );
    const stepRuns = children.filter(
        (child) => child.scriptName !== monitorScriptName,
    );
    const ownRuns = stepRuns.filter((child) => child.scriptName === step.run);
    const run = ownRuns.length === 1 ? ownRuns[0].run : undefined;
    if (exitCode === 0 && failures.length === 0) {
        if (step.run !== undefined && run === undefined)
            failures.push(
                `${step.name} created ${String(ownRuns.length)} ${step.run} runs instead of one.`,
            );
        if (run !== undefined) {
            let result: unknown;
            try {
                result = (
                    JSON.parse(
                        await readFile(
                            path.join(repositoryRoot, run, 'summary.json'),
                            'utf8',
                        ),
                    ) as { result?: unknown }
                ).result;
            } catch (error) {
                result = `unreadable (${errorMessage(error)})`;
            }
            if (result !== 'passed')
                failures.push(
                    `${run} did not pass; its summary result is ${String(result)}.`,
                );
        }
        if (monitor !== undefined && monitorRuns.length !== 1)
            failures.push(
                `${step.name} has ${String(monitorRuns.length)} monitor runs instead of one.`,
            );
    }
    const record: EvidenceRenewalStepRecord = {
        name: step.name,
        exitCode,
        ...(failures.length === 0 ? {} : { failure: failures.join('\n') }),
        startedAtIso: startedAt.toISOString(),
        finishedAtIso: new Date().toISOString(),
        commit: context.commit,
        runs: stepRuns.map((child) => child.run),
        ...(run === undefined ? {} : { run }),
        ...(monitorRuns.length === 1 ? { monitorRun: monitorRuns[0].run } : {}),
        ...(placement === undefined
            ? {}
            : { placement: describeProcessorPlacement(placement) }),
        ...(peakProcessTreeBytes === 0 ? {} : { peakProcessTreeBytes }),
        renewal: repositoryRelativeRun(
            repositoryRoot,
            context.runLog.runDirectoryPath,
        ),
    };
    return {
        durationMilliseconds: performance.now() - started,
        record,
        recentOutput: recent.snapshot(),
    };
};

// The step's command line as the plan prints it, with the runs of carried
// steps and placeholders for runs this invocation creates.
const describeCommand = (
    step: EvidenceRenewalStep,
    carried: ReadonlyMap<string, EvidenceRenewalStepRecord>,
): string => {
    if ('tool' in step.command)
        return `tsx ${step.command.tool} --renewal=<this renewal>${step.command.checkout === true ? ' --checkout=<renewed checkout>' : ''}`;
    const scriptArguments = stepScriptArguments(
        step,
        (name) => carried.get(name)?.run ?? `<run of ${name}>`,
    );
    return [
        'pnpm run',
        step.command.script,
        ...(scriptArguments.length === 0 ? [] : ['--', ...scriptArguments]),
    ].join(' ');
};

const formatPlan = (
    plan: EvidenceRenewalPlan,
    input: Readonly<{
        checkout: string;
        placements: RenewalContext['placements'];
        resumeSource?: string;
    }>,
): string => {
    const carried = new Map(
        plan.carried.map((record) => [record.name, record]),
    );
    const width = Math.max(
        ...evidenceRenewalSteps.map((step) => step.name.length),
    );
    const lines = [
        `Evidence renewal of ${input.checkout}`,
        ...(input.resumeSource === undefined
            ? []
            : [`Resumed from ${input.resumeSource}`]),
    ];
    for (const step of evidenceRenewalSteps) {
        const record = carried.get(step.name);
        if (record !== undefined) {
            lines.push(
                `  carried  ${step.name.padEnd(width)}  ${record.run ?? 'passed'}`,
            );
            continue;
        }
        if (!plan.run.includes(step)) continue;
        const notes = [
            ...(step.placement === undefined
                ? []
                : [
                      `${step.placement} placement ${describePlacement(input.placements[step.placement])}`,
                  ]),
            ...(step.monitored === true && input.placements.timing !== undefined
                ? ['monitored']
                : []),
        ];
        lines.push(
            `  run      ${step.name.padEnd(width)}  ${describeCommand(step, carried)}${notes.length === 0 ? '' : ` (${notes.join(', ')})`}`,
        );
    }
    return lines.join('\n') + '\n';
};

const resolveCommit = (revision: string): string =>
    execFileSync('git', ['rev-parse', '--verify', `${revision}^{commit}`], {
        cwd: repositoryRoot,
        encoding: 'utf8',
        windowsHide: true,
    }).trim();

// The package scripts of the renewed checkout: this checkout's working tree,
// or the worktree's commit.
const packageScripts = (worktreeCommit: string | undefined) => {
    const manifest =
        worktreeCommit === undefined
            ? readFileSync(path.join(repositoryRoot, 'package.json'), 'utf8')
            : execFileSync('git', ['show', `${worktreeCommit}:package.json`], {
                  cwd: repositoryRoot,
                  encoding: 'utf8',
                  windowsHide: true,
              });
    return new Set(
        Object.keys(
            (JSON.parse(manifest) as { scripts?: Record<string, string> })
                .scripts ?? {},
        ),
    );
};

const main = async (): Promise<void> => {
    const commandLineArguments = process.argv.slice(2);
    let options: ReturnType<typeof selectRenewalOptions>;
    try {
        options = selectRenewalOptions(commandLineArguments);
    } catch (error) {
        throw Object.assign(new Error(`${errorMessage(error)}\n\n${usage}`), {
            cause: error,
        });
    }
    validateEvidenceRenewalSteps(evidenceRenewalSteps);
    const resumeSource =
        options.resume === undefined ? undefined : path.resolve(options.resume);
    const plan = planEvidenceRenewal(evidenceRenewalSteps, {
        from: options.from,
        resumed:
            resumeSource === undefined
                ? undefined
                : await readEvidenceRenewalRecord(resumeSource),
    });
    const placements: Partial<Record<PlacementRole, ProcessorPlacement>> = {};
    for (const role of ['timing', 'background'] as const) {
        const value = options[`${role}-placement`];
        if (value === undefined) continue;
        placements[role] = parseProcessorPlacement(value);
        if (!plan.run.some((step) => step.placement === role))
            throw new Error(
                `No step this invocation runs uses the ${role} placement.`,
            );
    }
    const commit = resolveCommit(options.worktree ?? 'HEAD');
    const checkout =
        options.worktree === undefined
            ? `this checkout at ${commit}`
            : `a worktree at ${commit}`;
    const scripts = packageScripts(
        options.worktree === undefined ? undefined : commit,
    );
    const missing = new Set(
        plan.run.flatMap((step) =>
            'script' in step.command && !scripts.has(step.command.script)
                ? [step.command.script]
                : [],
        ),
    );
    if (missing.size > 0)
        throw new Error(
            `The package scripts of ${checkout} lack ${[...missing].join(', ')}.`,
        );
    if (options.plan === true) {
        process.stdout.write(
            formatPlan(plan, { checkout, placements, resumeSource }),
        );
        return;
    }
    await runWithLocalRunLog(
        {
            commandLineArguments,
            lanes: plan.run.map((step) => step.name),
            scriptName: 'research:evidence-renewal',
        },
        async (runLog) => {
            const releaseLock = await acquireEvidenceRenewalLock(
                runLog.runDirectoryPath,
                repositoryRoot,
            );
            const records = new Map<string, EvidenceRenewalStepRecord>();
            const outcomes = new Map<string, StepOutcome>();
            const cleanupFailures: string[] = [];
            const monitorDirectory = path.join(
                repositoryRoot,
                'temp',
                'evidence-renewal-monitors',
                path.basename(runLog.runDirectoryPath),
            );
            let failed: EvidenceRenewalStep | undefined;
            let worktree: RenewalWorktree | undefined;
            // A first interrupt stops the renewal after the running command
            // ends, which the command runner's own handler hastens, so the
            // worktree, monitor files and lock are still cleaned up; a second
            // one exits at once.
            let interrupted = false;
            const interrupt = (): void => {
                if (interrupted) process.exit(130);
                interrupted = true;
                process.stdout.write(
                    '\nStopping the renewal after cleanup; interrupt again to exit at once.\n',
                );
            };
            process.on('SIGINT', interrupt);
            process.on('SIGTERM', interrupt);
            try {
                if (options.worktree !== undefined)
                    worktree = await createRenewalWorktree({
                        commit,
                        name: path
                            .basename(runLog.runDirectoryPath)
                            .slice(0, 24),
                        repositoryRoot,
                        runLog,
                    });
                const context: RenewalContext = {
                    attributedRuns: new Set(),
                    checkoutRoot: worktree?.root ?? repositoryRoot,
                    commit,
                    memoryLimit: Math.floor(os.totalmem() / 2),
                    monitorDirectory,
                    placements,
                    records,
                    runLog,
                };
                runLog.writeEvent({
                    details: {
                        carried: plan.carried.map((record) => record.name),
                        checkoutRoot: context.checkoutRoot,
                        commit,
                        memoryLimit: context.memoryLimit,
                        placements: Object.fromEntries(
                            Object.entries(placements).map(
                                ([role, placement]) => [
                                    role,
                                    describeProcessorPlacement(placement),
                                ],
                            ),
                        ),
                        ...(resumeSource === undefined
                            ? {}
                            : { resumedFrom: resumeSource }),
                        run: plan.run.map((step) => step.name),
                    },
                    eventType: 'renewal-plan',
                });
                for (const record of plan.carried) {
                    records.set(record.name, record);
                    runLog.writeEvent({
                        details: record,
                        eventType: recordedStepEventType,
                    });
                }
                for (const [index, step] of plan.run.entries()) {
                    if (interrupted) break;
                    process.stdout.write(
                        `[${String(index + 1).padStart(2)}/${String(plan.run.length)}] ${step.name}: ${step.description}\n`,
                    );
                    const outcome = await runStep(step, context);
                    records.set(step.name, outcome.record);
                    outcomes.set(step.name, outcome);
                    runLog.writeEvent({
                        details: outcome.record,
                        eventType: recordedStepEventType,
                    });
                    const passed = stepPassed(outcome.record);
                    process.stdout.write(
                        `        ${passed ? 'passed' : 'failed'} in ${formatDuration(outcome.durationMilliseconds)}${outcome.record.run === undefined ? '' : ` (${outcome.record.run})`}\n`,
                    );
                    if (!passed) {
                        failed = step;
                        break;
                    }
                }
            } finally {
                process.off('SIGINT', interrupt);
                process.off('SIGTERM', interrupt);
                if (worktree !== undefined)
                    try {
                        await worktree.remove();
                    } catch (error) {
                        cleanupFailures.push(
                            `The worktree at ${worktree.root} could not be removed: ${errorMessage(error)}`,
                        );
                    }
                await rm(monitorDirectory, { force: true, recursive: true });
                await releaseLock();
            }
            const recorded = evidenceRenewalSteps.flatMap((step) => {
                const record = records.get(step.name);
                return record === undefined ? [] : [record];
            });
            await writeFile(
                path.join(runLog.runDirectoryPath, 'renewal-record.json'),
                JSON.stringify(
                    {
                        commit,
                        worktree: options.worktree !== undefined,
                        ...(resumeSource === undefined
                            ? {}
                            : { resumedFrom: resumeSource }),
                        steps: recorded,
                    },
                    null,
                    2,
                ) + '\n',
                { flag: 'wx' },
            );
            const carriedNames = new Set(
                plan.carried.map((record) => record.name),
            );
            const width = Math.max(
                ...evidenceRenewalSteps.map((step) => step.name.length),
            );
            const lines = ['', 'Evidence renewal summary'];
            for (const step of evidenceRenewalSteps) {
                const record = records.get(step.name);
                const outcome = outcomes.get(step.name);
                const status =
                    record === undefined
                        ? 'NOT RUN'
                        : carriedNames.has(step.name)
                          ? 'CARRIED'
                          : stepPassed(record)
                            ? 'PASSED'
                            : 'FAILED';
                lines.push(
                    `  ${status.padEnd(7)}  ${step.name.padEnd(width)}  ${[
                        outcome === undefined
                            ? ''
                            : formatDuration(outcome.durationMilliseconds),
                        record?.run ?? '',
                    ]
                        .filter(Boolean)
                        .join('  ')}`.trimEnd(),
                );
            }
            if (failed !== undefined) {
                const outcome = outcomes.get(failed.name);
                lines.push(
                    '',
                    `${failed.name} failed with exit code ${String(outcome?.record.exitCode)}.`,
                    ...(outcome?.record.failure === undefined
                        ? []
                        : [outcome.record.failure]),
                    ...(outcome === undefined ||
                    outcome.recentOutput.length === 0
                        ? []
                        : ['Recent output:', ...outcome.recentOutput]),
                    `Full output: ${path.join(runLog.runDirectoryPath, 'output.log')} (command ${failed.name})`,
                    `Resume with --resume=${path.relative(repositoryRoot, runLog.runDirectoryPath)}`,
                );
            }
            if (interrupted && failed === undefined)
                lines.push(
                    '',
                    `The renewal was interrupted; resume with --resume=${path.relative(repositoryRoot, runLog.runDirectoryPath)}`,
                );
            lines.push(...cleanupFailures);
            lines.push(
                `Renewal record: ${path.join(runLog.runDirectoryPath, 'renewal-record.json')}`,
                '',
            );
            process.stdout.write(lines.join('\n'));
            if (
                failed !== undefined ||
                interrupted ||
                cleanupFailures.length > 0
            )
                process.exitCode = 1;
        },
    );
};

if (import.meta.main) await main();
