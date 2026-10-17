import { execFile } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { setTimeout as delay } from 'node:timers/promises';
import { parseArgs, promisify } from 'node:util';

import { repositoryRoot, toolArguments } from '#tools/ci/command-line.js';
import {
    createPackageManagerCommand,
    runCommandAndCaptureOutput,
    type CommandInvocation,
} from '#tools/ci/command-runner.js';
import {
    runWithLocalRunLog,
    type ActiveLocalRunLog,
} from '#tools/ci/local-run-log.js';
import {
    placeCommand,
    processorJobSource,
    type ProcessorPlacement,
} from '#tools/ci/processor-placement.js';

// Records how busy the host is around a timed step and how much that load
// slows one single-threaded workload under this process's placement. It times
// a fixed SHA-512 workload, writes `<stop file>.ready`, samples once a minute
// the logical processors that its shared job and the rest of the host keep
// busy, and includes the final partial interval when stopped. The job includes
// the monitor, the workload and terminated descendants. The end probe follows
// the last CPU sample. Only aggregate processor use is recorded.
const usage =
    'Usage: monitor-host-contention.ts --label=<step> --stop-file=<path> --job=<accounting job>';
export const hostContentionMonitorScriptName = 'monitor-host-contention';
const readyLimitMilliseconds = 5 * 60_000;
const stopLimitMilliseconds = 10 * 60_000;
const sampleSeconds = 60;
const stopPollMilliseconds = 5_000;
const longIterations = 12_000;
const shortIterations = 120;
const longRepetitions = 3;
const shortRepetitions = 50;

export const selectMonitorOptions = (
    commandLineArguments: readonly string[],
) => {
    const { values } = parseArgs({
        args: [...toolArguments(commandLineArguments)],
        options: {
            label: { type: 'string' },
            job: { type: 'string' },
            'stop-file': { type: 'string' },
        },
        strict: true,
    });
    if (
        values.label === undefined ||
        !/^[a-z0-9]+(?:-[a-z0-9]+)*$/u.test(values.label) ||
        values['stop-file'] === undefined ||
        !values.job
    )
        throw new Error(usage);
    return {
        label: values.label,
        job: values.job,
        stopFile: path.resolve(values['stop-file']),
    };
};

const block = Buffer.alloc(64 * 1024, 7);
const hashChain = (iterations: number): number => {
    let digest = block;
    for (let index = 0; index < iterations; index++)
        digest = createHash('sha512')
            .update(block)
            .update(digest.subarray(0, 64))
            .digest();
    return digest[0];
};
const time = (iterations: number): number => {
    const started = performance.now();
    hashChain(iterations);
    return performance.now() - started;
};

// The median long repetition against the fastest short one scaled to the long
// length. Short repetitions seldom meet contention, so their minimum
// estimates the uncontended time.
export const estimateProbeSlowdown = (
    longMilliseconds: readonly number[],
    shortMilliseconds: readonly number[],
    iterationRatio: number,
) => {
    if (longMilliseconds.length === 0 || shortMilliseconds.length === 0)
        throw new Error('A probe needs long and short repetitions.');
    const median = [...longMilliseconds].sort((left, right) => left - right)[
        Math.floor(longMilliseconds.length / 2)
    ];
    const uncontended = Math.min(...shortMilliseconds) * iterationRatio;
    return {
        longMilliseconds: longMilliseconds.map((value) => Math.round(value)),
        medianMilliseconds: Math.round(median),
        uncontendedEstimateMilliseconds: Math.round(uncontended),
        slowdown: Math.round((median / uncontended) * 1000) / 1000,
    };
};

const probe = () => {
    hashChain(2_000);
    const long = Array.from({ length: longRepetitions }, () =>
        time(longIterations),
    );
    const short = Array.from({ length: shortRepetitions }, () =>
        time(shortIterations),
    );
    return estimateProbeSlowdown(long, short, longIterations / shortIterations);
};

const powerShell = async (script: string): Promise<string> =>
    (
        await promisify(execFile)(
            'powershell.exe',
            [
                '-NoProfile',
                '-NonInteractive',
                '-EncodedCommand',
                Buffer.from(script, 'utf16le').toString('base64'),
            ],
            {
                encoding: 'utf8',
                maxBuffer: 16 * 1024 * 1024,
                windowsHide: true,
            },
        )
    ).stdout;

// This process's processor affinity and priority class as Windows reports
// them, which show the placement it inherited.
const readPlacement = async () => {
    const [affinity, priorityClass] = (
        await powerShell(
            `$p = Get-Process -Id ${String(process.pid)}; '{0:X} {1}' -f [int64]$p.ProcessorAffinity, $p.PriorityClass`,
        )
    )
        .trim()
        .split(' ');
    return {
        affinityMask: '0x' + affinity,
        priorityClass,
        availableParallelism: os.availableParallelism(),
        logicalProcessors: os.cpus().length,
    };
};

export type CpuTimes = Readonly<{
    at: number;
    busySeconds: number;
    ownSeconds: number;
}>;

// The helper reads host and job counters together, with one monotonic timestamp.
// Host kernel time includes idle time; the native reader subtracts it.
// Job totals include terminated processes and descendants in nested jobs.
export const readCpuTimes = async (job: string): Promise<CpuTimes> => {
    if (process.platform !== 'win32' || os.cpus().length > 64)
        throw new Error(
            'Host CPU accounting requires Windows with at most 64 logical processors.',
        );
    const name = Buffer.from(job, 'utf8').toString('base64');
    const output = await powerShell(
        [
            "$ErrorActionPreference = 'Stop'",
            "$source = @'",
            processorJobSource,
            "'@",
            'Add-Type -TypeDefinition $source',
            `$name = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${name}'))`,
            '[ProcessorPlacementJob]::CpuTimes($name)',
        ].join('\n'),
    );
    const values = output.trim().split('|').map(Number);
    if (
        values.length !== 3 ||
        values.some((value) => !Number.isFinite(value) || value < 0)
    )
        throw new Error('The host CPU counters are malformed.');
    const [at, busySeconds, ownSeconds] = values;
    return { at, busySeconds, ownSeconds };
};

export const busyProcessors = (previous: CpuTimes, current: CpuTimes) => {
    const elapsedSeconds = (current.at - previous.at) / 1000;
    if (!(elapsedSeconds > 0))
        throw new Error('CPU-time readings must advance in time.');
    const busySeconds = current.busySeconds - previous.busySeconds;
    const ownSeconds = current.ownSeconds - previous.ownSeconds;
    if (busySeconds < 0 || ownSeconds < 0)
        throw new Error('Cumulative CPU counters must not decrease.');
    // Separate API reads can straddle a scheduling tick. Do not report
    // negative background use when the job counter leads the host slightly.
    const otherSeconds = Math.max(0, busySeconds - ownSeconds);
    const round = (value: number) => Math.round(value * 1000) / 1000;
    return {
        elapsedSeconds,
        ownSeconds,
        otherSeconds,
        ownProcessors: round(ownSeconds / elapsedSeconds),
        otherProcessors: round(otherSeconds / elapsedSeconds),
    };
};

type CpuSample = ReturnType<typeof busyProcessors>;

export const summarizeCpuLoad = (samples: readonly CpuSample[]) => {
    const seconds = samples.reduce(
        (sum, sample) => sum + sample.elapsedSeconds,
        0,
    );
    const rate = (field: 'ownSeconds' | 'otherSeconds') =>
        seconds === 0
            ? undefined
            : Math.round(
                  (samples.reduce((sum, sample) => sum + sample[field], 0) /
                      seconds) *
                      100,
              ) / 100;
    return {
        samples: samples.length,
        sampleSeconds,
        measuredSeconds: seconds,
        meanOwnProcessors: rate('ownSeconds'),
        meanOtherProcessors: rate('otherSeconds'),
        peakOtherProcessors:
            samples.length === 0
                ? undefined
                : Math.max(...samples.map((sample) => sample.otherProcessors)),
    };
};

// Baseline before readiness, then every interval and the final partial interval.
// A stopped short workload therefore still contributes an actual measurement.
export const sampleCpuLoad = async (
    input: Readonly<{
        read: () => Promise<CpuTimes>;
        ready: () => Promise<void>;
        stopped: Promise<void>;
        record: (sample: CpuSample) => void;
    }>,
) => {
    const samples: CpuSample[] = [];
    let previous = await input.read();
    await input.ready();
    for (;;) {
        let timer!: ReturnType<typeof setTimeout>;
        const elapsed = new Promise<boolean>((resolve) => {
            timer = setTimeout(() => resolve(false), sampleSeconds * 1000);
        });
        let stopped: boolean;
        try {
            stopped = await Promise.race([
                input.stopped.then(() => true),
                elapsed,
            ]);
        } finally {
            clearTimeout(timer);
        }
        const current = await input.read();
        const sample = busyProcessors(previous, current);
        samples.push(sample);
        input.record(sample);
        previous = current;
        if (stopped) return samples;
    }
};

// Starts the monitor around a step under the step's placement and waits for
// its first probe. Its stop ends the sampling, waits for the last probe and
// refuses a failed monitor.
export const startHostContentionMonitor = async (
    input: Readonly<{
        directory: string;
        label: string;
        placement: ProcessorPlacement;
        runLog: ActiveLocalRunLog;
    }>,
): Promise<{ readonly job: string; readonly stop: () => Promise<void> }> => {
    await mkdir(input.directory, { recursive: true });
    const stopFile = path.join(input.directory, `${input.label}.stop`);
    const readyFile = `${stopFile}.ready`;
    const controller = new AbortController();
    const job = 'Local\\sealed-lattice-contention-' + randomUUID();
    const invocation: CommandInvocation = {
        ...createPackageManagerCommand(
            `Host-contention monitor around ${input.label}`,
            [
                'exec',
                'tsx',
                path.join(
                    repositoryRoot,
                    'tools/ci/monitor-host-contention.ts',
                ),
                `--label=${input.label}`,
                `--stop-file=${stopFile}`,
                `--job=${job}`,
            ],
            { logFileSlug: `${input.label}-monitor` },
        ),
        workingDirectoryPath: repositoryRoot,
    };
    let settled = false;
    const finished = runCommandAndCaptureOutput(
        placeCommand(invocation, input.placement, { name: job, create: true }),
        { runLog: input.runLog, signal: controller.signal },
    ).finally(() => {
        settled = true;
    });
    const failure = async (problem: string) => {
        controller.abort(new Error(problem));
        const result = await finished.catch((error: unknown) => ({
            stderr: error instanceof Error ? error.message : String(error),
            stdout: '',
        }));
        const output = `${result.stdout}\n${result.stderr}`.trim();
        return new Error(
            output.length === 0 ? problem : `${problem}\n${output}`,
        );
    };
    const deadline = performance.now() + readyLimitMilliseconds;
    while (!existsSync(readyFile)) {
        if (settled)
            throw await failure(
                `The host-contention monitor for ${input.label} ended before its first probe.`,
            );
        if (performance.now() > deadline)
            throw await failure(
                `The host-contention monitor for ${input.label} gave no first probe within five minutes.`,
            );
        await delay(1000);
    }
    return {
        job,
        stop: async () => {
            await writeFile(stopFile, '');
            const timer = setTimeout(
                () =>
                    controller.abort(
                        new Error('The monitor outlasted its stop limit.'),
                    ),
                stopLimitMilliseconds,
            );
            try {
                const result = await finished;
                if (result.exitCode !== 0 || result.terminationSignal !== null)
                    throw new Error(
                        `The host-contention monitor for ${input.label} failed:\n${`${result.stdout}\n${result.stderr}`.trim()}`,
                    );
            } finally {
                clearTimeout(timer);
                await rm(stopFile, { force: true });
                await rm(readyFile, { force: true });
            }
        },
    };
};

const main = async (): Promise<void> => {
    const commandLineArguments = process.argv.slice(2);
    const options = selectMonitorOptions(commandLineArguments);
    if (process.platform !== 'win32')
        throw new Error(
            'The host-contention monitor reads Windows process times and placement, so it runs only on Windows.',
        );
    await runWithLocalRunLog(
        {
            commandLineArguments,
            scriptName: hostContentionMonitorScriptName,
        },
        async (log) => {
            const placement = await readPlacement();
            log.writeEvent({
                eventType: 'host-contention-placement',
                details: placement,
            });
            const start = probe();
            log.writeEvent({
                eventType: 'host-contention-probe',
                details: { phase: 'start', ...start },
            });
            const samples = await sampleCpuLoad({
                read: () => readCpuTimes(options.job),
                ready: () =>
                    writeFile(
                        `${options.stopFile}.ready`,
                        options.label + '\n',
                        { flag: 'wx' },
                    ),
                stopped: (async () => {
                    while (!existsSync(options.stopFile))
                        await delay(stopPollMilliseconds);
                })(),
                record: (sample) =>
                    log.writeEvent({
                        eventType: 'host-contention-sample',
                        details: sample,
                    }),
            });
            const end = probe();
            log.writeEvent({
                eventType: 'host-contention-probe',
                details: { phase: 'end', ...end },
            });
            await writeFile(
                path.join(log.runDirectoryPath, 'evidence.json'),
                JSON.stringify(
                    {
                        label: options.label,
                        placement,
                        probes: { start, end },
                        load: summarizeCpuLoad(samples),
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
