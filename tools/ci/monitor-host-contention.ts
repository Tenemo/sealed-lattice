import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { setTimeout as delay } from 'node:timers/promises';
import { parseArgs, promisify } from 'node:util';

import { toolArguments } from '#tools/ci/command-line.js';
import { runWithLocalRunLog } from '#tools/ci/local-run-log.js';

// Records how busy the host is around a timed step and how much that load
// slows one single-threaded workload under this process's placement. It times
// a fixed SHA-512 workload, writes `<stop file>.ready`, samples once a minute
// the logical processors that the renewal's own processes and all other
// processes keep busy until the stop file exists, and times the workload
// again. Only aggregate processor use is recorded, never another program's
// name or command line.
const usage =
    'Usage: monitor-host-contention.ts --label=<step> --stop-file=<path> --own-path=<checkout>...';
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
            'own-path': { type: 'string', multiple: true },
            'stop-file': { type: 'string' },
        },
        strict: true,
    });
    const ownPaths = values['own-path'] ?? [];
    if (
        values.label === undefined ||
        !/^[a-z0-9]+(?:-[a-z0-9]+)*$/u.test(values.label) ||
        values['stop-file'] === undefined ||
        ownPaths.length === 0
    )
        throw new Error(usage);
    return {
        label: values.label,
        ownPaths: ownPaths.map((ownPath) => path.resolve(ownPath)),
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

type ProcessTimes = Readonly<{
    at: number;
    times: ReadonlyMap<string, Readonly<{ seconds: number; own: boolean }>>;
}>;

// Parses `identifier|name|processor seconds|own` lines. A process is keyed by
// identifier and name, so a reused identifier starts a new process; the idle
// process is no load.
export const parseProcessTimes = (output: string, at: number): ProcessTimes => {
    const times = new Map<string, { seconds: number; own: boolean }>();
    for (const line of output.split(/\r?\n/u)) {
        const fields = line.split('|');
        if (fields.length !== 4) continue;
        const [identifier, name, seconds, own] = fields;
        const processorSeconds = Number(seconds);
        if (
            !/^\d+$/u.test(identifier) ||
            identifier === '0' ||
            !Number.isFinite(processorSeconds)
        )
            continue;
        times.set(`${identifier} ${name}`, {
            seconds: processorSeconds,
            own: own === '1',
        });
    }
    return { at, times };
};

// The logical processors the renewal's own processes and all others kept
// busy between two readings, over processes present in both.
export const busyProcessors = (
    previous: ProcessTimes,
    current: ProcessTimes,
) => {
    const elapsedSeconds = (current.at - previous.at) / 1000;
    if (!(elapsedSeconds > 0))
        throw new Error('Process-time readings must advance in time.');
    let own = 0;
    let other = 0;
    for (const [key, { seconds, own: isOwn }] of current.times) {
        const before = previous.times.get(key);
        if (before === undefined) continue;
        const delta = Math.max(0, seconds - before.seconds);
        if (isOwn) own += delta;
        else other += delta;
    }
    const round = (value: number) => Math.round(value * 1000) / 1000;
    return {
        ownProcessors: round(own / elapsedSeconds),
        otherProcessors: round(other / elapsedSeconds),
    };
};

// Every process's processor seconds, and whether its command line names one
// of the renewal's checkouts, which their Node, Chrome and Rust processes do.
const readProcessTimes = async (ownPaths: readonly string[]) => {
    const markers = Buffer.from(
        JSON.stringify(
            ownPaths.map((ownPath) =>
                ownPath.toLowerCase().replace(/\//gu, '\\'),
            ),
        ),
        'utf8',
    ).toString('base64');
    const output = await powerShell(
        [
            `$markers = @([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${markers}')) | ConvertFrom-Json)`,
            'Get-CimInstance Win32_Process | ForEach-Object {',
            "    $line = ([string]$_.CommandLine).ToLowerInvariant().Replace('/', '\\')",
            '    $own = 0',
            '    foreach ($marker in $markers) { if ($line.Contains($marker)) { $own = 1 } }',
            "    [string]::Format([cultureinfo]::InvariantCulture, '{0}|{1}|{2}|{3}', $_.ProcessId, $_.Name, ($_.KernelModeTime + $_.UserModeTime) / 1e7, $own)",
            '}',
        ].join('\n'),
    );
    return parseProcessTimes(output, performance.now());
};

const mean = (values: readonly number[]) =>
    values.length === 0
        ? undefined
        : Math.round(
              (values.reduce((sum, value) => sum + value, 0) / values.length) *
                  100,
          ) / 100;

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
            lanes: ['Host contention around a timed step'],
            scriptName: 'monitor-host-contention',
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
            await writeFile(`${options.stopFile}.ready`, options.label + '\n', {
                flag: 'wx',
            });
            const samples: {
                ownProcessors: number;
                otherProcessors: number;
            }[] = [];
            let previous = await readProcessTimes(options.ownPaths);
            let nextSample = performance.now() + sampleSeconds * 1000;
            while (!existsSync(options.stopFile)) {
                await delay(stopPollMilliseconds);
                if (performance.now() < nextSample) continue;
                const current = await readProcessTimes(options.ownPaths);
                const sample = busyProcessors(previous, current);
                samples.push(sample);
                log.writeEvent({
                    eventType: 'host-contention-sample',
                    details: sample,
                });
                previous = current;
                nextSample += sampleSeconds * 1000;
            }
            const end = probe();
            log.writeEvent({
                eventType: 'host-contention-probe',
                details: { phase: 'end', ...end },
            });
            const others = samples.map((sample) => sample.otherProcessors);
            await writeFile(
                path.join(log.runDirectoryPath, 'evidence.json'),
                JSON.stringify(
                    {
                        label: options.label,
                        placement,
                        probes: { start, end },
                        load: {
                            samples: samples.length,
                            sampleSeconds,
                            meanOtherProcessors: mean(others),
                            peakOtherProcessors:
                                others.length === 0
                                    ? undefined
                                    : Math.max(...others),
                            meanOwnProcessors: mean(
                                samples.map((sample) => sample.ownProcessors),
                            ),
                        },
                        scope: 'Development observation of this host while it stays in ordinary use. The probe times one fixed single-threaded SHA-512 workload under this process’s placement; its slowdown compares the median long repetition with the scaled minimum of short repetitions.',
                        limitations: [
                            'The probe workload stays in the processor caches, so it does not show how unrelated load slows memory-bound work.',
                            'The uncontended estimate is the fastest short repetition, not a measurement on an idle host.',
                            'Own processes are those whose command line names one of the renewal’s checkouts.',
                        ],
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
