import { execFile } from 'node:child_process';
import { mkdir, open, unlink } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';

import { runWithLocalRunLog, type ActiveLocalRunLog } from './local-run-log.js';
import { resolvePackageManagerRunner } from './package-manager-runner.js';
import {
    createPackageManagerCommand,
    runCommandAndCaptureOutput,
    runCommandsInSeries,
    type CommandRunObserver,
} from './run-command.js';

import {
    manualEvidenceCases,
    resolveManualEvidenceCase,
} from '#tests/manual-evidence-registry.js';

const execFileAsync = promisify(execFile);
const usage = `Usage: run-padded-tally-evidence.ts <${manualEvidenceCases
    .map((evidenceCase) => evidenceCase.identifier)
    .join('|')}>.`;
const repositoryRootPath = path.resolve(import.meta.dirname, '..', '..');
const lockDirectoryPath = path.join(
    repositoryRootPath,
    'temp',
    'test-checkpoints',
);
const lockFilePath = path.join(lockDirectoryPath, 'padded-tally-evidence.lock');
const memorySampleIntervalMilliseconds = 2_000;

type ProcessMemoryRow = Readonly<{
    parentProcessIdentifier: number;
    processIdentifier: number;
    residentByteLength: number;
}>;

const parseWindowsProcessRows = (stdout: string): ProcessMemoryRow[] => {
    const parsed: unknown = JSON.parse(stdout.length === 0 ? '[]' : stdout);
    const records = Array.isArray(parsed) ? parsed : [parsed];
    return records.map((record) => {
        if (typeof record !== 'object' || record === null) {
            throw new Error('The Windows process inventory is malformed.');
        }
        const value = record as Record<string, unknown>;
        const processIdentifier = Number(value.ProcessId);
        const parentProcessIdentifier = Number(value.ParentProcessId);
        const residentByteLength = Number(value.WorkingSetSize);
        if (
            !Number.isSafeInteger(processIdentifier) ||
            !Number.isSafeInteger(parentProcessIdentifier) ||
            !Number.isSafeInteger(residentByteLength) ||
            processIdentifier < 0 ||
            parentProcessIdentifier < 0 ||
            residentByteLength < 0
        ) {
            throw new Error(
                'The Windows process inventory contains invalid values.',
            );
        }
        return {
            parentProcessIdentifier,
            processIdentifier,
            residentByteLength,
        };
    });
};

const windowsProcessRows = async (): Promise<ProcessMemoryRow[]> => {
    const script = [
        '$ErrorActionPreference = "Stop"',
        'Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,WorkingSetSize | ConvertTo-Json -Compress',
    ].join('; ');
    const { stdout } = await execFileAsync(
        'powershell.exe',
        ['-NoProfile', '-NonInteractive', '-Command', script],
        {
            encoding: 'utf8',
            maxBuffer: 16 * 1_024 * 1_024,
            windowsHide: true,
        },
    );
    return parseWindowsProcessRows(stdout.trim());
};

const posixProcessRows = async (): Promise<ProcessMemoryRow[]> => {
    const { stdout } = await execFileAsync(
        'ps',
        ['-e', '-o', 'pid=', '-o', 'ppid=', '-o', 'rss='],
        { encoding: 'utf8', windowsHide: true },
    );
    return stdout
        .split(/\r?\n/gu)
        .map((line) => line.trim())
        .filter((line) => line.length > 0)
        .map((line) => {
            const fields = line.split(/\s+/gu).map(Number);
            const [processIdentifier, parentProcessIdentifier, residentKiB] =
                fields;
            if (
                !Number.isSafeInteger(processIdentifier) ||
                !Number.isSafeInteger(parentProcessIdentifier) ||
                !Number.isSafeInteger(residentKiB) ||
                processIdentifier === undefined ||
                parentProcessIdentifier === undefined ||
                residentKiB === undefined
            ) {
                throw new Error('The POSIX process inventory is malformed.');
            }
            return {
                processIdentifier,
                parentProcessIdentifier,
                residentByteLength: residentKiB * 1_024,
            };
        });
};

const processTreeResidentByteLength = async (
    rootProcessIdentifier: number,
): Promise<number> => {
    const rows =
        process.platform === 'win32'
            ? await windowsProcessRows()
            : await posixProcessRows();
    const childrenByParent = new Map<number, number[]>();
    const residentBytesByProcess = new Map<number, number>();
    for (const row of rows) {
        residentBytesByProcess.set(
            row.processIdentifier,
            row.residentByteLength,
        );
        const children =
            childrenByParent.get(row.parentProcessIdentifier) ?? [];
        children.push(row.processIdentifier);
        childrenByParent.set(row.parentProcessIdentifier, children);
    }
    const pending = [rootProcessIdentifier];
    const visited = new Set<number>();
    let total = 0;
    while (pending.length > 0) {
        const processIdentifier = pending.pop();
        if (processIdentifier === undefined || visited.has(processIdentifier)) {
            continue;
        }
        visited.add(processIdentifier);
        total += residentBytesByProcess.get(processIdentifier) ?? 0;
        pending.push(...(childrenByParent.get(processIdentifier) ?? []));
    }
    return total;
};

const createMemoryGuard = (
    byteLimit: number,
    runLog: ActiveLocalRunLog,
    abortController: AbortController,
): CommandRunObserver => {
    let timer: NodeJS.Timeout | undefined;
    let sampling = false;
    let active = false;
    let peakResidentByteLength = 0;
    let commandIdentifier: string | undefined;
    let rootProcessIdentifier: number | undefined;

    const stop = (): void => {
        active = false;
        if (timer !== undefined) clearInterval(timer);
        timer = undefined;
        runLog.writeEvent({
            ...(commandIdentifier === undefined
                ? {}
                : { commandId: commandIdentifier }),
            details: {
                byteLimit,
                peakResidentByteLength,
            },
            eventType: 'process-tree-memory-guard-finished',
        });
    };

    const sample = async (): Promise<void> => {
        if (!active || sampling || rootProcessIdentifier === undefined) return;
        sampling = true;
        try {
            const residentByteLength = await processTreeResidentByteLength(
                rootProcessIdentifier,
            );
            if (!active) return;
            peakResidentByteLength = Math.max(
                peakResidentByteLength,
                residentByteLength,
            );
            runLog.writeEvent({
                ...(commandIdentifier === undefined
                    ? {}
                    : { commandId: commandIdentifier }),
                details: {
                    byteLimit,
                    residentByteLength,
                    rootProcessIdentifier,
                },
                eventType: 'process-tree-memory-sample',
            });
            if (
                residentByteLength > byteLimit &&
                !abortController.signal.aborted
            ) {
                abortController.abort({
                    classification: 'memory-guard',
                    byteLimit,
                    residentByteLength,
                });
            }
        } catch (error) {
            if (!active) return;
            runLog.writeEvent({
                ...(commandIdentifier === undefined
                    ? {}
                    : { commandId: commandIdentifier }),
                details: {
                    error:
                        error instanceof Error ? error.message : String(error),
                },
                eventType: 'process-tree-memory-sample-failed',
            });
            if (!abortController.signal.aborted) {
                abortController.abort({
                    classification: 'memory-guard-sample-failed',
                });
            }
        } finally {
            sampling = false;
        }
    };

    return {
        onCommandStart: (event) => {
            if (event.processIdentifier === undefined) {
                abortController.abort({
                    classification: 'memory-guard-missing-process',
                });
                return;
            }
            commandIdentifier = event.logFiles?.commandId;
            rootProcessIdentifier = event.processIdentifier;
            active = true;
            runLog.writeEvent({
                ...(commandIdentifier === undefined
                    ? {}
                    : { commandId: commandIdentifier }),
                details: { byteLimit, rootProcessIdentifier },
                eventType: 'process-tree-memory-guard-started',
            });
            void sample();
            timer = setInterval(
                () => void sample(),
                memorySampleIntervalMilliseconds,
            );
        },
        onCommandExit: stop,
    };
};

const acquireSerializationLock = async (): Promise<() => Promise<void>> => {
    await mkdir(lockDirectoryPath, { recursive: true });
    let handle;
    try {
        handle = await open(lockFilePath, 'wx');
    } catch {
        throw new Error(
            `Another padded-tally evidence run owns ${lockFilePath}.`,
        );
    }
    await handle.writeFile(
        JSON.stringify({
            processIdentifier: process.pid,
            startedAtIso: new Date().toISOString(),
        }),
        'utf8',
    );
    await handle.sync();
    await handle.close();
    return async () => unlink(lockFilePath);
};

const requireSingleCase = (arguments_: readonly string[]): string => {
    if (
        arguments_.length !== 1 ||
        arguments_[0] === undefined ||
        arguments_[0].startsWith('-')
    ) {
        throw new Error(usage);
    }
    return arguments_[0];
};

const main = async (): Promise<void> => {
    const processArguments = process.argv.slice(2);
    const rawArguments =
        processArguments[0] === '--'
            ? processArguments.slice(1)
            : processArguments;
    const evidenceCase = resolveManualEvidenceCase(
        requireSingleCase(rawArguments),
    );
    const releaseLock = await acquireSerializationLock();
    try {
        await runWithLocalRunLog(
            {
                commandLineArguments: rawArguments,
                lanes: [evidenceCase.testName],
                resourceSampleIntervalMilliseconds:
                    memorySampleIntervalMilliseconds,
                scriptName: `evidence-${evidenceCase.identifier}`,
            },
            async (runLog) => {
                const packageManagerRunner = resolvePackageManagerRunner();
                const environment = { ...process.env };
                for (const registeredCase of manualEvidenceCases) {
                    environment[registeredCase.browserEnvironmentVariable] =
                        registeredCase.identifier === evidenceCase.identifier
                            ? '1'
                            : '0';
                }
                const buildExitCode = await runCommandsInSeries(
                    [
                        createPackageManagerCommand(
                            'Build the padded-tally evidence workspace',
                            ['run', 'build'],
                            {
                                env: environment,
                                logFileSlug: 'build',
                                packageManagerRunner,
                            },
                        ),
                    ],
                    { outputMode: 'inherit', runLog },
                );
                if (buildExitCode !== 0) {
                    process.exitCode = buildExitCode;
                    return;
                }
                const testArguments = [
                    '--project',
                    'browser-desktop',
                    '--testNamePattern',
                    evidenceCase.testName,
                    evidenceCase.testFile,
                ];
                const inventory = await runCommandAndCaptureOutput(
                    createPackageManagerCommand(
                        'Validate the padded-tally evidence selector',
                        ['exec', 'vitest', 'list', ...testArguments],
                        {
                            env: environment,
                            logFileSlug: 'test-inventory',
                            packageManagerRunner,
                        },
                    ),
                    { runLog },
                );
                if (
                    inventory.exitCode !== 0 ||
                    inventory.terminationSignal !== null ||
                    !inventory.stdout.includes(evidenceCase.testName)
                ) {
                    throw new Error(
                        'The padded-tally evidence selector matched zero tests.',
                    );
                }
                const abortController = new AbortController();
                const observer = createMemoryGuard(
                    evidenceCase.memoryLimitByteLength,
                    runLog,
                    abortController,
                );
                const exitCode = await runCommandsInSeries(
                    [
                        createPackageManagerCommand(
                            evidenceCase.testName,
                            ['exec', 'vitest', '--run', ...testArguments],
                            {
                                env: environment,
                                logFileSlug: 'padded-tally-evidence',
                                packageManagerRunner,
                            },
                        ),
                    ],
                    {
                        observer,
                        outputMode: 'inherit',
                        runLog,
                        signal: abortController.signal,
                    },
                );
                process.exitCode = exitCode || undefined;
                process.stdout.write(
                    `Padded-tally evidence log: ${runLog.runDirectoryPath}\n`,
                );
            },
        );
    } finally {
        await releaseLock();
    }
};

if (import.meta.main) void main();
