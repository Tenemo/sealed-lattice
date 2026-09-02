import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { promisify } from 'node:util';

import type { ActiveLocalRunLog } from './local-run-log.js';
import type { CommandRunObserver } from './run-command.js';

const execFileAsync = promisify(execFile);

export type ProcessMemoryRow = Readonly<{
    parentProcessIdentifier: number;
    processIdentifier: number;
    residentByteLength: number;
}>;

export type ProcessPrivateMemoryRow = Readonly<{
    processIdentifier: number;
    privateByteLength: number;
    residentByteLength: number;
}>;

export const parseWindowsProcessRows = (stdout: string): ProcessMemoryRow[] => {
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

export const parsePosixProcessRows = (stdout: string): ProcessMemoryRow[] =>
    stdout
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
                residentKiB === undefined ||
                processIdentifier < 0 ||
                parentProcessIdentifier < 0 ||
                residentKiB < 0
            ) {
                throw new Error('The POSIX process inventory is malformed.');
            }
            return {
                processIdentifier,
                parentProcessIdentifier,
                residentByteLength: residentKiB * 1_024,
            };
        });

export const sumProcessTreeResidentBytes = (
    rows: readonly ProcessMemoryRow[],
    rootProcessIdentifier: number,
): number => {
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
    return parsePosixProcessRows(stdout);
};

const processTreeResidentByteLength = async (
    rootProcessIdentifier: number,
): Promise<number> =>
    sumProcessTreeResidentBytes(
        process.platform === 'win32'
            ? await windowsProcessRows()
            : await posixProcessRows(),
        rootProcessIdentifier,
    );

const parsePrivateMemoryRows = (stdout: string): ProcessPrivateMemoryRow[] => {
    const parsed: unknown = JSON.parse(stdout.length === 0 ? '[]' : stdout);
    const records = Array.isArray(parsed) ? parsed : [parsed];
    return records.map((record) => {
        if (typeof record !== 'object' || record === null) {
            throw new Error(
                'The process private-memory inventory is malformed.',
            );
        }
        const value = record as Record<string, unknown>;
        const processIdentifier = Number(value.Id);
        const privateByteLength = Number(value.PrivateMemorySize64);
        const residentByteLength = Number(value.WorkingSet64);
        if (
            !Number.isSafeInteger(processIdentifier) ||
            !Number.isSafeInteger(privateByteLength) ||
            !Number.isSafeInteger(residentByteLength) ||
            processIdentifier < 0 ||
            privateByteLength < 0 ||
            residentByteLength < 0
        ) {
            throw new Error(
                'The process private-memory inventory contains invalid values.',
            );
        }
        return {
            processIdentifier,
            privateByteLength,
            residentByteLength,
        };
    });
};

const readWindowsPrivateMemory = async (
    processIdentifiers: readonly number[],
): Promise<ProcessPrivateMemoryRow[]> => {
    const identifierList = processIdentifiers.join(',');
    const script = [
        '$ErrorActionPreference = "Stop"',
        `$processIds = @(${identifierList})`,
        'Get-Process -ErrorAction Stop | Where-Object { $processIds -contains $_.Id } | Select-Object Id,PrivateMemorySize64,WorkingSet64 | ConvertTo-Json -Compress',
    ].join('; ');
    const { stdout } = await execFileAsync(
        'powershell.exe',
        ['-NoProfile', '-NonInteractive', '-Command', script],
        {
            encoding: 'utf8',
            maxBuffer: 4 * 1_024 * 1_024,
            windowsHide: true,
        },
    );
    return parsePrivateMemoryRows(stdout.trim());
};

const readLinuxPrivateMemory = async (
    processIdentifiers: readonly number[],
): Promise<ProcessPrivateMemoryRow[]> => {
    const rows: ProcessPrivateMemoryRow[] = [];
    for (const processIdentifier of processIdentifiers) {
        let contents: string;
        try {
            contents = await readFile(
                `/proc/${String(processIdentifier)}/smaps_rollup`,
                'utf8',
            );
        } catch {
            continue;
        }
        const valueKiB = (name: string): number => {
            const match = new RegExp(`^${name}:\\s+(\\d+)\\s+kB$`, 'mu').exec(
                contents,
            );
            return Number(match?.[1] ?? 0);
        };
        rows.push({
            processIdentifier,
            privateByteLength:
                (valueKiB('Private_Clean') + valueKiB('Private_Dirty')) * 1_024,
            residentByteLength: valueKiB('Rss') * 1_024,
        });
    }
    return rows;
};

export const readProcessPrivateMemory = async (
    processIdentifiers: readonly number[],
): Promise<ProcessPrivateMemoryRow[]> => {
    const identifiers = [...new Set(processIdentifiers)].sort(
        (left, right) => left - right,
    );
    if (
        identifiers.length === 0 ||
        identifiers.some(
            (identifier) =>
                !Number.isSafeInteger(identifier) || identifier <= 0,
        )
    ) {
        throw new Error('The process identifier inventory is invalid.');
    }
    if (process.platform === 'win32') {
        return readWindowsPrivateMemory(identifiers);
    }
    if (process.platform === 'linux') {
        return readLinuxPrivateMemory(identifiers);
    }
    throw new Error(
        'Private-memory counters are not implemented for this operating system.',
    );
};

export const createProcessTreeMemoryGuard = (input: {
    readonly abortController: AbortController;
    readonly byteLimit: number;
    readonly runLog: ActiveLocalRunLog;
    readonly sampleIntervalMilliseconds: number;
}): CommandRunObserver => {
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
        input.runLog.writeEvent({
            ...(commandIdentifier === undefined
                ? {}
                : { commandId: commandIdentifier }),
            details: {
                byteLimit: input.byteLimit,
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
            input.runLog.writeEvent({
                ...(commandIdentifier === undefined
                    ? {}
                    : { commandId: commandIdentifier }),
                details: {
                    byteLimit: input.byteLimit,
                    residentByteLength,
                    rootProcessIdentifier,
                },
                eventType: 'process-tree-memory-sample',
            });
            if (
                residentByteLength > input.byteLimit &&
                !input.abortController.signal.aborted
            ) {
                input.abortController.abort({
                    classification: 'memory-guard',
                    byteLimit: input.byteLimit,
                    residentByteLength,
                });
            }
        } catch (error) {
            if (!active) return;
            input.runLog.writeEvent({
                ...(commandIdentifier === undefined
                    ? {}
                    : { commandId: commandIdentifier }),
                details: {
                    error:
                        error instanceof Error ? error.message : String(error),
                },
                eventType: 'process-tree-memory-sample-failed',
            });
            if (!input.abortController.signal.aborted) {
                input.abortController.abort({
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
                input.abortController.abort({
                    classification: 'memory-guard-missing-process',
                });
                return;
            }
            commandIdentifier = event.logFiles?.commandId;
            rootProcessIdentifier = event.processIdentifier;
            active = true;
            input.runLog.writeEvent({
                ...(commandIdentifier === undefined
                    ? {}
                    : { commandId: commandIdentifier }),
                details: {
                    byteLimit: input.byteLimit,
                    rootProcessIdentifier,
                },
                eventType: 'process-tree-memory-guard-started',
            });
            void sample();
            timer = setInterval(
                () => void sample(),
                input.sampleIntervalMilliseconds,
            );
        },
        onCommandExit: stop,
    };
};
