import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { setTimeout } from 'node:timers/promises';
import { promisify } from 'node:util';

// A process's identifier, its recorded parent's, its private bytes and,
// where the host reports it, when it started in milliseconds.
type ProcessMemory = Readonly<{
    identifier: number;
    parent: number;
    bytes: number;
    started?: number;
}>;

// Sums the private bytes of the process and its descendants. Windows keeps
// an exited parent's identifier, which a later process may take, so a
// process that started before the process of its parent's identifier is
// not that process's child.
export const sumProtocolProcessTree = (
    identifier: number,
    processes: readonly ProcessMemory[],
): number | undefined => {
    const started = new Map(
        processes.map((process) => [process.identifier, process.started]),
    );
    if (!started.has(identifier)) {
        return undefined;
    }
    const owned = new Set([identifier]);
    let changed = true;
    while (changed) {
        changed = false;
        for (const process of processes) {
            const parentStarted = started.get(process.parent);
            if (
                owned.has(process.parent) &&
                !owned.has(process.identifier) &&
                (process.started === undefined ||
                    parentStarted === undefined ||
                    process.started >= parentStarted)
            ) {
                owned.add(process.identifier);
                changed = true;
            }
        }
    }
    return processes.reduce((total, process) => {
        assert.ok(Number.isSafeInteger(process.bytes) && process.bytes >= 0);
        return total + (owned.has(process.identifier) ? process.bytes : 0);
    }, 0);
};

// Reads every process's parent and private bytes, and on Windows when it
// started, in one snapshot, from which several process trees can be summed.
// Elsewhere an exited parent's children pass to another process, so their
// recorded parent is alive.
export const readProtocolProcesses = async (): Promise<
    readonly ProcessMemory[]
> => {
    const execute = promisify(execFile);
    if (process.platform === 'win32') {
        const result = await execute(
            'powershell.exe',
            [
                '-NoProfile',
                '-Command',
                "$taskRows = @(Get-CimInstance Win32_Process -ErrorAction Stop | Select-Object ProcessId,ParentProcessId,PrivatePageCount,@{Name='Started';Expression={if ($_.CreationDate) { [math]::Floor($_.CreationDate.ToFileTimeUtc() / 10000) } else { $null }}}); ConvertTo-Json -Compress -InputObject $taskRows",
            ],
            { windowsHide: true, timeout: 10_000, maxBuffer: 2 ** 22 },
        );
        const rows = JSON.parse(result.stdout) as {
            ProcessId: number;
            ParentProcessId: number;
            PrivatePageCount: number | string;
            Started: number | null;
        }[];
        assert.ok(Array.isArray(rows));
        return rows.map((row) => ({
            identifier: row.ProcessId,
            parent: row.ParentProcessId,
            bytes: Number(row.PrivatePageCount),
            ...(row.Started === null ? {} : { started: row.Started }),
        }));
    }
    const result = await execute('ps', ['-axo', 'pid=,ppid=,rss='], {
        timeout: 10_000,
        maxBuffer: 2 ** 22,
    });
    return result.stdout
        .trim()
        .split(/\r?\n/u)
        .map((line) => {
            const values = line.trim().split(/\s+/u).map(Number);
            assert.equal(values.length, 3);
            return {
                identifier: values[0],
                parent: values[1],
                bytes: values[2] * 1024,
            };
        });
};

export const readProtocolProcessTree = async (
    identifier: number,
): Promise<number | undefined> => {
    assert.ok(Number.isSafeInteger(identifier) && identifier > 0);
    return sumProtocolProcessTree(identifier, await readProtocolProcesses());
};

// Samples a process tree's memory once a second until stopped. Every sample
// reaches `onSample`, and a sample above the limit aborts the guarded run with
// the guard's message.
export const guardProcessTreeMemory = (input: {
    readonly processIdentifier: number;
    readonly memoryLimit: number;
    readonly exceededMessage: string;
    readonly onSample: (bytes: number) => void;
    readonly abort: (reason: unknown) => void;
}): { readonly stop: () => Promise<void> } => {
    let active = true;
    const sampling = (async () => {
        while (active) {
            const bytes = await readProtocolProcessTree(
                input.processIdentifier,
            );
            if (bytes !== undefined) {
                input.onSample(bytes);
                if (bytes > input.memoryLimit)
                    throw new Error(input.exceededMessage);
            }
            if (active) await setTimeout(1000);
        }
    })().catch((error: unknown) => {
        input.abort(error);
    });
    return {
        stop: async () => {
            active = false;
            await sampling;
        },
    };
};
