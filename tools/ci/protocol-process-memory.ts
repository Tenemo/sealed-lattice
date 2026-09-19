import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

type ProcessMemory = Readonly<{
    identifier: number;
    parent: number;
    bytes: number;
}>;

export const sumProtocolProcessTree = (
    identifier: number,
    processes: readonly ProcessMemory[],
): number | undefined => {
    if (!processes.some((process) => process.identifier === identifier)) {
        return undefined;
    }
    const owned = new Set([identifier]);
    let changed = true;
    while (changed) {
        changed = false;
        for (const process of processes) {
            if (owned.has(process.parent) && !owned.has(process.identifier)) {
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

export const readProtocolProcessTree = async (
    identifier: number,
): Promise<number | undefined> => {
    assert.ok(Number.isSafeInteger(identifier) && identifier > 0);
    const execute = promisify(execFile);
    if (process.platform === 'win32') {
        const result = await execute(
            'powershell.exe',
            [
                '-NoProfile',
                '-Command',
                '$taskRows = @(Get-CimInstance Win32_Process -ErrorAction Stop | Select-Object ProcessId,ParentProcessId,PrivatePageCount); ConvertTo-Json -Compress -InputObject $taskRows',
            ],
            { windowsHide: true, timeout: 10_000, maxBuffer: 2 ** 22 },
        );
        const rows = JSON.parse(result.stdout) as {
            ProcessId: number;
            ParentProcessId: number;
            PrivatePageCount: number | string;
        }[];
        assert.ok(Array.isArray(rows));
        return sumProtocolProcessTree(
            identifier,
            rows.map((row) => ({
                identifier: row.ProcessId,
                parent: row.ParentProcessId,
                bytes: Number(row.PrivatePageCount),
            })),
        );
    }
    const result = await execute('ps', ['-axo', 'pid=,ppid=,rss='], {
        timeout: 10_000,
        maxBuffer: 2 ** 22,
    });
    const rows = result.stdout
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
    return sumProtocolProcessTree(identifier, rows);
};
