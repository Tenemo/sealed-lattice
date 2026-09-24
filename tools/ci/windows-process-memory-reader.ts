import assert from 'node:assert/strict';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { Socket } from 'node:net';

export interface WindowsProcessMemory {
    Id: number;
    ProcessName: string;
    Started: string;
    PrivateMemorySize64: number;
    PeakPagedMemorySize64: number;
}

const script = String.raw`
$ErrorActionPreference = 'Stop'
while ($null -ne ($line = [Console]::ReadLine())) {
    $request = $line | ConvertFrom-Json
    try {
        $rows = [System.Collections.Generic.List[object]]::new()
        foreach ($identifier in $request.identifiers) {
            $process = $null
            try {
                $process = [System.Diagnostics.Process]::GetProcessById([int]$identifier)
                $process.Refresh()
                # Property access suppresses getter exceptions in PowerShell.
                # Invoke getters so an exit during sampling reaches the catches.
                $rows.Add([pscustomobject]@{
                    Id = $process.get_Id()
                    ProcessName = $process.get_ProcessName()
                    Started = $process.get_StartTime().ToUniversalTime().Ticks.ToString()
                    PrivateMemorySize64 = $process.get_PrivateMemorySize64()
                    PeakPagedMemorySize64 = $process.get_PeakPagedMemorySize64()
                })
            } catch [System.ArgumentException] {
                # A requested process has exited.
                if ($null -ne $process) { throw }
            } catch [System.InvalidOperationException] {
                # It exited between obtaining and reading its handle.
                if ($null -eq $process -or -not $process.get_HasExited()) { throw }
            } finally {
                if ($null -ne $process) { $process.Dispose() }
            }
        }
        [Console]::WriteLine((@{id=$request.id; rows=@($rows.ToArray())} | ConvertTo-Json -Compress -Depth 4))
    } catch {
        [Console]::WriteLine((@{id=$request.id; error=$_.Exception.GetType().Name} | ConvertTo-Json -Compress))
    }
}
`;

// One helper belongs to this reader. Every request obtains fresh counters for
// the requested process IDs; neither cached measurements nor retries are used.
export const createWindowsProcessMemoryReader = (
    options: {
        launch?: () => ChildProcessWithoutNullStreams;
        timeoutMilliseconds?: number;
    } = {},
) => {
    const child = options.launch
        ? options.launch()
        : spawn(
              'powershell.exe',
              ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', script],
              {
                  windowsHide: true,
                  stdio: 'pipe',
              },
          );
    const timeoutMilliseconds = options.timeoutMilliseconds ?? 10_000;
    let sequence = 0;
    let buffer = '';
    let failure: Error | undefined;
    let pending:
        | {
              id: number;
              resolve: (rows: WindowsProcessMemory[]) => void;
              reject: (error: Error) => void;
              timer: ReturnType<typeof setTimeout>;
          }
        | undefined;
    const stop = (error: Error) => {
        failure ??= error;
        if (pending) {
            clearTimeout(pending.timer);
            pending.reject(error);
            pending = undefined;
        }
        child.kill();
    };
    const close = () => stop(new Error('Process memory reader closed.'));
    process.once('exit', close);
    child.once('close', () => {
        process.removeListener('exit', close);
        stop(new Error('Process memory helper exited.'));
    });
    child.once('error', (error) => stop(error));
    child.stdin.on('error', (error) => stop(error));
    child.stderr.on('data', () =>
        stop(new Error('Process memory helper reported an error.')),
    );
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk: string) => {
        try {
            buffer += chunk;
            if (buffer.length > 262_144)
                throw new Error('Oversized process memory response.');
            let newline: number;
            while ((newline = buffer.indexOf('\n')) >= 0) {
                const line = buffer.slice(0, newline);
                buffer = buffer.slice(newline + 1);
                const response = JSON.parse(line) as {
                    id?: unknown;
                    rows?: unknown;
                    error?: unknown;
                };
                if (!pending || response.id !== pending.id)
                    throw new Error('Unexpected process memory response.');
                if (response.error !== undefined)
                    throw new Error(
                        'Native process query failed: ' +
                            (typeof response.error === 'string'
                                ? response.error
                                : 'Malformed error'),
                    );
                if (!Array.isArray(response.rows))
                    throw new Error('Malformed process memory response.');
                for (const row of response.rows as WindowsProcessMemory[]) {
                    assert.ok(Number.isSafeInteger(row.Id) && row.Id > 0);
                    assert.ok(
                        typeof row.ProcessName === 'string' &&
                            /^\d+$/u.test(row.Started),
                    );
                    assert.ok(
                        Number.isSafeInteger(row.PrivateMemorySize64) &&
                            row.PrivateMemorySize64 >= 0,
                    );
                    assert.ok(
                        Number.isSafeInteger(row.PeakPagedMemorySize64) &&
                            row.PeakPagedMemorySize64 >=
                                row.PrivateMemorySize64,
                    );
                }
                const completed = pending;
                pending = undefined;
                clearTimeout(completed.timer);
                completed.resolve(response.rows as WindowsProcessMemory[]);
            }
        } catch (error) {
            stop(
                error instanceof Error
                    ? error
                    : new Error('Process memory response failed.'),
            );
        }
    });
    // Pending-request deadlines keep an active sample alive. An idle reader
    // does not keep its runner alive; the exit handler terminates its helper.
    child.unref();
    for (const stream of [child.stdin, child.stdout, child.stderr])
        if (stream instanceof Socket) stream.unref();
    return {
        close,
        read(identifiers: readonly number[]): Promise<WindowsProcessMemory[]> {
            if (failure) return Promise.reject(failure);
            if (pending)
                return Promise.reject(
                    new Error('Concurrent process memory requests.'),
                );
            if (
                !identifiers.length ||
                identifiers.some((id) => !Number.isSafeInteger(id) || id <= 0)
            )
                return Promise.reject(
                    new Error('Invalid process memory identifiers.'),
                );
            return new Promise((resolve, reject) => {
                const id = ++sequence;
                const timer = setTimeout(
                    () => stop(new Error('Process memory query deadline.')),
                    timeoutMilliseconds,
                );
                pending = { id, resolve, reject, timer };
                child.stdin.write(JSON.stringify({ id, identifiers }) + '\n');
            });
        },
    };
};
