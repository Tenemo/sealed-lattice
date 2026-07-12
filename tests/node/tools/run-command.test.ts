import path from 'node:path';

import { describe, expect, it, vi } from 'vitest';

import {
    buildPackageManagerEntryPointCandidates,
    resolvePackageManagerRunnerForPackageManager,
} from '#tools/ci/package-manager-runner';
import {
    createAbortableCommandSpawnOptions,
    describeProcessTerminationAttempt,
    installProcessSignalChildCleanup,
    killProcessTree,
    runCommandAndCaptureOutput,
} from '#tools/ci/run-command';
import { normalizeProcessStatus } from '#tools/ci/run-log-diagnostics';

describe('package manager runner resolution', () => {
    it('resolves a requested package manager through the shared runner helper', () => {
        const nodeExecutablePath = path.resolve(
            'toolchains',
            'node',
            'bin',
            'node',
        );
        const npmEntryPointCandidates = buildPackageManagerEntryPointCandidates(
            'npm',
            '',
            nodeExecutablePath,
        );
        const expectedNpmEntryPoint = npmEntryPointCandidates[1];
        if (expectedNpmEntryPoint === undefined) {
            throw new Error(
                'Expected the npm candidate list to include fallback entries.',
            );
        }

        const runner = resolvePackageManagerRunnerForPackageManager(
            'npm',
            path.resolve('toolchains', 'pnpm', 'bin', 'pnpm.cjs'),
            '',
            nodeExecutablePath,
            (candidatePath) => candidatePath === expectedNpmEntryPoint,
        );

        expect(runner).toEqual({
            command: nodeExecutablePath,
            commandArgumentsPrefix: [expectedNpmEntryPoint],
            kind: 'npm',
        });
    });
});

describe('asynchronous command output capture', () => {
    it('retains separate streamed output and the nonzero process status', async () => {
        const result = await runCommandAndCaptureOutput({
            args: [
                '--input-type=module',
                '--eval',
                [
                    "process.stdout.write('first-out\\n');",
                    "process.stderr.write('first-error\\n');",
                    "setTimeout(() => { process.stdout.write('last-out\\n'); process.exitCode = 7; }, 20);",
                ].join(' '),
            ],
            command: process.execPath,
            description: 'Exercise asynchronous captured command output',
        });

        expect(result).toMatchObject({
            exitCode: 7,
            stderr: 'first-error\n',
            stdout: 'first-out\nlast-out\n',
            terminationSignal: null,
        });
        expect(result.processStatus).toMatchObject({
            rawExitCode: 7,
            terminationSignal: null,
        });
    });
});

describe('abortable command process cleanup', () => {
    it('starts non-Windows commands in a process group', () => {
        const environment = { PATH: '/usr/bin' };

        expect(
            createAbortableCommandSpawnOptions(environment, 'inherit', 'linux'),
        ).toEqual({
            detached: true,
            env: environment,
            stdio: 'inherit',
        });
    });

    it('keeps Windows commands in the existing process tree', () => {
        const environment = { PATH: 'C:\\Windows\\System32' };

        expect(
            createAbortableCommandSpawnOptions(
                environment,
                ['ignore', 'pipe', 'pipe'],
                'win32',
            ),
        ).toEqual({
            detached: false,
            env: environment,
            stdio: ['ignore', 'pipe', 'pipe'],
        });
    });

    it('passes an explicit working directory to cross-platform commands', () => {
        const environment = { PATH: '/usr/bin' };
        const workingDirectoryPath = path.resolve('fuzz');

        expect(
            createAbortableCommandSpawnOptions(
                environment,
                'inherit',
                'linux',
                workingDirectoryPath,
            ),
        ).toEqual({
            cwd: workingDirectoryPath,
            detached: true,
            env: environment,
            stdio: 'inherit',
        });
    });

    it('signals the non-Windows process group before falling back to the direct child', () => {
        const childProcess = {
            kill: vi.fn(() => true),
            pid: 32_100,
        };
        const processGroupSignals: {
            readonly processIdentifier: number;
            readonly signal: NodeJS.Signals;
        }[] = [];

        killProcessTree(childProcess, {
            platform: 'linux',
            processGroupKiller: (processIdentifier, signal) => {
                processGroupSignals.push({ processIdentifier, signal });
            },
        });

        expect(processGroupSignals).toEqual([
            {
                processIdentifier: -32_100,
                signal: 'SIGTERM',
            },
        ]);
        expect(childProcess.kill).not.toHaveBeenCalled();
    });

    it('falls back to the direct child when process group signaling is unavailable', () => {
        const childProcess = {
            kill: vi.fn(() => true),
            pid: 32_101,
        };

        const result = killProcessTree(childProcess, {
            platform: 'linux',
            processGroupKiller: () => {
                throw new Error('process group is unavailable');
            },
        });

        expect(childProcess.kill).toHaveBeenCalledWith('SIGTERM');
        expect(result).toMatchObject({
            fallbackReason: {
                message: 'process group is unavailable',
                name: 'Error',
            },
            method: 'direct-child',
            succeeded: true,
        });
    });

    it('can force-kill a non-Windows process group after graceful shutdown fails', () => {
        const childProcess = {
            kill: vi.fn(() => true),
            pid: 32_103,
        };
        const processGroupSignals: {
            readonly processIdentifier: number;
            readonly signal: NodeJS.Signals;
        }[] = [];

        killProcessTree(childProcess, {
            platform: 'linux',
            processGroupKiller: (processIdentifier, signal) => {
                processGroupSignals.push({ processIdentifier, signal });
            },
            signal: 'SIGKILL',
        });

        expect(processGroupSignals).toEqual([
            {
                processIdentifier: -32_103,
                signal: 'SIGKILL',
            },
        ]);
        expect(childProcess.kill).not.toHaveBeenCalled();
    });

    it('keeps using taskkill for Windows process trees', () => {
        const childProcess = {
            kill: vi.fn(() => true),
            pid: 32_102,
        };
        const windowsTaskKiller = vi.fn(
            (
                command: string,
                commandArguments: readonly string[],
                options: { readonly stdio: 'ignore' },
            ) => ({ command, commandArguments, options }),
        );

        const result = killProcessTree(childProcess, {
            platform: 'win32',
            windowsTaskKiller,
        });

        expect(windowsTaskKiller).toHaveBeenCalledWith(
            'taskkill',
            ['/pid', '32102', '/t', '/f'],
            { stdio: 'ignore' },
        );
        expect(childProcess.kill).not.toHaveBeenCalled();
        expect(result).toMatchObject({
            actualMechanism: 'taskkill-tree-force',
            forced: true,
            method: 'windows-taskkill',
            processIdentifier: 32_102,
            requestedSignal: 'SIGTERM',
            succeeded: true,
        });
        expect(
            describeProcessTerminationAttempt({
                requestedSignal: 'SIGTERM',
                requestedStage: 'requested',
                result,
            }),
        ).toMatchObject({
            actualMechanism: 'taskkill-tree-force',
            actualSignal: null,
            forced: true,
            requestedSignal: 'SIGTERM',
            requestedStage: 'requested',
            stage: 'forced',
        });
    });

    it('kills active child processes on terminal signals and unregisters handlers', () => {
        const originalExitCode = process.exitCode;
        const childProcesses = new Set([
            {
                kill: vi.fn(() => true),
                pid: 41_001,
            },
            {
                kill: vi.fn(() => true),
                pid: 41_002,
            },
        ]);
        const listeners = new Map<string, () => void>();
        const processEvents = {
            off: vi.fn((signal: string, listener: () => void) => {
                if (listeners.get(signal) === listener) {
                    listeners.delete(signal);
                }

                return processEvents;
            }),
            on: vi.fn((signal: string, listener: () => void) => {
                listeners.set(signal, listener);

                return processEvents;
            }),
        };
        const killedProcessIds: number[] = [];
        const forceKilledProcessIds: number[] = [];
        let scheduledForceKill: (() => void) | undefined;

        try {
            const uninstall = installProcessSignalChildCleanup({
                activeChildProcesses: childProcesses,
                clearScheduledForceKill: vi.fn(),
                forceKillChildProcess: (childProcess) => {
                    if (childProcess.pid !== undefined) {
                        forceKilledProcessIds.push(childProcess.pid);
                    }
                },
                killChildProcess: (childProcess) => {
                    if (childProcess.pid !== undefined) {
                        killedProcessIds.push(childProcess.pid);
                    }
                },
                processEvents,
                scheduleForceKill: (callback, delayMilliseconds) => {
                    expect(delayMilliseconds).toBe(5_000);
                    scheduledForceKill = callback;

                    return 'force-kill-timer';
                },
            });

            listeners.get('SIGINT')?.();
            scheduledForceKill?.();
            uninstall();

            expect(processEvents.on).toHaveBeenCalledWith(
                'SIGINT',
                expect.any(Function),
            );
            expect(processEvents.on).toHaveBeenCalledWith(
                'SIGTERM',
                expect.any(Function),
            );
            expect(killedProcessIds).toEqual([41_001, 41_002]);
            expect(forceKilledProcessIds).toEqual([41_001, 41_002]);
            expect(processEvents.off).toHaveBeenCalledTimes(2);
            expect(listeners.size).toBe(0);
        } finally {
            process.exitCode = originalExitCode;
        }
    });
});

describe('process status normalization', () => {
    it('normalizes signed Windows statuses without losing their raw form', () => {
        expect(normalizeProcessStatus(-1_073_741_502, null)).toEqual({
            hexadecimalExitCode: '0xC0000142',
            rawExitCode: -1_073_741_502,
            signedExitCode: -1_073_741_502,
            symbolicStatus: 'STATUS_DLL_INIT_FAILED',
            terminationSignal: null,
            unsignedExitCode: 3_221_225_794,
        });
    });

    it.each([
        [0xc000_0005, 'STATUS_ACCESS_VIOLATION'],
        [0xc000_0017, 'STATUS_NO_MEMORY'],
        [0xc000_00fd, 'STATUS_STACK_OVERFLOW'],
        [0xc000_0374, 'STATUS_HEAP_CORRUPTION'],
        [0xc000_0602, 'STATUS_FAIL_FAST_EXCEPTION'],
    ] as const)(
        'names common Windows crash status 0x%s as %s',
        (unsignedStatus, symbolicStatus) => {
            expect(
                normalizeProcessStatus(unsignedStatus | 0, null),
            ).toMatchObject({
                hexadecimalExitCode: `0x${unsignedStatus
                    .toString(16)
                    .toUpperCase()
                    .padStart(8, '0')}`,
                symbolicStatus,
                unsignedExitCode: unsignedStatus,
            });
        },
    );

    it('keeps conventional shell signal decoding explicitly inferential', () => {
        expect(normalizeProcessStatus(143, null)).toMatchObject({
            conventionalShellSignal: {
                evidence: 'inferred-from-shell-convention',
                signalName: 'SIGTERM',
                signalNumber: 15,
            },
            rawExitCode: 143,
            terminationSignal: null,
        });
    });
});
