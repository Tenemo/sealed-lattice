import { describe, expect, it, vi } from 'vitest';

import {
    installProcessSignalChildCleanup,
    killProcessTree,
    runCommandAndCaptureOutput,
} from '#tools/ci/run-command';

describe('command execution', () => {
    it('captures asynchronous output and a nonzero process status', async () => {
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
            description: 'Exercise captured output',
        });

        expect(result).toMatchObject({
            exitCode: 7,
            stderr: 'first-error\n',
            stdout: 'first-out\nlast-out\n',
            terminationSignal: null,
        });
    });
});

describe('command process cleanup', () => {
    it('signals the complete non-Windows process group', () => {
        const childProcess = {
            kill: vi.fn(() => true),
            pid: 32_100,
        };
        const processGroupKiller = vi.fn();

        const result = killProcessTree(childProcess, {
            platform: 'linux',
            processGroupKiller,
        });

        expect(processGroupKiller).toHaveBeenCalledWith(-32_100, 'SIGTERM');
        expect(childProcess.kill).not.toHaveBeenCalled();
        expect(result).toMatchObject({
            mechanism: 'process-group-signal',
            succeeded: true,
        });
    });

    it('falls back to the direct child when group signaling fails', () => {
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
            fallbackReason: { message: 'process group is unavailable' },
            mechanism: 'direct-signal',
            succeeded: true,
        });
    });

    it('uses taskkill for the complete Windows process tree', () => {
        const childProcess = {
            kill: vi.fn(() => true),
            pid: 32_102,
        };
        const windowsTaskKiller = vi.fn();

        const result = killProcessTree(childProcess, {
            platform: 'win32',
            windowsTaskKiller,
        });

        expect(windowsTaskKiller).toHaveBeenCalledWith(
            'taskkill',
            ['/pid', '32102', '/t', '/f'],
            { stdio: 'ignore', windowsHide: true },
        );
        expect(childProcess.kill).not.toHaveBeenCalled();
        expect(result).toMatchObject({
            mechanism: 'taskkill-tree-force',
            succeeded: true,
        });
    });

    it('cleans up every child on terminal signals and unregisters handlers', () => {
        const originalExitCode = process.exitCode;
        const childProcesses = new Set([
            { kill: vi.fn(() => true), pid: 41_001 },
            { kill: vi.fn(() => true), pid: 41_002 },
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
        const gracefulKill = vi.fn(() => ({
            mechanism: 'direct-signal' as const,
            succeeded: true,
        }));
        const forceKill = vi.fn(() => ({
            mechanism: 'direct-signal' as const,
            succeeded: true,
        }));
        let scheduledForceKill: (() => void) | undefined;

        try {
            const uninstall = installProcessSignalChildCleanup({
                activeChildProcesses: childProcesses,
                clearScheduledForceKill: vi.fn(),
                forceKillChildProcess: forceKill,
                killChildProcess: gracefulKill,
                processEvents,
                scheduleForceKill: (callback) => {
                    scheduledForceKill = callback;
                    return 'timer';
                },
            });

            listeners.get('SIGTERM')?.();
            scheduledForceKill?.();
            uninstall();

            expect(gracefulKill).toHaveBeenCalledTimes(2);
            expect(forceKill).toHaveBeenCalledTimes(2);
            expect(listeners.size).toBe(0);
        } finally {
            process.exitCode = originalExitCode;
        }
    });
});
