import path from 'node:path';

import { describe, expect, it, vi } from 'vitest';

import {
    buildPackageManagerEntryPointCandidates,
    resolvePackageManagerRunnerForPackageManager,
    resolvePackageManagerRunnerFromArguments,
} from '#tools/ci/package-manager-runner';
import {
    createAbortableCommandSpawnOptions,
    killProcessTree,
} from '#tools/ci/run-command';

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

    it('uses the same runner helper for command-line package manager overrides', () => {
        const nodeExecutablePath = path.resolve(
            'toolchains',
            'node',
            'bin',
            'node',
        );
        const expectedNpmEntryPoint = buildPackageManagerEntryPointCandidates(
            'npm',
            '',
            nodeExecutablePath,
        )[0];
        if (expectedNpmEntryPoint === undefined) {
            throw new Error(
                'Expected the npm candidate list to include an entry.',
            );
        }

        const runner = resolvePackageManagerRunnerFromArguments(
            ['--package-manager', 'npm'],
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

        killProcessTree(childProcess, {
            platform: 'linux',
            processGroupKiller: () => {
                throw new Error('process group is unavailable');
            },
        });

        expect(childProcess.kill).toHaveBeenCalledWith('SIGTERM');
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

        killProcessTree(childProcess, {
            platform: 'win32',
            windowsTaskKiller,
        });

        expect(windowsTaskKiller).toHaveBeenCalledWith(
            'taskkill',
            ['/pid', '32102', '/t', '/f'],
            { stdio: 'ignore' },
        );
        expect(childProcess.kill).not.toHaveBeenCalled();
    });
});
