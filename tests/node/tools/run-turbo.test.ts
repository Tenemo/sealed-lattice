import { describe, expect, it } from 'vitest';

import {
    buildTurboInvocation,
    cacheOverrideEnvironmentVariableName,
    getPnpmExecutableName,
    splitTurboArguments,
} from '../../../tools/run-turbo';

describe('Turbo runner helper', () => {
    it('splits task names from Turbo arguments', () => {
        expect(
            splitTurboArguments([
                'build',
                'check',
                '--filter=@sealed-lattice/wasm',
            ]),
        ).toEqual({
            tasks: ['build', 'check'],
            turboArguments: ['--filter=@sealed-lattice/wasm'],
        });
    });

    it('requires at least one task name', () => {
        expect(() => splitTurboArguments(['--filter=sealed-lattice'])).toThrow(
            'At least one Turbo task name is required.',
        );
    });

    it('selects the correct pnpm executable for each platform', () => {
        expect(getPnpmExecutableName('win32')).toBe('pnpm.cmd');
        expect(getPnpmExecutableName('linux')).toBe('pnpm');
    });

    it('builds a Turbo invocation without a cache override', () => {
        const originalCacheOverride =
            process.env[cacheOverrideEnvironmentVariableName];

        delete process.env[cacheOverrideEnvironmentVariableName];

        try {
            expect(buildTurboInvocation(['build'], undefined, 'linux')).toEqual(
                {
                    command: 'pnpm',
                    args: ['exec', 'turbo', 'run', 'build'],
                },
            );
        } finally {
            if (originalCacheOverride === undefined) {
                delete process.env[cacheOverrideEnvironmentVariableName];
            } else {
                process.env[cacheOverrideEnvironmentVariableName] =
                    originalCacheOverride;
            }
        }
    });

    it('appends the configured cache override', () => {
        expect(
            buildTurboInvocation(
                ['build', 'check'],
                'local:,remote:',
                'win32',
                'C:\\Windows\\System32\\cmd.exe',
            ),
        ).toEqual({
            command: 'C:\\Windows\\System32\\cmd.exe',
            args: [
                '/d',
                '/s',
                '/c',
                'pnpm.cmd',
                'exec',
                'turbo',
                'run',
                'build',
                'check',
                '--cache=local:,remote:',
            ],
        });
    });

    it('uses the environment cache override when no explicit override is provided', () => {
        const originalCacheOverride =
            process.env[cacheOverrideEnvironmentVariableName];

        process.env[cacheOverrideEnvironmentVariableName] = 'local:,remote:';

        try {
            expect(buildTurboInvocation(['build'], undefined, 'linux')).toEqual(
                {
                    command: 'pnpm',
                    args: [
                        'exec',
                        'turbo',
                        'run',
                        'build',
                        '--cache=local:,remote:',
                    ],
                },
            );
        } finally {
            if (originalCacheOverride === undefined) {
                delete process.env[cacheOverrideEnvironmentVariableName];
            } else {
                process.env[cacheOverrideEnvironmentVariableName] =
                    originalCacheOverride;
            }
        }
    });

    it('uses the documented cache override environment variable name', () => {
        expect(cacheOverrideEnvironmentVariableName).toBe(
            'SEALED_LATTICE_TURBO_CACHE',
        );
    });
});
