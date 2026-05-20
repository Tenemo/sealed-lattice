import { describe, expect, it } from 'vitest';

import {
    buildTurboInvocation,
    cacheOverrideEnvironmentVariableName,
    splitTurboArguments,
} from '#tools/run-turbo';

const nodePackageManagerRunner = {
    command: process.execPath,
    commandArgumentsPrefix: ['/tools/pnpm.cjs'],
} as const;

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

    it('builds a Turbo invocation without a cache override', () => {
        const originalCacheOverride =
            process.env[cacheOverrideEnvironmentVariableName];

        delete process.env[cacheOverrideEnvironmentVariableName];

        try {
            expect(
                buildTurboInvocation(
                    ['build'],
                    undefined,
                    nodePackageManagerRunner,
                ),
            ).toEqual({
                command: process.execPath,
                args: ['/tools/pnpm.cjs', 'exec', 'turbo', 'run', 'build'],
            });
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
                nodePackageManagerRunner,
            ),
        ).toEqual({
            command: process.execPath,
            args: [
                '/tools/pnpm.cjs',
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
            expect(
                buildTurboInvocation(
                    ['build'],
                    undefined,
                    nodePackageManagerRunner,
                ),
            ).toEqual({
                command: process.execPath,
                args: [
                    '/tools/pnpm.cjs',
                    'exec',
                    'turbo',
                    'run',
                    'build',
                    '--cache=local:,remote:',
                ],
            });
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
