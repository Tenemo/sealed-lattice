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
        expect(buildTurboInvocation(['build'], undefined, 'linux')).toEqual({
            command: 'pnpm',
            args: ['exec', 'turbo', 'run', 'build'],
        });
    });

    it('appends the configured cache override', () => {
        expect(
            buildTurboInvocation(
                ['check', 'check:workspace'],
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
                'check',
                'check:workspace',
                '--cache=local:,remote:',
            ],
        });
    });

    it('uses the documented cache override environment variable name', () => {
        expect(cacheOverrideEnvironmentVariableName).toBe(
            'SEALED_LATTICE_TURBO_CACHE',
        );
    });
});
