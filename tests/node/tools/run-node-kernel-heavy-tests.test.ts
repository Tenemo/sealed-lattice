import path from 'node:path';

import { describe, expect, it } from 'vitest';

import type { PackageManagerRunner } from '#tools/ci/package-manager-runner';
import {
    buildNodeKernelHeavyGuardVerificationCommand,
    buildNodeKernelHeavyTestCommand,
} from '#tools/ci/run-node-kernel-heavy-tests';

const packageManagerRunner: PackageManagerRunner = {
    command: 'node',
    commandArgumentsPrefix: ['pnpm-entry.js'],
    kind: 'pnpm',
};

describe('heavy Node kernel runner', () => {
    it('wraps the heavy Vitest project in the process-memory guard', () => {
        const runDirectoryPath = path.resolve('logs', 'heavy-node-test');
        const command = buildNodeKernelHeavyTestCommand({
            packageManagerRunner,
            runDirectoryPath,
        });

        expect(command.command).toContain(
            'sealed-lattice-process-memory-guard',
        );
        expect(command.args.slice(0, 7)).toEqual([
            '--memory-limit-bytes',
            expect.stringMatching(/^[1-9][0-9]*$/u),
            '--virtual-address-space-allowance-bytes',
            String(32 * 1024 ** 3),
            '--diagnostics-path',
            path.join(
                runDirectoryPath,
                'resources',
                'process-memory-guard-node-kernel-heavy.jsonl',
            ),
            '--',
        ]);
        expect(command.args.slice(7)).toEqual([
            'node',
            'pnpm-entry.js',
            'exec',
            'vitest',
            '--project',
            'node-kernel-heavy',
            '--run',
        ]);
        expect(command.env?.SEALED_LATTICE_TEST_PROJECT_LABEL).toBe(
            'node-kernel-heavy',
        );
        expect(command.env?.SEALED_LATTICE_RUN_DIRECTORY).toBe(
            runDirectoryPath,
        );
    });

    it('verifies the guard binary before running the heavy project', () => {
        const command = buildNodeKernelHeavyGuardVerificationCommand();

        expect(command.command).toBe('cargo');
        expect(command.args).toContain('sealed-lattice-process-memory-guard');
        expect(command.args).toContain('--test-threads');
        expect(command.args).toContain('1');
    });
});
