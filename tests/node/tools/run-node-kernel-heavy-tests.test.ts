import path from 'node:path';

import { describe, expect, it } from 'vitest';

import type { PackageManagerRunner } from '#tools/ci/package-manager-runner';
import { buildNodeKernelHeavyTestCommand } from '#tools/ci/run-node-kernel-heavy-tests';

const packageManagerRunner: PackageManagerRunner = {
    command: 'node',
    commandArgumentsPrefix: ['pnpm-entry.js'],
    kind: 'pnpm',
};

describe('heavy Node kernel runner', () => {
    it('runs the heavy project inside the measured Node memory envelope', () => {
        const runDirectoryPath = path.resolve('logs', 'heavy-node-test');
        const command = buildNodeKernelHeavyTestCommand({
            packageManagerRunner,
            runDirectoryPath,
        });

        expect(command.command).toContain(
            'sealed-lattice-process-memory-guard',
        );
        expect(command.args).toContain('--memory-limit-bytes');
        expect(command.args).toContain(
            '--virtual-address-space-allowance-bytes',
        );
        expect(command.args).toContain(String(32 * 1024 ** 3));
        expect(command.args).toContain('node-kernel-heavy');
        expect(command.env).toMatchObject({
            SEALED_LATTICE_RUN_DIRECTORY: runDirectoryPath,
            SEALED_LATTICE_TEST_PROJECT_LABEL: 'node-kernel-heavy',
        });
    });
});
