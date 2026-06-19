import { describe, expect, it } from 'vitest';

import { requiredRustHeavyEvidenceTests } from '#tools/ci/heavy-evidence-tests';
import type { PackageManagerRunner } from '#tools/ci/package-manager-runner';
import {
    createDirectBallotSetupHandoffEvidenceCommands,
    directBallotSetupHandoffPublicParityTestPaths,
    formatDirectBallotSetupHandoffEvidenceCommandPlan,
    shouldListDirectBallotSetupHandoffEvidenceCommands,
    unknownDirectBallotSetupHandoffEvidenceOptions,
} from '#tools/ci/run-direct-ballot-setup-handoff-evidence';

const packageManagerRunner = {
    command: 'node',
    commandArgumentsPrefix: ['pnpm.cjs'],
    kind: 'pnpm',
} as const satisfies PackageManagerRunner;

describe('direct ballot setup handoff evidence runner', () => {
    it('prints a manual command plan without running heavy evidence', () => {
        expect(
            shouldListDirectBallotSetupHandoffEvidenceCommands(['--list']),
        ).toBe(true);

        const commandPlan = formatDirectBallotSetupHandoffEvidenceCommandPlan(
            createDirectBallotSetupHandoffEvidenceCommands({
                packageManagerRunner,
                requiredRustHeavyEvidenceTests:
                    requiredRustHeavyEvidenceTests.slice(0, 1),
                targetDirectory: 'C:/workspace/target/heavy-required-evidence',
                testThreadCount: 1,
            }),
        );

        expect(commandPlan).toContain('Manual lane only.');
        expect(commandPlan).toContain('Build workspace packages');
        expect(commandPlan).toContain(
            'cargo test ' + requiredRustHeavyEvidenceTests[0].testName,
        );
        for (const testPath of directBallotSetupHandoffPublicParityTestPaths) {
            expect(commandPlan).toContain(testPath);
        }
        expect(commandPlan).toContain(
            'Verify test lane coverage and manual heavy evidence registry',
        );
    });

    it('rejects unknown options', () => {
        expect(
            unknownDirectBallotSetupHandoffEvidenceOptions(['--unknown']),
        ).toEqual(['--unknown']);
    });

    it('creates a build, required Rust heavy evidence, public parity, and lane coverage command sequence', () => {
        const selectedHeavyTest =
            requiredRustHeavyEvidenceTests[
                requiredRustHeavyEvidenceTests.length - 1
            ];
        if (selectedHeavyTest === undefined) {
            throw new Error('required Rust heavy evidence tests are empty.');
        }

        const targetDirectory = 'C:/workspace/target/heavy-required-evidence';
        const commands = createDirectBallotSetupHandoffEvidenceCommands({
            baseEnvironment: {
                EXISTING_VARIABLE: 'preserved',
            },
            packageManagerRunner,
            requiredRustHeavyEvidenceTests: [selectedHeavyTest],
            targetDirectory,
            testThreadCount: 2,
        });

        expect(commands).toHaveLength(4);
        expect(commands[0]).toMatchObject({
            args: ['pnpm.cjs', 'run', 'build'],
            command: 'node',
            description: 'Build workspace packages',
            logFileSlug: 'build',
        });
        expect(commands[1]).toMatchObject({
            args: [
                'test',
                '-p',
                'sealed-lattice-kernel',
                selectedHeavyTest.testName,
                '--',
                '--ignored',
                '--nocapture',
                '--test-threads',
                '2',
            ],
            command: 'cargo',
            description: `cargo test ${selectedHeavyTest.testName} (required heavy evidence)`,
            env: {
                CARGO_INCREMENTAL: '1',
                CARGO_TARGET_DIR: targetDirectory,
                EXISTING_VARIABLE: 'preserved',
                SEALED_LATTICE_RESUME_TEST_CHECKPOINTS: '1',
            },
            logFileSlug: `cargo-test-required-heavy-evidence-${selectedHeavyTest.testName}`,
        });
        expect(commands[2]).toMatchObject({
            args: [
                'pnpm.cjs',
                'exec',
                'vitest',
                'run',
                ...directBallotSetupHandoffPublicParityTestPaths,
            ],
            command: 'node',
            description:
                'Run direct ballot setup handoff SDK/WASM public package parity tests',
            logFileSlug: 'direct-ballot-setup-handoff-public-parity',
        });
        expect(commands[3]).toMatchObject({
            args: [
                'pnpm.cjs',
                'exec',
                'tsx',
                'tools/ci/verify-test-lane-coverage.ts',
            ],
            command: 'node',
            description:
                'Verify test lane coverage and manual heavy evidence registry',
            logFileSlug: 'verify-test-lane-coverage',
        });
    });
});
