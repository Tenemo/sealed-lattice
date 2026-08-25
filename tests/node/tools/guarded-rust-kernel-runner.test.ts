import { describe, expect, it } from 'vitest';

import {
    buildGuardedRustEnvironment,
    buildGuardedRustKernelCommand,
    deriveGuardedRustMemoryLimitGigabytes,
    guardRustKernelCommand,
    resolveGuardedRustMemoryLimitGigabytes,
    verifyGuardedRustProcessMemoryGuardCommand,
} from '#tools/ci/guarded-rust-kernel-runner';

describe('Guarded Rust kernel runner', () => {
    it('pins serialized non-incremental execution without inheriting proof checkpoints', () => {
        const environment = buildGuardedRustEnvironment({
            baseEnvironment: {
                CARGO_TARGET_DIR: 'inherited-target',
                SEALED_LATTICE_RESUME_TEST_CHECKPOINTS: '1',
                SEALED_LATTICE_TEST_CHECKPOINT_ROOT: 'inherited-checkpoints',
            },
            targetDirectoryPath: 'guarded-target',
        });
        expect(environment).toMatchObject({
            CARGO_BUILD_JOBS: '1',
            CARGO_INCREMENTAL: '0',
            CARGO_TARGET_DIR: 'guarded-target',
            RAYON_NUM_THREADS: '1',
        });
        expect(
            environment.SEALED_LATTICE_RESUME_TEST_CHECKPOINTS,
        ).toBeUndefined();
        expect(environment.SEALED_LATTICE_TEST_CHECKPOINT_ROOT).toBeUndefined();

        const command = buildGuardedRustKernelCommand('exact_test', {
            baseEnvironment: { RUNNER_OWNED_BOUNDARY: 'enabled' },
            logFileSlug: 'exact-test',
            progressLabel: 'exact-test',
            runName: 'Exact test',
            targetDirectoryPath: 'guarded-target',
        });
        expect(command.command.args).toContain('--include-ignored');
        expect(command.command.args).not.toContain('--skip');
        expect(command.command.env?.RUNNER_OWNED_BOUNDARY).toBe('enabled');
        expect(command.setupMessages[1]).toContain(
            'Incremental compilation: off.',
        );

        const featureGatedCommand = buildGuardedRustKernelCommand(
            'feature_gated_test',
            {
                cargoFeatures: ['example-feature'],
                logFileSlug: 'feature-gated-test',
                progressLabel: 'feature-gated-test',
                runName: 'Feature-gated test',
                targetDirectoryPath: 'guarded-target',
            },
        );
        expect(featureGatedCommand.command.args).toContain('--features');
        expect(featureGatedCommand.command.args).toContain('example-feature');

        const releaseProfileCommand = buildGuardedRustKernelCommand(
            'release_profile_test',
            {
                cargoFeatures: ['example-feature'],
                logFileSlug: 'release-profile-test',
                progressLabel: 'release-profile-test',
                runName: 'Release-profile test',
                targetDirectoryPath: 'guarded-target',
                useReleaseProfile: true,
            },
        );
        expect(releaseProfileCommand.command.args).toContain('--release');
        expect(releaseProfileCommand.command.args).toContain('example-feature');
        expect(releaseProfileCommand.setupMessages[0]).toContain(
            'release profile',
        );
    });

    it('derives a bounded memory ceiling and permits only lower overrides', () => {
        expect(
            deriveGuardedRustMemoryLimitGigabytes({
                freeMemoryGigabytes: 95,
                totalMemoryGigabytes: 127.7,
            }),
        ).toBe(32);
        expect(
            deriveGuardedRustMemoryLimitGigabytes({
                freeMemoryGigabytes: 14,
                totalMemoryGigabytes: 16,
            }),
        ).toBe(11);
        expect(() =>
            deriveGuardedRustMemoryLimitGigabytes({
                freeMemoryGigabytes: 2.5,
                totalMemoryGigabytes: 8,
            }),
        ).toThrow('at least 3 GiB');

        expect(
            resolveGuardedRustMemoryLimitGigabytes({
                automaticLimitGigabytes: 32,
                environment: {
                    SEALED_LATTICE_GUARDED_RUST_MEMORY_LIMIT_GIB: '24',
                },
            }),
        ).toBe(24);
        expect(() =>
            resolveGuardedRustMemoryLimitGigabytes({
                automaticLimitGigabytes: 32,
                environment: {
                    SEALED_LATTICE_GUARDED_RUST_MEMORY_LIMIT_GIB: '64',
                },
            }),
        ).toThrow('cannot exceed');
    });

    it('runs Cargo behind the verified hard guard', () => {
        const guardedCommand = guardRustKernelCommand(
            { args: ['test'], command: 'cargo', description: 'test' },
            4096,
        );
        expect(guardedCommand.command).toContain(
            'sealed-lattice-process-memory-guard',
        );
        expect(guardedCommand.args.slice(0, 4)).toEqual([
            '--memory-limit-bytes',
            '4096',
            '--',
            'cargo',
        ]);
        expect(verifyGuardedRustProcessMemoryGuardCommand().args).toContain(
            'sealed-lattice-process-memory-guard',
        );
    });
});
