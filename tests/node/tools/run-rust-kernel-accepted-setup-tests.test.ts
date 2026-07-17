import { describe, expect, it } from 'vitest';

import {
    buildAcceptedSetupEnvironment,
    buildFocusedCommand,
    cargoTestArgumentsForAcceptedSetupTests,
    deriveAcceptedSetupMemoryLimitGigabytes,
    guardAcceptedSetupCommand,
    parseRustKernelAcceptedSetupArguments,
    resolveAcceptedSetupMemoryLimitGigabytes,
    tenParticipantAcceptedSetupEvidenceTest,
    verifyProcessMemoryGuardCommand,
} from '#tools/ci/run-rust-kernel-accepted-setup-tests';

describe('Rust accepted setup runner', () => {
    it('distinguishes resumable local runs from prove-fresh CI runs', () => {
        expect(parseRustKernelAcceptedSetupArguments([])).toEqual({
            mode: 'accelerated',
        });
        expect(
            parseRustKernelAcceptedSetupArguments(['--ci', 'ceremony.rs']),
        ).toEqual({
            mode: 'ci',
            testFilter: 'ceremony',
        });

        const localEnvironment = buildFocusedCommand('ceremony', 'accelerated')
            .command.env;
        expect(localEnvironment?.CARGO_INCREMENTAL).toBe('1');
        expect(localEnvironment?.SEALED_LATTICE_RESUME_TEST_CHECKPOINTS).toBe(
            '1',
        );
        expect(localEnvironment?.CARGO_TARGET_DIR).toContain(
            'accepted-setup-focused',
        );

        const ciEnvironment = buildAcceptedSetupEnvironment({
            baseEnvironment: {
                CARGO_TARGET_DIR: 'inherited-target',
                SEALED_LATTICE_RESUME_TEST_CHECKPOINTS: '1',
                SEALED_LATTICE_TEST_CHECKPOINT_ROOT: 'inherited-checkpoints',
            },
            cargoIncremental: '0',
            resumeCheckpoints: false,
        });
        expect(ciEnvironment).toMatchObject({
            CARGO_BUILD_JOBS: '1',
            CARGO_INCREMENTAL: '0',
            RAYON_NUM_THREADS: '1',
            SEALED_LATTICE_TRUSTEE_PROOF_LIMB_BATCH_SIZE: '1',
        });
        expect(ciEnvironment.CARGO_TARGET_DIR).toBeUndefined();
        expect(
            ciEnvironment.SEALED_LATTICE_RESUME_TEST_CHECKPOINTS,
        ).toBeUndefined();
        expect(
            ciEnvironment.SEALED_LATTICE_TEST_CHECKPOINT_ROOT,
        ).toBeUndefined();
    });

    it('keeps ten-participant prototype evidence out of the routine accepted-setup lane', () => {
        const routineArguments = cargoTestArgumentsForAcceptedSetupTests();
        expect(routineArguments).toContain('--include-ignored');
        expect(routineArguments).toContain('--skip');
        expect(routineArguments).toContain(
            tenParticipantAcceptedSetupEvidenceTest,
        );

        const evidenceArguments = buildFocusedCommand(
            tenParticipantAcceptedSetupEvidenceTest,
            'ci',
        ).command.args;
        expect(evidenceArguments).toContain(
            tenParticipantAcceptedSetupEvidenceTest,
        );
        expect(evidenceArguments).not.toContain('--skip');
    });

    it('derives a bounded memory ceiling and permits only lower overrides', () => {
        expect(
            deriveAcceptedSetupMemoryLimitGigabytes({
                freeMemoryGigabytes: 95,
                totalMemoryGigabytes: 127.7,
            }),
        ).toBe(32);
        expect(
            deriveAcceptedSetupMemoryLimitGigabytes({
                freeMemoryGigabytes: 14,
                totalMemoryGigabytes: 16,
            }),
        ).toBe(11);
        expect(() =>
            deriveAcceptedSetupMemoryLimitGigabytes({
                freeMemoryGigabytes: 2.5,
                totalMemoryGigabytes: 8,
            }),
        ).toThrow('at least 3 GiB');

        expect(
            resolveAcceptedSetupMemoryLimitGigabytes({
                automaticLimitGigabytes: 32,
                environment: {
                    SEALED_LATTICE_ACCEPTED_SETUP_MEMORY_LIMIT_GIB: '24',
                },
            }),
        ).toBe(24);
        expect(() =>
            resolveAcceptedSetupMemoryLimitGigabytes({
                automaticLimitGigabytes: 32,
                environment: {
                    SEALED_LATTICE_ACCEPTED_SETUP_MEMORY_LIMIT_GIB: '64',
                },
            }),
        ).toThrow('cannot exceed');
    });

    it('runs accepted-setup cargo commands behind the verified hard guard', () => {
        const guardedCommand = guardAcceptedSetupCommand(
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
        expect(verifyProcessMemoryGuardCommand().args).toContain(
            'sealed-lattice-process-memory-guard',
        );
    });
});
