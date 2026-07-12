import { describe, expect, it } from 'vitest';

import {
    acceptedSetupTestModulePattern,
    buildAcceptedSetupEnvironment,
    buildFocusedCommand,
    cargoTestArgumentsForAcceptedSetupTests,
    cargoTestArgumentsForFocusedFilter,
    deriveAcceptedSetupMemoryLimitGigabytes,
    guardAcceptedSetupCommand,
    normalizeFocusedTestFilter,
    parseRustKernelAcceptedSetupArguments,
    resolveAcceptedSetupMemoryLimitGigabytes,
    resolveRunKnobs,
    verifyProcessMemoryGuardCommand,
} from '#tools/ci/run-rust-kernel-accepted-setup-tests';

describe('Rust accepted setup runner arguments', () => {
    it('runs the complete accepted setup module by default', () => {
        expect(parseRustKernelAcceptedSetupArguments([])).toEqual({
            focused: false,
            mode: 'accelerated',
            testFilters: [acceptedSetupTestModulePattern],
        });
    });

    it('accepts an explicit CI prove-fresh mode', () => {
        expect(parseRustKernelAcceptedSetupArguments(['--ci'])).toEqual({
            focused: false,
            mode: 'ci',
            testFilters: [acceptedSetupTestModulePattern],
        });
    });

    it('treats one positional filter as a focused local run', () => {
        expect(parseRustKernelAcceptedSetupArguments(['one_test'])).toEqual({
            focused: true,
            mode: 'accelerated',
            testFilters: ['one_test'],
        });
        expect(
            parseRustKernelAcceptedSetupArguments(['--ci', 'one_test']),
        ).toEqual({
            focused: true,
            mode: 'ci',
            testFilters: ['one_test'],
        });
    });

    it('normalizes Rust file paths into focused module filters', () => {
        expect(
            normalizeFocusedTestFilter('terminal_evaluation_key_proofs.rs'),
        ).toBe('terminal_evaluation_key_proofs');
        expect(
            normalizeFocusedTestFilter(
                'crates/sealed-lattice-kernel/src/bgv/setup/tests/accepted_setup/terminal_evaluation_key_proofs.rs',
            ),
        ).toBe('terminal_evaluation_key_proofs');
        expect(
            normalizeFocusedTestFilter(
                'crates\\sealed-lattice-kernel\\src\\bgv\\setup\\tests\\accepted_setup\\terminal_evaluation_key_proofs.rs',
            ),
        ).toBe('terminal_evaluation_key_proofs');
    });

    it('ignores the package-manager argument separator', () => {
        expect(parseRustKernelAcceptedSetupArguments(['--'])).toEqual({
            focused: false,
            mode: 'accelerated',
            testFilters: [acceptedSetupTestModulePattern],
        });
    });

    it('rejects ambiguous or unsupported arguments', () => {
        expect(() =>
            parseRustKernelAcceptedSetupArguments(['one_test', 'another_test']),
        ).toThrow('Focused accepted-setup runs accept one test or file filter');
        expect(() =>
            parseRustKernelAcceptedSetupArguments(['--unsupported']),
        ).toThrow('Unknown argument: --unsupported');
        expect(() =>
            parseRustKernelAcceptedSetupArguments(['--lane', 'fast']),
        ).toThrow('Unknown argument: --lane');
    });

    it('includes ordinary and ignored tests from the accepted setup module', () => {
        expect(cargoTestArgumentsForAcceptedSetupTests('4')).toEqual([
            'test',
            '--locked',
            '-p',
            'sealed-lattice-kernel',
            acceptedSetupTestModulePattern,
            '--',
            '--include-ignored',
            '--nocapture',
            '--test-threads',
            '4',
        ]);
    });

    it('builds focused cargo arguments from one normalized filter', () => {
        expect(
            cargoTestArgumentsForFocusedFilter(
                'terminal_evaluation_key_proofs',
                '3',
            ),
        ).toEqual([
            'test',
            '--locked',
            '-p',
            'sealed-lattice-kernel',
            'terminal_evaluation_key_proofs',
            '--',
            '--include-ignored',
            '--nocapture',
            '--test-threads',
            '3',
        ]);

        expect(
            cargoTestArgumentsForFocusedFilter('ceremony_phases', '1'),
        ).toContain('--include-ignored');
    });

    it('uses a 32 GiB ceiling on large hosts and reserves memory on smaller hosts', () => {
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
        expect(
            deriveAcceptedSetupMemoryLimitGigabytes({
                freeMemoryGigabytes: 6,
                totalMemoryGigabytes: 7,
            }),
        ).toBe(4);
        expect(() =>
            deriveAcceptedSetupMemoryLimitGigabytes({
                freeMemoryGigabytes: 2.5,
                totalMemoryGigabytes: 8,
            }),
        ).toThrow('at least 3 GiB');
    });

    it('accepts only memory-limit overrides that lower the safe ceiling', () => {
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
        expect(() =>
            resolveAcceptedSetupMemoryLimitGigabytes({
                automaticLimitGigabytes: 32,
                environment: {
                    SEALED_LATTICE_ACCEPTED_SETUP_MEMORY_LIMIT_GIB: '2.5',
                },
            }),
        ).toThrow('positive integer');
    });

    it('serializes every accepted setup concurrency layer', () => {
        expect(resolveRunKnobs()).toEqual({
            rayonThreadCount: { source: 'serialized', value: '1' },
            testThreads: { source: 'serialized', value: '1' },
            trusteeProofBatchSize: { source: 'serialized', value: '1' },
            trusteeProofLimbBatchSize: {
                source: 'serialized',
                value: '1',
            },
        });
    });

    it('removes inherited checkpoint state from prove-fresh environments', () => {
        const environment = buildAcceptedSetupEnvironment({
            baseEnvironment: {
                CARGO_TARGET_DIR: 'inherited-target',
                SEALED_LATTICE_RESUME_TEST_CHECKPOINTS: '1',
                SEALED_LATTICE_TEST_CHECKPOINT_ROOT: 'inherited-checkpoints',
            },
            cargoIncremental: '0',
            knobs: {
                rayonThreadCount: { source: 'test', value: '1' },
                testThreads: { source: 'test', value: '1' },
                trusteeProofBatchSize: { source: 'test', value: '1' },
                trusteeProofLimbBatchSize: { source: 'test', value: '1' },
            },
            resumeCheckpoints: false,
        });

        expect(environment.CARGO_INCREMENTAL).toBe('0');
        expect(environment.CARGO_BUILD_JOBS).toBe('1');
        expect(environment.CARGO_TARGET_DIR).toBeUndefined();
        expect(
            environment.SEALED_LATTICE_RESUME_TEST_CHECKPOINTS,
        ).toBeUndefined();
        expect(environment.SEALED_LATTICE_TEST_CHECKPOINT_ROOT).toBeUndefined();
    });

    it('wraps cargo in the hard memory guard and builds the guard separately', () => {
        const guardedCommand = guardAcceptedSetupCommand(
            {
                args: ['test', '--', '--test-threads', '1'],
                command: 'cargo',
                description: 'guarded test',
            },
            4096,
        );
        expect(guardedCommand.command).toContain(
            'sealed-lattice-process-memory-guard',
        );
        expect(guardedCommand.args).toEqual([
            '--memory-limit-bytes',
            '4096',
            '--',
            'cargo',
            'test',
            '--',
            '--test-threads',
            '1',
        ]);

        const verificationCommand = verifyProcessMemoryGuardCommand();
        expect(verificationCommand.command).toBe('cargo');
        expect(verificationCommand.args).toContain('test');
        expect(verificationCommand.args).toContain(
            'sealed-lattice-process-memory-guard',
        );
        expect(verificationCommand.args).toContain('--locked');
    });

    it('keeps focused CI runs prove-fresh', () => {
        const focusedCiCommand = buildFocusedCommand('ceremony_phases', 'ci');
        expect(focusedCiCommand.command.env?.CARGO_INCREMENTAL).toBe('0');
        expect(
            focusedCiCommand.command.env
                ?.SEALED_LATTICE_RESUME_TEST_CHECKPOINTS,
        ).toBeUndefined();
        expect(
            focusedCiCommand.command.env?.SEALED_LATTICE_TEST_CHECKPOINT_ROOT,
        ).toBeUndefined();
        expect(focusedCiCommand.command.env?.CARGO_TARGET_DIR).toBeUndefined();

        const focusedLocalCommand = buildFocusedCommand(
            'ceremony_phases',
            'accelerated',
        );
        expect(focusedLocalCommand.command.env?.CARGO_INCREMENTAL).toBe('1');
        expect(
            focusedLocalCommand.command.env
                ?.SEALED_LATTICE_RESUME_TEST_CHECKPOINTS,
        ).toBe('1');
        expect(focusedLocalCommand.command.env?.CARGO_TARGET_DIR).toContain(
            'accepted-setup-focused',
        );
    });
});
