import { describe, expect, it } from 'vitest';

import {
    acceptedSetupTestModulePattern,
    buildAcceptedSetupEnvironment,
    buildFocusedCommand,
    cargoTestArgumentsForAcceptedSetupTests,
    cargoTestArgumentsForFocusedFilter,
    deriveAutomaticAcceptedSetupConcurrency,
    normalizeFocusedTestFilter,
    parseRustKernelAcceptedSetupArguments,
    resolveRunKnobs,
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
            '-p',
            'sealed-lattice-kernel',
            'terminal_evaluation_key_proofs',
            '--',
            '--include-ignored',
            '--show-output',
            '--test-threads',
            '3',
        ]);

        expect(
            cargoTestArgumentsForFocusedFilter('ceremony_phases', '1'),
        ).toContain('--include-ignored');
    });

    it('shares one memory budget across nested proof concurrency', () => {
        expect(
            deriveAutomaticAcceptedSetupConcurrency({
                availableGigabytes: 14.2,
                logicalProcessorCount: 4,
            }),
        ).toEqual({
            rayonThreadCount: 1,
            testThreadCount: 1,
            trusteeProofBatchSize: 1,
            trusteeProofLimbBatchSize: 1,
        });

        expect(
            deriveAutomaticAcceptedSetupConcurrency({
                availableGigabytes: 64,
                logicalProcessorCount: 16,
            }),
        ).toEqual({
            rayonThreadCount: 2,
            testThreadCount: 2,
            trusteeProofBatchSize: 2,
            trusteeProofLimbBatchSize: 2,
        });

        expect(
            deriveAutomaticAcceptedSetupConcurrency({
                availableGigabytes: 128,
                logicalProcessorCount: 32,
            }),
        ).toEqual({
            rayonThreadCount: 7,
            testThreadCount: 5,
            trusteeProofBatchSize: 5,
            trusteeProofLimbBatchSize: 1,
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
        expect(environment.CARGO_TARGET_DIR).toBeUndefined();
        expect(
            environment.SEALED_LATTICE_RESUME_TEST_CHECKPOINTS,
        ).toBeUndefined();
        expect(environment.SEALED_LATTICE_TEST_CHECKPOINT_ROOT).toBeUndefined();
    });

    it('ignores manual concurrency overrides in CI mode', () => {
        const overrides = {
            RAYON_NUM_THREADS: '999',
            SEALED_LATTICE_TRUSTEE_PROOF_BATCH_SIZE: '999',
            SEALED_LATTICE_TRUSTEE_PROOF_LIMB_BATCH_SIZE: '999',
        };
        const ciKnobs = resolveRunKnobs('ci', overrides);
        expect(ciKnobs.rayonThreadCount.source).toBe('shared-memory-bounded');
        expect(ciKnobs.trusteeProofBatchSize.source).toBe(
            'shared-memory-bounded',
        );
        expect(ciKnobs.trusteeProofLimbBatchSize.source).toBe(
            'shared-memory-bounded',
        );
        expect(ciKnobs.rayonThreadCount.value).not.toBe('999');

        const localKnobs = resolveRunKnobs('accelerated', overrides);
        expect(localKnobs.rayonThreadCount).toEqual({
            source: 'environment override',
            value: '999',
        });
        expect(localKnobs.trusteeProofBatchSize.value).toBe('999');
        expect(localKnobs.trusteeProofLimbBatchSize.value).toBe('999');
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
