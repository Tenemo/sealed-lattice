import { describe, expect, it } from 'vitest';

import {
    buildRustKernelHeavyProcessMemoryGuardVerificationCommand,
    buildRustKernelHeavyTestCommand,
    parseRustKernelHeavyArguments,
} from '#tools/ci/run-rust-kernel-heavy-tests';
import {
    cargoTestArgumentsForRustKernelHeavy,
    heavyRustKernelTestNamePrefix,
} from '#tools/ci/rust-kernel-test-arguments';

describe('Rust kernel heavy runner arguments', () => {
    it('runs only ignored tests carrying the heavy Rust kernel prefix', () => {
        expect(parseRustKernelHeavyArguments([])).toEqual({
            testFilter: heavyRustKernelTestNamePrefix,
        });
        expect(cargoTestArgumentsForRustKernelHeavy()).toEqual([
            'test',
            '--locked',
            '-p',
            'sealed-lattice-kernel',
            heavyRustKernelTestNamePrefix,
            '--',
            '--ignored',
            '--test-threads',
            '1',
            '--show-output',
        ]);
    });

    it('accepts one normalized heavy test filter', () => {
        const heavyTestName =
            'heavy_rust_kernel_sparse_target_projection_decrypts_selected_ids_and_orders';
        expect(parseRustKernelHeavyArguments(['--'])).toEqual({
            testFilter: heavyRustKernelTestNamePrefix,
        });
        expect(parseRustKernelHeavyArguments([`${heavyTestName}.rs`])).toEqual({
            testFilter: heavyTestName,
        });
        expect(cargoTestArgumentsForRustKernelHeavy(heavyTestName)).toEqual([
            'test',
            '--locked',
            '-p',
            'sealed-lattice-kernel',
            heavyTestName,
            '--',
            '--ignored',
            '--test-threads',
            '1',
            '--show-output',
        ]);
    });

    it('defers lane ownership while rejecting ambiguous and unsupported filters', () => {
        expect(parseRustKernelHeavyArguments(['one_test'])).toEqual({
            testFilter: 'one_test',
        });
        expect(() => parseRustKernelHeavyArguments(['--unsupported'])).toThrow(
            'Unknown argument: --unsupported',
        );
        expect(() =>
            parseRustKernelHeavyArguments([
                'heavy_rust_kernel_first',
                'heavy_rust_kernel_second',
            ]),
        ).toThrow('Heavy Rust kernel runs accept one filter');
    });

    it('builds and verifies the process-memory guard before heavy Rust tests', () => {
        const verificationCommand =
            buildRustKernelHeavyProcessMemoryGuardVerificationCommand();

        expect(verificationCommand.command).toBe('cargo');
        expect(verificationCommand.args).toEqual([
            'test',
            '--locked',
            '-p',
            'sealed-lattice-process-memory-guard',
            '--target-dir',
            expect.stringContaining('process-memory-guard'),
            '--',
            '--test-threads',
            '1',
            '--show-output',
        ]);
        expect(verificationCommand.env?.CARGO_TARGET_DIR).toBeUndefined();
    });

    it('guards and serializes a focused heavy Rust cargo command', () => {
        const testFilter = 'heavy_rust_kernel_one_test';
        const command = buildRustKernelHeavyTestCommand({ testFilter });

        expect(command.command).toContain(
            'sealed-lattice-process-memory-guard',
        );
        expect(command.args[0]).toBe('--memory-limit-bytes');
        expect(Number(command.args[1])).toBeGreaterThan(0);
        expect(command.args.slice(2)).toEqual([
            '--',
            'cargo',
            ...cargoTestArgumentsForRustKernelHeavy(testFilter),
        ]);
        expect(command.description).toBe(
            'cargo test Rust kernel heavy (heavy_rust_kernel_one_test)',
        );
        expect(command.logFileSlug).toBe('cargo-test-rust-kernel-heavy');
        expect(command.env?.CARGO_BUILD_JOBS).toBe('1');
        expect(command.env?.CARGO_INCREMENTAL).toBe('0');
        expect(command.env?.RAYON_NUM_THREADS).toBe('1');
        expect(command.env?.RUST_BACKTRACE).toBe('full');
        expect(command.env?.SEALED_LATTICE_TRUSTEE_PROOF_BATCH_SIZE).toBe('1');
        expect(command.env?.SEALED_LATTICE_TRUSTEE_PROOF_LIMB_BATCH_SIZE).toBe(
            '1',
        );
    });
});
