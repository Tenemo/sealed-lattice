import { describe, expect, it } from 'vitest';

import {
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

    it('rejects non-heavy, ambiguous, and unsupported filters', () => {
        expect(() => parseRustKernelHeavyArguments(['one_test'])).toThrow(
            'Heavy Rust kernel filters must start with "heavy_rust_kernel_"',
        );
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

    it('builds a focused heavy Rust cargo command', () => {
        const testFilter = 'heavy_rust_kernel_one_test';
        const command = buildRustKernelHeavyTestCommand({ testFilter });

        expect(command.command).toBe('cargo');
        expect(command.args).toEqual(
            cargoTestArgumentsForRustKernelHeavy(testFilter),
        );
        expect(command.description).toBe(
            'cargo test Rust kernel heavy (heavy_rust_kernel_one_test)',
        );
        expect(command.logFileSlug).toBe('cargo-test-rust-kernel-heavy');
        expect(command.env?.CARGO_INCREMENTAL).toBe('0');
    });
});
