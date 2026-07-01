import { describe, expect, it } from 'vitest';

import {
    buildRustKernelTestCommand,
    parseRustKernelArguments,
} from '#tools/ci/run-rust-kernel-tests';
import {
    cargoTestArgumentsForRustKernelFast,
    heavyAcceptedSetupTestPattern,
    normalizeRustTestFilter,
} from '#tools/ci/rust-kernel-test-arguments';

describe('Rust kernel runner arguments', () => {
    it('runs all fast Rust kernel tests by default', () => {
        expect(parseRustKernelArguments([])).toEqual({});
        expect(cargoTestArgumentsForRustKernelFast()).toEqual([
            'test',
            '-p',
            'sealed-lattice-kernel',
            '--',
            '--skip',
            heavyAcceptedSetupTestPattern,
            '--show-output',
        ]);
    });

    it('accepts one focused Rust test filter', () => {
        expect(parseRustKernelArguments(['direct_ballots'])).toEqual({
            testFilter: 'direct_ballots',
        });
        expect(cargoTestArgumentsForRustKernelFast('direct_ballots')).toEqual([
            'test',
            '-p',
            'sealed-lattice-kernel',
            'direct_ballots',
            '--',
            '--skip',
            heavyAcceptedSetupTestPattern,
            '--show-output',
        ]);
    });

    it('normalizes Rust file paths into module filters', () => {
        expect(normalizeRustTestFilter('request_validation.rs')).toBe(
            'request_validation',
        );
        expect(
            normalizeRustTestFilter(
                'crates/sealed-lattice-kernel/src/bgv/direct_ballots/tests/request_validation.rs',
            ),
        ).toBe('request_validation');
        expect(
            normalizeRustTestFilter(
                'crates\\sealed-lattice-kernel\\src\\bgv\\direct_ballots\\tests\\request_validation.rs',
            ),
        ).toBe('request_validation');
    });

    it('ignores the package-manager argument separator', () => {
        expect(parseRustKernelArguments(['--'])).toEqual({});
    });

    it('rejects ambiguous or unsupported arguments', () => {
        expect(() =>
            parseRustKernelArguments(['one_test', 'another_test']),
        ).toThrow('Rust kernel test runs accept one filter');
        expect(() => parseRustKernelArguments(['--unsupported'])).toThrow(
            'Unknown argument: --unsupported',
        );
    });

    it('builds the cargo command for the package script', () => {
        const command = buildRustKernelTestCommand({
            testFilter: 'request_validation',
        });

        expect(command.command).toBe('cargo');
        expect(command.args).toEqual(
            cargoTestArgumentsForRustKernelFast('request_validation'),
        );
        expect(command.description).toBe(
            'cargo test Rust kernel fast (request_validation)',
        );
        expect(command.logFileSlug).toBe('cargo-test-rust-kernel-fast');
        expect(command.env?.CARGO_INCREMENTAL).toBe('0');
    });
});
