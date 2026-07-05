import { describe, expect, it } from 'vitest';

import {
    cargoTestArgumentsForAcceptedSetupTests,
    cargoTestArgumentsForFocusedFilter,
    heavyAcceptedSetupTestPattern,
    normalizeFocusedTestFilter,
    parseRustKernelAcceptedSetupArguments,
} from '#tools/ci/run-rust-kernel-accepted-setup-tests';

describe('Rust accepted setup runner arguments', () => {
    it('runs the heavy accepted setup suite by default', () => {
        expect(parseRustKernelAcceptedSetupArguments([])).toEqual({
            focused: false,
            mode: 'accelerated',
            testFilters: [heavyAcceptedSetupTestPattern],
        });
    });

    it('accepts an explicit CI prove-fresh mode', () => {
        expect(parseRustKernelAcceptedSetupArguments(['--ci'])).toEqual({
            focused: false,
            mode: 'ci',
            testFilters: [heavyAcceptedSetupTestPattern],
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
            testFilters: [heavyAcceptedSetupTestPattern],
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

    it('runs every heavy accepted setup test through one suite filter', () => {
        expect(cargoTestArgumentsForAcceptedSetupTests('4')).toEqual([
            'test',
            '-p',
            'sealed-lattice-kernel',
            heavyAcceptedSetupTestPattern,
            '--',
            '--ignored',
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
            '--ignored',
            '--show-output',
            '--test-threads',
            '3',
        ]);
    });
});
