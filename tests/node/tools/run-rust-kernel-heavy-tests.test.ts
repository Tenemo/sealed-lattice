import { describe, expect, it } from 'vitest';

import {
    authoritativeCommandScopesForScope,
    automaticTestThreadKnobForScope,
    automaticTrusteeProofBatchKnobForScope,
    cargoTestArgumentsForScope,
    heavyAcceptedSetupFinalPackageTestPattern,
    heavyAcceptedSetupTestPattern,
    parseRustKernelHeavyArguments,
} from '#tools/ci/run-rust-kernel-heavy-tests';

describe('rust kernel heavy runner arguments', () => {
    it('runs the full accepted setup heavy scope by default', () => {
        expect(parseRustKernelHeavyArguments([])).toEqual({
            iterate: false,
            scope: 'all',
            testFilters: [heavyAcceptedSetupTestPattern],
        });
    });

    it('accepts authoritative accepted setup scopes', () => {
        expect(parseRustKernelHeavyArguments(['--scope', 'checks'])).toEqual({
            iterate: false,
            scope: 'checks',
            testFilters: [heavyAcceptedSetupTestPattern],
        });
        expect(
            parseRustKernelHeavyArguments(['--scope=final-package']),
        ).toEqual({
            iterate: false,
            scope: 'final-package',
            testFilters: [heavyAcceptedSetupFinalPackageTestPattern],
        });
    });

    it('expands the full authoritative scope into the two split lanes', () => {
        expect(authoritativeCommandScopesForScope('all')).toEqual([
            'checks',
            'final-package',
        ]);
        expect(authoritativeCommandScopesForScope('checks')).toEqual([
            'checks',
        ]);
        expect(authoritativeCommandScopesForScope('final-package')).toEqual([
            'final-package',
        ]);
    });

    it('caps final package libtest concurrency without slowing the checks scope', () => {
        expect(automaticTestThreadKnobForScope('checks', 3)).toEqual({
            source: 'memory-bounded',
            value: '3',
        });
        expect(automaticTestThreadKnobForScope('final-package', 3)).toEqual({
            source: 'final-package fixture cap',
            value: '1',
        });
        expect(automaticTestThreadKnobForScope('final-package', 1)).toEqual({
            source: 'memory-bounded',
            value: '1',
        });
    });

    it('caps final package prover concurrency without slowing the checks scope', () => {
        expect(automaticTrusteeProofBatchKnobForScope('checks', 5)).toEqual({
            source: 'memory-bounded',
            value: '5',
        });
        expect(
            automaticTrusteeProofBatchKnobForScope('final-package', 5),
        ).toEqual({
            source: 'final-package prover cap',
            value: '2',
        });
        expect(
            automaticTrusteeProofBatchKnobForScope('final-package', 1),
        ).toEqual({
            source: 'memory-bounded',
            value: '1',
        });
    });

    it('allows iteration over explicit test filters', () => {
        expect(
            parseRustKernelHeavyArguments(['--iterate', 'one_test']),
        ).toEqual({
            iterate: true,
            scope: 'all',
            testFilters: ['one_test'],
        });
    });

    it('rejects ambiguous or unsupported arguments', () => {
        expect(() => parseRustKernelHeavyArguments(['one_test'])).toThrow(
            'Test-name filters require --iterate',
        );
        expect(() =>
            parseRustKernelHeavyArguments(['--scope', 'unknown']),
        ).toThrow('Usage: run-rust-kernel-heavy-tests.ts');
        expect(() =>
            parseRustKernelHeavyArguments(['--iterate', '--scope', 'checks']),
        ).toThrow('Use explicit test-name filters with --iterate');
    });

    it('skips final package tests only in the checks scope', () => {
        expect(cargoTestArgumentsForScope('checks', '4')).toEqual([
            'test',
            '-p',
            'sealed-lattice-kernel',
            heavyAcceptedSetupTestPattern,
            '--',
            '--ignored',
            '--nocapture',
            '--skip',
            heavyAcceptedSetupFinalPackageTestPattern,
            '--test-threads',
            '4',
        ]);
        expect(cargoTestArgumentsForScope('final-package', '2')).toEqual([
            'test',
            '-p',
            'sealed-lattice-kernel',
            heavyAcceptedSetupFinalPackageTestPattern,
            '--',
            '--ignored',
            '--nocapture',
            '--test-threads',
            '2',
        ]);
    });
});
