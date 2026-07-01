import { describe, expect, it } from 'vitest';

import {
    authoritativeCommandLanesForLane,
    automaticTestThreadKnobForLane,
    automaticTrusteeProofBatchKnobForLane,
    cargoTestArgumentsForFocusedFilter,
    cargoTestArgumentsForLane,
    heavyAcceptedSetupFinalPackageTestPattern,
    heavyAcceptedSetupTestPattern,
    normalizeFocusedTestFilter,
    parseRustKernelAcceptedSetupArguments,
} from '#tools/ci/run-rust-kernel-accepted-setup-tests';

describe('Rust accepted setup runner arguments', () => {
    it('runs the full accepted setup lane by default', () => {
        expect(parseRustKernelAcceptedSetupArguments([])).toEqual({
            focused: false,
            testFilters: [heavyAcceptedSetupTestPattern],
        });
    });

    it('expands the full authoritative lane into the two split lanes', () => {
        expect(authoritativeCommandLanesForLane('all')).toEqual([
            'fast',
            'final-package',
        ]);
        expect(authoritativeCommandLanesForLane('fast')).toEqual(['fast']);
        expect(authoritativeCommandLanesForLane('final-package')).toEqual([
            'final-package',
        ]);
    });

    it('caps final package libtest concurrency without slowing the fast lane', () => {
        expect(automaticTestThreadKnobForLane('fast', 3)).toEqual({
            source: 'memory-bounded',
            value: '3',
        });
        expect(automaticTestThreadKnobForLane('final-package', 3)).toEqual({
            source: 'final-package fixture cap',
            value: '1',
        });
        expect(automaticTestThreadKnobForLane('final-package', 1)).toEqual({
            source: 'memory-bounded',
            value: '1',
        });
    });

    it('caps final package prover concurrency without slowing the fast lane', () => {
        expect(automaticTrusteeProofBatchKnobForLane('fast', 5)).toEqual({
            source: 'memory-bounded',
            value: '5',
        });
        expect(
            automaticTrusteeProofBatchKnobForLane('final-package', 5),
        ).toEqual({
            source: 'final-package prover cap',
            value: '1',
        });
        expect(
            automaticTrusteeProofBatchKnobForLane('final-package', 1),
        ).toEqual({
            source: 'memory-bounded',
            value: '1',
        });
    });

    it('treats one positional filter as a focused local run', () => {
        expect(parseRustKernelAcceptedSetupArguments(['one_test'])).toEqual({
            focused: true,
            testFilters: ['one_test'],
        });
    });

    it('normalizes Rust file paths into focused module filters', () => {
        expect(
            normalizeFocusedTestFilter('evaluation_key_share_proofs.rs'),
        ).toBe('evaluation_key_share_proofs');
        expect(
            normalizeFocusedTestFilter(
                'crates/sealed-lattice-kernel/src/bgv/setup/tests/accepted_setup/evaluation_key_share_proofs.rs',
            ),
        ).toBe('evaluation_key_share_proofs');
        expect(
            normalizeFocusedTestFilter(
                'crates\\sealed-lattice-kernel\\src\\bgv\\setup\\tests\\accepted_setup\\evaluation_key_share_proofs.rs',
            ),
        ).toBe('evaluation_key_share_proofs');
    });

    it('ignores the package-manager argument separator', () => {
        expect(parseRustKernelAcceptedSetupArguments(['--'])).toEqual({
            focused: false,
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
    });

    it('skips final package tests only in the fast lane', () => {
        expect(cargoTestArgumentsForLane('fast', '4')).toEqual([
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
        expect(cargoTestArgumentsForLane('final-package', '2')).toEqual([
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

    it('builds focused cargo arguments from one normalized filter', () => {
        expect(
            cargoTestArgumentsForFocusedFilter(
                'evaluation_key_share_proofs',
                '3',
            ),
        ).toEqual([
            'test',
            '-p',
            'sealed-lattice-kernel',
            'evaluation_key_share_proofs',
            '--',
            '--ignored',
            '--show-output',
            '--test-threads',
            '3',
        ]);
    });
});
