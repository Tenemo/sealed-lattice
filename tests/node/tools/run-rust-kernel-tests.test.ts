import { describe, expect, it } from 'vitest';

import { parseRustKernelArguments } from '#tools/ci/run-rust-kernel-tests';
import {
    cargoTestArgumentsForRustKernelFast,
    heavyRustKernelTestNamePrefix,
} from '#tools/ci/rust-kernel-test-arguments';

describe('Rust kernel fast runner', () => {
    it('keeps ordinary and focused tests in the fast lane', () => {
        const argumentSets = [
            cargoTestArgumentsForRustKernelFast(),
            cargoTestArgumentsForRustKernelFast('request_validation'),
        ];
        for (const arguments_ of argumentSets) {
            expect(arguments_).not.toContain('--skip');
            expect(arguments_).not.toContain('--ignored');
        }
        expect(argumentSets[1]).toContain('request_validation');
    });

    it('normalizes one focused filter and rejects other lane ownership', () => {
        expect(
            parseRustKernelArguments([
                'crates/sealed-lattice-kernel/src/tests/request_validation.rs',
            ]),
        ).toEqual({ testFilter: 'request_validation' });
        expect(() =>
            parseRustKernelArguments([
                `${heavyRustKernelTestNamePrefix}expensive_relation`,
            ]),
        ).toThrow('test:rust:kernel:heavy');
    });
});
