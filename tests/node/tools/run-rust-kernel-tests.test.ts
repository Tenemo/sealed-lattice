import { describe, expect, it } from 'vitest';

import {
    buildRustKernelTestCommand,
    parseRustKernelArguments,
} from '#tools/ci/run-rust-kernel-tests';

describe('Rust kernel fast runner', () => {
    it('keeps ordinary and focused tests in the fast lane', () => {
        const argumentSets = [
            buildRustKernelTestCommand({}).args,
            buildRustKernelTestCommand({
                testFilter: 'request_validation',
            }).args,
        ];
        for (const arguments_ of argumentSets) {
            expect(arguments_).not.toContain('--ignored');
            expect(arguments_).not.toContain('--skip');
        }
        expect(argumentSets[1]).toContain('request_validation');
    });

    it('normalizes one focused filter and refuses invalid argument shapes', () => {
        expect(
            parseRustKernelArguments([
                'crates/sealed-lattice-kernel/src/tests/request_validation.rs',
            ]),
        ).toEqual({ testFilter: 'request_validation' });
        expect(() => parseRustKernelArguments(['first', 'second'])).toThrow(
            'one optional filter',
        );
        expect(() => parseRustKernelArguments(['--ignored'])).toThrow(
            'one optional filter',
        );
    });
});
