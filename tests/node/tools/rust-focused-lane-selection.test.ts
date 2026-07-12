import { describe, expect, it } from 'vitest';

import { validateFocusedRustLaneSelection } from '#tools/ci/rust-focused-lane-selection';
import { parseLibtestListOutput } from '#tools/ci/rust-test-inventory';

describe('focused Rust test containment', () => {
    it('parses listed tests without summary noise or duplicates', () => {
        expect(
            parseLibtestListOutput(
                'module::second: test\nmodule::first: test\nmodule::second: test\n2 tests, 0 benchmarks\n',
            ),
        ).toEqual(['module::first', 'module::second']);
    });

    it('rejects empty and cross-group focused selections', () => {
        expect(() =>
            validateFocusedRustLaneSelection({
                lane: 'rust-measurements',
                testFilter: 'missing',
                tests: [],
            }),
        ).toThrow('selects zero tests');
        expect(() =>
            validateFocusedRustLaneSelection({
                lane: 'rust-measurements',
                testFilter: 'heavy_rust_kernel_',
                tests: [
                    {
                        ignored: true,
                        testName:
                            'bgv::tests::heavy_rust_kernel_expensive_relation',
                    },
                ],
            }),
        ).toThrow('test:rust:kernel:heavy');
        expect(() =>
            validateFocusedRustLaneSelection({
                lane: 'rust-kernel-fast',
                testFilter: 'ignored_without_owner',
                tests: [
                    {
                        ignored: true,
                        testName: 'foundation::tests::ignored_without_owner',
                    },
                ],
            }),
        ).toThrow('dedicated guarded command');
    });

    it('detects names that overlap guarded groups', () => {
        expect(() =>
            validateFocusedRustLaneSelection({
                lane: 'rust-accepted-setup',
                testFilter: 'overlap',
                tests: [
                    {
                        ignored: true,
                        testName:
                            'bgv::setup::tests::accepted_setup::heavy_rust_kernel_overlap',
                    },
                ],
            }),
        ).toThrow('multiple guarded groups');
    });

    it('accepts ordinary, accepted-setup, and measurement selections only in their own groups', () => {
        expect(() =>
            validateFocusedRustLaneSelection({
                lane: 'rust-kernel-fast',
                testFilter: 'ordinary',
                tests: [
                    {
                        ignored: false,
                        testName: 'foundation::tests::ordinary',
                    },
                ],
            }),
        ).not.toThrow();
        expect(() =>
            validateFocusedRustLaneSelection({
                lane: 'rust-accepted-setup',
                testFilter: 'accepted_setup',
                tests: [
                    {
                        ignored: false,
                        testName:
                            'bgv::setup::tests::accepted_setup::ordinary_case',
                    },
                ],
            }),
        ).not.toThrow();
        expect(() =>
            validateFocusedRustLaneSelection({
                lane: 'rust-measurements',
                testFilter: 'lagrange_cleared_l1_worst_case',
                tests: [
                    {
                        ignored: true,
                        testName:
                            'bgv::evaluator::top_k::tests::level_budget_probe::lagrange_cleared_l1_worst_case',
                    },
                ],
            }),
        ).not.toThrow();
    });
});
