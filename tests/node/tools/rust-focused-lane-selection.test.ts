import { describe, expect, it } from 'vitest';

import {
    focusedRustLaneScripts,
    validateCompleteRustLaneOwnership,
    validateFocusedRustLaneSelection,
} from '#tools/ci/rust-focused-lane-selection';
import { heavyRustKernelTestNamePrefix } from '#tools/ci/rust-kernel-test-arguments';

const heavyTestName =
    'tally_preparation::tests::heavy_rust_kernel_expensive_relation';
describe('focused Rust lane selection', () => {
    it('assigns ordinary and heavy tests to exactly one owner', () => {
        expect(() =>
            validateCompleteRustLaneOwnership([
                {
                    ignored: false,
                    testName: 'tally_preparation::tests::ordinary',
                },
                { ignored: true, testName: heavyTestName },
            ]),
        ).not.toThrow();
    });

    it('rejects an empty inventory and ignored tests without an owner', () => {
        expect(() => validateCompleteRustLaneOwnership([])).toThrow(
            'inventory is empty',
        );
        expect(() =>
            validateCompleteRustLaneOwnership([
                {
                    ignored: true,
                    testName: 'foundation::tests::ignored_without_owner',
                },
            ]),
        ).toThrow('belongs to no guarded Rust lane');
    });

    it('rejects metadata that would run a guarded test in the fast lane too', () => {
        expect(() =>
            validateCompleteRustLaneOwnership([
                { ignored: false, testName: heavyTestName },
            ]),
        ).toThrow('belongs to multiple Rust lanes');
    });

    it.each([
        [
            'rust-kernel-fast' as const,
            false,
            'tally_preparation::tests::ordinary',
            'focused',
        ],
        [
            'rust-kernel-heavy' as const,
            true,
            heavyTestName,
            'heavy_rust_kernel_expensive_relation',
        ],
    ])(
        'accepts %s tests only in their owning lane',
        (lane, ignored, testName, testFilter) => {
            expect(() =>
                validateFocusedRustLaneSelection({
                    lane,
                    testFilter,
                    tests: [{ ignored, testName }],
                }),
            ).not.toThrow();
        },
    );

    it('fails closed for zero matches, cross-lane selections, and unowned tests', () => {
        expect(() =>
            validateFocusedRustLaneSelection({
                lane: 'rust-kernel-fast',
                testFilter: 'missing',
                tests: [],
            }),
        ).toThrow('selects zero tests');
        expect(() =>
            validateFocusedRustLaneSelection({
                lane: 'rust-kernel-fast',
                testFilter: 'heavy',
                tests: [{ ignored: true, testName: heavyTestName }],
            }),
        ).toThrow('test:rust:kernel:heavy');
        expect(() =>
            validateFocusedRustLaneSelection({
                lane: 'rust-kernel-fast',
                testFilter: 'unowned',
                tests: [
                    {
                        ignored: true,
                        testName: 'foundation::tests::ignored_without_owner',
                    },
                ],
            }),
        ).toThrow('dedicated guarded command');
        expect(() =>
            validateFocusedRustLaneSelection({
                lane: 'rust-kernel-heavy',
                testFilter: 'heavy_rust_kernel_expensive_relation',
                tests: [
                    { ignored: true, testName: heavyTestName },
                    {
                        ignored: true,
                        testName:
                            'tally_preparation::tests::heavy_rust_kernel_expensive_relation_variant',
                    },
                ],
            }),
        ).toThrow('must select exactly one test');
        expect(() =>
            validateFocusedRustLaneSelection({
                lane: 'rust-kernel-heavy',
                testFilter: 'heavy_rust_kernel_expensive',
                tests: [{ ignored: true, testName: heavyTestName }],
            }),
        ).toThrow('same leaf name');
    });

    it('exposes only the two live generic Rust lanes', () => {
        expect(focusedRustLaneScripts).toEqual({
            'rust-kernel-fast': 'test:rust:kernel',
            'rust-kernel-heavy': 'test:rust:kernel:heavy',
        });
        expect(heavyTestName).toContain(heavyRustKernelTestNamePrefix);
    });
});
