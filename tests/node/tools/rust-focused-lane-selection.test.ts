import { describe, expect, it } from 'vitest';

import {
    fullProfileEvidenceRustTests,
    measurementRustTests,
    validateFocusedRustLaneSelection,
} from '#tools/ci/rust-focused-lane-selection';

describe('focused Rust lane selection', () => {
    it.each([
        ['rust-kernel-fast' as const, false, 'foundation::tests::ordinary'],
        [
            'rust-accepted-setup' as const,
            false,
            'bgv::setup::tests::accepted_setup::ordinary_case',
        ],
        [
            'rust-kernel-heavy' as const,
            true,
            'bgv::tests::heavy_rust_kernel_expensive_relation',
        ],
        ['rust-measurements' as const, true, measurementRustTests[0]],
        [
            'rust-full-profile-evidence' as const,
            true,
            fullProfileEvidenceRustTests[0],
        ],
    ])(
        'accepts %s tests only in their owning lane',
        (lane, ignored, testName) => {
            expect(() =>
                validateFocusedRustLaneSelection({
                    lane,
                    testFilter: 'focused',
                    tests: [{ ignored, testName }],
                }),
            ).not.toThrow();
        },
    );

    it('fails closed for zero matches and cross-lane selections', () => {
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
                testFilter: 'heavy',
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
                testFilter: 'unowned',
                tests: [
                    {
                        ignored: true,
                        testName: 'foundation::tests::ignored_without_owner',
                    },
                ],
            }),
        ).toThrow('dedicated guarded command');
    });

    it('rejects test names that overlap guarded groups', () => {
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
});
