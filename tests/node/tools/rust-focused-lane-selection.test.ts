import { describe, expect, it } from 'vitest';

import {
    fullProfileEvidenceRustTests,
    measurementRustTests,
    phaseLivenessEvidenceRustTests,
    validateFocusedRustLaneSelection,
} from '#tools/ci/rust-focused-lane-selection';
import { heavyRustKernelTestNamePrefix } from '#tools/ci/rust-kernel-test-arguments';

describe('focused Rust lane selection', () => {
    it.each([
        ['rust-kernel-fast' as const, false, 'foundation::tests::ordinary'],
        [
            'rust-kernel-heavy' as const,
            true,
            'bgv::tests::heavy_rust_kernel_expensive_relation',
        ],
        [
            'rust-full-profile-evidence' as const,
            true,
            fullProfileEvidenceRustTests[0],
        ],
        [
            'rust-full-profile-evidence' as const,
            true,
            fullProfileEvidenceRustTests[1],
        ],
        ['rust-measurements' as const, true, measurementRustTests[0]],
        [
            'rust-phase-liveness-evidence' as const,
            true,
            phaseLivenessEvidenceRustTests[0],
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

    it('keeps the evaluator covering matrix exclusively in the full-profile lane', () => {
        const evaluatorCoveringMatrixTest = fullProfileEvidenceRustTests[0];
        const inventoryEntry = {
            ignored: true,
            testName: evaluatorCoveringMatrixTest,
        } as const;

        expect(evaluatorCoveringMatrixTest).not.toContain(
            heavyRustKernelTestNamePrefix,
        );
        expect(() =>
            validateFocusedRustLaneSelection({
                lane: 'rust-full-profile-evidence',
                testFilter: evaluatorCoveringMatrixTest,
                tests: [inventoryEntry],
            }),
        ).not.toThrow();
        expect(() =>
            validateFocusedRustLaneSelection({
                lane: 'rust-kernel-heavy',
                testFilter: evaluatorCoveringMatrixTest,
                tests: [inventoryEntry],
            }),
        ).toThrow('test:rust:kernel:full-profile-evidence');
    });

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

    it('rejects registered guarded tests that would also run in the fast lane', () => {
        expect(() =>
            validateFocusedRustLaneSelection({
                lane: 'rust-measurements',
                testFilter: measurementRustTests[0],
                tests: [
                    {
                        ignored: false,
                        testName: measurementRustTests[0],
                    },
                ],
            }),
        ).toThrow('multiple Rust lanes');
    });
});
