import { describe, expect, it } from 'vitest';

import { vssFusedRadix51ProjectionOwnerCaseIdentifiers } from '#tools/ci/primitive-measurement-evidence';
import {
    fullProfileEvidenceRustTests,
    measurementRustTests,
    phaseLivenessEvidenceRustTests,
    resolvePrimitiveMeasurementRustTestCases,
    theoremEvidenceRustTests,
    validateCompleteRustLaneOwnership,
    validateFocusedRustLaneSelection,
    vssFusedRadix51ProjectionOwnerRustFilter,
} from '#tools/ci/rust-focused-lane-selection';
import { heavyRustKernelTestNamePrefix } from '#tools/ci/rust-kernel-test-arguments';

describe('focused Rust lane selection', () => {
    it('assigns every discovered Rust test to exactly one lane', () => {
        expect(() =>
            validateCompleteRustLaneOwnership([
                {
                    ignored: false,
                    testName: 'foundation::tests::ordinary',
                },
                {
                    ignored: true,
                    testName:
                        'bgv::tests::heavy_rust_kernel_expensive_relation',
                },
                {
                    ignored: true,
                    testName: fullProfileEvidenceRustTests[0],
                },
                {
                    ignored: true,
                    testName: measurementRustTests[0],
                },
                {
                    ignored: true,
                    testName: phaseLivenessEvidenceRustTests[0],
                },
                {
                    ignored: true,
                    testName: theoremEvidenceRustTests[0],
                },
            ]),
        ).not.toThrow();
    });

    it('rejects an empty inventory and every discovered ignored test without an owner', () => {
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

    it('rejects test metadata that assigns one test to multiple lanes', () => {
        expect(() =>
            validateCompleteRustLaneOwnership([
                {
                    ignored: false,
                    testName: measurementRustTests[0],
                },
            ]),
        ).toThrow('belongs to multiple Rust lanes');
    });

    it.each([
        ['rust-kernel-fast' as const, false, 'foundation::tests::ordinary'],
        [
            'rust-kernel-heavy' as const,
            true,
            'bgv::tests::heavy_rust_kernel_expensive_relation',
        ],
        ...fullProfileEvidenceRustTests.map(
            (testName) =>
                ['rust-full-profile-evidence', true, testName] as [
                    'rust-full-profile-evidence',
                    boolean,
                    string,
                ],
        ),
        ['rust-measurements' as const, true, measurementRustTests[0]],
        ...phaseLivenessEvidenceRustTests.map(
            (testName) =>
                ['rust-phase-liveness-evidence', true, testName] as [
                    'rust-phase-liveness-evidence',
                    boolean,
                    string,
                ],
        ),
        ['rust-theorem-evidence' as const, true, theoremEvidenceRustTests[0]],
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

    it('keeps long evaluator evidence exclusively in the full-profile lane', () => {
        for (const evaluatorEvidenceTest of fullProfileEvidenceRustTests.slice(
            0,
            2,
        )) {
            const inventoryEntry = {
                ignored: true,
                testName: evaluatorEvidenceTest,
            } as const;

            expect(evaluatorEvidenceTest).not.toContain(
                heavyRustKernelTestNamePrefix,
            );
            expect(() =>
                validateFocusedRustLaneSelection({
                    lane: 'rust-full-profile-evidence',
                    testFilter: evaluatorEvidenceTest,
                    tests: [inventoryEntry],
                }),
            ).not.toThrow();
            expect(() =>
                validateFocusedRustLaneSelection({
                    lane: 'rust-kernel-heavy',
                    testFilter: evaluatorEvidenceTest,
                    tests: [inventoryEntry],
                }),
            ).toThrow('test:rust:kernel:full-profile-evidence');
        }
    });

    it('keeps construction theorem gates exclusively in the theorem-evidence lane', () => {
        for (const theoremEvidenceTest of theoremEvidenceRustTests) {
            const inventoryEntry = {
                ignored: true,
                testName: theoremEvidenceTest,
            } as const;

            expect(() =>
                validateFocusedRustLaneSelection({
                    lane: 'rust-theorem-evidence',
                    testFilter: theoremEvidenceTest,
                    tests: [inventoryEntry],
                }),
            ).not.toThrow();
            expect(() =>
                validateFocusedRustLaneSelection({
                    lane: 'rust-kernel-fast',
                    testFilter: theoremEvidenceTest,
                    tests: [inventoryEntry],
                }),
            ).toThrow('test:rust:kernel:theorem-evidence');
        }
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

    it('binds the radix-51 projection selector to the shared primitive case set', () => {
        expect(
            resolvePrimitiveMeasurementRustTestCases(
                vssFusedRadix51ProjectionOwnerRustFilter,
            ).map(({ caseIdentifier }) => caseIdentifier),
        ).toEqual(vssFusedRadix51ProjectionOwnerCaseIdentifiers);
        expect(
            resolvePrimitiveMeasurementRustTestCases(
                'vss_fused_bound_range_candidate',
            ).map(({ caseIdentifier }) => caseIdentifier),
        ).toEqual([11, 12]);
    });
});
