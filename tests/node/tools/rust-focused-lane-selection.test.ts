import { describe, expect, it } from 'vitest';

import {
    fullProfileEvidenceRustTests,
    measurementRustTests,
    phaseLivenessEvidenceRustTests,
    proofEvidenceRustTests,
    retiredRejectedBackendRustTests,
    theoremEvidenceRustTests,
    validateCompleteRustLaneOwnership,
    validateFocusedRustLaneSelection,
} from '#tools/ci/rust-focused-lane-selection';
import {
    heavyRustKernelTestNamePrefix,
    rejectedRowCodeBackendRustTestNamePrefix,
} from '#tools/ci/rust-kernel-test-arguments';

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
                    testName: proofEvidenceRustTests[0],
                },
                {
                    ignored: true,
                    testName: retiredRejectedBackendRustTests[0],
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
                    testName: proofEvidenceRustTests[0],
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
        ...phaseLivenessEvidenceRustTests.map(
            (testName) =>
                ['rust-phase-liveness-evidence', true, testName] as [
                    'rust-phase-liveness-evidence',
                    boolean,
                    string,
                ],
        ),
        ...proofEvidenceRustTests.map(
            (testName) =>
                ['rust-proof-evidence', true, testName] as [
                    'rust-proof-evidence',
                    boolean,
                    string,
                ],
        ),
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

    it('owns every rejected-backend evidence test as non-executable history', () => {
        for (const retiredTestName of retiredRejectedBackendRustTests) {
            const inventoryEntry = {
                ignored: true,
                testName: retiredTestName,
            } as const;

            expect(() =>
                validateCompleteRustLaneOwnership([inventoryEntry]),
            ).not.toThrow();
            expect(() =>
                validateFocusedRustLaneSelection({
                    lane: 'rust-proof-evidence',
                    testFilter: retiredTestName,
                    tests: [inventoryEntry],
                }),
            ).toThrow('retired non-executable Rust history');
        }
    });

    it('owns regular rejected-backend tests as non-executable history', () => {
        const retiredTestName = `${rejectedRowCodeBackendRustTestNamePrefix}generation_state::tests::ordinary_archived_test`;
        const inventoryEntry = {
            ignored: false,
            testName: retiredTestName,
        } as const;

        expect(() =>
            validateCompleteRustLaneOwnership([inventoryEntry]),
        ).not.toThrow();
        expect(() =>
            validateFocusedRustLaneSelection({
                lane: 'rust-kernel-fast',
                testFilter: retiredTestName,
                tests: [inventoryEntry],
            }),
        ).toThrow('retired non-executable Rust history');
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
                lane: 'rust-proof-evidence',
                testFilter: proofEvidenceRustTests[0],
                tests: [
                    {
                        ignored: false,
                        testName: proofEvidenceRustTests[0],
                    },
                ],
            }),
        ).toThrow('multiple Rust lanes');
    });

    it('keeps rejected-backend registries empty and disjoint from active evidence', () => {
        const activeEvidenceTestNames = [
            ...fullProfileEvidenceRustTests,
            ...measurementRustTests,
            ...phaseLivenessEvidenceRustTests,
            ...proofEvidenceRustTests,
            ...theoremEvidenceRustTests,
        ];

        expect(measurementRustTests).toEqual([]);
        expect(phaseLivenessEvidenceRustTests).toEqual([]);
        expect(theoremEvidenceRustTests).toEqual([]);
        expect(new Set(retiredRejectedBackendRustTests).size).toBe(
            retiredRejectedBackendRustTests.length,
        );
        for (const retiredTestName of retiredRejectedBackendRustTests) {
            expect(activeEvidenceTestNames).not.toContain(retiredTestName);
        }
        expect(retiredRejectedBackendRustTests).toContain(
            'bgv::proof_suite::resource_accounting_evidence::tests::selected_candidate_static_resource_accounting_emits_run_attachment',
        );
        expect(retiredRejectedBackendRustTests).toContain(
            'bgv::proof_suite::collective_public_key_runtime::tests::selected_collective_public_key_accounting_separates_live_memory_storage_and_traffic',
        );
    });
});
