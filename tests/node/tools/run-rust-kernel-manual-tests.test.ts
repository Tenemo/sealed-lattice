import { describe, expect, it } from 'vitest';

import { preflightAndRunManualRustKernelLane } from '#tools/ci/run-rust-kernel-manual-tests';
import {
    fullProfileEvidenceRustTests,
    measurementRustTests,
    phaseLivenessEvidenceRustTests,
    validateFocusedRustLaneSelection,
} from '#tools/ci/rust-focused-lane-selection';

describe('manual Rust kernel preflight', () => {
    it('preflights every configured name before starting the guarded executor', async () => {
        const missingTestName =
            'foundation::selected_suite::tests::deleted_candidate_gate';
        const verifiedTestFilters: string[] = [];
        let guardedExecutorCallCount = 0;

        await expect(
            preflightAndRunManualRustKernelLane({
                configuredTestNames: [
                    ...fullProfileEvidenceRustTests,
                    missingTestName,
                ],
                lane: 'rust-full-profile-evidence',
                runGuardedCommands: () => {
                    guardedExecutorCallCount += 1;
                    return Promise.resolve();
                },
                verifyLaneSelection: (input) => {
                    verifiedTestFilters.push(input.testFilter);
                    validateFocusedRustLaneSelection({
                        lane: input.lane,
                        testFilter: input.testFilter,
                        tests:
                            input.testFilter === missingTestName
                                ? []
                                : [
                                      {
                                          ignored: true,
                                          testName: input.testFilter,
                                      },
                                  ],
                    });
                    return Promise.resolve();
                },
            }),
        ).rejects.toThrow('selects zero tests');

        expect(verifiedTestFilters).toEqual([
            ...fullProfileEvidenceRustTests,
            missingTestName,
        ]);
        expect(guardedExecutorCallCount).toBe(0);
    });

    it('refuses an empty configured registry without starting preflight or execution', async () => {
        let guardedExecutorCallCount = 0;
        let verifierCallCount = 0;

        await expect(
            preflightAndRunManualRustKernelLane({
                configuredTestNames: [],
                lane: 'rust-measurements',
                runGuardedCommands: () => {
                    guardedExecutorCallCount += 1;
                    return Promise.resolve();
                },
                verifyLaneSelection: () => {
                    verifierCallCount += 1;
                    return Promise.resolve();
                },
            }),
        ).rejects.toThrow('has no configured Rust tests');

        expect(verifierCallCount).toBe(0);
        expect(guardedExecutorCallCount).toBe(0);
    });

    it('refuses a focused filter outside the exact registry before inventory or execution', async () => {
        let guardedExecutorCallCount = 0;
        let verifierCallCount = 0;

        await expect(
            preflightAndRunManualRustKernelLane({
                configuredTestNames: measurementRustTests,
                focusedFilter: 'deleted_selected_measurement',
                lane: 'rust-measurements',
                runGuardedCommands: () => {
                    guardedExecutorCallCount += 1;
                    return Promise.resolve();
                },
                verifyLaneSelection: () => {
                    verifierCallCount += 1;
                    return Promise.resolve();
                },
            }),
        ).rejects.toThrow('selects zero configured Rust tests');

        expect(verifierCallCount).toBe(0);
        expect(guardedExecutorCallCount).toBe(0);
    });

    it('resolves a libtest substring inside the exact registry before preflight', async () => {
        const focusedFilter = 'static_resource_accounting_emits_run_attachment';
        const verifiedTestFilters: string[] = [];
        let executedTestFilters: readonly string[] = [];

        await preflightAndRunManualRustKernelLane({
            configuredTestNames: measurementRustTests,
            focusedFilter,
            lane: 'rust-measurements',
            runGuardedCommands: (testFilters) => {
                executedTestFilters = testFilters;
                return Promise.resolve();
            },
            verifyLaneSelection: (input) => {
                verifiedTestFilters.push(input.testFilter);
                return Promise.resolve();
            },
        });

        expect(verifiedTestFilters).toEqual([focusedFilter]);
        expect(executedTestFilters).toEqual([focusedFilter]);
    });

    it('keeps complete phase-liveness closure in its guarded registry', async () => {
        const verifiedTestFilters: string[] = [];
        let executedTestFilters: readonly string[] = [];

        await preflightAndRunManualRustKernelLane({
            configuredTestNames: phaseLivenessEvidenceRustTests,
            lane: 'rust-phase-liveness-evidence',
            runGuardedCommands: (testFilters) => {
                executedTestFilters = testFilters;
                return Promise.resolve();
            },
            verifyLaneSelection: (input) => {
                verifiedTestFilters.push(input.testFilter);
                return Promise.resolve();
            },
        });

        expect(verifiedTestFilters).toEqual(phaseLivenessEvidenceRustTests);
        expect(executedTestFilters).toEqual(phaseLivenessEvidenceRustTests);
    });
});
