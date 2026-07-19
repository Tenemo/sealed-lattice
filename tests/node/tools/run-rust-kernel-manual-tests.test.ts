import { describe, expect, it } from 'vitest';

import { preflightAndRunManualRustKernelLane } from '#tools/ci/run-rust-kernel-manual-tests';
import {
    fullProfileEvidenceRustTests,
    measurementRustTests,
    validateFocusedRustLaneSelection,
} from '#tools/ci/rust-focused-lane-selection';

describe('manual Rust kernel preflight', () => {
    it('preflights every configured name before starting the guarded executor', async () => {
        const currentTestName = fullProfileEvidenceRustTests[0];
        const missingTestName =
            'foundation::selected_suite::tests::deleted_candidate_gate';
        const verifiedTestFilters: string[] = [];
        let guardedExecutorCallCount = 0;

        await expect(
            preflightAndRunManualRustKernelLane({
                lane: 'rust-full-profile-evidence',
                runGuardedCommands: () => {
                    guardedExecutorCallCount += 1;
                    return Promise.resolve();
                },
                testFilters: [currentTestName, missingTestName],
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
                                          testName: currentTestName,
                                      },
                                  ],
                    });
                    return Promise.resolve();
                },
            }),
        ).rejects.toThrow('selects zero tests');

        expect(verifiedTestFilters).toEqual([currentTestName, missingTestName]);
        expect(guardedExecutorCallCount).toBe(0);
    });

    it('refuses an empty configured registry without starting preflight or execution', async () => {
        let guardedExecutorCallCount = 0;
        let verifierCallCount = 0;

        await expect(
            preflightAndRunManualRustKernelLane({
                lane: 'rust-measurements',
                runGuardedCommands: () => {
                    guardedExecutorCallCount += 1;
                    return Promise.resolve();
                },
                testFilters: measurementRustTests,
                verifyLaneSelection: () => {
                    verifierCallCount += 1;
                    return Promise.resolve();
                },
            }),
        ).rejects.toThrow('has no configured Rust tests');

        expect(verifierCallCount).toBe(0);
        expect(guardedExecutorCallCount).toBe(0);
    });
});
