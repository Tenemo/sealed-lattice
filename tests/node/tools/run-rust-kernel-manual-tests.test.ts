import { describe, expect, it } from 'vitest';

import {
    buildManualRustKernelEnvironment,
    compactProofEvidenceRunIdentifierEnvironmentVariable,
    parseManualRustKernelArguments,
    preflightAndRunManualRustKernelLane,
} from '#tools/ci/run-rust-kernel-manual-tests';
import {
    compactPublicKeyProofEvidenceGenerationAndVerificationRustTestName,
    compactPublicKeyProofEvidenceSeparateProcessRestorationRustTestName,
    fullProfileEvidenceRustTests,
    measurementRustTests,
    phaseLivenessEvidenceRustTests,
    proofEvidenceRustTests,
    theoremEvidenceRustTests,
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

    it.each([
        ['rust-measurements' as const, measurementRustTests],
        [
            'rust-phase-liveness-evidence' as const,
            phaseLivenessEvidenceRustTests,
        ],
        ['rust-theorem-evidence' as const, theoremEvidenceRustTests],
    ])(
        'refuses the retired %s registry before inventory or execution',
        async (lane, configuredTestNames) => {
            let guardedExecutorCallCount = 0;
            let verifierCallCount = 0;

            expect(configuredTestNames).toEqual([]);
            await expect(
                preflightAndRunManualRustKernelLane({
                    configuredTestNames,
                    lane,
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
        },
    );

    it('refuses duplicate registry entries before inventory or execution', async () => {
        const duplicateTestName = proofEvidenceRustTests[0];
        let guardedExecutorCallCount = 0;
        let verifierCallCount = 0;

        await expect(
            preflightAndRunManualRustKernelLane({
                configuredTestNames: [duplicateTestName, duplicateTestName],
                lane: 'rust-proof-evidence',
                runGuardedCommands: () => {
                    guardedExecutorCallCount += 1;
                    return Promise.resolve();
                },
                verifyLaneSelection: () => {
                    verifierCallCount += 1;
                    return Promise.resolve();
                },
            }),
        ).rejects.toThrow('duplicate configured Rust tests');

        expect(verifierCallCount).toBe(0);
        expect(guardedExecutorCallCount).toBe(0);
    });

    it('owns positive, hostile, and separate-process compact owners in one serialized registry', async () => {
        const environment = buildManualRustKernelEnvironment({
            baseEnvironment: {
                [compactProofEvidenceRunIdentifierEnvironmentVariable]:
                    'hostile-inherited-value',
            },
            lane: 'rust-proof-evidence',
            targetDirectoryPath: 'proof-evidence-target',
        });
        expect(environment).toMatchObject({
            CARGO_BUILD_JOBS: '1',
            CARGO_TARGET_DIR: 'proof-evidence-target',
            RAYON_NUM_THREADS: '1',
            SEALED_LATTICE_TRUSTEE_PROOF_LIMB_BATCH_SIZE: '1',
        });
        expect(
            environment[compactProofEvidenceRunIdentifierEnvironmentVariable],
        ).toMatch(/^[0-9a-f]{32}$/u);
        expect(
            environment[compactProofEvidenceRunIdentifierEnvironmentVariable],
        ).not.toBe('hostile-inherited-value');

        const verifiedTestFilters: string[] = [];
        let executedTestFilters: readonly string[] = [];
        await preflightAndRunManualRustKernelLane({
            configuredTestNames: proofEvidenceRustTests,
            environment,
            lane: 'rust-proof-evidence',
            runGuardedCommands: (testFilters) => {
                executedTestFilters = testFilters;
                return Promise.resolve();
            },
            verifyLaneSelection: (input) => {
                verifiedTestFilters.push(input.testFilter);
                expect(input.environment).toBe(environment);
                return Promise.resolve();
            },
        });

        expect(verifiedTestFilters).toEqual(proofEvidenceRustTests);
        expect(executedTestFilters).toEqual(proofEvidenceRustTests);
        expect(
            buildManualRustKernelEnvironment({
                baseEnvironment: {
                    [compactProofEvidenceRunIdentifierEnvironmentVariable]:
                        'hostile-inherited-value',
                },
                lane: 'rust-phase-liveness-evidence',
                targetDirectoryPath: 'phase-liveness-target',
            })[compactProofEvidenceRunIdentifierEnvironmentVariable],
        ).toBeUndefined();
    });

    it('rejects retired proof filters and the removed controlled-stop option', () => {
        expect(() =>
            parseManualRustKernelArguments([
                'rust-proof-evidence',
                'exact_vss_prerequisite_proof_round_trip',
            ]),
        ).toThrow('selects zero configured Rust tests');
        expect(() =>
            parseManualRustKernelArguments([
                'rust-proof-evidence',
                '--stop-after-quotient-constraint-checkpoint',
            ]),
        ).toThrow('Unknown argument');
    });

    it('expands the compact proof-evidence filter only to its three ordered compact owners', async () => {
        let executedTestFilters: readonly string[] = [];
        await preflightAndRunManualRustKernelLane({
            configuredTestNames: proofEvidenceRustTests,
            focusedFilter: 'compact_public_key',
            lane: 'rust-proof-evidence',
            runGuardedCommands: (testFilters) => {
                executedTestFilters = testFilters;
                return Promise.resolve();
            },
            verifyLaneSelection: () =>
                Promise.reject(new Error('Focused inventory must not run.')),
        });

        expect(executedTestFilters).toEqual(proofEvidenceRustTests);
    });

    it('expands a restoration-only request to its ordered producer and consumer before execution', async () => {
        let executedTestFilters: readonly string[] = [];
        let verifierCallCount = 0;

        await preflightAndRunManualRustKernelLane({
            configuredTestNames: proofEvidenceRustTests,
            focusedFilter: 'separate_process_restoration',
            lane: 'rust-proof-evidence',
            runGuardedCommands: (testFilters) => {
                executedTestFilters = testFilters;
                return Promise.resolve();
            },
            verifyLaneSelection: () => {
                verifierCallCount += 1;
                return Promise.reject(
                    new Error('Focused inventory must not run.'),
                );
            },
        });

        expect(verifierCallCount).toBe(0);
        expect(executedTestFilters).toEqual([
            compactPublicKeyProofEvidenceGenerationAndVerificationRustTestName,
            compactPublicKeyProofEvidenceSeparateProcessRestorationRustTestName,
        ]);
    });

    it('refuses restoration before execution when its producer is absent from the registry', async () => {
        let guardedExecutorCallCount = 0;
        let verifierCallCount = 0;

        await expect(
            preflightAndRunManualRustKernelLane({
                configuredTestNames: [
                    compactPublicKeyProofEvidenceSeparateProcessRestorationRustTestName,
                ],
                focusedFilter: 'separate_process_restoration',
                lane: 'rust-proof-evidence',
                runGuardedCommands: () => {
                    guardedExecutorCallCount += 1;
                    return Promise.resolve();
                },
                verifyLaneSelection: () => {
                    verifierCallCount += 1;
                    return Promise.resolve();
                },
            }),
        ).rejects.toThrow(
            'restoration requires its registered generation-and-verification producer',
        );

        expect(verifierCallCount).toBe(0);
        expect(guardedExecutorCallCount).toBe(0);
    });
});
