import { describe, expect, it } from 'vitest';

import {
    buildManualRustKernelEnvironment,
    controlledQuotientConstraintCheckpointStopOutputPrefix,
    parseControlledQuotientConstraintCheckpointStopOutput,
    parseManualRustKernelArguments,
    preflightAndRunManualRustKernelLane,
    rustProofEvidenceCheckpointResumeEnvironmentVariable,
    rustProofEvidenceStopAfterQuotientConstraintCheckpointEnvironmentVariable,
    stopAfterQuotientConstraintCheckpointArgument,
} from '#tools/ci/run-rust-kernel-manual-tests';
import {
    fullProfileEvidenceRustTests,
    measurementRustTests,
    phaseLivenessEvidenceRustTests,
    proofEvidenceRustTests,
    resolvePrimitiveMeasurementRustTestCases,
    theoremEvidenceRustTests,
    validateFocusedRustLaneSelection,
    vssPrerequisiteProofEvidenceRustTest,
    vssFusedRadix51ProjectionOwnerRustFilter,
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

    it('resolves a focused substring to its exact registered test without compiling an inventory', async () => {
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

        expect(verifiedTestFilters).toEqual([]);
        expect(executedTestFilters).toEqual([
            measurementRustTests.find((testName) =>
                testName.includes(focusedFilter),
            ),
        ]);
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

    it('owns resumable exact proofs in one serialized guarded registry', async () => {
        const environment = buildManualRustKernelEnvironment({
            baseEnvironment: {
                [rustProofEvidenceCheckpointResumeEnvironmentVariable]: '0',
            },
            lane: 'rust-proof-evidence',
            targetDirectoryPath: 'proof-evidence-target',
        });
        expect(environment).toMatchObject({
            CARGO_BUILD_JOBS: '1',
            CARGO_TARGET_DIR: 'proof-evidence-target',
            RAYON_NUM_THREADS: '1',
            [rustProofEvidenceCheckpointResumeEnvironmentVariable]: '1',
            SEALED_LATTICE_TRUSTEE_PROOF_LIMB_BATCH_SIZE: '1',
        });

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
                    [rustProofEvidenceCheckpointResumeEnvironmentVariable]: '1',
                },
                lane: 'rust-phase-liveness-evidence',
                targetDirectoryPath: 'phase-liveness-target',
            })[rustProofEvidenceCheckpointResumeEnvironmentVariable],
        ).toBeUndefined();
        expect(
            environment[
                rustProofEvidenceStopAfterQuotientConstraintCheckpointEnvironmentVariable
            ],
        ).toBeUndefined();
    });

    it('owns a controlled quotient-constraint stop only for the focused VSS proof', () => {
        expect(
            parseManualRustKernelArguments([
                'rust-proof-evidence',
                '--',
                'exact_vss_prerequisite_proof_round_trip',
                stopAfterQuotientConstraintCheckpointArgument,
            ]),
        ).toEqual({
            focusedFilter: 'exact_vss_prerequisite_proof_round_trip',
            lane: 'rust-proof-evidence',
            stopAfterQuotientConstraintCheckpoint: true,
        });
        const environment = buildManualRustKernelEnvironment({
            baseEnvironment: {
                [rustProofEvidenceStopAfterQuotientConstraintCheckpointEnvironmentVariable]:
                    'hostile-inherited-value',
            },
            lane: 'rust-proof-evidence',
            stopAfterQuotientConstraintCheckpoint: true,
            targetDirectoryPath: 'proof-evidence-target',
        });
        expect(environment).toMatchObject({
            [rustProofEvidenceCheckpointResumeEnvironmentVariable]: '1',
            [rustProofEvidenceStopAfterQuotientConstraintCheckpointEnvironmentVariable]:
                '1',
        });
        expect(() =>
            parseManualRustKernelArguments([
                'rust-proof-evidence',
                'exact_aggregate_wide_same_secret_proof_round_trip',
                stopAfterQuotientConstraintCheckpointArgument,
            ]),
        ).toThrow('requires the focused production VSS prerequisite proof');
        expect(() =>
            parseManualRustKernelArguments([
                'rust-proof-evidence',
                stopAfterQuotientConstraintCheckpointArgument,
            ]),
        ).toThrow('requires the focused production VSS prerequisite proof');
        expect(() =>
            buildManualRustKernelEnvironment({
                lane: 'rust-measurements',
                stopAfterQuotientConstraintCheckpoint: true,
                targetDirectoryPath: 'measurement-target',
            }),
        ).toThrow('Only the Rust proof-evidence lane');
        expect(vssPrerequisiteProofEvidenceRustTest).toContain(
            'exact_vss_prerequisite_proof_round_trip',
        );
    });

    it('requires one authenticated and cancelled controlled-stop record', () => {
        const record = {
            authenticatedAfterWrite: true,
            cancellationCompleted: true,
            checkpointByteLength: 5_193,
            completedConstraintCount: 64,
            elapsedMilliseconds: 81_245,
            familyIdentifier: 'selected-vss-prerequisite-proof',
            maximumDeclaredExternalMemoryByteLength: 587_202_560,
            resumedFromAuthenticatedBoundary: 1,
            standardCheckpointCount: 2,
        };
        const encodedRecord = `${controlledQuotientConstraintCheckpointStopOutputPrefix}${JSON.stringify(record)}`;
        expect(
            parseControlledQuotientConstraintCheckpointStopOutput(
                `timestamp [stdout] ${encodedRecord}\n`,
            ),
        ).toEqual(record);
        expect(() =>
            parseControlledQuotientConstraintCheckpointStopOutput(
                `${encodedRecord}\n${encodedRecord}\n`,
            ),
        ).toThrow('exactly one terminal record');
        expect(() =>
            parseControlledQuotientConstraintCheckpointStopOutput(
                `${controlledQuotientConstraintCheckpointStopOutputPrefix}${JSON.stringify(
                    {
                        ...record,
                        authenticatedAfterWrite: false,
                    },
                )}\n`,
            ),
        ).toThrow('wrong terminal classification');
        expect(() =>
            parseControlledQuotientConstraintCheckpointStopOutput(
                `${controlledQuotientConstraintCheckpointStopOutputPrefix}${JSON.stringify(
                    {
                        ...record,
                        trailingProducerClaim: 'ignored',
                    },
                )}\n`,
            ),
        ).toThrow('wrong fields');
    });

    it('expands a broad proof-evidence filter only to registered exact tests', async () => {
        let executedTestFilters: readonly string[] = [];
        await preflightAndRunManualRustKernelLane({
            configuredTestNames: proofEvidenceRustTests,
            focusedFilter: 'exact_',
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

    it('preflights every theorem test under the theorem-only Cargo feature', async () => {
        const verifiedTestFilters: string[] = [];
        const verifiedCargoFeatures: string[][] = [];
        let executedTestFilters: readonly string[] = [];

        await preflightAndRunManualRustKernelLane({
            cargoFeatures: ['theorem-evidence'],
            configuredTestNames: theoremEvidenceRustTests,
            lane: 'rust-theorem-evidence',
            runGuardedCommands: (testFilters) => {
                executedTestFilters = testFilters;
                return Promise.resolve();
            },
            verifyLaneSelection: (input) => {
                verifiedTestFilters.push(input.testFilter);
                verifiedCargoFeatures.push([...(input.cargoFeatures ?? [])]);
                return Promise.resolve();
            },
        });

        expect(verifiedTestFilters).toEqual(theoremEvidenceRustTests);
        expect(verifiedCargoFeatures).toEqual(
            theoremEvidenceRustTests.map(() => ['theorem-evidence']),
        );
        expect(executedTestFilters).toEqual(theoremEvidenceRustTests);
    });

    it('preflights bounded measurements under their isolated Cargo feature', async () => {
        const verifiedCargoFeatures: string[][] = [];
        const verifiedReleaseProfiles: boolean[] = [];

        const configuredMeasurement =
            measurementRustTests.find((testName) =>
                testName.includes(
                    'selected_vss_source_replay_emits_measurement',
                ),
            ) ?? '';
        await preflightAndRunManualRustKernelLane({
            cargoFeatures: ['primitive-measurement-evidence'],
            configuredTestNames: [configuredMeasurement],
            lane: 'rust-measurements',
            runGuardedCommands: () => Promise.resolve(),
            useReleaseProfile: true,
            verifyLaneSelection: (input) => {
                verifiedCargoFeatures.push([...(input.cargoFeatures ?? [])]);
                verifiedReleaseProfiles.push(input.useReleaseProfile === true);
                return Promise.resolve();
            },
        });

        expect(verifiedCargoFeatures).toEqual([
            ['primitive-measurement-evidence'],
        ]);
        expect(verifiedReleaseProfiles).toEqual([true]);
    });

    it('runs a registry-owned focused filter without invoking Cargo inventory', async () => {
        let executedTestFilters: readonly string[] = [];
        let verifierCallCount = 0;

        await preflightAndRunManualRustKernelLane({
            configuredTestNames: measurementRustTests,
            focusedFilter: 'selected_authenticated_scratch_record_codec',
            lane: 'rust-measurements',
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
            measurementRustTests.find((testName) =>
                testName.includes(
                    'selected_authenticated_scratch_record_codec',
                ),
            ),
        ]);
    });

    it('expands the fused radix-51 projection owner selector to its exact release tests', async () => {
        let executedTestFilters: readonly string[] = [];

        await preflightAndRunManualRustKernelLane({
            configuredTestNames: measurementRustTests,
            focusedFilter: vssFusedRadix51ProjectionOwnerRustFilter,
            lane: 'rust-measurements',
            runGuardedCommands: (testFilters) => {
                executedTestFilters = testFilters;
                return Promise.resolve();
            },
            verifyLaneSelection: () =>
                Promise.reject(new Error('Focused inventory must not run.')),
        });

        expect(executedTestFilters).toEqual(
            resolvePrimitiveMeasurementRustTestCases(
                vssFusedRadix51ProjectionOwnerRustFilter,
            ).map(({ testName }) => testName),
        );
        expect(executedTestFilters).toHaveLength(8);
    });
});
