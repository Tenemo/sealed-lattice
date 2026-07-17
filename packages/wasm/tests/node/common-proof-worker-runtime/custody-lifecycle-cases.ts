import { foundationProfile } from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    openClosedWorkerCommonProofGenerationFamilyAdapter,
    openClosedWorkerCommonProofVerificationFamilyAdapter,
    releaseClosedWorkerCommonProofGenerationFamilyAdapter,
} from '../../../src/common-proof-worker-runtime.js';

import {
    createCommonProofGenerationCursorFixtureBytes,
    createExpectedWorkerCheckpointBoundary,
    createInstalledCommonProofGenerationFixture,
    createWorkerCheckpointBoundary,
    openReadyCommonProofApplication,
    openSameRealmCommonProofApplicationHost,
    workerCheckpointStateBytes,
} from './custody-fixtures.js';
import {
    applicationHandoffIndexKeySuffix,
    consumesCommonProofApplicationHandoff,
} from './wire-fixtures.js';

import {
    closeCommonProofExecutionEnvironmentInInstalledCustodyWorker,
    copyInstalledCommonProofCheckpointResumeDescriptor,
    openCommonProofExecutionEnvironmentInInstalledCustodyWorker,
    prepareCommonProofGenerationInInstalledCustodyWorker,
    retryPendingCommonProofApplicationInInstalledCustodyWorker,
    runCommonProofGenerationInInstalledCustodyWorker,
    suspendCommonProofExecutionEnvironmentForAuthenticatedResumeInInstalledCustodyWorker,
    verifyAndApplyCommonProofInInstalledCustodyWorker,
} from '#packages/protocol/src/runtime/browser-action-storage-custody-worker-channel';

type InstalledCustodyCommonProofExecutionEnvironment = Awaited<
    ReturnType<
        typeof openCommonProofExecutionEnvironmentInInstalledCustodyWorker
    >
>;

describe('common-proof custody lifecycle', () => {
    it('runs cancellation, authenticated resume, output verification, and durable application through installed custody', async () => {
        const generatedProofBytes = Uint8Array.from([8, 6, 7, 5, 3, 0, 9]);
        let completionAttemptCount = 0;
        let completionRetirementRetryCount = 0;
        const host = await openSameRealmCommonProofApplicationHost({
            decorateCommonProofCustody: (custody) =>
                Object.freeze({
                    ...custody,
                    completeVerifiedOutput: () => {
                        completionAttemptCount += 1;
                        if (completionAttemptCount === 1) {
                            return Promise.reject(
                                new Error(
                                    'Injected fail-once verified-output completion.',
                                ),
                            );
                        }
                        return custody.completeVerifiedOutput();
                    },
                    retire: async () => {
                        completionRetirementRetryCount += 1;
                        await custody.retire();
                    },
                }),
            proofBytes: generatedProofBytes,
        });
        let environment:
            | InstalledCustodyCommonProofExecutionEnvironment
            | undefined;
        try {
            const cursorBytes = createCommonProofGenerationCursorFixtureBytes(
                host.kernel,
            );
            const generationFixture =
                createInstalledCommonProofGenerationFixture(cursorBytes);
            const generationFamilyAdapter =
                openClosedWorkerCommonProofGenerationFamilyAdapter(
                    generationFixture.freshRuntime,
                    101,
                );
            const preparedOperation =
                prepareCommonProofGenerationInInstalledCustodyWorker(
                    host.installedHost,
                    {
                        foundationActionRandomnessHandleIdentifier:
                            host.actionRandomnessHandleIdentifier,
                        generationFamilyAdapter,
                    },
                );
            environment =
                await openCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    host.installedHost,
                    { preparedOperation },
                );
            await expect(
                openCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    host.installedHost,
                    { preparedOperation },
                ),
            ).rejects.toMatchObject({ code: 'InvalidInput' });
            const cancellationController = new AbortController();
            await expect(
                runCommonProofGenerationInInstalledCustodyWorker(environment, {
                    signal: cancellationController.signal,
                    yieldControl: () => {
                        cancellationController.abort(
                            'participant interrupted generation',
                        );
                        return Promise.resolve();
                    },
                }),
            ).rejects.toMatchObject({ code: 'Cancelled' });
            const copiedResumeDescriptor =
                copyInstalledCommonProofCheckpointResumeDescriptor(environment);
            expect(copiedResumeDescriptor).toBeDefined();
            if (copiedResumeDescriptor !== undefined) {
                copiedResumeDescriptor.checkpointLineageIdentifier.fill(0);
                copiedResumeDescriptor.commonProofEnvironmentIdentifier.fill(0);
                for (const copiedCursorBytes of copiedResumeDescriptor.orderedPrivateRandomCursorBytes) {
                    copiedCursorBytes.fill(0);
                }
                copiedResumeDescriptor.stableAttemptBindingHash.fill(0);
            }
            const resumeDescriptor =
                await suspendCommonProofExecutionEnvironmentForAuthenticatedResumeInInstalledCustodyWorker(
                    environment,
                );
            environment = undefined;
            const resumedGenerationFamilyAdapter =
                openClosedWorkerCommonProofGenerationFamilyAdapter(
                    generationFixture.resumeRuntime,
                    102,
                );
            const resumedPreparedOperation =
                prepareCommonProofGenerationInInstalledCustodyWorker(
                    host.installedHost,
                    {
                        foundationActionRandomnessHandleIdentifier:
                            host.actionRandomnessHandleIdentifier,
                        generationFamilyAdapter: resumedGenerationFamilyAdapter,
                    },
                );
            environment =
                await openCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    host.installedHost,
                    {
                        preparedOperation: resumedPreparedOperation,
                        resumeDescriptor,
                    },
                );
            resumeDescriptor.checkpointLineageIdentifier.fill(0);
            resumeDescriptor.commonProofEnvironmentIdentifier.fill(0);
            for (const resumeCursorBytes of resumeDescriptor.orderedPrivateRandomCursorBytes) {
                resumeCursorBytes.fill(0);
            }
            resumeDescriptor.stableAttemptBindingHash.fill(0);
            await runCommonProofGenerationInInstalledCustodyWorker(
                environment,
                {
                    yieldControl: () => Promise.resolve(),
                },
            );
            expect([...generationFixture.outputBytes]).toEqual([
                ...generatedProofBytes,
            ]);
            expect(generationFixture.observations).toEqual({
                acknowledgedCheckpointCount: 1,
                cancelledOperationReleaseCount: 1,
                discardedGenerationFamilyAdapterCount: 0,
                freshStorageResponseCount: 4,
                generatedCapabilityReleaseCount: 1,
                outputReadbackCount: 1,
                prefixReplayResponseCount: 4,
            });

            host.fixture.capability.release();
            const verificationFamilyAdapter =
                openClosedWorkerCommonProofVerificationFamilyAdapter(
                    host.fixture.runtime,
                    51,
                );
            const currentDurableBindingIdentifier =
                (await host.workerScope.send(
                    'open-foundation-witness-durable-binding',
                    {
                        stateObjectIdentifier: 'c'.repeat(64),
                        witnessRoleIdentifier: host.witnessRoleIdentifier,
                    },
                )) as string;
            await expect(
                verifyAndApplyCommonProofInInstalledCustodyWorker(environment, {
                    durableBindingIdentifier: currentDurableBindingIdentifier,
                    verificationFamilyAdapter,
                    witnessRoleIdentifier: host.witnessRoleIdentifier,
                    yieldControl: () => Promise.resolve(),
                }),
            ).resolves.toBeUndefined();
            expect(completionAttemptCount).toBe(1);
            expect(completionRetirementRetryCount).toBe(1);
            expect(host.fixture.observations).toEqual({
                abortedApplicationCount: 0,
                confirmedApplicationCount: 1,
                preparedApplicationCount: 1,
                releasedCapabilityCount: 1,
            });
            const retiredEnvironment = environment;
            expect(() =>
                copyInstalledCommonProofCheckpointResumeDescriptor(
                    retiredEnvironment,
                ),
            ).toThrowError(expect.objectContaining({ code: 'InvalidInput' }));
            environment = undefined;

            const unusedGenerationFamilyAdapter =
                openClosedWorkerCommonProofGenerationFamilyAdapter(
                    generationFixture.freshRuntime,
                    103,
                );
            const operationRetiredWithActionRandomness =
                prepareCommonProofGenerationInInstalledCustodyWorker(
                    host.installedHost,
                    {
                        foundationActionRandomnessHandleIdentifier:
                            host.actionRandomnessHandleIdentifier,
                        generationFamilyAdapter: unusedGenerationFamilyAdapter,
                    },
                );
            await host.workerScope.send(
                'close-foundation-action-randomness',
                host.actionRandomnessHandleIdentifier,
            );
            expect(
                generationFixture.observations
                    .discardedGenerationFamilyAdapterCount,
            ).toBe(1);
            await expect(
                openCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    host.installedHost,
                    { preparedOperation: operationRetiredWithActionRandomness },
                ),
            ).rejects.toMatchObject({ code: 'InvalidInput' });
        } finally {
            if (environment !== undefined) {
                await closeCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    environment,
                ).catch(() => undefined);
            }
            await host.close();
        }
    });

    it('retries the exact retained application after adapter rejection and CAS conflict', async () => {
        const readyApplication = await openReadyCommonProofApplication();
        let environment: typeof readyApplication.environment | undefined =
            readyApplication.environment;
        const pendingFailures: Array<'conflict' | 'reject'> = [
            'reject',
            'conflict',
        ];
        const observedHandoffIndexKeys: string[] = [];
        readyApplication.host.storageAdapter.classifyAtomicMutationFailure = (
            mutation,
        ) => {
            if (!consumesCommonProofApplicationHandoff(mutation)) {
                return undefined;
            }
            const handoffIndexKey = mutation.deletes.find((key) =>
                key.endsWith(applicationHandoffIndexKeySuffix),
            );
            if (handoffIndexKey !== undefined) {
                observedHandoffIndexKeys.push(handoffIndexKey);
            }
            return pendingFailures.shift();
        };
        try {
            const verificationFamilyAdapter =
                openClosedWorkerCommonProofVerificationFamilyAdapter(
                    readyApplication.host.fixture.runtime,
                    51,
                );
            await expect(
                verifyAndApplyCommonProofInInstalledCustodyWorker(environment, {
                    durableBindingIdentifier:
                        readyApplication.durableBindingIdentifier,
                    verificationFamilyAdapter,
                    witnessRoleIdentifier:
                        readyApplication.host.witnessRoleIdentifier,
                    yieldControl: () => Promise.resolve(),
                }),
            ).rejects.toMatchObject({ code: 'StorageFailure' });
            expect(
                readyApplication.host.workerScope.terminalNotifications,
            ).toEqual([]);
            expect(readyApplication.host.fixture.observations).toEqual({
                abortedApplicationCount: 1,
                confirmedApplicationCount: 0,
                preparedApplicationCount: 1,
                releasedCapabilityCount: 1,
            });

            await expect(
                retryPendingCommonProofApplicationInInstalledCustodyWorker(
                    environment,
                    {
                        durableBindingIdentifier:
                            readyApplication.durableBindingIdentifier,
                        witnessRoleIdentifier:
                            readyApplication.host.witnessRoleIdentifier,
                    },
                ),
            ).rejects.toMatchObject({ code: 'Conflict' });
            expect(
                readyApplication.host.workerScope.terminalNotifications,
            ).toEqual([]);
            expect(readyApplication.host.fixture.observations).toEqual({
                abortedApplicationCount: 2,
                confirmedApplicationCount: 0,
                preparedApplicationCount: 2,
                releasedCapabilityCount: 1,
            });

            await expect(
                retryPendingCommonProofApplicationInInstalledCustodyWorker(
                    environment,
                    {
                        durableBindingIdentifier:
                            readyApplication.durableBindingIdentifier,
                        witnessRoleIdentifier:
                            readyApplication.host.witnessRoleIdentifier,
                    },
                ),
            ).resolves.toBeUndefined();
            expect(pendingFailures).toEqual([]);
            expect(observedHandoffIndexKeys).toHaveLength(3);
            expect(new Set(observedHandoffIndexKeys).size).toBe(1);
            expect(readyApplication.host.fixture.observations).toEqual({
                abortedApplicationCount: 2,
                confirmedApplicationCount: 1,
                preparedApplicationCount: 3,
                releasedCapabilityCount: 1,
            });
            environment = undefined;
        } finally {
            if (environment !== undefined) {
                await closeCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    environment,
                ).catch(() => undefined);
            }
            await readyApplication.host.close();
        }
    });

    it('retires the host when a definitely unpublished pending application is closed', async () => {
        const readyApplication = await openReadyCommonProofApplication();
        let environment: typeof readyApplication.environment | undefined =
            readyApplication.environment;
        let applicationRejected = false;
        readyApplication.host.storageAdapter.classifyAtomicMutationFailure = (
            mutation,
        ) => {
            if (
                applicationRejected ||
                !consumesCommonProofApplicationHandoff(mutation)
            ) {
                return undefined;
            }
            applicationRejected = true;
            return 'reject';
        };
        try {
            const verificationFamilyAdapter =
                openClosedWorkerCommonProofVerificationFamilyAdapter(
                    readyApplication.host.fixture.runtime,
                    51,
                );
            await expect(
                verifyAndApplyCommonProofInInstalledCustodyWorker(environment, {
                    durableBindingIdentifier:
                        readyApplication.durableBindingIdentifier,
                    verificationFamilyAdapter,
                    witnessRoleIdentifier:
                        readyApplication.host.witnessRoleIdentifier,
                }),
            ).rejects.toMatchObject({ code: 'StorageFailure' });
            expect(applicationRejected).toBe(true);

            const retiredEnvironment = environment;
            await expect(
                closeCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    retiredEnvironment,
                ),
            ).rejects.toMatchObject({ code: 'OwnedWorkerFailure' });
            await expect(
                retryPendingCommonProofApplicationInInstalledCustodyWorker(
                    retiredEnvironment,
                    {
                        durableBindingIdentifier:
                            readyApplication.durableBindingIdentifier,
                        witnessRoleIdentifier:
                            readyApplication.host.witnessRoleIdentifier,
                    },
                ),
            ).rejects.toMatchObject({ code: 'InvalidInput' });
            await readyApplication.host.installedHost();
            expect(
                readyApplication.host.workerScope.terminalNotifications,
            ).toContainEqual(
                expect.objectContaining({
                    errorCode: 'OwnedWorkerFailure',
                    messageKind:
                        'browser-action-storage-custody-channel-failed',
                }),
            );
            environment = undefined;
        } finally {
            if (environment !== undefined) {
                await closeCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    environment,
                ).catch(() => undefined);
            }
            await readyApplication.host.close();
        }
    });

    it('fails closed after committed application readback authentication fails', async () => {
        const readyApplication = await openReadyCommonProofApplication();
        let environment: typeof readyApplication.environment | undefined =
            readyApplication.environment;
        let committedApplicationIndexRemoved = false;
        readyApplication.host.storageAdapter.afterAtomicMutation = (
            mutation,
        ) => {
            if (
                committedApplicationIndexRemoved ||
                !consumesCommonProofApplicationHandoff(mutation)
            ) {
                return;
            }
            const applicationIndexWrite = mutation.writes.find(
                (write) =>
                    write.key.includes('/indices/') &&
                    !write.key.endsWith(applicationHandoffIndexKeySuffix),
            );
            if (applicationIndexWrite !== undefined) {
                readyApplication.host.storageAdapter.rawDelete(
                    applicationIndexWrite.key,
                );
                committedApplicationIndexRemoved = true;
            }
        };
        try {
            const verificationFamilyAdapter =
                openClosedWorkerCommonProofVerificationFamilyAdapter(
                    readyApplication.host.fixture.runtime,
                    51,
                );
            const retiredEnvironment = environment;
            await expect(
                verifyAndApplyCommonProofInInstalledCustodyWorker(environment, {
                    durableBindingIdentifier:
                        readyApplication.durableBindingIdentifier,
                    verificationFamilyAdapter,
                    witnessRoleIdentifier:
                        readyApplication.host.witnessRoleIdentifier,
                    yieldControl: () => Promise.resolve(),
                }),
            ).rejects.toMatchObject({ code: 'OwnedWorkerFailure' });
            expect(committedApplicationIndexRemoved).toBe(true);
            expect(readyApplication.host.fixture.observations).toEqual({
                abortedApplicationCount: 0,
                confirmedApplicationCount: 0,
                preparedApplicationCount: 1,
                releasedCapabilityCount: 1,
            });
            await expect(
                retryPendingCommonProofApplicationInInstalledCustodyWorker(
                    retiredEnvironment,
                    {
                        durableBindingIdentifier:
                            readyApplication.durableBindingIdentifier,
                        witnessRoleIdentifier:
                            readyApplication.host.witnessRoleIdentifier,
                    },
                ),
            ).rejects.toMatchObject({ code: 'InvalidInput' });
            await readyApplication.host.installedHost();
            expect(
                readyApplication.host.workerScope.terminalNotifications,
            ).toContainEqual(
                expect.objectContaining({
                    errorCode: 'OwnedWorkerFailure',
                    messageKind:
                        'browser-action-storage-custody-channel-failed',
                }),
            );
            environment = undefined;
        } finally {
            if (environment !== undefined) {
                await closeCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    environment,
                ).catch(() => undefined);
            }
            await readyApplication.host.close();
        }
    });

    it('retains a prepared generation adapter until fail-once disposal succeeds', async () => {
        const host = await openSameRealmCommonProofApplicationHost();
        try {
            const cursorBytes = createCommonProofGenerationCursorFixtureBytes(
                host.kernel,
            );
            const generationFixture =
                createInstalledCommonProofGenerationFixture(cursorBytes, {
                    failFirstGenerationFamilyAdapterDiscard: true,
                });
            const preparedOperation =
                prepareCommonProofGenerationInInstalledCustodyWorker(
                    host.installedHost,
                    {
                        foundationActionRandomnessHandleIdentifier:
                            host.actionRandomnessHandleIdentifier,
                        generationFamilyAdapter:
                            openClosedWorkerCommonProofGenerationFamilyAdapter(
                                generationFixture.freshRuntime,
                                101,
                            ),
                    },
                );

            await expect(
                host.workerScope.send(
                    'close-foundation-action-randomness',
                    host.actionRandomnessHandleIdentifier,
                ),
            ).rejects.toMatchObject({ code: 'OwnedWorkerFailure' });
            expect(
                generationFixture.observations
                    .discardedGenerationFamilyAdapterCount,
            ).toBe(1);
            await expect(
                openCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    host.installedHost,
                    { preparedOperation },
                ),
            ).rejects.toMatchObject({ code: 'InvalidInput' });

            await expect(
                host.workerScope.send(
                    'close-foundation-action-randomness',
                    host.actionRandomnessHandleIdentifier,
                ),
            ).resolves.toBeUndefined();
            expect(
                generationFixture.observations
                    .discardedGenerationFamilyAdapterCount,
            ).toBe(2);
            await expect(
                openCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    host.installedHost,
                    { preparedOperation },
                ),
            ).rejects.toMatchObject({ code: 'InvalidInput' });
        } finally {
            await host.close();
        }
    });

    it('caps one prepared-or-executing proof chain without consuming rejected source adapters', async () => {
        const host = await openSameRealmCommonProofApplicationHost();
        let environment:
            | InstalledCustodyCommonProofExecutionEnvironment
            | undefined;
        try {
            const cursorBytes = createCommonProofGenerationCursorFixtureBytes(
                host.kernel,
            );
            const retainedFixture =
                createInstalledCommonProofGenerationFixture(cursorBytes);
            const preparedOperation =
                prepareCommonProofGenerationInInstalledCustodyWorker(
                    host.installedHost,
                    {
                        foundationActionRandomnessHandleIdentifier:
                            host.actionRandomnessHandleIdentifier,
                        generationFamilyAdapter:
                            openClosedWorkerCommonProofGenerationFamilyAdapter(
                                retainedFixture.freshRuntime,
                                101,
                            ),
                    },
                );
            const rejectedPreparedFixture =
                createInstalledCommonProofGenerationFixture(cursorBytes);
            const rejectedPreparedAdapter =
                openClosedWorkerCommonProofGenerationFamilyAdapter(
                    rejectedPreparedFixture.freshRuntime,
                    101,
                );
            expect(() =>
                prepareCommonProofGenerationInInstalledCustodyWorker(
                    host.installedHost,
                    {
                        foundationActionRandomnessHandleIdentifier:
                            host.actionRandomnessHandleIdentifier,
                        generationFamilyAdapter: rejectedPreparedAdapter,
                    },
                ),
            ).toThrowError(expect.objectContaining({ code: 'InvalidState' }));
            releaseClosedWorkerCommonProofGenerationFamilyAdapter(
                rejectedPreparedAdapter,
            );
            expect(
                rejectedPreparedFixture.observations
                    .discardedGenerationFamilyAdapterCount,
            ).toBe(1);

            environment =
                await openCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    host.installedHost,
                    { preparedOperation },
                );
            expect(
                retainedFixture.observations
                    .discardedGenerationFamilyAdapterCount,
            ).toBe(0);
            const rejectedExecutingFixture =
                createInstalledCommonProofGenerationFixture(cursorBytes);
            const rejectedExecutingAdapter =
                openClosedWorkerCommonProofGenerationFamilyAdapter(
                    rejectedExecutingFixture.freshRuntime,
                    101,
                );
            expect(() =>
                prepareCommonProofGenerationInInstalledCustodyWorker(
                    host.installedHost,
                    {
                        foundationActionRandomnessHandleIdentifier:
                            host.actionRandomnessHandleIdentifier,
                        generationFamilyAdapter: rejectedExecutingAdapter,
                    },
                ),
            ).toThrowError(expect.objectContaining({ code: 'InvalidState' }));
            releaseClosedWorkerCommonProofGenerationFamilyAdapter(
                rejectedExecutingAdapter,
            );
            expect(
                rejectedExecutingFixture.observations
                    .discardedGenerationFamilyAdapterCount,
            ).toBe(1);

            await closeCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                environment,
            );
            environment = undefined;
            expect(
                retainedFixture.observations
                    .discardedGenerationFamilyAdapterCount,
            ).toBe(1);
        } finally {
            if (environment !== undefined) {
                await closeCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    environment,
                ).catch(() => undefined);
            }
            await host.close();
        }
    });

    it('caps active checkpoint handles and preserves a refused source for retry after release', async () => {
        const host = await openSameRealmCommonProofApplicationHost();
        const checkpointIdentifiers: string[] = [];
        try {
            for (
                let checkpointIndex = 0;
                checkpointIndex < 64;
                checkpointIndex += 1
            ) {
                const streamAttemptIdentifier = new Uint8Array(32).fill(
                    checkpointIndex + 1,
                );
                const opened = (await host.workerScope.send(
                    'begin-checkpoint',
                    [streamAttemptIdentifier],
                )) as Readonly<{ checkpointIdentifier: string }>;
                checkpointIdentifiers.push(opened.checkpointIdentifier);
            }

            const refusedStreamAttemptIdentifier = new Uint8Array(32).fill(
                0xa5,
            );
            const retainedRefusedSource =
                refusedStreamAttemptIdentifier.slice();
            await expect(
                host.workerScope.send('begin-checkpoint', [
                    refusedStreamAttemptIdentifier,
                ]),
            ).rejects.toMatchObject({ code: 'InvalidState' });
            expect(refusedStreamAttemptIdentifier).toEqual(
                retainedRefusedSource,
            );

            const releasedCheckpointIdentifier = checkpointIdentifiers.shift();
            if (releasedCheckpointIdentifier === undefined) {
                throw new Error(
                    'The checkpoint capacity test opened no handle.',
                );
            }
            await host.workerScope.send(
                'evict-checkpoint',
                releasedCheckpointIdentifier,
            );
            const retried = (await host.workerScope.send('begin-checkpoint', [
                refusedStreamAttemptIdentifier,
            ])) as Readonly<{ checkpointIdentifier: string }>;
            checkpointIdentifiers.push(retried.checkpointIdentifier);

            for (const checkpointIdentifier of checkpointIdentifiers) {
                await host.workerScope.send(
                    'evict-checkpoint',
                    checkpointIdentifier,
                );
            }
            checkpointIdentifiers.length = 0;
        } finally {
            host.fixture.capability.release();
            await host.close();
        }
    });

    it('caps resumed checkpoint handles before store access and permits retry after an unrelated release', async () => {
        const host = await openSameRealmCommonProofApplicationHost();
        const checkpointIdentifiers: string[] = [];
        try {
            const persisted = (await host.workerScope.send(
                'begin-checkpoint',
                [],
            )) as Readonly<{ checkpointIdentifier: string }>;
            checkpointIdentifiers.push(persisted.checkpointIdentifier);
            const description = (await host.workerScope.send(
                'copy-checkpoint-description',
                persisted.checkpointIdentifier,
            )) as Readonly<{ checkpointLineageIdentifier: Uint8Array }>;
            const publicationIdentifier = (await host.workerScope.send(
                'begin-checkpoint-publication',
                {
                    boundary: createWorkerCheckpointBoundary(),
                    checkpointIdentifier: persisted.checkpointIdentifier,
                },
            )) as string;
            await host.workerScope.send('write-checkpoint-publication-chunk', {
                chunk: workerCheckpointStateBytes.slice(),
                publicationIdentifier,
            });
            await host.workerScope.send(
                'commit-checkpoint-publication',
                publicationIdentifier,
            );

            const unrelatedCheckpointIdentifiers: string[] = [];
            for (
                let checkpointIndex = 0;
                checkpointIndex < 63;
                checkpointIndex += 1
            ) {
                const opened = (await host.workerScope.send(
                    'begin-checkpoint',
                    [new Uint8Array(32).fill(checkpointIndex + 0x40)],
                )) as Readonly<{ checkpointIdentifier: string }>;
                unrelatedCheckpointIdentifiers.push(
                    opened.checkpointIdentifier,
                );
                checkpointIdentifiers.push(opened.checkpointIdentifier);
            }

            const resumeInput = {
                checkpointLineageIdentifier:
                    description.checkpointLineageIdentifier.slice(),
                expectedBoundary: createExpectedWorkerCheckpointBoundary(),
            };
            const retainedLineageIdentifier =
                resumeInput.checkpointLineageIdentifier.slice();
            await expect(
                host.workerScope.send('resume-checkpoint', resumeInput),
            ).rejects.toMatchObject({ code: 'InvalidState' });
            expect(resumeInput.checkpointLineageIdentifier).toEqual(
                retainedLineageIdentifier,
            );

            const releasedCheckpointIdentifier =
                unrelatedCheckpointIdentifiers.shift();
            if (releasedCheckpointIdentifier === undefined) {
                throw new Error(
                    'The resumed-checkpoint capacity test opened no unrelated handle.',
                );
            }
            await host.workerScope.send(
                'evict-checkpoint',
                releasedCheckpointIdentifier,
            );
            checkpointIdentifiers.splice(
                checkpointIdentifiers.indexOf(releasedCheckpointIdentifier),
                1,
            );
            const resumed = (await host.workerScope.send(
                'resume-checkpoint',
                resumeInput,
            )) as Readonly<{ checkpointIdentifier: string }>;
            checkpointIdentifiers.push(resumed.checkpointIdentifier);

            for (const checkpointIdentifier of checkpointIdentifiers) {
                await host.workerScope.send(
                    'evict-checkpoint',
                    checkpointIdentifier,
                );
            }
            checkpointIdentifiers.length = 0;
        } finally {
            host.fixture.capability.release();
            await host.close();
        }
    });

    it('refuses same-lineage checkpoint operations while a stream remains active', async () => {
        const host = await openSameRealmCommonProofApplicationHost();
        const checkpointIdentifiers: string[] = [];
        try {
            const opened = (await host.workerScope.send(
                'begin-checkpoint',
                [],
            )) as Readonly<{ checkpointIdentifier: string }>;
            checkpointIdentifiers.push(opened.checkpointIdentifier);
            const description = (await host.workerScope.send(
                'copy-checkpoint-description',
                opened.checkpointIdentifier,
            )) as Readonly<{ checkpointLineageIdentifier: Uint8Array }>;
            const resumeInput = {
                checkpointLineageIdentifier:
                    description.checkpointLineageIdentifier.slice(),
                expectedBoundary: createExpectedWorkerCheckpointBoundary(),
            };
            const publicationIdentifier = (await host.workerScope.send(
                'begin-checkpoint-publication',
                {
                    boundary: createWorkerCheckpointBoundary(),
                    checkpointIdentifier: opened.checkpointIdentifier,
                },
            )) as string;
            await host.workerScope.send('write-checkpoint-publication-chunk', {
                chunk: workerCheckpointStateBytes.slice(),
                publicationIdentifier,
            });

            await expect(
                host.workerScope.send(
                    'evict-checkpoint',
                    opened.checkpointIdentifier,
                ),
            ).rejects.toMatchObject({ code: 'InvalidState' });
            await expect(
                host.workerScope.send('resume-checkpoint', resumeInput),
            ).rejects.toMatchObject({ code: 'InvalidState' });

            await host.workerScope.send(
                'commit-checkpoint-publication',
                publicationIdentifier,
            );
            const resumed = (await host.workerScope.send(
                'resume-checkpoint',
                resumeInput,
            )) as Readonly<{ checkpointIdentifier: string }>;
            checkpointIdentifiers.push(resumed.checkpointIdentifier);
            const restoreIdentifier = (await host.workerScope.send(
                'begin-checkpoint-restore',
                resumed.checkpointIdentifier,
            )) as string;

            await expect(
                host.workerScope.send(
                    'evict-checkpoint',
                    resumed.checkpointIdentifier,
                ),
            ).rejects.toMatchObject({ code: 'InvalidState' });
            await expect(
                host.workerScope.send('resume-checkpoint', resumeInput),
            ).rejects.toMatchObject({ code: 'InvalidState' });
            await expect(
                host.workerScope.send('begin-checkpoint-publication', {
                    boundary: createWorkerCheckpointBoundary(),
                    checkpointIdentifier: opened.checkpointIdentifier,
                }),
            ).rejects.toMatchObject({ code: 'InvalidState' });

            await expect(
                host.workerScope.send(
                    'read-checkpoint-restore-chunk',
                    restoreIdentifier,
                ),
            ).resolves.toEqual({
                chunkBytes: workerCheckpointStateBytes,
                chunkIndex: 0,
                done: false,
            });
            await expect(
                host.workerScope.send(
                    'read-checkpoint-restore-chunk',
                    restoreIdentifier,
                ),
            ).resolves.toEqual({ done: true });
            for (const checkpointIdentifier of checkpointIdentifiers) {
                await host.workerScope.send(
                    'evict-checkpoint',
                    checkpointIdentifier,
                );
            }
            checkpointIdentifiers.length = 0;
        } finally {
            host.fixture.capability.release();
            await host.close();
        }
    });

    it('retains failed witness, randomness, and initialization cleanup ownership for retry', async () => {
        const host = await openSameRealmCommonProofApplicationHost({
            failActionRandomnessCloseAttemptNumbers: [1, 2, 3],
            failFirstFoundationWitnessClose: true,
        });
        try {
            await host.retainAdditionalFoundationInitializationBatches();
            host.fixture.capability.release();

            await expect(host.installedHost()).rejects.toMatchObject({
                code: 'OwnedWorkerFailure',
            });
            expect(host.cleanupAttemptCounts()).toEqual({
                actionRandomness: 3,
                foundationWitness: foundationProfile.participantCount - 1,
                stateObjectRelease: 0,
            });
            expect(host.ownedCustodyCloseCount()).toBe(0);

            await expect(host.installedHost()).resolves.toBeUndefined();
            expect(host.cleanupAttemptCounts()).toEqual({
                actionRandomness: 6,
                foundationWitness: foundationProfile.participantCount,
                stateObjectRelease: 0,
            });
            expect(host.ownedCustodyCloseCount()).toBe(1);
        } finally {
            await host.close();
        }
    });

    it('retains malformed initialization rollback ownership until an exact cleanup retry succeeds', async () => {
        const host = await openSameRealmCommonProofApplicationHost({
            failActionRandomnessCloseAttemptNumbers: [1],
            firstAdditionalInitializationWitnessCount:
                foundationProfile.participantCount - 2,
        });
        try {
            await expect(
                host.commitAdditionalFoundationOperationInitialization(),
            ).rejects.toMatchObject({
                code: 'OwnedWorkerFailure',
            });
            expect(host.cleanupAttemptCounts()).toEqual({
                actionRandomness: 1,
                foundationWitness: 0,
                stateObjectRelease: 0,
            });
            expect(host.ownedCustodyCloseCount()).toBe(0);

            await expect(
                host.commitAdditionalFoundationOperationInitialization(),
            ).resolves.toMatch(/^[0-9a-f]{64}$/u);
            expect(host.cleanupAttemptCounts()).toEqual({
                actionRandomness: 2,
                foundationWitness: 0,
                stateObjectRelease: 0,
            });

            await expect(host.installedHost()).resolves.toBeUndefined();
            expect(host.cleanupAttemptCounts()).toEqual({
                actionRandomness: 4,
                foundationWitness: 0,
                stateObjectRelease: 0,
            });
            expect(host.ownedCustodyCloseCount()).toBe(1);
        } finally {
            host.fixture.capability.release();
            await host.close();
        }
    });

    it('preserves an exact initialization batch across failed activation rollback and cleanup retry', async () => {
        const host = await openSameRealmCommonProofApplicationHost({
            failFirstAdditionalActivationHeadComparison: true,
            failFoundationWitnessCloseAttemptNumbers: [1],
        });
        try {
            const batchIdentifier =
                await host.commitAdditionalFoundationOperationInitialization();

            await expect(
                host.activateFreshFoundationInitialization(batchIdentifier),
            ).rejects.toMatchObject({
                code: 'OwnedWorkerFailure',
            });
            expect(host.cleanupAttemptCounts()).toEqual({
                actionRandomness: 0,
                foundationWitness: foundationProfile.participantCount - 1,
                stateObjectRelease: 0,
            });
            expect(host.ownedCustodyCloseCount()).toBe(0);

            const activated =
                await host.activateFreshFoundationInitialization(
                    batchIdentifier,
                );
            expect(activated.orderedWitnessRoleHandleIdentifiers).toHaveLength(
                foundationProfile.participantCount - 1,
            );
            expect(host.cleanupAttemptCounts()).toEqual({
                actionRandomness: 0,
                foundationWitness: foundationProfile.participantCount,
                stateObjectRelease: 0,
            });

            await expect(host.installedHost()).resolves.toBeUndefined();
            expect(host.cleanupAttemptCounts()).toEqual({
                actionRandomness: 2,
                foundationWitness:
                    foundationProfile.participantCount +
                    2 * (foundationProfile.participantCount - 1),
                stateObjectRelease: 0,
            });
            expect(host.ownedCustodyCloseCount()).toBe(1);
        } finally {
            host.fixture.capability.release();
            await host.close();
        }
    });

    it('retains a foundation state object until fail-once cleanup succeeds', async () => {
        const host = await openSameRealmCommonProofApplicationHost({
            failFirstStateObjectRelease: true,
        });
        try {
            await expect(
                host.retainFoundationStateReservationIntent(),
            ).resolves.toMatch(/^[0-9a-f]{64}$/u);
            host.fixture.capability.release();

            await expect(host.installedHost()).rejects.toMatchObject({
                code: 'OwnedWorkerFailure',
            });
            expect(host.cleanupAttemptCounts()).toEqual({
                actionRandomness: 1,
                foundationWitness: 0,
                stateObjectRelease: 1,
            });
            expect(host.ownedCustodyCloseCount()).toBe(0);

            await expect(host.installedHost()).resolves.toBeUndefined();
            expect(host.cleanupAttemptCounts()).toEqual({
                actionRandomness: 1,
                foundationWitness: 0,
                stateObjectRelease: 2,
            });
            expect(host.ownedCustodyCloseCount()).toBe(1);
        } finally {
            await host.close();
        }
    });

    it('drains an in-flight command before terminal worker cleanup', async () => {
        let releaseCommitGate: (() => void) | undefined;
        const commitGate = new Promise<void>((resolve) => {
            releaseCommitGate = resolve;
        });
        let reportCommitStarted: (() => void) | undefined;
        const commitStarted = new Promise<void>((resolve) => {
            reportCommitStarted = resolve;
        });
        const host = await openSameRealmCommonProofApplicationHost({
            additionalInitializationCommitGate: commitGate,
            onAdditionalInitializationCommitStarted: () =>
                reportCommitStarted?.(),
        });
        try {
            const inFlightCommit =
                host.retainAdditionalFoundationInitializationBatches();
            await commitStarted;

            host.workerScope.dispatchMalformedRequest({
                messageKind: 'malformed-concurrent-traffic',
            });
            expect(host.workerScope.terminalNotifications).toHaveLength(0);

            releaseCommitGate?.();
            await expect(inFlightCommit).rejects.toMatchObject({
                code: 'OwnedWorkerFailure',
            });
            expect(host.cleanupAttemptCounts()).toEqual({
                actionRandomness: 2,
                foundationWitness: 0,
                stateObjectRelease: 0,
            });
            expect(host.ownedCustodyCloseCount()).toBe(1);
            expect(host.workerScope.terminalNotifications).toHaveLength(1);
        } finally {
            releaseCommitGate?.();
            host.fixture.capability.release();
            await host.close();
        }
    });

    it('retains an authenticated resume descriptor until fail-once adapter disposal succeeds', async () => {
        const host = await openSameRealmCommonProofApplicationHost();
        let environment:
            | InstalledCustodyCommonProofExecutionEnvironment
            | undefined;
        try {
            const cursorBytes = createCommonProofGenerationCursorFixtureBytes(
                host.kernel,
            );
            const generationFixture =
                createInstalledCommonProofGenerationFixture(cursorBytes, {
                    failFirstGenerationFamilyAdapterDiscard: true,
                });
            const freshPreparedOperation =
                prepareCommonProofGenerationInInstalledCustodyWorker(
                    host.installedHost,
                    {
                        foundationActionRandomnessHandleIdentifier:
                            host.actionRandomnessHandleIdentifier,
                        generationFamilyAdapter:
                            openClosedWorkerCommonProofGenerationFamilyAdapter(
                                generationFixture.freshRuntime,
                                101,
                            ),
                    },
                );
            environment =
                await openCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    host.installedHost,
                    { preparedOperation: freshPreparedOperation },
                );
            const cancellationController = new AbortController();
            await expect(
                runCommonProofGenerationInInstalledCustodyWorker(environment, {
                    signal: cancellationController.signal,
                    yieldControl: () => {
                        cancellationController.abort(
                            'participant interrupted generation',
                        );
                        return Promise.resolve();
                    },
                }),
            ).rejects.toMatchObject({ code: 'Cancelled' });
            const initialResumeDescriptor =
                await suspendCommonProofExecutionEnvironmentForAuthenticatedResumeInInstalledCustodyWorker(
                    environment,
                );
            environment = undefined;
            const expectedCheckpointLineageIdentifier =
                initialResumeDescriptor.checkpointLineageIdentifier.slice();
            const expectedEnvironmentIdentifier =
                initialResumeDescriptor.commonProofEnvironmentIdentifier.slice();
            const expectedCursors =
                initialResumeDescriptor.orderedPrivateRandomCursorBytes.map(
                    (cursor) => cursor.slice(),
                );
            const expectedStableAttemptBindingHash =
                initialResumeDescriptor.stableAttemptBindingHash.slice();
            const resumedPreparedOperation =
                prepareCommonProofGenerationInInstalledCustodyWorker(
                    host.installedHost,
                    {
                        foundationActionRandomnessHandleIdentifier:
                            host.actionRandomnessHandleIdentifier,
                        generationFamilyAdapter:
                            openClosedWorkerCommonProofGenerationFamilyAdapter(
                                generationFixture.resumeRuntime,
                                102,
                            ),
                    },
                );
            environment =
                await openCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    host.installedHost,
                    {
                        preparedOperation: resumedPreparedOperation,
                        resumeDescriptor: initialResumeDescriptor,
                    },
                );
            initialResumeDescriptor.checkpointLineageIdentifier.fill(0);
            initialResumeDescriptor.commonProofEnvironmentIdentifier.fill(0);
            for (const resumeCursorBytes of initialResumeDescriptor.orderedPrivateRandomCursorBytes) {
                resumeCursorBytes.fill(0);
            }
            initialResumeDescriptor.stableAttemptBindingHash.fill(0);

            await expect(
                suspendCommonProofExecutionEnvironmentForAuthenticatedResumeInInstalledCustodyWorker(
                    environment,
                ),
            ).rejects.toMatchObject({ code: 'StorageFailure' });
            expect(
                generationFixture.observations
                    .discardedGenerationFamilyAdapterCount,
            ).toBe(1);
            expect(() =>
                copyInstalledCommonProofCheckpointResumeDescriptor(
                    environment!,
                ),
            ).toThrowError(expect.objectContaining({ code: 'InvalidInput' }));

            const retriedResumeDescriptor =
                await suspendCommonProofExecutionEnvironmentForAuthenticatedResumeInInstalledCustodyWorker(
                    environment,
                );
            environment = undefined;
            expect(
                generationFixture.observations
                    .discardedGenerationFamilyAdapterCount,
            ).toBe(2);
            expect([
                ...retriedResumeDescriptor.checkpointLineageIdentifier,
            ]).toEqual([...expectedCheckpointLineageIdentifier]);
            expect([
                ...retriedResumeDescriptor.commonProofEnvironmentIdentifier,
            ]).toEqual([...expectedEnvironmentIdentifier]);
            expect(
                retriedResumeDescriptor.orderedPrivateRandomCursorBytes.map(
                    (cursor) => [...cursor],
                ),
            ).toEqual(expectedCursors.map((cursor) => [...cursor]));
            expect([
                ...retriedResumeDescriptor.stableAttemptBindingHash,
            ]).toEqual([...expectedStableAttemptBindingHash]);
            retriedResumeDescriptor.checkpointLineageIdentifier.fill(0);
            retriedResumeDescriptor.commonProofEnvironmentIdentifier.fill(0);
            for (const cursor of retriedResumeDescriptor.orderedPrivateRandomCursorBytes) {
                cursor.fill(0);
            }
            retriedResumeDescriptor.stableAttemptBindingHash.fill(0);
            expectedCheckpointLineageIdentifier.fill(0);
            expectedEnvironmentIdentifier.fill(0);
            for (const cursor of expectedCursors) {
                cursor.fill(0);
            }
            expectedStableAttemptBindingHash.fill(0);
        } finally {
            if (environment !== undefined) {
                await closeCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    environment,
                ).catch(() => undefined);
            }
            await host.close();
        }
    });

    it('retains a verified capability until fail-once terminal disposal succeeds', async () => {
        const generatedProofBytes = Uint8Array.from([8, 6, 7, 5, 3, 0, 9]);
        const host = await openSameRealmCommonProofApplicationHost({
            failVerifiedCapabilityReleaseAttempt: 2,
            proofBytes: generatedProofBytes,
        });
        let environment:
            | InstalledCustodyCommonProofExecutionEnvironment
            | undefined;
        try {
            const cursorBytes = createCommonProofGenerationCursorFixtureBytes(
                host.kernel,
            );
            const generationFixture =
                createInstalledCommonProofGenerationFixture(cursorBytes);
            const freshPreparedOperation =
                prepareCommonProofGenerationInInstalledCustodyWorker(
                    host.installedHost,
                    {
                        foundationActionRandomnessHandleIdentifier:
                            host.actionRandomnessHandleIdentifier,
                        generationFamilyAdapter:
                            openClosedWorkerCommonProofGenerationFamilyAdapter(
                                generationFixture.freshRuntime,
                                101,
                            ),
                    },
                );
            environment =
                await openCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    host.installedHost,
                    { preparedOperation: freshPreparedOperation },
                );
            const cancellationController = new AbortController();
            await expect(
                runCommonProofGenerationInInstalledCustodyWorker(environment, {
                    signal: cancellationController.signal,
                    yieldControl: () => {
                        cancellationController.abort(
                            'participant interrupted generation',
                        );
                        return Promise.resolve();
                    },
                }),
            ).rejects.toMatchObject({ code: 'Cancelled' });
            const resumeDescriptor =
                await suspendCommonProofExecutionEnvironmentForAuthenticatedResumeInInstalledCustodyWorker(
                    environment,
                );
            environment = undefined;
            const resumedPreparedOperation =
                prepareCommonProofGenerationInInstalledCustodyWorker(
                    host.installedHost,
                    {
                        foundationActionRandomnessHandleIdentifier:
                            host.actionRandomnessHandleIdentifier,
                        generationFamilyAdapter:
                            openClosedWorkerCommonProofGenerationFamilyAdapter(
                                generationFixture.resumeRuntime,
                                102,
                            ),
                    },
                );
            environment =
                await openCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    host.installedHost,
                    {
                        preparedOperation: resumedPreparedOperation,
                        resumeDescriptor,
                    },
                );
            resumeDescriptor.checkpointLineageIdentifier.fill(0);
            resumeDescriptor.commonProofEnvironmentIdentifier.fill(0);
            for (const cursor of resumeDescriptor.orderedPrivateRandomCursorBytes) {
                cursor.fill(0);
            }
            resumeDescriptor.stableAttemptBindingHash.fill(0);
            await runCommonProofGenerationInInstalledCustodyWorker(
                environment,
                { yieldControl: () => Promise.resolve() },
            );

            host.fixture.capability.release();
            expect(host.fixture.observations.releasedCapabilityCount).toBe(1);
            const verificationFamilyAdapter =
                openClosedWorkerCommonProofVerificationFamilyAdapter(
                    host.fixture.runtime,
                    51,
                );
            const retiredEnvironment = environment;
            await expect(
                verifyAndApplyCommonProofInInstalledCustodyWorker(environment, {
                    durableBindingIdentifier: 'missing-durable-binding',
                    verificationFamilyAdapter,
                    witnessRoleIdentifier: host.witnessRoleIdentifier,
                    yieldControl: () => Promise.resolve(),
                }),
            ).rejects.toMatchObject({ code: 'OwnedWorkerFailure' });
            expect(host.fixture.observations.releasedCapabilityCount).toBe(3);
            await expect(
                closeCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    retiredEnvironment,
                ),
            ).rejects.toMatchObject({ code: 'InvalidInput' });
            environment = undefined;
        } finally {
            if (environment !== undefined) {
                await closeCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    environment,
                ).catch(() => undefined);
            }
            await host.close();
        }
    });

    it('retains action-randomness environments until fail-once retirement cleanup succeeds', async () => {
        let retirementAttemptCount = 0;
        const host = await openSameRealmCommonProofApplicationHost({
            decorateCommonProofCustody: (custody) =>
                Object.freeze({
                    ...custody,
                    retire: async () => {
                        retirementAttemptCount += 1;
                        if (retirementAttemptCount === 1) {
                            throw new Error(
                                'Injected fail-once installed retirement.',
                            );
                        }
                        await custody.retire();
                    },
                }),
        });
        let environment:
            | InstalledCustodyCommonProofExecutionEnvironment
            | undefined;
        try {
            const cursorBytes = createCommonProofGenerationCursorFixtureBytes(
                host.kernel,
            );
            const generationFixture =
                createInstalledCommonProofGenerationFixture(cursorBytes);
            const generationFamilyAdapter =
                openClosedWorkerCommonProofGenerationFamilyAdapter(
                    generationFixture.freshRuntime,
                    101,
                );
            const preparedOperation =
                prepareCommonProofGenerationInInstalledCustodyWorker(
                    host.installedHost,
                    {
                        foundationActionRandomnessHandleIdentifier:
                            host.actionRandomnessHandleIdentifier,
                        generationFamilyAdapter,
                    },
                );
            environment =
                await openCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    host.installedHost,
                    { preparedOperation },
                );

            await expect(
                host.workerScope.send(
                    'close-foundation-action-randomness',
                    host.actionRandomnessHandleIdentifier,
                ),
            ).rejects.toMatchObject({ code: 'OwnedWorkerFailure' });
            expect(retirementAttemptCount).toBe(1);
            await expect(
                host.workerScope.send(
                    'close-foundation-action-randomness',
                    host.actionRandomnessHandleIdentifier,
                ),
            ).resolves.toBeUndefined();
            expect(retirementAttemptCount).toBe(2);
            expect(
                generationFixture.observations
                    .discardedGenerationFamilyAdapterCount,
            ).toBe(1);
            environment = undefined;
        } finally {
            if (environment !== undefined) {
                await closeCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    environment,
                ).catch(() => undefined);
            }
            await host.close();
        }
    });

    it('permanently retires an installed resumed environment when checkpoint restoration is unusable', async () => {
        const host = await openSameRealmCommonProofApplicationHost();
        let environment:
            | InstalledCustodyCommonProofExecutionEnvironment
            | undefined;
        try {
            const cursorBytes = createCommonProofGenerationCursorFixtureBytes(
                host.kernel,
            );
            const generationFixture =
                createInstalledCommonProofGenerationFixture(cursorBytes, {
                    resumeCheckpointStateByteLength: 38,
                });
            const freshPreparedOperation =
                prepareCommonProofGenerationInInstalledCustodyWorker(
                    host.installedHost,
                    {
                        foundationActionRandomnessHandleIdentifier:
                            host.actionRandomnessHandleIdentifier,
                        generationFamilyAdapter:
                            openClosedWorkerCommonProofGenerationFamilyAdapter(
                                generationFixture.freshRuntime,
                                101,
                            ),
                    },
                );
            environment =
                await openCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    host.installedHost,
                    { preparedOperation: freshPreparedOperation },
                );
            const cancellationController = new AbortController();
            await expect(
                runCommonProofGenerationInInstalledCustodyWorker(environment, {
                    signal: cancellationController.signal,
                    yieldControl: () => {
                        cancellationController.abort(
                            'participant interrupted generation',
                        );
                        return Promise.resolve();
                    },
                }),
            ).rejects.toMatchObject({ code: 'Cancelled' });
            const resumeDescriptor =
                await suspendCommonProofExecutionEnvironmentForAuthenticatedResumeInInstalledCustodyWorker(
                    environment,
                );
            environment = undefined;
            const resumedPreparedOperation =
                prepareCommonProofGenerationInInstalledCustodyWorker(
                    host.installedHost,
                    {
                        foundationActionRandomnessHandleIdentifier:
                            host.actionRandomnessHandleIdentifier,
                        generationFamilyAdapter:
                            openClosedWorkerCommonProofGenerationFamilyAdapter(
                                generationFixture.resumeRuntime,
                                102,
                            ),
                    },
                );
            environment =
                await openCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    host.installedHost,
                    {
                        preparedOperation: resumedPreparedOperation,
                        resumeDescriptor,
                    },
                );
            resumeDescriptor.checkpointLineageIdentifier.fill(0);
            resumeDescriptor.commonProofEnvironmentIdentifier.fill(0);
            for (const resumeCursorBytes of resumeDescriptor.orderedPrivateRandomCursorBytes) {
                resumeCursorBytes.fill(0);
            }
            resumeDescriptor.stableAttemptBindingHash.fill(0);

            const retiredEnvironment = environment;
            await expect(
                runCommonProofGenerationInInstalledCustodyWorker(
                    retiredEnvironment,
                ),
            ).rejects.toMatchObject({
                code: 'StorageFailure',
                permanentRetirementRequired: true,
            });
            expect(generationFixture.resumeFamilyPreparationCount()).toBe(0);
            expect(
                generationFixture.observations
                    .discardedGenerationFamilyAdapterCount,
            ).toBe(1);
            expect(() =>
                copyInstalledCommonProofCheckpointResumeDescriptor(
                    retiredEnvironment,
                ),
            ).toThrowError(expect.objectContaining({ code: 'InvalidInput' }));
            await expect(
                closeCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    retiredEnvironment,
                ),
            ).rejects.toMatchObject({ code: 'InvalidInput' });
            environment = undefined;
        } finally {
            if (environment !== undefined) {
                await closeCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    environment,
                ).catch(() => undefined);
            }
            await host.close();
        }
    });
});
