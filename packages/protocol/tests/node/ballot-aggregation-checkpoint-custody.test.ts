import { foundationProfile } from '@sealed-lattice/types';
import type {
    BallotAggregationCheckpointBoundary,
    ExpectedBallotAggregationCheckpointBoundary,
} from '@sealed-lattice/wasm';
import { describe, expect, it } from 'vitest';

import {
    openAuthenticatedCheckpointStore,
    type AuthenticatedCheckpointStore,
    type AuthenticatedCheckpointStoreLimits,
    type CheckpointBoundaryPolicy,
} from '#packages/protocol/src/runtime/authenticated-checkpoint-store';
import {
    generateRuntimeStorageEncryptionKey,
    hashFilledWith,
    InMemoryRuntimeStorageAdapter,
    openRuntimeTestStore,
    runtimeAuthorityContext,
} from '#packages/protocol/tests/support/runtime-storage-test-support';
import { createBallotAggregationCheckpointCustody } from '@sealed-lattice/protocol';

const checkpointStateStreamDomain =
    'sealed-lattice/ballot-aggregation-selection-checkpoint/v1';
const emptyPrivateRandomCursorManifestBytes = Uint8Array.of(
    0x53,
    0x4c,
    0x43,
    0x50,
    0x43,
    0x4d,
    0x30,
    0x33,
    0x03,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
);

const checkpointLimits: AuthenticatedCheckpointStoreLimits = {
    maximumActiveOperationIdentityCount: 1,
    maximumCheckpointStateByteLength:
        2 * foundationProfile.streamChunkByteLength,
    maximumManifestByteLength: 16_384,
    maximumRandomCursorManifestByteLength: 4_096,
    maximumRecordSealingCount: 128,
    maximumSourceDigestCount: 12,
    transactionLifetimeMilliseconds: 5_000,
};

const boundaryPolicy: CheckpointBoundaryPolicy = {
    validatePublication: () => undefined,
    validateResume: () => undefined,
};

const openCheckpointStore = async (): Promise<
    Readonly<{
        adapter: InMemoryRuntimeStorageAdapter;
        store: AuthenticatedCheckpointStore;
    }>
> => {
    const openedStorage = await openRuntimeTestStore({
        namespace: 'ballot-aggregation-checkpoint-custody-test',
    });
    return {
        adapter: openedStorage.adapter,
        store: openAuthenticatedCheckpointStore({
            authorityContext: runtimeAuthorityContext(),
            boundaryPolicy,
            encryptionKey: await generateRuntimeStorageEncryptionKey(),
            limits: checkpointLimits,
            store: openedStorage.store,
        }),
    };
};

const checkpointBoundary = (input: {
    ballotCandidateViewRoot: Uint8Array;
    stateStreamDescriptorBytes: Uint8Array;
}): BallotAggregationCheckpointBoundary => ({
    operationKind: 0x1404,
    orderedSourceDigests: [
        hashFilledWith(0x31),
        input.ballotCandidateViewRoot,
        hashFilledWith(0x51),
    ],
    privateRandomCursorManifestBytes: emptyPrivateRandomCursorManifestBytes,
    safeBoundaryOrdinal: 0,
    stateStreamDescriptorBytes: input.stateStreamDescriptorBytes,
    stateStreamDomain: checkpointStateStreamDomain,
});

const expectedCheckpointBoundary = (
    boundary: BallotAggregationCheckpointBoundary,
): ExpectedBallotAggregationCheckpointBoundary => ({
    operationKind: boundary.operationKind,
    orderedSourceDigests: boundary.orderedSourceDigests,
    privateRandomCursorManifestBytes: boundary.privateRandomCursorManifestBytes,
    safeBoundaryOrdinal: boundary.safeBoundaryOrdinal,
    stateStreamDomain: boundary.stateStreamDomain,
});

describe('Ballot aggregation checkpoint custody', () => {
    it('publishes and restores authenticated state only with identities it issued', async () => {
        const { store } = await openCheckpointStore();
        try {
            const custody = createBallotAggregationCheckpointCustody(store);
            const stateBytes = Uint8Array.of(0x14, 0x04, 0x18, 0x0a);
            const boundary = checkpointBoundary({
                ballotCandidateViewRoot: hashFilledWith(0x41),
                stateStreamDescriptorBytes: custody.describeStateStream({
                    stateBytes,
                    stateStreamDomain: checkpointStateStreamDomain,
                }),
            });
            const operationSignal = new AbortController().signal;
            const identity = await custody.beginOperation(operationSignal);
            const checkpointLineageIdentifier =
                identity.checkpointLineageIdentifier;
            identity.checkpointLineageIdentifier.fill(0xff);

            const forgedIdentity = Object.freeze({
                checkpointLineageIdentifier:
                    checkpointLineageIdentifier.slice(),
            });
            await expect(
                custody.publish({
                    boundary,
                    identity: forgedIdentity,
                    signal: operationSignal,
                    stateChunks: [stateBytes],
                }),
            ).rejects.toMatchObject({ code: 'InvalidInput' });
            await expect(
                custody.releaseOperationIdentity(forgedIdentity),
            ).rejects.toMatchObject({ code: 'InvalidInput' });

            const canonicalManifestBytes = await custody.publish({
                boundary,
                identity,
                signal: operationSignal,
                stateChunks: [stateBytes],
            });
            expect(canonicalManifestBytes.byteLength).toBeGreaterThan(0);
            await custody.releaseOperationIdentity(identity);
            await custody.releaseOperationIdentity(identity);
            expect(identity.checkpointLineageIdentifier).toEqual(
                new Uint8Array(32),
            );

            const resumed = await custody.resume({
                checkpointLineageIdentifier,
                expectedBoundary: expectedCheckpointBoundary(boundary),
                signal: operationSignal,
            });
            const restoredChunks: Uint8Array[] = [];
            await resumed.restoreState((chunkIndex, chunkBytes) => {
                expect(chunkIndex).toBe(restoredChunks.length);
                restoredChunks.push(chunkBytes.slice());
            }, operationSignal);
            expect(restoredChunks).toEqual([stateBytes]);
            await custody.releaseOperationIdentity(resumed.operationIdentity);

            const resumedAgain = await custody.resume({
                checkpointLineageIdentifier,
                expectedBoundary: expectedCheckpointBoundary(boundary),
                signal: operationSignal,
            });
            expect(resumedAgain.operationIdentity).not.toBe(
                resumed.operationIdentity,
            );
            await custody.releaseOperationIdentity(
                resumedAgain.operationIdentity,
            );
        } finally {
            await store.close();
        }
    });

    it('releases late identities and evicts a cancelled publication after concurrent release', async () => {
        const { store } = await openCheckpointStore();
        try {
            const beginCancellationController = new AbortController();
            const abortingBeginStore: AuthenticatedCheckpointStore = {
                ...store,
                beginOperation: async () => {
                    const identity = await store.beginOperation();
                    beginCancellationController.abort('cancel after issue');
                    return identity;
                },
            };
            const abortingBeginCustody =
                createBallotAggregationCheckpointCustody(abortingBeginStore);
            await expect(
                abortingBeginCustody.beginOperation(
                    beginCancellationController.signal,
                ),
            ).rejects.toMatchObject({ code: 'InvalidState' });

            const publishCancellationController = new AbortController();
            let reportPublicationCommitted: (() => void) | undefined;
            const publicationCommitted = new Promise<void>((resolve) => {
                reportPublicationCommitted = resolve;
            });
            let allowPublishToReturn: (() => void) | undefined;
            const publishReturnGate = new Promise<void>((resolve) => {
                allowPublishToReturn = resolve;
            });
            const abortingPublishStore: AuthenticatedCheckpointStore = {
                ...store,
                publish: async (input) => {
                    const canonicalManifestBytes = await store.publish(input);
                    reportPublicationCommitted?.();
                    await publishReturnGate;
                    return canonicalManifestBytes;
                },
            };
            const abortingPublishCustody =
                createBallotAggregationCheckpointCustody(abortingPublishStore);
            const cancelledPublicationStateBytes = Uint8Array.of(
                0x11,
                0x22,
                0x33,
            );
            const cancelledPublicationBoundary = checkpointBoundary({
                ballotCandidateViewRoot: hashFilledWith(0x5a),
                stateStreamDescriptorBytes:
                    abortingPublishCustody.describeStateStream({
                        stateBytes: cancelledPublicationStateBytes,
                        stateStreamDomain: checkpointStateStreamDomain,
                    }),
            });
            const cancelledPublicationIdentity =
                await abortingPublishCustody.beginOperation(
                    publishCancellationController.signal,
                );
            const cancelledPublicationLineageIdentifier =
                cancelledPublicationIdentity.checkpointLineageIdentifier;
            const cancelledPublicationFailure = abortingPublishCustody
                .publish({
                    boundary: cancelledPublicationBoundary,
                    identity: cancelledPublicationIdentity,
                    signal: publishCancellationController.signal,
                    stateChunks: [cancelledPublicationStateBytes],
                })
                .then(
                    () => undefined,
                    (error: unknown) => error,
                );
            await publicationCommitted;
            publishCancellationController.abort(
                'cancel after committed publication',
            );
            await abortingPublishCustody.releaseOperationIdentity(
                cancelledPublicationIdentity,
            );
            expect(
                cancelledPublicationIdentity.checkpointLineageIdentifier,
            ).toEqual(new Uint8Array(32));
            if (allowPublishToReturn === undefined) {
                throw new Error(
                    'The delayed checkpoint publication did not expose its return gate.',
                );
            }
            allowPublishToReturn();
            expect(await cancelledPublicationFailure).toMatchObject({
                code: 'InvalidState',
            });
            await expect(
                store.resume({
                    checkpointLineageIdentifier:
                        cancelledPublicationLineageIdentifier,
                    expectedBoundary: expectedCheckpointBoundary(
                        cancelledPublicationBoundary,
                    ),
                }),
            ).rejects.toMatchObject({ code: 'MissingRecord' });

            const custody = createBallotAggregationCheckpointCustody(store);
            const stateBytes = Uint8Array.of(0x21, 0x32, 0x43, 0x54);
            const boundary = checkpointBoundary({
                ballotCandidateViewRoot: hashFilledWith(0x61),
                stateStreamDescriptorBytes: custody.describeStateStream({
                    stateBytes,
                    stateStreamDomain: checkpointStateStreamDomain,
                }),
            });
            const operationSignal = new AbortController().signal;
            const publishingIdentity =
                await custody.beginOperation(operationSignal);
            const checkpointLineageIdentifier =
                publishingIdentity.checkpointLineageIdentifier;
            await custody.publish({
                boundary,
                identity: publishingIdentity,
                signal: operationSignal,
                stateChunks: [stateBytes],
            });
            await custody.releaseOperationIdentity(publishingIdentity);

            const resumeCancellationController = new AbortController();
            let cancelledResumedCheckpoint:
                | Awaited<ReturnType<AuthenticatedCheckpointStore['resume']>>
                | undefined;
            const abortingResumeStore: AuthenticatedCheckpointStore = {
                ...store,
                resume: async (input) => {
                    const resumed = await store.resume(input);
                    cancelledResumedCheckpoint = resumed;
                    resumeCancellationController.abort('cancel after resume');
                    return resumed;
                },
            };
            const abortingResumeCustody =
                createBallotAggregationCheckpointCustody(abortingResumeStore);
            await expect(
                abortingResumeCustody.resume({
                    checkpointLineageIdentifier,
                    expectedBoundary: expectedCheckpointBoundary(boundary),
                    signal: resumeCancellationController.signal,
                }),
            ).rejects.toMatchObject({ code: 'InvalidState' });
            if (cancelledResumedCheckpoint === undefined) {
                throw new Error(
                    'The cancelling store did not return its resumed checkpoint.',
                );
            }
            expect(cancelledResumedCheckpoint.canonicalManifestBytes).toEqual(
                new Uint8Array(
                    cancelledResumedCheckpoint.canonicalManifestBytes
                        .byteLength,
                ),
            );
            expect(
                cancelledResumedCheckpoint.stateStreamDescriptorBytes,
            ).toEqual(
                new Uint8Array(
                    cancelledResumedCheckpoint.stateStreamDescriptorBytes
                        .byteLength,
                ),
            );

            const resumed = await custody.resume({
                checkpointLineageIdentifier,
                expectedBoundary: expectedCheckpointBoundary(boundary),
                signal: operationSignal,
            });
            await custody.releaseOperationIdentity(resumed.operationIdentity);
        } finally {
            await store.close();
        }
    });

    it('evicts rejected partial and committed publications without replacing their failures', async () => {
        const { adapter, store } = await openCheckpointStore();
        try {
            const baselineStorageKeys = adapter.keys();
            let partialPublicationFailure: unknown;
            let storageKeysBeforePartialPublicationEviction:
                | readonly string[]
                | undefined;
            const observingStore: AuthenticatedCheckpointStore = {
                ...store,
                evict: async (checkpointLineageIdentifier) => {
                    storageKeysBeforePartialPublicationEviction =
                        adapter.keys();
                    await store.evict(checkpointLineageIdentifier);
                },
                publish: async (input) => {
                    try {
                        return await store.publish(input);
                    } catch (error) {
                        partialPublicationFailure = error;
                        throw error;
                    }
                },
            };
            const custody =
                createBallotAggregationCheckpointCustody(observingStore);
            const stateBytes = Uint8Array.of(0x61, 0x72, 0x83, 0x94);
            const boundary = checkpointBoundary({
                ballotCandidateViewRoot: hashFilledWith(0x81),
                stateStreamDescriptorBytes: custody.describeStateStream({
                    stateBytes,
                    stateStreamDomain: checkpointStateStreamDomain,
                }),
            });
            const operationSignal = new AbortController().signal;
            const identity = await custody.beginOperation(operationSignal);
            const checkpointLineageIdentifier =
                identity.checkpointLineageIdentifier;
            adapter.failAtomicMutationAfter(4);

            let observedPublicationFailure: unknown;
            try {
                await custody.publish({
                    boundary,
                    identity,
                    signal: operationSignal,
                    stateChunks: [stateBytes],
                });
            } catch (error) {
                observedPublicationFailure = error;
            }
            expect(observedPublicationFailure).toBe(partialPublicationFailure);
            expect(observedPublicationFailure).toMatchObject({
                code: 'StorageFailure',
            });
            expect(
                storageKeysBeforePartialPublicationEviction?.length,
            ).toBeGreaterThan(baselineStorageKeys.length);
            const mutationCountAfterEviction = adapter.atomicMutationCount;
            await store.repair(checkpointLineageIdentifier);
            expect(adapter.atomicMutationCount).toBe(
                mutationCountAfterEviction,
            );
            await custody.releaseOperationIdentity(identity);
            await expect(
                store.resume({
                    checkpointLineageIdentifier,
                    expectedBoundary: expectedCheckpointBoundary(boundary),
                }),
            ).rejects.toMatchObject({ code: 'MissingRecord' });

            const committedPublicationFailure = new Error(
                'Injected failure after committed checkpoint publication.',
            );
            const rejectingCommittedStore: AuthenticatedCheckpointStore = {
                ...store,
                publish: async (input) => {
                    await store.publish(input);
                    throw committedPublicationFailure;
                },
            };
            const rejectingCommittedCustody =
                createBallotAggregationCheckpointCustody(
                    rejectingCommittedStore,
                );
            const committedStateBytes = Uint8Array.of(0xa1, 0xb2, 0xc3);
            const committedBoundary = checkpointBoundary({
                ballotCandidateViewRoot: hashFilledWith(0x91),
                stateStreamDescriptorBytes:
                    rejectingCommittedCustody.describeStateStream({
                        stateBytes: committedStateBytes,
                        stateStreamDomain: checkpointStateStreamDomain,
                    }),
            });
            const committedIdentity =
                await rejectingCommittedCustody.beginOperation(operationSignal);
            const committedLineageIdentifier =
                committedIdentity.checkpointLineageIdentifier;
            await expect(
                rejectingCommittedCustody.publish({
                    boundary: committedBoundary,
                    identity: committedIdentity,
                    signal: operationSignal,
                    stateChunks: [committedStateBytes],
                }),
            ).rejects.toBe(committedPublicationFailure);
            await rejectingCommittedCustody.releaseOperationIdentity(
                committedIdentity,
            );
            await expect(
                store.resume({
                    checkpointLineageIdentifier: committedLineageIdentifier,
                    expectedBoundary:
                        expectedCheckpointBoundary(committedBoundary),
                }),
            ).rejects.toMatchObject({ code: 'MissingRecord' });
        } finally {
            await store.close();
        }
    });

    it('combines publication and terminal eviction failures', async () => {
        const { store } = await openCheckpointStore();
        try {
            const publicationFailure = new Error(
                'Injected failure after durable publication.',
            );
            const evictionFailure = new Error(
                'Injected terminal eviction failure.',
            );
            const cleanupFailingStore: AuthenticatedCheckpointStore = {
                ...store,
                evict: () => Promise.reject(evictionFailure),
                publish: async (input) => {
                    await store.publish(input);
                    throw publicationFailure;
                },
            };
            const custody =
                createBallotAggregationCheckpointCustody(cleanupFailingStore);
            const stateBytes = Uint8Array.of(0xd1, 0xe2, 0xf3);
            const boundary = checkpointBoundary({
                ballotCandidateViewRoot: hashFilledWith(0xa1),
                stateStreamDescriptorBytes: custody.describeStateStream({
                    stateBytes,
                    stateStreamDomain: checkpointStateStreamDomain,
                }),
            });
            const operationSignal = new AbortController().signal;
            const identity = await custody.beginOperation(operationSignal);
            const checkpointLineageIdentifier =
                identity.checkpointLineageIdentifier;

            await expect(
                custody.publish({
                    boundary,
                    identity,
                    signal: operationSignal,
                    stateChunks: [stateBytes],
                }),
            ).rejects.toMatchObject({
                code: 'CleanupFailed',
                failureCause: [publicationFailure, evictionFailure],
            });
            await custody.releaseOperationIdentity(identity);
            await store.evict(checkpointLineageIdentifier);
        } finally {
            await store.close();
        }
    });

    it('stops authenticated restoration when its signal aborts', async () => {
        const { store } = await openCheckpointStore();
        try {
            const custody = createBallotAggregationCheckpointCustody(store);
            const stateBytes = new Uint8Array(
                foundationProfile.streamChunkByteLength + 1,
            );
            for (
                let byteIndex = 0;
                byteIndex < stateBytes.byteLength;
                byteIndex += 1
            ) {
                stateBytes[byteIndex] = (byteIndex * 113 + 0x39) & 0xff;
            }
            const boundary = checkpointBoundary({
                ballotCandidateViewRoot: hashFilledWith(0x71),
                stateStreamDescriptorBytes: custody.describeStateStream({
                    stateBytes,
                    stateStreamDomain: checkpointStateStreamDomain,
                }),
            });
            const operationSignal = new AbortController().signal;
            const publishingIdentity =
                await custody.beginOperation(operationSignal);
            const checkpointLineageIdentifier =
                publishingIdentity.checkpointLineageIdentifier;
            await custody.publish({
                boundary,
                identity: publishingIdentity,
                signal: operationSignal,
                stateChunks: [
                    stateBytes.subarray(
                        0,
                        foundationProfile.streamChunkByteLength,
                    ),
                    stateBytes.subarray(
                        foundationProfile.streamChunkByteLength,
                    ),
                ],
            });
            await custody.releaseOperationIdentity(publishingIdentity);

            const resumed = await custody.resume({
                checkpointLineageIdentifier,
                expectedBoundary: expectedCheckpointBoundary(boundary),
                signal: operationSignal,
            });
            const restorationCancellationController = new AbortController();
            const restoredChunkIndexes: number[] = [];
            let deliveredChunkBytes: Uint8Array | undefined;
            await expect(
                resumed.restoreState((chunkIndex, chunkBytes) => {
                    restoredChunkIndexes.push(chunkIndex);
                    deliveredChunkBytes = chunkBytes;
                    restorationCancellationController.abort(
                        'cancel restoration',
                    );
                }, restorationCancellationController.signal),
            ).rejects.toMatchObject({ code: 'InvalidState' });
            expect(restoredChunkIndexes).toEqual([0]);
            expect(deliveredChunkBytes).toEqual(
                new Uint8Array(foundationProfile.streamChunkByteLength),
            );
            await custody.releaseOperationIdentity(resumed.operationIdentity);
        } finally {
            await store.close();
        }
    });
});
