import type {
    BallotAggregationCheckpointCustody,
    BallotAggregationCheckpointOperationIdentity,
    ResumedBallotAggregationCheckpoint,
} from '@sealed-lattice/wasm';

import {
    AuthenticatedCheckpointStoreError,
    describeAuthenticatedCheckpointStateStream,
    type AuthenticatedCheckpointStore,
    type CheckpointOperationIdentity,
} from './authenticated-checkpoint-store.js';

const checkpointLineageIdentifierByteLength = 32;

type IssuedOperationIdentityRecord = {
    checkpointLineageIdentifier: Uint8Array;
    releasePromise?: Promise<void>;
    released: boolean;
    storeIdentity: CheckpointOperationIdentity;
};

const createCancellationError = (
    signal: AbortSignal,
): AuthenticatedCheckpointStoreError =>
    new AuthenticatedCheckpointStoreError(
        'InvalidState',
        'The ballot-aggregation checkpoint custody operation was cancelled.',
        signal.reason,
    );

const throwIfAborted = (signal: AbortSignal): void => {
    if (signal.aborted) {
        throw createCancellationError(signal);
    }
};

const createCleanupFailure = (
    message: string,
    operationFailure: unknown,
    cleanupFailure: unknown,
): AuthenticatedCheckpointStoreError =>
    new AuthenticatedCheckpointStoreError('CleanupFailed', message, [
        operationFailure,
        cleanupFailure,
    ]);

const copyCheckpointLineageIdentifier = (
    identity: CheckpointOperationIdentity,
): Uint8Array => {
    const checkpointLineageIdentifier = identity.checkpointLineageIdentifier;
    if (
        !(checkpointLineageIdentifier instanceof Uint8Array) ||
        checkpointLineageIdentifier.byteLength !==
            checkpointLineageIdentifierByteLength
    ) {
        throw new AuthenticatedCheckpointStoreError(
            'InvalidInput',
            'The authenticated checkpoint store returned an invalid operation identity.',
        );
    }
    return Uint8Array.from(checkpointLineageIdentifier);
};

/**
 * Adapts the protocol-owned authenticated store to ballot aggregation without
 * exposing its branded process-local operation identities.
 */
export const createBallotAggregationCheckpointCustody = (
    store: AuthenticatedCheckpointStore,
): BallotAggregationCheckpointCustody => {
    const issuedOperationIdentityRecords = new WeakMap<
        BallotAggregationCheckpointOperationIdentity,
        IssuedOperationIdentityRecord
    >();

    const wrapOperationIdentity = (
        storeIdentity: CheckpointOperationIdentity,
    ): BallotAggregationCheckpointOperationIdentity => {
        const checkpointLineageIdentifier =
            copyCheckpointLineageIdentifier(storeIdentity);
        const identity: BallotAggregationCheckpointOperationIdentity =
            Object.freeze({
                get checkpointLineageIdentifier(): Uint8Array {
                    return checkpointLineageIdentifier.slice();
                },
            });
        issuedOperationIdentityRecords.set(identity, {
            checkpointLineageIdentifier,
            released: false,
            storeIdentity,
        });
        return identity;
    };

    const requireIssuedOperationIdentity = (
        identity: BallotAggregationCheckpointOperationIdentity,
    ): IssuedOperationIdentityRecord => {
        const identityRecord = issuedOperationIdentityRecords.get(identity);
        if (identityRecord === undefined) {
            throw new AuthenticatedCheckpointStoreError(
                'InvalidInput',
                'Ballot-aggregation checkpoint custody requires an operation identity it issued.',
            );
        }
        if (
            identityRecord.released ||
            identityRecord.releasePromise !== undefined
        ) {
            throw new AuthenticatedCheckpointStoreError(
                'InvalidState',
                'The ballot-aggregation checkpoint operation identity is no longer active.',
            );
        }
        return identityRecord;
    };

    const releaseStoreIdentityAfterFailure = async (
        storeIdentity: CheckpointOperationIdentity,
        operationFailure: unknown,
    ): Promise<never> => {
        try {
            await store.releaseOperationIdentity(storeIdentity);
        } catch (cleanupFailure) {
            throw createCleanupFailure(
                'Ballot-aggregation checkpoint custody failed to release an operation identity.',
                operationFailure,
                cleanupFailure,
            );
        }
        throw operationFailure;
    };

    const beginOperation: BallotAggregationCheckpointCustody['beginOperation'] =
        async (signal) => {
            throwIfAborted(signal);
            const storeIdentity = await store.beginOperation();
            if (signal.aborted) {
                return await releaseStoreIdentityAfterFailure(
                    storeIdentity,
                    createCancellationError(signal),
                );
            }
            try {
                return wrapOperationIdentity(storeIdentity);
            } catch (operationFailure) {
                return await releaseStoreIdentityAfterFailure(
                    storeIdentity,
                    operationFailure,
                );
            }
        };

    const publish: BallotAggregationCheckpointCustody['publish'] = async (
        input,
    ) => {
        throwIfAborted(input.signal);
        const identityRecord = requireIssuedOperationIdentity(input.identity);
        const checkpointLineageIdentifier =
            identityRecord.checkpointLineageIdentifier.slice();
        try {
            const stateChunks = async function* (): AsyncIterable<Uint8Array> {
                throwIfAborted(input.signal);
                for await (const stateChunk of input.stateChunks) {
                    throwIfAborted(input.signal);
                    yield stateChunk;
                    throwIfAborted(input.signal);
                }
            };
            let canonicalManifestBytes: Uint8Array;
            try {
                canonicalManifestBytes = await store.publish({
                    boundary: input.boundary,
                    identity: identityRecord.storeIdentity,
                    stateChunks: stateChunks(),
                });
            } catch (publicationFailure) {
                try {
                    await store.evict(checkpointLineageIdentifier);
                } catch (cleanupFailure) {
                    throw createCleanupFailure(
                        'Ballot-aggregation checkpoint custody failed to evict a rejected publication.',
                        publicationFailure,
                        cleanupFailure,
                    );
                }
                throw publicationFailure;
            }
            if (input.signal.aborted) {
                const cancellationFailure = createCancellationError(
                    input.signal,
                );
                canonicalManifestBytes.fill(0);
                try {
                    await store.evict(checkpointLineageIdentifier);
                } catch (cleanupFailure) {
                    throw createCleanupFailure(
                        'Ballot-aggregation checkpoint custody failed to evict a publication completed after cancellation.',
                        cancellationFailure,
                        cleanupFailure,
                    );
                }
                throw cancellationFailure;
            }
            return canonicalManifestBytes;
        } finally {
            checkpointLineageIdentifier.fill(0);
        }
    };

    const releaseOperationIdentity: BallotAggregationCheckpointCustody['releaseOperationIdentity'] =
        async (identity) => {
            const identityRecord = issuedOperationIdentityRecords.get(identity);
            if (identityRecord === undefined) {
                throw new AuthenticatedCheckpointStoreError(
                    'InvalidInput',
                    'Ballot-aggregation checkpoint custody can release only an operation identity it issued.',
                );
            }
            if (identityRecord.released) {
                return;
            }
            if (identityRecord.releasePromise !== undefined) {
                return await identityRecord.releasePromise;
            }
            const releasePromise = store
                .releaseOperationIdentity(identityRecord.storeIdentity)
                .then(() => {
                    identityRecord.released = true;
                    identityRecord.checkpointLineageIdentifier.fill(0);
                })
                .finally(() => {
                    identityRecord.releasePromise = undefined;
                });
            identityRecord.releasePromise = releasePromise;
            return await releasePromise;
        };

    const resume: BallotAggregationCheckpointCustody['resume'] = async (
        input,
    ) => {
        throwIfAborted(input.signal);
        const resumedCheckpoint = await store.resume({
            checkpointLineageIdentifier: input.checkpointLineageIdentifier,
            expectedBoundary: input.expectedBoundary,
        });
        const storeIdentity = resumedCheckpoint.operationIdentity;
        if (input.signal.aborted) {
            resumedCheckpoint.canonicalManifestBytes.fill(0);
            resumedCheckpoint.stateStreamDescriptorBytes.fill(0);
            return await releaseStoreIdentityAfterFailure(
                storeIdentity,
                createCancellationError(input.signal),
            );
        }

        let operationIdentity:
            | BallotAggregationCheckpointOperationIdentity
            | undefined;
        try {
            const wrappedOperationIdentity =
                wrapOperationIdentity(storeIdentity);
            operationIdentity = wrappedOperationIdentity;
            requireIssuedOperationIdentity(wrappedOperationIdentity);
            const result: ResumedBallotAggregationCheckpoint = Object.freeze({
                canonicalManifestBytes:
                    resumedCheckpoint.canonicalManifestBytes.slice(),
                operationIdentity: wrappedOperationIdentity,
                restoreState: async (consumeChunk, signal) => {
                    throwIfAborted(signal);
                    requireIssuedOperationIdentity(wrappedOperationIdentity);
                    await resumedCheckpoint.restoreState(
                        async (chunkIndex, chunkBytes) => {
                            try {
                                throwIfAborted(signal);
                                await consumeChunk(chunkIndex, chunkBytes);
                                throwIfAborted(signal);
                            } finally {
                                chunkBytes.fill(0);
                            }
                        },
                    );
                    throwIfAborted(signal);
                },
                stateStreamDescriptorBytes:
                    resumedCheckpoint.stateStreamDescriptorBytes.slice(),
            });
            return result;
        } catch (operationFailure) {
            resumedCheckpoint.canonicalManifestBytes.fill(0);
            resumedCheckpoint.stateStreamDescriptorBytes.fill(0);
            if (operationIdentity !== undefined) {
                const identityRecord =
                    issuedOperationIdentityRecords.get(operationIdentity);
                identityRecord?.checkpointLineageIdentifier.fill(0);
                if (identityRecord !== undefined) {
                    identityRecord.released = true;
                }
            }
            return await releaseStoreIdentityAfterFailure(
                storeIdentity,
                operationFailure,
            );
        }
    };

    return Object.freeze({
        beginOperation,
        describeStateStream: describeAuthenticatedCheckpointStateStream,
        publish,
        releaseOperationIdentity,
        resume,
    });
};
