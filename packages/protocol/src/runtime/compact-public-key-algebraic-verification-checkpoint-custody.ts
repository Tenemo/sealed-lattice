import type { CompactPublicKeyAlgebraicVerificationCheckpointCustody } from '@sealed-lattice/wasm';

import {
    AuthenticatedCheckpointStoreError,
    describeAuthenticatedCheckpointStateStream,
    type AuthenticatedCheckpointStore,
    type CheckpointOperationIdentity,
    type ResumedCheckpoint,
} from './authenticated-checkpoint-store.js';

const hashByteLength = 64;
const checkpointLineageIdentifierByteLength = 32;
const checkpointByteLength = 400;
const operationKind = 0x1212;
const safeBoundaryCount = 290;
const stateStreamDomain =
    'sealed-lattice/bgv/compact-public-key-algebraic-verification-checkpoint/v1';
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

export type CompactPublicKeyAlgebraicVerificationCheckpointResume = Readonly<{
    checkpointLineageIdentifier: Uint8Array;
    safeBoundaryOrdinal: number;
}>;

export type CompactPublicKeyAlgebraicVerificationCheckpointCustodyInput =
    Readonly<{
        orderedSourceDigests: readonly Uint8Array[];
        resume?: CompactPublicKeyAlgebraicVerificationCheckpointResume;
        signal?: AbortSignal;
    }>;

export type OpenedCompactPublicKeyAlgebraicVerificationCheckpointCustody =
    Readonly<{
        checkpointCustody: CompactPublicKeyAlgebraicVerificationCheckpointCustody;
        checkpointLineageIdentifier: Uint8Array;
    }>;

type ActiveCustodyState = {
    operationIdentity: CheckpointOperationIdentity;
    releasePromise?: Promise<void>;
    released: boolean;
    restoredCheckpoint?: ResumedCheckpoint;
    restoredCheckpointConsumed: boolean;
};

const createCancellationError = (
    signal: AbortSignal,
): AuthenticatedCheckpointStoreError =>
    new AuthenticatedCheckpointStoreError(
        'InvalidState',
        'Compact public-key algebraic verification checkpoint custody was cancelled.',
        signal.reason,
    );

const throwIfAborted = (signal?: AbortSignal): void => {
    if (signal?.aborted === true) {
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

const copySourceDigests = (
    orderedSourceDigests: readonly Uint8Array[],
): readonly Uint8Array[] => {
    if (
        !Array.isArray(orderedSourceDigests) ||
        orderedSourceDigests.length === 0
    ) {
        throw new AuthenticatedCheckpointStoreError(
            'InvalidInput',
            'Compact public-key algebraic verification checkpoint custody requires verified source digests.',
        );
    }
    return Object.freeze(
        orderedSourceDigests.map((digest) => {
            if (
                !(digest instanceof Uint8Array) ||
                digest.byteLength !== hashByteLength
            ) {
                throw new AuthenticatedCheckpointStoreError(
                    'InvalidInput',
                    'A compact public-key algebraic verification source digest has the wrong byte length.',
                );
            }
            return Uint8Array.from(digest);
        }),
    );
};

const requireSafeBoundaryOrdinal = (safeBoundaryOrdinal: number): number => {
    if (
        !Number.isSafeInteger(safeBoundaryOrdinal) ||
        safeBoundaryOrdinal < 0 ||
        safeBoundaryOrdinal >= safeBoundaryCount
    ) {
        throw new AuthenticatedCheckpointStoreError(
            'InvalidInput',
            'The compact public-key algebraic verification checkpoint boundary is unassigned.',
        );
    }
    return safeBoundaryOrdinal;
};

const copyCheckpointLineageIdentifier = (bytes: Uint8Array): Uint8Array => {
    if (
        !(bytes instanceof Uint8Array) ||
        bytes.byteLength !== checkpointLineageIdentifierByteLength
    ) {
        throw new AuthenticatedCheckpointStoreError(
            'InvalidInput',
            'The compact public-key algebraic verification checkpoint lineage is malformed.',
        );
    }
    return Uint8Array.from(bytes);
};

const expectedBoundary = (
    orderedSourceDigests: readonly Uint8Array[],
    safeBoundaryOrdinal: number,
) => ({
    operationKind,
    orderedSourceDigests,
    privateRandomCursorManifestBytes: emptyPrivateRandomCursorManifestBytes,
    safeBoundaryOrdinal,
    stateStreamDomain,
});

const restoreExactCheckpointBytes = async (
    resumedCheckpoint: ResumedCheckpoint,
): Promise<Uint8Array<ArrayBuffer>> => {
    let restoredBytes: Uint8Array<ArrayBuffer> | undefined;
    try {
        await resumedCheckpoint.restoreState((chunkIndex, chunkBytes) => {
            try {
                if (
                    chunkIndex !== 0 ||
                    restoredBytes !== undefined ||
                    !(chunkBytes.buffer instanceof ArrayBuffer) ||
                    chunkBytes.byteLength !== checkpointByteLength
                ) {
                    throw new AuthenticatedCheckpointStoreError(
                        'AuthenticationFailed',
                        'Authenticated custody restored a malformed compact public-key algebraic verification checkpoint stream.',
                    );
                }
                restoredBytes = Uint8Array.from(chunkBytes);
            } finally {
                chunkBytes.fill(0);
            }
        });
    } catch (error) {
        restoredBytes?.fill(0);
        throw error;
    }
    if (restoredBytes === undefined) {
        throw new AuthenticatedCheckpointStoreError(
            'AuthenticationFailed',
            'Authenticated custody restored no compact public-key algebraic verification checkpoint bytes.',
        );
    }
    return restoredBytes;
};

const requireActiveRestoredCheckpoint = (
    canonicalCheckpointBytes: Uint8Array<ArrayBuffer>,
    requireActive: () => void,
): Uint8Array<ArrayBuffer> => {
    try {
        requireActive();
        return canonicalCheckpointBytes;
    } catch (error) {
        canonicalCheckpointBytes.fill(0);
        throw error;
    }
};

/**
 * Opens one operation-scoped adapter over the authenticated checkpoint store.
 * Verification has no private-randomness identity. The source list is fixed
 * for the lineage, and every replacement boundary is supplied by the Rust
 * verifier rather than by a caller-controlled poll count.
 */
export const openCompactPublicKeyAlgebraicVerificationCheckpointCustody =
    async (
        store: AuthenticatedCheckpointStore,
        input: CompactPublicKeyAlgebraicVerificationCheckpointCustodyInput,
    ): Promise<OpenedCompactPublicKeyAlgebraicVerificationCheckpointCustody> => {
        const orderedSourceDigests = copySourceDigests(
            input.orderedSourceDigests,
        );
        let operationIdentity: CheckpointOperationIdentity | undefined;
        let resumedCheckpoint: ResumedCheckpoint | undefined;
        let checkpointLineageIdentifier: Uint8Array | undefined;
        try {
            throwIfAborted(input.signal);
            if (input.resume === undefined) {
                operationIdentity = await store.beginOperation();
            } else {
                const resumeLineageIdentifier = copyCheckpointLineageIdentifier(
                    input.resume.checkpointLineageIdentifier,
                );
                try {
                    resumedCheckpoint = await store.resume({
                        checkpointLineageIdentifier: resumeLineageIdentifier,
                        expectedBoundary: expectedBoundary(
                            orderedSourceDigests,
                            requireSafeBoundaryOrdinal(
                                input.resume.safeBoundaryOrdinal,
                            ),
                        ),
                    });
                } finally {
                    resumeLineageIdentifier.fill(0);
                }
                operationIdentity = resumedCheckpoint.operationIdentity;
            }
            throwIfAborted(input.signal);
            checkpointLineageIdentifier = copyCheckpointLineageIdentifier(
                operationIdentity.checkpointLineageIdentifier,
            );
        } catch (operationFailure) {
            for (const digest of orderedSourceDigests) digest.fill(0);
            resumedCheckpoint?.canonicalManifestBytes.fill(0);
            resumedCheckpoint?.stateStreamDescriptorBytes.fill(0);
            if (operationIdentity !== undefined) {
                try {
                    await store.releaseOperationIdentity(operationIdentity);
                } catch (cleanupFailure) {
                    throw createCleanupFailure(
                        'Compact public-key algebraic verification checkpoint custody failed to release an incompletely opened identity.',
                        operationFailure,
                        cleanupFailure,
                    );
                }
            }
            throw operationFailure;
        }

        const activeState: ActiveCustodyState = {
            operationIdentity,
            released: false,
            restoredCheckpoint: resumedCheckpoint,
            restoredCheckpointConsumed: false,
        };
        const requireActive = (): void => {
            if (
                activeState.released ||
                activeState.releasePromise !== undefined
            ) {
                throw new AuthenticatedCheckpointStoreError(
                    'InvalidState',
                    'The compact public-key algebraic verification checkpoint custody identity is no longer active.',
                );
            }
            throwIfAborted(input.signal);
        };

        const checkpointCustody: CompactPublicKeyAlgebraicVerificationCheckpointCustody =
            Object.freeze({
                publishAuthenticatedCheckpoint: async (
                    canonicalCheckpointBytes,
                    untrustedSafeBoundaryOrdinal,
                ) => {
                    requireActive();
                    const safeBoundaryOrdinal = requireSafeBoundaryOrdinal(
                        untrustedSafeBoundaryOrdinal,
                    );
                    if (
                        !(canonicalCheckpointBytes instanceof Uint8Array) ||
                        canonicalCheckpointBytes.byteLength !==
                            checkpointByteLength
                    ) {
                        throw new AuthenticatedCheckpointStoreError(
                            'InvalidInput',
                            'The compact public-key algebraic verification checkpoint has the wrong byte length.',
                        );
                    }
                    const stateStreamDescriptorBytes =
                        describeAuthenticatedCheckpointStateStream({
                            stateBytes: canonicalCheckpointBytes,
                            stateStreamDomain,
                        });
                    try {
                        const stateChunks = function* () {
                            requireActive();
                            yield canonicalCheckpointBytes;
                            requireActive();
                        };
                        try {
                            const canonicalManifestBytes = await store.publish({
                                boundary: {
                                    ...expectedBoundary(
                                        orderedSourceDigests,
                                        safeBoundaryOrdinal,
                                    ),
                                    stateStreamDescriptorBytes,
                                },
                                identity: activeState.operationIdentity,
                                stateChunks: stateChunks(),
                            });
                            canonicalManifestBytes.fill(0);
                            requireActive();
                        } catch (publicationFailure) {
                            try {
                                await store.repair(
                                    activeState.operationIdentity
                                        .checkpointLineageIdentifier,
                                );
                            } catch (cleanupFailure) {
                                throw createCleanupFailure(
                                    'Compact public-key algebraic verification checkpoint custody could not repair a rejected replacement publication.',
                                    publicationFailure,
                                    cleanupFailure,
                                );
                            }
                            throw publicationFailure;
                        }
                    } finally {
                        stateStreamDescriptorBytes.fill(0);
                    }
                },
                release: async () => {
                    if (activeState.released) return;
                    if (activeState.releasePromise !== undefined) {
                        return await activeState.releasePromise;
                    }
                    const releasePromise = store
                        .releaseOperationIdentity(activeState.operationIdentity)
                        .then(() => {
                            activeState.released = true;
                            activeState.restoredCheckpoint?.canonicalManifestBytes.fill(
                                0,
                            );
                            activeState.restoredCheckpoint?.stateStreamDescriptorBytes.fill(
                                0,
                            );
                            for (const digest of orderedSourceDigests)
                                digest.fill(0);
                        })
                        .finally(() => {
                            activeState.releasePromise = undefined;
                        });
                    activeState.releasePromise = releasePromise;
                    return await releasePromise;
                },
                restoreAuthenticatedCheckpoint: async () => {
                    requireActive();
                    if (
                        activeState.restoredCheckpoint === undefined ||
                        input.resume === undefined ||
                        activeState.restoredCheckpointConsumed
                    ) {
                        throw new AuthenticatedCheckpointStoreError(
                            'InvalidState',
                            'No unconsumed compact public-key algebraic verification checkpoint is available for restoration.',
                        );
                    }
                    activeState.restoredCheckpointConsumed = true;
                    const canonicalCheckpointBytes =
                        requireActiveRestoredCheckpoint(
                            await restoreExactCheckpointBytes(
                                activeState.restoredCheckpoint,
                            ),
                            requireActive,
                        );
                    return Object.freeze({
                        canonicalCheckpointBytes,
                        safeBoundaryOrdinal: requireSafeBoundaryOrdinal(
                            input.resume.safeBoundaryOrdinal,
                        ),
                    });
                },
            });

        return Object.freeze({
            checkpointCustody,
            checkpointLineageIdentifier,
        });
    };
