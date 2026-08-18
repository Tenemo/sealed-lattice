import {
    publicKeyShareProofFamilySchemaIdentifier,
    readAcceptedSetupCompactPublicKeyVerificationCheckpointGeometry,
    type AcceptedSetupCompactPublicKeyVerificationCheckpointCustody,
    type CompactPublicKeyAlgebraicVerificationCheckpointCustody,
    type CompactPublicKeyVerificationCheckpointCustody,
    type TranscriptCoreKernel,
} from '@sealed-lattice/wasm';

import {
    AuthenticatedCheckpointStoreError,
    describeAuthenticatedCheckpointStateStream,
    type AuthenticatedCheckpointStore,
    type CheckpointOperationIdentity,
    type ResumedCheckpoint,
} from './authenticated-checkpoint-store.js';
import {
    compactPublicKeyVerificationCheckpointStateStreamDomains,
    createEmptyCompactPublicKeyVerificationPrivateRandomnessCursorManifestBytes,
} from './compact-public-key-verification-checkpoint-contract.js';

const hashByteLength = 64;
const checkpointLineageIdentifierByteLength = 32;

type CompactPublicKeyVerificationCheckpointProfile = Readonly<{
    checkpointByteLength: number;
    operationDescription: string;
    safeBoundaryCount: number;
    stateStreamDomain: string;
}>;

const compactPublicKeyAlgebraicVerificationCheckpointProfile = Object.freeze({
    checkpointByteLength: 400,
    operationDescription: 'compact public-key algebraic verification',
    safeBoundaryCount: 290,
    stateStreamDomain:
        compactPublicKeyVerificationCheckpointStateStreamDomains.algebraic,
}) satisfies CompactPublicKeyVerificationCheckpointProfile;

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

export type AcceptedSetupCompactPublicKeyVerificationCheckpointResume =
    Readonly<{
        checkpointLineageIdentifier: Uint8Array;
        safeBoundaryOrdinal: number;
    }>;

export type AcceptedSetupCompactPublicKeyVerificationCheckpointCustodyInput =
    Readonly<{
        orderedSourceDigests: readonly Uint8Array[];
        kernel: TranscriptCoreKernel;
        resume?: AcceptedSetupCompactPublicKeyVerificationCheckpointResume;
        signal?: AbortSignal;
    }>;

export type OpenedAcceptedSetupCompactPublicKeyVerificationCheckpointCustody =
    Readonly<{
        checkpointCustody: AcceptedSetupCompactPublicKeyVerificationCheckpointCustody;
        checkpointLineageIdentifier: Uint8Array;
    }>;

type CompactPublicKeyVerificationCheckpointResume = Readonly<{
    checkpointLineageIdentifier: Uint8Array;
    safeBoundaryOrdinal: number;
}>;

type CompactPublicKeyVerificationCheckpointCustodyInput = Readonly<{
    orderedSourceDigests: readonly Uint8Array[];
    resume?: CompactPublicKeyVerificationCheckpointResume;
    signal?: AbortSignal;
}>;

type OpenedCompactPublicKeyVerificationCheckpointCustody = Readonly<{
    checkpointCustody: CompactPublicKeyVerificationCheckpointCustody;
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
    profile: CompactPublicKeyVerificationCheckpointProfile,
): AuthenticatedCheckpointStoreError =>
    new AuthenticatedCheckpointStoreError(
        'InvalidState',
        `The ${profile.operationDescription} checkpoint custody was cancelled.`,
        signal.reason,
    );

const throwIfAborted = (
    profile: CompactPublicKeyVerificationCheckpointProfile,
    signal?: AbortSignal,
): void => {
    if (signal?.aborted === true) {
        throw createCancellationError(signal, profile);
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
    profile: CompactPublicKeyVerificationCheckpointProfile,
): readonly Uint8Array[] => {
    if (
        !Array.isArray(orderedSourceDigests) ||
        orderedSourceDigests.length === 0
    ) {
        throw new AuthenticatedCheckpointStoreError(
            'InvalidInput',
            `The ${profile.operationDescription} checkpoint custody requires verified source digests.`,
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
                    `A ${profile.operationDescription} source digest has the wrong byte length.`,
                );
            }
            return Uint8Array.from(digest);
        }),
    );
};

const requireSafeBoundaryOrdinal = (
    safeBoundaryOrdinal: number,
    profile: CompactPublicKeyVerificationCheckpointProfile,
): number => {
    if (
        !Number.isSafeInteger(safeBoundaryOrdinal) ||
        safeBoundaryOrdinal < 0 ||
        safeBoundaryOrdinal >= profile.safeBoundaryCount
    ) {
        throw new AuthenticatedCheckpointStoreError(
            'InvalidInput',
            `The ${profile.operationDescription} checkpoint boundary is unassigned.`,
        );
    }
    return safeBoundaryOrdinal;
};

const copyCheckpointLineageIdentifier = (
    bytes: Uint8Array,
    profile: CompactPublicKeyVerificationCheckpointProfile,
): Uint8Array => {
    if (
        !(bytes instanceof Uint8Array) ||
        bytes.byteLength !== checkpointLineageIdentifierByteLength
    ) {
        throw new AuthenticatedCheckpointStoreError(
            'InvalidInput',
            `The ${profile.operationDescription} checkpoint lineage is malformed.`,
        );
    }
    return Uint8Array.from(bytes);
};

const expectedBoundary = (
    orderedSourceDigests: readonly Uint8Array[],
    safeBoundaryOrdinal: number,
    profile: CompactPublicKeyVerificationCheckpointProfile,
) => ({
    operationKind: publicKeyShareProofFamilySchemaIdentifier,
    orderedSourceDigests,
    privateRandomCursorManifestBytes:
        createEmptyCompactPublicKeyVerificationPrivateRandomnessCursorManifestBytes(),
    safeBoundaryOrdinal,
    stateStreamDomain: profile.stateStreamDomain,
});

const restoreExactCheckpointBytes = async (
    resumedCheckpoint: ResumedCheckpoint,
    profile: CompactPublicKeyVerificationCheckpointProfile,
): Promise<Uint8Array<ArrayBuffer>> => {
    let restoredBytes: Uint8Array<ArrayBuffer> | undefined;
    try {
        await resumedCheckpoint.restoreState((chunkIndex, chunkBytes) => {
            try {
                if (
                    chunkIndex !== 0 ||
                    restoredBytes !== undefined ||
                    !(chunkBytes.buffer instanceof ArrayBuffer) ||
                    chunkBytes.byteLength !== profile.checkpointByteLength
                ) {
                    throw new AuthenticatedCheckpointStoreError(
                        'AuthenticationFailed',
                        `Authenticated custody restored a malformed ${profile.operationDescription} checkpoint stream.`,
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
            `Authenticated custody restored no ${profile.operationDescription} checkpoint bytes.`,
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
const openCompactPublicKeyVerificationCheckpointCustody = async (
    store: AuthenticatedCheckpointStore,
    input: CompactPublicKeyVerificationCheckpointCustodyInput,
    profile: CompactPublicKeyVerificationCheckpointProfile,
): Promise<OpenedCompactPublicKeyVerificationCheckpointCustody> => {
    const orderedSourceDigests = copySourceDigests(
        input.orderedSourceDigests,
        profile,
    );
    let operationIdentity: CheckpointOperationIdentity | undefined;
    let resumedCheckpoint: ResumedCheckpoint | undefined;
    let checkpointLineageIdentifier: Uint8Array | undefined;
    try {
        throwIfAborted(profile, input.signal);
        if (input.resume === undefined) {
            operationIdentity = await store.beginOperation();
        } else {
            const resumeLineageIdentifier = copyCheckpointLineageIdentifier(
                input.resume.checkpointLineageIdentifier,
                profile,
            );
            try {
                resumedCheckpoint = await store.resume({
                    checkpointLineageIdentifier: resumeLineageIdentifier,
                    expectedBoundary: expectedBoundary(
                        orderedSourceDigests,
                        requireSafeBoundaryOrdinal(
                            input.resume.safeBoundaryOrdinal,
                            profile,
                        ),
                        profile,
                    ),
                });
            } finally {
                resumeLineageIdentifier.fill(0);
            }
            operationIdentity = resumedCheckpoint.operationIdentity;
        }
        throwIfAborted(profile, input.signal);
        checkpointLineageIdentifier = copyCheckpointLineageIdentifier(
            operationIdentity.checkpointLineageIdentifier,
            profile,
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
                    `The ${profile.operationDescription} checkpoint custody failed to release an incompletely opened identity.`,
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
        if (activeState.released || activeState.releasePromise !== undefined) {
            throw new AuthenticatedCheckpointStoreError(
                'InvalidState',
                `The ${profile.operationDescription} checkpoint custody identity is no longer active.`,
            );
        }
        throwIfAborted(profile, input.signal);
    };

    const checkpointCustody: CompactPublicKeyVerificationCheckpointCustody =
        Object.freeze({
            publishAuthenticatedCheckpoint: async (
                canonicalCheckpointBytes,
                untrustedSafeBoundaryOrdinal,
            ) => {
                requireActive();
                const safeBoundaryOrdinal = requireSafeBoundaryOrdinal(
                    untrustedSafeBoundaryOrdinal,
                    profile,
                );
                if (
                    !(canonicalCheckpointBytes instanceof Uint8Array) ||
                    canonicalCheckpointBytes.byteLength !==
                        profile.checkpointByteLength
                ) {
                    throw new AuthenticatedCheckpointStoreError(
                        'InvalidInput',
                        `The ${profile.operationDescription} checkpoint has the wrong byte length.`,
                    );
                }
                const stateStreamDescriptorBytes =
                    describeAuthenticatedCheckpointStateStream({
                        stateBytes: canonicalCheckpointBytes,
                        stateStreamDomain: profile.stateStreamDomain,
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
                                    profile,
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
                                `The ${profile.operationDescription} checkpoint custody could not repair a rejected replacement publication.`,
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
                        `No unconsumed ${profile.operationDescription} checkpoint is available for restoration.`,
                    );
                }
                activeState.restoredCheckpointConsumed = true;
                const canonicalCheckpointBytes =
                    requireActiveRestoredCheckpoint(
                        await restoreExactCheckpointBytes(
                            activeState.restoredCheckpoint,
                            profile,
                        ),
                        requireActive,
                    );
                return Object.freeze({
                    canonicalCheckpointBytes,
                    safeBoundaryOrdinal: requireSafeBoundaryOrdinal(
                        input.resume.safeBoundaryOrdinal,
                        profile,
                    ),
                });
            },
        });

    return Object.freeze({
        checkpointCustody,
        checkpointLineageIdentifier,
    });
};

export const openCompactPublicKeyAlgebraicVerificationCheckpointCustody =
    async (
        store: AuthenticatedCheckpointStore,
        input: CompactPublicKeyAlgebraicVerificationCheckpointCustodyInput,
    ): Promise<OpenedCompactPublicKeyAlgebraicVerificationCheckpointCustody> =>
        await openCompactPublicKeyVerificationCheckpointCustody(
            store,
            input,
            compactPublicKeyAlgebraicVerificationCheckpointProfile,
        );

export const openAcceptedSetupCompactPublicKeyVerificationCheckpointCustody =
    async (
        store: AuthenticatedCheckpointStore,
        input: AcceptedSetupCompactPublicKeyVerificationCheckpointCustodyInput,
    ): Promise<OpenedAcceptedSetupCompactPublicKeyVerificationCheckpointCustody> => {
        const checkpointGeometry =
            readAcceptedSetupCompactPublicKeyVerificationCheckpointGeometry(
                input.kernel,
            );
        return await openCompactPublicKeyVerificationCheckpointCustody(
            store,
            input,
            Object.freeze({
                ...checkpointGeometry,
                operationDescription:
                    'accepted-setup compact public-key verification',
                stateStreamDomain:
                    compactPublicKeyVerificationCheckpointStateStreamDomains.acceptedSetup,
            }),
        );
    };
