import { foundationProfile } from '@sealed-lattice/types';
import { beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
    openAuthenticatedCheckpointStore,
    type AuthenticatedCheckpointStore,
    type CheckpointBoundary,
    type CheckpointBoundaryPolicy,
    type CheckpointOperationIdentity,
    type CheckpointRandomCursor,
    type ExpectedCheckpointBoundary,
} from '#packages/protocol/src/index';
import {
    generateRuntimeStorageEncryptionKey,
    hashFilledWith,
    InMemoryRuntimeStorageAdapter,
    openRuntimeTestStore,
    runtimeAuthorityContext,
} from '#packages/protocol/tests/support/runtime-storage-test-support';
import {
    loadFreshTranscriptCoreKernel,
    type TranscriptCoreKernel,
} from '#packages/wasm/src/index';
import {
    asciiItem,
    canonicalItem,
    canonicalTuple,
    concatenateBytes,
    foundationHash512,
    hashItem,
    unsigned16LittleEndian,
    unsigned32LittleEndian,
    unsigned64Item,
    variableBytesItem,
} from '#packages/wasm/tests/canonical-tuple-test-helpers';

const stateStreamDomain = 'sealed-lattice/test/checkpoint-state/v1';

const checkpointLimits = {
    maximumCheckpointStateByteLength:
        2 * foundationProfile.streamChunkByteLength,
    maximumManifestByteLength: 16_384,
    maximumRandomCursorCount: 8,
    maximumRecordSealingCount: 256,
    maximumSourceDigestCount: 8,
    maximumStreamAttemptCount: 4,
    transactionLifetimeMilliseconds: 5_000,
} as const;

const boundaryPolicy: CheckpointBoundaryPolicy = {
    validatePublication: () => undefined,
    validateResume: () => undefined,
};

const proofAttemptIdentifiers = (
    count: number,
): readonly Uint8Array[] =>
    Object.freeze(
        Array.from({ length: count }, (_unused, index) =>
            new Uint8Array(32).fill(index + 1),
        ),
    );

const chunkState = (stateBytes: Uint8Array): readonly Uint8Array[] => {
    const chunks: Uint8Array[] = [];
    for (
        let offset = 0;
        offset < stateBytes.byteLength;
        offset += foundationProfile.streamChunkByteLength
    ) {
        chunks.push(
            stateBytes.slice(
                offset,
                offset + foundationProfile.streamChunkByteLength,
            ),
        );
    }
    return chunks;
};

const deriveChunkDigest = (
    chunkBytes: Uint8Array,
    chunkIndex: number,
): Uint8Array =>
    foundationHash512(
        'sealed-lattice/transport/chunk/v1',
        asciiItem(stateStreamDomain),
        canonicalItem(0x04, unsigned32LittleEndian(chunkIndex)),
        canonicalItem(0x04, unsigned32LittleEndian(chunkBytes.byteLength)),
        variableBytesItem(chunkBytes),
    );

const deriveFullObjectDigest = (stateBytes: Uint8Array): Uint8Array =>
    foundationHash512(
        'sealed-lattice/transport/full-object/v1',
        asciiItem(stateStreamDomain),
        unsigned64Item(BigInt(stateBytes.byteLength)),
        variableBytesItem(stateBytes),
    );

const streamDescriptorFor = (stateBytes: Uint8Array): Uint8Array => {
    const chunks = chunkState(stateBytes);
    const chunkDigests = chunks.map(deriveChunkDigest);
    return canonicalTuple(
        0x1800,
        unsigned64Item(BigInt(stateBytes.byteLength)),
        canonicalItem(
            0x0e,
            concatenateBytes(
                unsigned16LittleEndian(0x06),
                unsigned32LittleEndian(chunkDigests.length),
                ...chunkDigests,
            ),
        ),
        hashItem(deriveFullObjectDigest(stateBytes)),
    );
};

const stateBytesFor = (seed: number): Uint8Array => {
    const bytes = new Uint8Array(foundationProfile.streamChunkByteLength + 37);
    for (let byteIndex = 0; byteIndex < bytes.byteLength; byteIndex += 1) {
        bytes[byteIndex] = (byteIndex * 113 + seed * 29) & 0xff;
    }
    return bytes;
};

const cursorFor = (input: {
    attemptIdentifier: Uint8Array;
    contextByte: number;
    family: number;
    nextCounter?: bigint;
    offset?: number;
    purpose: number;
}): CheckpointRandomCursor => ({
    derivationContextHash: hashFilledWith(input.contextByte),
    family: input.family,
    nextCounter: input.nextCounter ?? 4n,
    ...(input.offset === undefined
        ? {}
        : { nextUnreadBitOffsetInBufferedBlock: input.offset }),
    purpose: input.purpose,
    streamAttemptIdentifier: input.attemptIdentifier,
});

const boundaryFor = (input: {
    identity: CheckpointOperationIdentity;
    safeBoundaryOrdinal?: number;
    stateBytes: Uint8Array;
}): CheckpointBoundary => {
    const sharedAttemptIdentifier = input.identity.streamAttemptIdentifiers[0];
    if (sharedAttemptIdentifier === undefined) {
        throw new Error('test identity is missing its stream attempt');
    }
    return {
        operationKind: 7,
        orderedRandomCursors: [
            cursorFor({
                attemptIdentifier: sharedAttemptIdentifier,
                contextByte: 0x61,
                family: 0x0200,
                purpose: 2,
            }),
            cursorFor({
                attemptIdentifier: sharedAttemptIdentifier,
                contextByte: 0x62,
                family: 0x0200,
                purpose: 3,
                nextCounter: 6n,
                offset: 127,
            }),
        ],
        orderedSourceDigests: [hashFilledWith(0x71), hashFilledWith(0x72)],
        safeBoundaryOrdinal: input.safeBoundaryOrdinal ?? 3,
        stateStreamDescriptorBytes: streamDescriptorFor(input.stateBytes),
        stateStreamDomain,
    };
};

const deterministicBoundaryFor = (input: {
    operationKind?: number;
    safeBoundaryOrdinal?: number;
    sourceByte?: number;
    stateBytes: Uint8Array;
}): CheckpointBoundary => ({
    operationKind: input.operationKind ?? 7,
    orderedRandomCursors: [],
    orderedSourceDigests: [hashFilledWith(input.sourceByte ?? 0x71)],
    safeBoundaryOrdinal: input.safeBoundaryOrdinal ?? 3,
    stateStreamDescriptorBytes: streamDescriptorFor(input.stateBytes),
    stateStreamDomain,
});

const expectedBoundary = (
    boundary: CheckpointBoundary,
): ExpectedCheckpointBoundary => ({
    operationKind: boundary.operationKind,
    orderedRandomCursors: boundary.orderedRandomCursors,
    orderedSourceDigests: boundary.orderedSourceDigests,
    safeBoundaryOrdinal: boundary.safeBoundaryOrdinal,
    stateStreamDomain: boundary.stateStreamDomain,
});

const restoreBytes = async (
    resumed: Awaited<ReturnType<AuthenticatedCheckpointStore['resume']>>,
): Promise<Uint8Array> => {
    const chunks: Uint8Array[] = [];
    await resumed.restoreState((chunkIndex, chunkBytes) => {
        expect(chunkIndex).toBe(chunks.length);
        chunks.push(chunkBytes);
    });
    return concatenateBytes(...chunks);
};

describe('Authenticated checkpoint store', () => {
    let adapter: InMemoryRuntimeStorageAdapter;
    let cursorKernel: TranscriptCoreKernel;
    let encryptionKey: CryptoKey;
    let store: Awaited<ReturnType<typeof openRuntimeTestStore>>['store'];

    beforeAll(async () => {
        cursorKernel = await loadFreshTranscriptCoreKernel();
    });

    beforeEach(async () => {
        adapter = new InMemoryRuntimeStorageAdapter();
        ({ store } = await openRuntimeTestStore({ adapter }));
        encryptionKey = await generateRuntimeStorageEncryptionKey();
    });

    const openStore = (input?: {
        cryptoProvider?: Crypto;
        encryptionKey?: CryptoKey;
    }): AuthenticatedCheckpointStore =>
        openAuthenticatedCheckpointStore({
            authorityContext: runtimeAuthorityContext(),
            boundaryPolicy,
            cryptoProvider: input?.cryptoProvider,
            cursorKernel,
            encryptionKey: input?.encryptionKey ?? encryptionKey,
            limits: checkpointLimits,
            store,
        });

    it('publishes and resumes exact multi-chunk state with shared-attempt cursors', async () => {
        const checkpointStore = openStore();
        const identity = await checkpointStore.beginOperation(
            proofAttemptIdentifiers(1),
        );
        const stateBytes = stateBytesFor(1);
        const boundary = boundaryFor({ identity, stateBytes });
        const canonicalManifest = await checkpointStore.publish({
            boundary,
            identity,
            stateChunks: chunkState(stateBytes),
        });

        expect(new DataView(canonicalManifest.buffer).getUint16(0, true)).toBe(
            0x1805,
        );
        expect(identity.checkpointLineageIdentifier).toHaveLength(32);
        expect(identity.streamAttemptIdentifiers).toHaveLength(1);
        const resumed = await checkpointStore.resume({
            checkpointLineageIdentifier: identity.checkpointLineageIdentifier,
            expectedBoundary: expectedBoundary(boundary),
        });
        expect(resumed.canonicalManifestBytes).toEqual(canonicalManifest);
        expect(resumed.stateStreamDescriptorBytes).toEqual(
            boundary.stateStreamDescriptorBytes,
        );
        expect(await restoreBytes(resumed)).toEqual(stateBytes);
    });

    it('publishes deterministic checkpoint state without random cursors', async () => {
        const checkpointStore = openStore();
        const identity = await checkpointStore.beginOperation([]);
        const stateBytes = stateBytesFor(7);
        const boundary: CheckpointBoundary = {
            operationKind: 8,
            orderedRandomCursors: [],
            orderedSourceDigests: [hashFilledWith(0x73)],
            safeBoundaryOrdinal: 1,
            stateStreamDescriptorBytes: streamDescriptorFor(stateBytes),
            stateStreamDomain,
        };

        await checkpointStore.publish({
            boundary,
            identity,
            stateChunks: chunkState(stateBytes),
        });
        const resumed = await checkpointStore.resume({
            checkpointLineageIdentifier: identity.checkpointLineageIdentifier,
            expectedBoundary: expectedBoundary(boundary),
        });
        expect(resumed.operationIdentity.streamAttemptIdentifiers).toEqual([]);
        expect(await restoreBytes(resumed)).toEqual(stateBytes);
    });

    it('rejects a wrong full-object digest after every chunk digest matches', async () => {
        const checkpointStore = openStore();
        const identity = await checkpointStore.beginOperation([]);
        const stateBytes = stateBytesFor(8);
        const exactDescriptorBytes = streamDescriptorFor(stateBytes);
        const wrongFullObjectDigestDescriptorBytes =
            exactDescriptorBytes.slice();
        wrongFullObjectDigestDescriptorBytes[
            wrongFullObjectDigestDescriptorBytes.byteLength - 1
        ] ^= 1;
        const boundary: CheckpointBoundary = {
            ...deterministicBoundaryFor({ stateBytes }),
            stateStreamDescriptorBytes: wrongFullObjectDigestDescriptorBytes,
        };

        await expect(
            checkpointStore.publish({
                boundary,
                identity,
                stateChunks: chunkState(stateBytes),
            }),
        ).rejects.toMatchObject({ code: 'AuthenticationFailed' });
        await expect(
            checkpointStore.resume({
                checkpointLineageIdentifier:
                    identity.checkpointLineageIdentifier,
                expectedBoundary: expectedBoundary(boundary),
            }),
        ).rejects.toMatchObject({ code: 'MissingRecord' });
    });

    it('rejects a checkpoint state ceiling above the canonical stream profile', () => {
        expect(() =>
            openAuthenticatedCheckpointStore({
                authorityContext: runtimeAuthorityContext(),
                boundaryPolicy,
                cursorKernel,
                encryptionKey,
                limits: {
                    ...checkpointLimits,
                    maximumCheckpointStateByteLength: 2_147_483_649,
                },
                store,
            }),
        ).toThrow(
            'maximumCheckpointStateByteLength exceeds the canonical stream profile.',
        );
    });

    it('rejects a stale resumed identity after another handle advances the lineage', async () => {
        const checkpointStore = openStore();
        const identity = await checkpointStore.beginOperation([]);
        const firstState = stateBytesFor(12);
        const firstBoundary = deterministicBoundaryFor({
            stateBytes: firstState,
        });
        await checkpointStore.publish({
            boundary: firstBoundary,
            identity,
            stateChunks: chunkState(firstState),
        });
        const firstResume = await checkpointStore.resume({
            checkpointLineageIdentifier: identity.checkpointLineageIdentifier,
            expectedBoundary: expectedBoundary(firstBoundary),
        });
        const staleResume = await checkpointStore.resume({
            checkpointLineageIdentifier: identity.checkpointLineageIdentifier,
            expectedBoundary: expectedBoundary(firstBoundary),
        });
        const advancedState = stateBytesFor(13);
        const advancedBoundary = deterministicBoundaryFor({
            safeBoundaryOrdinal: 4,
            stateBytes: advancedState,
        });
        await checkpointStore.publish({
            boundary: advancedBoundary,
            identity: firstResume.operationIdentity,
            stateChunks: chunkState(advancedState),
        });

        await expect(
            checkpointStore.publish({
                boundary: firstBoundary,
                identity: staleResume.operationIdentity,
                stateChunks: chunkState(firstState),
            }),
        ).rejects.toMatchObject({ code: 'Conflict' });
        const resumedAdvanced = await checkpointStore.resume({
            checkpointLineageIdentifier: identity.checkpointLineageIdentifier,
            expectedBoundary: expectedBoundary(advancedBoundary),
        });
        expect(await restoreBytes(resumedAdvanced)).toEqual(advancedState);
    });

    it('snapshots queued resume and publication inputs before taking the lineage lock', async () => {
        const checkpointStore = openStore();
        const identity = await checkpointStore.beginOperation([]);
        const otherIdentity = await checkpointStore.beginOperation([]);
        const firstState = stateBytesFor(14);
        const firstBoundary = deterministicBoundaryFor({
            stateBytes: firstState,
        });
        const firstCanonicalManifest = await checkpointStore.publish({
            boundary: firstBoundary,
            identity,
            stateChunks: chunkState(firstState),
        });
        const restoringCheckpoint = await checkpointStore.resume({
            checkpointLineageIdentifier: identity.checkpointLineageIdentifier,
            expectedBoundary: expectedBoundary(firstBoundary),
        });
        let releaseRestoration: (() => void) | undefined;
        const restorationRelease = new Promise<void>((resolve) => {
            releaseRestoration = resolve;
        });
        let reportRestorationStarted: (() => void) | undefined;
        const restorationStarted = new Promise<void>((resolve) => {
            reportRestorationStarted = resolve;
        });
        const restoration = restoringCheckpoint.restoreState(async () => {
            reportRestorationStarted?.();
            await restorationRelease;
        });
        await restorationStarted;

        const mutableResumeInput = {
            checkpointLineageIdentifier:
                identity.checkpointLineageIdentifier.slice(),
            expectedBoundary: expectedBoundary(firstBoundary),
        };
        const queuedResume = checkpointStore.resume(mutableResumeInput);
        const advancedState = stateBytesFor(15);
        const advancedBoundary = deterministicBoundaryFor({
            safeBoundaryOrdinal: 4,
            stateBytes: advancedState,
        });
        const mutablePublication = {
            boundary: advancedBoundary,
            identity: restoringCheckpoint.operationIdentity,
            stateChunks: chunkState(advancedState),
        };
        const queuedPublication = checkpointStore.publish(mutablePublication);

        mutableResumeInput.checkpointLineageIdentifier.set(
            otherIdentity.checkpointLineageIdentifier,
        );
        mutableResumeInput.expectedBoundary = {
            ...mutableResumeInput.expectedBoundary,
            operationKind: 99,
        };
        mutablePublication.boundary = deterministicBoundaryFor({
            operationKind: 99,
            stateBytes: stateBytesFor(16),
        });
        mutablePublication.identity = otherIdentity;
        mutablePublication.stateChunks = chunkState(stateBytesFor(16));
        releaseRestoration?.();

        await restoration;
        expect((await queuedResume).canonicalManifestBytes).toEqual(
            firstCanonicalManifest,
        );
        await queuedPublication;
        const resumedAdvanced = await checkpointStore.resume({
            checkpointLineageIdentifier: identity.checkpointLineageIdentifier,
            expectedBoundary: expectedBoundary(advancedBoundary),
        });
        expect(await restoreBytes(resumedAdvanced)).toEqual(advancedState);
        await expect(
            checkpointStore.resume({
                checkpointLineageIdentifier:
                    otherIdentity.checkpointLineageIdentifier,
                expectedBoundary: expectedBoundary(mutablePublication.boundary),
            }),
        ).rejects.toMatchObject({ code: 'MissingRecord' });
    });

    it('requires the operation owner to accept every published and resumed boundary', async () => {
        let publicationValidationCount = 0;
        const refusingStore = openAuthenticatedCheckpointStore({
            authorityContext: runtimeAuthorityContext(),
            boundaryPolicy: {
                validatePublication: () => {
                    publicationValidationCount += 1;
                    throw new Error('not an operation-owned safe boundary');
                },
                validateResume: () => {
                    throw new Error('resume is not owned');
                },
            },
            cursorKernel,
            encryptionKey,
            limits: checkpointLimits,
            store,
        });
        const identity = await refusingStore.beginOperation([]);
        const stateBytes = stateBytesFor(17);
        await expect(
            refusingStore.publish({
                boundary: deterministicBoundaryFor({ stateBytes }),
                identity,
                stateChunks: chunkState(stateBytes),
            }),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
        expect(publicationValidationCount).toBe(1);
        expect(adapter.keys()).toEqual([]);
    });

    it('rejects replacement boundary rewinds and operation or source switches', async () => {
        const checkpointStore = openStore();
        const identity = await checkpointStore.beginOperation([]);
        const firstState = stateBytesFor(20);
        const firstBoundary = deterministicBoundaryFor({
            stateBytes: firstState,
        });
        await checkpointStore.publish({
            boundary: firstBoundary,
            identity,
            stateChunks: chunkState(firstState),
        });
        const replacementState = stateBytesFor(21);
        const invalidReplacements = [
            deterministicBoundaryFor({
                safeBoundaryOrdinal: 2,
                stateBytes: replacementState,
            }),
            deterministicBoundaryFor({
                operationKind: 8,
                safeBoundaryOrdinal: 4,
                stateBytes: replacementState,
            }),
            deterministicBoundaryFor({
                safeBoundaryOrdinal: 4,
                sourceByte: 0x72,
                stateBytes: replacementState,
            }),
            deterministicBoundaryFor({
                safeBoundaryOrdinal: 3,
                stateBytes: replacementState,
            }),
        ];
        for (const invalidBoundary of invalidReplacements) {
            await expect(
                checkpointStore.publish({
                    boundary: invalidBoundary,
                    identity,
                    stateChunks: chunkState(replacementState),
                }),
            ).rejects.toMatchObject({ code: 'Conflict' });
        }
        const resumed = await checkpointStore.resume({
            checkpointLineageIdentifier: identity.checkpointLineageIdentifier,
            expectedBoundary: expectedBoundary(firstBoundary),
        });
        expect(await restoreBytes(resumed)).toEqual(firstState);
    });

    it('rejects replacement cursor counter and buffered-bit rewinds', async () => {
        const checkpointStore = openStore();
        const identity = await checkpointStore.beginOperation(
            proofAttemptIdentifiers(1),
        );
        const firstState = stateBytesFor(22);
        const firstBoundary = boundaryFor({ identity, stateBytes: firstState });
        await checkpointStore.publish({
            boundary: firstBoundary,
            identity,
            stateChunks: chunkState(firstState),
        });

        const replacementState = stateBytesFor(23);
        const advancedBoundary = boundaryFor({
            identity,
            safeBoundaryOrdinal: 4,
            stateBytes: replacementState,
        });
        const counterRewindBoundary: CheckpointBoundary = {
            ...advancedBoundary,
            orderedRandomCursors: advancedBoundary.orderedRandomCursors.map(
                (cursor, cursorIndex) =>
                    cursorIndex === 0
                        ? { ...cursor, nextCounter: cursor.nextCounter - 1n }
                        : cursor,
            ),
        };
        const bufferedBitRewindBoundary: CheckpointBoundary = {
            ...advancedBoundary,
            orderedRandomCursors: advancedBoundary.orderedRandomCursors.map(
                (cursor, cursorIndex) =>
                    cursorIndex === 1
                        ? {
                              ...cursor,
                              nextUnreadBitOffsetInBufferedBlock:
                                  (cursor.nextUnreadBitOffsetInBufferedBlock ??
                                      0) - 1,
                          }
                        : cursor,
            ),
        };

        for (const rewoundBoundary of [
            counterRewindBoundary,
            bufferedBitRewindBoundary,
        ]) {
            await expect(
                checkpointStore.publish({
                    boundary: rewoundBoundary,
                    identity,
                    stateChunks: chunkState(replacementState),
                }),
            ).rejects.toMatchObject({ code: 'Conflict' });
        }

        const resumed = await checkpointStore.resume({
            checkpointLineageIdentifier: identity.checkpointLineageIdentifier,
            expectedBoundary: expectedBoundary(firstBoundary),
        });
        expect(await restoreBytes(resumed)).toEqual(firstState);
    });

    it('fails closed at the action-scoped runtime-record sealing ceiling', async () => {
        const boundedStore = openAuthenticatedCheckpointStore({
            authorityContext: runtimeAuthorityContext(),
            boundaryPolicy,
            cursorKernel,
            encryptionKey,
            limits: { ...checkpointLimits, maximumRecordSealingCount: 1 },
            store,
        });
        const identity = await boundedStore.beginOperation([]);
        const stateBytes = stateBytesFor(22);
        await expect(
            boundedStore.publish({
                boundary: deterministicBoundaryFor({ stateBytes }),
                identity,
                stateChunks: chunkState(stateBytes),
            }),
        ).rejects.toMatchObject({ code: 'ResourceLimit' });
        await boundedStore.repair(identity.checkpointLineageIdentifier);
        expect(adapter.keys()).toHaveLength(1);
        expect(adapter.keys()[0]).toMatch(/\/repair\/current-head$/u);
    });

    it('refuses every changed resume cursor, source, operation, and boundary coordinate', async () => {
        const checkpointStore = openStore();
        const identity = await checkpointStore.beginOperation(
            proofAttemptIdentifiers(1),
        );
        const stateBytes = stateBytesFor(2);
        const boundary = boundaryFor({ identity, stateBytes });
        await checkpointStore.publish({
            boundary,
            identity,
            stateChunks: chunkState(stateBytes),
        });
        const exact = expectedBoundary(boundary);
        const changedBoundaries: ExpectedCheckpointBoundary[] = [
            { ...exact, operationKind: exact.operationKind + 1 },
            {
                ...exact,
                safeBoundaryOrdinal: exact.safeBoundaryOrdinal + 1,
            },
            {
                ...exact,
                orderedSourceDigests: [
                    hashFilledWith(0x73),
                    exact.orderedSourceDigests[1],
                ],
            },
            {
                ...exact,
                orderedRandomCursors: exact.orderedRandomCursors.map(
                    (cursor, cursorIndex) =>
                        cursorIndex === 0
                            ? {
                                  ...cursor,
                                  nextCounter: cursor.nextCounter + 1n,
                              }
                            : cursor,
                ),
            },
            {
                ...exact,
                orderedRandomCursors: exact.orderedRandomCursors.map(
                    (cursor, cursorIndex) =>
                        cursorIndex === 1
                            ? {
                                  ...cursor,
                                  nextUnreadBitOffsetInBufferedBlock: 128,
                              }
                            : cursor,
                ),
            },
        ];
        for (const changedBoundary of changedBoundaries) {
            await expect(
                checkpointStore.resume({
                    checkpointLineageIdentifier:
                        identity.checkpointLineageIdentifier,
                    expectedBoundary: changedBoundary,
                }),
            ).rejects.toMatchObject({ code: 'AuthenticationFailed' });
        }
    });

    it('recovers a failed replacement without exposing partial state', async () => {
        const checkpointStore = openStore();
        const identity = await checkpointStore.beginOperation(
            proofAttemptIdentifiers(1),
        );
        const firstState = stateBytesFor(3);
        const firstBoundary = boundaryFor({ identity, stateBytes: firstState });
        await checkpointStore.publish({
            boundary: firstBoundary,
            identity,
            stateChunks: chunkState(firstState),
        });

        const replacementState = stateBytesFor(4);
        const replacementBoundary = boundaryFor({
            identity,
            safeBoundaryOrdinal: 4,
            stateBytes: replacementState,
        });
        adapter.failAtomicMutationAfter(4);
        await expect(
            checkpointStore.publish({
                boundary: replacementBoundary,
                identity,
                stateChunks: chunkState(replacementState),
            }),
        ).rejects.toMatchObject({ code: 'StorageFailure' });

        const restartedCheckpointStore = openStore();
        const resumedOriginal = await restartedCheckpointStore.resume({
            checkpointLineageIdentifier: identity.checkpointLineageIdentifier,
            expectedBoundary: expectedBoundary(firstBoundary),
        });
        expect(await restoreBytes(resumedOriginal)).toEqual(firstState);
        await expect(
            restartedCheckpointStore.resume({
                checkpointLineageIdentifier:
                    identity.checkpointLineageIdentifier,
                expectedBoundary: expectedBoundary(replacementBoundary),
            }),
        ).rejects.toMatchObject({ code: 'AuthenticationFailed' });

        await restartedCheckpointStore.publish({
            boundary: replacementBoundary,
            identity: resumedOriginal.operationIdentity,
            stateChunks: chunkState(replacementState),
        });
        const resumedReplacement = await restartedCheckpointStore.resume({
            checkpointLineageIdentifier: identity.checkpointLineageIdentifier,
            expectedBoundary: expectedBoundary(replacementBoundary),
        });
        expect(await restoreBytes(resumedReplacement)).toEqual(
            replacementState,
        );
    });

    it('refuses interrupted-publication repair when obsolete committed chunk ciphertext is corrupt', async () => {
        const checkpointStore = openStore();
        const identity = await checkpointStore.beginOperation([]);
        const firstState = stateBytesFor(18);
        const firstBoundary = deterministicBoundaryFor({
            stateBytes: firstState,
        });
        await checkpointStore.publish({
            boundary: firstBoundary,
            identity,
            stateChunks: chunkState(firstState),
        });
        const obsoleteChunkObjectKeys = adapter
            .keys()
            .filter(
                (key) =>
                    key.includes('/objects/') &&
                    (adapter.rawRead(key)?.byteLength ?? 0) > 1_000,
            );
        expect(obsoleteChunkObjectKeys).toHaveLength(2);

        const replacementState = stateBytesFor(19);
        const replacementBoundary = deterministicBoundaryFor({
            safeBoundaryOrdinal: 4,
            stateBytes: replacementState,
        });
        adapter.failAtomicMutationAfter(5);
        await expect(
            checkpointStore.publish({
                boundary: replacementBoundary,
                identity,
                stateChunks: chunkState(replacementState),
            }),
        ).rejects.toMatchObject({ code: 'StorageFailure' });
        const retainedObsoleteChunkObjectKeys = obsoleteChunkObjectKeys.filter(
            (objectKey) => adapter.rawRead(objectKey) !== undefined,
        );
        expect(retainedObsoleteChunkObjectKeys.length).toBeGreaterThan(0);
        for (const objectKey of retainedObsoleteChunkObjectKeys) {
            const corruptBytes = adapter.rawRead(objectKey);
            expect(corruptBytes).toBeDefined();
            if (corruptBytes === undefined) continue;
            corruptBytes[corruptBytes.byteLength - 1] ^= 1;
            adapter.rawWrite(objectKey, corruptBytes);
        }

        const restartedCheckpointStore = openStore();
        await expect(
            restartedCheckpointStore.repair(
                identity.checkpointLineageIdentifier,
            ),
        ).rejects.toMatchObject({ code: 'AuthenticationFailed' });
        for (const objectKey of retainedObsoleteChunkObjectKeys) {
            expect(adapter.rawRead(objectKey)).toBeDefined();
        }
    });

    it('rejects unissued attempts, duplicate cursors, malformed offsets, and wrong cursor schemas', async () => {
        const checkpointStore = openStore();
        const identity = await checkpointStore.beginOperation(
            proofAttemptIdentifiers(1),
        );
        const stateBytes = stateBytesFor(5);
        const boundary = boundaryFor({ identity, stateBytes });
        const forgedIdentity = {
            checkpointLineageIdentifier:
                identity.checkpointLineageIdentifier.slice(),
            streamAttemptIdentifiers: identity.streamAttemptIdentifiers.map(
                (identifier) => identifier.slice(),
            ),
        } as unknown as CheckpointOperationIdentity;
        await expect(
            checkpointStore.publish({
                boundary,
                identity: forgedIdentity,
                stateChunks: chunkState(stateBytes),
            }),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
        await expect(
            checkpointStore.publish({
                boundary: {
                    ...boundary,
                    orderedRandomCursors: boundary.orderedRandomCursors.map(
                        (cursor) => ({
                            ...cursor,
                            streamAttemptIdentifier: new Uint8Array(32).fill(
                                0xa5,
                            ),
                        }),
                    ),
                },
                identity,
                stateChunks: chunkState(stateBytes),
            }),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
        await expect(
            checkpointStore.publish({
                boundary: {
                    ...boundary,
                    orderedRandomCursors: [
                        boundary.orderedRandomCursors[0],
                        boundary.orderedRandomCursors[0],
                    ],
                },
                identity,
                stateChunks: chunkState(stateBytes),
            }),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
        await expect(
            checkpointStore.publish({
                boundary: {
                    ...boundary,
                    orderedRandomCursors: [
                        {
                            ...boundary.orderedRandomCursors[0],
                            nextCounter: 0n,
                            nextUnreadBitOffsetInBufferedBlock: 1,
                        },
                    ],
                },
                identity,
                stateChunks: chunkState(stateBytes),
            }),
        ).rejects.toMatchObject({ code: 'InvalidInput' });

        const wrongKernelStore = openAuthenticatedCheckpointStore({
            authorityContext: runtimeAuthorityContext(),
            boundaryPolicy,
            cursorKernel: {
                ...cursorKernel,
                encodePrivateRandomCursor: () => ({
                    canonicalBytesHex: '0318010000000000',
                }),
            },
            encryptionKey,
            limits: checkpointLimits,
            store,
        });
        const wrongKernelIdentity = await wrongKernelStore.beginOperation(
            proofAttemptIdentifiers(1),
        );
        await expect(
            wrongKernelStore.publish({
                boundary: boundaryFor({
                    identity: wrongKernelIdentity,
                    stateBytes,
                }),
                identity: wrongKernelIdentity,
                stateChunks: chunkState(stateBytes),
            }),
        ).rejects.toMatchObject({ code: 'AuthenticationFailed' });
    });

    it('fails closed on weak entropy, tampered chunks, a wrong key, and eviction', async () => {
        let randomnessInvocationCount = 0;
        const repeatingCryptoProvider = {
            getRandomValues: <Value extends ArrayBufferView>(
                value: Value,
            ): Value => {
                randomnessInvocationCount += 1;
                new Uint8Array(
                    value.buffer,
                    value.byteOffset,
                    value.byteLength,
                ).fill(1);
                return value;
            },
            subtle: globalThis.crypto.subtle,
        } as Crypto;
        await expect(
            openStore({
                cryptoProvider: repeatingCryptoProvider,
            }).beginOperation(proofAttemptIdentifiers(1)),
        ).rejects.toMatchObject({ code: 'EntropyFailure' });
        expect(randomnessInvocationCount).toBe(2);

        const checkpointStore = openStore();
        const identity = await checkpointStore.beginOperation(
            proofAttemptIdentifiers(1),
        );
        const stateBytes = stateBytesFor(6);
        const boundary = boundaryFor({ identity, stateBytes });
        await checkpointStore.publish({
            boundary,
            identity,
            stateChunks: chunkState(stateBytes),
        });
        const largestObjectKey = adapter
            .keys()
            .filter((key) => key.includes('/objects/'))
            .map((key) => ({
                byteLength: adapter.rawRead(key)?.byteLength ?? 0,
                key,
            }))
            .sort((left, right) => right.byteLength - left.byteLength)[0]?.key;
        if (largestObjectKey === undefined) {
            throw new Error('checkpoint did not publish an object');
        }
        const tampered = adapter.rawRead(largestObjectKey);
        if (tampered === undefined) {
            throw new Error('checkpoint object disappeared');
        }
        tampered[tampered.byteLength - 1] ^= 1;
        adapter.rawWrite(largestObjectKey, tampered);
        const resumed = await checkpointStore.resume({
            checkpointLineageIdentifier: identity.checkpointLineageIdentifier,
            expectedBoundary: expectedBoundary(boundary),
        });
        await expect(restoreBytes(resumed)).rejects.toMatchObject({
            code: 'AuthenticationFailed',
        });

        adapter.rawWrite(
            largestObjectKey,
            tampered.map((byte, index) =>
                index === tampered.byteLength - 1 ? byte ^ 1 : byte,
            ),
        );
        const wrongKey = await generateRuntimeStorageEncryptionKey();
        await expect(
            openStore({ encryptionKey: wrongKey }).resume({
                checkpointLineageIdentifier:
                    identity.checkpointLineageIdentifier,
                expectedBoundary: expectedBoundary(boundary),
            }),
        ).rejects.toMatchObject({ code: 'AuthenticationFailed' });
        const wrongContextStore = openAuthenticatedCheckpointStore({
            authorityContext: runtimeAuthorityContext({
                actionContextHash: hashFilledWith(0x99),
            }),
            boundaryPolicy,
            cursorKernel,
            encryptionKey,
            limits: checkpointLimits,
            store,
        });
        await expect(
            wrongContextStore.resume({
                checkpointLineageIdentifier:
                    identity.checkpointLineageIdentifier,
                expectedBoundary: expectedBoundary(boundary),
            }),
        ).rejects.toMatchObject({ code: 'AuthenticationFailed' });

        adapter.failAtomicMutationAfter(3);
        await expect(
            checkpointStore.evict(identity.checkpointLineageIdentifier),
        ).rejects.toMatchObject({ code: 'StorageFailure' });
        await checkpointStore.repair(identity.checkpointLineageIdentifier);
        await expect(
            checkpointStore.resume({
                checkpointLineageIdentifier:
                    identity.checkpointLineageIdentifier,
                expectedBoundary: expectedBoundary(boundary),
            }),
        ).rejects.toMatchObject({ code: 'MissingRecord' });
    });
});
