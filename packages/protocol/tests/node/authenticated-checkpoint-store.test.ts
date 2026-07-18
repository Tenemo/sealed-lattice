import { foundationProfile } from '@sealed-lattice/types';
import { beforeEach, describe, expect, it } from 'vitest';

import {
    openAuthenticatedCheckpointStore,
    openAuthenticatedCheckpointStoreWithProtection,
    type AuthenticatedCheckpointStore,
    type AuthenticatedCheckpointStoreLimits,
    type CheckpointBoundary,
    type CheckpointBoundaryPolicy,
    type CheckpointOperationIdentity,
    type ExpectedCheckpointBoundary,
    type TransferableAuthenticatedCheckpointStore,
} from '#packages/protocol/src/runtime/authenticated-checkpoint-store';
import {
    bytesToHex,
    createRuntimeRecordProtection,
    createRuntimeRecordProtectionFromSession,
    readRuntimeRecord,
    releaseRuntimeRecordProtection,
    stageRuntimeRecordWrite,
    type RuntimeRecordProtectionSession,
} from '#packages/protocol/src/runtime/authenticated-runtime-record';
import {
    generateRuntimeStorageEncryptionKey,
    hashFilledWith,
    InMemoryRuntimeStorageAdapter,
    openRuntimeTestStore,
    runtimeAuthorityContext,
} from '#packages/protocol/tests/support/runtime-storage-test-support';
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
    maximumActiveOperationIdentityCount: 64,
    maximumCheckpointStateByteLength:
        2 * foundationProfile.streamChunkByteLength,
    maximumManifestByteLength: 16_384,
    maximumRandomCursorManifestByteLength: 4_096,
    maximumRecordSealingCount: 256,
    maximumSourceDigestCount: 8,
    transactionLifetimeMilliseconds: 5_000,
} as const;

const boundaryPolicy: CheckpointBoundaryPolicy = {
    validatePublication: () => undefined,
    validateResume: () => undefined,
};

const proofAttemptIdentifier = (seed = 1): Uint8Array =>
    new Uint8Array(32).fill(seed);

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

const privateRandomCursorManifestFor = (seed: number): Uint8Array =>
    Uint8Array.from({ length: 96 }, (_unused, index) =>
        (seed * 37 + index * 113) & 0xff,
    );

const emptyPrivateRandomCursorManifest = (): Uint8Array<ArrayBuffer> =>
    Uint8Array.of(
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

const boundaryFor = (input: {
    identity: CheckpointOperationIdentity;
    safeBoundaryOrdinal?: number;
    stateBytes: Uint8Array;
}): CheckpointBoundary => {
    const sharedAttemptIdentifier =
        input.identity.privateRandomnessStreamAttemptIdentifier;
    if (sharedAttemptIdentifier === undefined) {
        throw new Error('test identity is missing its stream attempt');
    }
    return {
        operationKind: 7,
        privateRandomCursorManifestBytes: privateRandomCursorManifestFor(0x61),
        privateRandomnessStreamAttemptIdentifier:
            sharedAttemptIdentifier.slice(),
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
    privateRandomCursorManifestBytes: emptyPrivateRandomCursorManifest(),
    orderedSourceDigests: [hashFilledWith(input.sourceByte ?? 0x71)],
    safeBoundaryOrdinal: input.safeBoundaryOrdinal ?? 3,
    stateStreamDescriptorBytes: streamDescriptorFor(input.stateBytes),
    stateStreamDomain,
});

const expectedBoundary = (
    boundary: CheckpointBoundary,
): ExpectedCheckpointBoundary => ({
    operationKind: boundary.operationKind,
    privateRandomCursorManifestBytes:
        boundary.privateRandomCursorManifestBytes,
    ...(boundary.privateRandomnessStreamAttemptIdentifier === undefined
        ? {}
        : {
              privateRandomnessStreamAttemptIdentifier:
                  boundary.privateRandomnessStreamAttemptIdentifier,
          }),
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
    let encryptionKey: CryptoKey;
    let store: Awaited<ReturnType<typeof openRuntimeTestStore>>['store'];

    beforeEach(async () => {
        adapter = new InMemoryRuntimeStorageAdapter();
        ({ store } = await openRuntimeTestStore({ adapter }));
        encryptionKey = await generateRuntimeStorageEncryptionKey();
    });

    const openStore = (input?: {
        cryptoProvider?: Crypto;
        encryptionKey?: CryptoKey;
        limits?: AuthenticatedCheckpointStoreLimits;
    }): TransferableAuthenticatedCheckpointStore =>
        openAuthenticatedCheckpointStore({
            authorityContext: runtimeAuthorityContext(),
            boundaryPolicy,
            cryptoProvider: input?.cryptoProvider,
            encryptionKey: input?.encryptionKey ?? encryptionKey,
            limits: input?.limits ?? checkpointLimits,
            store,
        });

    it('transfers exclusive ownership and revokes identities on close', async () => {
        const retainedStore = openStore();
        const ownedStore = retainedStore.claimExclusiveOwner();

        expect(() => retainedStore.copyAuthorityContext()).toThrowError(
            expect.objectContaining({ code: 'InvalidState' }),
        );
        expect(() => retainedStore.claimExclusiveOwner()).toThrowError(
            expect.objectContaining({ code: 'InvalidState' }),
        );

        const identity = await ownedStore.beginOperation();
        const firstClose = ownedStore.close();
        const secondClose = ownedStore.close();
        expect(secondClose).toBe(firstClose);
        await firstClose;

        expect(() => ownedStore.beginOperation()).toThrowError(
            expect.objectContaining({ code: 'InvalidState' }),
        );
        expect(identity.checkpointLineageIdentifier).toEqual(
            new Uint8Array(32),
        );
    });

    it('retries failed protection cleanup without exposing half-closed state', async () => {
        let closeAttemptCount = 0;
        let sampledIdentifierByte = 0x40;
        const session: RuntimeRecordProtectionSession = Object.freeze({
            close: () => {
                closeAttemptCount += 1;
                if (closeAttemptCount === 1) {
                    return Promise.reject(
                        new Error('Injected protection cleanup failure.'),
                    );
                }
                return Promise.resolve();
            },
            openCanonicalEnvelope: () =>
                Promise.reject(new Error('No record is opened by this test.')),
            sampleIdentifier: ({ byteLength }) =>
                new Uint8Array(byteLength).fill((sampledIdentifierByte += 1)),
            sealPlaintext: () =>
                Promise.reject(new Error('No record is sealed by this test.')),
        });
        const protection = createRuntimeRecordProtectionFromSession({
            authorityContext: runtimeAuthorityContext(),
            session,
        });
        const checkpointStore = openAuthenticatedCheckpointStoreWithProtection({
            boundaryPolicy,
            limits: checkpointLimits,
            protection,
            store,
        });
        const identity = await checkpointStore.beginOperation();
        const retainedLineageIdentifier = identity.checkpointLineageIdentifier;

        const failedClose = checkpointStore.close();
        await expect(failedClose).rejects.toThrow(
            'Injected protection cleanup failure.',
        );
        expect(identity.checkpointLineageIdentifier).toEqual(
            retainedLineageIdentifier,
        );
        expect(() => checkpointStore.beginOperation()).toThrowError(
            expect.objectContaining({ code: 'InvalidState' }),
        );

        const successfulClose = checkpointStore.close();
        expect(successfulClose).not.toBe(failedClose);
        await expect(successfulClose).resolves.toBeUndefined();
        expect(closeAttemptCount).toBe(2);
        expect(identity.checkpointLineageIdentifier).toEqual(
            new Uint8Array(32),
        );
    });

    it('bounds active identities and recycles only released lineage reservations', async () => {
        const sampledIdentifierBytes = [0x11, 0x22, 0x33, 0x11];
        let randomnessInvocationCount = 0;
        const boundedCryptoProvider = {
            getRandomValues: <Value extends ArrayBufferView>(
                value: Value,
            ): Value => {
                const fillByte =
                    sampledIdentifierBytes[randomnessInvocationCount];
                if (fillByte === undefined) {
                    throw new Error('Unexpected identifier sampling request.');
                }
                randomnessInvocationCount += 1;
                new Uint8Array(
                    value.buffer,
                    value.byteOffset,
                    value.byteLength,
                ).fill(fillByte);
                return value;
            },
            subtle: globalThis.crypto.subtle,
        } as Crypto;
        const checkpointStore = openStore({
            cryptoProvider: boundedCryptoProvider,
            limits: {
                ...checkpointLimits,
                maximumActiveOperationIdentityCount: 2,
            },
        });
        const firstIdentity = await checkpointStore.beginOperation();
        const secondIdentity = await checkpointStore.beginOperation();
        await expect(checkpointStore.beginOperation()).rejects.toMatchObject({
            code: 'ResourceLimit',
        });
        expect(randomnessInvocationCount).toBe(2);

        await checkpointStore.releaseOperationIdentity(firstIdentity);
        await checkpointStore.releaseOperationIdentity(firstIdentity);
        expect(firstIdentity.checkpointLineageIdentifier).toEqual(
            new Uint8Array(32),
        );
        const thirdIdentity = await checkpointStore.beginOperation();
        await checkpointStore.releaseOperationIdentity(secondIdentity);
        await checkpointStore.releaseOperationIdentity(thirdIdentity);

        const recycledIdentity = await checkpointStore.beginOperation();
        expect(recycledIdentity.checkpointLineageIdentifier).toEqual(
            new Uint8Array(32).fill(0x11),
        );
        expect(randomnessInvocationCount).toBe(4);
        await expect(
            checkpointStore.releaseOperationIdentity(
                Object.freeze({}) as CheckpointOperationIdentity,
            ),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
        await checkpointStore.releaseOperationIdentity(recycledIdentity);
        await checkpointStore.close();
    });

    it('reserves one opaque lineage before proof-attempt binding and restores capacity on cancellation', async () => {
        const checkpointStore = openStore({
            limits: {
                ...checkpointLimits,
                maximumActiveOperationIdentityCount: 1,
            },
        });
        const reservation =
            await checkpointStore.reserveCheckpointLineage();
        const reservedLineageIdentifier =
            reservation.checkpointLineageIdentifier;
        expect(reservedLineageIdentifier).toHaveLength(32);
        await expect(checkpointStore.beginOperation()).rejects.toMatchObject({
            code: 'ResourceLimit',
        });

        const stateBytes = Uint8Array.of(0x21, 0x43, 0x65, 0x87);
        await expect(
            checkpointStore.publish({
                boundary: deterministicBoundaryFor({ stateBytes }),
                identity:
                    reservation as unknown as CheckpointOperationIdentity,
                stateChunks: [stateBytes],
            }),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
        expect(adapter.keys()).toEqual([]);

        await expect(
            checkpointStore.bindCheckpointLineageToProofAttempt(
                reservation,
                new Uint8Array(31),
            ),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
        expect(reservation.checkpointLineageIdentifier).toEqual(
            reservedLineageIdentifier,
        );

        const proofAttemptLineageIdentifier = proofAttemptIdentifier(0x42);
        const identity =
            await checkpointStore.bindCheckpointLineageToProofAttempt(
                reservation,
                proofAttemptLineageIdentifier,
            );
        expect(identity.checkpointLineageIdentifier).toEqual(
            reservedLineageIdentifier,
        );
        expect(identity.privateRandomnessStreamAttemptIdentifier).toEqual(
            proofAttemptLineageIdentifier,
        );
        expect(reservation.checkpointLineageIdentifier).toEqual(
            new Uint8Array(32),
        );
        await expect(
            checkpointStore.bindCheckpointLineageToProofAttempt(
                reservation,
                proofAttemptIdentifier(0x43),
            ),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
        await checkpointStore.releaseOperationIdentity(identity);

        const cancelledReservation =
            await checkpointStore.reserveCheckpointLineage();
        await checkpointStore.releaseCheckpointLineageReservation(
            cancelledReservation,
        );
        await checkpointStore.releaseCheckpointLineageReservation(
            cancelledReservation,
        );
        expect(cancelledReservation.checkpointLineageIdentifier).toEqual(
            new Uint8Array(32),
        );
        const replacementIdentity = await checkpointStore.beginOperation();
        await checkpointStore.releaseOperationIdentity(replacementIdentity);
        await checkpointStore.close();
    });

    it('releases every identity across repeated publish and eviction cycles', async () => {
        const checkpointStore = openStore({
            limits: {
                ...checkpointLimits,
                maximumActiveOperationIdentityCount: 2,
                maximumRecordSealingCount: 2_048,
            },
        });
        for (let cycleIndex = 0; cycleIndex < 16; cycleIndex += 1) {
            const identity = await checkpointStore.beginOperation();
            const stateBytes = Uint8Array.of(
                cycleIndex,
                cycleIndex ^ 0x5a,
                cycleIndex ^ 0xa5,
            );
            await checkpointStore.publish({
                boundary: deterministicBoundaryFor({
                    sourceByte: 0x80 + cycleIndex,
                    stateBytes,
                }),
                identity,
                stateChunks: [stateBytes],
            });
            await checkpointStore.evict(identity.checkpointLineageIdentifier);
            await checkpointStore.releaseOperationIdentity(identity);
            expect(identity.checkpointLineageIdentifier).toEqual(
                new Uint8Array(32),
            );
        }

        const finalIdentity = await checkpointStore.beginOperation();
        await checkpointStore.releaseOperationIdentity(finalIdentity);
        await checkpointStore.close();
    });

    it('releases resumed identities without losing the retained checkpoint', async () => {
        const checkpointStore = openStore({
            limits: {
                ...checkpointLimits,
                maximumActiveOperationIdentityCount: 1,
            },
        });
        const publishingIdentity = await checkpointStore.beginOperation();
        const lineageIdentifier =
            publishingIdentity.checkpointLineageIdentifier;
        const stateBytes = Uint8Array.of(0x31, 0x42, 0x53, 0x64);
        const boundary = deterministicBoundaryFor({ stateBytes });
        await checkpointStore.publish({
            boundary,
            identity: publishingIdentity,
            stateChunks: [stateBytes],
        });
        await checkpointStore.releaseOperationIdentity(publishingIdentity);

        for (let resumeIndex = 0; resumeIndex < 12; resumeIndex += 1) {
            const resumed = await checkpointStore.resume({
                checkpointLineageIdentifier: lineageIdentifier,
                expectedBoundary: expectedBoundary(boundary),
            });
            expect(await restoreBytes(resumed)).toEqual(stateBytes);
            await checkpointStore.releaseOperationIdentity(
                resumed.operationIdentity,
            );
        }

        await checkpointStore.evict(lineageIdentifier);
        await checkpointStore.close();
    });

    it('waits for an active publication before releasing its identity', async () => {
        const checkpointStore = openStore();
        const identity = await checkpointStore.beginOperation();
        const retainedLineageIdentifier = identity.checkpointLineageIdentifier;
        const stateBytes = Uint8Array.of(0x17, 0x28, 0x39);
        let allowStateChunk: (() => void) | undefined;
        const stateChunkGate = new Promise<void>((resolve) => {
            allowStateChunk = resolve;
        });
        const publication = checkpointStore.publish({
            boundary: deterministicBoundaryFor({ stateBytes }),
            identity,
            stateChunks: {
                async *[Symbol.asyncIterator]() {
                    await stateChunkGate;
                    yield stateBytes;
                },
            },
        });
        await Promise.resolve();
        const identityRelease =
            checkpointStore.releaseOperationIdentity(identity);
        expect(identity.checkpointLineageIdentifier).toEqual(
            retainedLineageIdentifier,
        );

        allowStateChunk?.();
        await publication;
        await identityRelease;
        expect(identity.checkpointLineageIdentifier).toEqual(
            new Uint8Array(32),
        );
        await checkpointStore.close();
    });

    it('publishes and resumes exact multi-chunk state with an opaque cursor manifest', async () => {
        const checkpointStore = openStore();
        const identity = await checkpointStore.beginOperation(
            proofAttemptIdentifier(),
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
        expect(identity.privateRandomnessStreamAttemptIdentifier).toEqual(
            proofAttemptIdentifier(),
        );
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

    it('refuses authenticated manifest storage records with noncanonical binary framing', async () => {
        const checkpointStore = openStore();
        const identity = await checkpointStore.beginOperation();
        const stateBytes = stateBytesFor(24);
        const boundary = deterministicBoundaryFor({ stateBytes });
        await checkpointStore.publish({
            boundary,
            identity,
            stateChunks: chunkState(stateBytes),
        });

        const logicalRecordKey = `checkpoint/manifest/${bytesToHex(
            identity.checkpointLineageIdentifier,
        )}`;
        const operationDomain =
            'sealed-lattice/runtime/checkpoint-manifest-record/v1';
        const protection = createRuntimeRecordProtection({
            authorityContext: runtimeAuthorityContext(),
            encryptionKey,
            maximumRecordSealingCount: 32,
        });
        const openedManifest = await readRuntimeRecord({
            logicalRecordKey,
            operationDomain,
            protection,
            store,
        });
        expect(openedManifest).toBeDefined();
        if (openedManifest === undefined) {
            await releaseRuntimeRecordProtection(protection);
            return;
        }
        const originalPlaintext = openedManifest.plaintext.slice();
        expect(new DataView(originalPlaintext.buffer).getUint16(0, true)).toBe(
            1,
        );
        expect(new DataView(originalPlaintext.buffer).getUint32(34, true)).toBe(
            originalPlaintext.byteLength - 38,
        );

        const malformedRecords = [
            (() => {
                const bytes = originalPlaintext.slice();
                new DataView(bytes.buffer).setUint16(0, 2, true);
                return bytes;
            })(),
            (() => {
                const bytes = originalPlaintext.slice();
                new DataView(bytes.buffer).setUint32(34, 0, true);
                return bytes;
            })(),
            (() => {
                const bytes = originalPlaintext.slice();
                bytes.fill(0, 2, 34);
                return bytes;
            })(),
            originalPlaintext.slice(0, -1),
            concatenateBytes(originalPlaintext, Uint8Array.of(0)),
        ];

        let currentSealedBytes = openedManifest.sealedBytes;
        try {
            for (const malformedRecord of malformedRecords) {
                const transaction = await store.beginTransaction({
                    lifetimeMilliseconds:
                        checkpointLimits.transactionLifetimeMilliseconds,
                });
                currentSealedBytes = await stageRuntimeRecordWrite({
                    expectedCurrentSealedBytes: currentSealedBytes,
                    logicalRecordKey,
                    operationDomain,
                    plaintext: malformedRecord,
                    protection,
                    transaction,
                });
                await transaction.commit();

                const malformedCheckpointStore = openStore();
                await expect(
                    malformedCheckpointStore.resume({
                        checkpointLineageIdentifier:
                            identity.checkpointLineageIdentifier,
                        expectedBoundary: expectedBoundary(boundary),
                    }),
                ).rejects.toMatchObject({ code: 'AuthenticationFailed' });
                await malformedCheckpointStore.close();

                const restoreTransaction = await store.beginTransaction({
                    lifetimeMilliseconds:
                        checkpointLimits.transactionLifetimeMilliseconds,
                });
                currentSealedBytes = await stageRuntimeRecordWrite({
                    expectedCurrentSealedBytes: currentSealedBytes,
                    logicalRecordKey,
                    operationDomain,
                    plaintext: originalPlaintext,
                    protection,
                    transaction: restoreTransaction,
                });
                await restoreTransaction.commit();
            }
        } finally {
            originalPlaintext.fill(0);
            openedManifest.plaintext.fill(0);
            for (const malformedRecord of malformedRecords) {
                malformedRecord.fill(0);
            }
            await releaseRuntimeRecordProtection(protection);
            await checkpointStore.close();
        }
    });

    it('retains one exact proof-attempt identifier and rejects malformed identifiers', async () => {
        const checkpointStore = openStore();
        const attemptIdentifier = new Uint8Array(32).fill(0x31);
        const beginPromise = checkpointStore.beginOperation(attemptIdentifier);
        attemptIdentifier.fill(0x91);

        const identity = await beginPromise;
        expect(identity.privateRandomnessStreamAttemptIdentifier).toEqual(
            new Uint8Array(32).fill(0x31),
        );

        const copiedIdentifier =
            identity.privateRandomnessStreamAttemptIdentifier;
        copiedIdentifier?.fill(0xff);
        expect(identity.privateRandomnessStreamAttemptIdentifier).toEqual(
            new Uint8Array(32).fill(0x31),
        );

        await expect(
            checkpointStore.beginOperation(new Uint8Array(31)),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
    });

    it('publishes deterministic checkpoint state without random cursors', async () => {
        const checkpointStore = openStore();
        const identity = await checkpointStore.beginOperation();
        const stateBytes = stateBytesFor(7);
        const boundary: CheckpointBoundary = {
            operationKind: 8,
            privateRandomCursorManifestBytes:
                emptyPrivateRandomCursorManifest(),
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
        expect(
            resumed.operationIdentity
                .privateRandomnessStreamAttemptIdentifier,
        ).toBeUndefined();
        expect(await restoreBytes(resumed)).toEqual(stateBytes);
    });

    it('rejects a wrong full-object digest after every chunk digest matches', async () => {
        const checkpointStore = openStore();
        const identity = await checkpointStore.beginOperation();
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
                encryptionKey,
                limits: {
                    ...checkpointLimits,
                    maximumActiveOperationIdentityCount: 0,
                },
                store,
            }),
        ).toThrow(
            'maximumActiveOperationIdentityCount must be a positive safe integer.',
        );
        expect(() =>
            openAuthenticatedCheckpointStore({
                authorityContext: runtimeAuthorityContext(),
                boundaryPolicy,
                encryptionKey,
                limits: {
                    ...checkpointLimits,
                    maximumActiveOperationIdentityCount: 65,
                },
                store,
            }),
        ).toThrow(
            'maximumActiveOperationIdentityCount exceeds the fixed 64-identity checkpoint profile.',
        );
        expect(() =>
            openAuthenticatedCheckpointStore({
                authorityContext: runtimeAuthorityContext(),
                boundaryPolicy,
                encryptionKey,
                limits: {
                    ...checkpointLimits,
                    maximumCheckpointStateByteLength:
                        foundationProfile.maximumCanonicalStreamByteLength + 1,
                },
                store,
            }),
        ).toThrow(
            'maximumCheckpointStateByteLength exceeds the canonical stream profile.',
        );
    });

    it('rejects a stale resumed identity after another handle advances the lineage', async () => {
        const checkpointStore = openStore();
        const identity = await checkpointStore.beginOperation();
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
        const identity = await checkpointStore.beginOperation();
        const otherIdentity = await checkpointStore.beginOperation();
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
            encryptionKey,
            limits: checkpointLimits,
            store,
        });
        const identity = await refusingStore.beginOperation();
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
        const identity = await checkpointStore.beginOperation();
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

    it('keeps cursor manifests opaque while binding their exact bytes', async () => {
        const checkpointStore = openStore();
        const identity = await checkpointStore.beginOperation(
            proofAttemptIdentifier(),
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
        const replacementBoundary: CheckpointBoundary = {
            ...advancedBoundary,
            privateRandomCursorManifestBytes:
                advancedBoundary.privateRandomCursorManifestBytes.map(
                    (byte, byteIndex) => (byteIndex === 17 ? byte ^ 0x80 : byte),
                ),
        };
        await checkpointStore.publish({
            boundary: replacementBoundary,
            identity,
            stateChunks: chunkState(replacementState),
        });

        await expect(
            checkpointStore.resume({
                checkpointLineageIdentifier:
                    identity.checkpointLineageIdentifier,
                expectedBoundary: expectedBoundary(advancedBoundary),
            }),
        ).rejects.toMatchObject({ code: 'AuthenticationFailed' });
        const resumedReplacement = await checkpointStore.resume({
            checkpointLineageIdentifier:
                identity.checkpointLineageIdentifier,
            expectedBoundary: expectedBoundary(replacementBoundary),
        });
        expect(await restoreBytes(resumedReplacement)).toEqual(
            replacementState,
        );

        const sameBoundaryDifferentManifest: CheckpointBoundary = {
            ...replacementBoundary,
            privateRandomCursorManifestBytes:
                replacementBoundary.privateRandomCursorManifestBytes.map(
                    (byte, byteIndex) => (byteIndex === 31 ? byte ^ 1 : byte),
                ),
        };
        await expect(
            checkpointStore.publish({
                boundary: sameBoundaryDifferentManifest,
                identity,
                stateChunks: chunkState(replacementState),
            }),
        ).rejects.toMatchObject({ code: 'Conflict' });
    });

    it('fails closed at the action-scoped runtime-record sealing ceiling', async () => {
        const boundedStore = openAuthenticatedCheckpointStore({
            authorityContext: runtimeAuthorityContext(),
            boundaryPolicy,
            encryptionKey,
            limits: { ...checkpointLimits, maximumRecordSealingCount: 1 },
            store,
        });
        const identity = await boundedStore.beginOperation();
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

    it('refuses every changed resume manifest, source, operation, and boundary coordinate', async () => {
        const checkpointStore = openStore();
        const identity = await checkpointStore.beginOperation(
            proofAttemptIdentifier(),
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
                privateRandomCursorManifestBytes:
                    exact.privateRandomCursorManifestBytes.map(
                        (byte, byteIndex) =>
                            byteIndex === 0 ? byte ^ 1 : byte,
                    ),
            },
            {
                ...exact,
                privateRandomnessStreamAttemptIdentifier:
                    proofAttemptIdentifier(0x7f),
            },
            {
                ...exact,
                privateRandomCursorManifestBytes: new Uint8Array(
                    exact.privateRandomCursorManifestBytes.byteLength + 1,
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
            proofAttemptIdentifier(),
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
        const identity = await checkpointStore.beginOperation();
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
                    (adapter.rawRead(key)?.byteLength ?? 0) >
                        foundationProfile.streamChunkByteLength,
            );
        expect(obsoleteChunkObjectKeys).toHaveLength(1);

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

    it('rejects forged identities, unissued attempts, and oversized opaque manifests', async () => {
        const checkpointStore = openStore();
        const identity = await checkpointStore.beginOperation(
            proofAttemptIdentifier(),
        );
        const stateBytes = stateBytesFor(5);
        const boundary = boundaryFor({ identity, stateBytes });
        const forgedIdentity = {
            checkpointLineageIdentifier:
                identity.checkpointLineageIdentifier.slice(),
            privateRandomnessStreamAttemptIdentifier:
                identity.privateRandomnessStreamAttemptIdentifier?.slice(),
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
                    privateRandomnessStreamAttemptIdentifier:
                        proofAttemptIdentifier(0xa5),
                },
                identity,
                stateChunks: chunkState(stateBytes),
            }),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
        await expect(
            checkpointStore.publish({
                boundary: {
                    ...boundary,
                    privateRandomCursorManifestBytes: new Uint8Array(
                        checkpointLimits.maximumRandomCursorManifestByteLength +
                            1,
                    ),
                },
                identity,
                stateChunks: chunkState(stateBytes),
            }),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
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
        const repeatingIdentifierStore = openStore({
            cryptoProvider: repeatingCryptoProvider,
        });
        await repeatingIdentifierStore.beginOperation(
            proofAttemptIdentifier(),
        );
        await expect(
            repeatingIdentifierStore.beginOperation(proofAttemptIdentifier()),
        ).rejects.toMatchObject({ code: 'EntropyFailure' });
        expect(randomnessInvocationCount).toBe(2);

        const checkpointStore = openStore();
        const identity = await checkpointStore.beginOperation(
            proofAttemptIdentifier(),
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
