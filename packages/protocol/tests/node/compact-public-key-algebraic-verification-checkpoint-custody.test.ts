import { foundationProfile } from '@sealed-lattice/types';
import { publicKeyShareProofFamilySchemaIdentifier } from '@sealed-lattice/wasm';
import { describe, expect, it } from 'vitest';

import {
    openAuthenticatedCheckpointStore,
    type AuthenticatedCheckpointStore,
    type AuthenticatedCheckpointStoreLimits,
    type CheckpointBoundaryPolicy,
} from '#packages/protocol/src/runtime/authenticated-checkpoint-store';
import { createAcceptedSetupCompactPublicKeyVerificationCheckpointBoundaryPolicy } from '#packages/protocol/src/runtime/compact-public-key-algebraic-verification-checkpoint-custody';
import {
    compactPublicKeyVerificationCheckpointStateStreamDomains,
    createEmptyCompactPublicKeyVerificationPrivateRandomnessCursorManifestBytes,
} from '#packages/protocol/src/runtime/compact-public-key-verification-checkpoint-contract';
import type { UntrustedStorageTransactionStore } from '#packages/protocol/src/runtime/untrusted-storage-transaction-store';
import {
    generateRuntimeStorageEncryptionKey,
    hashFilledWith,
    InMemoryRuntimeStorageAdapter,
    openRuntimeTestStore,
    runtimeAuthorityContext,
} from '#packages/protocol/tests/support/runtime-storage-test-support';
import { registerCommonProofKernelContext } from '#packages/wasm/src/transcript-core-bridge/common-proof-kernel-context';
import type { TranscriptCoreKernel } from '#packages/wasm/src/transcript-core-bridge/kernel-types';
import { createMockKernelRuntime } from '#packages/wasm/tests/node/common-proof-worker-runtime/kernel-fixtures';
import {
    openAcceptedSetupCompactPublicKeyVerificationCheckpointCustody,
    openCompactPublicKeyAlgebraicVerificationCheckpointCustody,
} from '@sealed-lattice/protocol';

const storageNamespace = 'compact-public-key-verifier-checkpoint-test';

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

const sourceDigests = (): readonly Uint8Array[] => [
    hashFilledWith(0x31),
    hashFilledWith(0x41),
    hashFilledWith(0x51),
    hashFilledWith(0x61),
];

const checkpointBytes = (
    seed: number,
    byteLength = 400,
): Uint8Array<ArrayBuffer> => {
    const bytes = new Uint8Array(byteLength);
    for (let byteIndex = 0; byteIndex < bytes.byteLength; byteIndex += 1) {
        bytes[byteIndex] =
            (seed + byteIndex * 113 + Math.floor(byteIndex / 7) * 29) & 0xff;
    }
    return bytes;
};

const createAcceptedCheckpointGeometryKernel = (
    checkpointByteLength = 404,
    safeBoundaryCount = 4_509,
): TranscriptCoreKernel => {
    const kernel = Object.freeze({}) as TranscriptCoreKernel;
    registerCommonProofKernelContext(
        kernel,
        createMockKernelRuntime(() => ({
            sealed_lattice_accepted_setup_compact_public_key_verification_checkpoint_byte_length:
                () => checkpointByteLength,
            sealed_lattice_accepted_setup_compact_public_key_verification_safe_boundary_count:
                () => safeBoundaryCount,
        })),
    );
    return kernel;
};

const openCheckpointStore = async (input?: {
    adapter?: InMemoryRuntimeStorageAdapter;
    encryptionKey?: CryptoKey;
    storageTransactionStore?: UntrustedStorageTransactionStore;
}): Promise<
    Readonly<{
        adapter: InMemoryRuntimeStorageAdapter;
        encryptionKey: CryptoKey;
        storageTransactionStore: UntrustedStorageTransactionStore;
        store: AuthenticatedCheckpointStore;
    }>
> => {
    const adapter = input?.adapter ?? new InMemoryRuntimeStorageAdapter();
    const encryptionKey =
        input?.encryptionKey ?? (await generateRuntimeStorageEncryptionKey());
    const storageTransactionStore =
        input?.storageTransactionStore ??
        (
            await openRuntimeTestStore({
                adapter,
                namespace: storageNamespace,
            })
        ).store;
    return {
        adapter,
        encryptionKey,
        store: openAuthenticatedCheckpointStore({
            authorityContext: runtimeAuthorityContext(),
            boundaryPolicy,
            encryptionKey,
            limits: checkpointLimits,
            store: storageTransactionStore,
        }),
        storageTransactionStore,
    };
};

describe('Compact public-key algebraic verification checkpoint custody', () => {
    it('publishes, cold reopens, restores once, and continues the same lineage', async () => {
        const firstStoreOpening = await openCheckpointStore();
        let activeStore = firstStoreOpening.store;
        try {
            const firstCheckpointBytes = checkpointBytes(0x17);
            const firstCheckpointBytesBeforePublication =
                firstCheckpointBytes.slice();
            const firstOpening =
                await openCompactPublicKeyAlgebraicVerificationCheckpointCustody(
                    activeStore,
                    { orderedSourceDigests: sourceDigests() },
                );
            const checkpointLineageIdentifier =
                firstOpening.checkpointLineageIdentifier.slice();
            await firstOpening.checkpointCustody.publishAuthenticatedCheckpoint(
                firstCheckpointBytes,
                0,
            );
            expect(firstCheckpointBytes).toEqual(
                firstCheckpointBytesBeforePublication,
            );
            await firstOpening.checkpointCustody.release();
            await firstOpening.checkpointCustody.release();
            await activeStore.close();

            const secondStoreOpening = await openCheckpointStore({
                adapter: firstStoreOpening.adapter,
                encryptionKey: firstStoreOpening.encryptionKey,
                storageTransactionStore:
                    firstStoreOpening.storageTransactionStore,
            });
            activeStore = secondStoreOpening.store;
            const resumedOpening =
                await openCompactPublicKeyAlgebraicVerificationCheckpointCustody(
                    activeStore,
                    {
                        orderedSourceDigests: sourceDigests(),
                        resume: {
                            checkpointLineageIdentifier,
                            safeBoundaryOrdinal: 0,
                        },
                    },
                );
            expect(resumedOpening.checkpointLineageIdentifier).toEqual(
                checkpointLineageIdentifier,
            );
            const restored =
                await resumedOpening.checkpointCustody.restoreAuthenticatedCheckpoint();
            expect(restored.safeBoundaryOrdinal).toBe(0);
            expect(restored.canonicalCheckpointBytes).toEqual(
                firstCheckpointBytesBeforePublication,
            );
            await expect(
                resumedOpening.checkpointCustody.restoreAuthenticatedCheckpoint(),
            ).rejects.toMatchObject({ code: 'InvalidState' });

            const replacementCheckpointBytes = checkpointBytes(0xa3);
            await resumedOpening.checkpointCustody.publishAuthenticatedCheckpoint(
                replacementCheckpointBytes,
                1,
            );
            await resumedOpening.checkpointCustody.release();

            const replacementOpening =
                await openCompactPublicKeyAlgebraicVerificationCheckpointCustody(
                    activeStore,
                    {
                        orderedSourceDigests: sourceDigests(),
                        resume: {
                            checkpointLineageIdentifier,
                            safeBoundaryOrdinal: 1,
                        },
                    },
                );
            const replacementRestoration =
                await replacementOpening.checkpointCustody.restoreAuthenticatedCheckpoint();
            expect(replacementRestoration.canonicalCheckpointBytes).toEqual(
                replacementCheckpointBytes,
            );
            await replacementOpening.checkpointCustody.release();
        } finally {
            await activeStore.close();
        }
    });

    it('retains the committed predecessor when replacement publication is interrupted', async () => {
        const { adapter, store } = await openCheckpointStore();
        try {
            const initialCheckpointBytes = checkpointBytes(0x24);
            const initialOpening =
                await openCompactPublicKeyAlgebraicVerificationCheckpointCustody(
                    store,
                    { orderedSourceDigests: sourceDigests() },
                );
            const checkpointLineageIdentifier =
                initialOpening.checkpointLineageIdentifier.slice();
            await initialOpening.checkpointCustody.publishAuthenticatedCheckpoint(
                initialCheckpointBytes,
                0,
            );

            adapter.failAtomicMutationAfter(3);
            await expect(
                initialOpening.checkpointCustody.publishAuthenticatedCheckpoint(
                    checkpointBytes(0x82),
                    1,
                ),
            ).rejects.toMatchObject({ code: 'StorageFailure' });
            await initialOpening.checkpointCustody.release();

            const resumedPredecessor =
                await openCompactPublicKeyAlgebraicVerificationCheckpointCustody(
                    store,
                    {
                        orderedSourceDigests: sourceDigests(),
                        resume: {
                            checkpointLineageIdentifier,
                            safeBoundaryOrdinal: 0,
                        },
                    },
                );
            const restoredPredecessor =
                await resumedPredecessor.checkpointCustody.restoreAuthenticatedCheckpoint();
            expect(restoredPredecessor.canonicalCheckpointBytes).toEqual(
                initialCheckpointBytes,
            );
            await resumedPredecessor.checkpointCustody.release();
            await expect(
                openCompactPublicKeyAlgebraicVerificationCheckpointCustody(
                    store,
                    {
                        orderedSourceDigests: sourceDigests(),
                        resume: {
                            checkpointLineageIdentifier,
                            safeBoundaryOrdinal: 1,
                        },
                    },
                ),
            ).rejects.toMatchObject({ code: 'AuthenticationFailed' });
        } finally {
            await store.close();
        }
    });

    it('fails closed on wrong context, malformed input, and deleted checkpoint objects', async () => {
        const { adapter, store } = await openCheckpointStore();
        try {
            const opening =
                await openCompactPublicKeyAlgebraicVerificationCheckpointCustody(
                    store,
                    { orderedSourceDigests: sourceDigests() },
                );
            const checkpointLineageIdentifier =
                opening.checkpointLineageIdentifier.slice();
            await expect(
                opening.checkpointCustody.publishAuthenticatedCheckpoint(
                    new Uint8Array(399),
                    0,
                ),
            ).rejects.toMatchObject({ code: 'InvalidInput' });
            await expect(
                opening.checkpointCustody.publishAuthenticatedCheckpoint(
                    checkpointBytes(0x33),
                    290,
                ),
            ).rejects.toMatchObject({ code: 'InvalidInput' });

            const canonicalCheckpointBytes = checkpointBytes(0x73);
            await opening.checkpointCustody.publishAuthenticatedCheckpoint(
                canonicalCheckpointBytes,
                0,
            );
            await opening.checkpointCustody.release();
            await expect(
                openCompactPublicKeyAlgebraicVerificationCheckpointCustody(
                    store,
                    {
                        orderedSourceDigests: [
                            hashFilledWith(0x99),
                            ...sourceDigests().slice(1),
                        ],
                        resume: {
                            checkpointLineageIdentifier,
                            safeBoundaryOrdinal: 0,
                        },
                    },
                ),
            ).rejects.toMatchObject({ code: 'AuthenticationFailed' });
            await expect(
                openCompactPublicKeyAlgebraicVerificationCheckpointCustody(
                    store,
                    {
                        orderedSourceDigests: sourceDigests(),
                        resume: {
                            checkpointLineageIdentifier,
                            safeBoundaryOrdinal: 1,
                        },
                    },
                ),
            ).rejects.toMatchObject({ code: 'AuthenticationFailed' });

            const storedObjectKey = adapter
                .keys()
                .filter((key) => key.includes('/objects/'))
                .map((key) => ({
                    byteLength: adapter.rawRead(key)?.byteLength ?? 0,
                    key,
                }))
                .sort(
                    (left, right) => right.byteLength - left.byteLength,
                )[0]?.key;
            if (storedObjectKey === undefined) {
                throw new Error('Checkpoint publication stored no object.');
            }
            adapter.rawDelete(storedObjectKey);
            let corruptionFailure: unknown;
            try {
                await (async () => {
                    const corruptOpening =
                        await openCompactPublicKeyAlgebraicVerificationCheckpointCustody(
                            store,
                            {
                                orderedSourceDigests: sourceDigests(),
                                resume: {
                                    checkpointLineageIdentifier,
                                    safeBoundaryOrdinal: 0,
                                },
                            },
                        );
                    try {
                        await corruptOpening.checkpointCustody.restoreAuthenticatedCheckpoint();
                    } finally {
                        await corruptOpening.checkpointCustody.release();
                    }
                })();
            } catch (error) {
                corruptionFailure = error;
            }
            expect(corruptionFailure).toBeInstanceOf(Error);
            if (
                !(corruptionFailure instanceof Error) ||
                !('code' in corruptionFailure)
            ) {
                throw new Error(
                    'Deleted checkpoint state did not return a typed failure.',
                );
            }
            expect(['AuthenticationFailed', 'MissingRecord']).toContain(
                corruptionFailure.code,
            );

            const replayOpening =
                await openCompactPublicKeyAlgebraicVerificationCheckpointCustody(
                    store,
                    { orderedSourceDigests: sourceDigests() },
                );
            expect(replayOpening.checkpointLineageIdentifier).not.toEqual(
                checkpointLineageIdentifier,
            );
            await replayOpening.checkpointCustody.publishAuthenticatedCheckpoint(
                canonicalCheckpointBytes,
                0,
            );
            await replayOpening.checkpointCustody.release();
        } finally {
            await store.close();
        }
    });

    it('releases identities after cancellation and refuses use after release', async () => {
        const { store } = await openCheckpointStore();
        try {
            const abortController = new AbortController();
            const abortingStore: AuthenticatedCheckpointStore = {
                ...store,
                beginOperation: async () => {
                    const identity = await store.beginOperation();
                    abortController.abort('cancel after identity issue');
                    return identity;
                },
            };
            await expect(
                openCompactPublicKeyAlgebraicVerificationCheckpointCustody(
                    abortingStore,
                    {
                        orderedSourceDigests: sourceDigests(),
                        signal: abortController.signal,
                    },
                ),
            ).rejects.toMatchObject({ code: 'InvalidState' });

            const opening =
                await openCompactPublicKeyAlgebraicVerificationCheckpointCustody(
                    store,
                    { orderedSourceDigests: sourceDigests() },
                );
            await opening.checkpointCustody.release();
            await opening.checkpointCustody.release();
            await expect(
                opening.checkpointCustody.publishAuthenticatedCheckpoint(
                    checkpointBytes(0x44),
                    0,
                ),
            ).rejects.toMatchObject({ code: 'InvalidState' });

            await expect(
                openCompactPublicKeyAlgebraicVerificationCheckpointCustody(
                    store,
                    { orderedSourceDigests: [new Uint8Array(63)] },
                ),
            ).rejects.toMatchObject({ code: 'InvalidInput' });
        } finally {
            await store.close();
        }
    });
});

describe('Accepted-setup compact public-key verification checkpoint custody', () => {
    it('accepts only the exact deterministic accepted-verifier boundary profile', async () => {
        const policy =
            createAcceptedSetupCompactPublicKeyVerificationCheckpointBoundaryPolicy(
                createAcceptedCheckpointGeometryKernel(),
            );
        const validBoundary = {
            operationKind: publicKeyShareProofFamilySchemaIdentifier,
            orderedSourceDigests: sourceDigests(),
            privateRandomCursorManifestBytes:
                createEmptyCompactPublicKeyVerificationPrivateRandomnessCursorManifestBytes(),
            safeBoundaryOrdinal: 4_508,
            stateStreamDomain:
                compactPublicKeyVerificationCheckpointStateStreamDomains.acceptedSetup,
        };

        await expect(
            Promise.resolve().then(() =>
                policy.validateResume({
                    checkpointLineageIdentifier: new Uint8Array(32),
                    expectedBoundary: validBoundary,
                }),
            ),
        ).resolves.toBeUndefined();

        for (const malformedBoundary of [
            {
                ...validBoundary,
                operationKind: publicKeyShareProofFamilySchemaIdentifier + 1,
            },
            {
                ...validBoundary,
                orderedSourceDigests: sourceDigests().slice(1),
            },
            {
                ...validBoundary,
                privateRandomCursorManifestBytes: Uint8Array.of(0),
            },
            {
                ...validBoundary,
                privateRandomnessStreamAttemptIdentifier: new Uint8Array(32),
            },
            { ...validBoundary, safeBoundaryOrdinal: 4_509 },
            { ...validBoundary, safeBoundaryOrdinal: -1 },
            { ...validBoundary, stateStreamDomain: 'wrong-domain' },
        ]) {
            await expect(
                Promise.resolve().then(() =>
                    policy.validateResume({
                        checkpointLineageIdentifier: new Uint8Array(32),
                        expectedBoundary: malformedBoundary,
                    }),
                ),
            ).rejects.toMatchObject({ code: 'InvalidInput' });
        }
    });

    it('derives accepted geometry from canonical kernel exports before opening custody', async () => {
        const { store } = await openCheckpointStore();
        try {
            await expect(
                openAcceptedSetupCompactPublicKeyVerificationCheckpointCustody(
                    store,
                    {
                        kernel: createAcceptedCheckpointGeometryKernel(403),
                        orderedSourceDigests: sourceDigests(),
                    },
                ),
            ).rejects.toThrow(/geometry disagrees/u);
            await expect(
                openAcceptedSetupCompactPublicKeyVerificationCheckpointCustody(
                    store,
                    {
                        kernel: createAcceptedCheckpointGeometryKernel(
                            404,
                            4_508,
                        ),
                        orderedSourceDigests: sourceDigests(),
                    },
                ),
            ).rejects.toThrow(/schedule disagrees/u);

            const opening =
                await openAcceptedSetupCompactPublicKeyVerificationCheckpointCustody(
                    store,
                    {
                        kernel: createAcceptedCheckpointGeometryKernel(),
                        orderedSourceDigests: sourceDigests(),
                    },
                );
            await opening.checkpointCustody.release();
        } finally {
            await store.close();
        }
    });

    it('cold restores the 404-byte source cursor under its separate authenticated profile', async () => {
        const firstStoreOpening = await openCheckpointStore();
        let activeStore = firstStoreOpening.store;
        const kernel = createAcceptedCheckpointGeometryKernel();
        try {
            const opening =
                await openAcceptedSetupCompactPublicKeyVerificationCheckpointCustody(
                    activeStore,
                    { kernel, orderedSourceDigests: sourceDigests() },
                );
            const checkpointLineageIdentifier =
                opening.checkpointLineageIdentifier.slice();
            const initialCheckpointBytes = checkpointBytes(0x29, 404);

            await expect(
                opening.checkpointCustody.publishAuthenticatedCheckpoint(
                    checkpointBytes(0x41, 403),
                    1,
                ),
            ).rejects.toMatchObject({ code: 'InvalidInput' });
            await expect(
                opening.checkpointCustody.publishAuthenticatedCheckpoint(
                    checkpointBytes(0x42, 405),
                    1,
                ),
            ).rejects.toMatchObject({ code: 'InvalidInput' });
            await expect(
                opening.checkpointCustody.publishAuthenticatedCheckpoint(
                    initialCheckpointBytes,
                    4_509,
                ),
            ).rejects.toMatchObject({ code: 'InvalidInput' });

            await opening.checkpointCustody.publishAuthenticatedCheckpoint(
                initialCheckpointBytes,
                1,
            );
            await opening.checkpointCustody.release();
            await activeStore.close();

            const secondStoreOpening = await openCheckpointStore({
                adapter: firstStoreOpening.adapter,
                encryptionKey: firstStoreOpening.encryptionKey,
                storageTransactionStore:
                    firstStoreOpening.storageTransactionStore,
            });
            activeStore = secondStoreOpening.store;

            const wrongProfileOpening =
                await openCompactPublicKeyAlgebraicVerificationCheckpointCustody(
                    activeStore,
                    {
                        orderedSourceDigests: sourceDigests(),
                        resume: {
                            checkpointLineageIdentifier,
                            safeBoundaryOrdinal: 1,
                        },
                    },
                );
            await expect(
                wrongProfileOpening.checkpointCustody.restoreAuthenticatedCheckpoint(),
            ).rejects.toMatchObject({ code: 'AuthenticationFailed' });
            await wrongProfileOpening.checkpointCustody.release();

            const resumedOpening =
                await openAcceptedSetupCompactPublicKeyVerificationCheckpointCustody(
                    activeStore,
                    {
                        kernel,
                        orderedSourceDigests: sourceDigests(),
                        resume: {
                            checkpointLineageIdentifier,
                            safeBoundaryOrdinal: 1,
                        },
                    },
                );
            const restoredCheckpoint =
                await resumedOpening.checkpointCustody.restoreAuthenticatedCheckpoint();
            expect(restoredCheckpoint).toEqual({
                canonicalCheckpointBytes: initialCheckpointBytes,
                safeBoundaryOrdinal: 1,
            });

            const terminalSourceCheckpointBytes = checkpointBytes(0xb7, 404);
            await resumedOpening.checkpointCustody.publishAuthenticatedCheckpoint(
                terminalSourceCheckpointBytes,
                4_508,
            );
            await resumedOpening.checkpointCustody.release();

            const terminalOpening =
                await openAcceptedSetupCompactPublicKeyVerificationCheckpointCustody(
                    activeStore,
                    {
                        kernel,
                        orderedSourceDigests: sourceDigests(),
                        resume: {
                            checkpointLineageIdentifier,
                            safeBoundaryOrdinal: 4_508,
                        },
                    },
                );
            await expect(
                terminalOpening.checkpointCustody.restoreAuthenticatedCheckpoint(),
            ).resolves.toEqual({
                canonicalCheckpointBytes: terminalSourceCheckpointBytes,
                safeBoundaryOrdinal: 4_508,
            });
            await terminalOpening.checkpointCustody.release();
        } finally {
            await activeStore.close();
        }
    });
});
