import { webcrypto } from 'node:crypto';

import {
    BrowserActionStorageCustodyError,
    type BrowserActionStorageWorkerKernel,
} from '@sealed-lattice/types';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';

import {
    openAuthenticatedCheckpointStore,
    type CheckpointBoundaryPolicy,
    type CheckpointOperationIdentity,
    type TransferableAuthenticatedCheckpointStore,
} from '#packages/protocol/src/runtime/authenticated-checkpoint-store';
import {
    deriveCommonProofAttemptLogicalRecordPrefix,
    openCommonProofBrowserCustody,
    type CommonProofBrowserCustody,
} from '#packages/protocol/src/runtime/common-proof-browser-custody';
import type {
    UntrustedStorageExclusiveCapacityReservation,
    UntrustedStorageTransactionStore,
} from '#packages/protocol/src/runtime/untrusted-storage-transaction-store';
import {
    commonProofStorageCapacityProfile,
    requireCommonProofStorageCapacity,
} from '#packages/protocol/src/runtime/web-lock-owned-untrusted-storage-transaction-store';
import {
    generateRuntimeStorageEncryptionKey,
    InMemoryRuntimeStorageAdapter,
    openRuntimeTestStore,
    runtimeAuthorityContext,
} from '#packages/protocol/tests/support/runtime-storage-test-support';
import {
    createWasmBrowserActionStorageWorkerKernel,
    loadFreshTranscriptCoreKernel,
    type CommonProofExternalMemoryOperation,
    type CommonProofExternalMemoryRequest,
    type TranscriptCoreKernel,
} from '#packages/wasm/src/index';

const cryptoProvider = webcrypto as unknown as Crypto;
const checkpointLimits = {
    maximumActiveOperationIdentityCount: 64,
    maximumCheckpointStateByteLength: 1_048_576,
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
const binding = Object.freeze({
    actionContextHash: new Uint8Array(64).fill(0x11),
    ceremonyContextHash: new Uint8Array(64).fill(0x22),
    participantId: new Uint8Array(64).fill(0x33),
    suiteId: new Uint8Array(64).fill(0x44),
});
const actionRandomnessCommitment = new Uint8Array(64).fill(0x55);
const runtimeBindingHash = new Uint8Array(64).fill(0x66);
const proofAttemptLineageIdentifier = new Uint8Array(32).fill(0x77);

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

const bytesFromHex = (encoded: string): Uint8Array<ArrayBuffer> => {
    const bytes = new Uint8Array(encoded.length / 2);
    for (let byteIndex = 0; byteIndex < bytes.byteLength; byteIndex += 1) {
        bytes[byteIndex] = Number.parseInt(
            encoded.slice(byteIndex * 2, byteIndex * 2 + 2),
            16,
        );
    }
    return bytes;
};

const request = (
    operations: readonly CommonProofExternalMemoryOperation[],
    requestSequence = 1n,
): CommonProofExternalMemoryRequest =>
    Object.freeze({
        maximumOperationCount: 4_096,
        maximumPayloadByteLength: 1_048_576n,
        operations: Object.freeze(operations),
        requestDigest: new Uint8Array(64).fill(0x88),
        requestSequence,
        runtimeBindingHash: runtimeBindingHash.slice(),
    });

const createOperation = (
    objectOrdinal: number,
    exactByteLength: bigint,
    protection:
        | 'public-integrity'
        | 'secret-authenticated-encryption' = 'secret-authenticated-encryption',
): CommonProofExternalMemoryOperation =>
    Object.freeze({
        exactByteLength,
        objectOrdinal,
        operationIndex: 0,
        operationKind: 'create',
        protection,
    });

const appendOperation = (
    objectOrdinal: number,
    bytes: Uint8Array,
    expectedOffset = 0n,
    operationIndex = 0,
): CommonProofExternalMemoryOperation =>
    Object.freeze({
        bytes,
        expectedOffset,
        objectOrdinal,
        operationIndex,
        operationKind: 'append',
    });

const canonicalAppendRequests = (
    objectOrdinal: number,
    bytes: Uint8Array,
    firstRequestSequence = 1n,
): readonly CommonProofExternalMemoryRequest[] => {
    const requests: CommonProofExternalMemoryRequest[] = [];
    let byteOffset = 0;
    while (byteOffset < bytes.byteLength) {
        const chunkByteLength = Math.min(49_152, bytes.byteLength - byteOffset);
        requests.push(
            request(
                [
                    appendOperation(
                        objectOrdinal,
                        bytes.slice(byteOffset, byteOffset + chunkByteLength),
                        BigInt(byteOffset),
                    ),
                ],
                firstRequestSequence + BigInt(requests.length),
            ),
        );
        byteOffset += chunkByteLength;
    }
    return Object.freeze(requests);
};

const sealOperation = (
    objectOrdinal: number,
    operationIndex = 0,
): CommonProofExternalMemoryOperation =>
    Object.freeze({
        objectOrdinal,
        operationIndex,
        operationKind: 'seal',
    });

const readOperation = (
    objectOrdinal: number,
    offset: bigint,
    byteLength: number,
    operationIndex = 0,
): CommonProofExternalMemoryOperation =>
    Object.freeze({
        byteLength,
        objectOrdinal,
        offset,
        operationIndex,
        operationKind: 'read',
    });

const deleteOperation = (
    objectOrdinal: number,
): CommonProofExternalMemoryOperation =>
    Object.freeze({
        objectOrdinal,
        operationIndex: 0,
        operationKind: 'delete',
    });

const ownedStorageRecordKeys = (
    adapter: InMemoryRuntimeStorageAdapter,
): readonly string[] =>
    adapter
        .keys()
        .filter(
            (key) => key.includes('/indices/') || key.includes('/objects/'),
        );

const containsSubsequence = (
    bytes: Uint8Array,
    sought: Uint8Array,
): boolean => {
    for (
        let offset = 0;
        offset + sought.byteLength <= bytes.byteLength;
        offset += 1
    ) {
        let equal = true;
        for (let index = 0; index < sought.byteLength; index += 1) {
            if (bytes[offset + index] !== sought[index]) {
                equal = false;
                break;
            }
        }
        if (equal) {
            return true;
        }
    }
    return false;
};

const ensureAuthenticatedRepairHead = async (
    store: UntrustedStorageTransactionStore,
): Promise<void> => {
    const logicalRecordKey = 'test/common-proof-capacity-head';
    const writeTransaction = await store.beginTransaction({
        lifetimeMilliseconds: 5_000,
    });
    try {
        const lease = await writeTransaction.issueWriteLease({
            declaredByteLength: 1,
            logicalRecordKey,
        });
        await lease.write(Uint8Array.of(1));
        await lease.seal(() => undefined);
        await writeTransaction.commit();
    } catch (error) {
        await writeTransaction.closeAfterFailure();
        throw error;
    }
    const deleteTransaction = await store.beginTransaction({
        lifetimeMilliseconds: 5_000,
    });
    try {
        await deleteTransaction.stageDeletion(logicalRecordKey);
        await deleteTransaction.commit();
    } catch (error) {
        await deleteTransaction.closeAfterFailure();
        throw error;
    }
};

describe('Common-proof browser custody', () => {
    let transcriptCoreKernel: TranscriptCoreKernel;
    const openedCustodies: CommonProofBrowserCustody[] = [];
    const openedCheckpointStores: TransferableAuthenticatedCheckpointStore[] =
        [];

    beforeAll(async () => {
        transcriptCoreKernel = await loadFreshTranscriptCoreKernel();
    });

    afterEach(async () => {
        await Promise.allSettled(
            openedCustodies.splice(0).map((custody) => custody.retire()),
        );
        await Promise.allSettled(
            openedCheckpointStores.splice(0).map((store) => store.close()),
        );
    });

    const openFixture = async (input?: {
        adapter?: InMemoryRuntimeStorageAdapter;
        decorateCapacityReservation?: (
            reservation: UntrustedStorageExclusiveCapacityReservation,
        ) => UntrustedStorageExclusiveCapacityReservation;
        checkpointStore?: TransferableAuthenticatedCheckpointStore;
        commonProofEnvironmentIdentifier?: Uint8Array;
        resumeDescriptor?: ReturnType<
            CommonProofBrowserCustody['copyCheckpointResumeDescriptor']
        >;
        store?: UntrustedStorageTransactionStore;
        workerKernel?: BrowserActionStorageWorkerKernel;
    }) => {
        const adapter = input?.adapter ?? new InMemoryRuntimeStorageAdapter();
        const store =
            input?.store ??
            (
                await openRuntimeTestStore({
                    adapter,
                    namespace: 'common-proof-browser-custody-test',
                })
            ).store;
        const workerKernel =
            input?.workerKernel ??
            createWasmBrowserActionStorageWorkerKernel({
                kernel: await loadFreshTranscriptCoreKernel(),
            });
        if (input?.workerKernel === undefined) {
            await workerKernel.createAndStageDeviceWrappingState({ binding });
            await workerKernel.commitStagedActionStorageRoot();
        }
        await ensureAuthenticatedRepairHead(store);
        const commonProofEnvironmentIdentifier =
            input?.commonProofEnvironmentIdentifier ??
            new Uint8Array(32).fill(0x99);
        const attemptLogicalRecordPrefix =
            deriveCommonProofAttemptLogicalRecordPrefix({
                commonProofEnvironmentIdentifier,
                commonProofRuntimeBindingHash: runtimeBindingHash,
                proofAttemptLineageIdentifier,
            });
        const capacityReservation = await store.reserveExclusiveCapacity({
            initialLogicalRecordKeyPrefixes: [attemptLogicalRecordPrefix],
            maximumAdditionalAuthenticatedRepairHeadPlaintextByteLength: 1_048_576,
            maximumAdditionalOwnedRecordCount: 200,
            maximumAdditionalStoredValueByteLength: 16_777_216,
            maximumDeletionBatchRecordCount: 8,
        });
        const ownedCapacityReservation =
            input?.decorateCapacityReservation?.(capacityReservation) ??
            capacityReservation;
        let freshCheckpointOperationIdentity:
            | CheckpointOperationIdentity
            | undefined;
        if (
            input?.checkpointStore !== undefined &&
            input.resumeDescriptor === undefined
        ) {
            const checkpointLineageReservation =
                await input.checkpointStore.reserveCheckpointLineage();
            try {
                freshCheckpointOperationIdentity =
                    await input.checkpointStore.bindCheckpointLineageToProofAttempt(
                        checkpointLineageReservation,
                        proofAttemptLineageIdentifier,
                    );
            } catch (error) {
                await input.checkpointStore.releaseCheckpointLineageReservation(
                    checkpointLineageReservation,
                );
                await ownedCapacityReservation.release();
                throw error;
            }
        }
        let custody: CommonProofBrowserCustody;
        try {
            custody = openCommonProofBrowserCustody({
                actionRandomnessCommitment,
                capacityReservation: ownedCapacityReservation,
                ...(input?.checkpointStore === undefined
                    ? {}
                    : {
                          checkpoint: {
                              ...(input.resumeDescriptor === undefined
                                  ? {
                                        operationIdentity:
                                            freshCheckpointOperationIdentity!,
                                    }
                                  : {
                                        resumeDescriptor:
                                            input.resumeDescriptor,
                                    }),
                              store: input.checkpointStore,
                          },
                      }),
                commonProofEnvironmentIdentifier,
                commonProofRuntimeBindingHash: runtimeBindingHash,
                limits: {
                    maximumExternalMemoryByteLength: 5_242_880n,
                    maximumExternalMemoryObjectCount: 32,
                    maximumExternalMemoryRecordCount: 512,
                    transactionLifetimeMilliseconds: 5_000,
                },
                proofAttemptLineageIdentifier,
                store,
                workerKernel,
            });
        } catch (error) {
            if (
                freshCheckpointOperationIdentity !== undefined &&
                input?.checkpointStore !== undefined
            ) {
                await input.checkpointStore.releaseOperationIdentity(
                    freshCheckpointOperationIdentity,
                );
            }
            await ownedCapacityReservation.release();
            throw error;
        }
        openedCustodies.push(custody);
        return { adapter, custody, store, workerKernel };
    };

    it('rejects hostile checkpoint manifest and attempt-identifier lengths before custody opens', async () => {
        const checkpointStorage = await openRuntimeTestStore({
            namespace: 'common-proof-hostile-checkpoint-descriptor-test',
        });
        const checkpointStore = openAuthenticatedCheckpointStore({
            authorityContext: runtimeAuthorityContext(),
            boundaryPolicy,
            cryptoProvider,
            encryptionKey: await generateRuntimeStorageEncryptionKey(),
            limits: checkpointLimits,
            store: checkpointStorage.store,
        });
        openedCheckpointStores.push(checkpointStore);
        const workerKernel = createWasmBrowserActionStorageWorkerKernel({
            kernel: await loadFreshTranscriptCoreKernel(),
        });
        await workerKernel.createAndStageDeviceWrappingState({ binding });
        await workerKernel.commitStagedActionStorageRoot();
        const descriptorBase = {
            checkpointLineageIdentifier: new Uint8Array(32).fill(0x12),
            commonProofEnvironmentIdentifier: new Uint8Array(32).fill(0x99),
            safeBoundaryOrdinal: 1,
            stableAttemptBindingHash: new Uint8Array(64).fill(0x34),
        } as const;

        await expect(
            openFixture({
                checkpointStore,
                resumeDescriptor: {
                    ...descriptorBase,
                    privateRandomCursorManifestBytes: new Uint8Array(
                        1_048_577,
                    ),
                },
                workerKernel,
            }),
        ).rejects.toMatchObject({ code: 'InvalidInput' });

        const malformedAttemptIdentifier = new Uint8Array(31).fill(0x56);
        await expect(
            openFixture({
                checkpointStore,
                resumeDescriptor: {
                    ...descriptorBase,
                    privateRandomCursorManifestBytes: new Uint8Array(),
                    privateRandomnessStreamAttemptIdentifier:
                        malformedAttemptIdentifier,
                },
                workerKernel,
            }),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
        expect(malformedAttemptIdentifier[0]).toBe(0x56);
    });

    it('persists encrypted and public objects through create, append, seal, ordered read, and delete', async () => {
        const { adapter, custody } = await openFixture();
        const secretBytes = Uint8Array.from(
            { length: 130_117 },
            (_unused, index) => (index * 29 + 7) & 0xff,
        );
        const publicBytes = Uint8Array.from(
            { length: 72_331 },
            (_unused, index) => (index * 17 + 3) & 0xff,
        );

        await custody.externalMemory.executeTransaction(
            request([createOperation(4, BigInt(secretBytes.byteLength))]),
        );
        for (const appendRequest of canonicalAppendRequests(4, secretBytes)) {
            await custody.externalMemory.executeTransaction(appendRequest);
        }
        await custody.externalMemory.executeTransaction(
            request([sealOperation(4)]),
        );
        await custody.externalMemory.executeTransaction(
            request([
                createOperation(
                    9,
                    BigInt(publicBytes.byteLength),
                    'public-integrity',
                ),
            ]),
        );
        for (const appendRequest of canonicalAppendRequests(9, publicBytes)) {
            await custody.externalMemory.executeTransaction(appendRequest);
        }
        await custody.externalMemory.executeTransaction(
            request([sealOperation(9)]),
        );
        const reads = [
            ...(await custody.externalMemory.executeTransaction(
                request([readOperation(9, 11_003n, 39_777, 0)]),
            )),
            ...(await custody.externalMemory.executeTransaction(
                request([readOperation(4, 49_001n, 70_003, 1)]),
            )),
        ];
        expect(reads).toHaveLength(2);
        expect(reads[0]).toMatchObject({
            objectOrdinal: 9,
            offset: 11_003n,
            operationIndex: 0,
        });
        expect(reads[0]?.bytes).toEqual(publicBytes.slice(11_003, 50_780));
        expect(reads[1]).toMatchObject({
            objectOrdinal: 4,
            offset: 49_001n,
            operationIndex: 1,
        });
        expect(reads[1]?.bytes).toEqual(secretBytes.slice(49_001, 119_004));

        const storedValues = adapter
            .keys()
            .map((key) => adapter.rawRead(key))
            .filter((value): value is Uint8Array => value !== undefined);
        expect(
            storedValues.some((value) =>
                containsSubsequence(value, secretBytes.subarray(0, 96)),
            ),
        ).toBe(false);

        await custody.externalMemory.executeTransaction(
            request([deleteOperation(4)]),
        );
        await custody.externalMemory.executeTransaction(
            request([deleteOperation(9)]),
        );
        expect(ownedStorageRecordKeys(adapter)).toEqual([]);
    });

    it('rejects append-after-seal, cross-object aliases, and mutated committed records', async () => {
        const { adapter, custody } = await openFixture();
        const bytes = new Uint8Array(80_000).fill(0xa5);
        const secondObjectBytes = new Uint8Array(80_000).fill(0x5a);
        await custody.externalMemory.executeTransaction(
            request([createOperation(12, BigInt(bytes.byteLength))]),
        );
        for (const appendRequest of canonicalAppendRequests(12, bytes)) {
            await custody.externalMemory.executeTransaction(appendRequest);
        }
        await custody.externalMemory.executeTransaction(
            request([sealOperation(12)]),
        );
        await custody.externalMemory.executeTransaction(
            request([
                createOperation(13, BigInt(secondObjectBytes.byteLength)),
            ]),
        );
        for (const appendRequest of canonicalAppendRequests(
            13,
            secondObjectBytes,
        )) {
            await custody.externalMemory.executeTransaction(appendRequest);
        }
        await custody.externalMemory.executeTransaction(
            request([sealOperation(13)]),
        );

        await expect(
            custody.externalMemory.executeTransaction(
                request([appendOperation(12, Uint8Array.of(1), 80_000n)]),
            ),
        ).rejects.toMatchObject({ code: 'InvalidState' });
        await expect(
            custody.externalMemory.executeTransaction(
                request([createOperation(12, 1n)]),
            ),
        ).rejects.toMatchObject({ code: 'InvalidState' });

        const dataObjectRecords = ownedStorageRecordKeys(adapter)
            .filter((key) => key.includes('/objects/'))
            .map((key) => ({ key, value: adapter.rawRead(key) }))
            .filter(
                (
                    record,
                ): record is Readonly<{
                    key: string;
                    value: Uint8Array;
                }> =>
                    record.value !== undefined &&
                    record.value.byteLength > 49_000,
            );
        const firstRecord = dataObjectRecords[0];
        const secondRecord = dataObjectRecords[1];
        if (firstRecord === undefined || secondRecord === undefined) {
            throw new Error(
                'Expected two large committed common-proof data records.',
            );
        }
        adapter.rawWrite(firstRecord.key, secondRecord.value);
        adapter.rawWrite(secondRecord.key, firstRecord.value);

        await expect(
            custody.externalMemory.executeTransaction(
                request([readOperation(12, 0n, 32)]),
            ),
        ).rejects.toBeInstanceOf(Error);
    });

    it('rejects mixed transaction grammar without changing quota counters', async () => {
        const { adapter, custody } = await openFixture();
        const bytes = new Uint8Array(257).fill(0x3d);
        const recordsBefore = ownedStorageRecordKeys(adapter);

        await expect(
            custody.externalMemory.executeTransaction(
                request([
                    createOperation(21, BigInt(bytes.byteLength)),
                    appendOperation(21, bytes, 1n, 1),
                ]),
            ),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
        expect(ownedStorageRecordKeys(adapter)).toEqual(recordsBefore);

        await custody.externalMemory.executeTransaction(
            request([createOperation(21, BigInt(bytes.byteLength))]),
        );
        for (const appendRequest of canonicalAppendRequests(21, bytes)) {
            await custody.externalMemory.executeTransaction(appendRequest);
        }
        await custody.externalMemory.executeTransaction(
            request([sealOperation(21)]),
        );
        await expect(
            custody.externalMemory.executeTransaction(
                request([readOperation(21, 0n, bytes.byteLength, 3)]),
            ),
        ).resolves.toEqual([
            expect.objectContaining({
                bytes,
                objectOrdinal: 21,
                operationIndex: 3,
            }),
        ]);
    });

    it('enforces custody quotas and removes partial writes after storage failure and retirement', async () => {
        const adapter = new InMemoryRuntimeStorageAdapter();
        const { custody } = await openFixture({ adapter });
        adapter.failAtomicMutationAfter(1);
        await expect(
            custody.externalMemory.executeTransaction(
                request([createOperation(1, 128n)]),
            ),
        ).rejects.toBeInstanceOf(Error);
        await custody.retire();
        openedCustodies.splice(openedCustodies.indexOf(custody), 1);
        expect(ownedStorageRecordKeys(adapter)).toEqual([]);

        const quotaFixture = await openFixture({
            commonProofEnvironmentIdentifier: new Uint8Array(32).fill(0xaa),
        });
        await expect(
            quotaFixture.custody.externalMemory.executeTransaction(
                request([createOperation(2, 5_242_881n)]),
            ),
        ).rejects.toMatchObject({ code: 'InvalidState' });
    });

    it('holds exclusive live capacity until terminal retirement', async () => {
        const { custody, store } = await openFixture();
        const competingTransaction = await store.beginTransaction({
            lifetimeMilliseconds: 5_000,
        });
        await expect(
            competingTransaction.issueWriteLease({
                declaredByteLength: 1,
                logicalRecordKey: 'foundation/competing-write',
            }),
        ).rejects.toMatchObject({ code: 'Conflict' });
        await competingTransaction.closeAfterFailure();

        await custody.retire();
        openedCustodies.splice(openedCustodies.indexOf(custody), 1);
        const releasedTransaction = await store.beginTransaction({
            lifetimeMilliseconds: 5_000,
        });
        const lease = await releasedTransaction.issueWriteLease({
            declaredByteLength: 1,
            logicalRecordKey: 'foundation/released-write',
        });
        await lease.write(Uint8Array.of(1));
        await lease.seal(() => undefined);
        await releasedTransaction.commit();
    });

    it('retires after an interrupted bounded delete series and removes its remaining prefix', async () => {
        const adapter = new InMemoryRuntimeStorageAdapter();
        const openedStore = await openRuntimeTestStore({
            adapter,
            limits: {
                maximumLeaseCountPerTransaction: 64,
                maximumOwnedRecordCount: 512,
            },
            namespace: 'common-proof-browser-custody-test',
        });
        const { custody } = await openFixture({
            adapter,
            store: openedStore.store,
        });
        const objectOrdinals = Array.from(
            { length: 22 },
            (_unused, objectIndex) => objectIndex + 1,
        );
        for (const objectOrdinal of objectOrdinals) {
            await custody.externalMemory.executeTransaction(
                request([createOperation(objectOrdinal, 1n)]),
            );
            await custody.externalMemory.executeTransaction(
                request([
                    appendOperation(
                        objectOrdinal,
                        Uint8Array.of(objectOrdinal),
                    ),
                ]),
            );
            await custody.externalMemory.executeTransaction(
                request([sealOperation(objectOrdinal)]),
            );
        }
        adapter.failAtomicMutationAfter(2);
        await expect(
            custody.externalMemory.executeTransaction(
                request(objectOrdinals.map(deleteOperation)),
            ),
        ).rejects.toBeInstanceOf(Error);
        await expect(
            custody.externalMemory.executeTransaction(
                request([readOperation(1, 0n, 1)]),
            ),
        ).rejects.toMatchObject({ code: 'InvalidState' });
        await custody.retire();
        openedCustodies.splice(openedCustodies.indexOf(custody), 1);
        expect(ownedStorageRecordKeys(adapter)).toEqual([]);
    });

    it('publishes and restores authenticated checkpoints before byte-identical copy-on-write replay', async () => {
        const adapter = new InMemoryRuntimeStorageAdapter();
        const openedStore = await openRuntimeTestStore({
            adapter,
            namespace: 'common-proof-browser-custody-test',
        });
        const checkpointStorage = await openRuntimeTestStore({
            namespace: 'common-proof-browser-checkpoint-test',
        });
        const encryptionKey = await generateRuntimeStorageEncryptionKey();
        const checkpointStore = openAuthenticatedCheckpointStore({
            authorityContext: runtimeAuthorityContext(),
            boundaryPolicy,
            cryptoProvider,
            encryptionKey,
            limits: checkpointLimits,
            store: checkpointStorage.store,
        });
        openedCheckpointStores.push(checkpointStore);
        const first = await openFixture({
            adapter,
            checkpointStore,
            store: openedStore.store,
        });
        const replayBytes = Uint8Array.from(
            { length: 100_003 },
            (_unused, index) => (index * 13 + 17) & 0xff,
        );
        const replayRequests = [
            request([createOperation(8, BigInt(replayBytes.byteLength))], 1n),
            ...canonicalAppendRequests(8, replayBytes, 2n),
            request([sealOperation(8)], 5n),
        ] as const;
        for (const replayRequest of replayRequests) {
            await first.custody.externalMemory.executeTransaction(
                replayRequest,
            );
        }
        const committedPrefixRecordBytes = ownedStorageRecordKeys(adapter)
            .filter((key) => key.includes('/objects/'))
            .map((key) => adapter.rawRead(key))
            .filter((value): value is Uint8Array => value !== undefined);
        const cursorBytes = bytesFromHex(
            transcriptCoreKernel.encodePrivateRandomCursor({
                derivationContextHash: 'ab'.repeat(64),
                family: 0x0200,
                nextCounter: '37',
                purpose: 2,
                streamAttemptIdentifierHex: 'cd'.repeat(32),
            }).canonicalBytesHex,
        );
        const checkpointState = Uint8Array.from(
            { length: 733 },
            (_unused, index) => (index * 41 + 9) & 0xff,
        );
        await first.custody.checkpointCustody?.publishAuthenticatedCheckpoint({
            canonicalStateBytes: checkpointState,
            privateRandomCursorManifestBytes: cursorBytes,
            privateRandomnessStreamAttemptIdentifier:
                proofAttemptLineageIdentifier.slice(),
            safeBoundaryOrdinal: 6,
            stableAttemptBindingHash: new Uint8Array(64).fill(0x31),
        });
        const resumeDescriptor = first.custody.copyCheckpointResumeDescriptor();
        expect(resumeDescriptor).toBeDefined();
        if (resumeDescriptor === undefined) {
            throw new Error('Expected an authenticated checkpoint descriptor.');
        }
        await first.custody.suspendForAuthenticatedResume();

        await expect(
            openFixture({
                adapter,
                checkpointStore,
                commonProofEnvironmentIdentifier: new Uint8Array(32).fill(0xbb),
                resumeDescriptor,
                store: openedStore.store,
                workerKernel: first.workerKernel,
            }),
        ).rejects.toMatchObject({ code: 'RecordAuthenticationFailed' });

        const resumed = await openFixture({
            adapter,
            checkpointStore,
            resumeDescriptor,
            store: openedStore.store,
            workerKernel: first.workerKernel,
        });
        await expect(
            resumed.custody.checkpointCustody?.restoreAuthenticatedCheckpointState(),
        ).resolves.toEqual(checkpointState);

        for (const replayRequest of replayRequests) {
            await resumed.custody.prefixReplayExternalMemory.executeDeterministicPrefixReplayTransaction(
                replayRequest,
            );
        }
        const replayRead =
            await resumed.custody.prefixReplayExternalMemory.executeDeterministicPrefixReplayTransaction(
                request([readOperation(8, 27_000n, 61_111)]),
            );
        expect(replayRead[0]?.bytes).toEqual(replayBytes.slice(27_000, 88_111));
        const recordsAfterReplay = ownedStorageRecordKeys(adapter)
            .filter((key) => key.includes('/objects/'))
            .map((key) => adapter.rawRead(key))
            .filter((value): value is Uint8Array => value !== undefined);
        for (const committedRecord of committedPrefixRecordBytes) {
            expect(
                recordsAfterReplay.some(
                    (record) =>
                        record.byteLength === committedRecord.byteLength &&
                        record.every(
                            (byte, byteIndex) =>
                                byte === committedRecord[byteIndex],
                        ),
                ),
            ).toBe(true);
        }
        await resumed.custody.suspendForAuthenticatedResume();

        const changedReplay = await openFixture({
            adapter,
            checkpointStore,
            resumeDescriptor,
            store: openedStore.store,
            workerKernel: first.workerKernel,
        });
        await changedReplay.custody.checkpointCustody?.restoreAuthenticatedCheckpointState();
        await changedReplay.custody.prefixReplayExternalMemory.executeDeterministicPrefixReplayTransaction(
            replayRequests[0],
        );
        const changedBytes = replayBytes.slice();
        changedBytes[changedBytes.byteLength - 1] ^= 1;
        const changedAppendRequests = canonicalAppendRequests(
            8,
            changedBytes,
            2n,
        );
        for (const unchangedRequest of changedAppendRequests.slice(0, -1)) {
            await changedReplay.custody.prefixReplayExternalMemory.executeDeterministicPrefixReplayTransaction(
                unchangedRequest,
            );
        }
        const changedFinalAppendRequest =
            changedAppendRequests[changedAppendRequests.length - 1];
        if (changedFinalAppendRequest === undefined) {
            throw new Error('Expected a changed canonical append request.');
        }
        await expect(
            changedReplay.custody.prefixReplayExternalMemory.executeDeterministicPrefixReplayTransaction(
                changedFinalAppendRequest,
            ),
        ).rejects.toMatchObject({ code: 'RecordAuthenticationFailed' });
    });

    it('retires cleanly when authenticated checkpoint custody is missing or corrupt', async () => {
        const adapter = new InMemoryRuntimeStorageAdapter();
        const openedStore = await openRuntimeTestStore({
            adapter,
            namespace: 'common-proof-browser-custody-test',
        });
        const checkpointAdapter = new InMemoryRuntimeStorageAdapter();
        const checkpointStorage = await openRuntimeTestStore({
            adapter: checkpointAdapter,
            namespace: 'common-proof-browser-checkpoint-test',
        });
        const checkpointStore = openAuthenticatedCheckpointStore({
            authorityContext: runtimeAuthorityContext(),
            boundaryPolicy,
            cryptoProvider,
            encryptionKey: await generateRuntimeStorageEncryptionKey(),
            limits: checkpointLimits,
            store: checkpointStorage.store,
        });
        openedCheckpointStores.push(checkpointStore);
        const first = await openFixture({
            adapter,
            checkpointStore,
            store: openedStore.store,
        });
        await first.custody.checkpointCustody?.publishAuthenticatedCheckpoint({
            canonicalStateBytes: new Uint8Array(64).fill(0x17),
            privateRandomCursorManifestBytes:
                emptyPrivateRandomCursorManifest(),
            privateRandomnessStreamAttemptIdentifier:
                proofAttemptLineageIdentifier.slice(),
            safeBoundaryOrdinal: 2,
            stableAttemptBindingHash: new Uint8Array(64).fill(0x29),
        });
        const resumeDescriptor = first.custody.copyCheckpointResumeDescriptor();
        if (resumeDescriptor === undefined) {
            throw new Error('Expected a checkpoint descriptor.');
        }
        const scratchBytes = new Uint8Array(70_003).fill(0x3b);
        await first.custody.externalMemory.executeTransaction(
            request([createOperation(17, BigInt(scratchBytes.byteLength))]),
        );
        for (const appendRequest of canonicalAppendRequests(17, scratchBytes)) {
            await first.custody.externalMemory.executeTransaction(
                appendRequest,
            );
        }
        await first.custody.externalMemory.executeTransaction(
            request([sealOperation(17)]),
        );
        await first.custody.outputStore.commitChunk(
            0,
            new Uint8Array(8_193).fill(0x4c),
        );
        expect(ownedStorageRecordKeys(adapter).length).toBeGreaterThan(0);
        await first.custody.suspendForAuthenticatedResume();

        const objectKey = ownedStorageRecordKeys(checkpointAdapter).find(
            (key) => key.includes('/objects/'),
        );
        if (objectKey === undefined) {
            throw new Error('Expected checkpoint storage bytes.');
        }
        checkpointAdapter.rawDelete(objectKey);
        const resumed = await openFixture({
            adapter,
            checkpointStore,
            resumeDescriptor,
            store: openedStore.store,
            workerKernel: first.workerKernel,
        });
        await expect(
            resumed.custody.checkpointCustody?.restoreAuthenticatedCheckpointState(),
        ).rejects.toMatchObject({ code: 'StorageFailure' });
        expect(ownedStorageRecordKeys(adapter)).toEqual([]);
        await expect(
            resumed.custody.externalMemory.executeTransaction(
                request([createOperation(1, 1n)]),
            ),
        ).rejects.toMatchObject({ code: 'InvalidState' });
    });

    it('recovers a byte-identical output chunk committed before kernel acknowledgement', async () => {
        const adapter = new InMemoryRuntimeStorageAdapter();
        const openedStore = await openRuntimeTestStore({
            adapter,
            namespace: 'common-proof-browser-custody-test',
        });
        const checkpointStorage = await openRuntimeTestStore({
            namespace: 'common-proof-browser-checkpoint-test',
        });
        const checkpointStore = openAuthenticatedCheckpointStore({
            authorityContext: runtimeAuthorityContext(),
            boundaryPolicy,
            cryptoProvider,
            encryptionKey: await generateRuntimeStorageEncryptionKey(),
            limits: checkpointLimits,
            store: checkpointStorage.store,
        });
        openedCheckpointStores.push(checkpointStore);
        const first = await openFixture({
            adapter,
            checkpointStore,
            store: openedStore.store,
        });
        await first.custody.checkpointCustody?.publishAuthenticatedCheckpoint({
            canonicalStateBytes: new Uint8Array(128).fill(0x41),
            privateRandomCursorManifestBytes:
                emptyPrivateRandomCursorManifest(),
            privateRandomnessStreamAttemptIdentifier:
                proofAttemptLineageIdentifier.slice(),
            safeBoundaryOrdinal: 3,
            stableAttemptBindingHash: new Uint8Array(64).fill(0x52),
        });
        const resumeDescriptor = first.custody.copyCheckpointResumeDescriptor();
        if (resumeDescriptor === undefined) {
            throw new Error('Expected an output-recovery checkpoint.');
        }
        const committedChunk = new Uint8Array(8_193).fill(0x63);
        await first.custody.outputStore.commitChunk(0, committedChunk);
        await first.custody.suspendForAuthenticatedResume();

        const resumed = await openFixture({
            adapter,
            checkpointStore,
            resumeDescriptor,
            store: openedStore.store,
            workerKernel: first.workerKernel,
        });
        await resumed.custody.checkpointCustody?.restoreAuthenticatedCheckpointState();
        await resumed.custody.outputStore.commitChunk(0, committedChunk);
        resumed.custody.sealCanonicalOutput();
        await expect(
            resumed.custody
                .authenticatedOutput()
                .readCommittedChunk(0, committedChunk.byteLength),
        ).resolves.toEqual(committedChunk);
        await resumed.custody.suspendForAuthenticatedResume();

        const changedResume = await openFixture({
            adapter,
            checkpointStore,
            resumeDescriptor,
            store: openedStore.store,
            workerKernel: first.workerKernel,
        });
        await changedResume.custody.checkpointCustody?.restoreAuthenticatedCheckpointState();
        const changedChunk = committedChunk.slice();
        changedChunk[0] ^= 1;
        await expect(
            changedResume.custody.outputStore.commitChunk(0, changedChunk),
        ).rejects.toMatchObject({ code: 'RecordAuthenticationFailed' });
        await expect(
            changedResume.custody.externalMemory.executeTransaction(
                request([createOperation(1, 1n)]),
            ),
        ).rejects.toMatchObject({ code: 'InvalidState' });
    });

    it('seals canonical output only after exact commit/readback and deletes it on retirement', async () => {
        const { adapter, custody } = await openFixture();
        const firstChunk = new Uint8Array(1_048_576).fill(0x3a);
        const secondChunk = new Uint8Array(731).fill(0x7c);
        await custody.outputStore.commitChunk(0, firstChunk);
        await custody.outputStore.commitChunk(1, secondChunk);
        await expect(custody.outputStore.readChunk(1, 731)).resolves.toEqual(
            secondChunk,
        );
        await expect(
            custody.outputStore.commitChunk(2, Uint8Array.of(1)),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
        custody.sealCanonicalOutput();
        const authenticatedOutput = custody.authenticatedOutput();
        expect(authenticatedOutput.declaredByteLength).toBe(1_049_307);
        await expect(
            authenticatedOutput.readCommittedChunk(0, 1_048_576),
        ).resolves.toEqual(firstChunk);
        await custody.retire();
        openedCustodies.splice(openedCustodies.indexOf(custody), 1);
        expect(ownedStorageRecordKeys(adapter)).toEqual([]);
    });

    it('deletes verified output records before releasing successful capacity', async () => {
        const { adapter, custody, store } = await openFixture();
        await custody.outputStore.commitChunk(
            0,
            new Uint8Array(8_193).fill(0x4d),
        );
        custody.sealCanonicalOutput();
        expect(ownedStorageRecordKeys(adapter).length).toBeGreaterThan(0);

        await custody.completeVerifiedOutput();
        openedCustodies.splice(openedCustodies.indexOf(custody), 1);
        expect(ownedStorageRecordKeys(adapter)).toEqual([]);

        const releasedTransaction = await store.beginTransaction({
            lifetimeMilliseconds: 5_000,
        });
        const releasedLease = await releasedTransaction.issueWriteLease({
            declaredByteLength: 1,
            logicalRecordKey: 'foundation/verified-output-cleanup-released',
        });
        await releasedLease.write(Uint8Array.of(1));
        await releasedLease.seal(() => undefined);
        await releasedTransaction.commit();
    });

    it('retries only unfinished record deletion and capacity-release steps', async () => {
        let deleteAttemptCount = 0;
        let releaseAttemptCount = 0;
        const { adapter, custody, store } = await openFixture({
            decorateCapacityReservation: (reservation) =>
                Object.freeze({
                    copyAuthenticatedLogicalRecordKeys: (prefix) =>
                        reservation.copyAuthenticatedLogicalRecordKeys(prefix),
                    deleteAuthenticatedLogicalRecords: async (prefix) => {
                        deleteAttemptCount += 1;
                        if (deleteAttemptCount === 1) {
                            throw new Error(
                                'Injected terminal record-deletion failure.',
                            );
                        }
                        return reservation.deleteAuthenticatedLogicalRecords(
                            prefix,
                        );
                    },
                    release: async () => {
                        releaseAttemptCount += 1;
                        if (releaseAttemptCount === 1) {
                            throw new Error(
                                'Injected terminal capacity-release failure.',
                            );
                        }
                        await reservation.release();
                    },
                }),
        });
        await custody.outputStore.commitChunk(
            0,
            new Uint8Array(7_111).fill(0x5e),
        );
        custody.sealCanonicalOutput();

        await expect(custody.completeVerifiedOutput()).rejects.toMatchObject({
            code: 'StorageFailure',
        });
        expect(deleteAttemptCount).toBe(1);
        expect(releaseAttemptCount).toBe(0);
        expect(ownedStorageRecordKeys(adapter).length).toBeGreaterThan(0);

        await expect(custody.retire()).rejects.toMatchObject({
            code: 'StorageFailure',
        });
        expect(deleteAttemptCount).toBe(2);
        expect(releaseAttemptCount).toBe(1);
        expect(ownedStorageRecordKeys(adapter)).toEqual([]);

        await expect(custody.retire()).resolves.toBeUndefined();
        openedCustodies.splice(openedCustodies.indexOf(custody), 1);
        expect(deleteAttemptCount).toBe(2);
        expect(releaseAttemptCount).toBe(2);

        const releasedTransaction = await store.beginTransaction({
            lifetimeMilliseconds: 5_000,
        });
        const releasedLease = await releasedTransaction.issueWriteLease({
            declaredByteLength: 1,
            logicalRecordKey: 'foundation/retried-proof-cleanup-released',
        });
        await releasedLease.write(Uint8Array.of(1));
        await releasedLease.seal(() => undefined);
        await releasedTransaction.commit();
    });

    it('retries checkpoint eviction and identity release without repeating completed proof cleanup', async () => {
        const checkpointAdapter = new InMemoryRuntimeStorageAdapter();
        const checkpointStorage = await openRuntimeTestStore({
            adapter: checkpointAdapter,
            namespace: 'common-proof-completion-checkpoint-retry-test',
        });
        const checkpointStore = openAuthenticatedCheckpointStore({
            authorityContext: runtimeAuthorityContext(),
            boundaryPolicy,
            cryptoProvider,
            encryptionKey: await generateRuntimeStorageEncryptionKey(),
            limits: checkpointLimits,
            store: checkpointStorage.store,
        });
        openedCheckpointStores.push(checkpointStore);
        let checkpointEvictionAttemptCount = 0;
        let checkpointIdentityReleaseAttemptCount = 0;
        const retryingCheckpointStore: TransferableAuthenticatedCheckpointStore =
            Object.freeze({
                ...checkpointStore,
                evict: async (checkpointLineageIdentifier) => {
                    checkpointEvictionAttemptCount += 1;
                    if (checkpointEvictionAttemptCount === 1) {
                        throw new Error(
                            'Injected terminal checkpoint-eviction failure.',
                        );
                    }
                    await checkpointStore.evict(checkpointLineageIdentifier);
                },
                releaseOperationIdentity: async (identity) => {
                    checkpointIdentityReleaseAttemptCount += 1;
                    if (checkpointIdentityReleaseAttemptCount === 1) {
                        throw new Error(
                            'Injected terminal checkpoint-identity release failure.',
                        );
                    }
                    await checkpointStore.releaseOperationIdentity(identity);
                },
            });
        let deleteAttemptCount = 0;
        let releaseAttemptCount = 0;
        const { adapter, custody } = await openFixture({
            checkpointStore: retryingCheckpointStore,
            decorateCapacityReservation: (reservation) =>
                Object.freeze({
                    copyAuthenticatedLogicalRecordKeys: (prefix) =>
                        reservation.copyAuthenticatedLogicalRecordKeys(prefix),
                    deleteAuthenticatedLogicalRecords: async (prefix) => {
                        deleteAttemptCount += 1;
                        return reservation.deleteAuthenticatedLogicalRecords(
                            prefix,
                        );
                    },
                    release: async () => {
                        releaseAttemptCount += 1;
                        await reservation.release();
                    },
                }),
        });
        await custody.checkpointCustody?.publishAuthenticatedCheckpoint({
            canonicalStateBytes: new Uint8Array(97).fill(0x61),
            privateRandomCursorManifestBytes:
                emptyPrivateRandomCursorManifest(),
            privateRandomnessStreamAttemptIdentifier:
                proofAttemptLineageIdentifier.slice(),
            safeBoundaryOrdinal: 4,
            stableAttemptBindingHash: new Uint8Array(64).fill(0x72),
        });
        await custody.outputStore.commitChunk(
            0,
            new Uint8Array(5_333).fill(0x83),
        );
        custody.sealCanonicalOutput();

        await expect(custody.completeVerifiedOutput()).rejects.toMatchObject({
            code: 'StorageFailure',
        });
        expect(checkpointEvictionAttemptCount).toBe(1);
        expect(checkpointIdentityReleaseAttemptCount).toBe(0);
        expect(deleteAttemptCount).toBe(1);
        expect(releaseAttemptCount).toBe(1);
        expect(ownedStorageRecordKeys(adapter)).toEqual([]);

        await expect(custody.retire()).rejects.toMatchObject({
            code: 'StorageFailure',
        });
        expect(checkpointEvictionAttemptCount).toBe(2);
        expect(checkpointIdentityReleaseAttemptCount).toBe(1);
        expect(deleteAttemptCount).toBe(1);
        expect(releaseAttemptCount).toBe(1);

        await expect(custody.retire()).resolves.toBeUndefined();
        openedCustodies.splice(openedCustodies.indexOf(custody), 1);
        expect(checkpointEvictionAttemptCount).toBe(3);
        expect(checkpointIdentityReleaseAttemptCount).toBe(2);
        expect(deleteAttemptCount).toBe(1);
        expect(releaseAttemptCount).toBe(1);
        expect(ownedStorageRecordKeys(checkpointAdapter)).toEqual([]);
    });

    it('enforces canonical output chunk segmentation and the absolute chunk-count safety bound', async () => {
        const overlongFixture = await openFixture();
        await expect(
            overlongFixture.custody.outputStore.commitChunk(
                0,
                new Uint8Array(1_048_577),
            ),
        ).rejects.toMatchObject({ code: 'InvalidInput' });

        const boundaryFixture = await openFixture({
            commonProofEnvironmentIdentifier: new Uint8Array(32).fill(0xde),
        });
        await boundaryFixture.custody.outputStore.commitChunk(
            0,
            new Uint8Array(1_048_576).fill(1),
        );
        await expect(
            boundaryFixture.custody.outputStore.commitChunk(
                256,
                Uint8Array.of(1),
            ),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
        boundaryFixture.custody.sealCanonicalOutput();
        expect(
            boundaryFixture.custody.authenticatedOutput().declaredByteLength,
        ).toBe(1_048_576);
    });

    it('uses typed custody failures for malformed environment inputs', async () => {
        const openedStore = await openRuntimeTestStore();
        const workerKernel = createWasmBrowserActionStorageWorkerKernel({
            kernel: transcriptCoreKernel,
        });
        await ensureAuthenticatedRepairHead(openedStore.store);
        const capacityReservation =
            await openedStore.store.reserveExclusiveCapacity({
                initialLogicalRecordKeyPrefixes: ['common-proof-attempt/'],
                maximumAdditionalAuthenticatedRepairHeadPlaintextByteLength: 1,
                maximumAdditionalOwnedRecordCount: 1,
                maximumAdditionalStoredValueByteLength: 1,
                maximumDeletionBatchRecordCount: 1,
            });
        expect(() =>
            openCommonProofBrowserCustody({
                actionRandomnessCommitment: new Uint8Array(63),
                capacityReservation,
                commonProofEnvironmentIdentifier: new Uint8Array(32),
                commonProofRuntimeBindingHash: runtimeBindingHash,
                limits: {
                    maximumExternalMemoryByteLength: 1n,
                    maximumExternalMemoryObjectCount: 1,
                    maximumExternalMemoryRecordCount: 1,
                    transactionLifetimeMilliseconds: 1,
                },
                proofAttemptLineageIdentifier,
                store: openedStore.store,
                workerKernel,
            }),
        ).toThrow(BrowserActionStorageCustodyError);
        await capacityReservation.release();
    });

    it('requires the exact installed scratch-record capacity at every store boundary', () => {
        const boundaryLimits = {
            maximumActiveTransactionCount: 1,
            maximumLeaseByteLength:
                commonProofStorageCapacityProfile.maximumLeaseByteLength,
            maximumLeaseCountPerTransaction:
                commonProofStorageCapacityProfile.maximumLeaseCountPerTransaction,
            maximumOwnedRecordCount:
                commonProofStorageCapacityProfile.maximumAdditionalOwnedRecordCount,
            maximumStoredValueByteLength:
                commonProofStorageCapacityProfile.maximumAdditionalStoredValueByteLength +
                commonProofStorageCapacityProfile.maximumAdditionalAuthenticatedRepairHeadPlaintextByteLength,
            maximumTransactionByteLength:
                commonProofStorageCapacityProfile.maximumTransactionByteLength,
            maximumTransactionLifetimeMilliseconds: 1,
        } as const;
        expect(() =>
            requireCommonProofStorageCapacity(boundaryLimits),
        ).not.toThrow();

        for (const [limitName, boundaryValue] of Object.entries(
            boundaryLimits,
        )) {
            if (
                limitName === 'maximumActiveTransactionCount' ||
                limitName === 'maximumTransactionLifetimeMilliseconds'
            ) {
                continue;
            }
            expect(() =>
                requireCommonProofStorageCapacity({
                    ...boundaryLimits,
                    [limitName]: boundaryValue - 1,
                }),
            ).toThrowError(expect.objectContaining({ code: 'OpenFailed' }));
        }
    });
});
