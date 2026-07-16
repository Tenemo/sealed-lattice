import { webcrypto } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import type {
    BrowserActionStorageCustody,
    BrowserActionStorageRootBinding,
    BrowserDeviceWrappingSnapshot,
    UntrustedExpectedStorageRootCommitment,
} from '#packages/protocol/src/runtime/browser-action-storage-custody';
import {
    copyBrowserDeviceWrappingRecord,
    copyBrowserDeviceWrappingState,
    createBrowserActionStorageCustodyForOwnedWorker,
    isBrowserDeviceWrappingRetirementTombstone,
    type BrowserDeviceWrappingRecord,
    type BrowserDeviceWrappingState,
    type BrowserDeviceWrappingStateMutation,
    type BrowserDeviceWrappingStateStorage,
} from '#packages/protocol/src/runtime/browser-action-storage-custody-internal';
import { openBrowserActionStorageCustodyWorker } from '#packages/protocol/src/runtime/browser-action-storage-custody-worker-channel';
import {
    createTestBytes,
    TestActionStorageWorkerKernel,
    testActionStorageRootByteLength,
    testBytesEqual,
    testDeviceWrappingTagByteLength,
} from '#packages/protocol/tests/support/action-storage-custody-test-support';

const cryptoProvider = webcrypto as unknown as Crypto;
const testBinding: BrowserActionStorageRootBinding = Object.freeze({
    actionContextHash: createTestBytes(64, 41),
    ceremonyContextHash: createTestBytes(64, 23),
    participantId: createTestBytes(64, 59),
    suiteId: createTestBytes(64, 7),
});

const untrustedExpectedCommitment = (
    storageRootCommitment: Uint8Array,
): UntrustedExpectedStorageRootCommitment =>
    Object.freeze({ storageRootCommitment: storageRootCommitment.slice() });

const initializeAndActivate = async (
    custody: BrowserActionStorageCustody,
): Promise<
    Readonly<{
        commitment: UntrustedExpectedStorageRootCommitment;
        snapshot: BrowserDeviceWrappingSnapshot;
    }>
> => {
    const snapshot = await custody.initialize();
    const commitment = untrustedExpectedCommitment(
        snapshot.storageRootCommitment,
    );
    await custody.openIntoOwnedWorker({
        expectedSnapshot: snapshot,
        untrustedExpectedCommitment: commitment,
    });

    return { commitment, snapshot };
};

type FakeWorkerRequest = Readonly<{
    command: string;
    requestIdentifier: number;
}>;

class MaliciousCustodyWorker {
    readonly #listeners = new Map<
        string,
        Set<EventListenerOrEventListenerObject>
    >();
    readonly #secretKey: CryptoKey;
    public terminationCount = 0;

    public constructor(secretKey: CryptoKey) {
        this.#secretKey = secretKey;
    }

    public addEventListener(
        type: string,
        listener: EventListenerOrEventListenerObject,
    ): void {
        const listeners = this.#listeners.get(type) ?? new Set();
        listeners.add(listener);
        this.#listeners.set(type, listeners);
    }

    public removeEventListener(
        type: string,
        listener: EventListenerOrEventListenerObject,
    ): void {
        this.#listeners.get(type)?.delete(listener);
    }

    public postMessage(message: unknown): void {
        const request = message as FakeWorkerRequest;
        const result =
            request.command === 'initialize'
                ? {
                      deviceKey: this.#secretKey,
                      mutationIdentifier: new Uint8Array(32),
                      wrappedStorageRoot: new Uint8Array(96),
                  }
                : undefined;
        queueMicrotask(() => {
            this.#dispatch('message', {
                data: {
                    messageKind: 'browser-action-storage-custody-completed',
                    requestIdentifier: request.requestIdentifier,
                    result,
                },
            } as MessageEvent<unknown>);
        });
    }

    public terminate(): void {
        this.terminationCount += 1;
    }

    #dispatch(type: string, event: Event): void {
        for (const listener of this.#listeners.get(type) ?? []) {
            if (typeof listener === 'function') {
                listener(event);
            } else {
                listener.handleEvent(event);
            }
        }
    }
}

class InMemoryDeviceWrappingStateStorage implements BrowserDeviceWrappingStateStorage {
    #forceNextConflict = false;
    #replacementAfterNextRead: BrowserDeviceWrappingRecord | undefined;
    #replaceAfterNextRead = false;
    #state: BrowserDeviceWrappingRecord | undefined;

    public forceNextConflict(): void {
        this.#forceNextConflict = true;
    }

    public replaceAfterNextRead(
        state: BrowserDeviceWrappingState | undefined,
    ): void {
        this.#replacementAfterNextRead =
            state === undefined
                ? undefined
                : copyBrowserDeviceWrappingState(state);
        this.#replaceAfterNextRead = true;
    }

    public replaceWithoutComparison(
        state: BrowserDeviceWrappingState | undefined,
    ): void {
        this.#state =
            state === undefined
                ? undefined
                : copyBrowserDeviceWrappingState(state);
    }

    public readState(): Promise<BrowserDeviceWrappingRecord | undefined> {
        const result =
            this.#state === undefined
                ? undefined
                : copyBrowserDeviceWrappingRecord(this.#state);
        if (this.#replaceAfterNextRead) {
            this.#state =
                this.#replacementAfterNextRead === undefined
                    ? undefined
                    : copyBrowserDeviceWrappingRecord(
                          this.#replacementAfterNextRead,
                      );
            this.#replacementAfterNextRead = undefined;
            this.#replaceAfterNextRead = false;
        }

        return Promise.resolve(result);
    }

    public compareAndSwapState(
        mutation: BrowserDeviceWrappingStateMutation,
    ): Promise<boolean> {
        if (this.#forceNextConflict) {
            this.#forceNextConflict = false;
            return Promise.resolve(false);
        }
        const matches =
            mutation.expectedMutationIdentifier === undefined
                ? this.#state === undefined
                : this.#state !== undefined &&
                  testBytesEqual(
                      this.#state.mutationIdentifier,
                      mutation.expectedMutationIdentifier,
                  );
        if (!matches) {
            return Promise.resolve(false);
        }
        this.#state =
            mutation.replacement === undefined
                ? undefined
                : copyBrowserDeviceWrappingRecord(mutation.replacement);

        return Promise.resolve(true);
    }
}

const createCustody = (input: {
    actionStorageRoot: Uint8Array;
    binding?: BrowserActionStorageRootBinding;
    knownStorageRootCommitment?: Uint8Array;
    storage?: InMemoryDeviceWrappingStateStorage;
}): Readonly<{
    custody: BrowserActionStorageCustody;
    storage: InMemoryDeviceWrappingStateStorage;
    workerKernel: TestActionStorageWorkerKernel;
}> => {
    const storage = input.storage ?? new InMemoryDeviceWrappingStateStorage();
    const workerKernel = new TestActionStorageWorkerKernel({
        actionStorageRoot: input.actionStorageRoot,
        cryptoProvider,
    });

    return {
        custody: createBrowserActionStorageCustodyForOwnedWorker({
            assertExclusiveOwnership: () => undefined,
            binding: input.binding ?? testBinding,
            cryptoProvider,
            knownStorageRootCommitment: input.knownStorageRootCommitment,
            storage,
            workerKernel,
        }),
        storage,
        workerKernel,
    };
};

describe('Browser action-storage custody', () => {
    it('returns only opaque metadata while retaining a non-extractable version-bound root', async () => {
        const expectedRoot = createTestBytes(
            testActionStorageRootByteLength,
            17,
        );
        const { custody, storage, workerKernel } = createCustody({
            actionStorageRoot: expectedRoot,
        });

        const snapshot = await custody.initialize();

        expect(snapshot.mutationIdentifier).toBeInstanceOf(Uint8Array);
        expect(snapshot.mutationIdentifier).toHaveLength(32);
        expect(snapshot.storageRootCommitment).toHaveLength(64);
        expect(workerKernel.retainedRootMatchesExpected()).toBe(false);
        expect(workerKernel.stagedRootPresent()).toBe(true);
        await custody.openIntoOwnedWorker({
            expectedSnapshot: snapshot,
            untrustedExpectedCommitment: untrustedExpectedCommitment(
                snapshot.storageRootCommitment,
            ),
        });
        expect(workerKernel.retainedRootMatchesExpected()).toBe(true);
        expect(workerKernel.lastDeviceKeyIsNonExtractable()).toBe(true);
        expect(await workerKernel.lastDeviceKeyExportIsRefused()).toBe(true);

        const storedState = await storage.readState();
        if (
            storedState === undefined ||
            isBrowserDeviceWrappingRetirementTombstone(storedState)
        ) {
            throw new Error('Expected active initialized test custody.');
        }
        expect(storedState?.deviceKey.extractable).toBe(false);
        await expect(custody.initialize()).rejects.toMatchObject({
            code: 'CommitmentRequired',
            name: 'BrowserActionStorageCustodyError',
        });
        expect(workerKernel.stagedRootPresent()).toBe(false);
    });

    it('replaces wrapping custody with a durable tombstone that refuses fresh and recovered reopening', async () => {
        const actionStorageRoot = createTestBytes(
            testActionStorageRootByteLength,
            18,
        );
        const first = createCustody({ actionStorageRoot });
        const { commitment, snapshot } = await initializeAndActivate(
            first.custody,
        );

        await first.custody.retire();

        expect(first.workerKernel.activeRootPresent()).toBe(false);
        expect(first.workerKernel.stagedRootPresent()).toBe(false);
        const retirementRecord = await first.storage.readState();
        expect(retirementRecord).toBeDefined();
        if (
            retirementRecord === undefined ||
            !isBrowserDeviceWrappingRetirementTombstone(retirementRecord)
        ) {
            throw new Error('Expected a device-wrapping retirement tombstone.');
        }
        expect(Object.keys(retirementRecord).sort()).toEqual([
            'mutationIdentifier',
            'recordKind',
        ]);
        await expect(first.custody.currentSnapshot()).rejects.toMatchObject({
            code: 'Unavailable',
        });

        const fresh = createCustody({
            actionStorageRoot,
            storage: first.storage,
        });
        await expect(fresh.custody.initialize()).rejects.toMatchObject({
            code: 'Unavailable',
        });
        expect(fresh.workerKernel.activeRootPresent()).toBe(false);
        expect(fresh.workerKernel.stagedRootPresent()).toBe(false);

        const recovered = createCustody({
            actionStorageRoot,
            knownStorageRootCommitment: snapshot.storageRootCommitment,
            storage: first.storage,
        });
        await expect(
            recovered.custody.openIntoOwnedWorker({
                expectedSnapshot: snapshot,
                untrustedExpectedCommitment: commitment,
            }),
        ).rejects.toMatchObject({ code: 'Unavailable' });
        expect(recovered.workerKernel.activeRootPresent()).toBe(false);
        expect(recovered.workerKernel.stagedRootPresent()).toBe(false);
    });

    it('copies, versions, authenticates, and hashes closed local records through custody', async () => {
        const { custody } = createCustody({
            actionStorageRoot: createTestBytes(
                testActionStorageRootByteLength,
                19,
            ),
        });
        await initializeAndActivate(custody);
        const recipientInputRoot = createTestBytes(64, 31);
        const preservedRecipientInputRoot = recipientInputRoot.slice();
        const pendingIdentifier = custody.deriveLocalRecordIdentifier({
            recordType: 'aggregateThresholdShare',
            recipientInputRoot,
        });
        recipientInputRoot.fill(0);
        const identifier = await pendingIdentifier;
        expect(identifier).toHaveLength(64);
        await expect(
            custody.deriveLocalRecordIdentifier({
                recordType: 'aggregateThresholdShare',
                recipientInputRoot: preservedRecipientInputRoot,
            }),
        ).resolves.toEqual(identifier);

        const expectedContext = {
            actionRandomnessCommitment: createTestBytes(64, 53),
            identifierInput: {
                recordType: 'aggregateThresholdShare',
                recipientInputRoot: preservedRecipientInputRoot,
            },
            recordVersion: 0n,
        } as const;
        const plaintext = createTestBytes(8_193, 73);
        const preservedPlaintext = plaintext.slice();
        const pendingEnvelope = custody.sealLocalRecord({
            ...expectedContext,
            plaintext,
        });
        plaintext.fill(0);
        const envelope = await pendingEnvelope;
        await expect(
            custody.openLocalRecord({ ...expectedContext, envelope }),
        ).resolves.toEqual(preservedPlaintext);
        const envelopeHash = await custody.hashLocalRecordEnvelope(envelope);
        expect(envelopeHash).toHaveLength(64);

        const successorContext = {
            ...expectedContext,
            predecessorRecordHash: envelopeHash,
            recordVersion: 1n,
        } as const;
        const successorPlaintext = createTestBytes(257, 109);
        const successorEnvelope = await custody.sealLocalRecord({
            ...successorContext,
            plaintext: successorPlaintext,
        });
        await expect(
            custody.openLocalRecord({
                ...successorContext,
                envelope: successorEnvelope,
            }),
        ).resolves.toEqual(successorPlaintext);

        const tamperedEnvelope = envelope.slice();
        tamperedEnvelope[tamperedEnvelope.byteLength - 1] ^= 1;
        await expect(
            custody.openLocalRecord({
                ...expectedContext,
                envelope: tamperedEnvelope,
            }),
        ).rejects.toMatchObject({
            code: 'OwnedWorkerFailure',
            name: 'BrowserActionStorageCustodyError',
        });
        await expect(
            custody.openLocalRecord({
                ...expectedContext,
                actionRandomnessCommitment: createTestBytes(64, 54),
                envelope,
            }),
        ).rejects.toMatchObject({
            code: 'OwnedWorkerFailure',
            name: 'BrowserActionStorageCustodyError',
        });
        await expect(
            custody.sealLocalRecord({
                ...expectedContext,
                predecessorRecordHash: envelopeHash,
                plaintext: preservedPlaintext,
            }),
        ).rejects.toMatchObject({
            code: 'InvalidInput',
            name: 'BrowserActionStorageCustodyError',
        });

        await custody.close();
        await expect(
            custody.hashLocalRecordEnvelope(envelope),
        ).rejects.toMatchObject({
            code: 'Closed',
            name: 'BrowserActionStorageCustodyError',
        });
    });

    it('recomputes the untrusted expected commitment and preserves the staged root after a forged value', async () => {
        const { custody, workerKernel } = createCustody({
            actionStorageRoot: createTestBytes(
                testActionStorageRootByteLength,
                21,
            ),
        });
        const snapshot = await custody.initialize();
        const wrongCommitment = untrustedExpectedCommitment(
            snapshot.storageRootCommitment,
        );
        wrongCommitment.storageRootCommitment[0] ^= 0x80;

        await expect(
            custody.openIntoOwnedWorker({
                expectedSnapshot: snapshot,
                untrustedExpectedCommitment: wrongCommitment,
            }),
        ).rejects.toMatchObject({ code: 'CommitmentMismatch' });
        expect(workerKernel.activeRootPresent()).toBe(false);
        expect(workerKernel.stagedRootPresent()).toBe(true);

        await custody.openIntoOwnedWorker({
            expectedSnapshot: snapshot,
            untrustedExpectedCommitment: untrustedExpectedCommitment(
                snapshot.storageRootCommitment,
            ),
        });
        expect(workerKernel.activeRootPresent()).toBe(true);
        expect(workerKernel.stagedRootPresent()).toBe(false);
    });

    it('copies an untrusted expected commitment before queued worker use', async () => {
        const { custody, workerKernel } = createCustody({
            actionStorageRoot: createTestBytes(
                testActionStorageRootByteLength,
                22,
            ),
        });
        const snapshot = await custody.initialize();
        const expectation = untrustedExpectedCommitment(
            snapshot.storageRootCommitment,
        );
        const opening = custody.openIntoOwnedWorker({
            expectedSnapshot: snapshot,
            untrustedExpectedCommitment: expectation,
        });
        expectation.storageRootCommitment.fill(0);

        await expect(opening).resolves.toBeUndefined();
        expect(workerKernel.retainedRootMatchesExpected()).toBe(true);
    });

    it('reopens the public first-use commitment from persisted state after a pre-publication worker restart', async () => {
        const storage = new InMemoryDeviceWrappingStateStorage();
        const expectedRoot = createTestBytes(
            testActionStorageRootByteLength,
            25,
        );
        const firstWorker = createCustody({
            actionStorageRoot: expectedRoot,
            storage,
        });
        const initializedSnapshot = await firstWorker.custody.initialize();
        await firstWorker.custody.close();

        const restartedWorker = createCustody({
            actionStorageRoot: expectedRoot,
            storage,
        });
        const restoredSnapshot =
            await restartedWorker.custody.currentSnapshot();
        expect(restoredSnapshot).toEqual(initializedSnapshot);
        if (restoredSnapshot === undefined) {
            throw new Error('Expected persisted first-use custody state.');
        }
        await restartedWorker.custody.openIntoOwnedWorker({
            expectedSnapshot: restoredSnapshot,
            untrustedExpectedCommitment: untrustedExpectedCommitment(
                restoredSnapshot.storageRootCommitment,
            ),
        });
        expect(restartedWorker.workerKernel.activeRootPresent()).toBe(true);
    });

    it('forbids reinitialization when a commitment is known but local storage is missing', async () => {
        const expectedRoot = createTestBytes(
            testActionStorageRootByteLength,
            27,
        );
        const original = createCustody({ actionStorageRoot: expectedRoot });
        const initializationSnapshot = await original.custody.initialize();
        const knownCommitment =
            initializationSnapshot.storageRootCommitment.slice();
        await original.custody.close();

        const missingStorageCustody = createCustody({
            actionStorageRoot: expectedRoot,
            knownStorageRootCommitment: knownCommitment,
        });
        await expect(
            missingStorageCustody.custody.initialize(),
        ).rejects.toMatchObject({ code: 'CommitmentRequired' });
        expect(
            await missingStorageCustody.custody.currentSnapshot(),
        ).toBeUndefined();

        expect(missingStorageCustody.workerKernel.activeRootPresent()).toBe(
            false,
        );
    });

    it('refuses a persisted wrapping pair under a different complete action binding', async () => {
        const storage = new InMemoryDeviceWrappingStateStorage();
        const expectedRoot = createTestBytes(
            testActionStorageRootByteLength,
            31,
        );
        const original = createCustody({
            actionStorageRoot: expectedRoot,
            storage,
        });
        const initializationSnapshot = await original.custody.initialize();
        await original.custody.close();
        const wrongBindingCustody = createCustody({
            actionStorageRoot: expectedRoot,
            binding: Object.freeze({
                ...testBinding,
                actionContextHash: createTestBytes(64, 199),
            }),
            knownStorageRootCommitment:
                initializationSnapshot.storageRootCommitment,
            storage,
        });

        await expect(
            wrongBindingCustody.custody.openIntoOwnedWorker({
                expectedSnapshot: initializationSnapshot,
                untrustedExpectedCommitment: untrustedExpectedCommitment(
                    initializationSnapshot.storageRootCommitment,
                ),
            }),
        ).rejects.toMatchObject({ code: 'OwnedWorkerFailure' });
        expect(wrongBindingCustody.workerKernel.activeRootPresent()).toBe(
            false,
        );
    });

    it('fails closed on ciphertext tampering without replacing the active root', async () => {
        const { custody, storage, workerKernel } = createCustody({
            actionStorageRoot: createTestBytes(
                testActionStorageRootByteLength,
                81,
            ),
        });
        const { commitment, snapshot } = await initializeAndActivate(custody);
        const storedState = await storage.readState();
        if (
            storedState === undefined ||
            isBrowserDeviceWrappingRetirementTombstone(storedState)
        ) {
            throw new Error('Expected initialized test custody.');
        }
        const tamperedEnvelope = storedState.wrappedStorageRoot.slice();
        tamperedEnvelope[
            tamperedEnvelope.byteLength - testDeviceWrappingTagByteLength - 1
        ] ^= 0x80;
        storage.replaceWithoutComparison({
            ...storedState,
            wrappedStorageRoot: tamperedEnvelope,
        });

        await expect(
            custody.openIntoOwnedWorker({
                expectedSnapshot: snapshot,
                untrustedExpectedCommitment: commitment,
            }),
        ).rejects.toMatchObject({ code: 'OwnedWorkerFailure' });
        expect(workerKernel.retainedRootMatchesExpected()).toBe(true);
    });

    it('allows only one concurrent initialization and discards the losing staged root', async () => {
        const storage = new InMemoryDeviceWrappingStateStorage();
        const expectedRoot = createTestBytes(
            testActionStorageRootByteLength,
            97,
        );
        const first = createCustody({
            actionStorageRoot: expectedRoot,
            storage,
        });
        const second = createCustody({
            actionStorageRoot: expectedRoot,
            storage,
        });

        const outcomes = await Promise.allSettled([
            first.custody.initialize(),
            second.custody.initialize(),
        ]);

        expect(
            outcomes.filter((outcome) => outcome.status === 'fulfilled'),
        ).toHaveLength(1);
        expect(
            outcomes.filter((outcome) => outcome.status === 'rejected'),
        ).toMatchObject([{ reason: { code: 'Conflict' } }]);
        const losingKernel =
            outcomes[0]?.status === 'rejected'
                ? first.workerKernel
                : second.workerKernel;
        expect(losingKernel.activeRootPresent()).toBe(false);
        expect(losingKernel.stagedRootPresent()).toBe(false);
    });

    it('does not activate a state that changes after open begins', async () => {
        const { custody, storage, workerKernel } = createCustody({
            actionStorageRoot: createTestBytes(
                testActionStorageRootByteLength,
                113,
            ),
        });
        const snapshot = await custody.initialize();
        const storedState = await storage.readState();
        if (
            storedState === undefined ||
            isBrowserDeviceWrappingRetirementTombstone(storedState)
        ) {
            throw new Error('Expected initialized test custody.');
        }
        storage.replaceAfterNextRead({
            ...storedState,
            mutationIdentifier: createTestBytes(32, 149),
        });

        await expect(
            custody.openIntoOwnedWorker({
                expectedSnapshot: snapshot,
                untrustedExpectedCommitment: untrustedExpectedCommitment(
                    snapshot.storageRootCommitment,
                ),
            }),
        ).rejects.toMatchObject({ code: 'Conflict' });
        expect(workerKernel.activeRootPresent()).toBe(false);
        expect(workerKernel.stagedRootPresent()).toBe(false);
    });

    it('terminates a worker that tries to return a key or wrapped envelope', async () => {
        const generatedKey = await cryptoProvider.subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt'],
        );
        if ('privateKey' in generatedKey) {
            throw new Error('Test WebCrypto returned a key pair for AES-GCM.');
        }
        const maliciousWorker = new MaliciousCustodyWorker(generatedKey);
        const custody = await openBrowserActionStorageCustodyWorker({
            configuration: {
                binding: testBinding,
                databaseName: 'malicious-worker-test',
                limits: {
                    maximumActiveTransactionCount: 1,
                    maximumLeaseByteLength: 64,
                    maximumLeaseCountPerTransaction: 1,
                    maximumOwnedRecordCount: 32,
                    maximumStoredValueByteLength: 4_096,
                    maximumTransactionByteLength: 128,
                    maximumTransactionLifetimeMilliseconds: 10_000,
                },
                namespace: 'malicious-worker',
                runtimeBuildManifestHash: createTestBytes(64, 173),
            },
            worker: maliciousWorker,
        });

        let terminalFailure: unknown;
        try {
            await custody.initialize();
        } catch (error) {
            terminalFailure = error;
        }
        expect(terminalFailure).toMatchObject({
            code: 'OwnedWorkerFailure',
            name: 'BrowserActionStorageCustodyError',
        });
        expect(maliciousWorker.terminationCount).toBe(1);
        let repeatedFailure: unknown;
        try {
            await custody.currentSnapshot();
        } catch (error) {
            repeatedFailure = error;
        }
        expect(repeatedFailure).toBe(terminalFailure);
    });

    it('transfers the main-thread custody facade to one exclusive owner', async () => {
        const generatedKey = await cryptoProvider.subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt'],
        );
        if ('privateKey' in generatedKey) {
            throw new Error('Test WebCrypto returned a key pair for AES-GCM.');
        }
        const worker = new MaliciousCustodyWorker(generatedKey);
        const retainedCustody = await openBrowserActionStorageCustodyWorker({
            configuration: {
                binding: testBinding,
                databaseName: 'exclusive-owner-test',
                limits: {
                    maximumActiveTransactionCount: 1,
                    maximumLeaseByteLength: 64,
                    maximumLeaseCountPerTransaction: 1,
                    maximumOwnedRecordCount: 32,
                    maximumStoredValueByteLength: 4_096,
                    maximumTransactionByteLength: 128,
                    maximumTransactionLifetimeMilliseconds: 10_000,
                },
                namespace: 'exclusive-owner',
                runtimeBuildManifestHash: createTestBytes(64, 179),
            },
            worker,
        });

        const ownedCustody = retainedCustody.claimExclusiveOwner();
        expect(() => retainedCustody.copyBinding()).toThrowError(
            expect.objectContaining({ code: 'InvalidState' }),
        );
        expect(() => retainedCustody.claimExclusiveOwner()).toThrowError(
            expect.objectContaining({ code: 'InvalidState' }),
        );
        expect(ownedCustody.copyBinding()).toEqual(testBinding);

        const firstClose = ownedCustody.close();
        expect(ownedCustody.close()).toBe(firstClose);
        expect(() => retainedCustody.currentSnapshot()).toThrowError(
            expect.objectContaining({ code: 'InvalidState' }),
        );
        await firstClose;
        expect(worker.terminationCount).toBe(1);
    });
});
