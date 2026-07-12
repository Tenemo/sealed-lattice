import { webcrypto } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import type {
    BrowserActionStorageCustody,
    BrowserActionStorageRootBinding,
    BrowserDeviceWrappingSnapshot,
    ExternallyVerifiedStorageRootCommitment,
} from '#packages/protocol/src/runtime/browser-action-storage-custody';
import {
    copyBrowserDeviceWrappingState,
    createBrowserActionStorageCustodyForOwnedWorker,
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
    testRecoveryText,
} from '#packages/protocol/tests/support/action-storage-custody-test-support';

const cryptoProvider = webcrypto as unknown as Crypto;
const testBinding: BrowserActionStorageRootBinding = Object.freeze({
    actionContextHash: createTestBytes(64, 41),
    ceremonyContextHash: createTestBytes(64, 23),
    participantId: createTestBytes(64, 59),
    suiteId: createTestBytes(64, 7),
});

const verifiedCommitment = (
    storageRootCommitment: Uint8Array,
): ExternallyVerifiedStorageRootCommitment =>
    Object.freeze({ storageRootCommitment: storageRootCommitment.slice() });

const initializeAndActivate = async (
    custody: BrowserActionStorageCustody,
): Promise<
    Readonly<{
        commitment: ExternallyVerifiedStorageRootCommitment;
        snapshot: BrowserDeviceWrappingSnapshot;
    }>
> => {
    const snapshot = await custody.initialize();
    const commitment = verifiedCommitment(snapshot.storageRootCommitment);
    await custody.openIntoOwnedWorker({
        expectedSnapshot: snapshot,
        externallyVerifiedCommitment: commitment,
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
                      recoveryValueExported: false,
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

class PostFailureCustodyWorker extends EventTarget {
    #postCount = 0;
    public terminationCount = 0;

    public postMessage(message: unknown): void {
        this.#postCount += 1;
        if (this.#postCount > 1) {
            throw new Error('Injected worker post failure.');
        }
        const request = message as FakeWorkerRequest;
        queueMicrotask(() => {
            this.dispatchEvent(
                new MessageEvent('message', {
                    data: {
                        messageKind: 'browser-action-storage-custody-completed',
                        requestIdentifier: request.requestIdentifier,
                        result: undefined,
                    },
                }),
            );
        });
    }

    public terminate(): void {
        this.terminationCount += 1;
    }
}

class InMemoryDeviceWrappingStateStorage implements BrowserDeviceWrappingStateStorage {
    #forceNextConflict = false;
    #replacementAfterNextRead: BrowserDeviceWrappingState | undefined;
    #replaceAfterNextRead = false;
    #state: BrowserDeviceWrappingState | undefined;

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

    public readState(): Promise<BrowserDeviceWrappingState | undefined> {
        const result =
            this.#state === undefined
                ? undefined
                : copyBrowserDeviceWrappingState(this.#state);
        if (this.#replaceAfterNextRead) {
            this.#state =
                this.#replacementAfterNextRead === undefined
                    ? undefined
                    : copyBrowserDeviceWrappingState(
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
                : copyBrowserDeviceWrappingState(mutation.replacement);

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
        expect(snapshot.recoveryValueExported).toBe(false);
        expect(snapshot.mutationIdentifier).toHaveLength(32);
        expect(Object.keys(snapshot).sort()).toEqual([
            'mutationIdentifier',
            'recoveryValueExported',
            'storageRootCommitment',
        ]);
        expect(snapshot.storageRootCommitment).toHaveLength(64);
        expect(workerKernel.retainedRootMatchesExpected()).toBe(false);
        expect(workerKernel.stagedRootPresent()).toBe(true);
        await custody.openIntoOwnedWorker({
            expectedSnapshot: snapshot,
            externallyVerifiedCommitment: verifiedCommitment(
                snapshot.storageRootCommitment,
            ),
        });
        expect(workerKernel.retainedRootMatchesExpected()).toBe(true);
        expect(
            workerKernel.activeMutationIdentifierMatches(
                snapshot.mutationIdentifier,
            ),
        ).toBe(true);
        expect(workerKernel.lastDeviceKeyIsNonExtractable()).toBe(true);
        expect(await workerKernel.lastDeviceKeyExportIsRefused()).toBe(true);

        const storedState = await storage.readState();
        expect(storedState?.deviceKey.extractable).toBe(false);
        expect(
            Object.values(snapshot).some(
                (value) =>
                    value instanceof Uint8Array &&
                    value.byteLength === testActionStorageRootByteLength,
            ),
        ).toBe(false);
        await expect(custody.initialize()).rejects.toMatchObject({
            code: 'CommitmentRequired',
            name: 'BrowserActionStorageCustodyError',
        });
        expect(workerKernel.stagedRootPresent()).toBe(false);
    });

    it('requires exact external acceptance before activation and preserves the staged root after a wrong commitment', async () => {
        const { custody, workerKernel } = createCustody({
            actionStorageRoot: createTestBytes(
                testActionStorageRootByteLength,
                21,
            ),
        });
        const snapshot = await custody.initialize();
        const wrongCommitment = verifiedCommitment(
            snapshot.storageRootCommitment,
        );
        wrongCommitment.storageRootCommitment[0] ^= 0x80;

        await expect(
            custody.openIntoOwnedWorker({
                expectedSnapshot: snapshot,
                externallyVerifiedCommitment: wrongCommitment,
            }),
        ).rejects.toMatchObject({ code: 'CommitmentMismatch' });
        expect(workerKernel.activeRootPresent()).toBe(false);
        expect(workerKernel.stagedRootPresent()).toBe(true);

        await custody.openIntoOwnedWorker({
            expectedSnapshot: snapshot,
            externallyVerifiedCommitment: verifiedCommitment(
                snapshot.storageRootCommitment,
            ),
        });
        expect(workerKernel.activeRootPresent()).toBe(true);
        expect(workerKernel.stagedRootPresent()).toBe(false);
    });

    it('recovers the public first-use commitment from persisted state after a pre-publication worker restart', async () => {
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
            externallyVerifiedCommitment: verifiedCommitment(
                restoredSnapshot.storageRootCommitment,
            ),
        });
        expect(restartedWorker.workerKernel.activeRootPresent()).toBe(true);
    });

    it('forbids silent reinitialization when a commitment is known but local storage is missing and permits explicit recovery', async () => {
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

        const recoveredSnapshot = await missingStorageCustody.custody.recover({
            caseInsensitiveRecoveryText: testRecoveryText.toLowerCase(),
            externallyVerifiedCommitment: verifiedCommitment(knownCommitment),
        });
        expect(recoveredSnapshot.recoveryValueExported).toBe(true);
        expect(
            missingStorageCustody.workerKernel.retainedRootMatchesExpected(),
        ).toBe(true);
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
                externallyVerifiedCommitment: verifiedCommitment(
                    initializationSnapshot.storageRootCommitment,
                ),
            }),
        ).rejects.toMatchObject({ code: 'OwnedWorkerFailure' });
        expect(wrongBindingCustody.workerKernel.activeRootPresent()).toBe(
            false,
        );
    });

    it('publishes recovery text once and only after worker-confirmed checksum bytes', async () => {
        const { custody, workerKernel } = createCustody({
            actionStorageRoot: createTestBytes(
                testActionStorageRootByteLength,
                33,
            ),
        });
        const { commitment, snapshot } = await initializeAndActivate(custody);
        const preparation = await custody.beginRecoveryExport({
            expectedSnapshot: snapshot,
            externallyVerifiedCommitment: commitment,
        });

        expect('canonicalRecoveryText' in preparation).toBe(false);
        await expect(
            custody.confirmRecoveryExport({
                confirmedChecksum: new Uint8Array(16),
                preparationIdentifier: preparation.preparationIdentifier,
            }),
        ).rejects.toMatchObject({ code: 'RecoveryConfirmationFailed' });
        expect((await custody.currentSnapshot())?.recoveryValueExported).toBe(
            false,
        );

        const confirmation = await custody.confirmRecoveryExport({
            confirmedChecksum: workerKernel.checksum(),
            preparationIdentifier: preparation.preparationIdentifier,
        });
        expect(confirmation.canonicalRecoveryText).toBe(testRecoveryText);
        expect(confirmation.snapshot.recoveryValueExported).toBe(true);
        expect(
            workerKernel.activeMutationIdentifierMatches(
                confirmation.snapshot.mutationIdentifier,
            ),
        ).toBe(true);
        await expect(
            custody.beginRecoveryExport({
                expectedSnapshot: confirmation.snapshot,
                externallyVerifiedCommitment: commitment,
            }),
        ).rejects.toMatchObject({ code: 'RecoveryAlreadyExported' });
        await expect(custody.delete(snapshot)).rejects.toMatchObject({
            code: 'Conflict',
        });
    });

    it('rewraps validated case-insensitive recovery material with a fresh key, nonce, and version', async () => {
        const { custody, storage, workerKernel } = createCustody({
            actionStorageRoot: createTestBytes(
                testActionStorageRootByteLength,
                49,
            ),
        });
        const { commitment, snapshot: originalSnapshot } =
            await initializeAndActivate(custody);
        const originalState = await storage.readState();
        const originalNonce = workerKernel.lastEnvelopeNonce();

        const recoveredSnapshot = await custody.recover({
            caseInsensitiveRecoveryText: testRecoveryText.toLowerCase(),
            externallyVerifiedCommitment: commitment,
            expectedSnapshot: originalSnapshot,
        });
        const recoveredState = await storage.readState();

        expect(recoveredSnapshot.recoveryValueExported).toBe(true);
        expect(recoveredSnapshot.mutationIdentifier).not.toEqual(
            originalSnapshot.mutationIdentifier,
        );
        expect(recoveredState?.deviceKey).not.toBe(originalState?.deviceKey);
        expect(workerKernel.lastEnvelopeNonce()).not.toEqual(originalNonce);
        expect(
            workerKernel.activeMutationIdentifierMatches(
                recoveredSnapshot.mutationIdentifier,
            ),
        ).toBe(true);
        await expect(custody.delete(originalSnapshot)).rejects.toMatchObject({
            code: 'Conflict',
        });
        await custody.delete(recoveredSnapshot);
        expect(await custody.currentSnapshot()).toBeUndefined();
        expect(workerKernel.activeRootPresent()).toBe(false);
    });

    it('refuses malformed ingress before invoking the cryptographic kernel', async () => {
        const { custody, workerKernel } = createCustody({
            actionStorageRoot: createTestBytes(
                testActionStorageRootByteLength,
                65,
            ),
        });
        const snapshot = await custody.initialize();
        const commitment = verifiedCommitment(snapshot.storageRootCommitment);

        await expect(
            custody.recover({
                caseInsensitiveRecoveryText: `${testRecoveryText}=`,
                externallyVerifiedCommitment: commitment,
                expectedSnapshot: snapshot,
            }),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
        await expect(
            custody.recover({
                caseInsensitiveRecoveryText: testRecoveryText.slice(1),
                externallyVerifiedCommitment: commitment,
                expectedSnapshot: snapshot,
            }),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
        expect(workerKernel.importCallCount).toBe(0);
        expect(await custody.currentSnapshot()).toEqual(snapshot);
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
        if (storedState === undefined) {
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
                externallyVerifiedCommitment: commitment,
            }),
        ).rejects.toMatchObject({ code: 'OwnedWorkerFailure' });
        expect(workerKernel.retainedRootMatchesExpected()).toBe(true);
        expect(
            workerKernel.activeMutationIdentifierMatches(
                snapshot.mutationIdentifier,
            ),
        ).toBe(true);
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
        if (storedState === undefined) {
            throw new Error('Expected initialized test custody.');
        }
        storage.replaceAfterNextRead({
            ...storedState,
            mutationIdentifier: createTestBytes(32, 149),
        });

        await expect(
            custody.openIntoOwnedWorker({
                expectedSnapshot: snapshot,
                externallyVerifiedCommitment: verifiedCommitment(
                    snapshot.storageRootCommitment,
                ),
            }),
        ).rejects.toMatchObject({ code: 'Conflict' });
        expect(workerKernel.activeRootPresent()).toBe(false);
        expect(workerKernel.stagedRootPresent()).toBe(false);
    });

    it('preserves current storage on stale recovery but destroys staged material', async () => {
        const { custody, storage, workerKernel } = createCustody({
            actionStorageRoot: createTestBytes(
                testActionStorageRootByteLength,
                129,
            ),
        });
        const { commitment, snapshot } = await initializeAndActivate(custody);
        storage.forceNextConflict();

        await expect(
            custody.recover({
                caseInsensitiveRecoveryText: testRecoveryText,
                externallyVerifiedCommitment: commitment,
                expectedSnapshot: snapshot,
            }),
        ).rejects.toMatchObject({ code: 'Conflict' });
        expect(await custody.currentSnapshot()).toEqual(snapshot);
        expect(workerKernel.stagedRootPresent()).toBe(false);
        expect(
            workerKernel.activeMutationIdentifierMatches(
                snapshot.mutationIdentifier,
            ),
        ).toBe(true);
    });

    it('deactivates the root before a stale delete can conflict', async () => {
        const { custody, storage, workerKernel } = createCustody({
            actionStorageRoot: createTestBytes(
                testActionStorageRootByteLength,
                145,
            ),
        });
        const { snapshot } = await initializeAndActivate(custody);
        storage.forceNextConflict();

        await expect(custody.delete(snapshot)).rejects.toMatchObject({
            code: 'Conflict',
        });
        expect(await custody.currentSnapshot()).toEqual(snapshot);
        expect(workerKernel.activeRootPresent()).toBe(false);
        expect(workerKernel.stagedRootPresent()).toBe(false);
    });

    it('destroys active and staged roots when custody closes', async () => {
        const { custody, workerKernel } = createCustody({
            actionStorageRoot: createTestBytes(
                testActionStorageRootByteLength,
                161,
            ),
        });
        await initializeAndActivate(custody);
        expect(workerKernel.activeRootPresent()).toBe(true);

        await custody.close();
        await custody.close();

        expect(workerKernel.activeRootPresent()).toBe(false);
        expect(workerKernel.stagedRootPresent()).toBe(false);
        await expect(custody.currentSnapshot()).rejects.toMatchObject({
            code: 'Closed',
        });
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
                    maximumStoredValueByteLength: 4_096,
                    maximumTransactionByteLength: 128,
                    maximumTransactionLifetimeMilliseconds: 10_000,
                },
                namespace: 'malicious-worker',
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

    it('fails closed when posting a command to an owned worker throws', async () => {
        const postFailureWorker = new PostFailureCustodyWorker();
        const custody = await openBrowserActionStorageCustodyWorker({
            configuration: {
                binding: testBinding,
                databaseName: 'post-failure-worker-test',
                limits: {
                    maximumActiveTransactionCount: 1,
                    maximumLeaseByteLength: 64,
                    maximumLeaseCountPerTransaction: 1,
                    maximumStoredValueByteLength: 4_096,
                    maximumTransactionByteLength: 128,
                    maximumTransactionLifetimeMilliseconds: 10_000,
                },
                namespace: 'post-failure-worker',
            },
            worker: postFailureWorker,
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
        expect(postFailureWorker.terminationCount).toBe(1);

        let repeatedFailure: unknown;
        try {
            await custody.currentSnapshot();
        } catch (error) {
            repeatedFailure = error;
        }
        expect(repeatedFailure).toBe(terminalFailure);
    });
});
