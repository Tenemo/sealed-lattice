import {
    createBrowserActionStorageCustodyForOwnedWorker,
    type BrowserActionStorageWorkerKernel,
} from './browser-action-storage-custody-internal.js';
import type {
    BrowserActionStorageCustody,
    BrowserActionStorageRootBinding,
} from './browser-action-storage-custody.js';
import {
    IndexedDbUntrustedStorageAdapter,
    openIndexedDbUntrustedStorageAdapter,
} from './indexed-db-untrusted-storage-adapter.js';
import {
    openPositivelyVerifiedStorageTransactionStore,
    openUntrustedStorageTransactionStore,
    type UntrustedStorageAdapter,
    type UntrustedStorageAuthenticatedRepairProtection,
    type UntrustedStorageRepairReport,
    type UntrustedStorageTransactionStoreOpenResult,
    type UntrustedStorageTransactionLimits,
    type UntrustedStorageTransactionStore,
} from './untrusted-storage-transaction-store.js';

const textEncoder = new TextEncoder();
const maximumDatabaseNameByteLength = 256;
const maximumLockAcquisitionDelayMilliseconds = 2_147_483_647;
const namespacePattern = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;
const lockNamePrefix = 'sealed-lattice-storage-namespace-';

type WebLockOwnedStorageErrorCode =
    | 'AcquisitionCancelled'
    | 'AcquisitionDeadlineExceeded'
    | 'InvalidConfiguration'
    | 'LockCallbackExited'
    | 'OpenFailed'
    | 'Unavailable';

class WebLockOwnedStorageError extends Error {
    public readonly code: WebLockOwnedStorageErrorCode;
    public readonly failureCause: unknown;

    public constructor(
        code: WebLockOwnedStorageErrorCode,
        message: string,
        failureCause?: unknown,
    ) {
        super(message);
        this.name = 'WebLockOwnedStorageError';
        this.code = code;
        this.failureCause = failureCause;
    }
}

type WebLockOwnedStorageState = 'open' | 'closing' | 'closed' | 'failed';

export type WebLockOwnedStorageTransactionStore = Readonly<{
    repairReport: UntrustedStorageRepairReport;
    store: UntrustedStorageTransactionStore;
    close(): Promise<void>;
    state(): WebLockOwnedStorageState;
}>;

type WebLockOwnedStorageBaseConfiguration = Readonly<{
    databaseName: string;
    namespace: string;
    limits: UntrustedStorageTransactionLimits;
    acquisitionDeadlineEpochMilliseconds?: number;
    acquisitionSignal?: AbortSignal;
    indexedDbFactory?: IDBFactory;
    keyRangeFactory?: typeof IDBKeyRange;
    lockManager?: LockManager | null;
}>;

export type WebLockOwnedStorageConfiguration =
    WebLockOwnedStorageBaseConfiguration &
        Readonly<{
            authenticatedRepairProtection: UntrustedStorageAuthenticatedRepairProtection;
        }>;

type WebLockOwnedBrowserActionStorageCustodyConfiguration =
    WebLockOwnedStorageBaseConfiguration &
        Readonly<{
            binding: BrowserActionStorageRootBinding;
            cryptoProvider?: Crypto;
            knownStorageRootCommitment?: Uint8Array;
            workerKernel: BrowserActionStorageWorkerKernel;
        }>;

export type WebLockOwnedBrowserActionStorageCustody = Readonly<{
    custody: BrowserActionStorageCustody;
    close(): Promise<void>;
    state(): WebLockOwnedStorageState;
}>;

type Deferred<Value> = Readonly<{
    promise: Promise<Value>;
    reject(error: Error): void;
    resolve(value: Value): void;
}>;

const createDeferred = <Value>(): Deferred<Value> => {
    let resolvePromise: ((value: Value) => void) | undefined;
    let rejectPromise: ((error: Error) => void) | undefined;
    let isSettled = false;
    const promise = new Promise<Value>((resolve, reject) => {
        resolvePromise = resolve;
        rejectPromise = reject;
    });
    if (resolvePromise === undefined || rejectPromise === undefined) {
        throw new WebLockOwnedStorageError(
            'OpenFailed',
            'Web Lock storage promise initialization failed.',
        );
    }
    const resolveDeferred = resolvePromise;
    const rejectDeferred = rejectPromise;

    return {
        promise,
        reject: (error) => {
            if (isSettled) {
                return;
            }
            isSettled = true;
            rejectDeferred(error);
        },
        resolve: (value) => {
            if (isSettled) {
                return;
            }
            isSettled = true;
            resolveDeferred(value);
        },
    };
};

const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const assertDatabaseName = (databaseName: string): Uint8Array => {
    const databaseNameBytes = textEncoder.encode(databaseName);
    if (
        databaseNameBytes.byteLength === 0 ||
        databaseNameBytes.byteLength > maximumDatabaseNameByteLength
    ) {
        throw new WebLockOwnedStorageError(
            'InvalidConfiguration',
            `databaseName must encode between 1 and ${maximumDatabaseNameByteLength} UTF-8 bytes.`,
        );
    }

    return databaseNameBytes;
};

const assertNamespace = (namespace: string): Uint8Array => {
    if (namespace.length > 64 || !namespacePattern.test(namespace)) {
        throw new WebLockOwnedStorageError(
            'InvalidConfiguration',
            'storage namespace must be lowercase kebab-case with at most 64 characters.',
        );
    }

    return textEncoder.encode(namespace);
};

/**
 * Returns a collision-free lock name for the bounded database and namespace
 * byte strings. Encoding both fields prevents one namespace from blocking an
 * unrelated IndexedDB database while preserving same-origin coordination.
 */
export const deriveWebLockStorageNamespaceName = (input: {
    databaseName: string;
    namespace: string;
}): string => {
    const databaseNameBytes = assertDatabaseName(input.databaseName);
    const namespaceBytes = assertNamespace(input.namespace);

    return `${lockNamePrefix}${bytesToHex(databaseNameBytes)}-${bytesToHex(
        namespaceBytes,
    )}`;
};

const normalizeError = (
    error: unknown,
    code: WebLockOwnedStorageErrorCode,
    message: string,
): WebLockOwnedStorageError =>
    error instanceof WebLockOwnedStorageError
        ? error
        : new WebLockOwnedStorageError(code, message, error);

class OwnedStorageTransactionStore implements WebLockOwnedStorageTransactionStore {
    readonly #adapter: IndexedDbUntrustedStorageAdapter;
    readonly #attachedCustodies = new Set<BrowserActionStorageCustody>();
    readonly #namespace: string;
    readonly #releaseLock: Deferred<void>;
    #lockRequestCompletion: Promise<void> | undefined;
    #closePromise: Promise<void> | undefined;
    #state: WebLockOwnedStorageState = 'open';
    public readonly repairReport: UntrustedStorageRepairReport;
    public readonly store: UntrustedStorageTransactionStore;

    public constructor(input: {
        adapter: IndexedDbUntrustedStorageAdapter;
        namespace: string;
        repairReport: UntrustedStorageRepairReport;
        releaseLock: Deferred<void>;
        store: UntrustedStorageTransactionStore;
    }) {
        this.#adapter = input.adapter;
        this.#namespace = input.namespace;
        this.#releaseLock = input.releaseLock;
        this.repairReport = input.repairReport;
        this.store = input.store;
    }

    public attachBrowserActionStorageCustody(input: {
        binding: BrowserActionStorageRootBinding;
        cryptoProvider?: Crypto;
        knownStorageRootCommitment?: Uint8Array;
        workerKernel: BrowserActionStorageWorkerKernel;
    }): BrowserActionStorageCustody {
        if (this.#state !== 'open') {
            throw new WebLockOwnedStorageError(
                'OpenFailed',
                'Browser action-storage custody cannot be attached after ownership closes.',
            );
        }
        const custody = createBrowserActionStorageCustodyForOwnedWorker({
            assertExclusiveOwnership: () => {
                if (this.#state !== 'open') {
                    throw new WebLockOwnedStorageError(
                        'LockCallbackExited',
                        'Exclusive browser storage ownership is no longer held.',
                    );
                }
            },
            binding: input.binding,
            cryptoProvider: input.cryptoProvider,
            knownStorageRootCommitment: input.knownStorageRootCommitment,
            storage: this.#adapter.createDeviceWrappingStateStorage({
                binding: input.binding,
                namespace: this.#namespace,
            }),
            workerKernel: input.workerKernel,
        });
        this.#attachedCustodies.add(custody);

        return custody;
    }

    public attachLockRequestCompletion(completion: Promise<void>): void {
        if (this.#lockRequestCompletion !== undefined) {
            throw new WebLockOwnedStorageError(
                'OpenFailed',
                'Web Lock request completion was attached more than once.',
            );
        }
        this.#lockRequestCompletion = completion;
    }

    public waitForRelease(): Promise<void> {
        return this.#releaseLock.promise;
    }

    public state(): WebLockOwnedStorageState {
        return this.#state;
    }

    public close(): Promise<void> {
        if (this.#closePromise !== undefined) {
            return this.#closePromise;
        }
        if (this.#state === 'closed') {
            return Promise.resolve();
        }
        if (this.#lockRequestCompletion === undefined) {
            return Promise.reject(
                new WebLockOwnedStorageError(
                    'OpenFailed',
                    'Web Lock request completion is unavailable during close.',
                ),
            );
        }

        this.#state = 'closing';
        this.#closePromise = (async () => {
            const closeFailures: unknown[] = [];
            try {
                await this.#closeAttachedCustodies();
            } catch (error) {
                closeFailures.push(error);
            }
            const adapterClose = this.#adapter.close();
            this.#releaseLock.resolve(undefined);
            try {
                await this.#lockRequestCompletion;
            } catch (error) {
                closeFailures.push(error);
            }
            try {
                await adapterClose;
            } catch (error) {
                closeFailures.push(error);
            }
            if (closeFailures.length === 0) {
                this.#state = 'closed';
                return;
            }
            this.#state = 'failed';
            throw closeFailures.length === 1
                ? normalizeError(
                      closeFailures[0],
                      'LockCallbackExited',
                      'The Web Lock callback exited before an orderly close completed.',
                  )
                : new WebLockOwnedStorageError(
                      'LockCallbackExited',
                      'Multiple failures occurred while closing exclusive browser storage ownership.',
                      closeFailures,
                  );
        })();
        void this.#closePromise.catch(() => undefined);

        return this.#closePromise;
    }

    public fail(error: WebLockOwnedStorageError): void {
        if (this.#state === 'closed' || this.#state === 'failed') {
            return;
        }
        this.#state = 'failed';
        const lockRequestCompletion = this.#lockRequestCompletion;
        this.#closePromise ??= (async () => {
            const failures: unknown[] = [error];
            try {
                await this.#closeAttachedCustodies();
            } catch (closeError) {
                failures.push(closeError);
            }
            const adapterClose = this.#adapter.close();
            this.#releaseLock.resolve(undefined);
            if (lockRequestCompletion !== undefined) {
                try {
                    await lockRequestCompletion;
                } catch (completionError) {
                    if (completionError !== error) {
                        failures.push(completionError);
                    }
                }
            }
            try {
                await adapterClose;
            } catch (adapterCloseError) {
                failures.push(adapterCloseError);
            }
            throw failures.length === 1
                ? error
                : new WebLockOwnedStorageError(
                      'LockCallbackExited',
                      'Exclusive storage ownership failed with additional completion or cleanup failures.',
                      failures,
                  );
        })();
        void this.#closePromise.catch(() => undefined);
    }

    public noteLockCallbackExit(): void {
        if (this.#state !== 'open') {
            return;
        }
        this.fail(
            new WebLockOwnedStorageError(
                'LockCallbackExited',
                'The Web Lock callback exited while the storage handle was open.',
            ),
        );
    }

    async #closeAttachedCustodies(): Promise<void> {
        const closeOutcomes = await Promise.allSettled(
            [...this.#attachedCustodies].map((custody) => custody.close()),
        );
        this.#attachedCustodies.clear();
        const failures = closeOutcomes
            .filter(
                (outcome): outcome is PromiseRejectedResult =>
                    outcome.status === 'rejected',
            )
            .map((outcome) => outcome.reason as unknown);
        if (failures.length > 0) {
            throw new WebLockOwnedStorageError(
                'LockCallbackExited',
                'One or more browser action-storage custody roots could not be destroyed.',
                failures,
            );
        }
    }
}

const resolveLockManager = (
    configuredLockManager: LockManager | null | undefined,
): LockManager => {
    const lockManager =
        configuredLockManager === undefined
            ? globalThis.navigator?.locks
            : configuredLockManager;
    if (lockManager === undefined || lockManager === null) {
        throw new WebLockOwnedStorageError(
            'Unavailable',
            'The Web Locks API is required for exclusive browser storage repair.',
        );
    }

    return lockManager;
};

const createAcquisitionAbortController = (configuration: {
    acquisitionDeadlineEpochMilliseconds?: number;
    acquisitionSignal?: AbortSignal;
}): Readonly<{
    controller: AbortController;
    dispose(): void;
}> => {
    const controller = new AbortController();
    const externalSignal = configuration.acquisitionSignal;
    let deadlineTimer: ReturnType<typeof setTimeout> | undefined;
    let remainingDeadlineMilliseconds: number | undefined;
    const deadline = configuration.acquisitionDeadlineEpochMilliseconds;
    if (deadline !== undefined) {
        if (!Number.isSafeInteger(deadline) || deadline < 0) {
            throw new WebLockOwnedStorageError(
                'InvalidConfiguration',
                'acquisitionDeadlineEpochMilliseconds must be a non-negative safe integer.',
            );
        }
        remainingDeadlineMilliseconds = deadline - Date.now();
        if (
            remainingDeadlineMilliseconds >
            maximumLockAcquisitionDelayMilliseconds
        ) {
            throw new WebLockOwnedStorageError(
                'InvalidConfiguration',
                `the acquisition deadline must be within ${maximumLockAcquisitionDelayMilliseconds} milliseconds.`,
            );
        }
    }
    const abortForExternalSignal = (): void => {
        controller.abort(
            new WebLockOwnedStorageError(
                'AcquisitionCancelled',
                'Web Lock storage acquisition was cancelled while queued.',
                externalSignal?.reason,
            ),
        );
    };

    if (externalSignal?.aborted === true) {
        abortForExternalSignal();
    } else {
        externalSignal?.addEventListener('abort', abortForExternalSignal, {
            once: true,
        });
    }

    if (remainingDeadlineMilliseconds !== undefined) {
        const abortForDeadline = (): void => {
            controller.abort(
                new WebLockOwnedStorageError(
                    'AcquisitionDeadlineExceeded',
                    'Web Lock storage acquisition exceeded its deadline while queued.',
                ),
            );
        };
        if (remainingDeadlineMilliseconds <= 0) {
            abortForDeadline();
        } else {
            deadlineTimer = setTimeout(
                abortForDeadline,
                remainingDeadlineMilliseconds,
            );
        }
    }

    return {
        controller,
        dispose: () => {
            externalSignal?.removeEventListener(
                'abort',
                abortForExternalSignal,
            );
            if (deadlineTimer !== undefined) {
                clearTimeout(deadlineTimer);
                deadlineTimer = undefined;
            }
        },
    };
};

const normalizeLockRequestFailure = (
    error: unknown,
    acquisitionSignal: AbortSignal,
): WebLockOwnedStorageError => {
    if (error instanceof WebLockOwnedStorageError) {
        return error;
    }
    if (acquisitionSignal.reason instanceof WebLockOwnedStorageError) {
        return acquisitionSignal.reason;
    }

    return new WebLockOwnedStorageError(
        'LockCallbackExited',
        'The exclusive Web Lock request failed.',
        error,
    );
};

const openWebLockOwnedStorageTransactionStoreWithFactory = async (
    configuration: WebLockOwnedStorageBaseConfiguration,
    openTransactionStore: (
        adapter: UntrustedStorageAdapter,
    ) => Promise<UntrustedStorageTransactionStoreOpenResult>,
): Promise<WebLockOwnedStorageTransactionStore> => {
    const lockName = deriveWebLockStorageNamespaceName(configuration);
    const lockManager = resolveLockManager(configuration.lockManager);
    const acquisition = createAcquisitionAbortController(configuration);
    if (acquisition.controller.signal.aborted) {
        acquisition.dispose();
        throw normalizeLockRequestFailure(
            acquisition.controller.signal.reason,
            acquisition.controller.signal,
        );
    }

    const acquiredHandle =
        createDeferred<WebLockOwnedStorageTransactionStore>();
    let activeAdapter: IndexedDbUntrustedStorageAdapter | undefined;
    let lockRequestFailure: WebLockOwnedStorageError | undefined;
    let lockWasGranted = false;
    let ownedHandle: OwnedStorageTransactionStore | undefined;
    let lockRequestCompletion: Promise<void> | undefined;
    const assertLockRequestStillHeld = (): void => {
        const failure = lockRequestFailure;
        if (failure !== undefined) {
            throw failure;
        }
    };
    try {
        lockRequestCompletion = lockManager.request(
            lockName,
            {
                mode: 'exclusive',
                signal: acquisition.controller.signal,
            },
            async (lock) => {
                lockWasGranted = true;
                acquisition.dispose();
                if (lock?.name !== lockName || lock.mode !== 'exclusive') {
                    throw new WebLockOwnedStorageError(
                        'OpenFailed',
                        'The Web Locks API did not grant the requested exclusive namespace lock.',
                    );
                }
                let adapter: IndexedDbUntrustedStorageAdapter | undefined;
                try {
                    adapter = await openIndexedDbUntrustedStorageAdapter({
                        databaseName: configuration.databaseName,
                        indexedDbFactory: configuration.indexedDbFactory,
                        keyRangeFactory: configuration.keyRangeFactory,
                    });
                    activeAdapter = adapter;
                    assertLockRequestStillHeld();
                    const openedStore = await openTransactionStore(adapter);
                    assertLockRequestStillHeld();
                    const releaseLock = createDeferred<void>();
                    ownedHandle = new OwnedStorageTransactionStore({
                        adapter,
                        namespace: configuration.namespace,
                        repairReport: openedStore.repairReport,
                        releaseLock,
                        store: openedStore.store,
                    });
                    if (lockRequestCompletion === undefined) {
                        throw new WebLockOwnedStorageError(
                            'OpenFailed',
                            'The Web Lock request was not initialized before acquisition.',
                        );
                    }
                    ownedHandle.attachLockRequestCompletion(
                        lockRequestCompletion,
                    );
                    acquiredHandle.resolve(ownedHandle);
                    await ownedHandle.waitForRelease();
                } catch (error) {
                    const openFailure = normalizeError(
                        error,
                        'OpenFailed',
                        'Opening the exclusively owned browser storage failed.',
                    );
                    acquiredHandle.reject(openFailure);
                    throw openFailure;
                } finally {
                    if (adapter !== undefined) {
                        await adapter.close();
                    }
                    if (activeAdapter === adapter) {
                        activeAdapter = undefined;
                    }
                    ownedHandle?.noteLockCallbackExit();
                }
            },
        );
    } catch (error) {
        acquisition.dispose();
        throw normalizeError(
            error,
            'OpenFailed',
            'Submitting the exclusive Web Lock request failed.',
        );
    }

    void lockRequestCompletion.catch((error: unknown) => {
        acquisition.dispose();
        const failure = lockWasGranted
            ? normalizeError(
                  error,
                  'LockCallbackExited',
                  'The exclusive Web Lock request failed after acquisition.',
              )
            : normalizeLockRequestFailure(error, acquisition.controller.signal);
        lockRequestFailure = failure;
        acquiredHandle.reject(failure);
        if (ownedHandle === undefined) {
            void activeAdapter?.close();
        } else {
            ownedHandle.fail(failure);
        }
    });

    return acquiredHandle.promise;
};

export const openWebLockOwnedStorageTransactionStore = async (
    configuration: WebLockOwnedStorageConfiguration,
): Promise<WebLockOwnedStorageTransactionStore> =>
    openWebLockOwnedStorageTransactionStoreWithFactory(
        configuration,
        (adapter) =>
            openUntrustedStorageTransactionStore({
                adapter,
                authenticatedRepairProtection:
                    configuration.authenticatedRepairProtection,
                limits: configuration.limits,
                namespace: configuration.namespace,
            }),
    );

/**
 * Opens browser action-storage custody inside a dedicated worker and retains
 * its IndexedDB connection and cryptographic kernel under one exclusive Web
 * Lock. The returned surface contains no generic storage adapter or key-bearing
 * state.
 */
export const openWebLockOwnedBrowserActionStorageCustody = async (
    configuration: WebLockOwnedBrowserActionStorageCustodyConfiguration,
): Promise<WebLockOwnedBrowserActionStorageCustody> => {
    if (typeof globalThis.document !== 'undefined') {
        throw new WebLockOwnedStorageError(
            'Unavailable',
            'Browser action-storage custody must be opened inside a dedicated worker.',
        );
    }
    const ownedStorage =
        await openWebLockOwnedStorageTransactionStoreWithFactory(
            configuration,
            (adapter) =>
                openPositivelyVerifiedStorageTransactionStore({
                    adapter,
                    limits: configuration.limits,
                    namespace: configuration.namespace,
                }),
        );
    if (!(ownedStorage instanceof OwnedStorageTransactionStore)) {
        await ownedStorage.close();
        throw new WebLockOwnedStorageError(
            'OpenFailed',
            'The exclusive storage owner could not attach browser action-storage custody.',
        );
    }
    try {
        const custody = ownedStorage.attachBrowserActionStorageCustody({
            binding: configuration.binding,
            cryptoProvider: configuration.cryptoProvider,
            knownStorageRootCommitment:
                configuration.knownStorageRootCommitment,
            workerKernel: configuration.workerKernel,
        });

        return Object.freeze({
            close: () => ownedStorage.close(),
            custody,
            state: () => ownedStorage.state(),
        });
    } catch (error) {
        let closeFailure: unknown;
        try {
            await ownedStorage.close();
        } catch (cleanupError) {
            closeFailure = cleanupError;
        }
        if (closeFailure !== undefined) {
            throw new WebLockOwnedStorageError(
                'OpenFailed',
                'Attaching browser action-storage custody failed and ownership cleanup also failed.',
                [error, closeFailure],
            );
        }
        throw normalizeError(
            error,
            'OpenFailed',
            'Attaching browser action-storage custody to exclusive storage ownership failed.',
        );
    }
};
