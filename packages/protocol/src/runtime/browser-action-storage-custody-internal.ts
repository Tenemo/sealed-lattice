import {
    BrowserActionStorageCustodyError,
    browserActionStorageCustodyErrorCodes,
    type BrowserActionProofAttemptBinding,
    type BrowserActionRandomnessRecordContext,
    type BrowserActionRandomnessReservationVerificationInput,
    type BrowserActionStateReservationVerificationInput,
    type BrowserActionStateVerifierSessionInput,
    type BrowserOpenedActionRandomnessSession,
    type BrowserSealedActionRandomnessSession,
    type BrowserTargetReleaseAttemptInput,
    type BrowserActionStorageCustodyErrorCode,
    type BrowserActionStorageRootBinding,
    type BrowserActionStorageWorkerKernel,
    type BrowserLocalRecordIdentifierInput,
    type BrowserLocalRecordOpenInput,
    type BrowserLocalRecordSealInput,
    type UntrustedExpectedStorageRootCommitment,
    type WorkerPreparedBrowserFoundationInitialization,
    type WorkerBrowserFoundationInitializationPreparationInput,
    type WorkerPreparedDeviceWrappingState,
    type VerificationResult,
} from '@sealed-lattice/types';

import {
    copyActionProofAttemptBinding,
    copyActionRandomnessReservationVerificationInput,
    copyActionStateReservationVerificationInput,
    copyActionStateVerifierSessionInput,
    copyCreateAndSealActionRandomnessInput,
    copyOpenedActionRandomnessSession,
    copyOpaqueWorkerIdentifier,
    copyOpenSealedActionRandomnessInput,
    copySealedActionRandomnessSession,
    copyTargetReleaseAttemptInput,
    copyWorkerIdentifierVerificationResult,
} from './browser-action-cryptography-validation.js';
import type {
    BrowserActionStorageCustody,
    BrowserDeviceWrappingSnapshot,
    PreparedBrowserFoundationInitialization,
} from './browser-action-storage-custody.js';
import {
    copyWorkerBrowserFoundationInitializationPreparationInput,
    createPreparedBrowserFoundationInitialization,
    destroyWorkerPreparedBrowserFoundationInitialization,
} from './browser-foundation-initialization.js';
import {
    copyLocalRecordBytes,
    copyLocalRecordIdentifierInput,
    copyLocalRecordOpenInput,
    copyLocalRecordSealInput,
} from './browser-local-record-validation.js';

export type {
    BrowserActionStorageWorkerKernel,
    WorkerPreparedDeviceWrappingState,
} from '@sealed-lattice/types';

export type BrowserActionStorageCustodyForOwnedWorker =
    BrowserActionStorageCustody &
        Readonly<{
            prepareBrowserFoundationInitialization(
                input: WorkerBrowserFoundationInitializationPreparationInput,
            ): Promise<PreparedBrowserFoundationInitialization>;
        }>;

const deviceWrappingMutationIdentifierByteLength = 32;
const foundationHashByteLength = 64;
const maximumWrappedStorageRootByteLength = 492;

export type BrowserDeviceWrappingState = Readonly<{
    deviceKey: CryptoKey;
    mutationIdentifier: Uint8Array;
    storageRootCommitment: Uint8Array;
    wrappedStorageRoot: Uint8Array;
}>;

export type BrowserDeviceWrappingRetirementTombstone = Readonly<{
    mutationIdentifier: Uint8Array;
    recordKind: 'retirementTombstone';
}>;

export type BrowserDeviceWrappingRecord =
    | BrowserDeviceWrappingState
    | BrowserDeviceWrappingRetirementTombstone;

export type BrowserDeviceWrappingStateMutation = Readonly<{
    expectedMutationIdentifier: Uint8Array | undefined;
    replacement: BrowserDeviceWrappingRecord | undefined;
}>;

export type BrowserDeviceWrappingStateStorage = Readonly<{
    readState(): Promise<BrowserDeviceWrappingRecord | undefined>;
    compareAndSwapState(
        mutation: BrowserDeviceWrappingStateMutation,
    ): Promise<boolean>;
}>;

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean => {
    if (left.byteLength !== right.byteLength) {
        return false;
    }
    let difference = 0;
    for (let byteIndex = 0; byteIndex < left.byteLength; byteIndex += 1) {
        difference |= left[byteIndex] ^ right[byteIndex];
    }

    return difference === 0;
};

const copyBytes = (
    value: Uint8Array,
    byteLength: number | undefined,
    errorCode: 'InvalidInput' | 'InvalidState',
    label: string,
): Uint8Array => {
    if (!(value instanceof Uint8Array)) {
        throw new BrowserActionStorageCustodyError(
            errorCode,
            `${label} must be a Uint8Array.`,
        );
    }
    if (byteLength !== undefined && value.byteLength !== byteLength) {
        throw new BrowserActionStorageCustodyError(
            errorCode,
            `${label} must contain exactly ${byteLength} bytes.`,
        );
    }
    try {
        return value.slice();
    } catch (error) {
        throw new BrowserActionStorageCustodyError(
            errorCode,
            `${label} could not be copied.`,
            error,
        );
    }
};

const copyStorageRootBinding = (
    binding: BrowserActionStorageRootBinding,
    errorCode: 'InvalidInput' | 'InvalidState' = 'InvalidInput',
): BrowserActionStorageRootBinding => {
    if (typeof binding !== 'object' || binding === null) {
        throw new BrowserActionStorageCustodyError(
            errorCode,
            'The browser action-storage root binding must be an object.',
        );
    }

    return Object.freeze({
        actionContextHash: copyBytes(
            binding.actionContextHash,
            foundationHashByteLength,
            errorCode,
            'Action-context hash',
        ),
        ceremonyContextHash: copyBytes(
            binding.ceremonyContextHash,
            foundationHashByteLength,
            errorCode,
            'Ceremony-context hash',
        ),
        participantId: copyBytes(
            binding.participantId,
            foundationHashByteLength,
            errorCode,
            'Participant identity',
        ),
        suiteId: copyBytes(
            binding.suiteId,
            foundationHashByteLength,
            errorCode,
            'Suite identifier',
        ),
    });
};

const copyUntrustedExpectedCommitment = (
    value: UntrustedExpectedStorageRootCommitment,
    errorCode: 'InvalidInput' | 'InvalidState' = 'InvalidInput',
): UntrustedExpectedStorageRootCommitment => {
    if (typeof value !== 'object' || value === null) {
        throw new BrowserActionStorageCustodyError(
            errorCode,
            'The untrusted expected storage-root commitment must be an object.',
        );
    }

    return Object.freeze({
        storageRootCommitment: copyBytes(
            value.storageRootCommitment,
            foundationHashByteLength,
            errorCode,
            'Untrusted expected storage-root commitment',
        ),
    });
};

const assertDeviceKey = (deviceKey: CryptoKey): void => {
    const algorithm = deviceKey?.algorithm as AesKeyAlgorithm | undefined;
    const usages = deviceKey?.usages;
    if (
        deviceKey?.type !== 'secret' ||
        deviceKey.extractable !== false ||
        algorithm?.name !== 'AES-GCM' ||
        algorithm.length !== 256 ||
        !Array.isArray(usages) ||
        usages.length !== 2 ||
        !usages.includes('encrypt') ||
        !usages.includes('decrypt')
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidState',
            'Device custody requires a non-extractable 256-bit AES-GCM key with only encrypt and decrypt usages.',
        );
    }
};

export const copyBrowserDeviceWrappingState = (
    state: BrowserDeviceWrappingState,
    errorCode: 'InvalidInput' | 'InvalidState' = 'InvalidState',
): BrowserDeviceWrappingState => {
    if (typeof state !== 'object' || state === null) {
        throw new BrowserActionStorageCustodyError(
            errorCode,
            'Device-wrapping state must be an object.',
        );
    }
    assertDeviceKey(state.deviceKey);
    const mutationIdentifier = copyBytes(
        state.mutationIdentifier,
        deviceWrappingMutationIdentifierByteLength,
        errorCode,
        'Device-wrapping mutation identifier',
    );
    const wrappedStorageRoot = copyBytes(
        state.wrappedStorageRoot,
        undefined,
        errorCode,
        'Wrapped storage-root envelope',
    );
    if (
        wrappedStorageRoot.byteLength === 0 ||
        wrappedStorageRoot.byteLength > maximumWrappedStorageRootByteLength
    ) {
        throw new BrowserActionStorageCustodyError(
            errorCode,
            `Wrapped storage-root envelope must contain 1 through ${maximumWrappedStorageRootByteLength} bytes.`,
        );
    }
    const storageRootCommitment = copyBytes(
        state.storageRootCommitment,
        foundationHashByteLength,
        errorCode,
        'Stored storage-root commitment',
    );

    return Object.freeze({
        deviceKey: state.deviceKey,
        mutationIdentifier,
        storageRootCommitment,
        wrappedStorageRoot,
    });
};

export const isBrowserDeviceWrappingRetirementTombstone = (
    record: BrowserDeviceWrappingRecord,
): record is BrowserDeviceWrappingRetirementTombstone =>
    'recordKind' in record && record.recordKind === 'retirementTombstone';

export const copyBrowserDeviceWrappingRetirementTombstone = (
    tombstone: BrowserDeviceWrappingRetirementTombstone,
    errorCode: 'InvalidInput' | 'InvalidState' = 'InvalidState',
): BrowserDeviceWrappingRetirementTombstone => {
    if (
        typeof tombstone !== 'object' ||
        tombstone === null ||
        tombstone.recordKind !== 'retirementTombstone'
    ) {
        throw new BrowserActionStorageCustodyError(
            errorCode,
            'Device-wrapping retirement tombstone is malformed.',
        );
    }
    return Object.freeze({
        mutationIdentifier: copyBytes(
            tombstone.mutationIdentifier,
            deviceWrappingMutationIdentifierByteLength,
            errorCode,
            'Device-wrapping retirement mutation identifier',
        ),
        recordKind: 'retirementTombstone' as const,
    });
};

export const copyBrowserDeviceWrappingRecord = (
    record: BrowserDeviceWrappingRecord,
    errorCode: 'InvalidInput' | 'InvalidState' = 'InvalidState',
): BrowserDeviceWrappingRecord =>
    isBrowserDeviceWrappingRetirementTombstone(record)
        ? copyBrowserDeviceWrappingRetirementTombstone(record, errorCode)
        : copyBrowserDeviceWrappingState(record, errorCode);

const copyPreparedState = (
    preparedState: WorkerPreparedDeviceWrappingState,
): WorkerPreparedDeviceWrappingState => {
    assertDeviceKey(preparedState.deviceKey);
    const wrappedStorageRoot = copyBytes(
        preparedState.wrappedStorageRoot,
        undefined,
        'InvalidState',
        'Worker-prepared wrapped storage-root envelope',
    );
    if (
        wrappedStorageRoot.byteLength === 0 ||
        wrappedStorageRoot.byteLength > maximumWrappedStorageRootByteLength
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidState',
            `Worker-prepared wrapped storage-root envelope must contain 1 through ${maximumWrappedStorageRootByteLength} bytes.`,
        );
    }

    const storageRootCommitment = copyBytes(
        preparedState.storageRootCommitment,
        foundationHashByteLength,
        'InvalidState',
        'Worker-derived storage-root commitment',
    );

    return {
        deviceKey: preparedState.deviceKey,
        storageRootCommitment,
        wrappedStorageRoot,
    };
};

const copySnapshot = (
    snapshot: BrowserDeviceWrappingSnapshot,
): BrowserDeviceWrappingSnapshot => {
    if (typeof snapshot !== 'object' || snapshot === null) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'Device custody snapshot must be an object.',
        );
    }
    return Object.freeze({
        mutationIdentifier: copyBytes(
            snapshot.mutationIdentifier,
            deviceWrappingMutationIdentifierByteLength,
            'InvalidInput',
            'Device custody snapshot mutation identifier',
        ),
        storageRootCommitment: copyBytes(
            snapshot.storageRootCommitment,
            foundationHashByteLength,
            'InvalidInput',
            'Snapshot storage-root commitment',
        ),
    });
};

const snapshotFromState = (
    state: BrowserDeviceWrappingState,
): BrowserDeviceWrappingSnapshot =>
    Object.freeze({
        mutationIdentifier: state.mutationIdentifier.slice(),
        storageRootCommitment: state.storageRootCommitment.slice(),
    });

const stateMatchesSnapshot = (
    state: BrowserDeviceWrappingState,
    snapshot: BrowserDeviceWrappingSnapshot,
): boolean =>
    bytesEqual(state.mutationIdentifier, snapshot.mutationIdentifier) &&
    bytesEqual(state.storageRootCommitment, snapshot.storageRootCommitment);

const isBrowserActionStorageCustodyError = (
    error: unknown,
): error is BrowserActionStorageCustodyError =>
    error instanceof BrowserActionStorageCustodyError ||
    (error instanceof Error &&
        error.name === 'BrowserActionStorageCustodyError' &&
        'code' in error &&
        typeof error.code === 'string' &&
        browserActionStorageCustodyErrorCodes.includes(
            error.code as BrowserActionStorageCustodyErrorCode,
        ) &&
        'failureCause' in error);

const normalizeFailure = (
    error: unknown,
    code: 'OwnedWorkerFailure' | 'StorageFailure',
    message: string,
): BrowserActionStorageCustodyError =>
    isBrowserActionStorageCustodyError(error)
        ? error
        : new BrowserActionStorageCustodyError(code, message, error);

const normalizeInputError = (error: unknown): Error =>
    error instanceof Error
        ? error
        : new BrowserActionStorageCustodyError(
              'InvalidInput',
              'Browser action-storage custody input validation failed.',
              error,
          );

class OwnedWorkerBrowserActionStorageCustody implements BrowserActionStorageCustody {
    readonly #assertExclusiveOwnership: () => void;
    readonly #binding: BrowserActionStorageRootBinding;
    readonly #cryptoProvider: Crypto;
    readonly #storage: BrowserDeviceWrappingStateStorage;
    readonly #workerKernel: BrowserActionStorageWorkerKernel;
    #expectedStorageRootCommitment: Uint8Array | undefined;
    #closed = false;
    #closing = false;
    #closePromise: Promise<void> | undefined;
    #operationTail: Promise<void> = Promise.resolve();

    public constructor(input: {
        assertExclusiveOwnership: () => void;
        binding: BrowserActionStorageRootBinding;
        cryptoProvider: Crypto;
        knownStorageRootCommitment?: Uint8Array;
        storage: BrowserDeviceWrappingStateStorage;
        workerKernel: BrowserActionStorageWorkerKernel;
    }) {
        this.#assertExclusiveOwnership = input.assertExclusiveOwnership;
        this.#binding = copyStorageRootBinding(input.binding);
        this.#cryptoProvider = input.cryptoProvider;
        this.#storage = input.storage;
        this.#workerKernel = input.workerKernel;
        this.#expectedStorageRootCommitment =
            input.knownStorageRootCommitment === undefined
                ? undefined
                : copyBytes(
                      input.knownStorageRootCommitment,
                      foundationHashByteLength,
                      'InvalidInput',
                      'Known storage-root commitment',
                  );
    }

    public copyBinding(): BrowserActionStorageRootBinding {
        return copyStorageRootBinding(this.#binding, 'InvalidState');
    }

    public initialize(): Promise<BrowserDeviceWrappingSnapshot> {
        return this.#runOperation(async () => {
            if (this.#expectedStorageRootCommitment !== undefined) {
                throw new BrowserActionStorageCustodyError(
                    'CommitmentRequired',
                    'Fresh initialization is forbidden after an expected storage-root commitment is known.',
                );
            }
            const existingRecord = await this.#readRecord();
            if (existingRecord !== undefined) {
                throw new BrowserActionStorageCustodyError(
                    isBrowserDeviceWrappingRetirementTombstone(existingRecord)
                        ? 'Unavailable'
                        : 'Conflict',
                    isBrowserDeviceWrappingRetirementTombstone(existingRecord)
                        ? 'This participant is permanently retired for the action on this browser.'
                        : 'Browser action-storage custody is already initialized.',
                );
            }
            const preparedState = await this.#workerCall(
                () =>
                    this.#workerKernel.createAndStageDeviceWrappingState({
                        binding: copyStorageRootBinding(this.#binding),
                    }),
                'Creating browser action-storage custody failed inside the owned worker.',
            );
            let stateWasPublished = false;
            try {
                const copiedPreparedState = copyPreparedState(preparedState);
                const replacement = this.#makeState(copiedPreparedState);
                await this.#compareAndSwapOrConflict({
                    expectedMutationIdentifier: undefined,
                    replacement,
                });
                stateWasPublished = true;

                return snapshotFromState(replacement);
            } catch (error) {
                await this.#cleanRootAfterFailedPublication(
                    stateWasPublished,
                    error,
                );
                throw error;
            }
        });
    }

    public currentSnapshot(): Promise<
        BrowserDeviceWrappingSnapshot | undefined
    > {
        return this.#runOperation(async () => {
            const state = await this.#readRecord();

            if (
                state !== undefined &&
                isBrowserDeviceWrappingRetirementTombstone(state)
            ) {
                throw new BrowserActionStorageCustodyError(
                    'Unavailable',
                    'This participant is permanently retired for the action on this browser.',
                );
            }

            return state === undefined ? undefined : snapshotFromState(state);
        });
    }

    public openIntoOwnedWorker(input: {
        expectedSnapshot: BrowserDeviceWrappingSnapshot;
        untrustedExpectedCommitment: UntrustedExpectedStorageRootCommitment;
    }): Promise<void> {
        let copiedSnapshot: BrowserDeviceWrappingSnapshot;
        let copiedCommitment: UntrustedExpectedStorageRootCommitment;
        try {
            copiedSnapshot = copySnapshot(input.expectedSnapshot);
            copiedCommitment = copyUntrustedExpectedCommitment(
                input.untrustedExpectedCommitment,
            );
        } catch (error) {
            return Promise.reject(normalizeInputError(error));
        }

        return this.#runOperation(async () => {
            const state = await this.#readExpectedState(copiedSnapshot);
            await this.#activateState(state, copiedCommitment);
        });
    }

    public delete(
        expectedSnapshot: BrowserDeviceWrappingSnapshot,
    ): Promise<void> {
        let copiedSnapshot: BrowserDeviceWrappingSnapshot;
        try {
            copiedSnapshot = copySnapshot(expectedSnapshot);
        } catch (error) {
            return Promise.reject(normalizeInputError(error));
        }

        return this.#runOperation(async () => {
            const state = await this.#readExpectedState(copiedSnapshot);
            await this.#destroyActiveAndStagedRoots();
            await this.#compareAndSwapOrConflict({
                expectedMutationIdentifier: state.mutationIdentifier,
                replacement: undefined,
            });
        });
    }

    public retire(): Promise<void> {
        return this.#runOperation(async () => {
            const existingRecord = await this.#readRecord();
            if (
                existingRecord === undefined ||
                !isBrowserDeviceWrappingRetirementTombstone(existingRecord)
            ) {
                await this.#compareAndSwapOrConflict({
                    expectedMutationIdentifier:
                        existingRecord?.mutationIdentifier,
                    replacement: {
                        mutationIdentifier: this.#randomBytes(
                            deviceWrappingMutationIdentifierByteLength,
                        ),
                        recordKind: 'retirementTombstone',
                    },
                });
            }
            await this.#destroyActiveAndStagedRoots();
            this.#expectedStorageRootCommitment?.fill(0);
            this.#expectedStorageRootCommitment = undefined;
        });
    }

    public deriveLocalRecordIdentifier(
        input: BrowserLocalRecordIdentifierInput,
    ): Promise<Uint8Array> {
        let copiedInput: BrowserLocalRecordIdentifierInput;
        try {
            copiedInput = copyLocalRecordIdentifierInput(input);
        } catch (error) {
            return Promise.reject(normalizeInputError(error));
        }

        return this.#runOperation(async () => {
            const identifier = await this.#workerCall(
                () =>
                    this.#workerKernel.deriveActiveLocalRecordIdentifier(
                        copiedInput,
                    ),
                'Deriving a local-record identifier failed inside the owned worker.',
            );

            return copyLocalRecordBytes(identifier, {
                allowEmpty: false,
                errorCode: 'OwnedWorkerFailure',
                exactByteLength: foundationHashByteLength,
                label: 'Worker-derived local-record identifier',
            });
        });
    }

    public sealLocalRecord(
        input: BrowserLocalRecordSealInput,
    ): Promise<Uint8Array> {
        let copiedInput: BrowserLocalRecordSealInput;
        try {
            copiedInput = copyLocalRecordSealInput(input);
        } catch (error) {
            return Promise.reject(normalizeInputError(error));
        }

        return this.#runOperation(async () => {
            const envelope = await this.#workerCall(
                () => this.#workerKernel.sealActiveLocalRecord(copiedInput),
                'Sealing a local record failed inside the owned worker.',
            );

            return copyLocalRecordBytes(envelope, {
                allowEmpty: false,
                errorCode: 'OwnedWorkerFailure',
                label: 'Worker-produced local-record envelope',
            });
        });
    }

    public openLocalRecord(
        input: BrowserLocalRecordOpenInput,
    ): Promise<Uint8Array> {
        let copiedInput: BrowserLocalRecordOpenInput;
        try {
            copiedInput = copyLocalRecordOpenInput(input);
        } catch (error) {
            return Promise.reject(normalizeInputError(error));
        }

        return this.#runOperation(async () => {
            const plaintext = await this.#workerCall(
                () => this.#workerKernel.openActiveLocalRecord(copiedInput),
                'Opening a local record failed inside the owned worker.',
            );

            return copyLocalRecordBytes(plaintext, {
                allowEmpty: true,
                errorCode: 'OwnedWorkerFailure',
                label: 'Worker-opened local-record plaintext',
            });
        });
    }

    public hashLocalRecordEnvelope(envelope: Uint8Array): Promise<Uint8Array> {
        let copiedEnvelope: Uint8Array;
        try {
            copiedEnvelope = copyLocalRecordBytes(envelope, {
                allowEmpty: false,
                errorCode: 'InvalidInput',
                label: 'Local-record envelope',
            });
        } catch (error) {
            return Promise.reject(normalizeInputError(error));
        }

        return this.#runOperation(async () => {
            const envelopeHash = await this.#workerCall(
                () =>
                    this.#workerKernel.hashActiveLocalRecordEnvelope(
                        copiedEnvelope,
                    ),
                'Hashing a local-record envelope failed inside the owned worker.',
            );

            return copyLocalRecordBytes(envelopeHash, {
                allowEmpty: false,
                errorCode: 'OwnedWorkerFailure',
                exactByteLength: foundationHashByteLength,
                label: 'Worker-derived local-record envelope hash',
            });
        });
    }

    public prepareBrowserFoundationInitialization(
        input: WorkerBrowserFoundationInitializationPreparationInput,
    ): Promise<PreparedBrowserFoundationInitialization> {
        let copiedInput: WorkerBrowserFoundationInitializationPreparationInput;
        try {
            copiedInput =
                copyWorkerBrowserFoundationInitializationPreparationInput(
                    input,
                );
        } catch (error) {
            return Promise.reject(normalizeInputError(error));
        }

        return this.#runOperation(async () => {
            let workerPreparation:
                | WorkerPreparedBrowserFoundationInitialization
                | undefined;
            try {
                workerPreparation = await this.#workerCall(
                    () =>
                        this.#workerKernel.prepareBrowserFoundationInitialization(
                            copiedInput,
                        ),
                    'Preparing browser foundation initialization failed inside the owned worker.',
                );

                return createPreparedBrowserFoundationInitialization({
                    custodyBinding: this.#binding,
                    preparationInput: copiedInput,
                    workerPreparation,
                });
            } finally {
                if (workerPreparation !== undefined) {
                    destroyWorkerPreparedBrowserFoundationInitialization(
                        workerPreparation,
                    );
                }
            }
        });
    }

    public openActionStateVerifierSession(
        input: BrowserActionStateVerifierSessionInput,
    ): Promise<VerificationResult<string>> {
        let copiedInput: BrowserActionStateVerifierSessionInput;
        try {
            copiedInput = copyActionStateVerifierSessionInput(input);
        } catch (error) {
            return Promise.reject(normalizeInputError(error));
        }

        return this.#runOperation(async () =>
            copyWorkerIdentifierVerificationResult(
                await this.#workerCall(
                    () =>
                        this.#workerKernel.openActionStateVerifierSession(
                            copiedInput,
                        ),
                    'Opening an action state-verifier session failed inside the owned worker.',
                ),
            ),
        );
    }

    public verifyActionStateReservation(
        input: BrowserActionStateReservationVerificationInput,
    ): Promise<VerificationResult<string>> {
        let copiedInput: BrowserActionStateReservationVerificationInput;
        try {
            copiedInput = copyActionStateReservationVerificationInput(input);
        } catch (error) {
            return Promise.reject(normalizeInputError(error));
        }

        return this.#runOperation(async () =>
            copyWorkerIdentifierVerificationResult(
                await this.#workerCall(
                    () =>
                        this.#workerKernel.verifyActionStateReservation(
                            copiedInput,
                        ),
                    'Verifying an action state reservation failed inside the owned worker.',
                ),
            ),
        );
    }

    public verifyActionRandomnessReservation(
        input: BrowserActionRandomnessReservationVerificationInput,
    ): Promise<VerificationResult<string>> {
        let copiedInput: BrowserActionRandomnessReservationVerificationInput;
        try {
            copiedInput =
                copyActionRandomnessReservationVerificationInput(input);
        } catch (error) {
            return Promise.reject(normalizeInputError(error));
        }

        return this.#runOperation(async () =>
            copyWorkerIdentifierVerificationResult(
                await this.#workerCall(
                    () =>
                        this.#workerKernel.verifyActionRandomnessReservation(
                            copiedInput,
                        ),
                    'Verifying the action-randomness reservation failed inside the owned worker.',
                ),
            ),
        );
    }

    public releaseActionStateObject(identifier: string): Promise<void> {
        let copiedIdentifier: string;
        try {
            copiedIdentifier = copyOpaqueWorkerIdentifier(
                identifier,
                'State object identifier',
            );
        } catch (error) {
            return Promise.reject(normalizeInputError(error));
        }

        return this.#runOperation(() =>
            this.#workerCall(
                () =>
                    this.#workerKernel.releaseActionStateObject(
                        copiedIdentifier,
                    ),
                'Releasing an action state object failed inside the owned worker.',
            ),
        );
    }

    public closeActionStateVerifierSession(identifier: string): Promise<void> {
        let copiedIdentifier: string;
        try {
            copiedIdentifier = copyOpaqueWorkerIdentifier(
                identifier,
                'State-verifier session identifier',
            );
        } catch (error) {
            return Promise.reject(normalizeInputError(error));
        }

        return this.#runOperation(() =>
            this.#workerCall(
                () =>
                    this.#workerKernel.closeActionStateVerifierSession(
                        copiedIdentifier,
                    ),
                'Closing an action state-verifier session failed inside the owned worker.',
            ),
        );
    }

    public createAndSealActionRandomness(
        input: BrowserActionRandomnessRecordContext,
    ): Promise<BrowserSealedActionRandomnessSession> {
        let copiedInput: BrowserActionRandomnessRecordContext;
        try {
            copiedInput = copyCreateAndSealActionRandomnessInput(input);
        } catch (error) {
            return Promise.reject(normalizeInputError(error));
        }

        return this.#runOperation(async () =>
            copySealedActionRandomnessSession(
                await this.#workerCall(
                    () =>
                        this.#workerKernel.createAndSealActionRandomness(
                            copiedInput,
                        ),
                    'Creating and sealing action randomness failed inside the owned worker.',
                ),
            ),
        );
    }

    public openSealedActionRandomness(
        input: BrowserActionRandomnessRecordContext &
            Readonly<{
                actionRandomnessCommitment: Uint8Array;
                canonicalEnvelope: Uint8Array;
            }>,
    ): Promise<BrowserOpenedActionRandomnessSession> {
        let copiedInput: BrowserActionRandomnessRecordContext &
            Readonly<{
                actionRandomnessCommitment: Uint8Array;
                canonicalEnvelope: Uint8Array;
            }>;
        try {
            copiedInput = copyOpenSealedActionRandomnessInput(input);
        } catch (error) {
            return Promise.reject(normalizeInputError(error));
        }

        return this.#runOperation(async () =>
            copyOpenedActionRandomnessSession(
                await this.#workerCall(
                    () =>
                        this.#workerKernel.openSealedActionRandomness(
                            copiedInput,
                        ),
                    'Opening sealed action randomness failed inside the owned worker.',
                ),
            ),
        );
    }

    public closeActionRandomness(identifier: string): Promise<void> {
        let copiedIdentifier: string;
        try {
            copiedIdentifier = copyOpaqueWorkerIdentifier(
                identifier,
                'Action-randomness session identifier',
            );
        } catch (error) {
            return Promise.reject(normalizeInputError(error));
        }

        return this.#runOperation(() =>
            this.#workerCall(
                () =>
                    this.#workerKernel.closeActionRandomness(copiedIdentifier),
                'Closing action randomness failed inside the owned worker.',
            ),
        );
    }

    public deriveTargetReleaseAttempt(
        input: BrowserTargetReleaseAttemptInput,
    ): Promise<BrowserActionProofAttemptBinding> {
        let copiedInput: BrowserTargetReleaseAttemptInput;
        try {
            copiedInput = copyTargetReleaseAttemptInput(input);
        } catch (error) {
            return Promise.reject(normalizeInputError(error));
        }

        return this.#runOperation(async () =>
            copyActionProofAttemptBinding(
                await this.#workerCall(
                    () =>
                        this.#workerKernel.deriveTargetReleaseAttempt(
                            copiedInput,
                        ),
                    'Deriving target-release randomness failed inside the owned worker.',
                ),
            ),
        );
    }

    public close(): Promise<void> {
        if (this.#closePromise !== undefined) {
            return this.#closePromise;
        }
        this.#closing = true;
        this.#closePromise = this.#enqueue(async () => {
            await this.#destroyActiveAndStagedRoots();
            this.#closed = true;
        });

        return this.#closePromise;
    }

    #runOperation<Result>(operation: () => Promise<Result>): Promise<Result> {
        if (this.#closing || this.#closed) {
            return Promise.reject(
                new BrowserActionStorageCustodyError(
                    'Closed',
                    'Browser action-storage custody is closed.',
                ),
            );
        }

        return this.#enqueue(async () => {
            if (this.#closing || this.#closed) {
                throw new BrowserActionStorageCustodyError(
                    'Closed',
                    'Browser action-storage custody is closed.',
                );
            }
            try {
                this.#assertExclusiveOwnership();
            } catch (error) {
                throw normalizeFailure(
                    error,
                    'OwnedWorkerFailure',
                    'Exclusive browser storage ownership was lost.',
                );
            }

            return operation();
        });
    }

    #enqueue<Result>(operation: () => Promise<Result>): Promise<Result> {
        const result = this.#operationTail.then(operation, operation);
        this.#operationTail = result.then(
            () => undefined,
            () => undefined,
        );

        return result;
    }

    async #readRecord(): Promise<BrowserDeviceWrappingRecord | undefined> {
        try {
            const record = await this.#storage.readState();

            return record === undefined
                ? undefined
                : copyBrowserDeviceWrappingRecord(record);
        } catch (error) {
            throw normalizeFailure(
                error,
                'StorageFailure',
                'Reading browser action-storage custody failed.',
            );
        }
    }

    async #readExpectedState(
        expectedSnapshot: BrowserDeviceWrappingSnapshot,
    ): Promise<BrowserDeviceWrappingState> {
        const record = await this.#readRecord();
        if (
            record === undefined ||
            isBrowserDeviceWrappingRetirementTombstone(record)
        ) {
            throw new BrowserActionStorageCustodyError(
                'Unavailable',
                record === undefined
                    ? 'The committed browser action-storage root is not present on this device.'
                    : 'This participant is permanently retired for the action on this browser.',
            );
        }
        if (!stateMatchesSnapshot(record, expectedSnapshot)) {
            throw new BrowserActionStorageCustodyError(
                'Conflict',
                'Browser action-storage custody changed before the requested operation.',
            );
        }

        return record;
    }

    #makeState(input: {
        deviceKey: CryptoKey;
        storageRootCommitment: Uint8Array;
        wrappedStorageRoot: Uint8Array;
    }): BrowserDeviceWrappingState {
        return copyBrowserDeviceWrappingState({
            deviceKey: input.deviceKey,
            mutationIdentifier: this.#randomBytes(
                deviceWrappingMutationIdentifierByteLength,
            ),
            storageRootCommitment: input.storageRootCommitment,
            wrappedStorageRoot: input.wrappedStorageRoot,
        });
    }

    #randomBytes(byteLength: number): Uint8Array {
        const bytes = new Uint8Array(byteLength);
        try {
            this.#cryptoProvider.getRandomValues(bytes);
        } catch (error) {
            throw new BrowserActionStorageCustodyError(
                'Unavailable',
                'Secure browser randomness is unavailable.',
                error,
            );
        }

        return bytes;
    }

    async #compareAndSwapOrConflict(
        mutation: BrowserDeviceWrappingStateMutation,
    ): Promise<void> {
        let replaced: boolean;
        try {
            replaced = await this.#storage.compareAndSwapState(mutation);
        } catch (error) {
            throw normalizeFailure(
                error,
                'StorageFailure',
                'Updating browser action-storage custody failed.',
            );
        }
        if (!replaced) {
            throw new BrowserActionStorageCustodyError(
                'Conflict',
                'Browser action-storage custody changed during the requested operation.',
            );
        }
    }

    async #activateState(
        state: BrowserDeviceWrappingState,
        untrustedExpectedCommitment: UntrustedExpectedStorageRootCommitment,
    ): Promise<void> {
        this.#assertCommitmentMatches(
            state.storageRootCommitment,
            untrustedExpectedCommitment.storageRootCommitment,
        );
        if (this.#expectedStorageRootCommitment !== undefined) {
            this.#assertCommitmentMatches(
                this.#expectedStorageRootCommitment,
                untrustedExpectedCommitment.storageRootCommitment,
            );
        }
        await this.#workerCall(
            () =>
                this.#workerKernel.stageDeviceWrappingStateOpen({
                    binding: copyStorageRootBinding(this.#binding),
                    untrustedExpectedCommitment,
                    state: {
                        deviceKey: state.deviceKey,
                        storageRootCommitment:
                            state.storageRootCommitment.slice(),
                        wrappedStorageRoot: state.wrappedStorageRoot.slice(),
                    },
                }),
            'Opening the browser action-storage root failed inside the owned worker.',
        );
        try {
            await this.#commitStagedRootForPublishedState(state);
        } catch (error) {
            await this.#cleanRootAfterFailedPublication(true, error);
            throw error;
        }
        this.#expectedStorageRootCommitment =
            untrustedExpectedCommitment.storageRootCommitment.slice();
    }

    #assertCommitmentMatches(left: Uint8Array, right: Uint8Array): void {
        if (!bytesEqual(left, right)) {
            throw new BrowserActionStorageCustodyError(
                'CommitmentMismatch',
                'The expected storage-root commitment does not match local custody.',
            );
        }
    }

    async #commitStagedRootForPublishedState(
        expectedState: BrowserDeviceWrappingState,
    ): Promise<void> {
        const publishedState = await this.#readRecord();
        if (
            publishedState === undefined ||
            isBrowserDeviceWrappingRetirementTombstone(publishedState) ||
            !bytesEqual(
                publishedState.mutationIdentifier,
                expectedState.mutationIdentifier,
            ) ||
            !bytesEqual(
                publishedState.storageRootCommitment,
                expectedState.storageRootCommitment,
            )
        ) {
            throw new BrowserActionStorageCustodyError(
                'Conflict',
                'Browser action-storage custody changed before root activation.',
            );
        }
        await this.#workerCall(
            () => this.#workerKernel.commitStagedActionStorageRoot(),
            'Activating the browser action-storage root failed inside the owned worker.',
        );
    }

    async #discardStagedRoot(): Promise<void> {
        await this.#workerCall(
            () => this.#workerKernel.discardStagedActionStorageRoot(),
            'Discarding a staged browser action-storage root failed inside the owned worker.',
        );
    }

    async #cleanRootAfterFailedPublication(
        stateWasPublished: boolean,
        originalFailure: unknown,
    ): Promise<void> {
        try {
            if (stateWasPublished) {
                await this.#destroyActiveAndStagedRoots();
            } else {
                await this.#discardStagedRoot();
            }
        } catch (cleanupFailure) {
            throw new BrowserActionStorageCustodyError(
                'OwnedWorkerFailure',
                'Browser action-storage custody failed and its root cleanup also failed.',
                [originalFailure, cleanupFailure],
            );
        }
    }

    async #destroyActiveAndStagedRoots(): Promise<void> {
        let discardFailure: unknown;
        try {
            await this.#workerKernel.discardStagedActionStorageRoot();
        } catch (error) {
            discardFailure = error;
        }
        try {
            await this.#workerKernel.destroyActiveActionStorageRoot();
        } catch (error) {
            throw new BrowserActionStorageCustodyError(
                'OwnedWorkerFailure',
                'Destroying the active browser action-storage root failed inside the owned worker.',
                discardFailure === undefined ? error : [discardFailure, error],
            );
        }
        if (discardFailure !== undefined) {
            throw new BrowserActionStorageCustodyError(
                'OwnedWorkerFailure',
                'Discarding a staged browser action-storage root failed inside the owned worker.',
                discardFailure,
            );
        }
    }

    async #workerCall<Result>(
        operation: () => Promise<Result>,
        message: string,
    ): Promise<Result> {
        try {
            return await operation();
        } catch (error) {
            throw isBrowserActionStorageCustodyError(error)
                ? error
                : new BrowserActionStorageCustodyError(
                      'OwnedWorkerFailure',
                      message,
                      error,
                  );
        }
    }
}

export const createBrowserActionStorageCustodyForOwnedWorker = (input: {
    assertExclusiveOwnership: () => void;
    binding: BrowserActionStorageRootBinding;
    cryptoProvider?: Crypto;
    knownStorageRootCommitment?: Uint8Array;
    storage: BrowserDeviceWrappingStateStorage;
    workerKernel: BrowserActionStorageWorkerKernel;
}): BrowserActionStorageCustodyForOwnedWorker => {
    const cryptoProvider = input.cryptoProvider ?? globalThis.crypto;
    if (
        cryptoProvider === undefined ||
        typeof cryptoProvider.getRandomValues !== 'function'
    ) {
        throw new BrowserActionStorageCustodyError(
            'Unavailable',
            'WebCrypto is required for browser action-storage custody.',
        );
    }

    return new OwnedWorkerBrowserActionStorageCustody({
        ...input,
        cryptoProvider,
    });
};
