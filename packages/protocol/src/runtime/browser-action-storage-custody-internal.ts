import {
    BrowserActionStorageCustodyError,
    browserActionStorageCustodyErrorCodes,
    type BrowserActionProofAttemptBinding,
    type BrowserActionRandomnessRecordContext,
    type BrowserActionRandomnessReservationVerificationInput,
    type BrowserActionStateRecoveryVerificationInput,
    type BrowserActionStateReservationVerificationInput,
    type BrowserActionStateVerifierSessionInput,
    type BrowserOpenedActionRandomnessSession,
    type BrowserPersistentProofAttemptInput,
    type BrowserSealedActionRandomnessSession,
    type BrowserTargetReleaseAttemptInput,
    type BrowserActionStorageCustodyErrorCode,
    type BrowserActionStorageRootBinding,
    type BrowserActionStorageWorkerKernel,
    type BrowserLocalRecordIdentifierInput,
    type BrowserLocalRecordOpenInput,
    type BrowserLocalRecordSealInput,
    type UntrustedExpectedStorageRootCommitment,
    type WorkerPreparedDeviceWrappingState,
    type VerificationResult,
} from '@sealed-lattice/types';

import {
    copyActionProofAttemptBinding,
    copyActionRandomnessReservationVerificationInput,
    copyActionStateRecoveryVerificationInput,
    copyActionStateReservationVerificationInput,
    copyActionStateVerifierSessionInput,
    copyCreateAndSealActionRandomnessInput,
    copyOpenedActionRandomnessSession,
    copyOpaqueWorkerIdentifier,
    copyOpenSealedActionRandomnessInput,
    copyPersistentProofAttemptInput,
    copySealedActionRandomnessSession,
    copyTargetReleaseAttemptInput,
    copyWorkerIdentifierVerificationResult,
} from './browser-action-cryptography-validation.js';
import type {
    BrowserActionStorageCustody,
    BrowserDeviceWrappingSnapshot,
    BrowserRecoveryExportChallenge,
    BrowserRecoveryExportConfirmation,
} from './browser-action-storage-custody.js';
import {
    copyLocalRecordBytes,
    copyLocalRecordIdentifierInput,
    copyLocalRecordOpenInput,
    copyLocalRecordSealInput,
} from './browser-local-record-validation.js';

export type {
    BrowserActionStorageWorkerKernel,
    LocalStorageRecoveryExportMaterial,
    WorkerPreparedDeviceWrappingState,
    WorkerPreparedRecoveryState,
} from '@sealed-lattice/types';

const deviceWrappingMutationIdentifierByteLength = 32;
const foundationHashByteLength = 64;
const maximumWrappedStorageRootByteLength = 492;
const recoveryChecksumByteLength = 16;
const recoveryTextLength = 708;
const recoveryTextPattern = /^[A-Z2-7]{708}$/u;

export type BrowserDeviceWrappingState = Readonly<{
    deviceKey: CryptoKey;
    mutationIdentifier: Uint8Array;
    recoveryValueExported: boolean;
    storageRootCommitment: Uint8Array;
    wrappedStorageRoot: Uint8Array;
}>;

export type BrowserDeviceWrappingStateMutation = Readonly<{
    expectedMutationIdentifier: Uint8Array | undefined;
    replacement: BrowserDeviceWrappingState | undefined;
}>;

export type BrowserDeviceWrappingStateStorage = Readonly<{
    readState(): Promise<BrowserDeviceWrappingState | undefined>;
    compareAndSwapState(
        mutation: BrowserDeviceWrappingStateMutation,
    ): Promise<boolean>;
}>;

type PendingRecoveryExport = Readonly<{
    canonicalRecoveryText: string;
    preparationIdentifier: string;
    recoveryChecksum: Uint8Array;
    state: BrowserDeviceWrappingState;
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
    if (typeof state.recoveryValueExported !== 'boolean') {
        throw new BrowserActionStorageCustodyError(
            errorCode,
            'Device-wrapping recovery export marker must be a boolean.',
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
        recoveryValueExported: state.recoveryValueExported,
        storageRootCommitment,
        wrappedStorageRoot,
    });
};

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
    if (typeof snapshot.recoveryValueExported !== 'boolean') {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'Device custody snapshot recovery marker must be a boolean.',
        );
    }

    return Object.freeze({
        mutationIdentifier: copyBytes(
            snapshot.mutationIdentifier,
            deviceWrappingMutationIdentifierByteLength,
            'InvalidInput',
            'Device custody snapshot mutation identifier',
        ),
        recoveryValueExported: snapshot.recoveryValueExported,
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
        recoveryValueExported: state.recoveryValueExported,
        storageRootCommitment: state.storageRootCommitment.slice(),
    });

const stateMatchesSnapshot = (
    state: BrowserDeviceWrappingState,
    snapshot: BrowserDeviceWrappingSnapshot,
): boolean =>
    state.recoveryValueExported === snapshot.recoveryValueExported &&
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

const assertRecoveryText = (caseInsensitiveRecoveryText: string): string => {
    if (typeof caseInsensitiveRecoveryText !== 'string') {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'Recovery material must be text.',
        );
    }
    const canonicalRecoveryText = caseInsensitiveRecoveryText.toUpperCase();
    if (
        canonicalRecoveryText.length !== recoveryTextLength ||
        !recoveryTextPattern.test(canonicalRecoveryText)
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            `Recovery material must contain exactly ${recoveryTextLength} base32 characters without separators or padding.`,
        );
    }

    return canonicalRecoveryText;
};

const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

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
    #pendingRecoveryExport: PendingRecoveryExport | undefined;

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

    public initialize(): Promise<BrowserDeviceWrappingSnapshot> {
        return this.#runOperation(async () => {
            if (this.#expectedStorageRootCommitment !== undefined) {
                throw new BrowserActionStorageCustodyError(
                    'CommitmentRequired',
                    'Fresh initialization is forbidden after an expected storage-root commitment is known; recover the committed root instead.',
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
                const replacement = this.#makeState({
                    ...copiedPreparedState,
                    recoveryValueExported: false,
                });
                await this.#compareAndSwapOrConflict({
                    expectedMutationIdentifier: undefined,
                    replacement,
                });
                stateWasPublished = true;
                this.#clearPendingRecoveryExport();

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
            const state = await this.#readState();

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

    public beginRecoveryExport(input: {
        expectedSnapshot: BrowserDeviceWrappingSnapshot;
        untrustedExpectedCommitment: UntrustedExpectedStorageRootCommitment;
    }): Promise<BrowserRecoveryExportChallenge> {
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
            if (state.recoveryValueExported) {
                throw new BrowserActionStorageCustodyError(
                    'RecoveryAlreadyExported',
                    'The recovery value for this custody state was already exported.',
                );
            }
            await this.#activateState(state, copiedCommitment);
            const exportMaterial = await this.#workerCall(
                () =>
                    this.#workerKernel.prepareRecoveryExport({
                        activeMutationIdentifier:
                            state.mutationIdentifier.slice(),
                    }),
                'Preparing browser recovery export failed inside the owned worker.',
            );
            const canonicalRecoveryText = assertRecoveryText(
                exportMaterial.canonicalRecoveryText,
            );
            if (
                exportMaterial.canonicalRecoveryText !== canonicalRecoveryText
            ) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidCanonicalMaterial',
                    'The owned worker returned non-canonical recovery text.',
                );
            }
            const recoveryChecksum = copyBytes(
                exportMaterial.recoveryChecksum,
                recoveryChecksumByteLength,
                'InvalidState',
                'Recovery checksum',
            );
            this.#clearPendingRecoveryExport();
            const preparationIdentifier = bytesToHex(
                this.#randomBytes(deviceWrappingMutationIdentifierByteLength),
            );
            this.#pendingRecoveryExport = {
                canonicalRecoveryText,
                preparationIdentifier,
                recoveryChecksum,
                state,
            };

            return Object.freeze({
                preparationIdentifier,
                recoveryChecksum: recoveryChecksum.slice(),
            });
        });
    }

    public confirmRecoveryExport(input: {
        preparationIdentifier: string;
        confirmedChecksum: Uint8Array;
    }): Promise<BrowserRecoveryExportConfirmation> {
        if (
            typeof input !== 'object' ||
            input === null ||
            typeof input.preparationIdentifier !== 'string'
        ) {
            return Promise.reject(
                new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'Recovery export confirmation is malformed.',
                ),
            );
        }
        let confirmedChecksum: Uint8Array;
        try {
            confirmedChecksum = copyBytes(
                input.confirmedChecksum,
                recoveryChecksumByteLength,
                'InvalidInput',
                'Confirmed recovery checksum',
            );
        } catch (error) {
            return Promise.reject(normalizeInputError(error));
        }
        const preparationIdentifier = input.preparationIdentifier;

        return this.#runOperation(async () => {
            const pendingExport = this.#pendingRecoveryExport;
            if (
                preparationIdentifier !== pendingExport?.preparationIdentifier
            ) {
                throw new BrowserActionStorageCustodyError(
                    'RecoveryConfirmationFailed',
                    'No matching recovery export preparation is pending.',
                );
            }
            try {
                await this.#workerCall(
                    () =>
                        this.#workerKernel.confirmRecoveryChecksum({
                            canonicalRecoveryText:
                                pendingExport.canonicalRecoveryText,
                            confirmedChecksum,
                        }),
                    'Recovery checksum confirmation failed inside the owned worker.',
                    'RecoveryConfirmationFailed',
                );
                const currentState = await this.#readExpectedState(
                    snapshotFromState(pendingExport.state),
                );
                const replacement = this.#makeState({
                    deviceKey: currentState.deviceKey,
                    recoveryValueExported: true,
                    storageRootCommitment: currentState.storageRootCommitment,
                    wrappedStorageRoot: currentState.wrappedStorageRoot,
                });
                await this.#workerCall(
                    () =>
                        this.#workerKernel.stageDeviceWrappingStateOpen({
                            binding: copyStorageRootBinding(this.#binding),
                            untrustedExpectedCommitment:
                                this.#expectedCommitmentForState(replacement),
                            state: {
                                deviceKey: replacement.deviceKey,
                                storageRootCommitment:
                                    replacement.storageRootCommitment.slice(),
                                wrappedStorageRoot:
                                    replacement.wrappedStorageRoot.slice(),
                            },
                        }),
                    'Reopening the browser action-storage root before recovery publication failed inside the owned worker.',
                );
                let stateWasPublished = false;
                try {
                    await this.#compareAndSwapOrConflict({
                        expectedMutationIdentifier:
                            currentState.mutationIdentifier,
                        replacement,
                    });
                    stateWasPublished = true;
                    await this.#commitStagedRootForPublishedState(replacement);
                } catch (error) {
                    await this.#cleanRootAfterFailedPublication(
                        stateWasPublished,
                        error,
                    );
                    throw error;
                }
                const confirmation = Object.freeze({
                    canonicalRecoveryText: pendingExport.canonicalRecoveryText,
                    snapshot: snapshotFromState(replacement),
                });
                this.#clearPendingRecoveryExport();

                return confirmation;
            } catch (error) {
                if (
                    isBrowserActionStorageCustodyError(error) &&
                    error.code === 'RecoveryConfirmationFailed'
                ) {
                    throw error;
                }
                throw error;
            }
        });
    }

    public cancelRecoveryExport(preparationIdentifier: string): Promise<void> {
        if (typeof preparationIdentifier !== 'string') {
            return Promise.reject(
                new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'Recovery export preparation identifier must be text.',
                ),
            );
        }

        return this.#runOperation(() => {
            if (
                this.#pendingRecoveryExport?.preparationIdentifier !==
                preparationIdentifier
            ) {
                throw new BrowserActionStorageCustodyError(
                    'RecoveryConfirmationFailed',
                    'No matching recovery export preparation is pending.',
                );
            }
            this.#clearPendingRecoveryExport();

            return Promise.resolve();
        });
    }

    public recover(input: {
        caseInsensitiveRecoveryText: string;
        untrustedExpectedCommitment: UntrustedExpectedStorageRootCommitment;
        expectedSnapshot?: BrowserDeviceWrappingSnapshot;
    }): Promise<BrowserDeviceWrappingSnapshot> {
        if (typeof input !== 'object' || input === null) {
            return Promise.reject(
                new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'Recovery input must be an object.',
                ),
            );
        }
        let canonicalRecoveryText: string;
        let untrustedExpectedCommitment: UntrustedExpectedStorageRootCommitment;
        let expectedSnapshot: BrowserDeviceWrappingSnapshot | undefined;
        try {
            canonicalRecoveryText = assertRecoveryText(
                input.caseInsensitiveRecoveryText,
            );
            untrustedExpectedCommitment = copyUntrustedExpectedCommitment(
                input.untrustedExpectedCommitment,
            );
            expectedSnapshot =
                input.expectedSnapshot === undefined
                    ? undefined
                    : copySnapshot(input.expectedSnapshot);
        } catch (error) {
            return Promise.reject(normalizeInputError(error));
        }

        return this.#runOperation(async () => {
            if (this.#expectedStorageRootCommitment !== undefined) {
                this.#assertCommitmentMatches(
                    this.#expectedStorageRootCommitment,
                    untrustedExpectedCommitment.storageRootCommitment,
                );
            }
            const currentState = await this.#readState();
            if (
                expectedSnapshot === undefined
                    ? currentState !== undefined
                    : currentState === undefined ||
                      !stateMatchesSnapshot(currentState, expectedSnapshot)
            ) {
                throw new BrowserActionStorageCustodyError(
                    'Conflict',
                    'Browser action-storage custody changed before recovery.',
                );
            }
            const preparedState = await this.#workerCall(
                () =>
                    this.#workerKernel.stageRecoveryValueImportAndDeviceWrapping(
                        {
                            binding: copyStorageRootBinding(this.#binding),
                            caseInsensitiveRecoveryText: canonicalRecoveryText,
                            untrustedExpectedCommitment,
                        },
                    ),
                'Importing browser recovery material failed inside the owned worker.',
            );
            let stateWasPublished = false;
            try {
                if (
                    preparedState.canonicalRecoveryText !==
                    canonicalRecoveryText
                ) {
                    throw new BrowserActionStorageCustodyError(
                        'InvalidCanonicalMaterial',
                        'The owned worker returned different canonical recovery text.',
                    );
                }
                const copiedPreparedState = copyPreparedState(preparedState);
                this.#assertCommitmentMatches(
                    copiedPreparedState.storageRootCommitment,
                    untrustedExpectedCommitment.storageRootCommitment,
                );
                const replacement = this.#makeState({
                    ...copiedPreparedState,
                    recoveryValueExported: true,
                });
                await this.#compareAndSwapOrConflict({
                    expectedMutationIdentifier:
                        currentState?.mutationIdentifier,
                    replacement,
                });
                stateWasPublished = true;
                await this.#commitStagedRootForPublishedState(replacement);
                this.#expectedStorageRootCommitment =
                    untrustedExpectedCommitment.storageRootCommitment.slice();
                this.#clearPendingRecoveryExport();

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
            this.#clearPendingRecoveryExport();
            await this.#compareAndSwapOrConflict({
                expectedMutationIdentifier: state.mutationIdentifier,
                replacement: undefined,
            });
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

    public verifyActionStateRecovery(
        input: BrowserActionStateRecoveryVerificationInput,
    ): Promise<VerificationResult<string>> {
        let copiedInput: BrowserActionStateRecoveryVerificationInput;
        try {
            copiedInput = copyActionStateRecoveryVerificationInput(input);
        } catch (error) {
            return Promise.reject(normalizeInputError(error));
        }

        return this.#runOperation(async () =>
            copyWorkerIdentifierVerificationResult(
                await this.#workerCall(
                    () =>
                        this.#workerKernel.verifyActionStateRecovery(
                            copiedInput,
                        ),
                    'Verifying an action state recovery failed inside the owned worker.',
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

    public derivePersistentProofAttempt(
        input: BrowserPersistentProofAttemptInput,
    ): Promise<BrowserActionProofAttemptBinding> {
        let copiedInput: BrowserPersistentProofAttemptInput;
        try {
            copiedInput = copyPersistentProofAttemptInput(input);
        } catch (error) {
            return Promise.reject(normalizeInputError(error));
        }

        return this.#runOperation(async () =>
            copyActionProofAttemptBinding(
                await this.#workerCall(
                    () =>
                        this.#workerKernel.derivePersistentProofAttempt(
                            copiedInput,
                        ),
                    'Deriving persistent proof randomness failed inside the owned worker.',
                ),
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
            this.#clearPendingRecoveryExport();
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

    async #readState(): Promise<BrowserDeviceWrappingState | undefined> {
        try {
            const state = await this.#storage.readState();

            return state === undefined
                ? undefined
                : copyBrowserDeviceWrappingState(state);
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
        const state = await this.#readState();
        if (state === undefined) {
            throw new BrowserActionStorageCustodyError(
                'Unavailable',
                'The committed browser action-storage root is not present locally; recovery material is required.',
            );
        }
        if (!stateMatchesSnapshot(state, expectedSnapshot)) {
            throw new BrowserActionStorageCustodyError(
                'Conflict',
                'Browser action-storage custody changed before the requested operation.',
            );
        }

        return state;
    }

    #makeState(input: {
        deviceKey: CryptoKey;
        recoveryValueExported: boolean;
        storageRootCommitment: Uint8Array;
        wrappedStorageRoot: Uint8Array;
    }): BrowserDeviceWrappingState {
        return copyBrowserDeviceWrappingState({
            ...input,
            mutationIdentifier: this.#randomBytes(
                deviceWrappingMutationIdentifierByteLength,
            ),
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

    #expectedCommitmentForState(
        state: BrowserDeviceWrappingState,
    ): UntrustedExpectedStorageRootCommitment {
        const expectedCommitment = this.#expectedStorageRootCommitment;
        if (expectedCommitment === undefined) {
            throw new BrowserActionStorageCustodyError(
                'CommitmentRequired',
                'An expected storage-root commitment is required before opening local custody.',
            );
        }
        this.#assertCommitmentMatches(
            state.storageRootCommitment,
            expectedCommitment,
        );

        return Object.freeze({
            storageRootCommitment: expectedCommitment.slice(),
        });
    }

    async #commitStagedRootForPublishedState(
        expectedState: BrowserDeviceWrappingState,
    ): Promise<void> {
        const publishedState = await this.#readState();
        if (
            publishedState === undefined ||
            !bytesEqual(
                publishedState.mutationIdentifier,
                expectedState.mutationIdentifier,
            ) ||
            publishedState.recoveryValueExported !==
                expectedState.recoveryValueExported ||
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
            () =>
                this.#workerKernel.commitStagedActionStorageRoot({
                    mutationIdentifier:
                        publishedState.mutationIdentifier.slice(),
                }),
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
        failureCode:
            | 'OwnedWorkerFailure'
            | 'RecoveryConfirmationFailed' = 'OwnedWorkerFailure',
    ): Promise<Result> {
        try {
            return await operation();
        } catch (error) {
            throw isBrowserActionStorageCustodyError(error)
                ? error
                : new BrowserActionStorageCustodyError(
                      failureCode,
                      message,
                      error,
                  );
        }
    }

    #clearPendingRecoveryExport(): void {
        this.#pendingRecoveryExport?.recoveryChecksum.fill(0);
        this.#pendingRecoveryExport = undefined;
    }
}

export const createBrowserActionStorageCustodyForOwnedWorker = (input: {
    assertExclusiveOwnership: () => void;
    binding: BrowserActionStorageRootBinding;
    cryptoProvider?: Crypto;
    knownStorageRootCommitment?: Uint8Array;
    storage: BrowserDeviceWrappingStateStorage;
    workerKernel: BrowserActionStorageWorkerKernel;
}): BrowserActionStorageCustody => {
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
