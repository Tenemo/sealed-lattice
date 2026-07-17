import {
    copyAuthenticatedMailboxFrozenRosterParticipantIdentities,
    openAuthenticatedMailboxFrozenRoster,
} from '@sealed-lattice/crypto';
import {
    BrowserActionStorageCustodyError,
    foundationProfile,
    type BrowserActionProofAttemptBinding,
    type BrowserActionRandomnessReservationVerificationInput,
    type BrowserActionStateReservationVerificationInput,
    type BrowserTargetReleaseAttemptInput,
    type RefusalReason,
    type VerificationResult,
} from '@sealed-lattice/types';
import {
    copyRuntimeBuildAuthorityBindingDescription,
    type RuntimeBuildAuthorityBinding,
    UntrustedCanonicalBoardCarrier,
    VerifiedTranscriptObject,
} from '@sealed-lattice/wasm';

import type {
    CheckpointBoundary,
    ExpectedCheckpointBoundary,
} from './authenticated-checkpoint-store.js';
import type {
    BrowserFoundationCheckpointHandle,
    CommittedBrowserFoundationInitializationBatch,
} from './browser-action-storage-custody.js';
import type {
    BrowserFoundationActionRandomnessHandle,
    BrowserFoundationDurableStateBindingHandle,
    BrowserFoundationInitializationInput,
    BrowserFoundationNormalWitnessRoleHandle,
    BrowserFoundationOperationOwner,
    BrowserRecoveredFoundationInitializationBatch,
    BrowserFoundationStateReservationIntentHandle,
    TransferableBrowserFoundationOperationOwner,
} from './browser-foundation-operation-owner.js';
import type {
    CanonicalBoardRuntime,
    TransferableCanonicalBoardRuntime,
    VerifiedCanonicalBoardSnapshot,
} from './canonical-board-runtime.js';

const hashByteLength = 64;
const maximumProofAttemptIdentifierByteLength = 32;
const terminalCleanupInitialRetryDelayMilliseconds = 8;
const terminalCleanupMaximumRetryDelayMilliseconds = 1_000;

declare const browserFoundationActiveCapabilityBrand: unique symbol;
declare const browserFoundationActionRandomnessBrand: unique symbol;
declare const browserFoundationDurableStateBindingBrand: unique symbol;
declare const browserFoundationStateReservationBrand: unique symbol;
declare const browserFoundationStateReservationIntentBrand: unique symbol;
declare const browserFoundationCheckpointBrand: unique symbol;
declare const browserFoundationProofAttemptBrand: unique symbol;
declare const browserFoundationWitnessRoleBrand: unique symbol;

export type BrowserFoundationActiveCapability = Readonly<{
    readonly [browserFoundationActiveCapabilityBrand]: true;
}>;

export type BrowserFoundationActionRandomness = Readonly<{
    readonly [browserFoundationActionRandomnessBrand]: true;
}>;

export type BrowserFoundationDurableStateBinding = Readonly<{
    readonly [browserFoundationDurableStateBindingBrand]: true;
}>;

export type BrowserFoundationStateReservation = Readonly<{
    readonly [browserFoundationStateReservationBrand]: true;
}>;

export type BrowserFoundationStateReservationIntent = Readonly<{
    readonly [browserFoundationStateReservationIntentBrand]: true;
}>;

export type BrowserFoundationProducedStateReservationIntent = Readonly<{
    canonicalReservationIntentCarrier: Uint8Array;
    stateReservationIntent: BrowserFoundationStateReservationIntent;
}>;

export type BrowserFoundationProducedStateReservation = Readonly<{
    canonicalStateCertificate: Uint8Array;
    stateReservation: BrowserFoundationStateReservation;
}>;

export type BrowserFoundationCheckpoint = Readonly<{
    readonly [browserFoundationCheckpointBrand]: true;
}>;

type BrowserFoundationProofAttempt = Readonly<{
    readonly [browserFoundationProofAttemptBrand]: true;
}>;

export type BrowserFoundationWitnessRole = Readonly<{
    readonly [browserFoundationWitnessRoleBrand]: true;
}>;

export type BrowserFoundationAuthorityState =
    | 'active'
    | 'retired'
    | 'unavailable';

export type BrowserFoundationAuthorityRetirementReason =
    | 'closed'
    | 'localStateAuthenticationFailed'
    | 'localStateUnavailable'
    | 'stateAuthorityUnavailable'
    | 'witnessStateUnavailable';

export type BrowserFoundationAuthorityErrorCode =
    | 'CleanupFailed'
    | 'InvalidConfiguration'
    | 'InvalidInput'
    | 'InvalidState'
    | 'Retired';

export class BrowserFoundationAuthorityError extends Error {
    public constructor(
        public readonly code: BrowserFoundationAuthorityErrorCode,
        message: string,
        public readonly failureCause?: unknown,
    ) {
        super(message);
        this.name = 'BrowserFoundationAuthorityError';
    }
}

export type BrowserFoundationCheckpointDescription = Readonly<{
    canonicalManifestBytes?: Uint8Array;
    checkpointLineageIdentifier: Uint8Array;
    stateStreamDescriptorBytes?: Uint8Array;
}>;

export type BrowserFoundationWitnessRoleDescription = Readonly<{
    subjectParticipantIdentity: Uint8Array;
}>;

export type BrowserFoundationStateReservationInput = Omit<
    BrowserActionStateReservationVerificationInput,
    'stateVerifierSessionIdentifier'
>;

export type BrowserFoundationRandomnessReservationInput = Omit<
    BrowserActionRandomnessReservationVerificationInput,
    'actionRandomnessSessionIdentifier' | 'stateVerifierSessionIdentifier'
>;

export type BrowserFoundationTargetReleaseAttemptInput = Omit<
    BrowserTargetReleaseAttemptInput,
    'actionRandomnessSessionIdentifier' | 'stateReservationIdentifier'
>;

export type BrowserFoundationAuthority = Readonly<{
    actionRandomness(
        capability: BrowserFoundationActiveCapability,
    ): BrowserFoundationActionRandomness;
    activeCapability(): BrowserFoundationActiveCapability;
    beginCheckpoint(
        capability: BrowserFoundationActiveCapability,
        proofAttempts: readonly BrowserFoundationProofAttempt[],
    ): Promise<BrowserFoundationCheckpoint>;
    cacheWitnessExactOutput(
        capability: BrowserFoundationActiveCapability,
        witnessRole: BrowserFoundationWitnessRole,
        input: {
            durableBinding: BrowserFoundationDurableStateBinding;
            exactOutputBytes: Uint8Array;
        },
    ): Promise<void>;
    cacheWitnessSignedVoteCarrier(
        capability: BrowserFoundationActiveCapability,
        witnessRole: BrowserFoundationWitnessRole,
        input: {
            canonicalSignedVoteCarrier: Uint8Array;
            durableBinding: BrowserFoundationDurableStateBinding;
        },
    ): Promise<Uint8Array>;
    close(): Promise<void>;
    closeActionRandomness(
        capability: BrowserFoundationActiveCapability,
        actionRandomness: BrowserFoundationActionRandomness,
    ): Promise<void>;
    closeWitnessDurableStateBinding(
        capability: BrowserFoundationActiveCapability,
        durableBinding: BrowserFoundationDurableStateBinding,
    ): Promise<void>;
    compareAndLockWitnessIntent(
        capability: BrowserFoundationActiveCapability,
        witnessRole: BrowserFoundationWitnessRole,
        input: { durableBinding: BrowserFoundationDurableStateBinding },
    ): Promise<void>;
    certifyActionRandomnessReservation(
        capability: BrowserFoundationActiveCapability,
        stateReservationIntent: BrowserFoundationStateReservationIntent,
        untrustedVoteCarriers: readonly Uint8Array[],
    ): Promise<VerificationResult<BrowserFoundationProducedStateReservation>>;
    copyCheckpointDescription(
        capability: BrowserFoundationActiveCapability,
        checkpoint: BrowserFoundationCheckpoint,
    ): Promise<BrowserFoundationCheckpointDescription>;
    copyProofAttemptBinding(
        capability: BrowserFoundationActiveCapability,
        proofAttempt: BrowserFoundationProofAttempt,
    ): Promise<BrowserActionProofAttemptBinding>;
    copyWitnessRoleDescription(
        witnessRole: BrowserFoundationWitnessRole,
    ): Promise<BrowserFoundationWitnessRoleDescription>;
    deriveTargetReleaseAttempt(
        capability: BrowserFoundationActiveCapability,
        actionRandomness: BrowserFoundationActionRandomness,
        stateReservation: BrowserFoundationStateReservation,
        input: BrowserFoundationTargetReleaseAttemptInput,
    ): Promise<BrowserFoundationProofAttempt>;
    ingestCanonicalBoard(
        capability: BrowserFoundationActiveCapability,
        carriers: readonly UntrustedCanonicalBoardCarrier[],
    ): Promise<VerificationResult<VerifiedCanonicalBoardSnapshot>>;
    listCanonicalBoardObjects(
        capability: BrowserFoundationActiveCapability,
        snapshot: VerifiedCanonicalBoardSnapshot,
    ): Promise<VerificationResult<readonly VerifiedTranscriptObject[]>>;
    openWitnessStateReservationBinding(
        capability: BrowserFoundationActiveCapability,
        witnessRole: BrowserFoundationWitnessRole,
        stateReservation: BrowserFoundationStateReservation,
    ): Promise<BrowserFoundationDurableStateBinding>;
    produceActionRandomnessReservationIntent(
        capability: BrowserFoundationActiveCapability,
        actionRandomness: BrowserFoundationActionRandomness,
    ): Promise<
        VerificationResult<BrowserFoundationProducedStateReservationIntent>
    >;
    publishCheckpoint(
        capability: BrowserFoundationActiveCapability,
        checkpoint: BrowserFoundationCheckpoint,
        input: {
            boundary: CheckpointBoundary;
            stateChunks: AsyncIterable<Uint8Array> | Iterable<Uint8Array>;
        },
    ): Promise<Uint8Array>;
    readWitnessExactOutput(
        capability: BrowserFoundationActiveCapability,
        witnessRole: BrowserFoundationWitnessRole,
        input: { durableBinding: BrowserFoundationDurableStateBinding },
    ): Promise<Uint8Array>;
    readWitnessSignedVoteCarrier(
        capability: BrowserFoundationActiveCapability,
        witnessRole: BrowserFoundationWitnessRole,
        input: { durableBinding: BrowserFoundationDurableStateBinding },
    ): Promise<Uint8Array>;
    releaseStateReservation(
        capability: BrowserFoundationActiveCapability,
        stateReservation: BrowserFoundationStateReservation,
    ): Promise<void>;
    releaseStateReservationIntent(
        capability: BrowserFoundationActiveCapability,
        stateReservationIntent: BrowserFoundationStateReservationIntent,
    ): Promise<void>;
    restoreCheckpointState(
        capability: BrowserFoundationActiveCapability,
        checkpoint: BrowserFoundationCheckpoint,
        consumeChunk: (
            chunkIndex: number,
            chunkBytes: Uint8Array,
        ) => Promise<void> | void,
    ): Promise<void>;
    resumeCheckpoint(
        capability: BrowserFoundationActiveCapability,
        input: {
            checkpointLineageIdentifier: Uint8Array;
            expectedBoundary: ExpectedCheckpointBoundary;
        },
    ): Promise<BrowserFoundationCheckpoint>;
    startup(): Promise<BrowserFoundationAuthorityState>;
    state(): BrowserFoundationAuthorityState;
    retirementReason(): BrowserFoundationAuthorityRetirementReason | undefined;
    verifyActionRandomnessReservation(
        capability: BrowserFoundationActiveCapability,
        actionRandomness: BrowserFoundationActionRandomness,
        input: BrowserFoundationRandomnessReservationInput,
    ): Promise<VerificationResult<BrowserFoundationStateReservation>>;
    verifyStateReservation(
        capability: BrowserFoundationActiveCapability,
        input: BrowserFoundationStateReservationInput,
    ): Promise<VerificationResult<BrowserFoundationStateReservation>>;
    voteForActionRandomnessReservationIntent(
        capability: BrowserFoundationActiveCapability,
        witnessRole: BrowserFoundationWitnessRole,
        canonicalReservationIntentCarrier: Uint8Array,
    ): Promise<VerificationResult<Uint8Array>>;
    witnessRoles(): Promise<readonly BrowserFoundationWitnessRole[]>;
}>;

export type BrowserFoundationAuthorityInput = Readonly<{
    canonicalBoardRuntime: TransferableCanonicalBoardRuntime;
    initializationMode: 'fresh' | 'recovered';
    operationOwner: TransferableBrowserFoundationOperationOwner;
    runtimeBuildAuthorityBinding: RuntimeBuildAuthorityBinding;
}>;

type ComponentBinding = Readonly<{
    actionContextHash: Uint8Array;
    canonicalRosterBytes: Uint8Array;
    ceremonyContextHash: Uint8Array;
    orderedRosterParticipantIdentities: readonly Uint8Array[];
    runtimeBuildManifestHash: Uint8Array;
    subjectParticipantIdentity: Uint8Array;
    suiteIdentifier: Uint8Array;
}>;

type WitnessRoleRecord = {
    normalHandle?: BrowserFoundationNormalWitnessRoleHandle;
    subjectParticipantIdentity: Uint8Array;
};

type StateReservationRecord = {
    active: boolean;
    identifier: string;
};

type StateReservationIntentRecord = {
    active: boolean;
    handle: BrowserFoundationStateReservationIntentHandle;
};

type DurableStateBindingRecord = {
    active: boolean;
    handle: BrowserFoundationDurableStateBindingHandle;
    stateObjectIdentifier: string;
    witnessRole: WitnessRoleRecord;
};

type ProofAttemptRecord = Readonly<{
    applicationSlotHash: Uint8Array;
    attemptIdentifier: Uint8Array;
}>;

const valid = <Value>(value: Value): VerificationResult<Value> =>
    Object.freeze({ isValid: true, value });

const refused = <Value>(
    refusalReason: RefusalReason,
): VerificationResult<Value> =>
    Object.freeze({ isValid: false, refusalReason });

const permanentStorageAuthorityFailureCodes = new Set([
    'AuthenticationFailed',
    'CleanupFailed',
    'OwnedWorkerFailure',
    'RecordAuthenticationFailed',
    'StorageFailure',
    'Unavailable',
]);

const requiresPermanentLocalRetirement = (error: unknown): boolean => {
    if (error instanceof BrowserActionStorageCustodyError) {
        return permanentStorageAuthorityFailureCodes.has(error.code);
    }
    return (
        error instanceof Error &&
        'code' in error &&
        permanentStorageAuthorityFailureCodes.has(
            String((error as { code?: unknown }).code),
        )
    );
};

const waitForTerminalCleanupRetry = (
    delayMilliseconds: number,
): Promise<void> =>
    new Promise((resolve) => {
        setTimeout(resolve, delayMilliseconds);
    });

const completeTerminalConstructionCleanup = async (
    cleanup: () => void | Promise<void>,
): Promise<void> => {
    let retryDelayMilliseconds = terminalCleanupInitialRetryDelayMilliseconds;
    for (;;) {
        try {
            await cleanup();
            return;
        } catch {
            // A failed construction cannot return a cleanup owner to its
            // caller. Keep that owner captured until terminal cleanup can
            // finish, while yielding so unavailable storage cannot hot-spin
            // the browser event loop.
            await waitForTerminalCleanupRetry(retryDelayMilliseconds);
            retryDelayMilliseconds = Math.min(
                terminalCleanupMaximumRetryDelayMilliseconds,
                retryDelayMilliseconds * 2,
            );
        }
    }
};

const retirementReasonForOwnerFailure = (
    error: unknown,
): BrowserFoundationAuthorityRetirementReason => {
    const errorCode =
        error instanceof Error && 'code' in error
            ? String((error as { code?: unknown }).code)
            : undefined;
    if (
        errorCode === 'AuthenticationFailed' ||
        errorCode === 'RecordAuthenticationFailed'
    ) {
        return 'localStateAuthenticationFailed';
    }
    return 'localStateUnavailable';
};

const isUint8Array = (value: unknown): value is Uint8Array => {
    try {
        return (
            ArrayBuffer.isView(value) &&
            Object.prototype.toString.call(value) === '[object Uint8Array]'
        );
    } catch {
        return false;
    }
};

const copyBytes = (
    value: unknown,
    label: string,
    expectedByteLength?: number,
): Uint8Array => {
    if (
        !isUint8Array(value) ||
        value.byteLength > foundationProfile.maximumCopiedBufferByteLength ||
        (expectedByteLength !== undefined &&
            value.byteLength !== expectedByteLength)
    ) {
        throw new BrowserFoundationAuthorityError(
            'InvalidInput',
            `${label} is not a byte array within the browser foundation safety bound.`,
        );
    }
    return value.slice();
};

const copyHash = (value: unknown, label: string): Uint8Array =>
    copyBytes(value, label, hashByteLength);

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean => {
    if (left.byteLength !== right.byteLength) {
        return false;
    }
    let difference = 0;
    for (let byteIndex = 0; byteIndex < left.byteLength; byteIndex += 1) {
        difference |= (left[byteIndex] ?? 0) ^ (right[byteIndex] ?? 0);
    }
    return difference === 0;
};

const createOpaqueCapability = <Capability>(): Capability =>
    Object.freeze(Object.create(null) as object) as Capability;

const copyAndValidateComponentBinding = (
    input: BrowserFoundationAuthorityInput,
): ComponentBinding => {
    if (
        typeof input.canonicalBoardRuntime?.claimExclusiveOwner !==
            'function' ||
        typeof input.operationOwner?.claimExclusiveOwner !== 'function'
    ) {
        throw new BrowserFoundationAuthorityError(
            'InvalidConfiguration',
            'Browser foundation components must support exclusive ownership transfer.',
        );
    }
    const runtimeBinding = copyRuntimeBuildAuthorityBindingDescription(
        input.runtimeBuildAuthorityBinding,
    );
    const boardContext = input.canonicalBoardRuntime.copyContextInput();
    const ownerBinding = input.operationOwner.copyBinding();
    const suiteIdentifier = copyHash(
        boardContext.expectedSuiteIdentifier,
        'canonicalBoardRuntime.expectedSuiteIdentifier',
    );
    const ceremonyContextHash = copyHash(
        boardContext.expectedCeremonyContextHash,
        'canonicalBoardRuntime.expectedCeremonyContextHash',
    );
    const actionContextHash = copyHash(
        boardContext.expectedActionContextHash,
        'canonicalBoardRuntime.expectedActionContextHash',
    );
    const subjectParticipantIdentity = copyHash(
        ownerBinding.participantId,
        'operationOwner.participantId',
    );
    const runtimeBuildManifestHash = copyHash(
        runtimeBinding.runtimeBuildManifestHash,
        'runtimeBuildAuthorityBinding.runtimeBuildManifestHash',
    );
    try {
        for (const [label, candidate, expected] of [
            [
                'runtimeBuildAuthorityBinding.suiteIdentifier',
                runtimeBinding.suiteIdentifier,
                suiteIdentifier,
            ],
            ['operationOwner.suiteId', ownerBinding.suiteId, suiteIdentifier],
            [
                'operationOwner.ceremonyContextHash',
                ownerBinding.ceremonyContextHash,
                ceremonyContextHash,
            ],
            [
                'operationOwner.actionContextHash',
                ownerBinding.actionContextHash,
                actionContextHash,
            ],
        ] as const) {
            if (!isUint8Array(candidate) || !bytesEqual(candidate, expected)) {
                throw new BrowserFoundationAuthorityError(
                    'InvalidConfiguration',
                    `${label} is cross-wired to another foundation operation.`,
                );
            }
        }
        if (
            !isUint8Array(boardContext.canonicalRosterBytes) ||
            boardContext.canonicalRosterBytes.byteLength === 0
        ) {
            throw new BrowserFoundationAuthorityError(
                'InvalidConfiguration',
                'The canonical board roster is unavailable.',
            );
        }
        const orderedRosterParticipantIdentities =
            copyAuthenticatedMailboxFrozenRosterParticipantIdentities(
                openAuthenticatedMailboxFrozenRoster(
                    boardContext.canonicalRosterBytes,
                ),
            );
        if (
            orderedRosterParticipantIdentities.filter((identity) =>
                bytesEqual(identity, subjectParticipantIdentity),
            ).length !== 1
        ) {
            throw new BrowserFoundationAuthorityError(
                'InvalidConfiguration',
                'The combined owner must occur exactly once in the fixed canonical roster.',
            );
        }
        return Object.freeze({
            actionContextHash: actionContextHash.slice(),
            canonicalRosterBytes: boardContext.canonicalRosterBytes.slice(),
            ceremonyContextHash: ceremonyContextHash.slice(),
            orderedRosterParticipantIdentities,
            runtimeBuildManifestHash: runtimeBuildManifestHash.slice(),
            subjectParticipantIdentity: subjectParticipantIdentity.slice(),
            suiteIdentifier: suiteIdentifier.slice(),
        });
    } finally {
        actionContextHash.fill(0);
        ceremonyContextHash.fill(0);
        runtimeBuildManifestHash.fill(0);
        subjectParticipantIdentity.fill(0);
        suiteIdentifier.fill(0);
        for (const value of [
            boardContext.canonicalActionDefinitionBytes,
            boardContext.canonicalBoardPolicyBytes,
            boardContext.canonicalManifestBytes,
            boardContext.canonicalRosterBytes,
            boardContext.canonicalSuiteRecordBytes,
            boardContext.expectedActionContextHash,
            boardContext.expectedCeremonyContextHash,
            boardContext.expectedSuiteIdentifier,
            ownerBinding.actionContextHash,
            ownerBinding.ceremonyContextHash,
            ownerBinding.participantId,
            ownerBinding.suiteId,
            runtimeBinding.runtimeBuildManifestHash,
            runtimeBinding.suiteIdentifier,
        ]) {
            value.fill(0);
        }
    }
};

const createInitializationInput = (
    binding: ComponentBinding,
): BrowserFoundationInitializationInput =>
    Object.freeze({
        actionRandomnessRecordContext: Object.freeze({ recordVersion: 0n }),
        canonicalRosterBytes: binding.canonicalRosterBytes.slice(),
        orderedWitnessBindings: Object.freeze(
            binding.orderedRosterParticipantIdentities
                .filter(
                    (identity) =>
                        !bytesEqual(
                            identity,
                            binding.subjectParticipantIdentity,
                        ),
                )
                .map((subjectParticipantIdentity) =>
                    Object.freeze({
                        subjectParticipantIdentity:
                            subjectParticipantIdentity.slice(),
                        witnessParticipantIdentity:
                            binding.subjectParticipantIdentity.slice(),
                    }),
                ),
        ),
        runtimeBuildManifestHash: binding.runtimeBuildManifestHash.slice(),
    });

const requireExactWitnessSubjects = async (input: {
    expectedSubjects: readonly Uint8Array[];
    handles: readonly BrowserFoundationNormalWitnessRoleHandle[];
    owner: BrowserFoundationOperationOwner;
}): Promise<void> => {
    const handlesAreArray = Array.isArray(input.handles);
    if (
        !handlesAreArray ||
        input.handles.length !== input.expectedSubjects.length ||
        new Set(input.handles).size !== input.handles.length
    ) {
        throw new BrowserFoundationAuthorityError(
            'InvalidConfiguration',
            'The combined owner did not return the exact fixed-roster witness roles.',
        );
    }
    for (const [roleIndex, handle] of input.handles.entries()) {
        const observed =
            await input.owner.copyWitnessSubjectParticipantIdentity(handle);
        try {
            const expected = input.expectedSubjects[roleIndex];
            if (
                expected === undefined ||
                !isUint8Array(observed) ||
                observed.byteLength !== hashByteLength ||
                !bytesEqual(observed, expected)
            ) {
                throw new BrowserFoundationAuthorityError(
                    'InvalidConfiguration',
                    'The combined owner returned a cross-wired witness role.',
                );
            }
        } finally {
            observed.fill(0);
        }
    }
};

type PreparedAuthority = Readonly<{
    board: CanonicalBoardRuntime;
    canonicalRosterBytes: Uint8Array;
    committedFreshBatch?: CommittedBrowserFoundationInitializationBatch;
    operationOwner: BrowserFoundationOperationOwner;
    recoveredBatch?: BrowserRecoveredFoundationInitializationBatch;
    witnessRoleRecords: readonly WitnessRoleRecord[];
}>;

const prepareAuthority = async (
    input: BrowserFoundationAuthorityInput,
): Promise<PreparedAuthority> => {
    if (
        input.initializationMode !== 'fresh' &&
        input.initializationMode !== 'recovered'
    ) {
        throw new BrowserFoundationAuthorityError(
            'InvalidConfiguration',
            'The browser foundation initialization mode is invalid.',
        );
    }
    const binding = copyAndValidateComponentBinding(input);
    let board: CanonicalBoardRuntime | undefined;
    let owner: BrowserFoundationOperationOwner | undefined;
    try {
        board = input.canonicalBoardRuntime.claimExclusiveOwner();
        owner = input.operationOwner.claimExclusiveOwner();
        const claimedOwner = owner;
        const initializationInput = createInitializationInput(binding);
        const expectedWitnessSubjects =
            binding.orderedRosterParticipantIdentities.filter(
                (identity) =>
                    !bytesEqual(identity, binding.subjectParticipantIdentity),
            );
        let committedFreshBatch:
            | CommittedBrowserFoundationInitializationBatch
            | undefined;
        let recoveredBatch:
            | BrowserRecoveredFoundationInitializationBatch
            | undefined;
        if (input.initializationMode === 'fresh') {
            const committed =
                await claimedOwner.commitFreshFoundationInitialization(
                    initializationInput,
                );
            committedFreshBatch = committed.committedBatch;
        } else {
            const recovered =
                await claimedOwner.openRecoveredFoundationInitialization(
                    initializationInput,
                );
            recoveredBatch = recovered.recoveredBatch;
        }
        const witnessRoleRecords = expectedWitnessSubjects.map(
            (subjectParticipantIdentity): WitnessRoleRecord => ({
                subjectParticipantIdentity: subjectParticipantIdentity.slice(),
            }),
        );
        return Object.freeze({
            board,
            canonicalRosterBytes: binding.canonicalRosterBytes.slice(),
            ...(committedFreshBatch === undefined
                ? {}
                : { committedFreshBatch }),
            operationOwner: claimedOwner,
            ...(recoveredBatch === undefined ? {} : { recoveredBatch }),
            witnessRoleRecords: Object.freeze(witnessRoleRecords),
        });
    } catch (failure) {
        const localRetirementRequired =
            owner !== undefined && requiresPermanentLocalRetirement(failure);
        if (owner !== undefined) {
            const retainedOperationOwner = owner;
            if (localRetirementRequired) {
                await completeTerminalConstructionCleanup(() =>
                    retainedOperationOwner.retire(),
                );
            }
            await completeTerminalConstructionCleanup(() =>
                retainedOperationOwner.close(),
            );
        }
        if (board !== undefined) {
            const retainedCanonicalBoard = board;
            await completeTerminalConstructionCleanup(() => {
                retainedCanonicalBoard.close();
            });
        }
        throw failure instanceof Error
            ? failure
            : new BrowserFoundationAuthorityError(
                  'InvalidConfiguration',
                  'Foundation construction failed with a non-error value.',
                  failure,
              );
    } finally {
        binding.actionContextHash.fill(0);
        binding.canonicalRosterBytes.fill(0);
        binding.ceremonyContextHash.fill(0);
        binding.runtimeBuildManifestHash.fill(0);
        binding.subjectParticipantIdentity.fill(0);
        binding.suiteIdentifier.fill(0);
        for (const identity of binding.orderedRosterParticipantIdentities) {
            identity.fill(0);
        }
    }
};

class BrowserFoundationAuthorityImplementation implements BrowserFoundationAuthority {
    readonly #board: CanonicalBoardRuntime;
    readonly #canonicalRosterBytes: Uint8Array;
    readonly #operationOwner: BrowserFoundationOperationOwner;
    readonly #witnessRoleRecords: readonly WitnessRoleRecord[];
    readonly #witnessRoleRecordByCapability = new WeakMap<
        object,
        WitnessRoleRecord
    >();
    readonly #witnessRoleCapabilities: readonly BrowserFoundationWitnessRole[];
    #committedFreshBatch?: CommittedBrowserFoundationInitializationBatch;
    #recoveredBatch?: BrowserRecoveredFoundationInitializationBatch;
    #actionRandomnessHandle?: BrowserFoundationActionRandomnessHandle;
    #actionRandomnessCapability?: BrowserFoundationActionRandomness;
    #activeCapability?: BrowserFoundationActiveCapability;
    #stateVerifierSessionIdentifier?: string;
    #state: BrowserFoundationAuthorityState = 'unavailable';
    #retirementReason?: BrowserFoundationAuthorityRetirementReason;
    #operationTail: Promise<void> = Promise.resolve();
    #closePromise?: Promise<void>;
    #cleanupPromise?: Promise<void>;
    #operationOwnerRetirementCompleted = false;
    #operationOwnerCloseCompleted = false;
    #boardCloseCompleted = false;
    #closeRequested = false;
    #localStorageRetirementRequired = false;
    #stateReservationIntents = new WeakMap<
        object,
        StateReservationIntentRecord
    >();
    readonly #issuedStateReservationIntentRecords =
        new Set<StateReservationIntentRecord>();
    #stateReservations = new WeakMap<object, StateReservationRecord>();
    readonly #activeStateReservationIdentifiers = new Set<string>();
    #durableStateBindings = new WeakMap<object, DurableStateBindingRecord>();
    readonly #issuedDurableStateBindingRecords =
        new Set<DurableStateBindingRecord>();
    #proofAttempts = new WeakMap<object, ProofAttemptRecord>();
    readonly #issuedProofAttemptRecords = new Set<ProofAttemptRecord>();
    #checkpoints = new WeakMap<object, BrowserFoundationCheckpointHandle>();

    public constructor(input: PreparedAuthority) {
        this.#board = input.board;
        this.#canonicalRosterBytes = input.canonicalRosterBytes;
        this.#committedFreshBatch = input.committedFreshBatch;
        this.#operationOwner = input.operationOwner;
        this.#recoveredBatch = input.recoveredBatch;
        this.#witnessRoleRecords = input.witnessRoleRecords;
        this.#witnessRoleCapabilities = Object.freeze(
            input.witnessRoleRecords.map((record) => {
                const capability =
                    createOpaqueCapability<BrowserFoundationWitnessRole>();
                this.#witnessRoleRecordByCapability.set(capability, record);
                return capability;
            }),
        );
    }

    public state(): BrowserFoundationAuthorityState {
        return this.#closeRequested ? 'retired' : this.#state;
    }

    public retirementReason():
        | BrowserFoundationAuthorityRetirementReason
        | undefined {
        return this.#closeRequested
            ? (this.#retirementReason ?? 'closed')
            : this.#retirementReason;
    }

    public activeCapability(): BrowserFoundationActiveCapability {
        if (this.#state !== 'active' || this.#activeCapability === undefined) {
            throw new BrowserFoundationAuthorityError(
                this.#state === 'retired' ? 'Retired' : 'InvalidState',
                this.#state === 'retired'
                    ? 'The participant is permanently retired for this action.'
                    : 'The browser foundation authority is not active.',
            );
        }
        return this.#activeCapability;
    }

    public actionRandomness(
        capability: BrowserFoundationActiveCapability,
    ): BrowserFoundationActionRandomness {
        this.#requireActive(capability);
        if (
            this.#actionRandomnessCapability === undefined ||
            this.#actionRandomnessHandle === undefined
        ) {
            throw new BrowserFoundationAuthorityError(
                'InvalidState',
                'The constructor-retained action-randomness root is unavailable.',
            );
        }
        return this.#actionRandomnessCapability;
    }

    public startup(): Promise<BrowserFoundationAuthorityState> {
        return this.#enqueue(async () => {
            this.#assertNotRetired();
            if (this.#state === 'active') {
                return this.#state;
            }
            this.#makeUnavailable();
            try {
                // Root authentication protects honest-client local state.
                // Shared authority comes from later verified quorum objects,
                // not from certifying each local storage transition.
                await this.#activateWorkerOwnedFoundation();
                if (this.#stateVerifierSessionIdentifier === undefined) {
                    const opened =
                        await this.#operationOwner.openActionStateVerifierSession(
                            {
                                canonicalRosterBytes:
                                    this.#canonicalRosterBytes.slice(),
                            },
                        );
                    if (!opened.isValid) {
                        await this.#retire('stateAuthorityUnavailable', opened);
                        return this.#state;
                    }
                    this.#stateVerifierSessionIdentifier = opened.value;
                }
                this.#activeCapability =
                    createOpaqueCapability<BrowserFoundationActiveCapability>();
                this.#state = 'active';
                return this.#state;
            } catch (error) {
                const localStorageRetirementRequired =
                    requiresPermanentLocalRetirement(error);
                await this.#retire(
                    localStorageRetirementRequired
                        ? retirementReasonForOwnerFailure(error)
                        : 'stateAuthorityUnavailable',
                    error,
                    localStorageRetirementRequired,
                );
                throw error;
            }
        });
    }

    public witnessRoles(): Promise<readonly BrowserFoundationWitnessRole[]> {
        return this.#enqueue(() => {
            this.#assertNotRetired();
            if (this.#state !== 'active') {
                throw new BrowserFoundationAuthorityError(
                    'InvalidState',
                    'Witness roles are available only while the foundation authority is active.',
                );
            }
            return this.#witnessRoleCapabilities;
        });
    }

    public copyWitnessRoleDescription(
        witnessRole: BrowserFoundationWitnessRole,
    ): Promise<BrowserFoundationWitnessRoleDescription> {
        return this.#enqueue(() => {
            this.#assertNotRetired();
            const record = this.#requireWitnessRole(witnessRole);
            if (this.#state !== 'active') {
                throw new BrowserFoundationAuthorityError(
                    'InvalidState',
                    'The witness role is available only while the foundation authority is active.',
                );
            }
            return Object.freeze({
                subjectParticipantIdentity:
                    record.subjectParticipantIdentity.slice(),
            });
        });
    }

    public ingestCanonicalBoard(
        capability: BrowserFoundationActiveCapability,
        carriers: readonly UntrustedCanonicalBoardCarrier[],
    ): Promise<VerificationResult<VerifiedCanonicalBoardSnapshot>> {
        return this.#enqueueActive(capability, () =>
            Promise.resolve(this.#board.ingestUnordered(carriers)),
        );
    }

    public listCanonicalBoardObjects(
        capability: BrowserFoundationActiveCapability,
        snapshot: VerifiedCanonicalBoardSnapshot,
    ): Promise<VerificationResult<readonly VerifiedTranscriptObject[]>> {
        return this.#enqueueActive(capability, () =>
            Promise.resolve(this.#board.objects(snapshot)),
        );
    }

    public produceActionRandomnessReservationIntent(
        capability: BrowserFoundationActiveCapability,
        actionRandomness: BrowserFoundationActionRandomness,
    ): Promise<
        VerificationResult<BrowserFoundationProducedStateReservationIntent>
    > {
        return this.#ownerOperation(capability, async () => {
            const produced =
                await this.#operationOwner.produceFoundationActionRandomnessReservationIntent(
                    this.#requireActionRandomness(actionRandomness),
                    {
                        stateVerifierSessionIdentifier:
                            this.#requireStateVerifierSession(),
                    },
                );
            if (!produced.isValid) {
                return refused(produced.refusalReason);
            }
            return valid(
                Object.freeze({
                    canonicalReservationIntentCarrier: copyBytes(
                        produced.value.canonicalReservationIntentCarrier,
                        'canonicalReservationIntentCarrier',
                    ),
                    stateReservationIntent:
                        this.#registerStateReservationIntent(
                            produced.value.intentHandle,
                        ),
                }),
            );
        });
    }

    public voteForActionRandomnessReservationIntent(
        capability: BrowserFoundationActiveCapability,
        witnessRole: BrowserFoundationWitnessRole,
        canonicalReservationIntentCarrier: Uint8Array,
    ): Promise<VerificationResult<Uint8Array>> {
        const copiedCarrier = copyBytes(
            canonicalReservationIntentCarrier,
            'canonicalReservationIntentCarrier',
        );
        return this.#enqueueActive(capability, async () => {
            const record = this.#requireWitnessRole(witnessRole);
            const handle = this.#requireNormalWitnessHandle(witnessRole);
            try {
                return await this.#operationOwner.voteForFoundationActionRandomnessReservationIntent(
                    handle,
                    {
                        canonicalReservationIntentCarrier: copiedCarrier,
                        stateVerifierSessionIdentifier:
                            this.#requireStateVerifierSession(),
                        subjectParticipantIdentity:
                            record.subjectParticipantIdentity,
                    },
                );
            } catch (error) {
                if (requiresPermanentLocalRetirement(error)) {
                    await this.#retire('witnessStateUnavailable', error, true);
                }
                throw error;
            } finally {
                copiedCarrier.fill(0);
            }
        });
    }

    public certifyActionRandomnessReservation(
        capability: BrowserFoundationActiveCapability,
        stateReservationIntent: BrowserFoundationStateReservationIntent,
        untrustedVoteCarriers: readonly Uint8Array[],
    ): Promise<VerificationResult<BrowserFoundationProducedStateReservation>> {
        return this.#ownerOperation(capability, async () => {
            const intentRecord = this.#requireStateReservationIntent(
                stateReservationIntent,
            );
            const produced =
                await this.#operationOwner.certifyFoundationActionRandomnessReservation(
                    intentRecord.handle,
                    untrustedVoteCarriers,
                );
            if (!produced.isValid) {
                return refused(produced.refusalReason);
            }
            intentRecord.active = false;
            this.#issuedStateReservationIntentRecords.delete(intentRecord);
            this.#stateReservationIntents.delete(stateReservationIntent);
            let stateReservation: BrowserFoundationStateReservation;
            try {
                stateReservation = this.#registerStateReservation(
                    produced.value.stateReservationIdentifier,
                );
            } catch (error) {
                await this.#operationOwner.releaseActionStateObject(
                    produced.value.stateReservationIdentifier,
                );
                throw error;
            }
            return valid(
                Object.freeze({
                    canonicalStateCertificate: copyBytes(
                        produced.value.canonicalStateCertificate,
                        'canonicalStateCertificate',
                    ),
                    stateReservation,
                }),
            );
        });
    }

    public releaseStateReservationIntent(
        capability: BrowserFoundationActiveCapability,
        stateReservationIntent: BrowserFoundationStateReservationIntent,
    ): Promise<void> {
        return this.#ownerOperation(capability, async () => {
            const record = this.#requireStateReservationIntent(
                stateReservationIntent,
            );
            await this.#operationOwner.releaseFoundationStateReservationIntent(
                record.handle,
            );
            record.active = false;
            this.#issuedStateReservationIntentRecords.delete(record);
            this.#stateReservationIntents.delete(stateReservationIntent);
        });
    }

    public verifyStateReservation(
        capability: BrowserFoundationActiveCapability,
        input: BrowserFoundationStateReservationInput,
    ): Promise<VerificationResult<BrowserFoundationStateReservation>> {
        return this.#ownerOperation(capability, async () => {
            const verification =
                await this.#operationOwner.verifyActionStateReservation({
                    ...input,
                    stateVerifierSessionIdentifier:
                        this.#requireStateVerifierSession(),
                });
            return verification.isValid
                ? valid(this.#registerStateReservation(verification.value))
                : refused(verification.refusalReason);
        });
    }

    public verifyActionRandomnessReservation(
        capability: BrowserFoundationActiveCapability,
        actionRandomness: BrowserFoundationActionRandomness,
        input: BrowserFoundationRandomnessReservationInput,
    ): Promise<VerificationResult<BrowserFoundationStateReservation>> {
        return this.#ownerOperation(capability, async () => {
            const actionHandle =
                this.#requireActionRandomness(actionRandomness);
            const verification =
                await this.#operationOwner.verifyFoundationActionRandomnessReservation(
                    actionHandle,
                    {
                        ...input,
                        stateVerifierSessionIdentifier:
                            this.#requireStateVerifierSession(),
                    },
                );
            return verification.isValid
                ? valid(this.#registerStateReservation(verification.value))
                : refused(verification.refusalReason);
        });
    }

    public releaseStateReservation(
        capability: BrowserFoundationActiveCapability,
        stateReservation: BrowserFoundationStateReservation,
    ): Promise<void> {
        return this.#ownerOperation(capability, async () => {
            const record = this.#requireStateReservation(stateReservation);
            const bindings = [...this.#issuedDurableStateBindingRecords].filter(
                (bindingRecord) =>
                    bindingRecord.stateObjectIdentifier === record.identifier,
            );
            for (const bindingRecord of bindings) {
                await this.#operationOwner.closeWitnessDurableStateBinding(
                    bindingRecord.handle,
                );
                bindingRecord.active = false;
                this.#issuedDurableStateBindingRecords.delete(bindingRecord);
            }
            await this.#operationOwner.releaseActionStateObject(
                record.identifier,
            );
            record.active = false;
            this.#activeStateReservationIdentifiers.delete(record.identifier);
        });
    }

    public openWitnessStateReservationBinding(
        capability: BrowserFoundationActiveCapability,
        witnessRole: BrowserFoundationWitnessRole,
        stateReservation: BrowserFoundationStateReservation,
    ): Promise<BrowserFoundationDurableStateBinding> {
        return this.#ownerOperation(capability, async () => {
            const witnessRoleRecord = this.#requireWitnessRole(witnessRole);
            const normalHandle = this.#requireNormalWitnessHandle(witnessRole);
            const stateObjectIdentifier =
                this.#requireStateReservation(stateReservation).identifier;
            const handle =
                await this.#operationOwner.openWitnessDurableStateBinding(
                    normalHandle,
                    stateObjectIdentifier,
                );
            const record: DurableStateBindingRecord = {
                active: true,
                handle,
                stateObjectIdentifier,
                witnessRole: witnessRoleRecord,
            };
            const binding =
                createOpaqueCapability<BrowserFoundationDurableStateBinding>();
            this.#durableStateBindings.set(binding, record);
            this.#issuedDurableStateBindingRecords.add(record);
            return binding;
        });
    }

    public deriveTargetReleaseAttempt(
        capability: BrowserFoundationActiveCapability,
        actionRandomness: BrowserFoundationActionRandomness,
        stateReservation: BrowserFoundationStateReservation,
        input: BrowserFoundationTargetReleaseAttemptInput,
    ): Promise<BrowserFoundationProofAttempt> {
        return this.#ownerOperation(capability, async () => {
            const binding =
                await this.#operationOwner.deriveFoundationTargetReleaseAttempt(
                    this.#requireActionRandomness(actionRandomness),
                    {
                        ...input,
                        stateReservationIdentifier:
                            this.#requireStateReservation(stateReservation)
                                .identifier,
                    },
                );
            return this.#registerProofAttempt(binding);
        });
    }

    public copyProofAttemptBinding(
        capability: BrowserFoundationActiveCapability,
        proofAttempt: BrowserFoundationProofAttempt,
    ): Promise<BrowserActionProofAttemptBinding> {
        return this.#enqueueActive(capability, () => {
            const record = this.#requireProofAttempt(proofAttempt);
            return Object.freeze({
                applicationSlotHash: record.applicationSlotHash.slice(),
                attemptIdentifier: record.attemptIdentifier.slice(),
            });
        });
    }

    public beginCheckpoint(
        capability: BrowserFoundationActiveCapability,
        proofAttempts: readonly BrowserFoundationProofAttempt[],
    ): Promise<BrowserFoundationCheckpoint> {
        return this.#ownerOperation(capability, async () => {
            if (!Array.isArray(proofAttempts)) {
                throw new BrowserFoundationAuthorityError(
                    'InvalidInput',
                    'proofAttempts must be an array of retained capabilities.',
                );
            }
            const handle = await this.#operationOwner.beginCheckpoint(
                proofAttempts.map(
                    (proofAttempt) =>
                        this.#requireProofAttempt(proofAttempt)
                            .attemptIdentifier,
                ),
            );
            return this.#registerCheckpoint(handle);
        });
    }

    public resumeCheckpoint(
        capability: BrowserFoundationActiveCapability,
        input: {
            checkpointLineageIdentifier: Uint8Array;
            expectedBoundary: ExpectedCheckpointBoundary;
        },
    ): Promise<BrowserFoundationCheckpoint> {
        const checkpointLineageIdentifier = copyBytes(
            input.checkpointLineageIdentifier,
            'checkpointLineageIdentifier',
        );
        return this.#ownerOperation(capability, async () => {
            try {
                return this.#registerCheckpoint(
                    await this.#operationOwner.resumeCheckpoint({
                        checkpointLineageIdentifier,
                        expectedBoundary: input.expectedBoundary,
                    }),
                );
            } finally {
                checkpointLineageIdentifier.fill(0);
            }
        });
    }

    public publishCheckpoint(
        capability: BrowserFoundationActiveCapability,
        checkpoint: BrowserFoundationCheckpoint,
        input: {
            boundary: CheckpointBoundary;
            stateChunks: AsyncIterable<Uint8Array> | Iterable<Uint8Array>;
        },
    ): Promise<Uint8Array> {
        return this.#ownerOperation(capability, () =>
            this.#operationOwner.publishCheckpoint(
                this.#requireCheckpoint(checkpoint),
                input,
            ),
        );
    }

    public copyCheckpointDescription(
        capability: BrowserFoundationActiveCapability,
        checkpoint: BrowserFoundationCheckpoint,
    ): Promise<BrowserFoundationCheckpointDescription> {
        return this.#ownerOperation(capability, () =>
            this.#operationOwner.copyCheckpointDescription(
                this.#requireCheckpoint(checkpoint),
            ),
        );
    }

    public restoreCheckpointState(
        capability: BrowserFoundationActiveCapability,
        checkpoint: BrowserFoundationCheckpoint,
        consumeChunk: (
            chunkIndex: number,
            chunkBytes: Uint8Array,
        ) => Promise<void> | void,
    ): Promise<void> {
        return this.#ownerOperation(capability, () =>
            this.#operationOwner.restoreCheckpointState(
                this.#requireCheckpoint(checkpoint),
                consumeChunk,
            ),
        );
    }

    public compareAndLockWitnessIntent(
        capability: BrowserFoundationActiveCapability,
        witnessRole: BrowserFoundationWitnessRole,
        input: { durableBinding: BrowserFoundationDurableStateBinding },
    ): Promise<void> {
        return this.#witnessMutation(capability, witnessRole, (handle) =>
            this.#operationOwner.compareAndLockWitnessIntent(handle, {
                durableBinding: this.#requireDurableStateBinding(
                    input.durableBinding,
                    witnessRole,
                ).handle,
            }),
        );
    }

    public cacheWitnessSignedVoteCarrier(
        capability: BrowserFoundationActiveCapability,
        witnessRole: BrowserFoundationWitnessRole,
        input: {
            canonicalSignedVoteCarrier: Uint8Array;
            durableBinding: BrowserFoundationDurableStateBinding;
        },
    ): Promise<Uint8Array> {
        return this.#witnessMutation(capability, witnessRole, (handle) =>
            this.#operationOwner.cacheWitnessSignedVoteCarrier(handle, {
                canonicalSignedVoteCarrier: input.canonicalSignedVoteCarrier,
                durableBinding: this.#requireDurableStateBinding(
                    input.durableBinding,
                    witnessRole,
                ).handle,
            }),
        );
    }

    public readWitnessSignedVoteCarrier(
        capability: BrowserFoundationActiveCapability,
        witnessRole: BrowserFoundationWitnessRole,
        input: { durableBinding: BrowserFoundationDurableStateBinding },
    ): Promise<Uint8Array> {
        return this.#witnessRead(capability, witnessRole, (handle) =>
            this.#operationOwner.readWitnessSignedVoteCarrier(handle, {
                durableBinding: this.#requireDurableStateBinding(
                    input.durableBinding,
                    witnessRole,
                ).handle,
            }),
        );
    }

    public cacheWitnessExactOutput(
        capability: BrowserFoundationActiveCapability,
        witnessRole: BrowserFoundationWitnessRole,
        input: {
            durableBinding: BrowserFoundationDurableStateBinding;
            exactOutputBytes: Uint8Array;
        },
    ): Promise<void> {
        return this.#witnessMutation(capability, witnessRole, (handle) =>
            this.#operationOwner.cacheWitnessExactOutput(handle, {
                durableBinding: this.#requireDurableStateBinding(
                    input.durableBinding,
                    witnessRole,
                ).handle,
                exactOutputBytes: input.exactOutputBytes,
            }),
        );
    }

    public readWitnessExactOutput(
        capability: BrowserFoundationActiveCapability,
        witnessRole: BrowserFoundationWitnessRole,
        input: { durableBinding: BrowserFoundationDurableStateBinding },
    ): Promise<Uint8Array> {
        return this.#witnessRead(capability, witnessRole, (handle) =>
            this.#operationOwner.readWitnessExactOutput(handle, {
                durableBinding: this.#requireDurableStateBinding(
                    input.durableBinding,
                    witnessRole,
                ).handle,
            }),
        );
    }

    public closeWitnessDurableStateBinding(
        capability: BrowserFoundationActiveCapability,
        durableBinding: BrowserFoundationDurableStateBinding,
    ): Promise<void> {
        return this.#ownerOperation(capability, async () => {
            const record = this.#requireDurableStateBinding(durableBinding);
            await this.#operationOwner.closeWitnessDurableStateBinding(
                record.handle,
            );
            record.active = false;
            this.#issuedDurableStateBindingRecords.delete(record);
            this.#durableStateBindings.delete(durableBinding);
        });
    }

    public closeActionRandomness(
        capability: BrowserFoundationActiveCapability,
        actionRandomness: BrowserFoundationActionRandomness,
    ): Promise<void> {
        return this.#ownerOperation(capability, async () => {
            await this.#operationOwner.closeFoundationActionRandomness(
                this.#requireActionRandomness(actionRandomness),
            );
            this.#actionRandomnessHandle = undefined;
            this.#actionRandomnessCapability = undefined;
        });
    }

    public close(): Promise<void> {
        this.#closeRequested = true;
        this.#state = 'retired';
        this.#retirementReason ??= 'closed';
        this.#activeCapability = undefined;
        if (this.#closePromise === undefined) {
            const closeAttempt = this.#operationTail.then(
                () => this.#retire(this.#retirementReason ?? 'closed'),
                () => this.#retire(this.#retirementReason ?? 'closed'),
            );
            this.#closePromise = closeAttempt;
            void closeAttempt.catch(() => {
                if (this.#closePromise === closeAttempt) {
                    this.#closePromise = undefined;
                }
            });
        }
        return this.#closePromise;
    }

    async #activateWorkerOwnedFoundation(): Promise<void> {
        if (this.#actionRandomnessHandle !== undefined) {
            return;
        }
        const activated =
            this.#committedFreshBatch !== undefined
                ? await this.#operationOwner.activateFreshFoundationInitialization(
                      this.#committedFreshBatch,
                  )
                : await this.#operationOwner.activateRecoveredFoundationInitialization(
                      this.#requireRecoveredBatch(),
                  );
        const expectedSubjects = this.#witnessRoleRecords.map(
            (record) => record.subjectParticipantIdentity,
        );
        await requireExactWitnessSubjects({
            expectedSubjects,
            handles: activated.orderedWitnessRoleHandles,
            owner: this.#operationOwner,
        });
        for (const [
            roleIndex,
            handle,
        ] of activated.orderedWitnessRoleHandles.entries()) {
            const record = this.#witnessRoleRecords[roleIndex];
            if (record === undefined) {
                throw new BrowserFoundationAuthorityError(
                    'InvalidConfiguration',
                    'The combined owner returned an unexpected normal witness role.',
                );
            }
            record.normalHandle = handle;
        }
        this.#actionRandomnessHandle = activated.actionRandomnessHandle;
        this.#actionRandomnessCapability =
            createOpaqueCapability<BrowserFoundationActionRandomness>();
        this.#committedFreshBatch = undefined;
        this.#recoveredBatch = undefined;
    }

    #requireRecoveredBatch(): BrowserRecoveredFoundationInitializationBatch {
        if (this.#recoveredBatch === undefined) {
            throw new BrowserFoundationAuthorityError(
                'InvalidState',
                'The recovered foundation batch is unavailable.',
            );
        }
        return this.#recoveredBatch;
    }

    #registerStateReservationIntent(
        handle: BrowserFoundationStateReservationIntentHandle,
    ): BrowserFoundationStateReservationIntent {
        const record: StateReservationIntentRecord = {
            active: true,
            handle,
        };
        const capability =
            createOpaqueCapability<BrowserFoundationStateReservationIntent>();
        this.#stateReservationIntents.set(capability, record);
        this.#issuedStateReservationIntentRecords.add(record);
        return capability;
    }

    #requireStateReservationIntent(
        capability: BrowserFoundationStateReservationIntent,
    ): StateReservationIntentRecord {
        const record =
            typeof capability === 'object' && capability !== null
                ? this.#stateReservationIntents.get(capability)
                : undefined;
        if (record === undefined || !record.active) {
            throw new BrowserFoundationAuthorityError(
                'InvalidInput',
                'The state reservation intent was not issued by this authority or is no longer active.',
            );
        }
        return record;
    }

    #registerStateReservation(
        identifier: string,
    ): BrowserFoundationStateReservation {
        if (
            typeof identifier !== 'string' ||
            identifier.length === 0 ||
            this.#activeStateReservationIdentifiers.has(identifier)
        ) {
            throw new BrowserFoundationAuthorityError(
                'InvalidState',
                'The worker returned an invalid or reused state reservation.',
            );
        }
        const capability =
            createOpaqueCapability<BrowserFoundationStateReservation>();
        this.#stateReservations.set(capability, { active: true, identifier });
        this.#activeStateReservationIdentifiers.add(identifier);
        return capability;
    }

    #requireStateReservation(
        capability: BrowserFoundationStateReservation,
    ): StateReservationRecord {
        const record =
            typeof capability === 'object' && capability !== null
                ? this.#stateReservations.get(capability)
                : undefined;
        if (record === undefined) {
            throw new BrowserFoundationAuthorityError(
                'InvalidInput',
                'The state reservation was not issued by this authority.',
            );
        }
        if (!record.active) {
            throw new BrowserFoundationAuthorityError(
                'InvalidState',
                'The state reservation capability has already been consumed.',
            );
        }
        return record;
    }

    #requireDurableStateBinding(
        capability: BrowserFoundationDurableStateBinding,
        expectedWitnessRole?: BrowserFoundationWitnessRole,
    ): DurableStateBindingRecord {
        const record =
            typeof capability === 'object' && capability !== null
                ? this.#durableStateBindings.get(capability)
                : undefined;
        const expectedWitnessRoleRecord =
            expectedWitnessRole === undefined
                ? undefined
                : this.#requireWitnessRole(expectedWitnessRole);
        if (
            record === undefined ||
            !record.active ||
            (expectedWitnessRoleRecord !== undefined &&
                record.witnessRole !== expectedWitnessRoleRecord)
        ) {
            throw new BrowserFoundationAuthorityError(
                'InvalidInput',
                'The durable state binding was not issued for this active witness role.',
            );
        }
        return record;
    }

    #registerProofAttempt(
        binding: BrowserActionProofAttemptBinding,
    ): BrowserFoundationProofAttempt {
        const record = Object.freeze({
            applicationSlotHash: copyHash(
                binding.applicationSlotHash,
                'proofAttempt.applicationSlotHash',
            ),
            attemptIdentifier: copyBytes(
                binding.attemptIdentifier,
                'proofAttempt.attemptIdentifier',
            ),
        });
        if (
            record.attemptIdentifier.byteLength === 0 ||
            record.attemptIdentifier.byteLength >
                maximumProofAttemptIdentifierByteLength
        ) {
            record.applicationSlotHash.fill(0);
            record.attemptIdentifier.fill(0);
            throw new BrowserFoundationAuthorityError(
                'InvalidState',
                'The worker returned an invalid proof-attempt identifier.',
            );
        }
        const capability =
            createOpaqueCapability<BrowserFoundationProofAttempt>();
        this.#proofAttempts.set(capability, record);
        this.#issuedProofAttemptRecords.add(record);
        return capability;
    }

    #requireProofAttempt(capability: unknown): ProofAttemptRecord {
        const record =
            typeof capability === 'object' && capability !== null
                ? this.#proofAttempts.get(capability)
                : undefined;
        if (record === undefined) {
            throw new BrowserFoundationAuthorityError(
                'InvalidInput',
                'The proof attempt was not issued by this authority.',
            );
        }
        return record;
    }

    #registerCheckpoint(
        handle: BrowserFoundationCheckpointHandle,
    ): BrowserFoundationCheckpoint {
        const capability =
            createOpaqueCapability<BrowserFoundationCheckpoint>();
        this.#checkpoints.set(capability, handle);
        return capability;
    }

    #requireCheckpoint(
        capability: BrowserFoundationCheckpoint,
    ): BrowserFoundationCheckpointHandle {
        const handle =
            typeof capability === 'object' && capability !== null
                ? this.#checkpoints.get(capability)
                : undefined;
        if (handle === undefined) {
            throw new BrowserFoundationAuthorityError(
                'InvalidInput',
                'The checkpoint was not issued by this authority.',
            );
        }
        return handle;
    }

    #requireWitnessRole(
        capability: BrowserFoundationWitnessRole,
    ): WitnessRoleRecord {
        const record =
            typeof capability === 'object' && capability !== null
                ? this.#witnessRoleRecordByCapability.get(capability)
                : undefined;
        if (record === undefined) {
            throw new BrowserFoundationAuthorityError(
                'InvalidInput',
                'The witness role was not issued by this authority.',
            );
        }
        return record;
    }

    #requireActionRandomness(
        capability: BrowserFoundationActionRandomness,
    ): BrowserFoundationActionRandomnessHandle {
        if (
            capability !== this.#actionRandomnessCapability ||
            this.#actionRandomnessHandle === undefined
        ) {
            throw new BrowserFoundationAuthorityError(
                'InvalidInput',
                'The action-randomness capability was not issued by this authority or has been closed.',
            );
        }
        return this.#actionRandomnessHandle;
    }

    #requireStateVerifierSession(): string {
        if (this.#stateVerifierSessionIdentifier === undefined) {
            throw new BrowserFoundationAuthorityError(
                'InvalidState',
                'The worker-owned state verifier is unavailable.',
            );
        }
        return this.#stateVerifierSessionIdentifier;
    }

    #requireActive(capability: BrowserFoundationActiveCapability): void {
        if (this.#state !== 'active' || capability !== this.#activeCapability) {
            throw new BrowserFoundationAuthorityError(
                this.#state === 'retired' ? 'Retired' : 'InvalidInput',
                'The active capability was not issued for the current authority state.',
            );
        }
    }

    #assertNotRetired(): void {
        if (this.#state === 'retired' || this.#closeRequested) {
            throw new BrowserFoundationAuthorityError(
                'Retired',
                'The participant is permanently retired for this action.',
            );
        }
    }

    #makeUnavailable(): void {
        this.#state = 'unavailable';
        this.#activeCapability = undefined;
    }

    #enqueue<Result>(
        operation: () => Promise<Result> | Result,
    ): Promise<Result> {
        const result = this.#operationTail.then(operation, operation);
        this.#operationTail = result.then(
            () => undefined,
            () => undefined,
        );
        return result;
    }

    #enqueueActive<Result>(
        capability: BrowserFoundationActiveCapability,
        operation: () => Promise<Result> | Result,
    ): Promise<Result> {
        return this.#enqueue(async () => {
            this.#requireActive(capability);
            return operation();
        });
    }

    #ownerOperation<Result>(
        capability: BrowserFoundationActiveCapability,
        operation: () => Promise<Result>,
    ): Promise<Result> {
        return this.#enqueueActive(capability, async () => {
            try {
                return await operation();
            } catch (error) {
                if (requiresPermanentLocalRetirement(error)) {
                    await this.#retire(
                        retirementReasonForOwnerFailure(error),
                        error,
                        true,
                    );
                }
                throw error;
            }
        });
    }

    #witnessMutation<Result>(
        capability: BrowserFoundationActiveCapability,
        witnessRole: BrowserFoundationWitnessRole,
        operation: (
            handle: BrowserFoundationNormalWitnessRoleHandle,
        ) => Promise<Result>,
    ): Promise<Result> {
        return this.#enqueueActive(capability, async () => {
            const handle = this.#requireNormalWitnessHandle(witnessRole);
            try {
                return await operation(handle);
            } catch (error) {
                if (requiresPermanentLocalRetirement(error)) {
                    await this.#retire('witnessStateUnavailable', error, true);
                }
                throw error;
            }
        });
    }

    #witnessRead<Result>(
        capability: BrowserFoundationActiveCapability,
        witnessRole: BrowserFoundationWitnessRole,
        operation: (
            handle: BrowserFoundationNormalWitnessRoleHandle,
        ) => Promise<Result>,
    ): Promise<Result> {
        return this.#enqueueActive(capability, async () => {
            try {
                return await operation(
                    this.#requireNormalWitnessHandle(witnessRole),
                );
            } catch (error) {
                if (requiresPermanentLocalRetirement(error)) {
                    await this.#retire('witnessStateUnavailable', error, true);
                }
                throw error;
            }
        });
    }

    #requireNormalWitnessHandle(
        witnessRole: BrowserFoundationWitnessRole,
    ): BrowserFoundationNormalWitnessRoleHandle {
        const handle = this.#requireWitnessRole(witnessRole).normalHandle;
        if (handle === undefined) {
            throw new BrowserFoundationAuthorityError(
                'InvalidState',
                'The normal durable witness role is unavailable.',
            );
        }
        return handle;
    }

    async #retire(
        reason: BrowserFoundationAuthorityRetirementReason,
        failureCause?: unknown,
        localStorageRetirementRequired = false,
    ): Promise<void> {
        this.#localStorageRetirementRequired ||= localStorageRetirementRequired;
        if (this.#state !== 'retired') {
            this.#state = 'retired';
            this.#retirementReason = reason;
            this.#activeCapability = undefined;
        }
        if (this.#cleanupPromise === undefined) {
            const cleanupAttempt = this.#cleanup(failureCause);
            this.#cleanupPromise = cleanupAttempt;
            void cleanupAttempt.catch(() => {
                if (this.#cleanupPromise === cleanupAttempt) {
                    this.#cleanupPromise = undefined;
                }
            });
        }
        return this.#cleanupPromise;
    }

    async #cleanup(failureCause?: unknown): Promise<void> {
        const cleanupFailures: unknown[] = [];
        const throwIfCleanupFailed = (): void => {
            if (cleanupFailures.length > 0) {
                throw new BrowserFoundationAuthorityError(
                    'CleanupFailed',
                    'The participant is retired, but browser-owned resources could not all be closed.',
                    Object.freeze({ cleanupFailures, failureCause }),
                );
            }
        };
        this.#activeStateReservationIdentifiers.clear();
        this.#stateVerifierSessionIdentifier = undefined;
        if (this.#localStorageRetirementRequired) {
            if (!this.#operationOwnerRetirementCompleted) {
                try {
                    await this.#operationOwner.retire();
                    this.#operationOwnerRetirementCompleted = true;
                } catch (error) {
                    cleanupFailures.push(error);
                }
            }
            throwIfCleanupFailed();
            for (const record of this.#issuedStateReservationIntentRecords) {
                record.active = false;
            }
            this.#issuedStateReservationIntentRecords.clear();
        } else {
            for (const record of this.#issuedStateReservationIntentRecords) {
                if (!record.active) {
                    continue;
                }
                try {
                    await this.#operationOwner.releaseFoundationStateReservationIntent(
                        record.handle,
                    );
                    record.active = false;
                } catch (error) {
                    cleanupFailures.push(error);
                }
            }
            throwIfCleanupFailed();
            this.#issuedStateReservationIntentRecords.clear();
        }
        if (!this.#operationOwnerCloseCompleted) {
            try {
                await this.#operationOwner.close();
                this.#operationOwnerCloseCompleted = true;
            } catch (error) {
                cleanupFailures.push(error);
            }
        }
        throwIfCleanupFailed();
        if (!this.#boardCloseCompleted) {
            try {
                this.#board.close();
                this.#boardCloseCompleted = true;
            } catch (error) {
                cleanupFailures.push(error);
            }
        }
        throwIfCleanupFailed();
        this.#canonicalRosterBytes.fill(0);
        this.#actionRandomnessCapability = undefined;
        this.#actionRandomnessHandle = undefined;
        this.#committedFreshBatch = undefined;
        this.#recoveredBatch = undefined;
        this.#stateReservationIntents = new WeakMap();
        this.#stateReservations = new WeakMap();
        this.#durableStateBindings = new WeakMap();
        this.#checkpoints = new WeakMap();
        this.#proofAttempts = new WeakMap();
        for (const record of this.#issuedProofAttemptRecords) {
            record.applicationSlotHash.fill(0);
            record.attemptIdentifier.fill(0);
        }
        this.#issuedProofAttemptRecords.clear();
        for (const record of this.#issuedDurableStateBindingRecords) {
            record.active = false;
        }
        this.#issuedDurableStateBindingRecords.clear();
        for (const role of this.#witnessRoleRecords) {
            role.normalHandle = undefined;
            role.subjectParticipantIdentity.fill(0);
        }
    }
}

export const openBrowserFoundationAuthority = (
    input: BrowserFoundationAuthorityInput,
): Promise<BrowserFoundationAuthority> =>
    prepareAuthority(input).then((prepared) =>
        Object.freeze(new BrowserFoundationAuthorityImplementation(prepared)),
    );
