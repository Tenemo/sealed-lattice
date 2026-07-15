import {
    copyAuthenticatedMailboxFrozenRosterParticipantIdentities,
    openAuthenticatedMailboxFrozenRoster,
} from '@sealed-lattice/crypto';
import {
    BrowserActionStorageCustodyError,
    foundationProfile,
    type BrowserActionProofAttemptBinding,
    type BrowserActionRandomnessRecordContext,
    type BrowserActionRandomnessReservationVerificationInput,
    type BrowserActionStateReservationVerificationInput,
    type BrowserLocalRecordIdentifierInput,
    type BrowserLocalRecordOpenInput,
    type BrowserLocalRecordSealInput,
    type BrowserPersistentProofAttemptInput,
    type BrowserTargetReleaseAttemptInput,
    type RefusalReason,
    type VerificationResult,
} from '@sealed-lattice/types';
import type {
    ProofApplicationReservationBinding,
    UntrustedCanonicalBoardCarrier,
    VerifiedStateDurableBinding,
    VerifiedTranscriptObject,
} from '@sealed-lattice/wasm';

import type {
    AuthenticatedCheckpointStore,
    CheckpointBoundary,
    CheckpointOperationIdentity,
    ExpectedCheckpointBoundary,
    ResumedCheckpoint,
} from './authenticated-checkpoint-store.js';
import { AuthenticatedRuntimeRecordError } from './authenticated-runtime-record.js';
import type { BrowserActionStorageCustody } from './browser-action-storage-custody.js';
import type {
    CanonicalBoardRuntime,
    VerifiedCanonicalBoardSnapshot,
} from './canonical-board-runtime.js';
import type { DurableStateWitnessService } from './durable-state-witness-service.js';
import type {
    NamespaceFreshnessActiveCapability,
    NamespaceFreshnessSubjectRuntime,
    NamespaceFreshnessWitnessService,
} from './namespace-freshness-runtime.js';
import type {
    ProofApplicationLedger,
    ProofApplicationLedgerSnapshot,
    ProofApplicationReservation,
    ProofApplicationReservationCapability,
} from './proof-application-ledger.js';

const foundationHashByteLength = 64;

declare const browserFoundationActiveCapabilityBrand: unique symbol;
declare const browserFoundationActionRandomnessBrand: unique symbol;
declare const browserFoundationStateReservationBrand: unique symbol;
declare const browserFoundationCheckpointBrand: unique symbol;
declare const browserFoundationProofAttemptBrand: unique symbol;
declare const browserFoundationWitnessRoleBrand: unique symbol;

export type BrowserFoundationActiveCapability = Readonly<{
    readonly [browserFoundationActiveCapabilityBrand]: true;
}>;

export type BrowserFoundationActionRandomness = Readonly<{
    readonly [browserFoundationActionRandomnessBrand]: true;
}>;

export type BrowserFoundationStateReservation = Readonly<{
    readonly [browserFoundationStateReservationBrand]: true;
}>;

export type BrowserFoundationCheckpoint = Readonly<{
    readonly [browserFoundationCheckpointBrand]: true;
}>;

export type BrowserFoundationProofAttempt = Readonly<{
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
    | 'localStateConflict'
    | 'localStateUnavailable'
    | 'namespaceRetired'
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

export type BrowserFoundationWitnessRoleInput = Readonly<{
    durableStateService: DurableStateWitnessService;
    namespaceFreshnessService: NamespaceFreshnessWitnessService;
    subjectParticipantIdentity: Uint8Array;
}>;

export type BrowserFoundationActionRandomnessDescription = Readonly<{
    actionRandomnessCommitment: Uint8Array;
    canonicalEnvelope: Uint8Array;
}>;

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

export type BrowserFoundationPersistentProofAttemptInput = Omit<
    BrowserPersistentProofAttemptInput,
    'actionRandomnessSessionIdentifier' | 'stateReservationIdentifier'
>;

export type BrowserFoundationTargetReleaseAttemptInput = Omit<
    BrowserTargetReleaseAttemptInput,
    'actionRandomnessSessionIdentifier' | 'stateReservationIdentifier'
>;

export type BrowserFoundationAuthority = Readonly<{
    activeCapability(): BrowserFoundationActiveCapability;
    beginCheckpoint(
        capability: BrowserFoundationActiveCapability,
        proofAttempts: readonly BrowserFoundationProofAttempt[],
    ): Promise<BrowserFoundationCheckpoint>;
    beginProofVerification(
        capability: BrowserFoundationActiveCapability,
        input: {
            proofQueryCount: bigint;
            reservation: ProofApplicationReservationCapability;
            signatureVerificationCount: number;
        },
    ): Promise<ProofApplicationReservation>;
    cacheWitnessExactOutput(
        capability: BrowserFoundationActiveCapability,
        witnessRole: BrowserFoundationWitnessRole,
        input: {
            exactOutputBytes: Uint8Array;
            verifiedOutputBinding: VerifiedStateDurableBinding;
        },
    ): Promise<void>;
    cacheWitnessSignedVoteCarrier(
        capability: BrowserFoundationActiveCapability,
        witnessRole: BrowserFoundationWitnessRole,
        input: {
            canonicalSignedVoteCarrier: Uint8Array;
            verifiedIntentBinding: VerifiedStateDurableBinding;
        },
    ): Promise<Uint8Array>;
    certifyMutation(
        capability: BrowserFoundationActiveCapability,
        durableMutation: () => Promise<void>,
    ): Promise<BrowserFoundationAuthorityState>;
    close(): Promise<void>;
    closeActionRandomness(
        capability: BrowserFoundationActiveCapability,
        actionRandomness: BrowserFoundationActionRandomness,
    ): Promise<void>;
    copyActionRandomnessDescription(
        capability: BrowserFoundationActiveCapability,
        actionRandomness: BrowserFoundationActionRandomness,
    ): Promise<BrowserFoundationActionRandomnessDescription>;
    copyCheckpointDescription(
        capability: BrowserFoundationActiveCapability,
        checkpoint: BrowserFoundationCheckpoint,
    ): Promise<BrowserFoundationCheckpointDescription>;
    copyProofAttemptBinding(
        capability: BrowserFoundationActiveCapability,
        proofAttempt: BrowserFoundationProofAttempt,
    ): Promise<BrowserActionProofAttemptBinding>;
    copyProofApplicationReservation(
        capability: BrowserFoundationActiveCapability,
        reservation: ProofApplicationReservationCapability,
    ): Promise<ProofApplicationReservation>;
    hashLocalRecordEnvelope(
        capability: BrowserFoundationActiveCapability,
        envelope: Uint8Array,
    ): Promise<Uint8Array>;
    createActionRandomness(
        capability: BrowserFoundationActiveCapability,
        input: BrowserActionRandomnessRecordContext,
    ): Promise<BrowserFoundationActionRandomness>;
    deriveLocalRecordIdentifier(
        capability: BrowserFoundationActiveCapability,
        input: BrowserLocalRecordIdentifierInput,
    ): Promise<Uint8Array>;
    derivePersistentProofAttempt(
        capability: BrowserFoundationActiveCapability,
        actionRandomness: BrowserFoundationActionRandomness,
        stateReservation: BrowserFoundationStateReservation,
        input: BrowserFoundationPersistentProofAttemptInput,
    ): Promise<BrowserFoundationProofAttempt>;
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
    openLocalRecord(
        capability: BrowserFoundationActiveCapability,
        input: BrowserLocalRecordOpenInput,
    ): Promise<Uint8Array>;
    proofApplicationSnapshot(
        capability: BrowserFoundationActiveCapability,
    ): Promise<ProofApplicationLedgerSnapshot>;
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
        input: { verifiedOutputBinding: VerifiedStateDurableBinding },
    ): Promise<Uint8Array>;
    readWitnessSignedVoteCarrier(
        capability: BrowserFoundationActiveCapability,
        witnessRole: BrowserFoundationWitnessRole,
        input: { verifiedIntentBinding: VerifiedStateDurableBinding },
    ): Promise<Uint8Array>;
    releaseProofReservationBeforeVerification(
        capability: BrowserFoundationActiveCapability,
        reservation: ProofApplicationReservationCapability,
    ): Promise<boolean>;
    releaseStateReservation(
        capability: BrowserFoundationActiveCapability,
        stateReservation: BrowserFoundationStateReservation,
    ): Promise<void>;
    reserveProofApplication(
        capability: BrowserFoundationActiveCapability,
        reservationBinding: ProofApplicationReservationBinding,
    ): Promise<ProofApplicationReservationCapability>;
    restoreCheckpointState(
        capability: BrowserFoundationActiveCapability,
        checkpoint: BrowserFoundationCheckpoint,
        consumeChunk: (
            chunkIndex: number,
            chunkBytes: Uint8Array,
        ) => Promise<void> | void,
    ): Promise<void>;
    resumeActionRandomness(
        capability: BrowserFoundationActiveCapability,
        input: BrowserActionRandomnessRecordContext &
            BrowserFoundationActionRandomnessDescription,
    ): Promise<BrowserFoundationActionRandomness>;
    resumeCheckpoint(
        capability: BrowserFoundationActiveCapability,
        input: {
            checkpointLineageIdentifier: Uint8Array;
            expectedBoundary: ExpectedCheckpointBoundary;
        },
    ): Promise<BrowserFoundationCheckpoint>;
    sealLocalRecord(
        capability: BrowserFoundationActiveCapability,
        input: BrowserLocalRecordSealInput,
    ): Promise<Uint8Array>;
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
    witnessRoles(
        capability: BrowserFoundationActiveCapability,
    ): Promise<readonly BrowserFoundationWitnessRole[]>;
    copyWitnessRoleDescription(
        capability: BrowserFoundationActiveCapability,
        witnessRole: BrowserFoundationWitnessRole,
    ): Promise<BrowserFoundationWitnessRoleDescription>;
    compareAndLockWitnessIntent(
        capability: BrowserFoundationActiveCapability,
        witnessRole: BrowserFoundationWitnessRole,
        input: { verifiedIntentBinding: VerifiedStateDurableBinding },
    ): Promise<void>;
    voteForNamespaceCheckpoint(
        capability: BrowserFoundationActiveCapability,
        witnessRole: BrowserFoundationWitnessRole,
        canonicalCheckpoint: Uint8Array,
    ): Promise<VerificationResult<Uint8Array>>;
}>;

export type BrowserFoundationAuthorityInput = Readonly<{
    canonicalBoardRuntime: CanonicalBoardRuntime;
    checkpointStore: AuthenticatedCheckpointStore;
    custody: BrowserActionStorageCustody;
    namespaceFreshnessRuntime: NamespaceFreshnessSubjectRuntime;
    orderedWitnessRoles: readonly BrowserFoundationWitnessRoleInput[];
    proofApplicationLedger: ProofApplicationLedger;
    runtimeBuildManifestHash: Uint8Array;
}>;

type ActionRandomnessRecord = Readonly<{
    actionRandomnessCommitment: Uint8Array;
    canonicalEnvelope: Uint8Array;
    identifier: string;
}>;

type StateReservationRecord = Readonly<{ identifier: string }>;

type CheckpointRecord = Readonly<{
    identity: CheckpointOperationIdentity;
    resumed?: ResumedCheckpoint;
}>;

type ProofAttemptRecord = Readonly<{
    applicationSlotHash: Uint8Array;
    attemptIdentifier: Uint8Array;
}>;

type WitnessRoleRecord = Readonly<{
    durableStateService: DurableStateWitnessService;
    namespaceFreshnessService: NamespaceFreshnessWitnessService;
    subjectParticipantIdentity: Uint8Array;
}>;

const valid = <Value>(value: Value): VerificationResult<Value> =>
    Object.freeze({ isValid: true, value });

const refused = <Value>(
    refusalReason: RefusalReason,
): VerificationResult<Value> =>
    Object.freeze({ isValid: false, refusalReason });

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

const copyHash = (value: unknown, label: string): Uint8Array => {
    if (!isUint8Array(value) || value.byteLength !== foundationHashByteLength) {
        throw new BrowserFoundationAuthorityError(
            'InvalidConfiguration',
            `${label} must contain exactly ${String(foundationHashByteLength)} bytes.`,
        );
    }
    return Uint8Array.from(value);
};

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean => {
    if (left.byteLength !== right.byteLength) {
        return false;
    }
    let difference = 0;
    for (let index = 0; index < left.byteLength; index += 1) {
        difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
    }
    return difference === 0;
};

const bytesKey = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const createOpaqueCapability = <Capability>(): Capability =>
    Object.freeze(Object.create(null) as object) as Capability;

const maximumQueuedCollectionEntryCount = 4096;
const maximumQueuedObjectDepth = 16;

const copyQueuedBytes = (
    value: unknown,
    label: string,
    maximumByteLength = foundationProfile.maximumCopiedBufferByteLength,
): Uint8Array => {
    if (!isUint8Array(value) || value.byteLength > maximumByteLength) {
        throw new BrowserFoundationAuthorityError(
            'InvalidInput',
            `${label} must be a byte array within the browser foundation copy bound.`,
        );
    }
    return Uint8Array.from(value);
};

const copyQueuedData = <Value>(
    value: Value,
    label: string,
    depth = 0,
): Value => {
    if (
        value === undefined ||
        value === null ||
        typeof value === 'string' ||
        typeof value === 'number' ||
        typeof value === 'bigint' ||
        typeof value === 'boolean'
    ) {
        return value;
    }
    if (isUint8Array(value)) {
        return copyQueuedBytes(value, label) as Value;
    }
    if (depth >= maximumQueuedObjectDepth) {
        throw new BrowserFoundationAuthorityError(
            'InvalidInput',
            `${label} exceeds the browser foundation input nesting bound.`,
        );
    }
    if (Array.isArray(value)) {
        if (value.length > maximumQueuedCollectionEntryCount) {
            throw new BrowserFoundationAuthorityError(
                'InvalidInput',
                `${label} exceeds the browser foundation collection bound.`,
            );
        }
        return Object.freeze(
            value.map((entry, entryIndex) =>
                copyQueuedData(
                    entry,
                    `${label}[${String(entryIndex)}]`,
                    depth + 1,
                ),
            ),
        ) as Value;
    }
    if (typeof value === 'object') {
        const prototype = Object.getPrototypeOf(value);
        if (prototype !== Object.prototype && prototype !== null) {
            throw new BrowserFoundationAuthorityError(
                'InvalidInput',
                `${label} must contain only plain structured-clone data.`,
            );
        }
        const entries = Object.entries(value);
        if (entries.length > maximumQueuedCollectionEntryCount) {
            throw new BrowserFoundationAuthorityError(
                'InvalidInput',
                `${label} exceeds the browser foundation object-field bound.`,
            );
        }
        return Object.freeze(
            Object.fromEntries(
                entries.map(([fieldName, fieldValue]) => [
                    fieldName,
                    copyQueuedData(
                        fieldValue,
                        `${label}.${fieldName}`,
                        depth + 1,
                    ),
                ]),
            ),
        ) as Value;
    }
    throw new BrowserFoundationAuthorityError(
        'InvalidInput',
        `${label} contains unsupported queued input data.`,
    );
};

const createBoundedCopiedChunkSource = (
    source: AsyncIterable<Uint8Array> | Iterable<Uint8Array>,
): AsyncIterable<Uint8Array> => {
    if (typeof source !== 'object' || source === null) {
        throw new BrowserFoundationAuthorityError(
            'InvalidInput',
            'Checkpoint state chunks must be iterable.',
        );
    }
    const asyncIteratorFactory = source[Symbol.asyncIterator];
    const synchronousIteratorFactory = source[Symbol.iterator];
    const iterator: AsyncIterator<Uint8Array> | Iterator<Uint8Array> =
        typeof asyncIteratorFactory === 'function'
            ? asyncIteratorFactory.call(source)
            : typeof synchronousIteratorFactory === 'function'
              ? synchronousIteratorFactory.call(source)
              : (() => {
                    throw new BrowserFoundationAuthorityError(
                        'InvalidInput',
                        'Checkpoint state chunks must be iterable.',
                    );
                })();
    if (typeof iterator?.next !== 'function') {
        throw new BrowserFoundationAuthorityError(
            'InvalidInput',
            'Checkpoint state chunks returned an invalid iterator.',
        );
    }

    let nextChunkIndex = 0;
    let iterationClaimed = false;
    let sourceFinished = false;
    const readNext = async (): Promise<IteratorResult<Uint8Array>> => {
        const result = await iterator.next();
        if (typeof result !== 'object' || result === null) {
            throw new BrowserFoundationAuthorityError(
                'InvalidInput',
                'Checkpoint state chunks returned an invalid iterator result.',
            );
        }
        if (result.done === true) {
            sourceFinished = true;
            return { done: true, value: undefined };
        }
        const copied = copyQueuedBytes(
            result.value,
            `stateChunks[${String(nextChunkIndex)}]`,
            foundationProfile.streamChunkByteLength,
        );
        nextChunkIndex += 1;
        return { done: false, value: copied };
    };
    let pendingResult = readNext();

    return Object.freeze({
        [Symbol.asyncIterator](): AsyncIterator<Uint8Array> {
            if (iterationClaimed) {
                throw new BrowserFoundationAuthorityError(
                    'InvalidInput',
                    'Checkpoint state chunks can be consumed only once.',
                );
            }
            iterationClaimed = true;
            return {
                next: async (): Promise<IteratorResult<Uint8Array>> => {
                    const result = await pendingResult;
                    if (!result.done) {
                        pendingResult = readNext();
                    }
                    return result;
                },
                return: async (): Promise<IteratorResult<Uint8Array>> => {
                    if (!sourceFinished && typeof iterator.return === 'function') {
                        await iterator.return();
                    }
                    sourceFinished = true;
                    return { done: true, value: undefined };
                },
            };
        },
    });
};

const validateWitnessRoles = (
    subjectParticipantIdentity: Uint8Array,
    orderedRosterParticipantIdentities: readonly Uint8Array[],
    sharedBinding: Readonly<{
        actionContextHash: Uint8Array;
        ceremonyContextHash: Uint8Array;
        runtimeBuildManifestHash: Uint8Array;
        suiteIdentifier: Uint8Array;
    }>,
    roles: readonly BrowserFoundationWitnessRoleInput[],
): readonly WitnessRoleRecord[] => {
    const subjectRosterPositions = orderedRosterParticipantIdentities
        .map((identity, rosterPosition) =>
            bytesEqual(subjectParticipantIdentity, identity)
                ? rosterPosition
                : -1,
        )
        .filter((rosterPosition) => rosterPosition >= 0);
    if (subjectRosterPositions.length !== 1) {
        throw new BrowserFoundationAuthorityError(
            'InvalidConfiguration',
            'The browser action-storage owner must occur exactly once in the canonical roster.',
        );
    }
    const expectedWitnessIdentities = orderedRosterParticipantIdentities.filter(
        (_identity, rosterPosition) =>
            rosterPosition !== subjectRosterPositions[0],
    );
    if (
        !Array.isArray(roles) ||
        roles.length !== expectedWitnessIdentities.length ||
        roles.length !== foundationProfile.participantCount - 1
    ) {
        throw new BrowserFoundationAuthorityError(
            'InvalidConfiguration',
            `The browser foundation authority requires exactly ${String(foundationProfile.participantCount - 1)} fixed-roster witness roles.`,
        );
    }
    const configuredRoles =
        roles as readonly BrowserFoundationWitnessRoleInput[];
    const copied = Array.from(configuredRoles, (role, roleIndex) => {
        if (typeof role !== 'object' || role === null) {
            throw new BrowserFoundationAuthorityError(
                'InvalidConfiguration',
                `orderedWitnessRoles[${String(roleIndex)}] must be an object.`,
            );
        }
        const witnessSubjectIdentity = copyHash(
            role.subjectParticipantIdentity,
            `orderedWitnessRoles[${String(roleIndex)}].subjectParticipantIdentity`,
        );
        if (
            typeof role.namespaceFreshnessService?.vote !== 'function' ||
            typeof role.namespaceFreshnessService?.state !== 'function' ||
            typeof role.namespaceFreshnessService?.copyBinding !== 'function' ||
            typeof role.durableStateService?.compareAndLockIntent !==
                'function' ||
            typeof role.durableStateService?.copyAuthorityContext !==
                'function' ||
            typeof role.durableStateService?.cacheSignedVoteCarrier !==
                'function' ||
            typeof role.durableStateService?.readSignedVoteCarrier !==
                'function' ||
            typeof role.durableStateService?.cacheExactOutput !== 'function' ||
            typeof role.durableStateService?.readExactOutput !== 'function'
        ) {
            throw new BrowserFoundationAuthorityError(
                'InvalidConfiguration',
                `orderedWitnessRoles[${String(roleIndex)}] has an invalid witness service.`,
            );
        }
        if (bytesEqual(subjectParticipantIdentity, witnessSubjectIdentity)) {
            throw new BrowserFoundationAuthorityError(
                'InvalidConfiguration',
                'A participant cannot configure itself as a witnessed subject.',
            );
        }
        if (
            !bytesEqual(
                expectedWitnessIdentities[roleIndex],
                witnessSubjectIdentity,
            )
        ) {
            throw new BrowserFoundationAuthorityError(
                'InvalidConfiguration',
                `orderedWitnessRoles[${String(roleIndex)}] is not the corresponding other identity from the canonical roster.`,
            );
        }
        let namespaceWitnessBinding;
        let durableStateAuthorityContext;
        try {
            namespaceWitnessBinding =
                role.namespaceFreshnessService.copyBinding();
            durableStateAuthorityContext =
                role.durableStateService.copyAuthorityContext();
        } catch (error) {
            throw new BrowserFoundationAuthorityError(
                'InvalidConfiguration',
                `orderedWitnessRoles[${String(roleIndex)}] could not disclose its retained authority binding.`,
                error,
            );
        }
        try {
            const serviceBindings = [
                [
                    'namespace subject identity',
                    namespaceWitnessBinding.context.subjectParticipantIdentity,
                    witnessSubjectIdentity,
                ],
                [
                    'namespace witness identity',
                    namespaceWitnessBinding.witnessParticipantIdentity,
                    subjectParticipantIdentity,
                ],
                [
                    'namespace suite identifier',
                    namespaceWitnessBinding.context.suiteIdentifier,
                    sharedBinding.suiteIdentifier,
                ],
                [
                    'namespace ceremony context',
                    namespaceWitnessBinding.context.ceremonyContextHash,
                    sharedBinding.ceremonyContextHash,
                ],
                [
                    'namespace action context',
                    namespaceWitnessBinding.context.actionContextHash,
                    sharedBinding.actionContextHash,
                ],
                [
                    'durable-state owner identity',
                    durableStateAuthorityContext.ownerParticipantIdentity,
                    subjectParticipantIdentity,
                ],
                [
                    'durable-state suite identifier',
                    durableStateAuthorityContext.suiteIdentifier,
                    sharedBinding.suiteIdentifier,
                ],
                [
                    'durable-state ceremony context',
                    durableStateAuthorityContext.ceremonyContextHash,
                    sharedBinding.ceremonyContextHash,
                ],
                [
                    'durable-state action context',
                    durableStateAuthorityContext.actionContextHash,
                    sharedBinding.actionContextHash,
                ],
                [
                    'durable-state runtime build manifest',
                    durableStateAuthorityContext.runtimeBuildManifestHash,
                    sharedBinding.runtimeBuildManifestHash,
                ],
            ] as const;
            for (const [serviceLabel, candidate, expected] of serviceBindings) {
                if (
                    isUint8Array(candidate) &&
                    bytesEqual(candidate, expected)
                ) {
                    continue;
                }
                throw new BrowserFoundationAuthorityError(
                    'InvalidConfiguration',
                    `orderedWitnessRoles[${String(roleIndex)}] has a cross-wired ${serviceLabel}.`,
                );
            }
            if (
                !isUint8Array(
                    namespaceWitnessBinding.context.storageInstanceIdentity,
                ) ||
                namespaceWitnessBinding.context.storageInstanceIdentity
                    .byteLength !== foundationHashByteLength
            ) {
                throw new BrowserFoundationAuthorityError(
                    'InvalidConfiguration',
                    `orderedWitnessRoles[${String(roleIndex)}] has a malformed namespace storage-instance identity.`,
                );
            }
            return Object.freeze({
                durableStateService: role.durableStateService,
                namespaceFreshnessService: role.namespaceFreshnessService,
                subjectParticipantIdentity: witnessSubjectIdentity,
            });
        } finally {
            for (const value of [
                namespaceWitnessBinding.context.actionContextHash,
                namespaceWitnessBinding.context.ceremonyContextHash,
                namespaceWitnessBinding.context.storageInstanceIdentity,
                namespaceWitnessBinding.context.subjectParticipantIdentity,
                namespaceWitnessBinding.context.suiteIdentifier,
                namespaceWitnessBinding.witnessParticipantIdentity,
                durableStateAuthorityContext.actionContextHash,
                durableStateAuthorityContext.ceremonyContextHash,
                durableStateAuthorityContext.ownerParticipantIdentity,
                durableStateAuthorityContext.runtimeBuildManifestHash,
                durableStateAuthorityContext.suiteIdentifier,
            ]) {
                if (isUint8Array(value)) {
                    value.fill(0);
                }
            }
        }
    });
    const identities = copied.map((role) =>
        bytesKey(role.subjectParticipantIdentity),
    );
    if (new Set(identities).size !== identities.length) {
        throw new BrowserFoundationAuthorityError(
            'InvalidConfiguration',
            'Fixed-roster witness roles must have distinct subject identities.',
        );
    }
    return Object.freeze(copied);
};

const requireComponentBinding = (
    input: BrowserFoundationAuthorityInput,
): {
    actionContextHash: Uint8Array;
    canonicalRosterBytes: Uint8Array;
    ceremonyContextHash: Uint8Array;
    orderedRosterParticipantIdentities: readonly Uint8Array[];
    runtimeBuildManifestHash: Uint8Array;
    subjectParticipantIdentity: Uint8Array;
    suiteIdentifier: Uint8Array;
} => {
    let boardConfiguration;
    let custodyBinding;
    let namespaceContext;
    let proofAuthorityContext;
    let checkpointAuthorityContext;
    try {
        boardConfiguration = input.canonicalBoardRuntime.copyConfiguration();
        custodyBinding = input.custody.copyBinding();
        namespaceContext = input.namespaceFreshnessRuntime.copyContext();
        proofAuthorityContext =
            input.proofApplicationLedger.copyAuthorityContext();
        checkpointAuthorityContext =
            input.checkpointStore.copyAuthorityContext();
    } catch (error) {
        throw new BrowserFoundationAuthorityError(
            'InvalidConfiguration',
            'A browser foundation component could not disclose its retained authority binding.',
            error,
        );
    }
    let actionContextHash: Uint8Array | undefined;
    let ceremonyContextHash: Uint8Array | undefined;
    let expectedRuntimeBuildManifestHash: Uint8Array | undefined;
    let orderedRosterParticipantIdentities: readonly Uint8Array[] | undefined;
    let subjectParticipantIdentity: Uint8Array | undefined;
    let suiteIdentifier: Uint8Array | undefined;
    let returnedBinding = false;
    try {
        suiteIdentifier = copyHash(
            boardConfiguration.suiteIdentifier,
            'canonicalBoardRuntime.suiteIdentifier',
        );
        ceremonyContextHash = copyHash(
            boardConfiguration.ceremonyContextHash,
            'canonicalBoardRuntime.ceremonyContextHash',
        );
        actionContextHash = copyHash(
            boardConfiguration.actionContextHash,
            'canonicalBoardRuntime.actionContextHash',
        );
        subjectParticipantIdentity = copyHash(
            custodyBinding.participantId,
            'custody.participantId',
        );
        expectedRuntimeBuildManifestHash = copyHash(
            input.runtimeBuildManifestHash,
            'runtimeBuildManifestHash',
        );
        const comparedBindings = [
            ['custody.suiteId', custodyBinding.suiteId, suiteIdentifier],
            [
                'custody.ceremonyContextHash',
                custodyBinding.ceremonyContextHash,
                ceremonyContextHash,
            ],
            [
                'custody.actionContextHash',
                custodyBinding.actionContextHash,
                actionContextHash,
            ],
            [
                'namespaceFreshnessRuntime.suiteIdentifier',
                namespaceContext.suiteIdentifier,
                suiteIdentifier,
            ],
            [
                'namespaceFreshnessRuntime.ceremonyContextHash',
                namespaceContext.ceremonyContextHash,
                ceremonyContextHash,
            ],
            [
                'namespaceFreshnessRuntime.actionContextHash',
                namespaceContext.actionContextHash,
                actionContextHash,
            ],
            [
                'namespaceFreshnessRuntime.subjectParticipantIdentity',
                namespaceContext.subjectParticipantIdentity,
                subjectParticipantIdentity,
            ],
            [
                'proofApplicationLedger.suiteIdentifier',
                proofAuthorityContext.suiteIdentifier,
                suiteIdentifier,
            ],
            [
                'proofApplicationLedger.ceremonyContextHash',
                proofAuthorityContext.ceremonyContextHash,
                ceremonyContextHash,
            ],
            [
                'proofApplicationLedger.actionContextHash',
                proofAuthorityContext.actionContextHash,
                actionContextHash,
            ],
            [
                'proofApplicationLedger.ownerParticipantIdentity',
                proofAuthorityContext.ownerParticipantIdentity,
                subjectParticipantIdentity,
            ],
            [
                'checkpointStore.suiteIdentifier',
                checkpointAuthorityContext.suiteIdentifier,
                suiteIdentifier,
            ],
            [
                'checkpointStore.ceremonyContextHash',
                checkpointAuthorityContext.ceremonyContextHash,
                ceremonyContextHash,
            ],
            [
                'checkpointStore.actionContextHash',
                checkpointAuthorityContext.actionContextHash,
                actionContextHash,
            ],
            [
                'checkpointStore.ownerParticipantIdentity',
                checkpointAuthorityContext.ownerParticipantIdentity,
                subjectParticipantIdentity,
            ],
            [
                'proofApplicationLedger.runtimeBuildManifestHash',
                proofAuthorityContext.runtimeBuildManifestHash,
                expectedRuntimeBuildManifestHash,
            ],
            [
                'checkpointStore.runtimeBuildManifestHash',
                checkpointAuthorityContext.runtimeBuildManifestHash,
                expectedRuntimeBuildManifestHash,
            ],
        ] as const;
        for (const [label, candidate, expected] of comparedBindings) {
            if (isUint8Array(candidate) && bytesEqual(candidate, expected)) {
                continue;
            }
            throw new BrowserFoundationAuthorityError(
                'InvalidConfiguration',
                `${label} is cross-wired to a different browser foundation authority context.`,
            );
        }
        if (
            !isUint8Array(namespaceContext.storageInstanceIdentity) ||
            namespaceContext.storageInstanceIdentity.byteLength !==
                foundationHashByteLength
        ) {
            throw new BrowserFoundationAuthorityError(
                'InvalidConfiguration',
                'The namespace freshness storage-instance identity is malformed.',
            );
        }
        if (
            !isUint8Array(boardConfiguration.canonicalRosterBytes) ||
            boardConfiguration.canonicalRosterBytes.byteLength === 0
        ) {
            throw new BrowserFoundationAuthorityError(
                'InvalidConfiguration',
                'The canonical board roster bytes must not be empty.',
            );
        }
        try {
            orderedRosterParticipantIdentities =
                copyAuthenticatedMailboxFrozenRosterParticipantIdentities(
                    openAuthenticatedMailboxFrozenRoster(
                        boardConfiguration.canonicalRosterBytes,
                    ),
                );
        } catch (error) {
            throw new BrowserFoundationAuthorityError(
                'InvalidConfiguration',
                'The canonical board does not retain a valid fixed foundation roster.',
                error,
            );
        }
        if (orderedRosterParticipantIdentities === undefined) {
            throw new BrowserFoundationAuthorityError(
                'InvalidConfiguration',
                'The canonical board roster identities are unavailable.',
            );
        }
        const retainedBinding = {
            actionContextHash: actionContextHash.slice(),
            canonicalRosterBytes:
                boardConfiguration.canonicalRosterBytes.slice(),
            ceremonyContextHash: ceremonyContextHash.slice(),
            orderedRosterParticipantIdentities,
            runtimeBuildManifestHash: expectedRuntimeBuildManifestHash.slice(),
            subjectParticipantIdentity: subjectParticipantIdentity.slice(),
            suiteIdentifier: suiteIdentifier.slice(),
        };
        returnedBinding = true;
        return retainedBinding;
    } finally {
        actionContextHash?.fill(0);
        ceremonyContextHash?.fill(0);
        expectedRuntimeBuildManifestHash?.fill(0);
        subjectParticipantIdentity?.fill(0);
        suiteIdentifier?.fill(0);
        if (!returnedBinding) {
            for (const identity of orderedRosterParticipantIdentities ?? []) {
                identity.fill(0);
            }
        }
        for (const value of [
            boardConfiguration.actionContextHash,
            boardConfiguration.canonicalRosterBytes,
            boardConfiguration.ceremonyContextHash,
            boardConfiguration.suiteIdentifier,
            custodyBinding.actionContextHash,
            custodyBinding.ceremonyContextHash,
            custodyBinding.participantId,
            custodyBinding.suiteId,
            namespaceContext.actionContextHash,
            namespaceContext.ceremonyContextHash,
            namespaceContext.storageInstanceIdentity,
            namespaceContext.subjectParticipantIdentity,
            namespaceContext.suiteIdentifier,
            proofAuthorityContext.actionContextHash,
            proofAuthorityContext.ceremonyContextHash,
            proofAuthorityContext.ownerParticipantIdentity,
            proofAuthorityContext.runtimeBuildManifestHash,
            proofAuthorityContext.suiteIdentifier,
            checkpointAuthorityContext.actionContextHash,
            checkpointAuthorityContext.ceremonyContextHash,
            checkpointAuthorityContext.ownerParticipantIdentity,
            checkpointAuthorityContext.runtimeBuildManifestHash,
            checkpointAuthorityContext.suiteIdentifier,
        ]) {
            if (isUint8Array(value)) {
                value.fill(0);
            }
        }
    }
};

const custodyFailureRetirementReason = (
    error: unknown,
): BrowserFoundationAuthorityRetirementReason | undefined => {
    if (error instanceof BrowserFoundationAuthorityError) {
        return undefined;
    }
    if (!(error instanceof BrowserActionStorageCustodyError)) {
        return 'stateAuthorityUnavailable';
    }
    switch (error.code) {
        case 'CommitmentMismatch':
        case 'RecordAuthenticationFailed':
            return 'localStateAuthenticationFailed';
        case 'Conflict':
            return 'localStateConflict';
        case 'Closed':
        case 'InvalidState':
        case 'OwnedWorkerFailure':
        case 'StorageFailure':
        case 'Unavailable':
            return 'localStateUnavailable';
        case 'CommitmentRequired':
        case 'InvalidCanonicalMaterial':
        case 'InvalidInput':
            return undefined;
    }
};

const storageFailureRetirementReason = (
    error: unknown,
    conflictRetires: boolean,
): BrowserFoundationAuthorityRetirementReason | undefined => {
    if (
        error instanceof BrowserFoundationAuthorityError ||
        error instanceof TypeError
    ) {
        return undefined;
    }
    if (!(error instanceof AuthenticatedRuntimeRecordError)) {
        return 'localStateUnavailable';
    }
    switch (error.code) {
        case 'AuthenticationFailed':
        case 'MissingRecord':
            return 'localStateAuthenticationFailed';
        case 'Conflict':
            return conflictRetires ? 'localStateConflict' : undefined;
        case 'CleanupFailed':
        case 'EntropyFailure':
        case 'StorageFailure':
            return 'localStateUnavailable';
        case 'InvalidConfiguration':
        case 'InvalidInput':
        case 'InvalidState':
        case 'ResourceLimit':
            return undefined;
    }
};

class BrowserFoundationAuthorityImplementation implements BrowserFoundationAuthority {
    readonly #canonicalBoardRuntime: CanonicalBoardRuntime;
    readonly #canonicalRosterBytes: Uint8Array;
    readonly #checkpointStore: AuthenticatedCheckpointStore;
    readonly #custody: BrowserActionStorageCustody;
    readonly #namespaceFreshnessRuntime: NamespaceFreshnessSubjectRuntime;
    readonly #proofApplicationLedger: ProofApplicationLedger;
    readonly #witnessRoleRecords = new WeakMap<object, WitnessRoleRecord>();
    readonly #witnessRoles: readonly BrowserFoundationWitnessRole[];
    readonly #actionRandomnessRecords = new WeakMap<
        object,
        ActionRandomnessRecord
    >();
    readonly #stateReservationRecords = new WeakMap<
        object,
        StateReservationRecord
    >();
    readonly #checkpointRecords = new WeakMap<object, CheckpointRecord>();
    readonly #proofAttemptRecords = new WeakMap<object, ProofAttemptRecord>();
    readonly #activeActionRandomnessIdentifiers = new Set<string>();
    readonly #activeStateReservationIdentifiers = new Set<string>();
    #activeCapability: BrowserFoundationActiveCapability | undefined;
    #namespaceCapability: NamespaceFreshnessActiveCapability | undefined;
    #stateVerifierSessionIdentifier: string | undefined;
    #state: BrowserFoundationAuthorityState = 'unavailable';
    #retirementReason: BrowserFoundationAuthorityRetirementReason | undefined;
    #cleanupPromise: Promise<void> | undefined;
    #operationTail: Promise<void> = Promise.resolve();

    public constructor(input: BrowserFoundationAuthorityInput) {
        this.#canonicalBoardRuntime = input.canonicalBoardRuntime;
        const binding = requireComponentBinding(input);
        this.#canonicalRosterBytes = binding.canonicalRosterBytes;
        this.#checkpointStore = input.checkpointStore;
        this.#custody = input.custody;
        this.#namespaceFreshnessRuntime = input.namespaceFreshnessRuntime;
        this.#proofApplicationLedger = input.proofApplicationLedger;
        let constructionSucceeded = false;
        try {
            const roles = validateWitnessRoles(
                binding.subjectParticipantIdentity,
                binding.orderedRosterParticipantIdentities,
                binding,
                input.orderedWitnessRoles,
            );
            const capabilities: BrowserFoundationWitnessRole[] = [];
            for (const role of roles) {
                const capability =
                    createOpaqueCapability<BrowserFoundationWitnessRole>();
                this.#witnessRoleRecords.set(capability, role);
                capabilities.push(capability);
            }
            this.#witnessRoles = Object.freeze(capabilities);
            constructionSucceeded = true;
        } finally {
            binding.subjectParticipantIdentity.fill(0);
            binding.actionContextHash.fill(0);
            binding.ceremonyContextHash.fill(0);
            binding.runtimeBuildManifestHash.fill(0);
            binding.suiteIdentifier.fill(0);
            for (const identity of binding.orderedRosterParticipantIdentities) {
                identity.fill(0);
            }
            if (!constructionSucceeded) {
                this.#canonicalRosterBytes.fill(0);
            }
        }
    }

    public state(): BrowserFoundationAuthorityState {
        return this.#state;
    }

    public retirementReason():
        | BrowserFoundationAuthorityRetirementReason
        | undefined {
        return this.#retirementReason;
    }

    public activeCapability(): BrowserFoundationActiveCapability {
        if (this.#state === 'retired') {
            throw new BrowserFoundationAuthorityError(
                'Retired',
                'The participant is permanently retired for this action.',
            );
        }
        if (this.#state !== 'active' || this.#activeCapability === undefined) {
            throw new BrowserFoundationAuthorityError(
                'InvalidState',
                'The browser foundation authority is not roster-certified and active.',
            );
        }
        return this.#activeCapability;
    }

    public startup(): Promise<BrowserFoundationAuthorityState> {
        return this.#enqueue(async () => {
            this.#assertNotRetired();
            this.#makeUnavailable();
            let namespaceState;
            try {
                namespaceState =
                    await this.#namespaceFreshnessRuntime.startup();
            } catch (error) {
                if (this.#namespaceFreshnessRuntime.state() === 'retired') {
                    await this.#retire('namespaceRetired', error);
                }
                throw error;
            }
            if (namespaceState === 'retired') {
                await this.#retire('namespaceRetired');
                return this.#state;
            }
            if (namespaceState === 'unavailable') {
                return this.#state;
            }
            try {
                if (this.#stateVerifierSessionIdentifier === undefined) {
                    const opened =
                        await this.#custody.openActionStateVerifierSession({
                            canonicalRosterBytes:
                                this.#canonicalRosterBytes.slice(),
                        });
                    if (!opened.isValid) {
                        await this.#retire('stateAuthorityUnavailable', opened);
                        return this.#state;
                    }
                    this.#stateVerifierSessionIdentifier = opened.value;
                }
                this.#namespaceCapability =
                    this.#namespaceFreshnessRuntime.activeCapability();
                this.#activeCapability =
                    createOpaqueCapability<BrowserFoundationActiveCapability>();
                this.#state = 'active';
                return this.#state;
            } catch (error) {
                const reason = custodyFailureRetirementReason(error);
                if (reason !== undefined) {
                    await this.#retire(reason, error);
                }
                throw error;
            }
        });
    }

    public certifyMutation(
        capability: BrowserFoundationActiveCapability,
        durableMutation: () => Promise<void>,
    ): Promise<BrowserFoundationAuthorityState> {
        return this.#enqueue(async () => {
            this.#requireActive(capability);
            if (typeof durableMutation !== 'function') {
                throw new BrowserFoundationAuthorityError(
                    'InvalidInput',
                    'The durable mutation must be a function.',
                );
            }
            this.#makeUnavailable();
            let namespaceState;
            try {
                namespaceState =
                    await this.#namespaceFreshnessRuntime.certifyMutation(
                        durableMutation,
                    );
            } catch (error) {
                if (this.#namespaceFreshnessRuntime.state() === 'retired') {
                    await this.#retire('namespaceRetired', error);
                }
                throw error;
            }
            if (namespaceState === 'retired') {
                await this.#retire('namespaceRetired');
                return this.#state;
            }
            if (namespaceState === 'unavailable') {
                return this.#state;
            }
            this.#namespaceCapability =
                this.#namespaceFreshnessRuntime.activeCapability();
            this.#activeCapability =
                createOpaqueCapability<BrowserFoundationActiveCapability>();
            this.#state = 'active';
            return this.#state;
        });
    }

    public ingestCanonicalBoard(
        capability: BrowserFoundationActiveCapability,
        carriers: readonly UntrustedCanonicalBoardCarrier[],
    ): Promise<VerificationResult<VerifiedCanonicalBoardSnapshot>> {
        const copiedCarriers = copyQueuedData(carriers, 'carriers');
        return this.#enqueueActive(capability, () =>
            Promise.resolve(
                this.#canonicalBoardRuntime.ingestUnordered(copiedCarriers),
            ),
        );
    }

    public listCanonicalBoardObjects(
        capability: BrowserFoundationActiveCapability,
        snapshot: VerifiedCanonicalBoardSnapshot,
    ): Promise<VerificationResult<readonly VerifiedTranscriptObject[]>> {
        return this.#enqueueActive(capability, () =>
            Promise.resolve(this.#canonicalBoardRuntime.objects(snapshot)),
        );
    }

    public deriveLocalRecordIdentifier(
        capability: BrowserFoundationActiveCapability,
        input: BrowserLocalRecordIdentifierInput,
    ): Promise<Uint8Array> {
        const copiedInput = copyQueuedData(input, 'input');
        return this.#custodyOperation(capability, () =>
            this.#custody.deriveLocalRecordIdentifier(copiedInput),
        );
    }

    public sealLocalRecord(
        capability: BrowserFoundationActiveCapability,
        input: BrowserLocalRecordSealInput,
    ): Promise<Uint8Array> {
        const copiedInput = copyQueuedData(input, 'input');
        return this.#custodyOperation(capability, () =>
            this.#custody.sealLocalRecord(copiedInput),
        );
    }

    public openLocalRecord(
        capability: BrowserFoundationActiveCapability,
        input: BrowserLocalRecordOpenInput,
    ): Promise<Uint8Array> {
        const copiedInput = copyQueuedData(input, 'input');
        return this.#custodyOperation(capability, () =>
            this.#custody.openLocalRecord(copiedInput),
        );
    }

    public hashLocalRecordEnvelope(
        capability: BrowserFoundationActiveCapability,
        envelope: Uint8Array,
    ): Promise<Uint8Array> {
        const copiedEnvelope = copyQueuedBytes(envelope, 'envelope');
        return this.#custodyOperation(capability, () =>
            this.#custody.hashLocalRecordEnvelope(copiedEnvelope),
        );
    }

    public createActionRandomness(
        capability: BrowserFoundationActiveCapability,
        input: BrowserActionRandomnessRecordContext,
    ): Promise<BrowserFoundationActionRandomness> {
        const copiedInput = copyQueuedData(input, 'input');
        return this.#custodyOperation(capability, async () => {
            const created =
                await this.#custody.createAndSealActionRandomness(copiedInput);
            return this.#registerActionRandomness({
                actionRandomnessCommitment: created.actionRandomnessCommitment,
                canonicalEnvelope: created.canonicalEnvelope,
                identifier: created.actionRandomnessSessionIdentifier,
            });
        });
    }

    public resumeActionRandomness(
        capability: BrowserFoundationActiveCapability,
        input: BrowserActionRandomnessRecordContext &
            BrowserFoundationActionRandomnessDescription,
    ): Promise<BrowserFoundationActionRandomness> {
        const copiedInput = copyQueuedData(input, 'input');
        return this.#custodyOperation(capability, async () => {
            const opened =
                await this.#custody.openSealedActionRandomness(copiedInput);
            return this.#registerActionRandomness({
                actionRandomnessCommitment: opened.actionRandomnessCommitment,
                canonicalEnvelope: copiedInput.canonicalEnvelope,
                identifier: opened.actionRandomnessSessionIdentifier,
            });
        });
    }

    public copyActionRandomnessDescription(
        capability: BrowserFoundationActiveCapability,
        actionRandomness: BrowserFoundationActionRandomness,
    ): Promise<BrowserFoundationActionRandomnessDescription> {
        return this.#enqueueActive(capability, () => {
            const record = this.#requireActionRandomness(actionRandomness);
            return Promise.resolve(
                Object.freeze({
                    actionRandomnessCommitment:
                        record.actionRandomnessCommitment.slice(),
                    canonicalEnvelope: record.canonicalEnvelope.slice(),
                }),
            );
        });
    }

    public closeActionRandomness(
        capability: BrowserFoundationActiveCapability,
        actionRandomness: BrowserFoundationActionRandomness,
    ): Promise<void> {
        return this.#custodyOperation(capability, async () => {
            const record = this.#requireActionRandomness(actionRandomness);
            await this.#custody.closeActionRandomness(record.identifier);
            this.#activeActionRandomnessIdentifiers.delete(record.identifier);
            this.#actionRandomnessRecords.delete(actionRandomness);
        });
    }

    public verifyStateReservation(
        capability: BrowserFoundationActiveCapability,
        input: BrowserFoundationStateReservationInput,
    ): Promise<VerificationResult<BrowserFoundationStateReservation>> {
        const copiedInput = copyQueuedData(input, 'input');
        return this.#custodyOperation(capability, async () => {
            const sessionIdentifier = this.#requireStateVerifierSession();
            const verification =
                await this.#custody.verifyActionStateReservation({
                    ...copiedInput,
                    stateVerifierSessionIdentifier: sessionIdentifier,
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
        const copiedInput = copyQueuedData(input, 'input');
        return this.#custodyOperation(capability, async () => {
            const randomnessRecord =
                this.#requireActionRandomness(actionRandomness);
            const sessionIdentifier = this.#requireStateVerifierSession();
            const verification =
                await this.#custody.verifyActionRandomnessReservation({
                    ...copiedInput,
                    actionRandomnessSessionIdentifier:
                        randomnessRecord.identifier,
                    stateVerifierSessionIdentifier: sessionIdentifier,
                });
            return verification.isValid
                ? valid(this.#registerStateReservation(verification.value))
                : refused(verification.refusalReason);
        });
    }

    public releaseStateReservation(
        capability: BrowserFoundationActiveCapability,
        stateReservation: BrowserFoundationStateReservation,
    ): Promise<void> {
        return this.#custodyOperation(capability, async () => {
            const record = this.#requireStateReservation(stateReservation);
            await this.#custody.releaseActionStateObject(record.identifier);
            this.#activeStateReservationIdentifiers.delete(record.identifier);
            this.#stateReservationRecords.delete(stateReservation);
        });
    }

    public derivePersistentProofAttempt(
        capability: BrowserFoundationActiveCapability,
        actionRandomness: BrowserFoundationActionRandomness,
        stateReservation: BrowserFoundationStateReservation,
        input: BrowserFoundationPersistentProofAttemptInput,
    ): Promise<BrowserFoundationProofAttempt> {
        const copiedInput = copyQueuedData(input, 'input');
        return this.#custodyOperation(capability, async () => {
            const randomnessRecord =
                this.#requireActionRandomness(actionRandomness);
            const reservationRecord =
                this.#requireStateReservation(stateReservation);
            return this.#registerProofAttempt(
                await this.#custody.derivePersistentProofAttempt({
                    ...copiedInput,
                    actionRandomnessSessionIdentifier:
                        randomnessRecord.identifier,
                    stateReservationIdentifier: reservationRecord.identifier,
                }),
            );
        });
    }

    public deriveTargetReleaseAttempt(
        capability: BrowserFoundationActiveCapability,
        actionRandomness: BrowserFoundationActionRandomness,
        stateReservation: BrowserFoundationStateReservation,
        input: BrowserFoundationTargetReleaseAttemptInput,
    ): Promise<BrowserFoundationProofAttempt> {
        const copiedInput = copyQueuedData(input, 'input');
        return this.#custodyOperation(capability, async () => {
            const randomnessRecord =
                this.#requireActionRandomness(actionRandomness);
            const reservationRecord =
                this.#requireStateReservation(stateReservation);
            return this.#registerProofAttempt(
                await this.#custody.deriveTargetReleaseAttempt({
                    ...copiedInput,
                    actionRandomnessSessionIdentifier:
                        randomnessRecord.identifier,
                    stateReservationIdentifier: reservationRecord.identifier,
                }),
            );
        });
    }

    public copyProofAttemptBinding(
        capability: BrowserFoundationActiveCapability,
        proofAttempt: BrowserFoundationProofAttempt,
    ): Promise<BrowserActionProofAttemptBinding> {
        return this.#enqueueActive(capability, () => {
            const record = this.#requireProofAttempt(proofAttempt);
            return Promise.resolve(
                Object.freeze({
                    applicationSlotHash: record.applicationSlotHash.slice(),
                    attemptIdentifier: record.attemptIdentifier.slice(),
                }),
            );
        });
    }

    public reserveProofApplication(
        capability: BrowserFoundationActiveCapability,
        reservationBinding: ProofApplicationReservationBinding,
    ): Promise<ProofApplicationReservationCapability> {
        return this.#storageOperation(capability, true, () =>
            this.#proofApplicationLedger.reserve(reservationBinding),
        );
    }

    public beginProofVerification(
        capability: BrowserFoundationActiveCapability,
        input: {
            proofQueryCount: bigint;
            reservation: ProofApplicationReservationCapability;
            signatureVerificationCount: number;
        },
    ): Promise<ProofApplicationReservation> {
        return this.#storageOperation(capability, true, () =>
            this.#proofApplicationLedger.beginVerification(input),
        );
    }

    public releaseProofReservationBeforeVerification(
        capability: BrowserFoundationActiveCapability,
        reservation: ProofApplicationReservationCapability,
    ): Promise<boolean> {
        return this.#storageOperation(capability, true, () =>
            this.#proofApplicationLedger.releaseBeforeVerification(reservation),
        );
    }

    public copyProofApplicationReservation(
        capability: BrowserFoundationActiveCapability,
        reservation: ProofApplicationReservationCapability,
    ): Promise<ProofApplicationReservation> {
        return this.#enqueueActive(capability, () =>
            Promise.resolve(
                this.#proofApplicationLedger.copyReservation(reservation),
            ),
        );
    }

    public proofApplicationSnapshot(
        capability: BrowserFoundationActiveCapability,
    ): Promise<ProofApplicationLedgerSnapshot> {
        return this.#storageOperation(capability, true, () =>
            this.#proofApplicationLedger.snapshot(),
        );
    }

    public beginCheckpoint(
        capability: BrowserFoundationActiveCapability,
        proofAttempts: readonly BrowserFoundationProofAttempt[],
    ): Promise<BrowserFoundationCheckpoint> {
        if (!Array.isArray(proofAttempts)) {
            throw new BrowserFoundationAuthorityError(
                'InvalidInput',
                'Checkpoint proof attempts must be an array.',
            );
        }
        const copiedProofAttempts = Array.from(proofAttempts);
        return this.#storageOperation(capability, true, async () => {
            const streamAttemptIdentifiers = copiedProofAttempts.map(
                (proofAttempt) =>
                    this.#requireProofAttempt(proofAttempt).attemptIdentifier,
            );
            const identity = await this.#checkpointStore.beginOperation(
                streamAttemptIdentifiers,
            );
            return this.#registerCheckpoint({ identity });
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
        const copiedBoundary = copyQueuedData(input.boundary, 'input.boundary');
        const copiedStateChunks = createBoundedCopiedChunkSource(
            input.stateChunks,
        );
        return this.#checkpointPublicationOperation(capability, async () => {
            const record = this.#requireCheckpoint(checkpoint);
            return this.#checkpointStore.publish({
                boundary: copiedBoundary,
                identity: record.identity,
                stateChunks: copiedStateChunks,
            });
        });
    }

    public resumeCheckpoint(
        capability: BrowserFoundationActiveCapability,
        input: {
            checkpointLineageIdentifier: Uint8Array;
            expectedBoundary: ExpectedCheckpointBoundary;
        },
    ): Promise<BrowserFoundationCheckpoint> {
        const copiedInput = copyQueuedData(input, 'input');
        return this.#storageOperation(capability, true, async () => {
            const resumed = await this.#checkpointStore.resume(copiedInput);
            return this.#registerCheckpoint({
                identity: resumed.operationIdentity,
                resumed,
            });
        });
    }

    public copyCheckpointDescription(
        capability: BrowserFoundationActiveCapability,
        checkpoint: BrowserFoundationCheckpoint,
    ): Promise<BrowserFoundationCheckpointDescription> {
        return this.#enqueueActive(capability, () => {
            const record = this.#requireCheckpoint(checkpoint);
            return Promise.resolve(
                Object.freeze({
                    ...(record.resumed === undefined
                        ? {}
                        : {
                              canonicalManifestBytes:
                                  record.resumed.canonicalManifestBytes.slice(),
                              stateStreamDescriptorBytes:
                                  record.resumed.stateStreamDescriptorBytes.slice(),
                          }),
                    checkpointLineageIdentifier:
                        record.identity.checkpointLineageIdentifier.slice(),
                }),
            );
        });
    }

    public restoreCheckpointState(
        capability: BrowserFoundationActiveCapability,
        checkpoint: BrowserFoundationCheckpoint,
        consumeChunk: (
            chunkIndex: number,
            chunkBytes: Uint8Array,
        ) => Promise<void> | void,
    ): Promise<void> {
        return this.#enqueueActive(capability, async () => {
            const record = this.#requireCheckpoint(checkpoint);
            if (record.resumed === undefined) {
                throw new BrowserFoundationAuthorityError(
                    'InvalidInput',
                    'Only a resumed checkpoint can restore state.',
                );
            }
            if (typeof consumeChunk !== 'function') {
                throw new BrowserFoundationAuthorityError(
                    'InvalidInput',
                    'The checkpoint state consumer must be a function.',
                );
            }
            let consumerFailure: unknown;
            try {
                await record.resumed.restoreState(async (chunkIndex, bytes) => {
                    try {
                        await consumeChunk(chunkIndex, bytes.slice());
                    } catch (error) {
                        consumerFailure = error;
                        throw error;
                    } finally {
                        bytes.fill(0);
                    }
                });
            } catch (error) {
                if (consumerFailure === error) {
                    throw error;
                }
                const reason = storageFailureRetirementReason(error, true);
                if (reason !== undefined) {
                    await this.#retire(reason, error);
                }
                throw error;
            }
        });
    }

    public witnessRoles(
        capability: BrowserFoundationActiveCapability,
    ): Promise<readonly BrowserFoundationWitnessRole[]> {
        return this.#enqueueActive(capability, () =>
            Promise.resolve(this.#witnessRoles),
        );
    }

    public copyWitnessRoleDescription(
        capability: BrowserFoundationActiveCapability,
        witnessRole: BrowserFoundationWitnessRole,
    ): Promise<BrowserFoundationWitnessRoleDescription> {
        return this.#enqueueActive(capability, () => {
            const role = this.#requireWitnessRole(witnessRole);
            return Promise.resolve(
                Object.freeze({
                    subjectParticipantIdentity:
                        role.subjectParticipantIdentity.slice(),
                }),
            );
        });
    }

    public voteForNamespaceCheckpoint(
        capability: BrowserFoundationActiveCapability,
        witnessRole: BrowserFoundationWitnessRole,
        canonicalCheckpoint: Uint8Array,
    ): Promise<VerificationResult<Uint8Array>> {
        const copiedCheckpoint = copyQueuedBytes(
            canonicalCheckpoint,
            'canonicalCheckpoint',
        );
        return this.#enqueueActive(capability, async () => {
            const role = this.#requireWitnessRole(witnessRole);
            let result: VerificationResult<Uint8Array>;
            try {
                result =
                    await role.namespaceFreshnessService.vote(
                        copiedCheckpoint,
                    );
            } catch (error) {
                await this.#retire('witnessStateUnavailable', error);
                throw error;
            }
            if (role.namespaceFreshnessService.state() === 'retired') {
                await this.#retire('witnessStateUnavailable', result);
            }
            return result.isValid
                ? valid(result.value.slice())
                : refused(result.refusalReason);
        });
    }

    public compareAndLockWitnessIntent(
        capability: BrowserFoundationActiveCapability,
        witnessRole: BrowserFoundationWitnessRole,
        input: { verifiedIntentBinding: VerifiedStateDurableBinding },
    ): Promise<void> {
        return this.#witnessStorageOperation(capability, witnessRole, (role) =>
            role.durableStateService.compareAndLockIntent(input),
        );
    }

    public cacheWitnessSignedVoteCarrier(
        capability: BrowserFoundationActiveCapability,
        witnessRole: BrowserFoundationWitnessRole,
        input: {
            canonicalSignedVoteCarrier: Uint8Array;
            verifiedIntentBinding: VerifiedStateDurableBinding;
        },
    ): Promise<Uint8Array> {
        const copiedInput = Object.freeze({
            canonicalSignedVoteCarrier: copyQueuedBytes(
                input.canonicalSignedVoteCarrier,
                'input.canonicalSignedVoteCarrier',
            ),
            verifiedIntentBinding: input.verifiedIntentBinding,
        });
        return this.#witnessStorageOperation(capability, witnessRole, (role) =>
            role.durableStateService.cacheSignedVoteCarrier(copiedInput),
        );
    }

    public readWitnessSignedVoteCarrier(
        capability: BrowserFoundationActiveCapability,
        witnessRole: BrowserFoundationWitnessRole,
        input: { verifiedIntentBinding: VerifiedStateDurableBinding },
    ): Promise<Uint8Array> {
        return this.#witnessStorageOperation(capability, witnessRole, (role) =>
            role.durableStateService.readSignedVoteCarrier(input),
        );
    }

    public cacheWitnessExactOutput(
        capability: BrowserFoundationActiveCapability,
        witnessRole: BrowserFoundationWitnessRole,
        input: {
            exactOutputBytes: Uint8Array;
            verifiedOutputBinding: VerifiedStateDurableBinding;
        },
    ): Promise<void> {
        const copiedInput = Object.freeze({
            exactOutputBytes: copyQueuedBytes(
                input.exactOutputBytes,
                'input.exactOutputBytes',
            ),
            verifiedOutputBinding: input.verifiedOutputBinding,
        });
        return this.#witnessStorageOperation(capability, witnessRole, (role) =>
            role.durableStateService.cacheExactOutput(copiedInput),
        );
    }

    public readWitnessExactOutput(
        capability: BrowserFoundationActiveCapability,
        witnessRole: BrowserFoundationWitnessRole,
        input: { verifiedOutputBinding: VerifiedStateDurableBinding },
    ): Promise<Uint8Array> {
        return this.#witnessStorageOperation(capability, witnessRole, (role) =>
            role.durableStateService.readExactOutput(input),
        );
    }

    public close(): Promise<void> {
        return this.#enqueue(() => this.#retire('closed'));
    }

    #makeUnavailable(): void {
        this.#state = 'unavailable';
        this.#activeCapability = undefined;
        this.#namespaceCapability = undefined;
    }

    #assertNotRetired(): void {
        if (this.#state === 'retired') {
            throw new BrowserFoundationAuthorityError(
                'Retired',
                'The participant is permanently retired for this action.',
            );
        }
    }

    #requireActive(capability: BrowserFoundationActiveCapability): void {
        this.#assertNotRetired();
        if (
            this.#state !== 'active' ||
            this.#activeCapability === undefined ||
            capability !== this.#activeCapability ||
            this.#namespaceCapability === undefined ||
            this.#namespaceFreshnessRuntime.state() !== 'active' ||
            this.#namespaceFreshnessRuntime.activeCapability() !==
                this.#namespaceCapability
        ) {
            throw new BrowserFoundationAuthorityError(
                'InvalidInput',
                'The active capability was not issued for the current browser foundation authority state.',
            );
        }
    }

    #requireStateVerifierSession(): string {
        if (this.#stateVerifierSessionIdentifier === undefined) {
            throw new BrowserFoundationAuthorityError(
                'InvalidState',
                'The worker-owned state verifier session is unavailable.',
            );
        }
        return this.#stateVerifierSessionIdentifier;
    }

    #registerActionRandomness(
        input: ActionRandomnessRecord,
    ): BrowserFoundationActionRandomness {
        if (this.#activeActionRandomnessIdentifiers.has(input.identifier)) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'The owned worker reused an active action-randomness session identifier.',
            );
        }
        const capability =
            createOpaqueCapability<BrowserFoundationActionRandomness>();
        this.#actionRandomnessRecords.set(
            capability,
            Object.freeze({
                actionRandomnessCommitment:
                    input.actionRandomnessCommitment.slice(),
                canonicalEnvelope: input.canonicalEnvelope.slice(),
                identifier: input.identifier,
            }),
        );
        this.#activeActionRandomnessIdentifiers.add(input.identifier);
        return capability;
    }

    #requireActionRandomness(
        capability: BrowserFoundationActionRandomness,
    ): ActionRandomnessRecord {
        const record =
            typeof capability === 'object' && capability !== null
                ? this.#actionRandomnessRecords.get(capability)
                : undefined;
        if (record === undefined) {
            throw new BrowserFoundationAuthorityError(
                'InvalidInput',
                'The action-randomness capability was not issued by this authority or has been closed.',
            );
        }
        return record;
    }

    #registerStateReservation(
        identifier: string,
    ): BrowserFoundationStateReservation {
        if (this.#activeStateReservationIdentifiers.has(identifier)) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'The owned worker reused an active state-reservation identifier.',
            );
        }
        const capability =
            createOpaqueCapability<BrowserFoundationStateReservation>();
        this.#stateReservationRecords.set(
            capability,
            Object.freeze({ identifier }),
        );
        this.#activeStateReservationIdentifiers.add(identifier);
        return capability;
    }

    #requireStateReservation(
        capability: BrowserFoundationStateReservation,
    ): StateReservationRecord {
        const record =
            typeof capability === 'object' && capability !== null
                ? this.#stateReservationRecords.get(capability)
                : undefined;
        if (record === undefined) {
            throw new BrowserFoundationAuthorityError(
                'InvalidInput',
                'The state-reservation capability was not issued by this authority or has been released.',
            );
        }
        return record;
    }

    #registerProofAttempt(
        binding: BrowserActionProofAttemptBinding,
    ): BrowserFoundationProofAttempt {
        const capability =
            createOpaqueCapability<BrowserFoundationProofAttempt>();
        this.#proofAttemptRecords.set(
            capability,
            Object.freeze({
                applicationSlotHash: copyHash(
                    binding.applicationSlotHash,
                    'proofAttempt.applicationSlotHash',
                ),
                attemptIdentifier: copyQueuedBytes(
                    binding.attemptIdentifier,
                    'proofAttempt.attemptIdentifier',
                    32,
                ),
            }),
        );
        return capability;
    }

    #requireProofAttempt(
        capability: BrowserFoundationProofAttempt,
    ): ProofAttemptRecord {
        const record =
            typeof capability === 'object' && capability !== null
                ? this.#proofAttemptRecords.get(capability)
                : undefined;
        if (record === undefined) {
            throw new BrowserFoundationAuthorityError(
                'InvalidInput',
                'The proof-attempt capability was not issued by this authority.',
            );
        }
        return record;
    }

    #registerCheckpoint(record: CheckpointRecord): BrowserFoundationCheckpoint {
        const capability =
            createOpaqueCapability<BrowserFoundationCheckpoint>();
        this.#checkpointRecords.set(capability, record);
        return capability;
    }

    #requireCheckpoint(
        capability: BrowserFoundationCheckpoint,
    ): CheckpointRecord {
        const record =
            typeof capability === 'object' && capability !== null
                ? this.#checkpointRecords.get(capability)
                : undefined;
        if (record === undefined) {
            throw new BrowserFoundationAuthorityError(
                'InvalidInput',
                'The checkpoint capability was not issued by this authority.',
            );
        }
        return record;
    }

    #requireWitnessRole(
        capability: BrowserFoundationWitnessRole,
    ): WitnessRoleRecord {
        const record =
            typeof capability === 'object' && capability !== null
                ? this.#witnessRoleRecords.get(capability)
                : undefined;
        if (record === undefined) {
            throw new BrowserFoundationAuthorityError(
                'InvalidInput',
                'The witness-role capability was not issued by this authority.',
            );
        }
        return record;
    }

    #enqueue<Result>(operation: () => Promise<Result>): Promise<Result> {
        const result = this.#operationTail.then(operation, operation);
        this.#operationTail = result.then(
            () => undefined,
            () => undefined,
        );
        return result;
    }

    #enqueueActive<Result>(
        capability: BrowserFoundationActiveCapability,
        operation: () => Promise<Result>,
    ): Promise<Result> {
        return this.#enqueue(async () => {
            this.#requireActive(capability);
            return operation();
        });
    }

    #custodyOperation<Result>(
        capability: BrowserFoundationActiveCapability,
        operation: () => Promise<Result>,
    ): Promise<Result> {
        return this.#enqueueActive(capability, async () => {
            try {
                return await operation();
            } catch (error) {
                const reason = custodyFailureRetirementReason(error);
                if (reason !== undefined) {
                    await this.#retire(reason, error);
                }
                throw error;
            }
        });
    }

    #storageOperation<Result>(
        capability: BrowserFoundationActiveCapability,
        conflictRetires: boolean,
        operation: () => Promise<Result>,
    ): Promise<Result> {
        return this.#enqueueActive(capability, async () => {
            try {
                return await operation();
            } catch (error) {
                const reason = storageFailureRetirementReason(
                    error,
                    conflictRetires,
                );
                if (reason !== undefined) {
                    await this.#retire(reason, error);
                }
                throw error;
            }
        });
    }

    #checkpointPublicationOperation<Result>(
        capability: BrowserFoundationActiveCapability,
        operation: () => Promise<Result>,
    ): Promise<Result> {
        return this.#enqueueActive(capability, async () => {
            try {
                return await operation();
            } catch (error) {
                if (error instanceof AuthenticatedRuntimeRecordError) {
                    const reason = storageFailureRetirementReason(error, true);
                    if (reason !== undefined) {
                        await this.#retire(reason, error);
                    }
                }
                throw error;
            }
        });
    }

    #witnessStorageOperation<Result>(
        capability: BrowserFoundationActiveCapability,
        witnessRole: BrowserFoundationWitnessRole,
        operation: (role: WitnessRoleRecord) => Promise<Result>,
    ): Promise<Result> {
        return this.#enqueueActive(capability, async () => {
            const role = this.#requireWitnessRole(witnessRole);
            try {
                return await operation(role);
            } catch (error) {
                const reason = storageFailureRetirementReason(error, false);
                if (reason !== undefined) {
                    await this.#retire('witnessStateUnavailable', error);
                }
                throw error;
            }
        });
    }

    async #retire(
        reason: BrowserFoundationAuthorityRetirementReason,
        failureCause?: unknown,
    ): Promise<void> {
        if (this.#state !== 'retired') {
            this.#state = 'retired';
            this.#retirementReason = reason;
            this.#activeCapability = undefined;
            this.#namespaceCapability = undefined;
        }
        this.#cleanupPromise ??= this.#cleanup(failureCause);
        return this.#cleanupPromise;
    }

    async #cleanup(failureCause: unknown): Promise<void> {
        const cleanupFailures: unknown[] = [];
        for (const identifier of [...this.#activeActionRandomnessIdentifiers]) {
            try {
                await this.#custody.closeActionRandomness(identifier);
            } catch (error) {
                cleanupFailures.push(error);
            } finally {
                this.#activeActionRandomnessIdentifiers.delete(identifier);
            }
        }
        for (const identifier of [...this.#activeStateReservationIdentifiers]) {
            try {
                await this.#custody.releaseActionStateObject(identifier);
            } catch (error) {
                cleanupFailures.push(error);
            } finally {
                this.#activeStateReservationIdentifiers.delete(identifier);
            }
        }
        const stateVerifierSessionIdentifier =
            this.#stateVerifierSessionIdentifier;
        this.#stateVerifierSessionIdentifier = undefined;
        if (stateVerifierSessionIdentifier !== undefined) {
            try {
                await this.#custody.closeActionStateVerifierSession(
                    stateVerifierSessionIdentifier,
                );
            } catch (error) {
                cleanupFailures.push(error);
            }
        }
        try {
            this.#canonicalBoardRuntime.close();
        } catch (error) {
            cleanupFailures.push(error);
        }
        try {
            await this.#custody.close();
        } catch (error) {
            cleanupFailures.push(error);
        }
        this.#canonicalRosterBytes.fill(0);
        if (cleanupFailures.length !== 0) {
            throw new BrowserFoundationAuthorityError(
                'CleanupFailed',
                'The participant is permanently retired, but one or more browser-owned resources could not be closed.',
                Object.freeze({
                    cleanupFailures: Object.freeze(cleanupFailures),
                    failureCause,
                }),
            );
        }
    }
}

/**
 * Composes one participant browser's foundation authority. The returned
 * operation exposes process-local capabilities only; transcript, mailbox, and
 * freshness transports remain byte relays and never become result authority.
 */
export const openBrowserFoundationAuthority = (
    input: BrowserFoundationAuthorityInput,
): BrowserFoundationAuthority =>
    Object.freeze(new BrowserFoundationAuthorityImplementation(input));
