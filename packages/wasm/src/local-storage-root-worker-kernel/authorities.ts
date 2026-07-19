import {
    BrowserActionStorageCustodyError,
    type BrowserActionRandomnessRecordContext,
    type BrowserActionRandomnessReservationCertificationInput,
    type BrowserActionRandomnessReservationIntentProductionInput,
    type BrowserActionRandomnessReservationIntentWitnessVerificationInput,
    type BrowserActionRandomnessReservationWitnessVoteProductionInput,
    type BrowserActionStorageRootBinding,
    type BrowserActionStorageWorkerKernel,
    type BrowserOpenedActionRandomnessSession,
    type BrowserProducedActionRandomnessReservation,
    type BrowserProducedActionRandomnessReservationIntent,
    type BrowserSealedActionRandomnessSession,
    type ProtocolHash,
    type VerificationResult,
} from '@sealed-lattice/types';

import type {
    AggregateThresholdShareRecipientAuthority,
    ClosedWorkerAggregateThresholdShareRecipientAuthorityInput,
} from '../aggregate-threshold-share-authenticated-recipient.js';
import type { VerifiedTranscriptObject } from '../canonical-board-runtime.js';
import type {
    CommonProofApplicationFreshnessCoordinate,
    VerifiedCommonProofCapability,
} from '../common-proof-worker-runtime.js';
import type { BrowserOwnedSetupGenerationAuthority } from '../setup-generation-recipient-payload.js';
import type {
    StateVerifierSession,
    VerifiedStateDurableBinding,
    VerifiedStateReservation,
    VerifiedStateReservationIntent,
} from '../state-verifier-runtime.js';
import type { ActionRandomnessKernelContext } from '../transcript-core-bridge/action-randomness-kernel-context.js';
import type {
    SetupMailboxSlot,
    TranscriptCoreKernel,
} from '../transcript-core-bridge/kernel-types.js';

export type RootLease = {
    binding: BrowserActionStorageRootBinding;
    capability: Uint8Array<ArrayBuffer>;
    handle: number;
    storageRootCommitment: Uint8Array<ArrayBuffer>;
};

export type ClosedWorkerCommonProofScratchRecordIdentifierInput = Readonly<{
    commonProofEnvironmentIdentifier: Uint8Array;
    commonProofRuntimeBindingHash: Uint8Array;
    externalMemoryByteOffset: bigint;
    externalMemoryChunkOrdinal: number;
    externalMemoryObjectOrdinal: number;
    externalMemoryRecordKind: 'object-header' | 'data-chunk' | 'seal-marker';
    proofAttemptLineageIdentifier: Uint8Array;
    recordType: 'commonProofExternalMemory';
}>;

export type ClosedWorkerCommonProofScratchRecordSealInput = Readonly<{
    actionRandomnessCommitment: Uint8Array;
    identifierInput: ClosedWorkerCommonProofScratchRecordIdentifierInput;
    plaintext: Uint8Array;
}>;

export type ClosedWorkerCommonProofScratchRecordOpenInput = Readonly<{
    actionRandomnessCommitment: Uint8Array;
    envelope: Uint8Array;
    identifierInput: ClosedWorkerCommonProofScratchRecordIdentifierInput;
}>;

export type ClosedWorkerCommonProofScratchStorage = Readonly<{
    deriveRecordIdentifier(
        input: ClosedWorkerCommonProofScratchRecordIdentifierInput,
    ): Promise<Uint8Array>;
    openRecord(
        input: ClosedWorkerCommonProofScratchRecordOpenInput,
    ): Promise<Uint8Array>;
    sealRecord(
        input: ClosedWorkerCommonProofScratchRecordSealInput,
    ): Promise<Uint8Array>;
}>;

export type WorkerActionRandomnessRecordContext =
    BrowserActionRandomnessRecordContext;

export type WorkerActionRandomnessSessionRecord = Readonly<{
    actionRandomnessCommitment: Uint8Array<ArrayBuffer>;
    handle: number;
}>;

export type ClosedWorkerProductionOperationIdentifiers = Readonly<{
    actionRandomnessSessionIdentifier: string;
    stateReservationIdentifier: string;
    stateVerifierSessionIdentifier: string;
}>;

type ClosedWorkerProductionOperationKernelAuthorization = Readonly<{
    readonly actionRandomnessContext: ActionRandomnessKernelContext;
    readonly actionRandomnessHandle: number;
    readonly kernel: TranscriptCoreKernel;
    readonly stateReservationCapabilityMemory: WebAssembly.Memory;
    readonly stateReservationCapabilityPointer: number;
    readonly stateReservationHandle: number;
    readonly stateVerifierSessionHandle: number;
}>;

export type ClosedWorkerProductionOperationAuthority = Readonly<{
    withExactKernelAuthorization(
        operation: (
            authorization: ClosedWorkerProductionOperationKernelAuthorization,
        ) => Promise<void> | void,
    ): Promise<void> | void;
}>;

type ClosedWorkerProductionOperationAuthorityRecord = {
    authorization:
        | ClosedWorkerProductionOperationKernelAuthorization
        | undefined;
    state: 'active' | 'revoked';
};

const closedWorkerProductionOperationAuthorityRecords = new WeakMap<
    ClosedWorkerProductionOperationAuthority,
    ClosedWorkerProductionOperationAuthorityRecord
>();

const requireLiveClosedWorkerProductionOperationAuthorityRecord = (
    authority: ClosedWorkerProductionOperationAuthority,
): ClosedWorkerProductionOperationKernelAuthorization => {
    const record =
        closedWorkerProductionOperationAuthorityRecords.get(authority);
    if (
        record === undefined ||
        record.state !== 'active' ||
        record.authorization === undefined
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidState',
            'The closed worker production-operation authority is no longer active.',
        );
    }
    return record.authorization;
};

const defineBorrowedAuthorizationProperty = <
    PropertyName extends
        keyof ClosedWorkerProductionOperationKernelAuthorization,
>(
    target: object,
    authority: ClosedWorkerProductionOperationAuthority,
    propertyName: PropertyName,
): void => {
    Object.defineProperty(target, propertyName, {
        configurable: false,
        enumerable: false,
        get: () =>
            requireLiveClosedWorkerProductionOperationAuthorityRecord(
                authority,
            )[propertyName],
    });
};

export const createClosedWorkerProductionOperationAuthority = (input: {
    authorization: ClosedWorkerProductionOperationKernelAuthorization;
}): Readonly<{
    authority: ClosedWorkerProductionOperationAuthority;
    revoke(): void;
}> => {
    const authorityTarget = Object.create(null) as object;
    const authority =
        authorityTarget as ClosedWorkerProductionOperationAuthority;
    Object.defineProperty(authorityTarget, 'withExactKernelAuthorization', {
        configurable: false,
        enumerable: false,
        value: (
            operation: (
                authorization: ClosedWorkerProductionOperationKernelAuthorization,
            ) => Promise<void> | void,
        ): Promise<void> | void => {
            if (typeof operation !== 'function') {
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'The exact-kernel production operation must be a function.',
                );
            }
            requireLiveClosedWorkerProductionOperationAuthorityRecord(
                authority,
            );
            const borrowedAuthorizationTarget = Object.create(null) as object;
            for (const propertyName of [
                'actionRandomnessContext',
                'actionRandomnessHandle',
                'kernel',
                'stateReservationCapabilityMemory',
                'stateReservationCapabilityPointer',
                'stateReservationHandle',
                'stateVerifierSessionHandle',
            ] as const) {
                defineBorrowedAuthorizationProperty(
                    borrowedAuthorizationTarget,
                    authority,
                    propertyName,
                );
            }
            const operationOutput = operation(
                Object.freeze(
                    borrowedAuthorizationTarget,
                ) as ClosedWorkerProductionOperationKernelAuthorization,
            );
            if (operationOutput === undefined) {
                return;
            }
            return Promise.resolve(operationOutput).then((resolvedOutput) => {
                if (resolvedOutput !== undefined) {
                    throw new BrowserActionStorageCustodyError(
                        'InvalidInput',
                        'An exact-kernel production operation must not return authority material.',
                    );
                }
            });
        },
        writable: false,
    });
    Object.freeze(authorityTarget);
    const record: ClosedWorkerProductionOperationAuthorityRecord = {
        authorization: input.authorization,
        state: 'active',
    };
    closedWorkerProductionOperationAuthorityRecords.set(authority, record);

    return Object.freeze({
        authority,
        revoke: (): void => {
            record.state = 'revoked';
            record.authorization = undefined;
        },
    });
};

export type WorkerAuthenticatedRepairProtectionRecord = Readonly<{
    namespaceBytes: Uint8Array<ArrayBuffer>;
    runtimeBuildManifestHash: Uint8Array<ArrayBuffer>;
}>;

export type WorkerSealedActionRandomnessSession =
    BrowserSealedActionRandomnessSession;

export type ClosedWorkerSetupMailboxRandomnessOperations = Readonly<{
    readonly actionContextHash: ProtocolHash;
    readonly ceremonyContextHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly sourceParticipantId: string;
    readonly suiteId: ProtocolHash;
    encapsulate(input: {
        readonly recipientEncapsulationKey: Uint8Array;
        readonly setupMailboxSlot: SetupMailboxSlot;
        readonly setupMailboxSlotHash: ProtocolHash;
    }): Readonly<{
        readonly ciphertext: Uint8Array<ArrayBuffer>;
        readonly envelopeAttemptIdentifier: Uint8Array<ArrayBuffer>;
        readonly sharedSecret: Uint8Array<ArrayBuffer>;
    }>;
    signEnvelope(input: {
        readonly envelopeHash: ProtocolHash;
        readonly setupMailboxSlot: SetupMailboxSlot;
        readonly setupMailboxSlotHash: ProtocolHash;
    }): Uint8Array<ArrayBuffer>;
    signSetupObject(input: {
        readonly signatureMessageHash: ProtocolHash;
    }): Uint8Array<ArrayBuffer>;
    produceSetupIntentCarrier(): Uint8Array<ArrayBuffer>;
    producePublicRandomnessCommitmentCarrier(input: {
        readonly orderedSetupIntentObjects: readonly VerifiedTranscriptObject[];
    }): Uint8Array<ArrayBuffer>;
    producePublicRandomnessRevealCarrier(input: {
        readonly publicRandomnessCommitmentObject: VerifiedTranscriptObject;
        readonly setupIntentObject: VerifiedTranscriptObject;
    }): Uint8Array<ArrayBuffer>;
    produceDealerPublicRecordCarrier(input: {
        readonly orderedRecipientEnvelopeHashes: readonly ProtocolHash[];
        readonly proofDescriptorBytes: Uint8Array;
        readonly setupGenerationAuthority: BrowserOwnedSetupGenerationAuthority;
    }): Uint8Array<ArrayBuffer>;
    revoke(): void;
}>;

export type ClosedWorkerPreparedCommonProofApplication = Readonly<{
    authorizationFrame: Uint8Array<ArrayBuffer>;
    proofApplicationSlotHash: Uint8Array<ArrayBuffer>;
    abort(): Promise<void>;
    confirm(input: {
        authenticatedAuthorizationFrame: Uint8Array;
        successor: CommonProofApplicationFreshnessCoordinate;
    }): Promise<void>;
}>;

export type WorkerSetupMailboxSigningOperations = Readonly<{
    readonly verificationKey: Uint8Array;
    signClosedMessage(input: {
        readonly message: Uint8Array;
        readonly context: Uint8Array;
        readonly hedge: Uint8Array;
    }): Uint8Array;
}>;

export type WorkerSetupMailboxRandomnessInput = Readonly<{
    readonly actionRandomnessSessionIdentifier: string;
    readonly sourceMailboxEncapsulationKey: Uint8Array;
    readonly signing: WorkerSetupMailboxSigningOperations;
    readonly stateReservationIdentifier: string;
}>;

export type WorkerActionRandomnessKernelRunner = Readonly<{
    close(sessionIdentifier: string): Promise<void>;
    createAndSeal(
        input: WorkerActionRandomnessRecordContext,
    ): Promise<WorkerSealedActionRandomnessSession>;
    openSealed(
        input: WorkerActionRandomnessRecordContext &
            Readonly<{
                actionRandomnessCommitment: Uint8Array;
                canonicalEnvelope: Uint8Array;
            }>,
    ): Promise<BrowserOpenedActionRandomnessSession>;
    openSetupMailboxRandomness(
        input: WorkerSetupMailboxRandomnessInput,
    ): Promise<ClosedWorkerSetupMailboxRandomnessOperations>;
    openAggregateThresholdShareRecipientAuthority(
        input: ClosedWorkerAggregateThresholdShareRecipientAuthorityInput,
    ): Promise<AggregateThresholdShareRecipientAuthority>;
    durableBindingForStateObject(
        stateObjectIdentifier: string,
    ): Promise<VerificationResult<VerifiedStateDurableBinding>>;
}>;

export type WorkerStateObject =
    | Readonly<{
          capabilityKind: number;
          kind: 'reservation';
          sessionIdentifier: string;
          subjectParticipantIdentity: Uint8Array<ArrayBuffer>;
          value: VerifiedStateReservation;
      }>
    | Readonly<{
          capabilityKind: number;
          kind: 'reservation-intent';
          sessionIdentifier: string;
          subjectParticipantIdentity: Uint8Array<ArrayBuffer>;
          value: VerifiedStateReservationIntent;
      }>;

export type WorkerStateVerifierSession = Readonly<{
    canonicalRosterBytes: Uint8Array<ArrayBuffer>;
    session: StateVerifierSession;
}>;

export const workerActionRandomnessKernelRunners = new WeakMap<
    BrowserActionStorageWorkerKernel,
    WorkerActionRandomnessKernelRunner
>();

export type WorkerFoundationStateProducerRunner = Readonly<{
    certifyReservation(
        input: BrowserActionRandomnessReservationCertificationInput,
    ): Promise<VerificationResult<BrowserProducedActionRandomnessReservation>>;
    produceIntent(
        input: BrowserActionRandomnessReservationIntentProductionInput,
    ): Promise<
        VerificationResult<BrowserProducedActionRandomnessReservationIntent>
    >;
    produceWitnessVote(
        input: BrowserActionRandomnessReservationWitnessVoteProductionInput,
    ): Promise<VerificationResult<Uint8Array>>;
    verifyIntentForWitness(
        input: BrowserActionRandomnessReservationIntentWitnessVerificationInput,
    ): Promise<VerificationResult<string>>;
}>;

export const workerFoundationStateProducerRunners = new WeakMap<
    BrowserActionStorageWorkerKernel,
    WorkerFoundationStateProducerRunner
>();

type WorkerCommonProofApplicationRunner = Readonly<{
    prepare(
        capability: VerifiedCommonProofCapability,
        predecessor: CommonProofApplicationFreshnessCoordinate,
    ): Promise<ClosedWorkerPreparedCommonProofApplication>;
}>;

export const workerCommonProofApplicationRunners = new WeakMap<
    BrowserActionStorageWorkerKernel,
    WorkerCommonProofApplicationRunner
>();

export type WorkerProductionOperationAuthorityRunner = Readonly<{
    withAuthority(
        identifiers: ClosedWorkerProductionOperationIdentifiers,
        operation: (
            authority: ClosedWorkerProductionOperationAuthority,
        ) => Promise<void> | void,
    ): Promise<void>;
}>;

export const workerProductionOperationAuthorityRunners = new WeakMap<
    BrowserActionStorageWorkerKernel,
    WorkerProductionOperationAuthorityRunner
>();

export const closedWorkerCommonProofScratchStorage = new WeakMap<
    BrowserActionStorageWorkerKernel,
    ClosedWorkerCommonProofScratchStorage
>();

export const requireClosedWorkerCommonProofScratchStorage = (
    workerKernel: BrowserActionStorageWorkerKernel,
): ClosedWorkerCommonProofScratchStorage => {
    const scratchStorage =
        closedWorkerCommonProofScratchStorage.get(workerKernel);
    if (scratchStorage === undefined) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The action storage worker has no closed common-proof scratch storage.',
        );
    }
    return scratchStorage;
};

export const openClosedWorkerCommonProofScratchStorage = (
    workerKernel: BrowserActionStorageWorkerKernel,
): ClosedWorkerCommonProofScratchStorage => {
    if (typeof document !== 'undefined') {
        throw new BrowserActionStorageCustodyError(
            'Unavailable',
            'Common-proof scratch storage is available only inside the worker runtime.',
        );
    }
    return requireClosedWorkerCommonProofScratchStorage(workerKernel);
};
