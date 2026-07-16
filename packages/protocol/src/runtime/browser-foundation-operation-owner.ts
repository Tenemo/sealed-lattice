import type {
    BrowserActionProofAttemptBinding,
    BrowserActionRandomnessReservationVerificationInput,
    BrowserTargetReleaseAttemptInput,
    VerificationResult,
} from '@sealed-lattice/types';

import type {
    BrowserFoundationStorageAuthority,
    CommittedBrowserFoundationInitializationBatch,
} from './browser-action-storage-custody.js';

declare const browserFoundationActionRandomnessHandleBrand: unique symbol;
declare const browserFoundationDurableStateBindingHandleBrand: unique symbol;
declare const browserFoundationNormalWitnessRoleHandleBrand: unique symbol;
declare const browserFoundationStateReservationIntentHandleBrand: unique symbol;
declare const browserRecoveredFoundationInitializationBatchBrand: unique symbol;

export type BrowserFoundationActionRandomnessHandle = Readonly<{
    readonly [browserFoundationActionRandomnessHandleBrand]: true;
}>;

export type BrowserFoundationDurableStateBindingHandle = Readonly<{
    readonly [browserFoundationDurableStateBindingHandleBrand]: true;
}>;

export type BrowserFoundationNormalWitnessRoleHandle = Readonly<{
    readonly [browserFoundationNormalWitnessRoleHandleBrand]: true;
}>;

export type BrowserFoundationStateReservationIntentHandle = Readonly<{
    readonly [browserFoundationStateReservationIntentHandleBrand]: true;
}>;

export type BrowserFoundationProducedStateReservationIntent = Readonly<{
    canonicalReservationIntentCarrier: Uint8Array;
    intentHandle: BrowserFoundationStateReservationIntentHandle;
}>;

export type BrowserFoundationProducedStateReservation = Readonly<{
    canonicalStateCertificate: Uint8Array;
    stateReservationIdentifier: string;
}>;

export type BrowserRecoveredFoundationInitializationBatch = Readonly<{
    readonly [browserRecoveredFoundationInitializationBatchBrand]: true;
}>;

export type BrowserFoundationWitnessBindingInput = Readonly<{
    subjectParticipantIdentity: Uint8Array;
    witnessParticipantIdentity: Uint8Array;
}>;

export type BrowserFoundationInitializationInput = Readonly<{
    actionRandomnessRecordContext: Readonly<{
        recordVersion: bigint;
    }>;
    canonicalRosterBytes: Uint8Array;
    orderedWitnessBindings: readonly BrowserFoundationWitnessBindingInput[];
    runtimeBuildManifestHash: Uint8Array;
}>;

export type BrowserRecoveredFoundationInitialization = Readonly<{
    recoveredBatch: BrowserRecoveredFoundationInitializationBatch;
}>;

export type BrowserActivatedFoundationInitialization = Readonly<{
    actionRandomnessHandle: BrowserFoundationActionRandomnessHandle;
    orderedWitnessRoleHandles: readonly BrowserFoundationNormalWitnessRoleHandle[];
}>;

export type BrowserFoundationOperationOwner = Pick<
    BrowserFoundationStorageAuthority,
    | 'beginCheckpoint'
    | 'close'
    | 'copyBinding'
    | 'copyCheckpointDescription'
    | 'publishCheckpoint'
    | 'releaseActionStateObject'
    | 'restoreCheckpointState'
    | 'resumeCheckpoint'
    | 'verifyActionStateReservation'
    | 'openActionStateVerifierSession'
> &
    Readonly<{
        activateFreshFoundationInitialization(
            committedBatch: CommittedBrowserFoundationInitializationBatch,
        ): Promise<BrowserActivatedFoundationInitialization>;
        activateRecoveredFoundationInitialization(
            recoveredBatch: BrowserRecoveredFoundationInitializationBatch,
        ): Promise<BrowserActivatedFoundationInitialization>;
        cacheWitnessExactOutput(
            witnessRole: BrowserFoundationNormalWitnessRoleHandle,
            input: {
                durableBinding: BrowserFoundationDurableStateBindingHandle;
                exactOutputBytes: Uint8Array;
            },
        ): Promise<void>;
        cacheWitnessSignedVoteCarrier(
            witnessRole: BrowserFoundationNormalWitnessRoleHandle,
            input: {
                canonicalSignedVoteCarrier: Uint8Array;
                durableBinding: BrowserFoundationDurableStateBindingHandle;
            },
        ): Promise<Uint8Array>;
        closeFoundationActionRandomness(
            actionRandomness: BrowserFoundationActionRandomnessHandle,
        ): Promise<void>;
        closeWitnessDurableStateBinding(
            durableBinding: BrowserFoundationDurableStateBindingHandle,
        ): Promise<void>;
        commitFreshFoundationInitialization(
            input: BrowserFoundationInitializationInput,
        ): Promise<
            Readonly<{
                committedBatch: CommittedBrowserFoundationInitializationBatch;
            }>
        >;
        compareAndLockWitnessIntent(
            witnessRole: BrowserFoundationNormalWitnessRoleHandle,
            input: {
                durableBinding: BrowserFoundationDurableStateBindingHandle;
            },
        ): Promise<void>;
        certifyFoundationActionRandomnessReservation(
            intent: BrowserFoundationStateReservationIntentHandle,
            untrustedVoteCarriers: readonly Uint8Array[],
        ): Promise<
            VerificationResult<BrowserFoundationProducedStateReservation>
        >;
        copyWitnessSubjectParticipantIdentity(
            witnessRole: BrowserFoundationNormalWitnessRoleHandle,
        ): Promise<Uint8Array>;
        deriveFoundationTargetReleaseAttempt(
            actionRandomness: BrowserFoundationActionRandomnessHandle,
            input: Omit<
                BrowserTargetReleaseAttemptInput,
                'actionRandomnessSessionIdentifier'
            >,
        ): Promise<BrowserActionProofAttemptBinding>;
        openRecoveredFoundationInitialization(
            input: BrowserFoundationInitializationInput,
        ): Promise<BrowserRecoveredFoundationInitialization>;
        openWitnessDurableStateBinding(
            witnessRole: BrowserFoundationNormalWitnessRoleHandle,
            stateObjectIdentifier: string,
        ): Promise<BrowserFoundationDurableStateBindingHandle>;
        produceFoundationActionRandomnessReservationIntent(
            actionRandomness: BrowserFoundationActionRandomnessHandle,
            input: { stateVerifierSessionIdentifier: string },
        ): Promise<
            VerificationResult<BrowserFoundationProducedStateReservationIntent>
        >;
        readWitnessExactOutput(
            witnessRole: BrowserFoundationNormalWitnessRoleHandle,
            input: {
                durableBinding: BrowserFoundationDurableStateBindingHandle;
            },
        ): Promise<Uint8Array>;
        readWitnessSignedVoteCarrier(
            witnessRole: BrowserFoundationNormalWitnessRoleHandle,
            input: {
                durableBinding: BrowserFoundationDurableStateBindingHandle;
            },
        ): Promise<Uint8Array>;
        releaseFoundationStateReservationIntent(
            intent: BrowserFoundationStateReservationIntentHandle,
        ): Promise<void>;
        verifyFoundationActionRandomnessReservation(
            actionRandomness: BrowserFoundationActionRandomnessHandle,
            input: Omit<
                BrowserActionRandomnessReservationVerificationInput,
                'actionRandomnessSessionIdentifier'
            >,
        ): Promise<VerificationResult<string>>;
        voteForFoundationActionRandomnessReservationIntent(
            witnessRole: BrowserFoundationNormalWitnessRoleHandle,
            input: {
                canonicalReservationIntentCarrier: Uint8Array;
                stateVerifierSessionIdentifier: string;
                subjectParticipantIdentity: Uint8Array;
            },
        ): Promise<VerificationResult<Uint8Array>>;
    }>;

export type TransferableBrowserFoundationOperationOwner =
    BrowserFoundationOperationOwner &
        Readonly<{
            claimExclusiveOwner(): BrowserFoundationOperationOwner;
        }>;
