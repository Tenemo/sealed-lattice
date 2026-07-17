import {
    stateCapabilityKinds,
    type StateCapabilityKind,
    type VerificationResult,
} from '@sealed-lattice/types';
export const stateVerifierConfigurationVersion = 1;
export const stateVerifierCapabilityByteLength = 32;
export const stateDurableBindingByteLength = 601;
export const stateIdentityByteLength = 64;
export const stateHashByteLength = 64;
export const mlDsa65SignatureByteLength = 3_309;
export const wasm32WordByteLength = 4;
export const maximumWasm32UnsignedInteger = 0xffff_ffff;
export const fixedConfigurationByteLength = 2 + 3 * stateHashByteLength + 4;
export const stateProducerCommands = Object.freeze({
    certifyReservation: 6,
    constructReservationIntent: 2,
    constructWitnessVoteCarrier: 5,
    deriveWitnessVoteSignatureMessage: 4,
    prepareSetupActionRandomnessIntent: 1,
    verifyReservationIntentForWitness: 3,
});

export { stateCapabilityKinds };
export type { StateCapabilityKind };

export type StateOutputCapabilityKind =
    | typeof stateCapabilityKinds.finalitySignature
    | typeof stateCapabilityKinds.targetRelease;

declare const verifiedStateReservationBrand: unique symbol;
declare const verifiedStateOutputBrand: unique symbol;
declare const verifiedStateReservationIntentBrand: unique symbol;
declare const verifiedStateOutputIntentBrand: unique symbol;
declare const verifiedStateDurableBindingBrand: unique symbol;

export const stateWitnessVoteKinds = Object.freeze({
    reservation: 1,
    output: 2,
} as const);

export type StateWitnessVoteKind =
    (typeof stateWitnessVoteKinds)[keyof typeof stateWitnessVoteKinds];

export type VerifiedStateDurableBinding = Readonly<{
    readonly [verifiedStateDurableBindingBrand]: true;
}>;

export type StateDurableBindingDescription = Readonly<{
    actionContextHash: Uint8Array;
    capabilityKind: StateCapabilityKind;
    ceremonyContextHash: Uint8Array;
    exactOutputByteLength?: bigint;
    exactOutputHash?: Uint8Array;
    intentObjectHash: Uint8Array;
    outputIntentObjectHash?: Uint8Array;
    reservationIntentObjectHash?: Uint8Array;
    stateKey: Uint8Array;
    subjectParticipantIdentity: Uint8Array;
    suiteIdentifier: Uint8Array;
    voteKind: StateWitnessVoteKind;
    witnessVoteSequence: bigint;
}>;

export type VerifiedStateReservationIntent = Readonly<{
    readonly [verifiedStateReservationIntentBrand]: true;
}>;

export type VerifiedStateOutputIntent = Readonly<{
    readonly [verifiedStateOutputIntentBrand]: true;
}>;

export type VerifiedStateIntent =
    | VerifiedStateOutputIntent
    | VerifiedStateReservationIntent;

export type UntrustedStateWitnessVoteCarrier = Readonly<{
    canonicalCarrier: Uint8Array;
}>;

export type VerifiedStateReservation = Readonly<{
    readonly [verifiedStateReservationBrand]: true;
}>;

export type StateObjectSignatureOperation = Readonly<{
    signStateObjectMessage(signatureMessageHash: Uint8Array): Uint8Array;
}>;

export type ProducedStateReservationIntent = Readonly<{
    canonicalReservationIntentCarrier: Uint8Array;
    verifiedIntent: VerifiedStateReservationIntent;
}>;

export type ProducedStateReservation = Readonly<{
    canonicalStateCertificate: Uint8Array;
    verifiedReservation: VerifiedStateReservation;
}>;

export type VerifiedStateOutput = Readonly<{
    readonly [verifiedStateOutputBrand]: true;
}>;

export type StateVerifierSessionInput = Readonly<{
    actionContextHash: Uint8Array;
    canonicalRosterBytes: Uint8Array;
    ceremonyContextHash: Uint8Array;
    suiteIdentifier: Uint8Array;
}>;

export type StateReservationVerification = Readonly<{
    canonicalReservationIntentCarrier: Uint8Array;
    canonicalStateCertificate: Uint8Array;
    capabilityKind: StateCapabilityKind;
    expectedAuthorizationHash: Uint8Array;
    subjectParticipantIdentity: Uint8Array;
}>;

export type StateReservationIntentVerification = Omit<
    StateReservationVerification,
    'canonicalStateCertificate'
>;

export type StateOutputVerification = Readonly<{
    canonicalOutputIntentCarrier: Uint8Array;
    canonicalStateCertificate: Uint8Array;
    exactOutputDescriptorBytes: Uint8Array;
    verifiedReservation: VerifiedStateReservation;
}>;

export type StateOutputIntentVerification = Omit<
    StateOutputVerification,
    'canonicalStateCertificate'
>;

export type StateOutputVerificationLeaseState =
    | 'active'
    | 'cancelled'
    | 'completed'
    | 'failed';

/**
 * Owns one kernel canonical-stream verifier until it reaches a terminal state.
 * A finish attempt is terminal whether verification accepts or refuses. Call
 * `dispose()` or `cancel()` when abandoning an active lease.
 */
export type StateOutputVerificationLease = Readonly<{
    readonly chunkCount: number;
    readonly totalByteLength: number;
    absorbChunk(
        chunkIndex: number,
        bytes: ArrayBuffer,
    ): VerificationResult<undefined>;
    cancel(): void;
    dispose(): void;
    finish(): VerificationResult<VerifiedStateOutput>;
    state(): StateOutputVerificationLeaseState;
}>;

/**
 * Owns one kernel canonical-stream verifier until it reaches a terminal state.
 * A finish attempt is terminal whether verification accepts or refuses. Call
 * `dispose()` or `cancel()` when abandoning an active lease.
 */
export type StateOutputIntentVerificationLease = Readonly<{
    readonly chunkCount: number;
    readonly totalByteLength: number;
    absorbChunk(
        chunkIndex: number,
        bytes: ArrayBuffer,
    ): VerificationResult<undefined>;
    cancel(): void;
    dispose(): void;
    finish(): VerificationResult<VerifiedStateOutputIntent>;
    state(): StateOutputVerificationLeaseState;
}>;

export type StateVerifierSessionState = 'active' | 'cancelled';

/**
 * Owns the kernel's sole state-verifier session and its capability allocation.
 * Call `dispose()` or `cancel()` in a `finally` block when the session is no
 * longer needed. Disposal also cancels every active output lease.
 */
export type StateVerifierSession = Readonly<{
    cancel(): void;
    certifyReservationIntentFromUntrustedVoteCarriers(input: {
        untrustedVoteCarriers: readonly UntrustedStateWitnessVoteCarrier[];
        verifiedIntent: VerifiedStateReservationIntent;
    }): VerificationResult<ProducedStateReservation>;
    certifyIntent(input: {
        canonicalStateCertificate: Uint8Array;
        verifiedIntent: VerifiedStateIntent;
    }): VerificationResult<VerifiedStateOutput | VerifiedStateReservation>;
    certifyIntentFromUntrustedVoteCarriers(input: {
        untrustedVoteCarriers: readonly UntrustedStateWitnessVoteCarrier[];
        verifiedIntent: VerifiedStateIntent;
    }): VerificationResult<VerifiedStateOutput | VerifiedStateReservation>;
    openOutputIntentVerification(
        input: StateOutputIntentVerification,
    ): VerificationResult<StateOutputIntentVerificationLease>;
    openOutputVerification(
        input: StateOutputVerification,
    ): VerificationResult<StateOutputVerificationLease>;
    durableBindingFor(
        verifiedObject:
            | VerifiedStateOutput
            | VerifiedStateOutputIntent
            | VerifiedStateReservation
            | VerifiedStateReservationIntent,
    ): VerificationResult<VerifiedStateDurableBinding>;
    dispose(): void;
    releaseVerifiedObject(
        verifiedObject:
            | VerifiedStateOutput
            | VerifiedStateOutputIntent
            | VerifiedStateReservation
            | VerifiedStateReservationIntent,
    ): VerificationResult<undefined>;
    state(): StateVerifierSessionState;
    verifyReservation(
        input: StateReservationVerification,
    ): VerificationResult<VerifiedStateReservation>;
    verifyReservationIntent(
        input: StateReservationIntentVerification,
    ): VerificationResult<VerifiedStateReservationIntent>;
    verifySetupActionRandomnessIntentForWitness(input: {
        canonicalReservationIntentCarrier: Uint8Array;
        subjectParticipantIdentity: Uint8Array;
    }): VerificationResult<VerifiedStateReservationIntent>;
}>;

export type StateVerifierWorkerProducerSession = StateVerifierSession &
    Readonly<{
        constructVerifiedStateWitnessVoteCarrier(input: {
            signatureOperation: StateObjectSignatureOperation;
            verifiedIntent: VerifiedStateReservationIntent;
            witnessParticipantIdentity: Uint8Array;
        }): VerificationResult<Uint8Array>;
        produceSetupActionRandomnessReservationIntent(input: {
            actionRandomnessHandle: number;
            signatureOperation: StateObjectSignatureOperation;
        }): VerificationResult<ProducedStateReservationIntent>;
    }>;
