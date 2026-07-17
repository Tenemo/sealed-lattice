import type { TranscriptCoreKernel } from '../transcript-core-bridge/kernel-types.js';

export type StateVerifierKernelContext = Readonly<{
    allocate(length: number): number;
    begin(
        configurationPointer: number,
        configurationLength: number,
        capabilityPointer: number,
        capabilityLength: number,
        statusPointer: number,
    ): number;
    cancel(
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
    ): number;
    certifyIntent(
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        verifiedIntentHandle: number,
        canonicalStateCertificatePointer: number,
        canonicalStateCertificateLength: number,
        statusPointer: number,
    ): number;
    certifyUnorderedVotes(
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        verifiedIntentHandle: number,
        framedCanonicalVoteCarriersPointer: number,
        framedCanonicalVoteCarriersLength: number,
        statusPointer: number,
    ): number;
    deallocate(pointer: number, length: number): void;
    describe(
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        verifiedObjectHandle: number,
        outputPointer: number,
        outputLength: number,
    ): number;
    memory: WebAssembly.Memory;
    release(
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        verifiedObjectHandle: number,
    ): number;
    runExclusive<Result>(
        operationName: string,
        operation: () => Result,
    ): Result;
    finishOutput(
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        streamHandle: number,
        verifiedReservationHandle: number,
        canonicalOutputIntentCarrierPointer: number,
        canonicalOutputIntentCarrierLength: number,
        canonicalStateCertificatePointer: number,
        canonicalStateCertificateLength: number,
        statusPointer: number,
    ): number;
    prepareOutput(
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        streamHandle: number,
        verifiedReservationHandle: number,
        canonicalOutputIntentCarrierPointer: number,
        canonicalOutputIntentCarrierLength: number,
        statusPointer: number,
    ): number;
    prepareReservation(
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        subjectParticipantIdentityPointer: number,
        subjectParticipantIdentityLength: number,
        capabilityKindCode: number,
        expectedAuthorizationHashPointer: number,
        expectedAuthorizationHashLength: number,
        canonicalReservationIntentCarrierPointer: number,
        canonicalReservationIntentCarrierLength: number,
        statusPointer: number,
    ): number;
    producerCommand(
        command: number,
        inputPointer: number,
        inputLength: number,
        statusPointer: number,
        outputLengthPointer: number,
    ): number;
    verifyReservation(
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        subjectParticipantIdentityPointer: number,
        subjectParticipantIdentityLength: number,
        capabilityKindCode: number,
        expectedAuthorizationHashPointer: number,
        expectedAuthorizationHashLength: number,
        canonicalReservationIntentCarrierPointer: number,
        canonicalReservationIntentCarrierLength: number,
        canonicalStateCertificatePointer: number,
        canonicalStateCertificateLength: number,
        statusPointer: number,
    ): number;
}>;

const contexts = new WeakMap<
    TranscriptCoreKernel,
    StateVerifierKernelContext
>();

export const registerStateVerifierKernelContext = (
    kernel: TranscriptCoreKernel,
    context: StateVerifierKernelContext,
): void => {
    contexts.set(kernel, context);
};

export const resolveStateVerifierKernelContext = (
    kernel: TranscriptCoreKernel,
): StateVerifierKernelContext | undefined => contexts.get(kernel);
