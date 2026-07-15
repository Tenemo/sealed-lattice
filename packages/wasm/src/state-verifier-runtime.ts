import type {
    RefusalReason,
    StateCapabilityKind,
    VerificationResult,
} from '@sealed-lattice/types';
import { foundationProfile, stateCapabilityKinds } from '@sealed-lattice/types';

import {
    CanonicalStreamRefusalError,
    CanonicalStreamResourceError,
    canonicalStreamDomains,
    openCanonicalStreamVerifierForAtomicFinish,
    type CanonicalStreamDomain,
    type CanonicalStreamVerifierLease,
} from './canonical-stream-runtime.js';
import { refusalReasonByCode } from './transcript-core-bridge/kernel-errors.js';
import type { TranscriptCoreKernel } from './transcript-core-bridge/kernel-types.js';

type StateVerifierKernelContext = Readonly<{
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

const stateVerifierConfigurationVersion = 1;
const stateVerifierCapabilityByteLength = 32;
const stateDurableBindingByteLength = 601;
const stateIdentityByteLength = 64;
const stateHashByteLength = 64;
const wasm32WordByteLength = 4;
const maximumWasm32UnsignedInteger = 0xffff_ffff;
const fixedConfigurationByteLength = 2 + 3 * stateHashByteLength + 4;

export { stateCapabilityKinds };
export type { StateCapabilityKind };

type StateOutputCapabilityKind =
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

type StateOutputVerificationLeaseState =
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

type StateVerifierSessionState = 'active' | 'cancelled';

/**
 * Owns the kernel's sole state-verifier session and its capability allocation.
 * Call `dispose()` or `cancel()` in a `finally` block when the session is no
 * longer needed. Disposal also cancels every active output lease.
 */
export type StateVerifierSession = Readonly<{
    cancel(): void;
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
}>;

class StateVerifierInternalError extends Error {
    public readonly failureCause: unknown;

    public constructor(message: string, failureCause?: unknown) {
        super(message);
        this.name = 'StateVerifierInternalError';
        this.failureCause = failureCause;
    }
}

class StateVerifierRefusalError extends Error {
    public readonly refusalReason: RefusalReason;

    public constructor(refusalReason: RefusalReason) {
        super(`The state verifier operation was refused: ${refusalReason}.`);
        this.name = 'StateVerifierRefusalError';
        this.refusalReason = refusalReason;
    }
}

type VerifiedObjectKind =
    | 'output'
    | 'output-intent'
    | 'reservation'
    | 'reservation-intent';

type VerifiedObjectRecord = {
    active: boolean;
    activeOutputLeaseCount: number;
    capabilityKind: StateCapabilityKind;
    handle: number;
    kind: VerifiedObjectKind;
    session: StateVerifierSessionImplementation;
};

type VerifiedStateReservationKernelAuthorization = Readonly<{
    capabilityMemory: WebAssembly.Memory;
    capabilityPointer: number;
    reservationHandle: number;
    sessionHandle: number;
}>;

const verifiedObjectRecords = new WeakMap<object, VerifiedObjectRecord>();
const durableBindingDescriptions = new WeakMap<
    object,
    StateDurableBindingDescription
>();
const copyDurableBindingDescription = (
    description: StateDurableBindingDescription,
): StateDurableBindingDescription =>
    Object.freeze({
        actionContextHash: description.actionContextHash.slice(),
        capabilityKind: description.capabilityKind,
        ceremonyContextHash: description.ceremonyContextHash.slice(),
        ...(description.exactOutputByteLength === undefined
            ? {}
            : { exactOutputByteLength: description.exactOutputByteLength }),
        ...(description.exactOutputHash === undefined
            ? {}
            : { exactOutputHash: description.exactOutputHash.slice() }),
        intentObjectHash: description.intentObjectHash.slice(),
        ...(description.outputIntentObjectHash === undefined
            ? {}
            : {
                  outputIntentObjectHash:
                      description.outputIntentObjectHash.slice(),
              }),
        ...(description.reservationIntentObjectHash === undefined
            ? {}
            : {
                  reservationIntentObjectHash:
                      description.reservationIntentObjectHash.slice(),
              }),
        stateKey: description.stateKey.slice(),
        subjectParticipantIdentity:
            description.subjectParticipantIdentity.slice(),
        suiteIdentifier: description.suiteIdentifier.slice(),
        voteKind: description.voteKind,
        witnessVoteSequence: description.witnessVoteSequence,
    });

export const copyVerifiedStateDurableBinding = (
    binding: VerifiedStateDurableBinding,
): StateDurableBindingDescription => {
    if (
        (typeof binding !== 'object' && typeof binding !== 'function') ||
        binding === null
    ) {
        throw new TypeError(
            'The durable state binding was not issued by the WASM state verifier.',
        );
    }
    const description = durableBindingDescriptions.get(binding);
    if (description === undefined) {
        throw new TypeError(
            'The durable state binding was not issued by the WASM state verifier.',
        );
    }

    return copyDurableBindingDescription(description);
};

export const resolveVerifiedStateReservationKernelAuthorization = (
    reservation: VerifiedStateReservation,
    kernel: TranscriptCoreKernel,
): VerifiedStateReservationKernelAuthorization => {
    if (
        (typeof reservation !== 'object' &&
            typeof reservation !== 'function') ||
        reservation === null
    ) {
        throw new TypeError(
            'The state reservation was not issued by the WASM state verifier.',
        );
    }
    const record = verifiedObjectRecords.get(reservation);
    if (
        record === undefined ||
        !record.active ||
        record.kind !== 'reservation'
    ) {
        throw new TypeError(
            'The state reservation is unavailable or was not issued by the WASM state verifier.',
        );
    }

    return record.session.reservationKernelAuthorization(record, kernel);
};

const refused = <Value>(
    refusalReason: RefusalReason,
): VerificationResult<Value> =>
    Object.freeze({ isValid: false, refusalReason });

const valid = <Value>(value: Value): VerificationResult<Value> =>
    Object.freeze({ isValid: true, value });

const isUint8Array = (value: unknown): value is Uint8Array =>
    ArrayBuffer.isView(value) &&
    Object.prototype.toString.call(value) === '[object Uint8Array]';

const isStateCapabilityKind = (value: unknown): value is StateCapabilityKind =>
    value === stateCapabilityKinds.finalitySignature ||
    value === stateCapabilityKinds.targetRelease ||
    value === stateCapabilityKinds.setupActionRandomnessRoot ||
    value === stateCapabilityKinds.setupTerminalPackage;

const isStateOutputCapabilityKind = (
    value: StateCapabilityKind,
): value is StateOutputCapabilityKind =>
    value === stateCapabilityKinds.finalitySignature ||
    value === stateCapabilityKinds.targetRelease;

const isStateWitnessVoteKind = (value: number): value is StateWitnessVoteKind =>
    value === stateWitnessVoteKinds.reservation ||
    value === stateWitnessVoteKinds.output;

const bytesAreZero = (bytes: Uint8Array): boolean =>
    bytes.every((byte) => byte === 0);

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean => {
    if (left.byteLength !== right.byteLength) {
        return false;
    }
    for (let byteIndex = 0; byteIndex < left.byteLength; byteIndex += 1) {
        if (left[byteIndex] !== right[byteIndex]) {
            return false;
        }
    }
    return true;
};

const expectedWitnessVoteSequence = (voteKind: StateWitnessVoteKind): bigint =>
    voteKind === stateWitnessVoteKinds.reservation ? 1n : 2n;

const decodeDurableBinding = (
    bytes: Uint8Array,
): StateDurableBindingDescription => {
    if (bytes.byteLength !== stateDurableBindingByteLength) {
        throw new StateVerifierInternalError(
            'The WASM state verifier returned a durable binding with the wrong length.',
        );
    }
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    let offset = 0;
    const readUnsigned16 = (): number => {
        const value = view.getUint16(offset, true);
        offset += 2;
        return value;
    };
    const readUnsigned64 = (): bigint => {
        const value = view.getBigUint64(offset, true);
        offset += 8;
        return value;
    };
    const readFixedBytes = (byteLength: number): Uint8Array => {
        const value = bytes.slice(offset, offset + byteLength);
        offset += byteLength;
        return value;
    };
    const readOptionalHash = (): Uint8Array | undefined => {
        const present = bytes[offset];
        offset += 1;
        const hash = readFixedBytes(stateHashByteLength);
        if (present === 0) {
            if (!bytesAreZero(hash)) {
                throw new StateVerifierInternalError(
                    'The WASM state verifier returned a noncanonical absent durable hash.',
                );
            }
            return undefined;
        }
        if (present !== 1) {
            throw new StateVerifierInternalError(
                'The WASM state verifier returned an invalid optional-hash flag.',
            );
        }
        return hash;
    };

    if (readUnsigned16() !== 1) {
        throw new StateVerifierInternalError(
            'The WASM state verifier returned an unsupported durable-binding version.',
        );
    }
    const voteKind = readUnsigned16();
    const capabilityKind = readUnsigned16();
    if (
        !isStateWitnessVoteKind(voteKind) ||
        !isStateCapabilityKind(capabilityKind)
    ) {
        throw new StateVerifierInternalError(
            'The WASM state verifier returned an unassigned durable-binding code.',
        );
    }
    const suiteIdentifier = readFixedBytes(stateHashByteLength);
    const ceremonyContextHash = readFixedBytes(stateHashByteLength);
    const actionContextHash = readFixedBytes(stateHashByteLength);
    const subjectParticipantIdentity = readFixedBytes(stateIdentityByteLength);
    const stateKey = readFixedBytes(stateHashByteLength);
    const intentObjectHash = readFixedBytes(stateHashByteLength);
    const witnessVoteSequence = readUnsigned64();
    const reservationIntentObjectHash = readOptionalHash();
    const outputIntentObjectHash = readOptionalHash();
    const exactOutputHash = readOptionalHash();
    const encodedExactOutputByteLength = readUnsigned64();
    if (
        offset !== bytes.byteLength ||
        witnessVoteSequence !== expectedWitnessVoteSequence(voteKind)
    ) {
        throw new StateVerifierInternalError(
            'The WASM state verifier returned an inconsistent durable binding.',
        );
    }
    if (
        (voteKind === stateWitnessVoteKinds.reservation &&
            (reservationIntentObjectHash === undefined ||
                !bytesEqual(reservationIntentObjectHash, intentObjectHash) ||
                outputIntentObjectHash !== undefined ||
                exactOutputHash !== undefined ||
                encodedExactOutputByteLength !== 0n)) ||
        (voteKind === stateWitnessVoteKinds.output &&
            (reservationIntentObjectHash === undefined ||
                outputIntentObjectHash === undefined ||
                !bytesEqual(outputIntentObjectHash, intentObjectHash) ||
                exactOutputHash === undefined))
    ) {
        throw new StateVerifierInternalError(
            'The WASM state verifier returned a semantically inconsistent durable binding.',
        );
    }

    return Object.freeze({
        actionContextHash,
        capabilityKind,
        ceremonyContextHash,
        ...(exactOutputHash === undefined
            ? {}
            : {
                  exactOutputByteLength: encodedExactOutputByteLength,
                  exactOutputHash,
              }),
        intentObjectHash,
        ...(outputIntentObjectHash === undefined
            ? {}
            : { outputIntentObjectHash }),
        ...(reservationIntentObjectHash === undefined
            ? {}
            : { reservationIntentObjectHash }),
        stateKey,
        subjectParticipantIdentity,
        suiteIdentifier,
        voteKind,
        witnessVoteSequence,
    });
};

const decodeStatus = (status: number): RefusalReason | undefined => {
    if (status === 0) {
        return undefined;
    }
    const refusalReason = refusalReasonByCode.get(status);
    if (refusalReason === undefined) {
        throw new StateVerifierInternalError(
            'The WASM state verifier returned an unknown status code.',
        );
    }
    return refusalReason;
};

const requireCopiedBytes = (
    value: unknown,
    expectedByteLength?: number,
): RefusalReason | undefined => {
    if (
        !isUint8Array(value) ||
        value.byteLength === 0 ||
        (expectedByteLength !== undefined &&
            value.byteLength !== expectedByteLength)
    ) {
        return 'wrongTypeOrLength';
    }
    if (
        value.byteLength > foundationProfile.maximumCopiedBufferByteLength ||
        value.byteLength > maximumWasm32UnsignedInteger
    ) {
        return 'outsideSupportedProfile';
    }
    return undefined;
};

const frameUntrustedStateWitnessVoteCarriers = (
    untrustedVoteCarriers: readonly UntrustedStateWitnessVoteCarrier[],
): Uint8Array => {
    const maximumCarrierCount = foundationProfile.participantCount * 2;
    if (
        !Array.isArray(untrustedVoteCarriers) ||
        untrustedVoteCarriers.length === 0 ||
        untrustedVoteCarriers.length > maximumCarrierCount
    ) {
        throw new StateVerifierRefusalError('outsideSupportedProfile');
    }
    const canonicalCarriers = (untrustedVoteCarriers as readonly unknown[]).map(
        (untrustedCarrier) => {
            if (
                typeof untrustedCarrier !== 'object' ||
                untrustedCarrier === null ||
                Array.isArray(untrustedCarrier)
            ) {
                throw new StateVerifierRefusalError('wrongTypeOrLength');
            }
            const canonicalCarrier = (
                untrustedCarrier as { readonly canonicalCarrier?: unknown }
            ).canonicalCarrier;
            const refusalReason = requireCopiedBytes(canonicalCarrier);
            if (refusalReason !== undefined) {
                throw new StateVerifierRefusalError(refusalReason);
            }
            return Uint8Array.from(canonicalCarrier as Uint8Array);
        },
    );
    const byteLength = canonicalCarriers.reduce(
        (total, carrier) => total + wasm32WordByteLength + carrier.byteLength,
        wasm32WordByteLength,
    );
    if (
        byteLength > foundationProfile.maximumCopiedBufferByteLength ||
        byteLength > maximumWasm32UnsignedInteger
    ) {
        throw new StateVerifierRefusalError('outsideSupportedProfile');
    }
    const framed = new Uint8Array(byteLength);
    const view = new DataView(framed.buffer);
    let offset = 0;
    view.setUint32(offset, canonicalCarriers.length, true);
    offset += wasm32WordByteLength;
    for (const carrier of canonicalCarriers) {
        view.setUint32(offset, carrier.byteLength, true);
        offset += wasm32WordByteLength;
        framed.set(carrier, offset);
        offset += carrier.byteLength;
        carrier.fill(0);
    }
    return framed;
};

const encodeConfiguration = (input: StateVerifierSessionInput): Uint8Array => {
    if (typeof input !== 'object' || input === null || Array.isArray(input)) {
        throw new StateVerifierRefusalError('wrongTypeOrLength');
    }
    for (const hash of [
        input.suiteIdentifier,
        input.ceremonyContextHash,
        input.actionContextHash,
    ]) {
        const refusalReason = requireCopiedBytes(hash, stateHashByteLength);
        if (refusalReason !== undefined) {
            throw new StateVerifierRefusalError(refusalReason);
        }
    }
    const rosterRefusal = requireCopiedBytes(input.canonicalRosterBytes);
    if (rosterRefusal !== undefined) {
        throw new StateVerifierRefusalError(rosterRefusal);
    }
    const configurationByteLength =
        fixedConfigurationByteLength + input.canonicalRosterBytes.byteLength;
    if (
        configurationByteLength >
            foundationProfile.maximumCopiedBufferByteLength ||
        configurationByteLength > maximumWasm32UnsignedInteger
    ) {
        throw new StateVerifierRefusalError('outsideSupportedProfile');
    }

    const configuration = new Uint8Array(configurationByteLength);
    const view = new DataView(configuration.buffer);
    let offset = 0;
    view.setUint16(offset, stateVerifierConfigurationVersion, true);
    offset += 2;
    for (const hash of [
        input.suiteIdentifier,
        input.ceremonyContextHash,
        input.actionContextHash,
    ]) {
        configuration.set(hash, offset);
        offset += stateHashByteLength;
    }
    view.setUint32(offset, input.canonicalRosterBytes.byteLength, true);
    offset += wasm32WordByteLength;
    configuration.set(input.canonicalRosterBytes, offset);
    return configuration;
};

const zeroMemory = (
    context: StateVerifierKernelContext,
    pointer: number,
    byteLength: number,
): void => {
    if (
        pointer !== 0 &&
        pointer + byteLength <= context.memory.buffer.byteLength
    ) {
        new Uint8Array(context.memory.buffer, pointer, byteLength).fill(0);
    }
};

const allocate = (
    context: StateVerifierKernelContext,
    byteLength: number,
): number => {
    if (
        !Number.isSafeInteger(byteLength) ||
        byteLength <= 0 ||
        byteLength > foundationProfile.maximumCopiedBufferByteLength
    ) {
        throw new StateVerifierRefusalError('outsideSupportedProfile');
    }
    if (
        context.memory.buffer.byteLength >
        foundationProfile.maximumWasmMemoryByteLength - byteLength
    ) {
        throw new StateVerifierRefusalError('outsideSupportedProfile');
    }
    const pointer = context.allocate(byteLength) >>> 0;
    if (
        pointer === 0 ||
        pointer + byteLength > context.memory.buffer.byteLength
    ) {
        throw new StateVerifierInternalError(
            'The WASM state verifier allocator returned an invalid range.',
        );
    }
    return pointer;
};

const allocateZeroed = (
    context: StateVerifierKernelContext,
    byteLength: number,
): number => {
    const pointer = allocate(context, byteLength);
    zeroMemory(context, pointer, byteLength);
    return pointer;
};

const allocateAndCopy = (
    context: StateVerifierKernelContext,
    bytes: Uint8Array,
): number => {
    const pointer = allocate(context, bytes.byteLength);
    try {
        new Uint8Array(context.memory.buffer).set(bytes, pointer);
        return pointer;
    } catch (error) {
        zeroMemory(context, pointer, bytes.byteLength);
        context.deallocate(pointer, bytes.byteLength);
        throw new StateVerifierInternalError(
            'A state verifier input could not be copied into WASM memory.',
            error,
        );
    }
};

const createCapability = (context: StateVerifierKernelContext): number => {
    const capability = new Uint8Array(
        new ArrayBuffer(stateVerifierCapabilityByteLength),
    );
    const cryptoProvider = globalThis.crypto;
    if (cryptoProvider === undefined) {
        throw new StateVerifierInternalError(
            'Web Crypto getRandomValues is required for state capabilities.',
        );
    }
    try {
        cryptoProvider.getRandomValues(capability);
        if (capability.every((byte) => byte === 0)) {
            cryptoProvider.getRandomValues(capability);
        }
        if (capability.every((byte) => byte === 0)) {
            throw new StateVerifierInternalError(
                'Web Crypto produced an invalid all-zero state capability.',
            );
        }
        return allocateAndCopy(context, capability);
    } finally {
        capability.fill(0);
    }
};

type ResolvedVerifiedObject =
    | Readonly<{ record: VerifiedObjectRecord }>
    | Readonly<{ refusalReason: RefusalReason }>;

const resolveVerifiedObject = (
    value: unknown,
    session: StateVerifierSessionImplementation,
    acceptedKinds: readonly VerifiedObjectKind[],
): ResolvedVerifiedObject => {
    if (
        (typeof value !== 'object' && typeof value !== 'function') ||
        value === null
    ) {
        return { refusalReason: 'wrongTypeOrLength' };
    }
    const record = verifiedObjectRecords.get(value);
    if (record === undefined || !acceptedKinds.includes(record.kind)) {
        return { refusalReason: 'wrongTypeOrLength' };
    }
    if (record.session !== session) {
        return { refusalReason: 'wrongContext' };
    }
    if (!record.active) {
        return { refusalReason: 'consumedState' };
    }
    return { record };
};

const stateExactOutputDomain = (
    capabilityKind: StateOutputCapabilityKind,
): CanonicalStreamDomain => {
    switch (capabilityKind) {
        case stateCapabilityKinds.finalitySignature:
            return canonicalStreamDomains.stateFinalitySignatureExactOutput;
        case stateCapabilityKinds.targetRelease:
            return canonicalStreamDomains.stateTargetReleaseExactOutput;
    }
};

const canonicalStreamRefusalReason = (
    error: unknown,
): RefusalReason | undefined => {
    if (error instanceof CanonicalStreamRefusalError) {
        return error.refusalReason;
    }
    if (error instanceof CanonicalStreamResourceError) {
        return 'outsideSupportedProfile';
    }
    return undefined;
};

class StateOutputVerificationLeaseImplementation<Value> {
    readonly #streamLease: CanonicalStreamVerifierLease;
    readonly #finishResult: () => VerificationResult<Value> | undefined;
    readonly #onTerminal: () => void;
    #state: StateOutputVerificationLeaseState = 'active';

    public constructor(
        streamLease: CanonicalStreamVerifierLease,
        finishResult: () => VerificationResult<Value> | undefined,
        onTerminal: () => void,
    ) {
        this.#streamLease = streamLease;
        this.#finishResult = finishResult;
        this.#onTerminal = onTerminal;
    }

    public get chunkCount(): number {
        return this.#streamLease.chunkCount;
    }

    public get totalByteLength(): number {
        return this.#streamLease.totalByteLength;
    }

    public absorbChunk(
        chunkIndex: number,
        bytes: ArrayBuffer,
    ): VerificationResult<undefined> {
        if (this.#state !== 'active') {
            return refused('consumedState');
        }
        try {
            this.#streamLease.absorbChunk(chunkIndex, bytes);
            return valid(undefined);
        } catch (error) {
            const refusalReason = canonicalStreamRefusalReason(error);
            this.#terminate('failed');
            if (refusalReason === undefined) {
                throw error;
            }
            return refused(refusalReason);
        }
    }

    public cancel(): void {
        if (this.#state !== 'active') {
            return;
        }
        try {
            this.#streamLease.cancel();
            this.#terminate('cancelled');
        } catch (error) {
            if (this.#state === 'active') {
                this.#terminate('failed');
            }
            throw error;
        }
    }

    public dispose(): void {
        this.cancel();
    }

    public finish(): VerificationResult<Value> {
        if (this.#state !== 'active') {
            return refused('consumedState');
        }
        try {
            this.#streamLease.finish();
            const result = this.#finishResult();
            if (result === undefined) {
                throw new StateVerifierInternalError(
                    'The atomic state-output finish returned no result.',
                );
            }
            this.#terminate(result.isValid ? 'completed' : 'failed');
            return result;
        } catch (error) {
            const refusalReason = canonicalStreamRefusalReason(error);
            if (this.#state === 'active') {
                this.#terminate('failed');
            }
            if (refusalReason !== undefined) {
                return refused(refusalReason);
            }
            throw error;
        }
    }

    public state(): StateOutputVerificationLeaseState {
        return this.#state;
    }

    #terminate(
        state: Exclude<StateOutputVerificationLeaseState, 'active'>,
    ): void {
        this.#state = state;
        this.#onTerminal();
    }
}

class StateVerifierSessionImplementation implements StateVerifierSession {
    readonly #context: StateVerifierKernelContext;
    readonly #kernel: TranscriptCoreKernel;
    readonly #handle: number;
    readonly #verifiedObjectRecords = new Set<VerifiedObjectRecord>();
    readonly #outputLeases = new Set<
        StateOutputVerificationLeaseImplementation<unknown>
    >();
    #capabilityPointer: number;
    #state: StateVerifierSessionState = 'active';

    public constructor(
        kernel: TranscriptCoreKernel,
        context: StateVerifierKernelContext,
        handle: number,
        capabilityPointer: number,
    ) {
        this.#kernel = kernel;
        this.#context = context;
        this.#handle = handle;
        this.#capabilityPointer = capabilityPointer;
    }

    public reservationKernelAuthorization(
        record: VerifiedObjectRecord,
        kernel: TranscriptCoreKernel,
    ): VerifiedStateReservationKernelAuthorization {
        if (
            this.#state !== 'active' ||
            !record.active ||
            record.kind !== 'reservation' ||
            record.session !== this
        ) {
            throw new TypeError(
                'The verified state reservation is unavailable.',
            );
        }
        if (kernel !== this.#kernel) {
            throw new TypeError(
                'The verified state reservation belongs to another WASM kernel.',
            );
        }
        return Object.freeze({
            capabilityMemory: this.#context.memory,
            capabilityPointer: this.#capabilityPointer,
            reservationHandle: record.handle,
            sessionHandle: this.#handle,
        });
    }

    public durableBindingFor(
        verifiedObject:
            | VerifiedStateOutput
            | VerifiedStateOutputIntent
            | VerifiedStateReservation
            | VerifiedStateReservationIntent,
    ): VerificationResult<VerifiedStateDurableBinding> {
        if (this.#state !== 'active') {
            return refused('consumedState');
        }
        const resolved = resolveVerifiedObject(verifiedObject, this, [
            'output',
            'output-intent',
            'reservation',
            'reservation-intent',
        ]);
        if ('refusalReason' in resolved) {
            return refused(resolved.refusalReason);
        }

        let outputPointer = 0;
        try {
            outputPointer = allocateZeroed(
                this.#context,
                stateDurableBindingByteLength,
            );
            const status = this.#context.runExclusive(
                'state verifier describe durable binding',
                () =>
                    this.#context.describe(
                        this.#handle,
                        this.#capabilityPointer,
                        stateVerifierCapabilityByteLength,
                        resolved.record.handle,
                        outputPointer,
                        stateDurableBindingByteLength,
                    ),
            );
            const refusalReason = decodeStatus(status);
            if (refusalReason !== undefined) {
                return refused(refusalReason);
            }
            const description = decodeDurableBinding(
                new Uint8Array(
                    this.#context.memory.buffer,
                    outputPointer,
                    stateDurableBindingByteLength,
                ).slice(),
            );
            const expectedVoteKind =
                resolved.record.kind === 'reservation' ||
                resolved.record.kind === 'reservation-intent'
                    ? stateWitnessVoteKinds.reservation
                    : stateWitnessVoteKinds.output;
            if (
                description.capabilityKind !== resolved.record.capabilityKind ||
                description.voteKind !== expectedVoteKind
            ) {
                throw new StateVerifierInternalError(
                    'The WASM durable binding does not match its verified object handle.',
                );
            }
            const binding = Object.freeze(Object.create(null) as object);
            durableBindingDescriptions.set(binding, description);
            return valid(binding as VerifiedStateDurableBinding);
        } catch (error) {
            if (error instanceof StateVerifierRefusalError) {
                return refused(error.refusalReason);
            }
            throw error;
        } finally {
            if (outputPointer !== 0) {
                zeroMemory(
                    this.#context,
                    outputPointer,
                    stateDurableBindingByteLength,
                );
                this.#context.deallocate(
                    outputPointer,
                    stateDurableBindingByteLength,
                );
            }
        }
    }

    public verifyReservation(
        input: StateReservationVerification,
    ): VerificationResult<VerifiedStateReservation> {
        if (this.#state !== 'active') {
            return refused('consumedState');
        }
        if (
            typeof input !== 'object' ||
            input === null ||
            Array.isArray(input) ||
            !isStateCapabilityKind(input.capabilityKind)
        ) {
            return refused('wrongTypeOrLength');
        }
        for (const [bytes, expectedByteLength] of [
            [input.subjectParticipantIdentity, stateIdentityByteLength],
            [input.expectedAuthorizationHash, stateHashByteLength],
            [input.canonicalReservationIntentCarrier, undefined],
            [input.canonicalStateCertificate, undefined],
        ] as const) {
            const refusalReason = requireCopiedBytes(bytes, expectedByteLength);
            if (refusalReason !== undefined) {
                return refused(refusalReason);
            }
        }
        return this.#runHandleVerification(
            'state reservation verification',
            [
                input.subjectParticipantIdentity,
                input.expectedAuthorizationHash,
                input.canonicalReservationIntentCarrier,
                input.canonicalStateCertificate,
            ],
            (pointers, statusPointer) =>
                this.#context.verifyReservation(
                    this.#handle,
                    this.#capabilityPointer,
                    stateVerifierCapabilityByteLength,
                    pointers[0],
                    input.subjectParticipantIdentity.byteLength,
                    input.capabilityKind,
                    pointers[1],
                    input.expectedAuthorizationHash.byteLength,
                    pointers[2],
                    input.canonicalReservationIntentCarrier.byteLength,
                    pointers[3],
                    input.canonicalStateCertificate.byteLength,
                    statusPointer,
                ),
            (handle) =>
                this.#issueVerifiedObject<VerifiedStateReservation>(
                    handle,
                    'reservation',
                    input.capabilityKind,
                ),
        );
    }

    public verifyReservationIntent(
        input: StateReservationIntentVerification,
    ): VerificationResult<VerifiedStateReservationIntent> {
        if (this.#state !== 'active') {
            return refused('consumedState');
        }
        if (
            typeof input !== 'object' ||
            input === null ||
            Array.isArray(input) ||
            !isStateCapabilityKind(input.capabilityKind)
        ) {
            return refused('wrongTypeOrLength');
        }
        for (const [bytes, expectedByteLength] of [
            [input.subjectParticipantIdentity, stateIdentityByteLength],
            [input.expectedAuthorizationHash, stateHashByteLength],
            [input.canonicalReservationIntentCarrier, undefined],
        ] as const) {
            const refusalReason = requireCopiedBytes(bytes, expectedByteLength);
            if (refusalReason !== undefined) {
                return refused(refusalReason);
            }
        }
        return this.#runHandleVerification(
            'state reservation-intent verification',
            [
                input.subjectParticipantIdentity,
                input.expectedAuthorizationHash,
                input.canonicalReservationIntentCarrier,
            ],
            (pointers, statusPointer) =>
                this.#context.prepareReservation(
                    this.#handle,
                    this.#capabilityPointer,
                    stateVerifierCapabilityByteLength,
                    pointers[0],
                    input.subjectParticipantIdentity.byteLength,
                    input.capabilityKind,
                    pointers[1],
                    input.expectedAuthorizationHash.byteLength,
                    pointers[2],
                    input.canonicalReservationIntentCarrier.byteLength,
                    statusPointer,
                ),
            (handle) =>
                this.#issueVerifiedObject<VerifiedStateReservationIntent>(
                    handle,
                    'reservation-intent',
                    input.capabilityKind,
                ),
        );
    }

    public certifyIntent(input: {
        canonicalStateCertificate: Uint8Array;
        verifiedIntent: VerifiedStateIntent;
    }): VerificationResult<VerifiedStateOutput | VerifiedStateReservation> {
        if (this.#state !== 'active') {
            return refused('consumedState');
        }
        if (
            typeof input !== 'object' ||
            input === null ||
            Array.isArray(input)
        ) {
            return refused('wrongTypeOrLength');
        }
        const certificateRefusal = requireCopiedBytes(
            input.canonicalStateCertificate,
        );
        if (certificateRefusal !== undefined) {
            return refused(certificateRefusal);
        }
        const resolved = resolveVerifiedObject(input.verifiedIntent, this, [
            'output-intent',
            'reservation-intent',
        ]);
        if ('refusalReason' in resolved) {
            return refused(resolved.refusalReason);
        }
        const certifiedKind: Extract<
            VerifiedObjectKind,
            'output' | 'reservation'
        > = resolved.record.kind === 'output-intent' ? 'output' : 'reservation';

        return this.#runHandleVerification(
            'state intent certification',
            [input.canonicalStateCertificate],
            (pointers, statusPointer) =>
                this.#context.certifyIntent(
                    this.#handle,
                    this.#capabilityPointer,
                    stateVerifierCapabilityByteLength,
                    resolved.record.handle,
                    pointers[0],
                    input.canonicalStateCertificate.byteLength,
                    statusPointer,
                ),
            (handle) =>
                this.#issueVerifiedObject<
                    VerifiedStateOutput | VerifiedStateReservation
                >(handle, certifiedKind, resolved.record.capabilityKind),
        );
    }

    public certifyIntentFromUntrustedVoteCarriers(input: {
        untrustedVoteCarriers: readonly UntrustedStateWitnessVoteCarrier[];
        verifiedIntent: VerifiedStateIntent;
    }): VerificationResult<VerifiedStateOutput | VerifiedStateReservation> {
        if (this.#state !== 'active') {
            return refused('consumedState');
        }
        if (
            typeof input !== 'object' ||
            input === null ||
            Array.isArray(input)
        ) {
            return refused('wrongTypeOrLength');
        }
        const resolved = resolveVerifiedObject(input.verifiedIntent, this, [
            'output-intent',
            'reservation-intent',
        ]);
        if ('refusalReason' in resolved) {
            return refused(resolved.refusalReason);
        }
        let framedCarriers: Uint8Array;
        try {
            framedCarriers = frameUntrustedStateWitnessVoteCarriers(
                input.untrustedVoteCarriers,
            );
        } catch (error) {
            if (error instanceof StateVerifierRefusalError) {
                return refused(error.refusalReason);
            }
            throw error;
        }
        const certifiedKind: Extract<
            VerifiedObjectKind,
            'output' | 'reservation'
        > = resolved.record.kind === 'output-intent' ? 'output' : 'reservation';
        try {
            return this.#runHandleVerification(
                'unordered state vote certification',
                [framedCarriers],
                (pointers, statusPointer) =>
                    this.#context.certifyUnorderedVotes(
                        this.#handle,
                        this.#capabilityPointer,
                        stateVerifierCapabilityByteLength,
                        resolved.record.handle,
                        pointers[0],
                        framedCarriers.byteLength,
                        statusPointer,
                    ),
                (handle) =>
                    this.#issueVerifiedObject<
                        VerifiedStateOutput | VerifiedStateReservation
                    >(handle, certifiedKind, resolved.record.capabilityKind),
            );
        } finally {
            framedCarriers.fill(0);
        }
    }

    public openOutputIntentVerification(
        input: StateOutputIntentVerification,
    ): VerificationResult<StateOutputIntentVerificationLease> {
        if (this.#state !== 'active') {
            return refused('consumedState');
        }
        if (
            typeof input !== 'object' ||
            input === null ||
            Array.isArray(input)
        ) {
            return refused('wrongTypeOrLength');
        }
        const resolvedReservation = resolveVerifiedObject(
            input.verifiedReservation,
            this,
            ['reservation'],
        );
        if ('refusalReason' in resolvedReservation) {
            return refused(resolvedReservation.refusalReason);
        }
        const capabilityKind = resolvedReservation.record.capabilityKind;
        if (!isStateOutputCapabilityKind(capabilityKind)) {
            return refused('wrongTypeOrLength');
        }
        for (const bytes of [
            input.canonicalOutputIntentCarrier,
            input.exactOutputDescriptorBytes,
        ]) {
            const refusalReason = requireCopiedBytes(bytes);
            if (refusalReason !== undefined) {
                return refused(refusalReason);
            }
        }

        const outputIntentCarrier = Uint8Array.from(
            input.canonicalOutputIntentCarrier,
        );
        let finishResult:
            | VerificationResult<VerifiedStateOutputIntent>
            | undefined;
        let outputLease:
            | StateOutputVerificationLeaseImplementation<VerifiedStateOutputIntent>
            | undefined;
        try {
            const streamLease = openCanonicalStreamVerifierForAtomicFinish({
                atomicFinish: (stream) => {
                    finishResult = this.#finishOutputIntent(
                        resolvedReservation.record,
                        outputIntentCarrier,
                        stream,
                    );
                },
                descriptorBytes: input.exactOutputDescriptorBytes,
                kernel: this.#kernel,
                streamDomain: stateExactOutputDomain(capabilityKind),
            });
            outputLease = new StateOutputVerificationLeaseImplementation(
                streamLease,
                () => finishResult,
                () => {
                    if (
                        resolvedReservation.record.activeOutputLeaseCount === 0
                    ) {
                        throw new StateVerifierInternalError(
                            'A state output-intent lease released an unpinned reservation.',
                        );
                    }
                    resolvedReservation.record.activeOutputLeaseCount -= 1;
                    if (outputLease !== undefined) {
                        this.#outputLeases.delete(outputLease);
                    }
                },
            );
            resolvedReservation.record.activeOutputLeaseCount += 1;
            this.#outputLeases.add(outputLease);
            return valid(outputLease);
        } catch (error) {
            const refusalReason = canonicalStreamRefusalReason(error);
            if (refusalReason !== undefined) {
                return refused(refusalReason);
            }
            throw error;
        }
    }

    public openOutputVerification(
        input: StateOutputVerification,
    ): VerificationResult<StateOutputVerificationLease> {
        if (this.#state !== 'active') {
            return refused('consumedState');
        }
        if (
            typeof input !== 'object' ||
            input === null ||
            Array.isArray(input)
        ) {
            return refused('wrongTypeOrLength');
        }
        const resolvedReservation = resolveVerifiedObject(
            input.verifiedReservation,
            this,
            ['reservation'],
        );
        if ('refusalReason' in resolvedReservation) {
            return refused(resolvedReservation.refusalReason);
        }
        const capabilityKind = resolvedReservation.record.capabilityKind;
        if (!isStateOutputCapabilityKind(capabilityKind)) {
            return refused('wrongTypeOrLength');
        }
        for (const bytes of [
            input.canonicalOutputIntentCarrier,
            input.canonicalStateCertificate,
            input.exactOutputDescriptorBytes,
        ]) {
            const refusalReason = requireCopiedBytes(bytes);
            if (refusalReason !== undefined) {
                return refused(refusalReason);
            }
        }

        const outputIntentCarrier = Uint8Array.from(
            input.canonicalOutputIntentCarrier,
        );
        const stateCertificate = Uint8Array.from(
            input.canonicalStateCertificate,
        );
        let finishResult: VerificationResult<VerifiedStateOutput> | undefined;
        let outputLease:
            | StateOutputVerificationLeaseImplementation<VerifiedStateOutput>
            | undefined;
        try {
            const streamLease = openCanonicalStreamVerifierForAtomicFinish({
                atomicFinish: (stream) => {
                    finishResult = this.#finishOutput(
                        resolvedReservation.record,
                        outputIntentCarrier,
                        stateCertificate,
                        stream,
                    );
                },
                descriptorBytes: input.exactOutputDescriptorBytes,
                kernel: this.#kernel,
                streamDomain: stateExactOutputDomain(capabilityKind),
            });
            outputLease = new StateOutputVerificationLeaseImplementation(
                streamLease,
                () => finishResult,
                () => {
                    if (
                        resolvedReservation.record.activeOutputLeaseCount === 0
                    ) {
                        throw new StateVerifierInternalError(
                            'A state-output lease released an unpinned reservation.',
                        );
                    }
                    resolvedReservation.record.activeOutputLeaseCount -= 1;
                    if (outputLease !== undefined) {
                        this.#outputLeases.delete(outputLease);
                    }
                },
            );
            resolvedReservation.record.activeOutputLeaseCount += 1;
            this.#outputLeases.add(outputLease);
            return valid(outputLease);
        } catch (error) {
            const refusalReason = canonicalStreamRefusalReason(error);
            if (refusalReason !== undefined) {
                return refused(refusalReason);
            }
            throw error;
        }
    }

    public releaseVerifiedObject(
        verifiedObject:
            | VerifiedStateOutput
            | VerifiedStateOutputIntent
            | VerifiedStateReservation
            | VerifiedStateReservationIntent,
    ): VerificationResult<undefined> {
        if (this.#state !== 'active') {
            return refused('consumedState');
        }
        const resolved = resolveVerifiedObject(verifiedObject, this, [
            'reservation',
            'reservation-intent',
            'output',
            'output-intent',
        ]);
        if ('refusalReason' in resolved) {
            return refused(resolved.refusalReason);
        }
        if (resolved.record.activeOutputLeaseCount !== 0) {
            return refused('consumedState');
        }
        const status = this.#context.runExclusive(
            'verified state object release',
            () =>
                this.#context.release(
                    this.#handle,
                    this.#capabilityPointer,
                    stateVerifierCapabilityByteLength,
                    resolved.record.handle,
                ),
        );
        const refusalReason = decodeStatus(status);
        if (refusalReason !== undefined) {
            return refused(refusalReason);
        }
        resolved.record.active = false;
        this.#verifiedObjectRecords.delete(resolved.record);
        return valid(undefined);
    }

    public state(): StateVerifierSessionState {
        return this.#state;
    }

    public dispose(): void {
        this.cancel();
    }

    public cancel(): void {
        if (this.#state !== 'active') {
            return;
        }
        for (const outputLease of [...this.#outputLeases]) {
            outputLease.cancel();
        }
        const status = this.#context.runExclusive(
            'state verifier cancellation',
            () =>
                this.#context.cancel(
                    this.#handle,
                    this.#capabilityPointer,
                    stateVerifierCapabilityByteLength,
                ),
        );
        const refusalReason = decodeStatus(status);
        if (refusalReason !== undefined) {
            throw new StateVerifierRefusalError(refusalReason);
        }
        this.#state = 'cancelled';
        for (const record of this.#verifiedObjectRecords) {
            record.active = false;
        }
        this.#verifiedObjectRecords.clear();
        zeroMemory(
            this.#context,
            this.#capabilityPointer,
            stateVerifierCapabilityByteLength,
        );
        this.#context.deallocate(
            this.#capabilityPointer,
            stateVerifierCapabilityByteLength,
        );
        this.#capabilityPointer = 0;
    }

    #finishOutputIntent(
        reservationRecord: VerifiedObjectRecord,
        outputIntentCarrier: Uint8Array,
        stream: Readonly<{
            streamHandle: number;
        }>,
    ): VerificationResult<VerifiedStateOutputIntent> {
        if (this.#state !== 'active' || !reservationRecord.active) {
            throw new StateVerifierInternalError(
                'A state output-intent transaction lost its pinned reservation.',
            );
        }
        if (reservationRecord.session !== this) {
            throw new StateVerifierInternalError(
                'A state output-intent transaction crossed verifier sessions.',
            );
        }
        return this.#runHandleVerification(
            'state output-intent verification',
            [outputIntentCarrier],
            (pointers, statusPointer) =>
                this.#context.prepareOutput(
                    this.#handle,
                    this.#capabilityPointer,
                    stateVerifierCapabilityByteLength,
                    stream.streamHandle,
                    reservationRecord.handle,
                    pointers[0],
                    outputIntentCarrier.byteLength,
                    statusPointer,
                ),
            (handle) =>
                this.#issueVerifiedObject<VerifiedStateOutputIntent>(
                    handle,
                    'output-intent',
                    reservationRecord.capabilityKind,
                ),
        );
    }

    #finishOutput(
        reservationRecord: VerifiedObjectRecord,
        outputIntentCarrier: Uint8Array,
        stateCertificate: Uint8Array,
        stream: Readonly<{
            streamHandle: number;
        }>,
    ): VerificationResult<VerifiedStateOutput> {
        if (this.#state !== 'active' || !reservationRecord.active) {
            throw new StateVerifierInternalError(
                'A state-output transaction lost its pinned reservation.',
            );
        }
        if (reservationRecord.session !== this) {
            throw new StateVerifierInternalError(
                'A state-output transaction crossed verifier sessions.',
            );
        }
        return this.#runHandleVerification(
            'state output verification',
            [outputIntentCarrier, stateCertificate],
            (pointers, statusPointer) =>
                this.#context.finishOutput(
                    this.#handle,
                    this.#capabilityPointer,
                    stateVerifierCapabilityByteLength,
                    stream.streamHandle,
                    reservationRecord.handle,
                    pointers[0],
                    outputIntentCarrier.byteLength,
                    pointers[1],
                    stateCertificate.byteLength,
                    statusPointer,
                ),
            (handle) =>
                this.#issueVerifiedObject<VerifiedStateOutput>(
                    handle,
                    'output',
                    reservationRecord.capabilityKind,
                ),
        );
    }

    #runHandleVerification<Value>(
        operationName: string,
        inputs: readonly Uint8Array[],
        invoke: (pointers: readonly number[], statusPointer: number) => number,
        issueValue: (handle: number) => Value,
    ): VerificationResult<Value> {
        const pointers: number[] = [];
        let statusPointer = 0;
        try {
            for (const input of inputs) {
                pointers.push(allocateAndCopy(this.#context, input));
            }
            statusPointer = allocateZeroed(this.#context, wasm32WordByteLength);
            const handle = this.#context.runExclusive(operationName, () =>
                invoke(pointers, statusPointer),
            );
            const status = new DataView(
                this.#context.memory.buffer,
                statusPointer,
                wasm32WordByteLength,
            ).getUint32(0, true);
            const refusalReason = decodeStatus(status);
            if (refusalReason !== undefined) {
                if (handle !== 0) {
                    throw new StateVerifierInternalError(
                        'A refused state verification returned an object handle.',
                    );
                }
                return refused(refusalReason);
            }
            if (handle === 0) {
                throw new StateVerifierInternalError(
                    'A successful state verification returned no object handle.',
                );
            }
            return valid(issueValue(handle));
        } catch (error) {
            if (error instanceof StateVerifierRefusalError) {
                return refused(error.refusalReason);
            }
            throw error;
        } finally {
            for (
                let inputIndex = 0;
                inputIndex < pointers.length;
                inputIndex += 1
            ) {
                zeroMemory(
                    this.#context,
                    pointers[inputIndex],
                    inputs[inputIndex].byteLength,
                );
                this.#context.deallocate(
                    pointers[inputIndex],
                    inputs[inputIndex].byteLength,
                );
            }
            if (statusPointer !== 0) {
                zeroMemory(this.#context, statusPointer, wasm32WordByteLength);
                this.#context.deallocate(statusPointer, wasm32WordByteLength);
            }
        }
    }

    #issueVerifiedObject<Value>(
        handle: number,
        kind: VerifiedObjectKind,
        capabilityKind: StateCapabilityKind,
    ): Value {
        const value = Object.freeze(Object.create(null) as object);
        const record: VerifiedObjectRecord = {
            active: true,
            activeOutputLeaseCount: 0,
            capabilityKind,
            handle,
            kind,
            session: this,
        };
        verifiedObjectRecords.set(value, record);
        this.#verifiedObjectRecords.add(record);
        return value as Value;
    }
}

export const openStateVerifierSession = (input: {
    readonly configuration: StateVerifierSessionInput;
    readonly kernel: TranscriptCoreKernel;
}): VerificationResult<StateVerifierSession> => {
    const context = contexts.get(input.kernel);
    if (context === undefined) {
        throw new StateVerifierInternalError(
            'The transcript-core kernel has no registered state verifier boundary.',
        );
    }
    let configuration: Uint8Array;
    try {
        configuration = encodeConfiguration(input.configuration);
    } catch (error) {
        if (error instanceof StateVerifierRefusalError) {
            return refused(error.refusalReason);
        }
        throw error;
    }

    let capabilityPointer = 0;
    let configurationPointer = 0;
    let handle = 0;
    let statusPointer = 0;
    let sessionActivated = false;
    try {
        capabilityPointer = createCapability(context);
        configurationPointer = allocateAndCopy(context, configuration);
        statusPointer = allocateZeroed(context, wasm32WordByteLength);
        handle = context.runExclusive('state verifier begin', () =>
            context.begin(
                configurationPointer,
                configuration.byteLength,
                capabilityPointer,
                stateVerifierCapabilityByteLength,
                statusPointer,
            ),
        );
        const status = new DataView(
            context.memory.buffer,
            statusPointer,
            wasm32WordByteLength,
        ).getUint32(0, true);
        const refusalReason = decodeStatus(status);
        if (refusalReason !== undefined) {
            if (handle !== 0) {
                throw new StateVerifierInternalError(
                    'A refused state-verifier begin returned a session handle.',
                );
            }
            return refused(refusalReason);
        }
        if (handle === 0) {
            throw new StateVerifierInternalError(
                'The WASM state verifier returned an invalid session handle.',
            );
        }
        sessionActivated = true;
        return valid(
            Object.freeze(
                new StateVerifierSessionImplementation(
                    input.kernel,
                    context,
                    handle,
                    capabilityPointer,
                ),
            ),
        );
    } catch (operationFailure) {
        if (!sessionActivated && handle !== 0 && capabilityPointer !== 0) {
            try {
                const cleanupStatus = context.runExclusive(
                    'state verifier begin failure cleanup',
                    () =>
                        context.cancel(
                            handle,
                            capabilityPointer,
                            stateVerifierCapabilityByteLength,
                        ),
                );
                const cleanupRefusal = decodeStatus(cleanupStatus);
                if (cleanupRefusal !== undefined) {
                    throw new StateVerifierRefusalError(cleanupRefusal);
                }
            } catch (cleanupFailure) {
                throw new StateVerifierInternalError(
                    'The state-verifier begin operation and cleanup both failed.',
                    Object.freeze({ cleanupFailure, operationFailure }),
                );
            }
        }
        if (operationFailure instanceof StateVerifierRefusalError) {
            return refused(operationFailure.refusalReason);
        }
        throw operationFailure;
    } finally {
        configuration.fill(0);
        if (configurationPointer !== 0) {
            zeroMemory(context, configurationPointer, configuration.byteLength);
            context.deallocate(configurationPointer, configuration.byteLength);
        }
        if (statusPointer !== 0) {
            zeroMemory(context, statusPointer, wasm32WordByteLength);
            context.deallocate(statusPointer, wasm32WordByteLength);
        }
        if (!sessionActivated && capabilityPointer !== 0) {
            zeroMemory(
                context,
                capabilityPointer,
                stateVerifierCapabilityByteLength,
            );
            context.deallocate(
                capabilityPointer,
                stateVerifierCapabilityByteLength,
            );
        }
    }
};
