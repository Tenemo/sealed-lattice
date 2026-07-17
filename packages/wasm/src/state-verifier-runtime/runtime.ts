import type { RefusalReason, VerificationResult } from '@sealed-lattice/types';
import {
    configurableParticipantCountRange,
    foundationProfile,
} from '@sealed-lattice/types';

import { byteArraysEqual, isUint8Array } from '../byte-array.js';
import {
    CanonicalStreamRefusalError,
    CanonicalStreamResourceError,
    canonicalStreamDomains,
    openCanonicalStreamVerifierForAtomicFinish,
    type CanonicalStreamDomain,
    type CanonicalStreamVerifierLease,
} from '../canonical-stream-runtime.js';
import { decodeWasmRefusalStatus } from '../transcript-core-bridge/kernel-errors.js';
import type { TranscriptCoreKernel } from '../transcript-core-bridge/kernel-types.js';

import {
    fixedConfigurationByteLength,
    maximumWasm32UnsignedInteger,
    mlDsa65SignatureByteLength,
    stateCapabilityKinds,
    stateDurableBindingByteLength,
    stateHashByteLength,
    stateIdentityByteLength,
    stateProducerCommands,
    stateVerifierCapabilityByteLength,
    stateVerifierConfigurationVersion,
    stateWitnessVoteKinds,
    wasm32WordByteLength,
    type ProducedStateReservation,
    type ProducedStateReservationIntent,
    type StateCapabilityKind,
    type StateDurableBindingDescription,
    type StateObjectSignatureOperation,
    type StateOutputCapabilityKind,
    type StateOutputIntentVerification,
    type StateOutputIntentVerificationLease,
    type StateOutputVerification,
    type StateOutputVerificationLease,
    type StateOutputVerificationLeaseState,
    type StateReservationIntentVerification,
    type StateReservationVerification,
    type StateVerifierSession,
    type StateVerifierSessionInput,
    type StateVerifierSessionState,
    type StateVerifierWorkerProducerSession,
    type StateWitnessVoteKind,
    type UntrustedStateWitnessVoteCarrier,
    type VerifiedStateDurableBinding,
    type VerifiedStateIntent,
    type VerifiedStateOutput,
    type VerifiedStateOutputIntent,
    type VerifiedStateReservation,
    type VerifiedStateReservationIntent,
} from './contracts.js';
import {
    resolveStateVerifierKernelContext,
    type StateVerifierKernelContext,
} from './kernel-context.js';

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
                !byteArraysEqual(
                    reservationIntentObjectHash,
                    intentObjectHash,
                ) ||
                outputIntentObjectHash !== undefined ||
                exactOutputHash !== undefined ||
                encodedExactOutputByteLength !== 0n)) ||
        (voteKind === stateWitnessVoteKinds.output &&
            (reservationIntentObjectHash === undefined ||
                outputIntentObjectHash === undefined ||
                !byteArraysEqual(outputIntentObjectHash, intentObjectHash) ||
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
    return decodeWasmRefusalStatus(
        status,
        StateVerifierInternalError,
        'The WASM state verifier returned an unknown status code.',
    );
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
    const maximumCarrierCount = configurableParticipantCountRange.maximum * 2;
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

const concatenateBytes = (...parts: readonly Uint8Array[]): Uint8Array => {
    const byteLength = parts.reduce(
        (total, part) => total + part.byteLength,
        0,
    );
    if (
        byteLength === 0 ||
        byteLength > foundationProfile.maximumCopiedBufferByteLength ||
        byteLength > maximumWasm32UnsignedInteger
    ) {
        throw new StateVerifierRefusalError('outsideSupportedProfile');
    }
    const output = new Uint8Array(byteLength);
    let offset = 0;
    for (const part of parts) {
        output.set(part, offset);
        offset += part.byteLength;
    }
    return output;
};

const encodeUnsigned32 = (value: number): Uint8Array => {
    if (!Number.isInteger(value) || value <= 0 || value > 0xffff_ffff) {
        throw new StateVerifierRefusalError('wrongTypeOrLength');
    }
    const bytes = new Uint8Array(wasm32WordByteLength);
    new DataView(bytes.buffer).setUint32(0, value, true);
    return bytes;
};

const lengthPrefixed = (bytes: Uint8Array): Uint8Array =>
    concatenateBytes(encodeUnsigned32(bytes.byteLength), bytes);

const decodeHandleAndBytes = (
    output: Uint8Array,
    label: string,
): Readonly<{ bytes: Uint8Array; handle: number }> => {
    if (output.byteLength < 2 * wasm32WordByteLength) {
        throw new StateVerifierInternalError(
            `The WASM state producer returned a truncated ${label}.`,
        );
    }
    const view = new DataView(
        output.buffer,
        output.byteOffset,
        output.byteLength,
    );
    const handle = view.getUint32(0, true);
    const byteLength = view.getUint32(wasm32WordByteLength, true);
    if (
        handle === 0 ||
        byteLength === 0 ||
        output.byteLength !== 2 * wasm32WordByteLength + byteLength
    ) {
        throw new StateVerifierInternalError(
            `The WASM state producer returned malformed ${label} metadata.`,
        );
    }
    return Object.freeze({
        bytes: output.slice(2 * wasm32WordByteLength),
        handle,
    });
};

const decodeLeadingHandle = (output: Uint8Array, label: string): number => {
    if (output.byteLength < wasm32WordByteLength) {
        throw new StateVerifierInternalError(
            `The WASM state producer returned truncated ${label} metadata.`,
        );
    }
    const handle = new DataView(
        output.buffer,
        output.byteOffset,
        output.byteLength,
    ).getUint32(0, true);
    if (handle === 0) {
        throw new StateVerifierInternalError(
            `The WASM state producer returned no ${label} handle.`,
        );
    }
    return handle;
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

    public verifySetupActionRandomnessIntentForWitness(input: {
        canonicalReservationIntentCarrier: Uint8Array;
        subjectParticipantIdentity: Uint8Array;
    }): VerificationResult<VerifiedStateReservationIntent> {
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
        const subjectRefusal = requireCopiedBytes(
            input.subjectParticipantIdentity,
            stateIdentityByteLength,
        );
        const carrierRefusal = requireCopiedBytes(
            input.canonicalReservationIntentCarrier,
        );
        if (subjectRefusal !== undefined || carrierRefusal !== undefined) {
            return refused(subjectRefusal ?? carrierRefusal!);
        }
        let output: Uint8Array | undefined;
        try {
            output = this.#runStateProducerCommand(
                stateProducerCommands.verifyReservationIntentForWitness,
                this.#stateProducerInput(
                    input.subjectParticipantIdentity,
                    lengthPrefixed(input.canonicalReservationIntentCarrier),
                ),
                'verify a setup action-randomness intent for witnessing',
            );
            if (output.byteLength !== wasm32WordByteLength) {
                throw new StateVerifierInternalError(
                    'The WASM state producer returned a malformed verified-intent handle.',
                );
            }
            const handle = new DataView(
                output.buffer,
                output.byteOffset,
                output.byteLength,
            ).getUint32(0, true);
            if (handle === 0) {
                throw new StateVerifierInternalError(
                    'The WASM state producer returned no verified-intent handle.',
                );
            }
            try {
                return valid(
                    this.#issueVerifiedObject<VerifiedStateReservationIntent>(
                        handle,
                        'reservation-intent',
                        stateCapabilityKinds.setupActionRandomnessRoot,
                    ),
                );
            } catch (registrationFailure) {
                return this.#releaseUnregisteredKernelHandle(
                    handle,
                    registrationFailure,
                );
            }
        } catch (error) {
            if (error instanceof StateVerifierRefusalError) {
                return refused(error.refusalReason);
            }
            throw error;
        } finally {
            output?.fill(0);
        }
    }

    public produceSetupActionRandomnessReservationIntent(input: {
        actionRandomnessHandle: number;
        signatureOperation: StateObjectSignatureOperation;
    }): VerificationResult<ProducedStateReservationIntent> {
        if (this.#state !== 'active') {
            return refused('consumedState');
        }
        if (
            typeof input !== 'object' ||
            input === null ||
            Array.isArray(input) ||
            typeof input.signatureOperation !== 'object' ||
            input.signatureOperation === null ||
            typeof input.signatureOperation.signStateObjectMessage !==
                'function'
        ) {
            return refused('wrongTypeOrLength');
        }
        let candidateHandle = 0;
        let constructedIntentHandle = 0;
        let prepareOutput: Uint8Array | undefined;
        let signature: Uint8Array | undefined;
        let constructOutput: Uint8Array | undefined;
        try {
            prepareOutput = this.#runStateProducerCommand(
                stateProducerCommands.prepareSetupActionRandomnessIntent,
                this.#stateProducerInput(
                    encodeUnsigned32(input.actionRandomnessHandle),
                ),
                'prepare a setup action-randomness reservation intent',
            );
            if (
                prepareOutput.byteLength !==
                wasm32WordByteLength + stateHashByteLength
            ) {
                throw new StateVerifierInternalError(
                    'The WASM state producer returned malformed reservation-intent preparation.',
                );
            }
            candidateHandle = new DataView(
                prepareOutput.buffer,
                prepareOutput.byteOffset,
                prepareOutput.byteLength,
            ).getUint32(0, true);
            if (candidateHandle === 0) {
                throw new StateVerifierInternalError(
                    'The WASM state producer returned no reservation-intent candidate handle.',
                );
            }
            const signatureMessage = prepareOutput.slice(wasm32WordByteLength);
            try {
                const operationResult =
                    input.signatureOperation.signStateObjectMessage(
                        signatureMessage,
                    );
                const signatureRefusal = requireCopiedBytes(
                    operationResult,
                    mlDsa65SignatureByteLength,
                );
                if (signatureRefusal !== undefined) {
                    throw new StateVerifierRefusalError(signatureRefusal);
                }
                signature = Uint8Array.from(operationResult);
            } finally {
                signatureMessage.fill(0);
            }
            constructOutput = this.#runStateProducerCommand(
                stateProducerCommands.constructReservationIntent,
                this.#stateProducerInput(
                    encodeUnsigned32(candidateHandle),
                    signature,
                ),
                'construct and verify a setup action-randomness reservation intent',
            );
            candidateHandle = 0;
            constructedIntentHandle = decodeLeadingHandle(
                constructOutput,
                'reservation-intent',
            );
            const decoded = decodeHandleAndBytes(
                constructOutput,
                'reservation-intent carrier',
            );
            if (decoded.handle !== constructedIntentHandle) {
                throw new StateVerifierInternalError(
                    'The WASM state producer returned inconsistent reservation-intent metadata.',
                );
            }
            const verifiedIntent =
                this.#issueVerifiedObject<VerifiedStateReservationIntent>(
                    constructedIntentHandle,
                    'reservation-intent',
                    stateCapabilityKinds.setupActionRandomnessRoot,
                );
            constructedIntentHandle = 0;
            return valid(
                Object.freeze({
                    canonicalReservationIntentCarrier: decoded.bytes.slice(),
                    verifiedIntent,
                }),
            );
        } catch (error) {
            if (constructedIntentHandle !== 0) {
                this.#releaseUnregisteredKernelHandle(
                    constructedIntentHandle,
                    error,
                );
            }
            if (error instanceof StateVerifierRefusalError) {
                return refused(error.refusalReason);
            }
            throw error;
        } finally {
            if (candidateHandle !== 0) {
                this.#releaseKernelHandle(candidateHandle);
            }
            prepareOutput?.fill(0);
            signature?.fill(0);
            constructOutput?.fill(0);
        }
    }

    public constructVerifiedStateWitnessVoteCarrier(input: {
        signatureOperation: StateObjectSignatureOperation;
        verifiedIntent: VerifiedStateReservationIntent;
        witnessParticipantIdentity: Uint8Array;
    }): VerificationResult<Uint8Array> {
        if (this.#state !== 'active') {
            return refused('consumedState');
        }
        if (
            typeof input !== 'object' ||
            input === null ||
            Array.isArray(input) ||
            typeof input.signatureOperation !== 'object' ||
            input.signatureOperation === null ||
            typeof input.signatureOperation.signStateObjectMessage !==
                'function'
        ) {
            return refused('wrongTypeOrLength');
        }
        const resolved = resolveVerifiedObject(input.verifiedIntent, this, [
            'reservation-intent',
        ]);
        if ('refusalReason' in resolved) {
            return refused(resolved.refusalReason);
        }
        if (
            resolved.record.capabilityKind !==
            stateCapabilityKinds.setupActionRandomnessRoot
        ) {
            return refused('wrongTypeOrLength');
        }
        const witnessRefusal = requireCopiedBytes(
            input.witnessParticipantIdentity,
            stateIdentityByteLength,
        );
        if (witnessRefusal !== undefined) {
            return refused(witnessRefusal);
        }
        let message: Uint8Array | undefined;
        let operationSuffix: Uint8Array | undefined;
        let signature: Uint8Array | undefined;
        let carrier: Uint8Array | undefined;
        try {
            operationSuffix = concatenateBytes(
                encodeUnsigned32(resolved.record.handle),
                input.witnessParticipantIdentity,
            );
            message = this.#runStateProducerCommand(
                stateProducerCommands.deriveWitnessVoteSignatureMessage,
                this.#stateProducerInput(operationSuffix),
                'derive a state witness-vote signature message',
            );
            if (message.byteLength !== stateHashByteLength) {
                throw new StateVerifierInternalError(
                    'The WASM state producer returned a malformed witness-vote signature message.',
                );
            }
            const operationResult =
                input.signatureOperation.signStateObjectMessage(message);
            const signatureRefusal = requireCopiedBytes(
                operationResult,
                mlDsa65SignatureByteLength,
            );
            if (signatureRefusal !== undefined) {
                return refused(signatureRefusal);
            }
            signature = Uint8Array.from(operationResult);
            carrier = this.#runStateProducerCommand(
                stateProducerCommands.constructWitnessVoteCarrier,
                this.#stateProducerInput(operationSuffix, signature),
                'construct and verify a state witness-vote carrier',
            );
            if (carrier.byteLength === 0) {
                throw new StateVerifierInternalError(
                    'The WASM state producer returned an empty witness-vote carrier.',
                );
            }
            return valid(carrier.slice());
        } catch (error) {
            if (error instanceof StateVerifierRefusalError) {
                return refused(error.refusalReason);
            }
            throw error;
        } finally {
            message?.fill(0);
            operationSuffix?.fill(0);
            signature?.fill(0);
            carrier?.fill(0);
        }
    }

    public certifyReservationIntentFromUntrustedVoteCarriers(input: {
        untrustedVoteCarriers: readonly UntrustedStateWitnessVoteCarrier[];
        verifiedIntent: VerifiedStateReservationIntent;
    }): VerificationResult<ProducedStateReservation> {
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
            'reservation-intent',
        ]);
        if ('refusalReason' in resolved) {
            return refused(resolved.refusalReason);
        }
        if (
            resolved.record.capabilityKind !==
            stateCapabilityKinds.setupActionRandomnessRoot
        ) {
            return refused('wrongTypeOrLength');
        }
        let framedCarriers: Uint8Array | undefined;
        let output: Uint8Array | undefined;
        let reservationHandle = 0;
        try {
            framedCarriers = frameUntrustedStateWitnessVoteCarriers(
                input.untrustedVoteCarriers,
            );
            output = this.#runStateProducerCommand(
                stateProducerCommands.certifyReservation,
                this.#stateProducerInput(
                    encodeUnsigned32(resolved.record.handle),
                    framedCarriers,
                ),
                'certify a setup action-randomness reservation',
            );
            reservationHandle = decodeLeadingHandle(output, 'reservation');
            const decoded = decodeHandleAndBytes(output, 'state certificate');
            if (decoded.handle !== reservationHandle) {
                throw new StateVerifierInternalError(
                    'The WASM state producer returned inconsistent reservation metadata.',
                );
            }
            resolved.record.active = false;
            this.#verifiedObjectRecords.delete(resolved.record);
            const verifiedReservation =
                this.#issueVerifiedObject<VerifiedStateReservation>(
                    reservationHandle,
                    'reservation',
                    resolved.record.capabilityKind,
                );
            reservationHandle = 0;
            return valid(
                Object.freeze({
                    canonicalStateCertificate: decoded.bytes.slice(),
                    verifiedReservation,
                }),
            );
        } catch (error) {
            if (reservationHandle !== 0) {
                this.#releaseUnregisteredKernelHandle(reservationHandle, error);
            }
            if (error instanceof StateVerifierRefusalError) {
                return refused(error.refusalReason);
            }
            throw error;
        } finally {
            framedCarriers?.fill(0);
            output?.fill(0);
        }
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

    #stateProducerSessionBinding(): Uint8Array {
        if (this.#state !== 'active' || this.#capabilityPointer === 0) {
            throw new StateVerifierRefusalError('consumedState');
        }
        const capabilityEnd =
            this.#capabilityPointer + stateVerifierCapabilityByteLength;
        if (
            capabilityEnd < this.#capabilityPointer ||
            capabilityEnd > this.#context.memory.buffer.byteLength
        ) {
            throw new StateVerifierInternalError(
                'The retained state-verifier capability is outside WASM memory.',
            );
        }
        const capability = new Uint8Array(
            this.#context.memory.buffer,
            this.#capabilityPointer,
            stateVerifierCapabilityByteLength,
        ).slice();
        try {
            return concatenateBytes(encodeUnsigned32(this.#handle), capability);
        } finally {
            capability.fill(0);
        }
    }

    #stateProducerInput(...parts: readonly Uint8Array[]): Uint8Array {
        const binding = this.#stateProducerSessionBinding();
        try {
            return concatenateBytes(binding, ...parts);
        } finally {
            binding.fill(0);
        }
    }

    #runStateProducerCommand(
        command: number,
        input: Uint8Array,
        operationName: string,
    ): Uint8Array {
        return this.#context.runExclusive(
            `state producer: ${operationName}`,
            () => {
                let inputPointer = 0;
                let metadataPointer = 0;
                let outputPointer = 0;
                let outputByteLength = 0;
                try {
                    const inputRefusal = requireCopiedBytes(input);
                    if (inputRefusal !== undefined) {
                        throw new StateVerifierRefusalError(inputRefusal);
                    }
                    inputPointer = allocateAndCopy(this.#context, input);
                    metadataPointer = allocateZeroed(
                        this.#context,
                        2 * wasm32WordByteLength,
                    );
                    outputPointer = this.#context.producerCommand(
                        command,
                        inputPointer,
                        input.byteLength,
                        metadataPointer,
                        metadataPointer + wasm32WordByteLength,
                    );
                    const metadata = new DataView(
                        this.#context.memory.buffer,
                        metadataPointer,
                        2 * wasm32WordByteLength,
                    );
                    const status = metadata.getUint32(0, true);
                    outputByteLength = metadata.getUint32(
                        wasm32WordByteLength,
                        true,
                    );
                    const refusalReason = decodeStatus(status);
                    if (refusalReason !== undefined) {
                        if (outputPointer !== 0 || outputByteLength !== 0) {
                            throw new StateVerifierInternalError(
                                'The WASM state producer returned output with a refusal.',
                            );
                        }
                        throw new StateVerifierRefusalError(refusalReason);
                    }
                    if (
                        outputByteLength >
                            foundationProfile.maximumCopiedBufferByteLength ||
                        (outputByteLength === 0) !== (outputPointer === 0) ||
                        outputPointer >
                            this.#context.memory.buffer.byteLength -
                                outputByteLength
                    ) {
                        throw new StateVerifierInternalError(
                            'The WASM state producer returned invalid output metadata.',
                        );
                    }
                    return outputByteLength === 0
                        ? new Uint8Array(0)
                        : new Uint8Array(
                              this.#context.memory.buffer,
                              outputPointer,
                              outputByteLength,
                          ).slice();
                } catch (error) {
                    if (
                        error instanceof StateVerifierRefusalError ||
                        error instanceof StateVerifierInternalError
                    ) {
                        throw error;
                    }
                    throw new StateVerifierInternalError(
                        `The WASM kernel failed to ${operationName}.`,
                        error,
                    );
                } finally {
                    input.fill(0);
                    if (
                        outputPointer !== 0 &&
                        outputByteLength > 0 &&
                        outputPointer <=
                            this.#context.memory.buffer.byteLength -
                                outputByteLength
                    ) {
                        zeroMemory(
                            this.#context,
                            outputPointer,
                            outputByteLength,
                        );
                        this.#context.deallocate(
                            outputPointer,
                            outputByteLength,
                        );
                    }
                    if (metadataPointer !== 0) {
                        zeroMemory(
                            this.#context,
                            metadataPointer,
                            2 * wasm32WordByteLength,
                        );
                        this.#context.deallocate(
                            metadataPointer,
                            2 * wasm32WordByteLength,
                        );
                    }
                    if (inputPointer !== 0) {
                        zeroMemory(
                            this.#context,
                            inputPointer,
                            input.byteLength,
                        );
                        this.#context.deallocate(
                            inputPointer,
                            input.byteLength,
                        );
                    }
                }
            },
        );
    }

    #releaseKernelHandle(handle: number): void {
        const status = this.#context.runExclusive(
            'state producer handle release',
            () =>
                this.#context.release(
                    this.#handle,
                    this.#capabilityPointer,
                    stateVerifierCapabilityByteLength,
                    handle,
                ),
        );
        const refusalReason = decodeStatus(status);
        if (refusalReason !== undefined) {
            throw new StateVerifierRefusalError(refusalReason);
        }
    }

    #releaseUnregisteredKernelHandle(
        handle: number,
        operationFailure: unknown,
    ): never {
        try {
            this.#releaseKernelHandle(handle);
        } catch (cleanupFailure) {
            throw new StateVerifierInternalError(
                'The state producer operation and unregistered-handle cleanup both failed.',
                Object.freeze({ cleanupFailure, operationFailure }),
            );
        }
        throw operationFailure;
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

const requireWorkerProducerSession = (
    session: StateVerifierSession,
): StateVerifierWorkerProducerSession => {
    if (!(session instanceof StateVerifierSessionImplementation)) {
        throw new TypeError(
            'The state-verifier session was not issued by this WASM runtime.',
        );
    }
    return session;
};

/** Package-internal bridge used only by the worker-owned storage kernel. */
export const produceSetupActionRandomnessReservationIntentFromRetainedKernelHandle =
    (input: {
        actionRandomnessHandle: number;
        session: StateVerifierSession;
        signatureOperation: StateObjectSignatureOperation;
    }): VerificationResult<ProducedStateReservationIntent> =>
        requireWorkerProducerSession(
            input.session,
        ).produceSetupActionRandomnessReservationIntent(input);

/** Package-internal bridge used only by a participant's custody worker. */
export const constructVerifiedStateWitnessVoteCarrierForWorker = (input: {
    session: StateVerifierSession;
    signatureOperation: StateObjectSignatureOperation;
    verifiedIntent: VerifiedStateReservationIntent;
    witnessParticipantIdentity: Uint8Array;
}): VerificationResult<Uint8Array> =>
    requireWorkerProducerSession(
        input.session,
    ).constructVerifiedStateWitnessVoteCarrier(input);

export const openStateVerifierSession = (input: {
    readonly configuration: StateVerifierSessionInput;
    readonly kernel: TranscriptCoreKernel;
}): VerificationResult<StateVerifierSession> => {
    const context = resolveStateVerifierKernelContext(input.kernel);
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
