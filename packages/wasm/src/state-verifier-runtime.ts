import type {
    RefusalReason,
    StateCapabilityKind,
    VerificationResult,
} from '@sealed-lattice/types';
import {
    foundationProfile,
    refusalReasonCodes,
    stateCapabilityKinds,
} from '@sealed-lattice/types';

import {
    CanonicalStreamRefusalError,
    CanonicalStreamResourceError,
    canonicalStreamDomains,
    openCanonicalStreamVerifierForAtomicFinish,
    type CanonicalStreamDomain,
    type CanonicalStreamVerifierLease,
} from './canonical-stream-runtime.js';
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
    deallocate(pointer: number, length: number): void;
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
        streamCapabilityPointer: number,
        streamCapabilityLength: number,
        verifiedReservationHandle: number,
        canonicalOutputIntentCarrierPointer: number,
        canonicalOutputIntentCarrierLength: number,
        canonicalStateCertificatePointer: number,
        canonicalStateCertificateLength: number,
        statusPointer: number,
    ): number;
    verifyRecovery(
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        subjectParticipantIdentityPointer: number,
        subjectParticipantIdentityLength: number,
        capabilityKindCode: number,
        predecessorRecoveryHandle: number,
        preservedIntentHandle: number,
        canonicalRecoveryTransitionCarrierPointer: number,
        canonicalRecoveryTransitionCarrierLength: number,
        canonicalStateCertificatePointer: number,
        canonicalStateCertificateLength: number,
        statusPointer: number,
    ): number;
    verifyReservation(
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        subjectParticipantIdentityPointer: number,
        subjectParticipantIdentityLength: number,
        capabilityKindCode: number,
        predecessorRecoveryHandle: number,
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
const stateIdentityByteLength = 64;
const stateHashByteLength = 64;
const wasm32WordByteLength = 4;
const maximumWasm32UnsignedInteger = 0xffff_ffff;
const fixedConfigurationByteLength = 2 + 3 * stateHashByteLength + 2 + 4;

export { stateCapabilityKinds };
export type { StateCapabilityKind };

type StateOutputCapabilityKind =
    | typeof stateCapabilityKinds.ballotCandidateList
    | typeof stateCapabilityKinds.finalitySignature
    | typeof stateCapabilityKinds.targetRelease;

declare const verifiedStateReservationBrand: unique symbol;
declare const verifiedStateOutputBrand: unique symbol;
declare const verifiedStateRecoveryBrand: unique symbol;

export type VerifiedStateReservation = Readonly<{
    readonly [verifiedStateReservationBrand]: true;
}>;

export type VerifiedStateOutput = Readonly<{
    readonly [verifiedStateOutputBrand]: true;
}>;

export type VerifiedStateRecovery = Readonly<{
    readonly [verifiedStateRecoveryBrand]: true;
}>;

export type StateVerifierSessionInput = Readonly<{
    actionContextHash: Uint8Array;
    canonicalRosterBytes: Uint8Array;
    ceremonyContextHash: Uint8Array;
    maximumRecoveryTransitionsPerStateKey: number;
    suiteIdentifier: Uint8Array;
}>;

export type StateReservationVerification = Readonly<{
    canonicalReservationIntentCarrier: Uint8Array;
    canonicalStateCertificate: Uint8Array;
    capabilityKind: StateCapabilityKind;
    expectedAuthorizationHash: Uint8Array;
    subjectParticipantIdentity: Uint8Array;
    verifiedPredecessorRecovery?: VerifiedStateRecovery;
}>;

export type StateOutputVerification = Readonly<{
    canonicalOutputIntentCarrier: Uint8Array;
    canonicalStateCertificate: Uint8Array;
    exactOutputDescriptorBytes: Uint8Array;
    verifiedReservation: VerifiedStateReservation;
}>;

export type StateRecoveryVerification = Readonly<{
    canonicalRecoveryTransitionCarrier: Uint8Array;
    canonicalStateCertificate: Uint8Array;
    capabilityKind: StateCapabilityKind;
    preservedStateIntent?: VerifiedStateOutput | VerifiedStateReservation;
    subjectParticipantIdentity: Uint8Array;
    verifiedPredecessorRecovery?: VerifiedStateRecovery;
}>;

export type StateOutputVerificationLeaseState =
    | 'active'
    | 'cancelled'
    | 'completed'
    | 'failed';

export type StateOutputVerificationLease = Readonly<{
    readonly chunkCount: number;
    readonly totalByteLength: number;
    absorbChunk(
        chunkIndex: number,
        bytes: ArrayBuffer,
    ): VerificationResult<undefined>;
    cancel(): void;
    finish(): VerificationResult<VerifiedStateOutput>;
    state(): StateOutputVerificationLeaseState;
}>;

export type StateVerifierSessionState = 'active' | 'cancelled';

export type StateVerifierSession = Readonly<{
    cancel(): void;
    openOutputVerification(
        input: StateOutputVerification,
    ): VerificationResult<StateOutputVerificationLease>;
    releaseVerifiedObject(
        verifiedObject:
            | VerifiedStateOutput
            | VerifiedStateRecovery
            | VerifiedStateReservation,
    ): VerificationResult<undefined>;
    state(): StateVerifierSessionState;
    verifyRecovery(
        input: StateRecoveryVerification,
    ): VerificationResult<VerifiedStateRecovery>;
    verifyReservation(
        input: StateReservationVerification,
    ): VerificationResult<VerifiedStateReservation>;
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

type VerifiedObjectKind = 'output' | 'recovery' | 'reservation';

type VerifiedObjectRecord = {
    active: boolean;
    activeOutputLeaseCount: number;
    capabilityKind: StateCapabilityKind;
    handle: number;
    kind: VerifiedObjectKind;
    session: StateVerifierSessionImplementation;
};

const verifiedObjectRecords = new WeakMap<object, VerifiedObjectRecord>();

const refusalReasonByCode = new Map<number, RefusalReason>(
    Object.entries(refusalReasonCodes).map(([reason, code]) => [
        code,
        reason as RefusalReason,
    ]),
);

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
    value === stateCapabilityKinds.ballotCandidateList ||
    value === stateCapabilityKinds.finalitySignature ||
    value === stateCapabilityKinds.targetRelease ||
    value === stateCapabilityKinds.setupActionRandomnessRoot ||
    value === stateCapabilityKinds.setupPublicSeedBranch ||
    value === stateCapabilityKinds.setupDealerSetBranch ||
    value === stateCapabilityKinds.setupRelinearizationRoundOneBranch ||
    value === stateCapabilityKinds.setupTerminalPackage;

const isStateOutputCapabilityKind = (
    value: StateCapabilityKind,
): value is StateOutputCapabilityKind =>
    value === stateCapabilityKinds.ballotCandidateList ||
    value === stateCapabilityKinds.finalitySignature ||
    value === stateCapabilityKinds.targetRelease;

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
    if (
        !Number.isSafeInteger(input.maximumRecoveryTransitionsPerStateKey) ||
        input.maximumRecoveryTransitionsPerStateKey <= 0 ||
        input.maximumRecoveryTransitionsPerStateKey > 0xffff
    ) {
        throw new StateVerifierRefusalError('outsideSupportedProfile');
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
    view.setUint16(offset, input.maximumRecoveryTransitionsPerStateKey, true);
    offset += 2;
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
        case stateCapabilityKinds.ballotCandidateList:
            return canonicalStreamDomains.stateBallotCandidateListExactOutput;
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

class StateOutputVerificationLeaseImplementation implements StateOutputVerificationLease {
    readonly #streamLease: CanonicalStreamVerifierLease;
    readonly #finishResult: () =>
        | VerificationResult<VerifiedStateOutput>
        | undefined;
    readonly #onTerminal: () => void;
    #state: StateOutputVerificationLeaseState = 'active';

    public constructor(
        streamLease: CanonicalStreamVerifierLease,
        finishResult: () => VerificationResult<VerifiedStateOutput> | undefined,
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
            if (refusalReason === undefined) {
                throw error;
            }
            this.#state = 'failed';
            this.#onTerminal();
            return refused(refusalReason);
        }
    }

    public cancel(): void {
        if (this.#state !== 'active') {
            return;
        }
        this.#streamLease.cancel();
        this.#state = 'cancelled';
        this.#onTerminal();
    }

    public finish(): VerificationResult<VerifiedStateOutput> {
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
            this.#state = 'completed';
            this.#onTerminal();
            return result;
        } catch (error) {
            const refusalReason = canonicalStreamRefusalReason(error);
            this.#state = 'failed';
            this.#onTerminal();
            if (refusalReason !== undefined) {
                return refused(refusalReason);
            }
            throw error;
        }
    }

    public state(): StateOutputVerificationLeaseState {
        return this.#state;
    }
}

class StateVerifierSessionImplementation implements StateVerifierSession {
    readonly #context: StateVerifierKernelContext;
    readonly #kernel: TranscriptCoreKernel;
    readonly #handle: number;
    readonly #verifiedObjectRecords = new Set<VerifiedObjectRecord>();
    readonly #outputLeases =
        new Set<StateOutputVerificationLeaseImplementation>();
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
        let predecessorHandle = 0;
        if (input.verifiedPredecessorRecovery !== undefined) {
            const resolved = resolveVerifiedObject(
                input.verifiedPredecessorRecovery,
                this,
                ['recovery'],
            );
            if ('refusalReason' in resolved) {
                return refused(resolved.refusalReason);
            }
            predecessorHandle = resolved.record.handle;
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
                    predecessorHandle,
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
        let outputLease: StateOutputVerificationLeaseImplementation | undefined;
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

    public verifyRecovery(
        input: StateRecoveryVerification,
    ): VerificationResult<VerifiedStateRecovery> {
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
            [input.canonicalRecoveryTransitionCarrier, undefined],
            [input.canonicalStateCertificate, undefined],
        ] as const) {
            const refusalReason = requireCopiedBytes(bytes, expectedByteLength);
            if (refusalReason !== undefined) {
                return refused(refusalReason);
            }
        }
        let predecessorHandle = 0;
        if (input.verifiedPredecessorRecovery !== undefined) {
            const resolved = resolveVerifiedObject(
                input.verifiedPredecessorRecovery,
                this,
                ['recovery'],
            );
            if ('refusalReason' in resolved) {
                return refused(resolved.refusalReason);
            }
            predecessorHandle = resolved.record.handle;
        }
        let preservedIntentHandle = 0;
        if (input.preservedStateIntent !== undefined) {
            const resolved = resolveVerifiedObject(
                input.preservedStateIntent,
                this,
                ['reservation', 'output'],
            );
            if ('refusalReason' in resolved) {
                return refused(resolved.refusalReason);
            }
            preservedIntentHandle = resolved.record.handle;
        }

        return this.#runHandleVerification(
            'state recovery verification',
            [
                input.subjectParticipantIdentity,
                input.canonicalRecoveryTransitionCarrier,
                input.canonicalStateCertificate,
            ],
            (pointers, statusPointer) =>
                this.#context.verifyRecovery(
                    this.#handle,
                    this.#capabilityPointer,
                    stateVerifierCapabilityByteLength,
                    pointers[0],
                    input.subjectParticipantIdentity.byteLength,
                    input.capabilityKind,
                    predecessorHandle,
                    preservedIntentHandle,
                    pointers[1],
                    input.canonicalRecoveryTransitionCarrier.byteLength,
                    pointers[2],
                    input.canonicalStateCertificate.byteLength,
                    statusPointer,
                ),
            (handle) =>
                this.#issueVerifiedObject<VerifiedStateRecovery>(
                    handle,
                    'recovery',
                    input.capabilityKind,
                ),
        );
    }

    public releaseVerifiedObject(
        verifiedObject:
            | VerifiedStateOutput
            | VerifiedStateRecovery
            | VerifiedStateReservation,
    ): VerificationResult<undefined> {
        if (this.#state !== 'active') {
            return refused('consumedState');
        }
        const resolved = resolveVerifiedObject(verifiedObject, this, [
            'reservation',
            'output',
            'recovery',
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

    #finishOutput(
        reservationRecord: VerifiedObjectRecord,
        outputIntentCarrier: Uint8Array,
        stateCertificate: Uint8Array,
        stream: Readonly<{
            streamCapabilityLength: number;
            streamCapabilityPointer: number;
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
                    stream.streamCapabilityPointer,
                    stream.streamCapabilityLength,
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
