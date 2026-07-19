import { foundationProfile, type RefusalReason } from '@sealed-lattice/types';

import { isArrayBuffer } from './byte-array.js';
import { pumpCanonicalStreamChunks } from './canonical-stream-chunk-pump.js';
import type { TranscriptCoreKernelContextOwner } from './transcript-core-bridge/kernel-types.js';
import { WasmMemoryBoundary } from './wasm-memory-boundary.js';
import { WasmStatusBoundary } from './wasm-status-boundary.js';

const maximumCanonicalStreamChunkCount = Math.ceil(
    foundationProfile.maximumCanonicalStreamByteLength /
        foundationProfile.streamChunkByteLength,
);
const canonicalStreamDescriptorFixedByteLength = 104;
const maximumCanonicalStreamDescriptorByteLength =
    canonicalStreamDescriptorFixedByteLength +
    64 * maximumCanonicalStreamChunkCount;
const wasm32WordByteLength = 4;
const canonicalStreamLeaseIdentifierByteLength = 32;

export const deriveCanonicalStreamChunkCount = (
    totalByteLength: number,
): number =>
    Math.ceil(totalByteLength / foundationProfile.streamChunkByteLength);

export const canonicalStreamDomains = Object.freeze({
    privateMailboxCiphertext: 1,
    dealerVssShareLinkageProof: 2,
    recipientAggregateThresholdShareProof: 3,
    sameSecretProof: 4,
    publicKeyShareProof: 5,
    collectivePublicKeyAggregateProof: 6,
    rkgRoundOneProof: 7,
    rkgRoundOneAggregateProof: 8,
    rkgRoundTwoProof: 9,
    galoisShareProof: 10,
    evaluatorKeyAggregateProof: 11,
    collectivePublicKey: 12,
    evaluatorKeyStore: 13,
    ballotCiphertext: 14,
    ballotValidityProof: 15,
    aggregateCiphertext: 16,
    replayTargetIdentifierCiphertext: 17,
    replayTargetOrderCiphertext: 18,
    targetIdentifierPartialDecryption: 19,
    targetOrderPartialDecryption: 20,
    maliciousTargetShareProof: 21,
    checkpointState: 22,
    stateFinalitySignatureExactOutput: 24,
    stateTargetReleaseExactOutput: 25,
    publicKeyShareMaterial: 26,
} as const);

export type CanonicalStreamDomain =
    (typeof canonicalStreamDomains)[keyof typeof canonicalStreamDomains];

export type CanonicalStreamLeaseState =
    | 'active'
    | 'cancelled'
    | 'completed'
    | 'failed';

export class CanonicalStreamRefusalError extends Error {
    public readonly refusalReason: RefusalReason;

    public constructor(refusalReason: RefusalReason) {
        super(`The canonical stream was refused: ${refusalReason}.`);
        this.name = 'CanonicalStreamRefusalError';
        this.refusalReason = refusalReason;
    }
}

export class CanonicalStreamResourceError extends Error {
    public readonly refusalReason = 'outsideSupportedProfile' as const;

    public constructor(
        message = 'The canonical stream exceeds an absolute runtime safety bound.',
    ) {
        super(message);
        this.name = 'CanonicalStreamResourceError';
    }
}

export class CanonicalStreamInternalError extends Error {
    public readonly failureCause: unknown;

    public constructor(message: string, failureCause?: unknown) {
        super(message);
        this.name = 'CanonicalStreamInternalError';
        this.failureCause = failureCause;
    }
}

export class CanonicalStreamCancellationError extends Error {
    public constructor() {
        super('The canonical stream operation was cancelled.');
        this.name = 'CanonicalStreamCancellationError';
    }
}

export class CanonicalStreamCleanupError extends Error {
    public readonly cleanupFailure: unknown;
    public readonly operationFailure: unknown;

    public constructor(operationFailure: unknown, cleanupFailure: unknown) {
        super('The canonical stream operation and its cleanup both failed.');
        this.name = 'CanonicalStreamCleanupError';
        this.operationFailure = operationFailure;
        this.cleanupFailure = cleanupFailure;
    }
}

export type CanonicalStreamRuntimeCounterSnapshot = Readonly<{
    absorbedPayloadByteLength: number;
    absorbedPayloadChunkCount: number;
    activeSessionCount: number;
    cancelledSessionCount: number;
    completedSessionCount: number;
    failedSessionCount: number;
    javascriptToWasmPayloadCopyCount: number;
    maximumObservedCopiedPayloadByteLength: number;
    maximumObservedWasmMemoryByteLength: number;
    startedSessionCount: number;
    wasmToJavascriptPayloadCopyCount: number;
}>;

export type CanonicalStreamChunkPull = (input: {
    readonly abortSignal?: AbortSignal;
    readonly chunkIndex: number;
    readonly expectedByteLength: number;
}) => Promise<ArrayBuffer | undefined>;

/**
 * Consumes one runtime-owned chunk. The `bytes` buffer remains valid only until
 * the returned promise settles and is then zeroed. A consumer that needs to
 * retain the chunk must copy it before resolving.
 */
export type CanonicalStreamChunkSink = (input: {
    readonly abortSignal?: AbortSignal;
    readonly bytes: ArrayBuffer;
    readonly chunkIndex: number;
}) => Promise<void>;

export type CanonicalStreamWriterLease = Readonly<{
    readonly chunkCount: number;
    readonly totalByteLength: number;
    absorbChunk(chunkIndex: number, bytes: ArrayBuffer): void;
    cancel(): void;
    finish(): Uint8Array;
    state(): CanonicalStreamLeaseState;
}>;

export type CanonicalStreamVerifierLease = Readonly<{
    readonly chunkCount: number;
    readonly totalByteLength: number;
    absorbChunk(chunkIndex: number, bytes: ArrayBuffer): void;
    cancel(): void;
    finish(): void;
    state(): CanonicalStreamLeaseState;
}>;

export type CanonicalStreamWorkerRuntime = Readonly<{
    counterSnapshot(): CanonicalStreamRuntimeCounterSnapshot;
    openVerifier(input: {
        readonly descriptorBytes: Uint8Array;
        readonly streamDomain: CanonicalStreamDomain;
    }): CanonicalStreamVerifierLease;
    openWriter(input: {
        readonly streamDomain: CanonicalStreamDomain;
        readonly totalByteLength: number;
    }): CanonicalStreamWriterLease;
    read(input: {
        readonly abortSignal?: AbortSignal;
        readonly consumeVerifiedChunk: CanonicalStreamChunkSink;
        readonly descriptorBytes: Uint8Array;
        readonly pullChunk: CanonicalStreamChunkPull;
        readonly streamDomain: CanonicalStreamDomain;
    }): Promise<void>;
    write(input: {
        readonly abortSignal?: AbortSignal;
        readonly emitChunk: CanonicalStreamChunkSink;
        readonly pullChunk: CanonicalStreamChunkPull;
        readonly streamDomain: CanonicalStreamDomain;
        readonly totalByteLength: number;
    }): Promise<Uint8Array>;
}>;

type CanonicalStreamKernelContext = Readonly<{
    aggregateThresholdShareBeginRecipientAuthority?: (
        actionRandomnessHandle: number,
        localRecipientRosterPosition: number,
        boardVerifierSessionHandle: number,
        boardVerifierSessionCapabilityPointer: number,
        boardVerifierSessionCapabilityByteLength: number,
        orderedPublicRandomnessHandleBytesPointer: number,
        orderedPublicRandomnessHandleBytesByteLength: number,
        orderedDealerTerminalHandleBytesPointer: number,
        orderedDealerTerminalHandleBytesByteLength: number,
        statusPointer: number,
    ) => number;
    aggregateThresholdShareAbsorbAuthenticatedRecipientPayload?: (
        recipientAuthorityHandle: number,
        authenticatedPlaintextCapabilityHandle: number,
        canonicalSignedEnvelopePointer: number,
        canonicalSignedEnvelopeLength: number,
        canonicalPlaintextPointer: number,
        canonicalPlaintextLength: number,
    ) => number;
    aggregateThresholdShareDiscardRecipientAuthority?: (
        recipientAuthorityHandle: number,
    ) => number;
    allocate(length: number): number;
    beginVerifier(
        streamDomain: number,
        descriptorPointer: number,
        descriptorLength: number,
        statusPointer: number,
        totalByteLengthPointer: number,
    ): number;
    beginWriter(
        streamDomain: number,
        totalByteLength: number,
        statusPointer: number,
    ): number;
    cancel(handle: number): number;
    deallocate(pointer: number, length: number): void;
    absorbChunk(
        handle: number,
        chunkIndex: number,
        chunkPointer: number,
        chunkLength: number,
    ): number;
    finishVerifier(handle: number): number;
    finishWriter(
        handle: number,
        statusPointer: number,
        outputLengthPointer: number,
    ): number;
    memory: WebAssembly.Memory;
    mailboxGcmAuthenticateChunk?: (
        handle: number,
        chunkPointer: number,
        chunkLength: number,
    ) => number;
    mailboxGcmBeginEncryptor?: (
        keyPointer: number,
        keyLength: number,
        noncePointer: number,
        nonceLength: number,
        associatedDataPointer: number,
        associatedDataLength: number,
        totalByteLength: number,
        statusPointer: number,
    ) => number;
    mailboxGcmBeginVerifier?: (
        keyPointer: number,
        keyLength: number,
        noncePointer: number,
        nonceLength: number,
        associatedDataPointer: number,
        associatedDataLength: number,
        totalByteLength: number,
        statusPointer: number,
    ) => number;
    mailboxGcmCancel?: (handle: number) => number;
    mailboxGcmDecryptChunk?: (
        handle: number,
        chunkPointer: number,
        chunkLength: number,
    ) => number;
    mailboxGcmEncryptChunk?: (
        handle: number,
        chunkPointer: number,
        chunkLength: number,
    ) => number;
    mailboxGcmFinishAuthentication?: (
        handle: number,
        tagPointer: number,
        tagLength: number,
    ) => number;
    mailboxGcmFinishDecryptor?: (handle: number) => number;
    mailboxGcmFinishEncryptor?: (
        handle: number,
        tagPointer: number,
        tagLength: number,
    ) => number;
    setupGenerationAuthorityBegin?: (
        selectedSuiteHandle: number,
        boardVerifierSessionHandle: number,
        boardVerifierSessionCapabilityPointer: number,
        boardVerifierSessionCapabilityByteLength: number,
        orderedPublicRandomnessObjectHandlesPointer: number,
        orderedPublicRandomnessObjectHandlesByteLength: number,
        actionRandomnessHandle: number,
        stateVerifierSessionHandle: number,
        stateVerifierSessionCapabilityPointer: number,
        stateVerifierSessionCapabilityByteLength: number,
        verifiedReservationHandle: number,
        statusPointer: number,
    ) => number;
    setupGenerationAuthorityRelease?: (authorityHandle: number) => number;
    setupGenerationPublicKeyShareBodyByteLength?: (
        authorityHandle: number,
        statusPointer: number,
    ) => bigint;
    setupGenerationPublicKeyShareBodyOpen?: (
        authorityHandle: number,
        statusPointer: number,
    ) => number;
    setupGenerationPublicKeyShareSourceByteLength?: (
        sourceHandle: number,
        statusPointer: number,
    ) => bigint;
    setupGenerationPublicKeyShareBodyRead?: (
        sourceHandle: number,
        expectedOffset: bigint,
        outputPointer: number,
        outputByteLength: number,
    ) => number;
    setupGenerationPublicKeyShareBodyCancel?: (sourceHandle: number) => number;
    setupGenerationRecipientVssPayloadByteLength?: (
        authorityHandle: number,
        recipientRosterPosition: number,
        statusPointer: number,
    ) => bigint;
    setupGenerationRecipientVssPayloadOpen?: (
        authorityHandle: number,
        recipientRosterPosition: number,
        statusPointer: number,
    ) => number;
    setupGenerationRecipientVssPayloadSourceByteLength?: (
        sourceHandle: number,
        statusPointer: number,
    ) => bigint;
    setupGenerationRecipientVssPayloadSourceRecipientRosterPosition?: (
        sourceHandle: number,
        statusPointer: number,
    ) => number;
    setupGenerationRecipientVssPayloadRead?: (
        sourceHandle: number,
        expectedOffset: bigint,
        outputPointer: number,
        outputByteLength: number,
    ) => number;
    setupGenerationRecipientVssPayloadCancel?: (sourceHandle: number) => number;
    runExclusive<Result>(
        operationName: string,
        operation: () => Result,
    ): Result;
}>;

type CanonicalStreamAtomicVerifierFinish = (input: {
    readonly streamHandle: number;
}) => void;

const contexts = new WeakMap<
    TranscriptCoreKernelContextOwner,
    CanonicalStreamKernelContext
>();
const workerRuntimes = new WeakMap<
    TranscriptCoreKernelContextOwner,
    CanonicalStreamWorkerRuntimeImplementation
>();

export const registerCanonicalStreamKernelContext = (
    kernel: TranscriptCoreKernelContextOwner,
    context: CanonicalStreamKernelContext,
): void => {
    workerRuntimes.get(kernel)?.invalidate();
    contexts.set(kernel, context);
    workerRuntimes.delete(kernel);
};

export const canonicalStreamKernelContext = (
    kernel: TranscriptCoreKernelContextOwner,
): CanonicalStreamKernelContext | undefined => contexts.get(kernel);

type MutableCounters = {
    -readonly [CounterName in keyof CanonicalStreamRuntimeCounterSnapshot]: CanonicalStreamRuntimeCounterSnapshot[CounterName];
};

type ActiveLease = {
    atomicVerifierFinish?: CanonicalStreamAtomicVerifierFinish;
    authorityContext: CanonicalStreamKernelContext;
    authorityOwner: TranscriptCoreKernelContextOwner;
    chunkCount: number;
    handle: number;
    identifier: string;
    kind: 'verifier' | 'writer';
    state: CanonicalStreamLeaseState;
    totalByteLength: number;
};

const canonicalStreamDomainCodes = new Set<number>(
    Object.values(canonicalStreamDomains),
);

const isCanonicalStreamDomain = (
    value: number,
): value is CanonicalStreamDomain =>
    Number.isSafeInteger(value) && canonicalStreamDomainCodes.has(value);

const assertSafeNonNegativeInteger = (value: number, label: string): void => {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    if (value > 0xffff_ffff) {
        throw new CanonicalStreamResourceError(
            `${label} exceeds the WASM32 boundary.`,
        );
    }
};

class CanonicalStreamWorkerRuntimeImplementation implements CanonicalStreamWorkerRuntime {
    readonly #authorityOwner: TranscriptCoreKernelContextOwner;
    readonly #context: CanonicalStreamKernelContext;
    readonly #counters: MutableCounters;
    readonly #memoryBoundary: WasmMemoryBoundary;
    readonly #statusBoundary: WasmStatusBoundary;
    readonly #issuedLeaseIdentifiers = new Set<string>();
    readonly #leaseAuthorities = new Map<string, ActiveLease>();
    #activeLease: ActiveLease | undefined;
    #invalidated = false;

    public constructor(
        authorityOwner: TranscriptCoreKernelContextOwner,
        context: CanonicalStreamKernelContext,
    ) {
        this.#authorityOwner = authorityOwner;
        this.#context = context;
        this.#counters = {
            absorbedPayloadByteLength: 0,
            absorbedPayloadChunkCount: 0,
            activeSessionCount: 0,
            cancelledSessionCount: 0,
            completedSessionCount: 0,
            failedSessionCount: 0,
            javascriptToWasmPayloadCopyCount: 0,
            maximumObservedCopiedPayloadByteLength: 0,
            maximumObservedWasmMemoryByteLength:
                context.memory.buffer.byteLength,
            startedSessionCount: 0,
            wasmToJavascriptPayloadCopyCount: 0,
        };
        this.#memoryBoundary = new WasmMemoryBoundary({
            context,
            createInternalError: (message) =>
                new CanonicalStreamInternalError(message),
            createResourceError: (message) =>
                new CanonicalStreamResourceError(message),
            label: 'canonical stream',
            observeMemoryByteLength: (byteLength) => {
                this.#counters.maximumObservedWasmMemoryByteLength = Math.max(
                    this.#counters.maximumObservedWasmMemoryByteLength,
                    byteLength,
                );
            },
        });
        this.#statusBoundary = new WasmStatusBoundary({
            createInternalError: (message) =>
                new CanonicalStreamInternalError(message),
            createRefusalError: (refusalReason) =>
                new CanonicalStreamRefusalError(refusalReason),
            createResourceError: () => new CanonicalStreamResourceError(),
            internalFailureMessage:
                'The WASM canonical stream session failed internally.',
            unknownStatusMessage:
                'The WASM canonical stream returned an unknown status code.',
        });
    }

    public counterSnapshot(): CanonicalStreamRuntimeCounterSnapshot {
        return Object.freeze({ ...this.#counters });
    }

    public invalidate(): void {
        if (this.#invalidated) {
            return;
        }
        this.#invalidated = true;
        const activeLease = this.#activeLease;
        if (activeLease !== undefined) {
            this.#cancelLease(activeLease);
        }
    }

    public openWriter(input: {
        readonly streamDomain: CanonicalStreamDomain;
        readonly totalByteLength: number;
    }): CanonicalStreamWriterLease {
        this.#prepareBegin(input.streamDomain);
        assertSafeNonNegativeInteger(
            input.totalByteLength,
            'canonical stream byte length',
        );
        if (
            input.totalByteLength >
            foundationProfile.maximumCanonicalStreamByteLength
        ) {
            throw new CanonicalStreamResourceError();
        }
        const leaseIdentifier = this.#issueLeaseIdentifier();
        let handle = 0;
        let metadataPointer = 0;
        try {
            metadataPointer = this.#allocateMetadata(1);
            handle = this.#context.runExclusive('canonical stream begin', () =>
                this.#context.beginWriter(
                    input.streamDomain,
                    input.totalByteLength,
                    metadataPointer,
                ),
            );
            const [status] = this.#readWords(metadataPointer, 1);
            this.#statusBoundary.throwIfError(status);
            if (handle === 0) {
                throw new CanonicalStreamInternalError(
                    'The WASM stream writer returned malformed begin metadata.',
                );
            }
            const lease: ActiveLease = {
                authorityContext: this.#context,
                authorityOwner: this.#authorityOwner,
                chunkCount: deriveCanonicalStreamChunkCount(
                    input.totalByteLength,
                ),
                handle,
                identifier: leaseIdentifier,
                kind: 'writer',
                state: 'active',
                totalByteLength: input.totalByteLength,
            };
            this.#activate(lease);
            return this.#writerLease(lease);
        } catch (error) {
            return this.#throwAfterUnactivatedBeginFailure(handle, error);
        } finally {
            if (metadataPointer !== 0) {
                this.#context.deallocate(metadataPointer, wasm32WordByteLength);
            }
        }
    }

    public openVerifier(
        input: {
            readonly descriptorBytes: Uint8Array;
            readonly streamDomain: CanonicalStreamDomain;
        },
        atomicVerifierFinish?: CanonicalStreamAtomicVerifierFinish,
    ): CanonicalStreamVerifierLease {
        this.#prepareBegin(input.streamDomain);
        if (
            !ArrayBuffer.isView(input.descriptorBytes) ||
            Object.prototype.toString.call(input.descriptorBytes) !==
                '[object Uint8Array]'
        ) {
            throw new CanonicalStreamRefusalError('wrongTypeOrLength');
        }
        if (
            input.descriptorBytes.byteLength === 0 ||
            input.descriptorBytes.byteLength >
                maximumCanonicalStreamDescriptorByteLength
        ) {
            throw new CanonicalStreamResourceError(
                'The canonical stream descriptor exceeds its binary metadata bound.',
            );
        }
        const leaseIdentifier = this.#issueLeaseIdentifier();
        let descriptorPointer = 0;
        let handle = 0;
        let metadataPointer = 0;
        try {
            metadataPointer = this.#allocateMetadata(2);
            descriptorPointer = this.#copyMetadataIntoWasm(
                input.descriptorBytes,
            );
            handle = this.#context.runExclusive('canonical stream begin', () =>
                this.#context.beginVerifier(
                    input.streamDomain,
                    descriptorPointer,
                    input.descriptorBytes.byteLength,
                    metadataPointer,
                    metadataPointer + wasm32WordByteLength,
                ),
            );
            const [status, totalByteLength] = this.#readWords(
                metadataPointer,
                2,
            );
            this.#statusBoundary.throwIfError(status);
            if (handle === 0 || totalByteLength === 0) {
                throw new CanonicalStreamInternalError(
                    'The WASM stream verifier returned malformed begin metadata.',
                );
            }
            const lease: ActiveLease = {
                ...(atomicVerifierFinish === undefined
                    ? {}
                    : { atomicVerifierFinish }),
                authorityContext: this.#context,
                authorityOwner: this.#authorityOwner,
                chunkCount: deriveCanonicalStreamChunkCount(totalByteLength),
                handle,
                identifier: leaseIdentifier,
                kind: 'verifier',
                state: 'active',
                totalByteLength,
            };
            this.#activate(lease);
            return this.#verifierLease(lease);
        } catch (error) {
            return this.#throwAfterUnactivatedBeginFailure(handle, error);
        } finally {
            if (descriptorPointer !== 0) {
                this.#context.deallocate(
                    descriptorPointer,
                    input.descriptorBytes.byteLength,
                );
            }
            if (metadataPointer !== 0) {
                this.#context.deallocate(
                    metadataPointer,
                    2 * wasm32WordByteLength,
                );
            }
        }
    }

    public async write(input: {
        readonly abortSignal?: AbortSignal;
        readonly emitChunk: CanonicalStreamChunkSink;
        readonly pullChunk: CanonicalStreamChunkPull;
        readonly streamDomain: CanonicalStreamDomain;
        readonly totalByteLength: number;
    }): Promise<Uint8Array> {
        const lease = this.openWriter(input);
        let operationFailure: unknown;
        try {
            return await pumpCanonicalStreamChunks({
                ...(input.abortSignal === undefined
                    ? {}
                    : { abortSignal: input.abortSignal }),
                consumeChunk: input.emitChunk,
                createCancellationError: () =>
                    new CanonicalStreamCancellationError(),
                lease,
                pullChunk: input.pullChunk,
            });
        } catch (error) {
            operationFailure = error;
            throw error;
        } finally {
            this.#cancelAfterOperation(lease, operationFailure);
        }
    }

    public async read(input: {
        readonly abortSignal?: AbortSignal;
        readonly consumeVerifiedChunk: CanonicalStreamChunkSink;
        readonly descriptorBytes: Uint8Array;
        readonly pullChunk: CanonicalStreamChunkPull;
        readonly streamDomain: CanonicalStreamDomain;
    }): Promise<void> {
        const lease = this.openVerifier(input);
        let operationFailure: unknown;
        try {
            await pumpCanonicalStreamChunks({
                ...(input.abortSignal === undefined
                    ? {}
                    : { abortSignal: input.abortSignal }),
                consumeChunk: input.consumeVerifiedChunk,
                createCancellationError: () =>
                    new CanonicalStreamCancellationError(),
                lease,
                pullChunk: input.pullChunk,
            });
        } catch (error) {
            operationFailure = error;
            throw error;
        } finally {
            this.#cancelAfterOperation(lease, operationFailure);
        }
    }

    #prepareBegin(streamDomain: number): void {
        if (this.#invalidated) {
            throw new CanonicalStreamInternalError(
                'The canonical stream worker runtime was invalidated.',
            );
        }
        if (this.#activeLease !== undefined) {
            throw new CanonicalStreamResourceError(
                'Only one canonical stream may be active in a WASM instance.',
            );
        }
        if (!isCanonicalStreamDomain(streamDomain)) {
            throw new CanonicalStreamRefusalError('malformedEncoding');
        }
    }

    #writerLease(lease: ActiveLease): CanonicalStreamWriterLease {
        return Object.freeze({
            absorbChunk: (chunkIndex: number, bytes: ArrayBuffer): void =>
                this.#absorbLeaseChunk(lease, chunkIndex, bytes),
            cancel: (): void => this.#cancelLease(lease),
            chunkCount: lease.chunkCount,
            finish: (): Uint8Array => this.#finishWriterLease(lease),
            state: (): CanonicalStreamLeaseState => lease.state,
            totalByteLength: lease.totalByteLength,
        });
    }

    #verifierLease(lease: ActiveLease): CanonicalStreamVerifierLease {
        return Object.freeze({
            absorbChunk: (chunkIndex: number, bytes: ArrayBuffer): void =>
                this.#absorbLeaseChunk(lease, chunkIndex, bytes),
            cancel: (): void => this.#cancelLease(lease),
            chunkCount: lease.chunkCount,
            finish: (): void => this.#finishVerifierLease(lease),
            state: (): CanonicalStreamLeaseState => lease.state,
            totalByteLength: lease.totalByteLength,
        });
    }

    #activate(lease: ActiveLease): void {
        if (
            lease.authorityOwner !== this.#authorityOwner ||
            lease.authorityContext !== this.#context ||
            !this.#issuedLeaseIdentifiers.has(lease.identifier) ||
            this.#leaseAuthorities.has(lease.identifier)
        ) {
            throw new CanonicalStreamInternalError(
                'The canonical stream lease authority is invalid.',
            );
        }
        this.#charge('startedSessionCount', 1);
        this.#activeLease = lease;
        this.#leaseAuthorities.set(lease.identifier, lease);
        this.#counters.activeSessionCount = 1;
    }

    #issueLeaseIdentifier(): string {
        const cryptoProvider = globalThis.crypto;
        if (
            cryptoProvider === undefined ||
            typeof cryptoProvider.getRandomValues !== 'function'
        ) {
            throw new CanonicalStreamInternalError(
                'Web Crypto getRandomValues is required for canonical stream leases.',
            );
        }
        const identifierBytes = new Uint8Array(
            new ArrayBuffer(canonicalStreamLeaseIdentifierByteLength),
        );
        try {
            try {
                cryptoProvider.getRandomValues(identifierBytes);
            } catch (error) {
                throw new CanonicalStreamInternalError(
                    'Web Crypto failed to issue a canonical stream lease identifier.',
                    error,
                );
            }
            const identifier = Array.from(identifierBytes, (byte) =>
                byte.toString(16).padStart(2, '0'),
            ).join('');
            if (this.#issuedLeaseIdentifiers.has(identifier)) {
                throw new CanonicalStreamInternalError(
                    'Web Crypto repeated a canonical stream lease identifier.',
                );
            }
            this.#issuedLeaseIdentifiers.add(identifier);
            return identifier;
        } finally {
            identifierBytes.fill(0);
        }
    }

    #absorbLeaseChunk(
        lease: ActiveLease,
        chunkIndex: number,
        bytes: ArrayBuffer,
    ): void {
        try {
            this.#requireActive(lease);
            assertSafeNonNegativeInteger(
                chunkIndex,
                'canonical stream chunk index',
            );
            if (!isArrayBuffer(bytes)) {
                throw new CanonicalStreamRefusalError('wrongTypeOrLength');
            }
            if (bytes.byteLength === 0) {
                throw new CanonicalStreamRefusalError('wrongTypeOrLength');
            }
            if (bytes.byteLength > foundationProfile.streamChunkByteLength) {
                throw new CanonicalStreamResourceError(
                    'A stream payload exceeds the canonical chunk bound.',
                );
            }
            const chunkPointer = this.#copyPayloadIntoWasm(bytes);
            try {
                const status = this.#context.runExclusive(
                    'canonical stream chunk',
                    () =>
                        this.#context.absorbChunk(
                            lease.handle,
                            chunkIndex,
                            chunkPointer,
                            bytes.byteLength,
                        ),
                );
                this.#statusBoundary.throwIfError(status);
                this.#charge('absorbedPayloadChunkCount', 1);
                this.#charge('absorbedPayloadByteLength', bytes.byteLength);
            } finally {
                if (chunkPointer !== 0) {
                    this.#context.deallocate(chunkPointer, bytes.byteLength);
                }
            }
        } catch (error) {
            return this.#throwAfterFailingLease(lease, error);
        }
    }

    #finishWriterLease(lease: ActiveLease): Uint8Array {
        this.#requireActive(lease);
        if (lease.kind !== 'writer') {
            return this.#throwAfterFailingLease(
                lease,
                new CanonicalStreamInternalError(
                    'A verifier lease cannot finish as a writer.',
                ),
            );
        }
        let metadataPointer = 0;
        let outputPointer = 0;
        try {
            this.#memoryBoundary.validateAllocationByteLength(
                2 * wasm32WordByteLength +
                    maximumCanonicalStreamDescriptorByteLength,
            );
            metadataPointer = this.#allocateMetadata(2);
            outputPointer = this.#context.runExclusive(
                'canonical stream writer finish',
                () =>
                    this.#context.finishWriter(
                        lease.handle,
                        metadataPointer,
                        metadataPointer + wasm32WordByteLength,
                    ),
            );
            const [status, outputLength] = this.#readWords(metadataPointer, 2);
            this.#statusBoundary.throwIfError(status);
            if (
                outputPointer === 0 ||
                outputLength === 0 ||
                outputLength > maximumCanonicalStreamDescriptorByteLength
            ) {
                throw new CanonicalStreamInternalError(
                    'The WASM stream writer returned malformed descriptor metadata.',
                );
            }
            const descriptorBytes = Uint8Array.from(
                new Uint8Array(
                    this.#context.memory.buffer,
                    outputPointer,
                    outputLength,
                ),
            );
            this.#completeLease(lease);
            return descriptorBytes;
        } catch (error) {
            return this.#throwAfterFailingLease(lease, error);
        } finally {
            if (outputPointer !== 0 && metadataPointer !== 0) {
                const outputLength = this.#readWords(metadataPointer, 2)[1];
                if (
                    outputLength > 0 &&
                    outputLength <= maximumCanonicalStreamDescriptorByteLength
                ) {
                    this.#context.deallocate(outputPointer, outputLength);
                }
            }
            if (metadataPointer !== 0) {
                this.#context.deallocate(
                    metadataPointer,
                    2 * wasm32WordByteLength,
                );
            }
        }
    }

    #finishVerifierLease(lease: ActiveLease): void {
        this.#requireActive(lease);
        if (lease.kind !== 'verifier') {
            return this.#throwAfterFailingLease(
                lease,
                new CanonicalStreamInternalError(
                    'A writer lease cannot finish as a verifier.',
                ),
            );
        }
        try {
            if (lease.atomicVerifierFinish === undefined) {
                const status = this.#context.runExclusive(
                    'canonical stream verifier finish',
                    () => this.#context.finishVerifier(lease.handle),
                );
                this.#statusBoundary.throwIfError(status);
            } else {
                lease.atomicVerifierFinish({
                    streamHandle: lease.handle,
                });
            }
            this.#completeLease(lease);
        } catch (error) {
            return this.#throwAfterFailingLease(lease, error);
        }
    }

    #cancelLease(lease: ActiveLease): void {
        if (lease.state !== 'active') {
            return;
        }
        this.#requireActive(lease);
        try {
            const status = this.#context.runExclusive(
                'canonical stream cancellation',
                () => this.#context.cancel(lease.handle),
            );
            this.#statusBoundary.throwIfError(status);
            lease.state = 'cancelled';
            this.#charge('cancelledSessionCount', 1);
            this.#releaseLease(lease);
        } catch (error) {
            this.#markLeaseFailed(lease);
            throw error;
        }
    }

    #completeLease(lease: ActiveLease): void {
        lease.state = 'completed';
        this.#charge('completedSessionCount', 1);
        this.#releaseLease(lease);
    }

    #markLeaseFailed(lease: ActiveLease): void {
        if (lease.state !== 'active') {
            return;
        }
        lease.state = 'failed';
        this.#charge('failedSessionCount', 1);
        this.#releaseLease(lease);
    }

    #throwAfterFailingLease(
        lease: ActiveLease,
        operationFailure: unknown,
    ): never {
        let cleanupFailure: unknown;
        if (lease.state === 'active') {
            try {
                const status = this.#context.runExclusive(
                    'canonical stream failure cleanup',
                    () => this.#context.cancel(lease.handle),
                );
                this.#statusBoundary.throwIfError(status);
            } catch (error) {
                cleanupFailure = error;
            }
        }
        this.#markLeaseFailed(lease);
        if (cleanupFailure !== undefined) {
            throw new CanonicalStreamCleanupError(
                operationFailure,
                cleanupFailure,
            );
        }
        throw operationFailure;
    }

    #throwAfterUnactivatedBeginFailure(
        handle: number,
        operationFailure: unknown,
    ): never {
        let cleanupFailure: unknown;
        if (handle !== 0) {
            try {
                const status = this.#context.runExclusive(
                    'canonical stream begin failure cleanup',
                    () => this.#context.cancel(handle),
                );
                this.#statusBoundary.throwIfError(status);
            } catch (error) {
                cleanupFailure = error;
            }
        }
        if (cleanupFailure !== undefined) {
            throw new CanonicalStreamCleanupError(
                operationFailure,
                cleanupFailure,
            );
        }
        throw operationFailure;
    }

    #releaseLease(lease: ActiveLease): void {
        if (this.#activeLease === lease) {
            this.#leaseAuthorities.delete(lease.identifier);
            this.#activeLease = undefined;
            this.#counters.activeSessionCount = 0;
        }
    }

    #requireActive(lease: ActiveLease): void {
        if (
            lease.state !== 'active' ||
            lease.authorityOwner !== this.#authorityOwner ||
            lease.authorityContext !== this.#context ||
            this.#activeLease !== lease ||
            this.#leaseAuthorities.get(lease.identifier) !== lease
        ) {
            throw new CanonicalStreamInternalError(
                'The canonical stream lease is no longer active.',
            );
        }
    }

    #cancelAfterOperation(
        lease: CanonicalStreamWriterLease | CanonicalStreamVerifierLease,
        operationFailure: unknown,
    ): void {
        try {
            lease.cancel();
        } catch (cleanupFailure) {
            if (operationFailure !== undefined) {
                throw new CanonicalStreamCleanupError(
                    operationFailure,
                    cleanupFailure,
                );
            }
            throw cleanupFailure;
        }
    }

    #copyMetadataIntoWasm(bytes: Uint8Array): number {
        return this.#memoryBoundary.copy(bytes);
    }

    #copyPayloadIntoWasm(buffer: ArrayBuffer): number {
        const bytes = new Uint8Array(buffer);
        const pointer = this.#memoryBoundary.copy(bytes);
        this.#charge('javascriptToWasmPayloadCopyCount', 1);
        this.#counters.maximumObservedCopiedPayloadByteLength = Math.max(
            this.#counters.maximumObservedCopiedPayloadByteLength,
            bytes.byteLength,
        );
        return pointer;
    }

    #allocateMetadata(wordCount: number): number {
        return this.#memoryBoundary.allocateZeroedWords(wordCount);
    }

    #readWords(pointer: number, wordCount: number): readonly number[] {
        return this.#memoryBoundary.readWords(pointer, wordCount);
    }

    #charge(counterName: keyof MutableCounters, amount: number): void {
        const nextValue = this.#counters[counterName] + amount;
        if (!Number.isSafeInteger(nextValue)) {
            throw new CanonicalStreamInternalError(
                'A canonical stream runtime counter overflowed.',
            );
        }
        this.#counters[counterName] = nextValue;
    }
}

export const openCanonicalStreamWorkerRuntime = (input: {
    readonly kernel: TranscriptCoreKernelContextOwner;
}): CanonicalStreamWorkerRuntime => {
    const context = contexts.get(input.kernel);
    if (context === undefined) {
        throw new CanonicalStreamInternalError(
            'The transcript-core kernel has no registered stream boundary.',
        );
    }
    let runtime = workerRuntimes.get(input.kernel);
    if (runtime === undefined) {
        runtime = new CanonicalStreamWorkerRuntimeImplementation(
            input.kernel,
            context,
        );
        Object.freeze(runtime);
        workerRuntimes.set(input.kernel, runtime);
    }
    return runtime;
};

/** Invalidates every process-local stream lease owned by one worker's WASM
 * instance. A terminated worker realm drops the same authority implicitly;
 * an orderly worker shutdown calls this hook before releasing the instance.
 */
export const invalidateCanonicalStreamWorkerRuntime = (input: {
    readonly kernel: TranscriptCoreKernelContextOwner;
}): void => {
    workerRuntimes.get(input.kernel)?.invalidate();
};

/** Internal composition hook for consumers that must atomically consume a
 * generic verifier lease in another kernel verifier. The stream handle never
 * leaves the callback invoked by `finish()`.
 */
export const openCanonicalStreamVerifierForAtomicFinish = (input: {
    readonly atomicFinish: CanonicalStreamAtomicVerifierFinish;
    readonly descriptorBytes: Uint8Array;
    readonly kernel: TranscriptCoreKernelContextOwner;
    readonly streamDomain: CanonicalStreamDomain;
}): CanonicalStreamVerifierLease => {
    if (contexts.get(input.kernel) === undefined) {
        throw new CanonicalStreamInternalError(
            'The transcript-core kernel has no registered stream boundary.',
        );
    }
    const runtime = openCanonicalStreamWorkerRuntime({ kernel: input.kernel });
    if (!(runtime instanceof CanonicalStreamWorkerRuntimeImplementation)) {
        throw new CanonicalStreamInternalError(
            'The transcript-core kernel has an invalid stream runtime boundary.',
        );
    }
    return runtime.openVerifier(
        {
            descriptorBytes: input.descriptorBytes,
            streamDomain: input.streamDomain,
        },
        input.atomicFinish,
    );
};

export type { CanonicalStreamKernelContext };
