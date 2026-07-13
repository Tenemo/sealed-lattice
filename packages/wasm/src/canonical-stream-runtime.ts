import type { RefusalReason } from '@sealed-lattice/types';
import { foundationProfile } from '@sealed-lattice/types';

import { refusalReasonByCode } from './transcript-core-bridge/kernel-errors.js';
import type { TranscriptCoreKernelContextOwner } from './transcript-core-bridge/kernel-types.js';

const maximumCanonicalStreamByteLength = 2_147_483_648;
const maximumCanonicalStreamChunkCount =
    maximumCanonicalStreamByteLength / foundationProfile.streamChunkByteLength;
const maximumCanonicalStreamDescriptorByteLength =
    104 + 64 * maximumCanonicalStreamChunkCount;
const runtimeInternalFailureStatus = 0xffff_ffff;
const runtimeInvalidSessionStatus = 0xffff_fffe;
const wasm32WordByteLength = 4;

export const canonicalStreamDomains = Object.freeze({
    dealerVssShareLinkageProof: 2,
    recipientAggregateThresholdShareProof: 3,
    sameSecretProof: 4,
    publicKeyShareProof: 5,
    evaluatorKeyAggregateProof: 11,
    evaluatorKeyStore: 13,
    maliciousTargetShareProof: 21,
    stateBallotCandidateListExactOutput: 23,
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
        message = 'The canonical stream exceeds the supported runtime profile.',
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
    maximumObservedResidentPayloadChunkCount: number;
    maximumObservedWasmMemoryByteLength: number;
    startedSessionCount: number;
    wasmToJavascriptPayloadCopyCount: number;
}>;

export type CanonicalStreamChunkPull = (input: {
    readonly abortSignal?: AbortSignal;
    readonly chunkIndex: number;
    readonly expectedByteLength: number;
}) => Promise<ArrayBuffer | undefined>;

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
    allocate(length: number): number;
    beginVerifier(
        streamDomain: number,
        descriptorPointer: number,
        descriptorLength: number,
        statusPointer: number,
        totalByteLengthPointer: number,
        chunkCountPointer: number,
    ): number;
    beginWriter(
        streamDomain: number,
        totalByteLength: number,
        statusPointer: number,
        chunkCountPointer: number,
    ): number;
    bgvAbsorbChunk?: (
        handle: number,
        chunkIndex: number,
        chunkPointer: number,
        chunkLength: number,
    ) => number;
    bgvBegin?: (
        familyCode: number,
        materialRootPointer: number,
        materialRootLength: number,
        descriptorPointer: number,
        descriptorLength: number,
        statusPointer: number,
        totalByteLengthPointer: number,
        chunkCountPointer: number,
    ) => number;
    bgvCancel?: (handle: number) => number;
    bgvFinish?: (handle: number) => number;
    bgvMaterialReaderBegin?: (
        familyCode: number,
        materialRootPointer: number,
        materialRootLength: number,
        statusPointer: number,
        totalByteLengthPointer: number,
        chunkCountPointer: number,
    ) => number;
    bgvMaterialReaderCancel?: (handle: number) => number;
    bgvMaterialReaderFinish?: (handle: number) => number;
    bgvMaterialReaderReadChunk?: (
        handle: number,
        chunkIndex: number,
        outputPointer: number,
        outputLength: number,
    ) => number;
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

export const registerCanonicalStreamKernelContext = (
    kernel: TranscriptCoreKernelContextOwner,
    context: CanonicalStreamKernelContext,
): void => {
    contexts.set(kernel, context);
};

export const canonicalStreamKernelContext = (
    kernel: TranscriptCoreKernelContextOwner,
): CanonicalStreamKernelContext | undefined => contexts.get(kernel);

type MutableCounters = {
    -readonly [CounterName in keyof CanonicalStreamRuntimeCounterSnapshot]: CanonicalStreamRuntimeCounterSnapshot[CounterName];
};

type ActiveLease = {
    atomicVerifierFinish?: CanonicalStreamAtomicVerifierFinish;
    chunkCount: number;
    handle: number;
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

const isArrayBuffer = (value: unknown): value is ArrayBuffer =>
    Object.prototype.toString.call(value) === '[object ArrayBuffer]';

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
    readonly #context: CanonicalStreamKernelContext;
    readonly #counters: MutableCounters;
    #activeLease: ActiveLease | undefined;

    public constructor(context: CanonicalStreamKernelContext) {
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
            maximumObservedResidentPayloadChunkCount: 0,
            maximumObservedWasmMemoryByteLength:
                context.memory.buffer.byteLength,
            startedSessionCount: 0,
            wasmToJavascriptPayloadCopyCount: 0,
        };
        this.#assertMemoryWithinProfile();
    }

    public counterSnapshot(): CanonicalStreamRuntimeCounterSnapshot {
        return Object.freeze({ ...this.#counters });
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
        if (input.totalByteLength > maximumCanonicalStreamByteLength) {
            throw new CanonicalStreamResourceError();
        }
        let handle = 0;
        let metadataPointer = 0;
        try {
            metadataPointer = this.#allocateMetadata(2);
            handle = this.#context.runExclusive('canonical stream begin', () =>
                this.#context.beginWriter(
                    input.streamDomain,
                    input.totalByteLength,
                    metadataPointer,
                    metadataPointer + wasm32WordByteLength,
                ),
            );
            const metadata = this.#readWords(metadataPointer, 2);
            this.#throwStatus(metadata[0]);
            if (handle === 0 || metadata[1] === 0) {
                throw new CanonicalStreamInternalError(
                    'The WASM stream writer returned malformed begin metadata.',
                );
            }
            const lease: ActiveLease = {
                chunkCount: metadata[1],
                handle,
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
                this.#context.deallocate(
                    metadataPointer,
                    2 * wasm32WordByteLength,
                );
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
        let descriptorPointer = 0;
        let handle = 0;
        let metadataPointer = 0;
        try {
            metadataPointer = this.#allocateMetadata(3);
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
                    metadataPointer + 2 * wasm32WordByteLength,
                ),
            );
            const metadata = this.#readWords(metadataPointer, 3);
            this.#throwStatus(metadata[0]);
            if (handle === 0 || metadata[1] === 0 || metadata[2] === 0) {
                throw new CanonicalStreamInternalError(
                    'The WASM stream verifier returned malformed begin metadata.',
                );
            }
            const lease: ActiveLease = {
                ...(atomicVerifierFinish === undefined
                    ? {}
                    : { atomicVerifierFinish }),
                chunkCount: metadata[2],
                handle,
                kind: 'verifier',
                state: 'active',
                totalByteLength: metadata[1],
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
                    3 * wasm32WordByteLength,
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
            for (
                let chunkIndex = 0;
                chunkIndex < lease.chunkCount;
                chunkIndex += 1
            ) {
                this.#throwIfCancelled(input.abortSignal);
                const expectedByteLength = this.#expectedChunkByteLength(
                    lease,
                    chunkIndex,
                );
                const bytes = await input.pullChunk({
                    ...(input.abortSignal === undefined
                        ? {}
                        : { abortSignal: input.abortSignal }),
                    chunkIndex,
                    expectedByteLength,
                });
                if (bytes === undefined) {
                    this.#throwIfCancelled(input.abortSignal);
                    return lease.finish();
                }
                try {
                    this.#throwIfCancelled(input.abortSignal);
                    lease.absorbChunk(chunkIndex, bytes);
                    await input.emitChunk({
                        ...(input.abortSignal === undefined
                            ? {}
                            : { abortSignal: input.abortSignal }),
                        bytes,
                        chunkIndex,
                    });
                } finally {
                    this.#releaseBuffer(bytes);
                }
            }
            const trailingBytes = await input.pullChunk({
                ...(input.abortSignal === undefined
                    ? {}
                    : { abortSignal: input.abortSignal }),
                chunkIndex: lease.chunkCount,
                expectedByteLength: 0,
            });
            if (trailingBytes !== undefined) {
                try {
                    this.#throwIfCancelled(input.abortSignal);
                    lease.absorbChunk(lease.chunkCount, trailingBytes);
                } finally {
                    this.#releaseBuffer(trailingBytes);
                }
            } else {
                this.#throwIfCancelled(input.abortSignal);
            }
            return lease.finish();
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
            for (
                let chunkIndex = 0;
                chunkIndex < lease.chunkCount;
                chunkIndex += 1
            ) {
                this.#throwIfCancelled(input.abortSignal);
                const expectedByteLength = this.#expectedChunkByteLength(
                    lease,
                    chunkIndex,
                );
                const bytes = await input.pullChunk({
                    ...(input.abortSignal === undefined
                        ? {}
                        : { abortSignal: input.abortSignal }),
                    chunkIndex,
                    expectedByteLength,
                });
                if (bytes === undefined) {
                    this.#throwIfCancelled(input.abortSignal);
                    lease.finish();
                    return;
                }
                try {
                    this.#throwIfCancelled(input.abortSignal);
                    lease.absorbChunk(chunkIndex, bytes);
                    await input.consumeVerifiedChunk({
                        ...(input.abortSignal === undefined
                            ? {}
                            : { abortSignal: input.abortSignal }),
                        bytes,
                        chunkIndex,
                    });
                } finally {
                    this.#releaseBuffer(bytes);
                }
            }
            const trailingBytes = await input.pullChunk({
                ...(input.abortSignal === undefined
                    ? {}
                    : { abortSignal: input.abortSignal }),
                chunkIndex: lease.chunkCount,
                expectedByteLength: 0,
            });
            if (trailingBytes !== undefined) {
                try {
                    this.#throwIfCancelled(input.abortSignal);
                    lease.absorbChunk(lease.chunkCount, trailingBytes);
                } finally {
                    this.#releaseBuffer(trailingBytes);
                }
            } else {
                this.#throwIfCancelled(input.abortSignal);
            }
            lease.finish();
        } catch (error) {
            operationFailure = error;
            throw error;
        } finally {
            this.#cancelAfterOperation(lease, operationFailure);
        }
    }

    #prepareBegin(streamDomain: number): void {
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
        this.#activeLease = lease;
        this.#charge('startedSessionCount', 1);
        this.#counters.activeSessionCount = 1;
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
                this.#throwStatus(status);
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
            this.#preflightAllocation(
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
            this.#throwStatus(status);
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
                this.#throwStatus(status);
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
        try {
            const status = this.#context.runExclusive(
                'canonical stream cancellation',
                () => this.#context.cancel(lease.handle),
            );
            this.#throwStatus(status);
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
                this.#throwStatus(status);
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
                this.#throwStatus(status);
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
            this.#activeLease = undefined;
            this.#counters.activeSessionCount = 0;
        }
    }

    #requireActive(lease: ActiveLease): void {
        if (lease.state !== 'active' || this.#activeLease !== lease) {
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

    #throwIfCancelled(abortSignal: AbortSignal | undefined): void {
        if (abortSignal?.aborted === true) {
            throw new CanonicalStreamCancellationError();
        }
    }

    #expectedChunkByteLength(
        lease:
            | ActiveLease
            | CanonicalStreamWriterLease
            | CanonicalStreamVerifierLease,
        chunkIndex: number,
    ): number {
        if (chunkIndex + 1 < lease.chunkCount) {
            return foundationProfile.streamChunkByteLength;
        }
        return (
            lease.totalByteLength -
            (lease.chunkCount - 1) * foundationProfile.streamChunkByteLength
        );
    }

    #releaseBuffer(buffer: ArrayBuffer): void {
        if (buffer.byteLength > 0) {
            new Uint8Array(buffer).fill(0);
        }
    }

    #copyMetadataIntoWasm(bytes: Uint8Array): number {
        const pointer = this.#allocate(bytes.byteLength);
        try {
            new Uint8Array(this.#context.memory.buffer).set(bytes, pointer);
            return pointer;
        } catch (error) {
            this.#context.deallocate(pointer, bytes.byteLength);
            throw error;
        }
    }

    #copyPayloadIntoWasm(buffer: ArrayBuffer): number {
        const bytes = new Uint8Array(buffer);
        const pointer = this.#allocate(bytes.byteLength);
        try {
            new Uint8Array(this.#context.memory.buffer).set(bytes, pointer);
        } catch (error) {
            this.#context.deallocate(pointer, bytes.byteLength);
            throw error;
        }
        this.#charge('javascriptToWasmPayloadCopyCount', 1);
        this.#counters.maximumObservedCopiedPayloadByteLength = Math.max(
            this.#counters.maximumObservedCopiedPayloadByteLength,
            bytes.byteLength,
        );
        this.#counters.maximumObservedResidentPayloadChunkCount = Math.max(
            this.#counters.maximumObservedResidentPayloadChunkCount,
            2,
        );
        return pointer;
    }

    #allocateMetadata(wordCount: number): number {
        const byteLength = wordCount * wasm32WordByteLength;
        const pointer = this.#allocate(byteLength);
        new Uint8Array(this.#context.memory.buffer, pointer, byteLength).fill(
            0,
        );
        return pointer;
    }

    #allocate(byteLength: number): number {
        this.#preflightAllocation(byteLength);
        const pointer = this.#context.allocate(byteLength) >>> 0;
        this.#assertMemoryWithinProfile();
        if (
            pointer === 0 ||
            pointer + byteLength > this.#context.memory.buffer.byteLength
        ) {
            throw new CanonicalStreamInternalError(
                'The WASM stream allocator returned an invalid memory range.',
            );
        }
        this.#counters.maximumObservedWasmMemoryByteLength = Math.max(
            this.#counters.maximumObservedWasmMemoryByteLength,
            this.#context.memory.buffer.byteLength,
        );
        return pointer;
    }

    #preflightAllocation(byteLength: number): void {
        assertSafeNonNegativeInteger(byteLength, 'canonical stream allocation');
        this.#assertMemoryWithinProfile();
        if (
            byteLength > foundationProfile.maximumCopiedBufferByteLength ||
            this.#context.memory.buffer.byteLength >
                foundationProfile.maximumWasmMemoryByteLength - byteLength
        ) {
            throw new CanonicalStreamResourceError(
                'The canonical stream allocation would exceed the WASM memory profile.',
            );
        }
    }

    #assertMemoryWithinProfile(): void {
        if (
            this.#context.memory.buffer.byteLength >
            foundationProfile.maximumWasmMemoryByteLength
        ) {
            throw new CanonicalStreamResourceError(
                'The WASM instance already exceeds the memory profile.',
            );
        }
    }

    #readWords(pointer: number, wordCount: number): readonly number[] {
        const byteLength = wordCount * wasm32WordByteLength;
        if (
            pointer === 0 ||
            pointer + byteLength > this.#context.memory.buffer.byteLength
        ) {
            throw new CanonicalStreamInternalError(
                'The WASM stream metadata range is invalid.',
            );
        }
        const view = new DataView(
            this.#context.memory.buffer,
            pointer,
            byteLength,
        );
        return Object.freeze(
            Array.from({ length: wordCount }, (_, index) =>
                view.getUint32(index * wasm32WordByteLength, true),
            ),
        );
    }

    #throwStatus(status: number): void {
        const normalizedStatus = status >>> 0;
        if (normalizedStatus === 0) {
            return;
        }
        if (
            normalizedStatus === runtimeInternalFailureStatus ||
            normalizedStatus === runtimeInvalidSessionStatus
        ) {
            throw new CanonicalStreamInternalError(
                'The WASM canonical stream session failed internally.',
            );
        }
        const refusalReason = refusalReasonByCode.get(normalizedStatus);
        if (refusalReason === undefined) {
            throw new CanonicalStreamInternalError(
                'The WASM canonical stream returned an unknown status code.',
            );
        }
        if (refusalReason === 'outsideSupportedProfile') {
            throw new CanonicalStreamResourceError();
        }
        throw new CanonicalStreamRefusalError(refusalReason);
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
    return Object.freeze(
        new CanonicalStreamWorkerRuntimeImplementation(context),
    );
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
    const context = contexts.get(input.kernel);
    if (context === undefined) {
        throw new CanonicalStreamInternalError(
            'The transcript-core kernel has no registered stream boundary.',
        );
    }
    const runtime = new CanonicalStreamWorkerRuntimeImplementation(context);
    return runtime.openVerifier(
        {
            descriptorBytes: input.descriptorBytes,
            streamDomain: input.streamDomain,
        },
        input.atomicFinish,
    );
};

export type { CanonicalStreamKernelContext };
