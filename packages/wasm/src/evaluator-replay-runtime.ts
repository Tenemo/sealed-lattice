import {
    markVerifiedEvaluatorAggregateConsumedAfterKernelInvocation,
    requireVerifiedEvaluatorAggregateKernelAuthority,
    retireVerifiedBallotEvaluationWorkerLease,
    type EvaluatorKeyStoreRangeSource,
    type VerifiedEvaluatorAggregateAuthority,
} from './ballot-aggregation-runtime.js';
import { isUint8Array } from './byte-array.js';
import {
    resolveVerifiedTranscriptObjectKernelAuthorization,
    type VerifiedTranscriptObject,
} from './canonical-board-runtime.js';
import {
    CanonicalStreamCancellationError,
    CanonicalStreamCleanupError,
    CanonicalStreamInternalError,
    CanonicalStreamRefusalError,
    CanonicalStreamResourceError,
} from './canonical-stream-runtime.js';
import { yieldBrowserWorkerTurn } from './common-proof-worker-runtime/kernel-boundaries.js';
import {
    createVerifiedEvaluatorReplayKernelAuthority,
    type VerifiedEvaluatorReplay,
} from './finality-verifier-runtime.js';
import type { TranscriptCoreKernelCommandRuntime } from './transcript-core-bridge/kernel-runtime.js';
import type { TranscriptCoreKernel } from './transcript-core-bridge/kernel-types.js';
import { WasmMemoryBoundary } from './wasm-memory-boundary.js';
import { WasmStatusBoundary } from './wasm-status-boundary.js';

const boardVerifierCapabilityByteLength = 32;
const evaluatorProgressByteLength = 16;
const evaluatorProgressVersion = 1;
const evaluatorStoreReadRequired = 1;
const evaluatorExecutionComplete = 2;
const maximumWasm32UnsignedInteger = 0xffff_ffff;
const wasm32WordByteLength = Uint32Array.BYTES_PER_ELEMENT;

type EvaluatorReplayKernel = Readonly<{
    absorbStoreChunk: NonNullable<
        TranscriptCoreKernelCommandRuntime['wasmExports']['sealed_lattice_evaluator_execution_absorb_store_chunk']
    >;
    begin: NonNullable<
        TranscriptCoreKernelCommandRuntime['wasmExports']['sealed_lattice_evaluator_execution_begin']
    >;
    bindReplayObject: NonNullable<
        TranscriptCoreKernelCommandRuntime['wasmExports']['sealed_lattice_evaluator_execution_bind_replay_object']
    >;
    cancel: NonNullable<
        TranscriptCoreKernelCommandRuntime['wasmExports']['sealed_lattice_evaluator_execution_cancel']
    >;
    copyReplayCarrier: NonNullable<
        TranscriptCoreKernelCommandRuntime['wasmExports']['sealed_lattice_evaluator_execution_copy_replay_carrier']
    >;
    finish: NonNullable<
        TranscriptCoreKernelCommandRuntime['wasmExports']['sealed_lattice_evaluator_execution_finish']
    >;
    poll: NonNullable<
        TranscriptCoreKernelCommandRuntime['wasmExports']['sealed_lattice_evaluator_execution_poll']
    >;
    releaseReplay: NonNullable<
        TranscriptCoreKernelCommandRuntime['wasmExports']['sealed_lattice_evaluator_replay_release']
    >;
    replayCarrierByteLength: NonNullable<
        TranscriptCoreKernelCommandRuntime['wasmExports']['sealed_lattice_evaluator_execution_replay_carrier_byte_length']
    >;
}>;

type EvaluatorExecutionProgress =
    | Readonly<{
          exactByteLength: number;
          kind: 'store-read-required';
          storeByteOffset: bigint;
      }>
    | Readonly<{ kind: 'complete' }>;

const preparedEvaluatorReplayBrand: unique symbol = Symbol(
    'sealed-lattice/prepared-evaluator-replay',
);

/**
 * Retained evaluator output awaiting relay and positive ingestion of its exact
 * deterministic carrier by the live canonical-board verifier.
 */
export type PreparedEvaluatorReplay = Readonly<{
    readonly [preparedEvaluatorReplayBrand]: true;
    bind(
        verifiedReplayObject: VerifiedTranscriptObject,
    ): VerifiedEvaluatorReplay;
    cancel(): void;
    copyCanonicalCarrier(): Uint8Array<ArrayBuffer>;
}>;

type PreparedEvaluatorReplayRecord = {
    canonicalCarrier: Uint8Array<ArrayBuffer>;
    cancellationController: AbortController;
    context: TranscriptCoreKernelCommandRuntime;
    executionHandle: number;
    kernel: EvaluatorReplayKernel;
    transcriptCoreKernel: TranscriptCoreKernel;
};

const preparedEvaluatorReplayRecords = new WeakMap<
    PreparedEvaluatorReplay,
    PreparedEvaluatorReplayRecord
>();
const activeEvaluatorContexts = new WeakSet<object>();

const createStatusBoundary = (): WasmStatusBoundary =>
    new WasmStatusBoundary({
        createInternalError: (message) =>
            new CanonicalStreamInternalError(message),
        createRefusalError: (refusalReason) =>
            new CanonicalStreamRefusalError(refusalReason),
        createResourceError: () => new CanonicalStreamResourceError(),
        internalFailureMessage:
            'The selected evaluator replay kernel failed internally.',
        unknownStatusMessage:
            'The selected evaluator replay kernel returned an unknown status code.',
    });

const requireLiveHandle = (value: number, label: string): number => {
    if (
        !Number.isSafeInteger(value) ||
        value <= 0 ||
        value > maximumWasm32UnsignedInteger
    ) {
        throw new CanonicalStreamInternalError(`${label} is invalid.`);
    }
    return value;
};

const requireEvaluatorReplayKernel = (
    context: TranscriptCoreKernelCommandRuntime,
): EvaluatorReplayKernel => {
    const {
        sealed_lattice_evaluator_execution_absorb_store_chunk: absorbStoreChunk,
        sealed_lattice_evaluator_execution_begin: begin,
        sealed_lattice_evaluator_execution_bind_replay_object: bindReplayObject,
        sealed_lattice_evaluator_execution_cancel: cancel,
        sealed_lattice_evaluator_execution_copy_replay_carrier:
            copyReplayCarrier,
        sealed_lattice_evaluator_execution_finish: finish,
        sealed_lattice_evaluator_execution_poll: poll,
        sealed_lattice_evaluator_execution_replay_carrier_byte_length:
            replayCarrierByteLength,
        sealed_lattice_evaluator_replay_release: releaseReplay,
    } = context.wasmExports;
    if (
        typeof absorbStoreChunk !== 'function' ||
        typeof begin !== 'function' ||
        typeof bindReplayObject !== 'function' ||
        typeof cancel !== 'function' ||
        typeof copyReplayCarrier !== 'function' ||
        typeof finish !== 'function' ||
        typeof poll !== 'function' ||
        typeof releaseReplay !== 'function' ||
        typeof replayCarrierByteLength !== 'function'
    ) {
        throw new CanonicalStreamInternalError(
            'The transcript-core kernel lacks the selected evaluator replay boundary.',
        );
    }
    return Object.freeze({
        absorbStoreChunk,
        begin,
        bindReplayObject,
        cancel,
        copyReplayCarrier,
        finish,
        poll,
        releaseReplay,
        replayCarrierByteLength,
    });
};

const throwIfCancelled = (signal?: AbortSignal): void => {
    if (signal?.aborted === true) {
        throw new CanonicalStreamCancellationError();
    }
};

const awaitAbortableHostOperation = async <Result>(
    signal: AbortSignal | undefined,
    startOperation: () => Promise<Result>,
    disposeLateResult?: (result: Result) => void,
): Promise<Result> => {
    if (signal === undefined) {
        return await startOperation();
    }
    throwIfCancelled(signal);

    const cancellationError = new CanonicalStreamCancellationError();
    const operationState = { cancellationWon: false };
    let abortListener = (): void => undefined;
    const cancellationPromise = new Promise<never>((_resolve, reject) => {
        abortListener = (): void => {
            operationState.cancellationWon = true;
            reject(cancellationError);
        };
    });
    signal.addEventListener('abort', abortListener, { once: true });
    if (signal.aborted) {
        abortListener();
    }

    const hostOperationPromise = Promise.resolve()
        .then(startOperation)
        .then((result) => {
            if (operationState.cancellationWon) {
                disposeLateResult?.(result);
                throw cancellationError;
            }
            return result;
        });
    try {
        return await Promise.race([hostOperationPromise, cancellationPromise]);
    } finally {
        signal.removeEventListener('abort', abortListener);
    }
};

const decodeProgress = (bytes: Uint8Array): EvaluatorExecutionProgress => {
    if (bytes.byteLength !== evaluatorProgressByteLength) {
        throw new CanonicalStreamInternalError(
            'The evaluator progress record has the wrong byte length.',
        );
    }
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    if (view.getUint16(0, true) !== evaluatorProgressVersion) {
        throw new CanonicalStreamInternalError(
            'The evaluator progress record has an unsupported version.',
        );
    }
    const progressCode = view.getUint16(2, true);
    const storeByteOffset = view.getBigUint64(4, true);
    const exactByteLength = view.getUint32(12, true);
    if (progressCode === evaluatorStoreReadRequired) {
        if (exactByteLength === 0) {
            throw new CanonicalStreamInternalError(
                'The evaluator requested an empty key-store range.',
            );
        }
        return Object.freeze({
            exactByteLength,
            kind: 'store-read-required' as const,
            storeByteOffset,
        });
    }
    if (
        progressCode === evaluatorExecutionComplete &&
        storeByteOffset === 0n &&
        exactByteLength === 0
    ) {
        return Object.freeze({ kind: 'complete' as const });
    }
    throw new CanonicalStreamInternalError(
        'The evaluator returned an invalid progress code or payload.',
    );
};

const requirePreparedRecord = (
    preparedReplay: PreparedEvaluatorReplay,
): PreparedEvaluatorReplayRecord => {
    if (
        (typeof preparedReplay !== 'object' &&
            typeof preparedReplay !== 'function') ||
        preparedReplay === null
    ) {
        throw new CanonicalStreamRefusalError('consumedState');
    }
    const record = preparedEvaluatorReplayRecords.get(preparedReplay);
    if (record === undefined) {
        throw new CanonicalStreamRefusalError('consumedState');
    }
    return record;
};

const retirePreparedRecord = (
    preparedReplay: PreparedEvaluatorReplay,
    record: PreparedEvaluatorReplayRecord,
): void => {
    preparedEvaluatorReplayRecords.delete(preparedReplay);
    activeEvaluatorContexts.delete(record.context);
    record.canonicalCarrier.fill(0);
    retireVerifiedBallotEvaluationWorkerLease(
        record.context,
        record.cancellationController,
    );
};

const copyPreparedCanonicalCarrier = (
    preparedReplay: PreparedEvaluatorReplay,
): Uint8Array<ArrayBuffer> =>
    Uint8Array.from(requirePreparedRecord(preparedReplay).canonicalCarrier);

const cancelPreparedEvaluatorReplay = (
    preparedReplay: PreparedEvaluatorReplay,
): void => {
    const record = requirePreparedRecord(preparedReplay);
    const statusBoundary = createStatusBoundary();
    let invocationEntered = false;
    let status: number;
    try {
        status = record.context.runExclusive(
            'prepared evaluator replay cancellation',
            () => {
                invocationEntered = true;
                return record.kernel.cancel(record.executionHandle);
            },
        );
    } finally {
        if (invocationEntered) {
            retirePreparedRecord(preparedReplay, record);
        }
    }
    statusBoundary.throwIfError(status);
};

const bindPreparedEvaluatorReplay = (
    preparedReplay: PreparedEvaluatorReplay,
    verifiedReplayObject: VerifiedTranscriptObject,
): VerifiedEvaluatorReplay => {
    const record = requirePreparedRecord(preparedReplay);
    const boardAuthorization =
        resolveVerifiedTranscriptObjectKernelAuthorization(
            verifiedReplayObject,
            record.transcriptCoreKernel,
        );
    if (
        boardAuthorization.capabilityMemory !== record.context.memory ||
        boardAuthorization.capabilityPointer <= 0 ||
        boardAuthorization.capabilityPointer +
            boardVerifierCapabilityByteLength >
            record.context.memory.buffer.byteLength
    ) {
        throw new CanonicalStreamRefusalError('wrongContext');
    }
    const memoryBoundary = new WasmMemoryBoundary({
        context: record.context,
        createInternalError: (message) =>
            new CanonicalStreamInternalError(message),
        createResourceError: (message) =>
            new CanonicalStreamResourceError(message),
        label: 'evaluator replay board-binding boundary',
    });
    const statusBoundary = createStatusBoundary();
    const statusPointer = memoryBoundary.allocateZeroedWords(1);
    let verifiedReplayHandle = 0;
    try {
        verifiedReplayHandle = record.context.runExclusive(
            'evaluator replay board binding',
            () =>
                record.kernel.bindReplayObject(
                    record.executionHandle,
                    boardAuthorization.sessionHandle,
                    boardAuthorization.capabilityPointer,
                    boardVerifierCapabilityByteLength,
                    boardAuthorization.objectHandle,
                    statusPointer,
                ),
        );
        const [status] = memoryBoundary.readWords(statusPointer, 1);
        statusBoundary.throwIfError(status);
        requireLiveHandle(
            verifiedReplayHandle,
            'The verified evaluator replay handle',
        );
    } finally {
        memoryBoundary.zeroAndDeallocate(statusPointer, wasm32WordByteLength);
    }

    retirePreparedRecord(preparedReplay, record);
    try {
        return createVerifiedEvaluatorReplayKernelAuthority({
            handle: verifiedReplayHandle,
            kernel: record.transcriptCoreKernel,
            release: (handle) =>
                record.context.runExclusive(
                    'verified evaluator replay release',
                    () => record.kernel.releaseReplay(handle),
                ),
        });
    } catch (operationFailure) {
        let cleanupFailure: unknown;
        try {
            const status = record.context.runExclusive(
                'unwrapped evaluator replay cleanup',
                () => record.kernel.releaseReplay(verifiedReplayHandle),
            );
            statusBoundary.throwIfError(status);
        } catch (error) {
            cleanupFailure = error;
        }
        if (cleanupFailure !== undefined) {
            throw new CanonicalStreamCleanupError(
                operationFailure,
                cleanupFailure,
            );
        }
        throw operationFailure;
    }
};

const createPreparedEvaluatorReplay = (
    record: PreparedEvaluatorReplayRecord,
): PreparedEvaluatorReplay => {
    const preparedReplay: PreparedEvaluatorReplay = Object.freeze({
        [preparedEvaluatorReplayBrand]: true as const,
        bind: (verifiedReplayObject: VerifiedTranscriptObject) =>
            bindPreparedEvaluatorReplay(preparedReplay, verifiedReplayObject),
        cancel: () => cancelPreparedEvaluatorReplay(preparedReplay),
        copyCanonicalCarrier: () =>
            copyPreparedCanonicalCarrier(preparedReplay),
    });
    preparedEvaluatorReplayRecords.set(preparedReplay, record);
    return preparedReplay;
};

const readExactStoreRange = async (input: {
    exactByteLength: number;
    source: EvaluatorKeyStoreRangeSource;
    storeByteOffset: bigint;
}): Promise<Uint8Array<ArrayBuffer>> => {
    let chunkBytes: Uint8Array;
    try {
        chunkBytes = await input.source.readExactRange(
            input.storeByteOffset,
            input.exactByteLength,
        );
    } catch (error) {
        throw new CanonicalStreamInternalError(
            'The evaluator key store could not read the exact requested range.',
            error,
        );
    }
    if (
        !isUint8Array(chunkBytes) ||
        !(chunkBytes.buffer instanceof ArrayBuffer) ||
        chunkBytes.byteOffset !== 0 ||
        chunkBytes.byteLength !== chunkBytes.buffer.byteLength ||
        chunkBytes.byteLength !== input.exactByteLength
    ) {
        if (isUint8Array(chunkBytes)) {
            chunkBytes.fill(0);
        }
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    return chunkBytes as Uint8Array<ArrayBuffer>;
};

const copyReplayCarrier = (input: {
    context: TranscriptCoreKernelCommandRuntime;
    executionHandle: number;
    kernel: EvaluatorReplayKernel;
    memoryBoundary: WasmMemoryBoundary;
    statusBoundary: WasmStatusBoundary;
}): Uint8Array<ArrayBuffer> =>
    input.context.runExclusive('evaluator replay carrier copy', () => {
        const statusPointer = input.memoryBoundary.allocateZeroedWords(1);
        let outputPointer = 0;
        let outputByteLength = 0;
        try {
            outputByteLength = input.kernel.replayCarrierByteLength(
                input.executionHandle,
                statusPointer,
            );
            const [lengthStatus] = input.memoryBoundary.readWords(
                statusPointer,
                1,
            );
            input.statusBoundary.throwIfError(lengthStatus);
            input.memoryBoundary.validateAllocationByteLength(outputByteLength);
            outputPointer = input.memoryBoundary.allocate(outputByteLength);
            const copyStatus = input.kernel.copyReplayCarrier(
                input.executionHandle,
                outputPointer,
                outputByteLength,
            );
            input.statusBoundary.throwIfError(copyStatus);
            return Uint8Array.from(
                new Uint8Array(
                    input.context.memory.buffer,
                    outputPointer,
                    outputByteLength,
                ),
            );
        } finally {
            input.memoryBoundary.zeroAndDeallocate(
                outputPointer,
                outputByteLength,
            );
            input.memoryBoundary.zeroAndDeallocate(
                statusPointer,
                wasm32WordByteLength,
            );
        }
    });

/**
 * Runs the suite-fixed evaluator entirely in the dedicated WASM worker. Rust
 * requests and authenticates exact external-store ranges; only the compact
 * deterministic replay carrier is exposed for relay and board ingestion.
 */
export const prepareEvaluatorReplayInClosedWorker = async (input: {
    verifiedAggregateAuthority: VerifiedEvaluatorAggregateAuthority;
}): Promise<PreparedEvaluatorReplay> => {
    if (typeof globalThis.document !== 'undefined') {
        throw new CanonicalStreamInternalError(
            'Evaluator replay may only run inside the dedicated WASM worker.',
        );
    }
    const aggregateAuthority = requireVerifiedEvaluatorAggregateKernelAuthority(
        input.verifiedAggregateAuthority,
    );
    const context = aggregateAuthority.context;
    if (activeEvaluatorContexts.has(context)) {
        throw new CanonicalStreamResourceError(
            'The WASM worker already retains an evaluator execution.',
        );
    }
    const kernel = requireEvaluatorReplayKernel(context);
    const statusBoundary = createStatusBoundary();
    const memoryBoundary = new WasmMemoryBoundary({
        context,
        createInternalError: (message) =>
            new CanonicalStreamInternalError(message),
        createResourceError: (message) =>
            new CanonicalStreamResourceError(message),
        label: 'selected evaluator replay boundary',
    });
    const signal = aggregateAuthority.options.signal;
    const yieldControl =
        aggregateAuthority.options.yieldControl ?? yieldBrowserWorkerTurn;

    activeEvaluatorContexts.add(context);
    let executionHandle = 0;
    let aggregateAuthorityConsumed = false;
    let preparedReplayCreated = false;
    try {
        throwIfCancelled(signal);
        const statusPointer = memoryBoundary.allocateZeroedWords(1);
        try {
            context.runExclusive('selected evaluator begin', () => {
                let beginInvoked = false;
                try {
                    beginInvoked = true;
                    executionHandle = kernel.begin(
                        aggregateAuthority.handle,
                        statusPointer,
                    );
                } finally {
                    if (beginInvoked) {
                        aggregateAuthorityConsumed = true;
                        markVerifiedEvaluatorAggregateConsumedAfterKernelInvocation(
                            input.verifiedAggregateAuthority,
                            aggregateAuthority.kernel,
                        );
                    }
                }
                const [status] = memoryBoundary.readWords(statusPointer, 1);
                statusBoundary.throwIfError(status);
                requireLiveHandle(
                    executionHandle,
                    'The selected evaluator execution handle',
                );
            });
        } finally {
            memoryBoundary.zeroAndDeallocate(
                statusPointer,
                wasm32WordByteLength,
            );
        }

        const progressPointer = memoryBoundary.allocate(
            evaluatorProgressByteLength,
        );
        try {
            for (;;) {
                throwIfCancelled(signal);
                const progress = context.runExclusive(
                    'selected evaluator progress',
                    () => {
                        const status = kernel.poll(
                            executionHandle,
                            progressPointer,
                            evaluatorProgressByteLength,
                        );
                        if (status !== 0) {
                            // Rust drops a refused executing state immediately.
                            // Retaining this identifier would make cleanup issue
                            // a second, misleading consumed-state refusal.
                            executionHandle = 0;
                        }
                        statusBoundary.throwIfError(status);
                        return decodeProgress(
                            new Uint8Array(
                                context.memory.buffer,
                                progressPointer,
                                evaluatorProgressByteLength,
                            ),
                        );
                    },
                );
                if (progress.kind === 'complete') {
                    break;
                }
                memoryBoundary.validateAllocationByteLength(
                    progress.exactByteLength,
                );
                const chunkBytes = await awaitAbortableHostOperation(
                    signal,
                    () =>
                        readExactStoreRange({
                            exactByteLength: progress.exactByteLength,
                            source: aggregateAuthority.evaluatorKeyStore,
                            storeByteOffset: progress.storeByteOffset,
                        }),
                    (lateChunkBytes) => lateChunkBytes.fill(0),
                );
                try {
                    aggregateAuthority.options.observeEvaluatorKeyStoreRangeRead?.(
                        Object.freeze({
                            requestedByteLength: progress.exactByteLength,
                            returnedByteLength: chunkBytes.byteLength,
                            storeByteOffset: progress.storeByteOffset,
                        }),
                    );
                    throwIfCancelled(signal);
                    context.runExclusive(
                        'selected evaluator store-range absorption',
                        () => {
                            const chunkPointer =
                                memoryBoundary.copy(chunkBytes);
                            try {
                                const status = kernel.absorbStoreChunk(
                                    executionHandle,
                                    progress.storeByteOffset,
                                    chunkPointer,
                                    chunkBytes.byteLength,
                                );
                                if (status !== 0) {
                                    executionHandle = 0;
                                }
                                statusBoundary.throwIfError(status);
                            } finally {
                                memoryBoundary.zeroAndDeallocate(
                                    chunkPointer,
                                    chunkBytes.byteLength,
                                );
                            }
                        },
                    );
                } finally {
                    chunkBytes.fill(0);
                }
                await awaitAbortableHostOperation(signal, yieldControl);
            }
        } finally {
            memoryBoundary.zeroAndDeallocate(
                progressPointer,
                evaluatorProgressByteLength,
            );
        }

        throwIfCancelled(signal);
        context.runExclusive('selected evaluator completion', () => {
            const status = kernel.finish(executionHandle);
            if (status !== 0) {
                executionHandle = 0;
            }
            statusBoundary.throwIfError(status);
        });
        const canonicalCarrier = copyReplayCarrier({
            context,
            executionHandle,
            kernel,
            memoryBoundary,
            statusBoundary,
        });
        const preparedReplay = createPreparedEvaluatorReplay({
            canonicalCarrier,
            cancellationController: aggregateAuthority.cancellationController,
            context,
            executionHandle,
            kernel,
            transcriptCoreKernel: aggregateAuthority.kernel,
        });
        preparedReplayCreated = true;
        return preparedReplay;
    } catch (operationFailure) {
        let cleanupFailure: unknown;
        if (!preparedReplayCreated && executionHandle !== 0) {
            try {
                const status = context.runExclusive(
                    'failed selected evaluator cleanup',
                    () => kernel.cancel(executionHandle),
                );
                statusBoundary.throwIfError(status);
            } catch (error) {
                cleanupFailure = error;
            }
        } else if (!aggregateAuthorityConsumed) {
            try {
                input.verifiedAggregateAuthority.release();
            } catch (error) {
                cleanupFailure = error;
            }
        }
        activeEvaluatorContexts.delete(context);
        retireVerifiedBallotEvaluationWorkerLease(
            context,
            aggregateAuthority.cancellationController,
        );
        if (cleanupFailure !== undefined) {
            throw new CanonicalStreamCleanupError(
                operationFailure,
                cleanupFailure,
            );
        }
        throw operationFailure;
    }
};
