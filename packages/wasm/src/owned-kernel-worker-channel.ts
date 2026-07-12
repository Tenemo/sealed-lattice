import {
    foundationProfile,
    refusalReasons,
    type RefusalReason,
} from '@sealed-lattice/types';

const maximumWorkerResultByteLength = 65_536;
const maximumWorkerResultNestingDepth = 32;
const maximumOperationDurationMilliseconds = 24 * 60 * 60 * 1_000;
const cancellationTerminationDelayMilliseconds = 1_000;
const maximumOperationKind = 0xffff;

export class KernelWorkerCryptographicRefusalError extends Error {
    readonly refusalReason: RefusalReason;

    constructor(refusalReason: RefusalReason) {
        super(`The cryptographic worker refused the input: ${refusalReason}.`);
        this.name = 'KernelWorkerCryptographicRefusalError';
        this.refusalReason = refusalReason;
    }
}

export class KernelWorkerResourceError extends Error {
    constructor(
        message = 'The cryptographic worker exceeded its runtime profile.',
    ) {
        super(message);
        this.name = 'KernelWorkerResourceError';
    }
}

export class KernelWorkerCancellationError extends Error {
    constructor(message = 'The cryptographic worker operation was cancelled.') {
        super(message);
        this.name = 'KernelWorkerCancellationError';
    }
}

export class KernelWorkerInternalError extends Error {
    constructor(message = 'The cryptographic worker failed internally.') {
        super(message);
        this.name = 'KernelWorkerInternalError';
    }
}

type KernelWorkerTraceEvent =
    | Readonly<{
          eventKind: 'operation-started';
          inputByteLength: number;
          operationKind: number;
      }>
    | Readonly<{
          elapsedMilliseconds: number;
          eventKind: 'operation-finished';
          operationKind: number;
      }>;

type KernelWorkerCounterSnapshot = Readonly<{
    cancellationCount: number;
    completedOperationCount: number;
    cryptographicRefusalCount: number;
    internalFailureCount: number;
    operationCount: number;
    resourceFailureCount: number;
    telemetryFailureCount: number;
    transferredInputByteCount: number;
}>;

type MutableKernelWorkerCounters = {
    -readonly [CounterName in keyof KernelWorkerCounterSnapshot]: number;
};

type ExecuteOperationMessage = Readonly<{
    inputBuffer: ArrayBuffer;
    maximumDurationMilliseconds: number;
    messageKind: 'execute-operation';
    operationKind: number;
    requestIdentifier: number;
}>;

type CancelOperationMessage = Readonly<{
    cancellationKind: 'caller' | 'deadline';
    messageKind: 'cancel-operation';
    requestIdentifier: number;
}>;

type WorkerRequestMessage = ExecuteOperationMessage | CancelOperationMessage;

type WorkerResponseMessage =
    | Readonly<{
          messageKind: 'operation-completed';
          requestIdentifier: number;
          value: unknown;
      }>
    | Readonly<{
          messageKind: 'operation-refused';
          refusalReason: RefusalReason;
          requestIdentifier: number;
      }>
    | Readonly<{
          failureKind: 'cancelled' | 'internal' | 'resource';
          messageKind: 'operation-failed';
          requestIdentifier: number;
      }>;

type InFlightOperation = {
    readonly abortListener?: () => void;
    readonly abortSignal?: AbortSignal;
    cancellationKind?: 'caller' | 'deadline';
    cancellationTerminationTimer?: ReturnType<typeof setTimeout>;
    deadlineTimer: ReturnType<typeof setTimeout>;
    readonly operationKind: number;
    readonly reject: (reason: unknown) => void;
    readonly requestIdentifier: number;
    readonly resolve: (value: unknown) => void;
    readonly startMonotonicMilliseconds: number;
};

type WorkerLike = Pick<
    Worker,
    'addEventListener' | 'postMessage' | 'removeEventListener' | 'terminate'
>;

type OwnedKernelWorkerChannelOptions = Readonly<{
    trace?: (event: KernelWorkerTraceEvent) => void;
}>;

type KernelWorkerOperationInput = Readonly<{
    abortSignal?: AbortSignal;
    inputBuffer: ArrayBuffer;
    maximumDurationMilliseconds: number;
    operationKind: number;
}>;

const validateOperationKind = (operationKind: number): void => {
    if (
        !Number.isSafeInteger(operationKind) ||
        operationKind <= 0 ||
        operationKind > maximumOperationKind
    ) {
        throw new KernelWorkerResourceError(
            'The cryptographic worker operation kind is unassigned.',
        );
    }
};

const validateOperationDuration = (durationMilliseconds: number): void => {
    if (
        !Number.isSafeInteger(durationMilliseconds) ||
        durationMilliseconds <= 0 ||
        durationMilliseconds > maximumOperationDurationMilliseconds
    ) {
        throw new KernelWorkerResourceError(
            'The cryptographic worker duration is outside the runtime profile.',
        );
    }
};

const isPlainRecord = (value: unknown): value is Record<string, unknown> => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        return false;
    }
    const prototype = Reflect.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
};

const isSafePositiveInteger = (value: unknown): value is number =>
    typeof value === 'number' && Number.isSafeInteger(value) && value > 0;

const isRefusalReason = (value: unknown): value is RefusalReason =>
    typeof value === 'string' &&
    (refusalReasons as readonly string[]).includes(value);

const isWorkerRequestMessage = (
    value: unknown,
): value is WorkerRequestMessage => {
    if (
        !isPlainRecord(value) ||
        !isSafePositiveInteger(value.requestIdentifier)
    ) {
        return false;
    }
    if (value.messageKind === 'cancel-operation') {
        return (
            value.cancellationKind === 'caller' ||
            value.cancellationKind === 'deadline'
        );
    }
    return (
        value.messageKind === 'execute-operation' &&
        value.inputBuffer instanceof ArrayBuffer &&
        typeof value.operationKind === 'number' &&
        Number.isSafeInteger(value.operationKind) &&
        value.operationKind > 0 &&
        value.operationKind <= maximumOperationKind &&
        typeof value.maximumDurationMilliseconds === 'number' &&
        Number.isSafeInteger(value.maximumDurationMilliseconds) &&
        value.maximumDurationMilliseconds > 0 &&
        value.maximumDurationMilliseconds <=
            maximumOperationDurationMilliseconds
    );
};

const isWorkerResponseMessage = (
    value: unknown,
): value is WorkerResponseMessage => {
    if (
        !isPlainRecord(value) ||
        !isSafePositiveInteger(value.requestIdentifier)
    ) {
        return false;
    }
    if (value.messageKind === 'operation-completed') {
        return Object.prototype.hasOwnProperty.call(value, 'value');
    }
    if (value.messageKind === 'operation-refused') {
        return isRefusalReason(value.refusalReason);
    }
    return (
        value.messageKind === 'operation-failed' &&
        (value.failureKind === 'cancelled' ||
            value.failureKind === 'internal' ||
            value.failureKind === 'resource')
    );
};

const validateBoundedWorkerResult = (value: unknown): void => {
    let measuredByteLength = 0;
    const activeContainers = new WeakSet<object>();
    const charge = (byteLength: number): void => {
        measuredByteLength += byteLength;
        if (measuredByteLength > maximumWorkerResultByteLength) {
            throw new KernelWorkerInternalError(
                'The cryptographic worker result exceeds its byte limit.',
            );
        }
    };

    const visit = (current: unknown, depth: number): void => {
        if (depth > maximumWorkerResultNestingDepth) {
            throw new KernelWorkerInternalError(
                'The cryptographic worker result exceeds its nesting limit.',
            );
        }
        if (current === null) {
            charge(4);
            return;
        }
        if (typeof current === 'string') {
            charge(new TextEncoder().encode(current).byteLength + 2);
            return;
        }
        if (typeof current === 'boolean') {
            charge(current ? 4 : 5);
            return;
        }
        if (typeof current === 'number') {
            if (!Number.isFinite(current) || !Number.isSafeInteger(current)) {
                throw new KernelWorkerInternalError(
                    'The cryptographic worker result contains an unsafe number.',
                );
            }
            charge(String(current).length);
            return;
        }
        if (typeof current !== 'object') {
            throw new KernelWorkerInternalError(
                'The cryptographic worker result is not bounded JSON data.',
            );
        }
        if (
            current instanceof ArrayBuffer ||
            ArrayBuffer.isView(current) ||
            (typeof Blob !== 'undefined' && current instanceof Blob)
        ) {
            throw new KernelWorkerInternalError(
                'The cryptographic worker cannot return binary buffers to the main thread.',
            );
        }
        if (activeContainers.has(current)) {
            throw new KernelWorkerInternalError(
                'The cryptographic worker result contains a cycle.',
            );
        }
        const ownKeys = Reflect.ownKeys(current);
        if (ownKeys.some((key) => typeof key !== 'string')) {
            throw new KernelWorkerInternalError(
                'The cryptographic worker result contains a symbol-keyed field.',
            );
        }
        activeContainers.add(current);
        try {
            if (Array.isArray(current)) {
                charge(2 + Math.max(0, current.length - 1));
                if (
                    ownKeys.length !== current.length + 1 ||
                    !Object.prototype.hasOwnProperty.call(current, 'length')
                ) {
                    throw new KernelWorkerInternalError(
                        'The cryptographic worker result contains a sparse or decorated array.',
                    );
                }
                for (
                    let elementIndex = 0;
                    elementIndex < current.length;
                    elementIndex += 1
                ) {
                    if (
                        !Object.prototype.hasOwnProperty.call(
                            current,
                            elementIndex,
                        )
                    ) {
                        throw new KernelWorkerInternalError(
                            'The cryptographic worker result contains a sparse or decorated array.',
                        );
                    }
                    visit(current[elementIndex], depth + 1);
                }
                return;
            }
            if (!isPlainRecord(current)) {
                throw new KernelWorkerInternalError(
                    'The cryptographic worker result contains a non-plain object.',
                );
            }
            const descriptors = Object.getOwnPropertyDescriptors(current);
            charge(2 + Math.max(0, Object.keys(descriptors).length - 1));
            for (const [fieldName, descriptor] of Object.entries(descriptors)) {
                if (
                    descriptor.enumerable !== true ||
                    'get' in descriptor ||
                    'set' in descriptor
                ) {
                    throw new KernelWorkerInternalError(
                        'The cryptographic worker result contains a non-data property.',
                    );
                }
                charge(new TextEncoder().encode(fieldName).byteLength + 3);
                visit(descriptor.value, depth + 1);
            }
        } finally {
            activeContainers.delete(current);
        }
    };

    visit(value, 0);
};

/**
 * Owns one verified dedicated worker and permits exactly one transferred
 * binary operation at a time. This module is internal runtime plumbing and is
 * intentionally absent from package entry points.
 */
export class OwnedKernelWorkerChannel {
    readonly #worker: WorkerLike;
    readonly #trace?: (event: KernelWorkerTraceEvent) => void;
    readonly #messageListener: (event: MessageEvent<unknown>) => void;
    readonly #errorListener: () => void;
    #closed = false;
    #inFlightOperation: InFlightOperation | undefined;
    #nextRequestIdentifier = 1;
    #counters: MutableKernelWorkerCounters = {
        cancellationCount: 0,
        completedOperationCount: 0,
        cryptographicRefusalCount: 0,
        internalFailureCount: 0,
        operationCount: 0,
        resourceFailureCount: 0,
        telemetryFailureCount: 0,
        transferredInputByteCount: 0,
    };

    constructor(
        worker: WorkerLike,
        options: OwnedKernelWorkerChannelOptions = {},
    ) {
        this.#worker = worker;
        this.#trace = options.trace;
        this.#messageListener = (event): void => {
            this.#handleWorkerMessage(event.data);
        };
        this.#errorListener = (): void => {
            this.#failInternally(
                'The cryptographic worker emitted an unhandled error.',
            );
        };
        worker.addEventListener('message', this.#messageListener);
        worker.addEventListener('error', this.#errorListener);
        worker.addEventListener('messageerror', this.#errorListener);
    }

    runOperation<Result>(input: KernelWorkerOperationInput): Promise<Result> {
        if (this.#closed) {
            return Promise.reject(
                new KernelWorkerInternalError(
                    'The cryptographic worker channel is closed.',
                ),
            );
        }
        if (this.#inFlightOperation !== undefined) {
            return Promise.reject(
                new KernelWorkerInternalError(
                    'The single cryptographic worker cannot run overlapping operations.',
                ),
            );
        }
        validateOperationKind(input.operationKind);
        validateOperationDuration(input.maximumDurationMilliseconds);
        if (!(input.inputBuffer instanceof ArrayBuffer)) {
            return Promise.reject(
                new KernelWorkerResourceError(
                    'The cryptographic worker input must own an ArrayBuffer.',
                ),
            );
        }
        const inputByteLength = input.inputBuffer.byteLength;
        if (
            inputByteLength === 0 ||
            inputByteLength > foundationProfile.maximumCopiedBufferByteLength
        ) {
            return Promise.reject(
                new KernelWorkerResourceError(
                    'The cryptographic worker input is outside the copied-buffer profile.',
                ),
            );
        }
        if (input.abortSignal?.aborted === true) {
            return Promise.reject(new KernelWorkerCancellationError());
        }

        const requestIdentifier = this.#takeRequestIdentifier();
        return new Promise<Result>((resolve, reject) => {
            const deadlineTimer = setTimeout(() => {
                this.#requestCancellation('deadline');
            }, input.maximumDurationMilliseconds);
            const abortListener =
                input.abortSignal === undefined
                    ? undefined
                    : (): void => {
                          this.#requestCancellation('caller');
                      };
            const inFlightOperation: InFlightOperation = {
                ...(abortListener === undefined ? {} : { abortListener }),
                ...(input.abortSignal === undefined
                    ? {}
                    : { abortSignal: input.abortSignal }),
                deadlineTimer,
                operationKind: input.operationKind,
                reject,
                requestIdentifier,
                resolve: (value): void => {
                    resolve(value as Result);
                },
                startMonotonicMilliseconds: performance.now(),
            };
            this.#inFlightOperation = inFlightOperation;
            if (
                input.abortSignal !== undefined &&
                abortListener !== undefined
            ) {
                input.abortSignal.addEventListener('abort', abortListener, {
                    once: true,
                });
            }
            this.#chargeCounter('operationCount', 1);
            this.#chargeCounter('transferredInputByteCount', inputByteLength);
            this.#emitTrace({
                eventKind: 'operation-started',
                inputByteLength,
                operationKind: input.operationKind,
            });

            const message: ExecuteOperationMessage = {
                inputBuffer: input.inputBuffer,
                maximumDurationMilliseconds: input.maximumDurationMilliseconds,
                messageKind: 'execute-operation',
                operationKind: input.operationKind,
                requestIdentifier,
            };
            try {
                this.#worker.postMessage(message, [input.inputBuffer]);
            } catch {
                this.#finishOperation(
                    new KernelWorkerInternalError(
                        'The cryptographic worker input transfer failed.',
                    ),
                );
            }
        });
    }

    counterSnapshot(): KernelWorkerCounterSnapshot {
        return Object.freeze({ ...this.#counters });
    }

    close(): void {
        if (this.#closed) {
            return;
        }
        this.#closed = true;
        this.#worker.removeEventListener('message', this.#messageListener);
        this.#worker.removeEventListener('error', this.#errorListener);
        this.#worker.removeEventListener('messageerror', this.#errorListener);
        this.#worker.terminate();
        if (this.#inFlightOperation !== undefined) {
            this.#finishOperation(
                new KernelWorkerInternalError(
                    'The cryptographic worker channel closed during an operation.',
                ),
            );
        }
    }

    #takeRequestIdentifier(): number {
        const requestIdentifier = this.#nextRequestIdentifier;
        this.#nextRequestIdentifier += 1;
        if (!Number.isSafeInteger(this.#nextRequestIdentifier)) {
            this.#nextRequestIdentifier = 1;
        }
        return requestIdentifier;
    }

    #handleWorkerMessage(message: unknown): void {
        const operation = this.#inFlightOperation;
        if (operation === undefined) {
            this.#failInternally(
                'The cryptographic worker returned an unsolicited message.',
            );
            return;
        }
        if (!isWorkerResponseMessage(message)) {
            this.#failInternally(
                'The cryptographic worker returned a malformed message.',
            );
            return;
        }
        if (message.requestIdentifier !== operation.requestIdentifier) {
            this.#failInternally(
                'The cryptographic worker returned a mismatched request identifier.',
            );
            return;
        }
        if (operation.cancellationKind !== undefined) {
            this.#finishOperation(
                operation.cancellationKind === 'deadline'
                    ? new KernelWorkerResourceError(
                          'The cryptographic worker exceeded its monotonic deadline.',
                      )
                    : new KernelWorkerCancellationError(),
            );
            return;
        }

        switch (message.messageKind) {
            case 'operation-completed':
                try {
                    validateBoundedWorkerResult(message.value);
                } catch {
                    this.#failInternally(
                        'The cryptographic worker returned a non-bounded result.',
                    );
                    return;
                }
                this.#finishOperation(undefined, message.value);
                return;
            case 'operation-refused':
                this.#finishOperation(
                    new KernelWorkerCryptographicRefusalError(
                        message.refusalReason,
                    ),
                );
                return;
            case 'operation-failed':
                this.#finishOperation(
                    message.failureKind === 'resource'
                        ? new KernelWorkerResourceError()
                        : message.failureKind === 'cancelled'
                          ? new KernelWorkerCancellationError()
                          : new KernelWorkerInternalError(),
                );
        }
    }

    #requestCancellation(cancellationKind: 'caller' | 'deadline'): void {
        const operation = this.#inFlightOperation;
        if (
            operation === undefined ||
            operation.cancellationKind !== undefined
        ) {
            return;
        }
        operation.cancellationKind = cancellationKind;
        const message: CancelOperationMessage = {
            cancellationKind,
            messageKind: 'cancel-operation',
            requestIdentifier: operation.requestIdentifier,
        };
        try {
            this.#worker.postMessage(message);
        } catch {
            this.#failInternally(
                'The cryptographic worker cancellation message failed.',
            );
            return;
        }
        operation.cancellationTerminationTimer = setTimeout(() => {
            this.#failInternally(
                'The cryptographic worker did not acknowledge cancellation.',
            );
        }, cancellationTerminationDelayMilliseconds);
    }

    #failInternally(message: string): void {
        if (!this.#closed) {
            this.#closed = true;
            this.#worker.removeEventListener('message', this.#messageListener);
            this.#worker.removeEventListener('error', this.#errorListener);
            this.#worker.removeEventListener(
                'messageerror',
                this.#errorListener,
            );
            this.#worker.terminate();
        }
        if (this.#inFlightOperation !== undefined) {
            this.#finishOperation(new KernelWorkerInternalError(message));
        }
    }

    #finishOperation(error?: Error, value?: unknown): void {
        const operation = this.#inFlightOperation;
        if (operation === undefined) {
            return;
        }
        this.#inFlightOperation = undefined;
        clearTimeout(operation.deadlineTimer);
        if (operation.cancellationTerminationTimer !== undefined) {
            clearTimeout(operation.cancellationTerminationTimer);
        }
        if (
            operation.abortSignal !== undefined &&
            operation.abortListener !== undefined
        ) {
            operation.abortSignal.removeEventListener(
                'abort',
                operation.abortListener,
            );
        }
        if (error === undefined) {
            this.#chargeCounter('completedOperationCount', 1);
            operation.resolve(value);
        } else {
            if (error instanceof KernelWorkerCryptographicRefusalError) {
                this.#chargeCounter('cryptographicRefusalCount', 1);
            } else if (error instanceof KernelWorkerResourceError) {
                this.#chargeCounter('resourceFailureCount', 1);
            } else if (error instanceof KernelWorkerCancellationError) {
                this.#chargeCounter('cancellationCount', 1);
            } else {
                this.#chargeCounter('internalFailureCount', 1);
            }
            operation.reject(error);
        }
        this.#emitTrace({
            elapsedMilliseconds: Math.max(
                0,
                performance.now() - operation.startMonotonicMilliseconds,
            ),
            eventKind: 'operation-finished',
            operationKind: operation.operationKind,
        });
    }

    #emitTrace(event: KernelWorkerTraceEvent): void {
        try {
            this.#trace?.(event);
        } catch {
            // Telemetry is deliberately non-authoritative. Preserve visibility
            // through a bounded counter without changing the operation result.
            this.#chargeCounter('telemetryFailureCount', 1);
        }
    }

    #chargeCounter(
        counterName: keyof MutableKernelWorkerCounters,
        amount: number,
    ): void {
        const nextValue = this.#counters[counterName] + amount;
        if (!Number.isSafeInteger(nextValue)) {
            this.#failInternally(
                'The cryptographic worker instrumentation counter overflowed.',
            );
            return;
        }
        this.#counters[counterName] = nextValue;
    }
}

export type KernelWorkerOperationContext = Readonly<{
    abortSignal: AbortSignal;
    inputBytes: Uint8Array;
    operationKind: number;
}>;

export type KernelWorkerOperationHandler = (
    context: KernelWorkerOperationContext,
) => unknown;

type DedicatedWorkerScope = Readonly<{
    addEventListener(
        type: 'message',
        listener: (event: MessageEvent<unknown>) => void,
    ): void;
    postMessage(message: WorkerResponseMessage): void;
    removeEventListener(
        type: 'message',
        listener: (event: MessageEvent<unknown>) => void,
    ): void;
}>;

/** Installs the worker half over a registry frozen into verified worker bytes. */
export const installOwnedKernelWorkerRuntime = (
    workerScope: DedicatedWorkerScope,
    operationHandlers: ReadonlyMap<number, KernelWorkerOperationHandler>,
): (() => void) => {
    for (const operationKind of operationHandlers.keys()) {
        validateOperationKind(operationKind);
    }
    let activeOperation:
        | {
              abortController: AbortController;
              cancellationKind?: 'caller' | 'deadline';
              requestIdentifier: number;
          }
        | undefined;

    const sendFailure = (
        requestIdentifier: number,
        failureKind: 'cancelled' | 'internal' | 'resource',
    ): void => {
        workerScope.postMessage({
            failureKind,
            messageKind: 'operation-failed',
            requestIdentifier,
        });
    };

    const listener = (event: MessageEvent<unknown>): void => {
        const message = event.data;
        if (!isWorkerRequestMessage(message)) {
            if (
                isPlainRecord(message) &&
                isSafePositiveInteger(message.requestIdentifier)
            ) {
                sendFailure(message.requestIdentifier, 'internal');
            }
            return;
        }
        if (message.messageKind === 'cancel-operation') {
            if (
                activeOperation?.requestIdentifier === message.requestIdentifier
            ) {
                activeOperation.cancellationKind = message.cancellationKind;
                activeOperation.abortController.abort();
            }
            return;
        }
        if (activeOperation !== undefined) {
            sendFailure(message.requestIdentifier, 'internal');
            return;
        }

        const handler = operationHandlers.get(message.operationKind);
        if (
            handler === undefined ||
            message.inputBuffer.byteLength === 0 ||
            message.inputBuffer.byteLength >
                foundationProfile.maximumCopiedBufferByteLength
        ) {
            sendFailure(message.requestIdentifier, 'resource');
            return;
        }
        const abortController = new AbortController();
        activeOperation = {
            abortController,
            requestIdentifier: message.requestIdentifier,
        };
        const deadlineTimer = setTimeout(() => {
            if (
                activeOperation?.requestIdentifier === message.requestIdentifier
            ) {
                activeOperation.cancellationKind = 'deadline';
                activeOperation.abortController.abort();
            }
        }, message.maximumDurationMilliseconds);
        const inputBytes = new Uint8Array(message.inputBuffer);

        const execute = async (): Promise<void> => {
            try {
                const value = await handler({
                    abortSignal: abortController.signal,
                    inputBytes,
                    operationKind: message.operationKind,
                });
                const cancellationKind = activeOperation?.cancellationKind;
                if (cancellationKind !== undefined) {
                    sendFailure(
                        message.requestIdentifier,
                        cancellationKind === 'deadline'
                            ? 'resource'
                            : 'cancelled',
                    );
                    return;
                }
                validateBoundedWorkerResult(value);
                workerScope.postMessage({
                    messageKind: 'operation-completed',
                    requestIdentifier: message.requestIdentifier,
                    value,
                });
            } catch (error) {
                const cancellationKind =
                    activeOperation?.requestIdentifier ===
                    message.requestIdentifier
                        ? activeOperation.cancellationKind
                        : undefined;
                if (cancellationKind !== undefined) {
                    sendFailure(
                        message.requestIdentifier,
                        cancellationKind === 'deadline'
                            ? 'resource'
                            : 'cancelled',
                    );
                } else if (
                    error instanceof KernelWorkerCryptographicRefusalError
                ) {
                    workerScope.postMessage({
                        messageKind: 'operation-refused',
                        refusalReason: error.refusalReason,
                        requestIdentifier: message.requestIdentifier,
                    });
                } else if (error instanceof KernelWorkerResourceError) {
                    sendFailure(message.requestIdentifier, 'resource');
                } else if (error instanceof KernelWorkerCancellationError) {
                    sendFailure(message.requestIdentifier, 'cancelled');
                } else {
                    sendFailure(message.requestIdentifier, 'internal');
                }
            } finally {
                inputBytes.fill(0);
                clearTimeout(deadlineTimer);
                if (
                    activeOperation?.requestIdentifier ===
                    message.requestIdentifier
                ) {
                    activeOperation = undefined;
                }
            }
        };
        void execute();
    };

    workerScope.addEventListener('message', listener);
    return (): void => {
        activeOperation?.abortController.abort();
        activeOperation = undefined;
        workerScope.removeEventListener('message', listener);
    };
};
