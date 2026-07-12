import { describe, expect, it } from 'vitest';

import {
    installOwnedKernelWorkerRuntime,
    KernelWorkerCancellationError,
    KernelWorkerCryptographicRefusalError,
    KernelWorkerInternalError,
    KernelWorkerResourceError,
    OwnedKernelWorkerChannel,
    type KernelWorkerOperationHandler,
} from '#packages/wasm/src/owned-kernel-worker-channel';

class FakeWorker extends EventTarget {
    readonly postedMessages: unknown[] = [];
    terminated = false;
    onPostMessage?: (message: unknown) => void;

    postMessage(message: unknown): void {
        this.postedMessages.push(message);
        this.onPostMessage?.(message);
    }

    terminate(): void {
        this.terminated = true;
    }

    emitMessage(message: unknown): void {
        this.dispatchEvent(new MessageEvent('message', { data: message }));
    }
}

const executeMessage = (
    worker: FakeWorker,
): {
    readonly requestIdentifier: number;
} => {
    const message = worker.postedMessages[0];
    if (
        typeof message !== 'object' ||
        message === null ||
        !('requestIdentifier' in message) ||
        typeof message.requestIdentifier !== 'number'
    ) {
        throw new Error('expected one execute message');
    }
    return { requestIdentifier: message.requestIdentifier };
};

describe('Owned kernel worker channel', () => {
    it('serializes one operation, exposes bounded counters, and rejects overlap', async () => {
        const worker = new FakeWorker();
        const traces: unknown[] = [];
        const channel = new OwnedKernelWorkerChannel(worker, {
            trace: (event) => traces.push(event),
        });
        const resultPromise = channel.runOperation<{ readonly sum: number }>({
            inputBuffer: Uint8Array.of(3, 5, 8).buffer,
            maximumDurationMilliseconds: 5_000,
            operationKind: 0x1302,
        });
        await expect(
            channel.runOperation({
                inputBuffer: Uint8Array.of(1).buffer,
                maximumDurationMilliseconds: 5_000,
                operationKind: 0x1302,
            }),
        ).rejects.toBeInstanceOf(KernelWorkerInternalError);

        const { requestIdentifier } = executeMessage(worker);
        worker.emitMessage({
            messageKind: 'operation-completed',
            requestIdentifier,
            value: { sum: 16 },
        });
        await expect(resultPromise).resolves.toEqual({ sum: 16 });
        expect(channel.counterSnapshot()).toEqual({
            cancellationCount: 0,
            completedOperationCount: 1,
            cryptographicRefusalCount: 0,
            internalFailureCount: 0,
            operationCount: 1,
            resourceFailureCount: 0,
            telemetryFailureCount: 0,
            transferredInputByteCount: 3,
        });
        expect(traces).toHaveLength(2);
        channel.close();
        expect(worker.terminated).toBe(true);
    });

    it('keeps throwing telemetry isolated from operation settlement', async () => {
        const worker = new FakeWorker();
        const channel = new OwnedKernelWorkerChannel(worker, {
            trace: () => {
                throw new Error('telemetry sink failed');
            },
        });
        const resultPromise = channel.runOperation<{ readonly value: number }>({
            inputBuffer: Uint8Array.of(1).buffer,
            maximumDurationMilliseconds: 5_000,
            operationKind: 7,
        });
        const { requestIdentifier } = executeMessage(worker);
        worker.emitMessage({
            messageKind: 'operation-completed',
            requestIdentifier,
            value: { value: 11 },
        });

        await expect(resultPromise).resolves.toEqual({ value: 11 });
        expect(channel.counterSnapshot()).toMatchObject({
            completedOperationCount: 1,
            internalFailureCount: 0,
            telemetryFailureCount: 2,
        });
        channel.close();
    });

    it('keeps cryptographic refusal, resource failure, and cancellation distinct', async () => {
        const runResponse = async (
            response: (requestIdentifier: number) => unknown,
        ): Promise<unknown> => {
            const worker = new FakeWorker();
            const channel = new OwnedKernelWorkerChannel(worker);
            const promise = channel.runOperation({
                inputBuffer: Uint8Array.of(1, 2).buffer,
                maximumDurationMilliseconds: 5_000,
                operationKind: 0x1302,
            });
            worker.emitMessage(
                response(executeMessage(worker).requestIdentifier),
            );
            return promise;
        };

        await expect(
            runResponse((requestIdentifier) => ({
                messageKind: 'operation-refused',
                refusalReason: 'invalidProof',
                requestIdentifier,
            })),
        ).rejects.toMatchObject({
            constructor: KernelWorkerCryptographicRefusalError,
            refusalReason: 'invalidProof',
        });
        await expect(
            runResponse((requestIdentifier) => ({
                failureKind: 'resource',
                messageKind: 'operation-failed',
                requestIdentifier,
            })),
        ).rejects.toBeInstanceOf(KernelWorkerResourceError);

        const worker = new FakeWorker();
        const channel = new OwnedKernelWorkerChannel(worker);
        const abortController = new AbortController();
        const cancelledPromise = channel.runOperation({
            abortSignal: abortController.signal,
            inputBuffer: Uint8Array.of(9).buffer,
            maximumDurationMilliseconds: 5_000,
            operationKind: 0x1302,
        });
        const { requestIdentifier } = executeMessage(worker);
        abortController.abort();
        worker.emitMessage({
            failureKind: 'cancelled',
            messageKind: 'operation-failed',
            requestIdentifier,
        });
        await expect(cancelledPromise).rejects.toBeInstanceOf(
            KernelWorkerCancellationError,
        );
        expect(channel.counterSnapshot().cancellationCount).toBe(1);
    });

    it('terminates on malformed, unsolicited, or binary-return messages', async () => {
        const symbolKeyedResult = { visible: 1 } as Record<
            PropertyKey,
            unknown
        >;
        symbolKeyedResult[Symbol('hidden')] = Uint8Array.of(9);
        const sparseResult: unknown[] = [];
        sparseResult.length = 2;
        sparseResult[0] = 1;
        const decoratedResult = [1];
        Object.defineProperty(decoratedResult, 'hidden', {
            enumerable: false,
            value: 2,
        });
        for (const response of [
            { messageKind: 'unknown', requestIdentifier: 1 },
            {
                messageKind: 'operation-completed',
                requestIdentifier: 1,
                value: { leakedBytes: Uint8Array.of(7) },
            },
            {
                messageKind: 'operation-completed',
                requestIdentifier: 1,
                value: symbolKeyedResult,
            },
            {
                messageKind: 'operation-completed',
                requestIdentifier: 1,
                value: sparseResult,
            },
            {
                messageKind: 'operation-completed',
                requestIdentifier: 1,
                value: decoratedResult,
            },
        ]) {
            const worker = new FakeWorker();
            const channel = new OwnedKernelWorkerChannel(worker);
            const promise = channel.runOperation({
                inputBuffer: Uint8Array.of(1).buffer,
                maximumDurationMilliseconds: 5_000,
                operationKind: 7,
            });
            worker.emitMessage(response);
            await expect(promise).rejects.toBeInstanceOf(
                KernelWorkerInternalError,
            );
            expect(worker.terminated).toBe(true);
        }
    });
});

describe('Owned kernel worker runtime', () => {
    it('runs only registered operations, wipes transferred input, and maps handler failures', async () => {
        const listeners = new Set<(event: MessageEvent<unknown>) => void>();
        const responses: unknown[] = [];
        const workerScope = {
            addEventListener: (
                _type: 'message',
                listener: (event: MessageEvent<unknown>) => void,
            ): void => {
                listeners.add(listener);
            },
            postMessage: (message: unknown): void => {
                responses.push(message);
            },
            removeEventListener: (
                _type: 'message',
                listener: (event: MessageEvent<unknown>) => void,
            ): void => {
                listeners.delete(listener);
            },
        };
        let observedInput: Uint8Array | undefined;
        const handlers = new Map<number, KernelWorkerOperationHandler>([
            [
                9,
                ({ inputBytes }) => {
                    observedInput = inputBytes;
                    return {
                        byteLength: inputBytes.byteLength,
                        sum: inputBytes.reduce(
                            (accumulated, value) => accumulated + value,
                            0,
                        ),
                    };
                },
            ],
            [
                10,
                () => {
                    throw new KernelWorkerCryptographicRefusalError(
                        'wrongHashOrRoot',
                    );
                },
            ],
        ]);
        const uninstall = installOwnedKernelWorkerRuntime(
            workerScope,
            handlers,
        );
        const send = (message: unknown): void => {
            for (const listener of listeners) {
                listener(new MessageEvent('message', { data: message }));
            }
        };

        const inputBuffer = Uint8Array.of(2, 4, 6).buffer;
        send({
            inputBuffer,
            maximumDurationMilliseconds: 5_000,
            messageKind: 'execute-operation',
            operationKind: 9,
            requestIdentifier: 1,
        });
        await expect.poll(() => responses.length).toBe(1);
        expect(responses[0]).toEqual({
            messageKind: 'operation-completed',
            requestIdentifier: 1,
            value: { byteLength: 3, sum: 12 },
        });
        expect(Array.from(observedInput ?? [])).toEqual([0, 0, 0]);

        send({
            inputBuffer: Uint8Array.of(1).buffer,
            maximumDurationMilliseconds: 5_000,
            messageKind: 'execute-operation',
            operationKind: 10,
            requestIdentifier: 2,
        });
        await expect.poll(() => responses.length).toBe(2);
        expect(responses[1]).toEqual({
            messageKind: 'operation-refused',
            refusalReason: 'wrongHashOrRoot',
            requestIdentifier: 2,
        });
        uninstall();
        expect(listeners.size).toBe(0);
    });

    it('classifies a handler abort caused by its worker deadline as a resource failure', async () => {
        const listeners = new Set<(event: MessageEvent<unknown>) => void>();
        const responses: unknown[] = [];
        const workerScope = {
            addEventListener: (
                _type: 'message',
                listener: (event: MessageEvent<unknown>) => void,
            ): void => {
                listeners.add(listener);
            },
            postMessage: (message: unknown): void => {
                responses.push(message);
            },
            removeEventListener: (
                _type: 'message',
                listener: (event: MessageEvent<unknown>) => void,
            ): void => {
                listeners.delete(listener);
            },
        };
        const handlers = new Map<number, KernelWorkerOperationHandler>([
            [
                12,
                ({ abortSignal }) =>
                    new Promise((_resolve, reject) => {
                        abortSignal.addEventListener(
                            'abort',
                            () => {
                                const abortError = new Error('aborted');
                                abortError.name = 'AbortError';
                                reject(abortError);
                            },
                            { once: true },
                        );
                    }),
            ],
        ]);
        const uninstall = installOwnedKernelWorkerRuntime(
            workerScope,
            handlers,
        );
        for (const listener of listeners) {
            listener(
                new MessageEvent('message', {
                    data: {
                        inputBuffer: Uint8Array.of(1).buffer,
                        maximumDurationMilliseconds: 1,
                        messageKind: 'execute-operation',
                        operationKind: 12,
                        requestIdentifier: 3,
                    },
                }),
            );
        }

        await expect.poll(() => responses.length).toBe(1);
        expect(responses[0]).toEqual({
            failureKind: 'resource',
            messageKind: 'operation-failed',
            requestIdentifier: 3,
        });
        uninstall();
    });
});
