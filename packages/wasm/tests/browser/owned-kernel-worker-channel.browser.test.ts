import { afterEach, describe, expect, it } from 'vitest';

import {
    KernelWorkerCancellationError,
    OwnedKernelWorkerChannel,
} from '#packages/wasm/src/owned-kernel-worker-channel';

const workerSource = `
let pendingRequest;
self.onmessage = (event) => {
    const message = event.data;
    if (message.messageKind === 'execute-operation') {
        pendingRequest = message.requestIdentifier;
        if (message.operationKind === 1) {
            const input = new Uint8Array(message.inputBuffer);
            let sum = 0;
            for (const value of input) sum += value;
            input.fill(0);
            self.postMessage({
                messageKind: 'operation-completed',
                requestIdentifier: message.requestIdentifier,
                value: { inputByteLength: input.byteLength, sum },
            });
        }
        return;
    }
    if (
        message.messageKind === 'cancel-operation' &&
        message.requestIdentifier === pendingRequest
    ) {
        self.postMessage({
            failureKind: 'cancelled',
            messageKind: 'operation-failed',
            requestIdentifier: message.requestIdentifier,
        });
        pendingRequest = undefined;
    }
};
`;

const objectUrls: string[] = [];
const createWorker = (): Worker => {
    const objectUrl = URL.createObjectURL(
        new Blob([workerSource], { type: 'text/javascript' }),
    );
    objectUrls.push(objectUrl);
    return new Worker(objectUrl);
};

afterEach(() => {
    for (const objectUrl of objectUrls.splice(0)) {
        URL.revokeObjectURL(objectUrl);
    }
});

describe('Owned kernel worker channel in browsers', () => {
    it('transfers input ownership without returning a binary buffer', async () => {
        const channel = new OwnedKernelWorkerChannel(createWorker());
        const inputBuffer = Uint8Array.of(3, 5, 8, 13).buffer;
        const resultPromise = channel.runOperation<{
            readonly inputByteLength: number;
            readonly sum: number;
        }>({
            inputBuffer,
            maximumDurationMilliseconds: 5_000,
            operationKind: 1,
        });
        expect(inputBuffer.byteLength).toBe(0);
        await expect(resultPromise).resolves.toEqual({
            inputByteLength: 4,
            sum: 29,
        });
        expect(channel.counterSnapshot()).toMatchObject({
            completedOperationCount: 1,
            operationCount: 1,
            transferredInputByteCount: 4,
        });
        channel.close();
    });

    it('cancels cooperatively and never accepts a late operation result', async () => {
        const channel = new OwnedKernelWorkerChannel(createWorker());
        const abortController = new AbortController();
        const resultPromise = channel.runOperation({
            abortSignal: abortController.signal,
            inputBuffer: Uint8Array.of(21).buffer,
            maximumDurationMilliseconds: 5_000,
            operationKind: 2,
        });
        abortController.abort();
        await expect(resultPromise).rejects.toBeInstanceOf(
            KernelWorkerCancellationError,
        );
        expect(channel.counterSnapshot()).toMatchObject({
            cancellationCount: 1,
            completedOperationCount: 0,
        });
        channel.close();
    });
});
