import { foundationProfile } from '@sealed-lattice/types';
import { afterEach, describe, expect, it } from 'vitest';

import { canonicalStreamDomains } from '#packages/wasm/src/canonical-stream-runtime';

type PullMessage = Readonly<{
    chunkIndex: number;
    expectedByteLength: number;
    messageKind: 'pull';
    phase: 'read' | 'write';
    requestIdentifier: number;
}>;

type ResultMessage = Readonly<{
    consumedByteLength?: number;
    counters?: Readonly<Record<string, number>>;
    descriptorByteLength?: number;
    failureKind?: 'cancelled' | 'internal' | 'refused' | 'resource';
    messageKind: 'completed' | 'failed';
    refusalReason?: string;
    requestIdentifier: number;
}>;

type WorkerRun = Readonly<{
    maximumOutstandingPullCount: number;
    pullOrder: readonly string[];
    result: ResultMessage;
}>;

const workers = new Set<Worker>();

const isPlainRecord = (value: unknown): value is Record<string, unknown> =>
    typeof value === 'object' && value !== null && !Array.isArray(value);

const isPullMessage = (value: unknown): value is PullMessage =>
    isPlainRecord(value) &&
    value.messageKind === 'pull' &&
    (value.phase === 'read' || value.phase === 'write') &&
    Number.isSafeInteger(value.requestIdentifier) &&
    Number.isSafeInteger(value.chunkIndex) &&
    Number.isSafeInteger(value.expectedByteLength);

const isResultMessage = (value: unknown): value is ResultMessage =>
    isPlainRecord(value) &&
    (value.messageKind === 'completed' || value.messageKind === 'failed') &&
    Number.isSafeInteger(value.requestIdentifier);

const createChunk = (chunkIndex: number, byteLength: number): ArrayBuffer => {
    return Uint8Array.from(
        { length: byteLength },
        (_, byteIndex) => (17 + chunkIndex * 29 + byteIndex * 131) & 0xff,
    ).buffer;
};

const runWorker = (input: {
    cancelAfterFirstChunk?: boolean;
    totalByteLength: number;
}): Promise<WorkerRun> => {
    const worker = new Worker(
        new URL(
            '../support/canonical-stream-browser-worker.ts',
            import.meta.url,
        ),
        { type: 'module' },
    );
    workers.add(worker);
    const requestIdentifier = 1;
    const pullOrder: string[] = [];
    let outstandingPullCount = 0;
    let maximumOutstandingPullCount = 0;

    return new Promise<WorkerRun>((resolve, reject) => {
        worker.addEventListener(
            'error',
            (event) =>
                reject(
                    event.error instanceof Error
                        ? event.error
                        : new Error('The canonical stream worker failed.'),
                ),
            { once: true },
        );
        worker.addEventListener('messageerror', () => {
            reject(
                new Error(
                    'The canonical stream worker message could not be cloned.',
                ),
            );
        });
        worker.addEventListener('message', (event) => {
            const message = event.data as unknown;
            if (isPullMessage(message)) {
                outstandingPullCount += 1;
                maximumOutstandingPullCount = Math.max(
                    maximumOutstandingPullCount,
                    outstandingPullCount,
                );
                pullOrder.push(`${message.phase}:${message.chunkIndex}`);
                if (message.expectedByteLength === 0) {
                    worker.postMessage({
                        chunkIndex: message.chunkIndex,
                        messageKind: 'end',
                        phase: message.phase,
                        requestIdentifier,
                    });
                } else {
                    const buffer = createChunk(
                        message.chunkIndex,
                        message.expectedByteLength,
                    );
                    worker.postMessage(
                        {
                            buffer,
                            chunkIndex: message.chunkIndex,
                            messageKind: 'chunk',
                            phase: message.phase,
                            requestIdentifier,
                        },
                        [buffer],
                    );
                    expect(buffer.byteLength).toBe(0);
                }
                outstandingPullCount -= 1;
                return;
            }
            if (!isResultMessage(message)) {
                reject(
                    new Error(
                        'The canonical stream worker returned a malformed result.',
                    ),
                );
                return;
            }
            resolve({
                maximumOutstandingPullCount,
                pullOrder,
                result: message,
            });
        });
        worker.postMessage({
            cancelAfterFirstChunk: input.cancelAfterFirstChunk ?? false,
            command: 'start',
            requestIdentifier,
            streamDomain: canonicalStreamDomains.publicKeyShareProof,
            totalByteLength: input.totalByteLength,
        });
    }).finally(() => {
        worker.terminate();
        workers.delete(worker);
    });
};

afterEach(() => {
    for (const worker of workers) {
        worker.terminate();
    }
    workers.clear();
});

describe('Canonical stream runtime in a browser worker', () => {
    it('transfers one chunk at a time through real WASM without returning payload bytes', async () => {
        const totalByteLength = foundationProfile.streamChunkByteLength + 37;
        const run = await runWorker({ totalByteLength });

        expect(run.pullOrder).toEqual([
            'write:0',
            'write:1',
            'write:2',
            'read:0',
            'read:1',
            'read:2',
        ]);
        expect(run.maximumOutstandingPullCount).toBe(1);
        expect(run.result).toMatchObject({
            consumedByteLength: totalByteLength,
            messageKind: 'completed',
        });
        expect(run.result.counters).toMatchObject({
            activeSessionCount: 0,
            completedSessionCount: 2,
            javascriptToWasmPayloadCopyCount: 4,
            maximumObservedCopiedPayloadByteLength:
                foundationProfile.streamChunkByteLength,
            wasmToJavascriptPayloadCopyCount: 0,
        });
        expect(
            run.result.counters?.maximumObservedWasmMemoryByteLength,
        ).toBeLessThanOrEqual(foundationProfile.maximumWasmMemoryByteLength);
    });

    it('cancels deterministically and releases the worker-owned stream lease', async () => {
        const run = await runWorker({
            cancelAfterFirstChunk: true,
            totalByteLength: foundationProfile.streamChunkByteLength + 1,
        });

        expect(run.result).toMatchObject({
            failureKind: 'cancelled',
            messageKind: 'failed',
        });
        expect(run.result.counters).toMatchObject({
            activeSessionCount: 0,
            cancelledSessionCount: 1,
            completedSessionCount: 0,
        });
        expect(run.pullOrder).toEqual(['write:0']);
    });
});
