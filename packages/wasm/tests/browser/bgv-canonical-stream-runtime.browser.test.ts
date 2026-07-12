import { foundationProfile } from '@sealed-lattice/types';
import { afterEach, describe, expect, it } from 'vitest';

import { bgvCanonicalStreamFamilies } from '#packages/wasm/src/bgv-canonical-stream-runtime';
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
    failureKind?: 'cancelled' | 'internal' | 'refused' | 'resource';
    messageKind: 'completed' | 'failed';
    refusalReason?: string;
    requestIdentifier: number;
}>;

const workers = new Set<Worker>();

const isRecord = (value: unknown): value is Record<string, unknown> =>
    typeof value === 'object' && value !== null && !Array.isArray(value);

const isPullMessage = (value: unknown): value is PullMessage =>
    isRecord(value) &&
    value.messageKind === 'pull' &&
    (value.phase === 'read' || value.phase === 'write') &&
    Number.isSafeInteger(value.chunkIndex) &&
    Number.isSafeInteger(value.expectedByteLength);

const isResultMessage = (value: unknown): value is ResultMessage =>
    isRecord(value) &&
    (value.messageKind === 'completed' || value.messageKind === 'failed');

const chunk = (
    chunkIndex: number,
    byteLength: number,
    substituted: boolean,
): ArrayBuffer => {
    const bytes = Uint8Array.from(
        { length: byteLength },
        (_, byteIndex) => (53 + chunkIndex * 17 + byteIndex * 131) & 0xff,
    );
    if (substituted) {
        bytes[0] ^= 1;
    }
    return bytes.buffer;
};

const run = (
    substituteReadChunkIndex?: number,
): Promise<{
    maximumOutstandingPullCount: number;
    pullOrder: readonly string[];
    result: ResultMessage;
}> => {
    const worker = new Worker(
        new URL(
            '../support/canonical-stream-browser-worker.ts',
            import.meta.url,
        ),
        { type: 'module' },
    );
    workers.add(worker);
    const requestIdentifier = 7;
    const pullOrder: string[] = [];
    let outstandingPullCount = 0;
    let maximumOutstandingPullCount = 0;

    return new Promise<{
        maximumOutstandingPullCount: number;
        pullOrder: readonly string[];
        result: ResultMessage;
    }>((resolve, reject) => {
        worker.addEventListener(
            'error',
            (event) =>
                reject(
                    event.error instanceof Error
                        ? event.error
                        : new Error('The BGV stream worker failed.'),
                ),
            { once: true },
        );
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
                    const bytes = chunk(
                        message.chunkIndex,
                        message.expectedByteLength,
                        message.phase === 'read' &&
                            message.chunkIndex === substituteReadChunkIndex,
                    );
                    worker.postMessage(
                        {
                            buffer: bytes,
                            chunkIndex: message.chunkIndex,
                            messageKind: 'chunk',
                            phase: message.phase,
                            requestIdentifier,
                        },
                        [bytes],
                    );
                    expect(bytes.byteLength).toBe(0);
                }
                outstandingPullCount -= 1;
                return;
            }
            if (!isResultMessage(message)) {
                reject(new Error('The BGV stream worker returned bad data.'));
                return;
            }
            resolve({
                maximumOutstandingPullCount,
                pullOrder,
                result: message,
            });
        });
        worker.postMessage({
            bgvFamily: bgvCanonicalStreamFamilies.publicKeyShare,
            cancelAfterFirstChunk: false,
            command: 'startBgv',
            materialRoot: '71'.repeat(64),
            requestIdentifier,
            streamDomain: canonicalStreamDomains.publicKeyShareProof,
            totalByteLength: foundationProfile.streamChunkByteLength + 31,
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

describe('BGV canonical stream boundary in a browser worker', () => {
    it('authenticates transferred binary chunks with one outstanding pull', async () => {
        const result = await run();

        expect(result.maximumOutstandingPullCount).toBe(1);
        expect(result.pullOrder).toEqual([
            'write:0',
            'write:1',
            'write:2',
            'read:0',
            'read:1',
            'read:2',
        ]);
        expect(result.result).toMatchObject({
            consumedByteLength: foundationProfile.streamChunkByteLength + 31,
            messageKind: 'completed',
        });
    });

    it('does not release a substituted chunk to the semantic sink', async () => {
        const result = await run(1);

        expect(result.result).toMatchObject({
            consumedByteLength: foundationProfile.streamChunkByteLength,
            failureKind: 'refused',
            messageKind: 'failed',
            refusalReason: 'wrongHashOrRoot',
        });
    });
});
