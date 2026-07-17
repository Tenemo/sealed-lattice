import { foundationProfile } from '@sealed-lattice/types';
import { afterEach, describe, expect, it } from 'vitest';

import { canonicalStreamDomains } from '#packages/wasm/src/canonical-stream-runtime';
import {
    runCanonicalStreamBrowserWorker,
    terminateCanonicalStreamBrowserWorkers,
} from '#packages/wasm/tests/support/canonical-stream-browser-worker-runner';

const runWorker = (input: {
    cancelAfterFirstChunk?: boolean;
    totalByteLength: number;
}) =>
    runCanonicalStreamBrowserWorker({
        byteSeed: 17,
        chunkIndexMultiplier: 29,
        operationName: 'The canonical stream',
        requestIdentifier: 1,
        startMessage: {
            cancelAfterFirstChunk: input.cancelAfterFirstChunk ?? false,
            command: 'start',
            streamDomain: canonicalStreamDomains.publicKeyShareProof,
            totalByteLength: input.totalByteLength,
        },
    });

afterEach(() => {
    terminateCanonicalStreamBrowserWorkers();
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
