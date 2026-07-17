import { foundationProfile } from '@sealed-lattice/types';
import { afterEach, describe, expect, it } from 'vitest';

import { bgvCanonicalStreamFamilies } from '#packages/wasm/src/bgv-canonical-stream-runtime';
import { canonicalStreamDomains } from '#packages/wasm/src/canonical-stream-runtime';
import {
    runCanonicalStreamBrowserWorker,
    terminateCanonicalStreamBrowserWorkers,
} from '#packages/wasm/tests/support/canonical-stream-browser-worker-runner';

const run = () =>
    runCanonicalStreamBrowserWorker({
        byteSeed: 53,
        chunkIndexMultiplier: 17,
        operationName: 'The BGV stream',
        requestIdentifier: 7,
        startMessage: {
            bgvFamily: bgvCanonicalStreamFamilies.publicKeyShare,
            cancelAfterFirstChunk: false,
            command: 'startBgv',
            materialRoot: '71'.repeat(64),
            streamDomain: canonicalStreamDomains.publicKeyShareProof,
            totalByteLength: foundationProfile.streamChunkByteLength + 31,
        },
    });

afterEach(() => {
    terminateCanonicalStreamBrowserWorkers();
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
});
