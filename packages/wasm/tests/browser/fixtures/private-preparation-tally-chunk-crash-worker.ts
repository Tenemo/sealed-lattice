/// <reference lib="webworker" />

import { installPrivatePreparationWorker } from '../../../src/private-preparation-worker-runtime.js';

const workerScope = globalThis as unknown as DedicatedWorkerGlobalScope;

installPrivatePreparationWorker(workerScope, {
    persistentStorageRequired: false,
    unpinnedKernelAllowed: true,
    afterDurableTallyChunkPersist: () => {
        workerScope.postMessage({
            testBoundary: 'tally-chunk-durably-persisted',
        });
        return new Promise<void>(() => undefined);
    },
});
