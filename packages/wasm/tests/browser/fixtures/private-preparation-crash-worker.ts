/// <reference lib="webworker" />

import { installPrivatePreparationWorker } from '../../../src/private-preparation-worker-runtime.js';

const workerScope = globalThis as unknown as DedicatedWorkerGlobalScope;

installPrivatePreparationWorker(workerScope, {
    persistentStorageRequired: false,
    unpinnedKernelAllowed: true,
    afterDurableConsume: () => {
        workerScope.postMessage({ testBoundary: 'durably-consumed' });
        return new Promise<void>(() => undefined);
    },
});
