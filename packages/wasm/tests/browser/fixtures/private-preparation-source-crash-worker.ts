/// <reference lib="webworker" />

import { installPrivatePreparationWorker } from '../../../src/private-preparation-worker-runtime.js';

const workerScope = globalThis as unknown as DedicatedWorkerGlobalScope;

installPrivatePreparationWorker(workerScope, {
    persistentStorageRequired: false,
    unpinnedKernelAllowed: true,
    afterDurableSourceBind: () => {
        workerScope.postMessage({ testBoundary: 'source-durably-bound' });
        return new Promise<void>(() => undefined);
    },
});
