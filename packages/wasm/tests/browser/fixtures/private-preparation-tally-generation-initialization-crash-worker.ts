/// <reference lib="webworker" />

import { installPrivatePreparationWorker } from '../../../src/private-preparation-worker-runtime.js';

const workerScope = globalThis as unknown as DedicatedWorkerGlobalScope;

installPrivatePreparationWorker(workerScope, {
    persistentStorageRequired: false,
    unpinnedKernelAllowed: true,
    afterDurableTallyGenerationInitialize: () => {
        workerScope.postMessage({
            testBoundary: 'tally-generation-durably-initialized',
        });
        return new Promise<void>(() => undefined);
    },
});
