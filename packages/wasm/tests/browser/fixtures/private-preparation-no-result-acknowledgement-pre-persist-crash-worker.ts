/// <reference lib="webworker" />

import { installPrivatePreparationWorker } from '../../../src/private-preparation-worker-runtime.js';

const workerScope = globalThis as unknown as DedicatedWorkerGlobalScope;

installPrivatePreparationWorker(workerScope, {
    persistentStorageRequired: false,
    unpinnedKernelAllowed: true,
    beforeDurableNoResultAcknowledgementPersist: () => {
        workerScope.postMessage({
            testBoundary: 'no-result-acknowledgement-before-persist',
        });
        return new Promise<void>(() => undefined);
    },
});
