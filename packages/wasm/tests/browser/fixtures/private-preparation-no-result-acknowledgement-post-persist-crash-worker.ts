/// <reference lib="webworker" />

import { installPrivatePreparationWorker } from '../../../src/private-preparation-worker-runtime.js';

const workerScope = globalThis as unknown as DedicatedWorkerGlobalScope;

installPrivatePreparationWorker(workerScope, {
    persistentStorageRequired: false,
    unpinnedKernelAllowed: true,
    afterDurableNoResultAcknowledgementPersist: () => {
        workerScope.postMessage({
            testBoundary: 'no-result-acknowledgement-after-persist',
        });
        return new Promise<void>(() => undefined);
    },
});
