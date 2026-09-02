/// <reference lib="webworker" />

import { installPrivatePreparationWorker } from '../../../src/private-preparation-worker-runtime.js';

const workerScope = globalThis as unknown as DedicatedWorkerGlobalScope;

installPrivatePreparationWorker(workerScope, {
    persistentStorageRequired: false,
    unpinnedKernelAllowed: true,
    afterDurableActivationBodyBind: () => {
        workerScope.postMessage({
            testBoundary: 'activation-body-durably-bound',
        });
        return new Promise<void>(() => undefined);
    },
});
