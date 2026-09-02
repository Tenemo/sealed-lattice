/// <reference lib="webworker" />

import { installPrivatePreparationWorker } from '../../../src/private-preparation-worker-runtime.js';

const workerScope = globalThis as unknown as DedicatedWorkerGlobalScope;

installPrivatePreparationWorker(workerScope, {
    persistentStorageRequired: false,
    unpinnedKernelAllowed: true,
    afterDurableTallyActivationPublish: () => {
        workerScope.postMessage({
            testBoundary: 'tally-activation-durably-published',
        });
        return new Promise<void>(() => undefined);
    },
});
