/// <reference lib="webworker" />

import { installPrivatePreparationWorker } from '../../../src/private-preparation-worker-runtime.js';

const workerScope = globalThis as unknown as DedicatedWorkerGlobalScope;

installPrivatePreparationWorker(workerScope, {
    persistentStorageRequired: false,
    unpinnedKernelAllowed: true,
    afterDurableTallyTerminalPersist: () => {
        workerScope.postMessage({
            testBoundary: 'tally-terminal-durably-persisted',
        });
        return new Promise<void>(() => undefined);
    },
});
