/// <reference lib="webworker" />

import { installPrivatePreparationWorker } from '../../../src/private-preparation-worker-runtime.js';

const workerScope = globalThis as unknown as DedicatedWorkerGlobalScope;

installPrivatePreparationWorker(workerScope, {
    persistentStorageRequired: false,
    unpinnedKernelAllowed: true,
    afterDurableTallyEvaluationStep: () => {
        workerScope.postMessage({
            testBoundary: 'tally-evaluation-step-durably-persisted',
        });
        return new Promise<void>(() => undefined);
    },
});
