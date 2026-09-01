/// <reference lib="webworker" />

import { installPrivatePreparationWorker } from '../../../src/private-preparation-worker-runtime.js';

installPrivatePreparationWorker(
    globalThis as unknown as DedicatedWorkerGlobalScope,
    {
        persistentStorageRequired: false,
        unpinnedKernelAllowed: true,
    },
);
