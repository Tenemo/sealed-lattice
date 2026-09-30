import { describe, expect, it } from 'vitest';

import { PublicInputFailure } from '#packages/sdk/src/participant/worker/context.js';
import {
    ModuleFailure,
    ResourceFailure,
} from '#packages/sdk/src/participant/worker/kernel.js';
import { pendingCause } from '#packages/sdk/src/participant/worker/outcome.js';
import { StoragePending } from '#packages/sdk/src/participant/worker/storage.js';

describe('participant outcomes', () => {
    it('name what a pending participant waits for by the failure that ended its operation', () => {
        expect(pendingCause(new PublicInputFailure('missing'))).toBe(
            'public input',
        );
        expect(pendingCause(new StoragePending('quota'))).toBe('storage');
        expect(pendingCause(new ResourceFailure('memory'))).toBe('resource');
        expect(pendingCause(new ModuleFailure('trap'))).toBe('module');
        // Any other failure ended the worker before authority started.
        for (const error of [
            new Error('database'),
            new TypeError('fetch'),
            'thrown text',
            undefined,
        ])
            expect(pendingCause(error)).toBe('worker');
    });
});
