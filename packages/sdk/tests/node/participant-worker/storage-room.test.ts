import { afterEach, describe, expect, it, vi } from 'vitest';

import { StorageFailure } from '#packages/sdk/src/participant/worker/shared/failures.js';
import { hasStorageRoom } from '#packages/sdk/src/participant/worker/storage/database.js';

const estimating = (estimate: () => Promise<StorageEstimate>) => {
    vi.stubGlobal('navigator', { storage: { estimate } });
};

describe('participant storage room', () => {
    afterEach(() => {
        vi.unstubAllGlobals();
    });

    it('holds work exactly when the estimated free quota covers its bytes', async () => {
        estimating(() => Promise.resolve({ quota: 1000, usage: 400 }));
        expect(await hasStorageRoom(600)).toBe(true);
        expect(await hasStorageRoom(601)).toBe(false);
    });

    it('holds no work under an estimate without its quota or usage', async () => {
        for (const estimate of [{ usage: 0 }, { quota: 1000 }, {}]) {
            estimating(() => Promise.resolve(estimate));
            expect(await hasStorageRoom(0)).toBe(false);
        }
    });

    it('reports an estimate the browser fails as a storage failure', async () => {
        estimating(() =>
            Promise.reject(new DOMException('denied', 'SecurityError')),
        );
        await expect(hasStorageRoom(1)).rejects.toBeInstanceOf(StorageFailure);
    });
});
