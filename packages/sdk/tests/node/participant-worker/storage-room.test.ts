import { afterEach, describe, expect, it, vi } from 'vitest';

import { StorageFailure } from '#packages/sdk/src/participant/worker/shared/failures.js';
import { beginBallot } from '#packages/sdk/src/participant/worker/stages/ballot/ballot.js';
import { beginContribution } from '#packages/sdk/src/participant/worker/stages/contribution/contribution.js';
import type { ParticipantSession } from '#packages/sdk/src/participant/worker/stages/participant-session.js';
import { hasStorageRoom } from '#packages/sdk/src/participant/worker/storage/database.js';
import { rootGeneration } from '#packages/sdk/src/participant/worker/storage/root-generation.js';
import { compileParticipantRuntimeProfile } from '#tests/participant-runtime-bounds-model.js';

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

    it('refuses a ballot or a contribution one byte beyond the estimated room as a storage failure', async () => {
        const profile = compileParticipantRuntimeProfile(4, 2);
        const session = (generation: number) =>
            ({
                context: { profile, position: 0 },
                root: { head: { generation } },
            }) as unknown as ParticipantSession;
        estimating(() =>
            Promise.resolve({
                quota: profile.ballot.requiredStorageBytes,
                usage: 1,
            }),
        );
        await expect(
            beginBallot(
                session(rootGeneration.setupRetained),
                new Uint8Array(profile.optionCount).fill(
                    profile.ballot.minimumScore,
                ),
            ),
        ).rejects.toBeInstanceOf(StorageFailure);
        estimating(() =>
            Promise.resolve({
                quota: profile.contribution.requiredStorageBytes,
                usage: 1,
            }),
        );
        await expect(
            beginContribution(session(rootGeneration.preparation)),
        ).rejects.toBeInstanceOf(StorageFailure);
    });
});
