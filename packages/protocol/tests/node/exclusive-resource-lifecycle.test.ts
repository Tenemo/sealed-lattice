import { describe, expect, it } from 'vitest';

import { AuthenticatedRuntimeRecordError } from '#packages/protocol/src/runtime/authenticated-runtime-record';
import { ExclusiveResourceLifecycle } from '#packages/protocol/src/runtime/exclusive-resource-lifecycle';

describe('exclusive resource lifecycle', () => {
    it('blocks new work synchronously and drains in-flight work before cleanup', async () => {
        let finishOperation: (() => void) | undefined;
        let cleanupStarted = false;
        const lifecycle = new ExclusiveResourceLifecycle({
            cleanup: () => {
                cleanupStarted = true;
                return Promise.resolve();
            },
            createInvalidStateError: (message) =>
                new AuthenticatedRuntimeRecordError('InvalidState', message),
        });
        const owner = lifecycle.initialOwner();
        const operation = lifecycle.run(
            owner,
            () =>
                new Promise<void>((resolve) => {
                    finishOperation = resolve;
                }),
        );

        const close = lifecycle.close(owner);
        expect(cleanupStarted).toBe(false);
        expect(() =>
            lifecycle.run(owner, () => Promise.resolve()),
        ).toThrowError(expect.objectContaining({ code: 'InvalidState' }));

        finishOperation?.();
        await operation;
        await close;
        expect(cleanupStarted).toBe(true);
        expect(lifecycle.close(owner)).toBe(close);
    });
});
