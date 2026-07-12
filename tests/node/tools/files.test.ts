import { describe, expect, it } from 'vitest';

import {
    filesystemMaximumRetries,
    withTransientFilesystemRetries,
} from '#tools/internal/files';

describe('transient filesystem retries', () => {
    const noDelay = (): Promise<void> => Promise.resolve();
    const transientError = (code: string): NodeJS.ErrnoException =>
        Object.assign(new Error(`transient ${code}`), { code });

    it('retries transient errors until the operation succeeds', async () => {
        let attempts = 0;
        const result = await withTransientFilesystemRetries(
            (): Promise<string> => {
                attempts += 1;
                if (attempts === 1) {
                    return Promise.reject(transientError('ENOTEMPTY'));
                }
                if (attempts === 2) {
                    return Promise.reject(transientError('ENOENT'));
                }

                return Promise.resolve('written');
            },
            noDelay,
        );

        expect(result).toBe('written');
        expect(attempts).toBe(3);
    });

    it('does not retry a non-transient error', async () => {
        let attempts = 0;
        await expect(
            withTransientFilesystemRetries((): Promise<never> => {
                attempts += 1;

                return Promise.reject(transientError('ENOSPC'));
            }, noDelay),
        ).rejects.toMatchObject({ code: 'ENOSPC' });

        expect(attempts).toBe(1);
    });

    it('stops after the bounded retry count', async () => {
        let attempts = 0;
        await expect(
            withTransientFilesystemRetries((): Promise<never> => {
                attempts += 1;

                return Promise.reject(transientError('EPERM'));
            }, noDelay),
        ).rejects.toMatchObject({ code: 'EPERM' });

        expect(attempts).toBe(filesystemMaximumRetries);
    });
});
