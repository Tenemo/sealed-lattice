import type { BigIntStats } from 'node:fs';
import { lstat, mkdir, open, readFile, unlink } from 'node:fs/promises';
import path from 'node:path';

const cleanupFailure = (
    operation: string,
    error: unknown,
    cleanupError: unknown,
) =>
    Object.assign(
        new Error(
            `${operation}: ${error instanceof Error ? error.message : String(error)}; cleanup also failed.`,
        ),
        { cause: cleanupError },
    );

export const acquireProtocolResearchLock = async (
    runDirectoryPath: string,
    rootDirectoryPath: string,
): Promise<() => Promise<void>> => {
    const directory = path.join(rootDirectoryPath, 'temp');
    await mkdir(directory, { recursive: true });
    const lockPath = path.join(directory, 'protocol-research.lock');
    const handle = await open(lockPath, 'wx');
    const value = JSON.stringify({ pid: process.pid, run: runDirectoryPath });
    let identity: BigIntStats | undefined;
    let initialized = false;
    const release = async (): Promise<void> => {
        try {
            const original = identity ?? (await handle.stat({ bigint: true }));
            const current = await lstat(lockPath, { bigint: true });
            if (current.dev !== original.dev || current.ino !== original.ino)
                throw new Error('Protocol research lock was replaced.');
            if (initialized && (await readFile(lockPath, 'utf8')) !== value)
                throw new Error('Protocol research lock contents changed.');
            await unlink(lockPath);
        } catch (error) {
            try {
                await handle.close();
            } catch (closeError) {
                throw cleanupFailure(
                    'Protocol research lock release failed',
                    error,
                    closeError,
                );
            }
            throw error;
        }
        await handle.close();
    };
    try {
        identity = await handle.stat({ bigint: true });
        await handle.writeFile(value);
        initialized = true;
        return release;
    } catch (error) {
        try {
            await release();
        } catch (cleanupError) {
            throw cleanupFailure(
                'Protocol research lock acquisition failed',
                error,
                cleanupError,
            );
        }
        throw error;
    }
};
