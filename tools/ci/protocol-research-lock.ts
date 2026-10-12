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

// Holds an exclusive lock file under the checkout's `temp/` for one run and
// returns its release, which refuses a lock another process replaced or
// rewrote.
const acquireRunLock = async (
    label: string,
    fileName: string,
    runDirectoryPath: string,
    rootDirectoryPath: string,
): Promise<() => Promise<void>> => {
    const directory = path.join(rootDirectoryPath, 'temp');
    await mkdir(directory, { recursive: true });
    const lockPath = path.join(directory, fileName);
    const handle = await open(lockPath, 'wx');
    const value = JSON.stringify({ pid: process.pid, run: runDirectoryPath });
    let identity: BigIntStats | undefined;
    let initialized = false;
    const release = async (): Promise<void> => {
        try {
            const original = identity ?? (await handle.stat({ bigint: true }));
            const current = await lstat(lockPath, { bigint: true });
            if (current.dev !== original.dev || current.ino !== original.ino)
                throw new Error(`${label} was replaced.`);
            if (initialized && (await readFile(lockPath, 'utf8')) !== value)
                throw new Error(`${label} contents changed.`);
            await unlink(lockPath);
        } catch (error) {
            try {
                await handle.close();
            } catch (closeError) {
                throw cleanupFailure(
                    `${label} release failed`,
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
                `${label} acquisition failed`,
                error,
                cleanupError,
            );
        }
        throw error;
    }
};

export const acquireProtocolResearchLock = (
    runDirectoryPath: string,
    rootDirectoryPath: string,
): Promise<() => Promise<void>> =>
    acquireRunLock(
        'Protocol research lock',
        'protocol-research.lock',
        runDirectoryPath,
        rootDirectoryPath,
    );

// Serializes evidence renewals, whose steps each take the protocol research
// lock in turn.
export const acquireEvidenceRenewalLock = (
    runDirectoryPath: string,
    rootDirectoryPath: string,
): Promise<() => Promise<void>> =>
    acquireRunLock(
        'Evidence renewal lock',
        'evidence-renewal.lock',
        runDirectoryPath,
        rootDirectoryPath,
    );
