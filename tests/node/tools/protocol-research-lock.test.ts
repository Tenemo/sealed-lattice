import assert from 'node:assert/strict';
import {
    mkdir,
    mkdtemp,
    readFile,
    rename,
    rm,
    writeFile,
} from 'node:fs/promises';
import path from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { acquireProtocolResearchLock } from '#tools/ci/protocol-research-lock.js';
import { serializeErrorDiagnostic } from '#tools/ci/run-log-diagnostics.js';

const fault = vi.hoisted(() => ({
    mode: undefined as
        | 'partial-write'
        | 'initial-stat'
        | 'write-and-cleanup'
        | 'close-failure'
        | 'rounded-replacement'
        | undefined,
}));

vi.mock('node:fs/promises', async (importOriginal) => {
    const original = await importOriginal<typeof import('node:fs/promises')>();
    return {
        ...original,
        lstat: async (...args: Parameters<typeof original.lstat>) => {
            if (fault.mode === 'write-and-cleanup')
                throw new Error('Injected lock cleanup failure.');
            const value = await original.lstat(...args);
            return fault.mode === 'rounded-replacement'
                ? {
                      ...value,
                      ino: args[1]?.bigint
                          ? (1n << 53n) + 1n
                          : Number((1n << 53n) + 1n),
                  }
                : value;
        },
        open: async (...args: Parameters<typeof original.open>) => {
            const handle = await original.open(...args);
            let statFailed = false;
            return new Proxy(handle, {
                get(target, property) {
                    if (
                        property === 'stat' &&
                        fault.mode === 'rounded-replacement'
                    )
                        return async (options?: { bigint?: boolean }) => {
                            const value = await target.stat(options);
                            return {
                                ...value,
                                ino: options?.bigint
                                    ? 1n << 53n
                                    : Number(1n << 53n),
                            };
                        };
                    if (property === 'close' && fault.mode === 'close-failure')
                        return async () => {
                            await target.close();
                            throw new Error('Injected lock close failure.');
                        };
                    if (
                        property === 'writeFile' &&
                        (fault.mode === 'partial-write' ||
                            fault.mode === 'write-and-cleanup')
                    )
                        return async (value: string) => {
                            await target.writeFile(value.slice(0, 9));
                            throw new Error('Injected partial lock write.');
                        };
                    if (
                        property === 'stat' &&
                        fault.mode === 'initial-stat' &&
                        !statFailed
                    )
                        return () => {
                            statFailed = true;
                            return Promise.reject(
                                new Error(
                                    'Injected initial lock stat failure.',
                                ),
                            );
                        };
                    const value: unknown = Reflect.get(target, property);
                    return typeof value === 'function'
                        ? (value.bind(target) as unknown)
                        : value;
                },
            });
        },
    };
});

describe('protocol research serialization', () => {
    const temporaryRoot = path.resolve('temp');
    let root: string;
    let lockPath: string;
    beforeEach(async () => {
        await mkdir(temporaryRoot, { recursive: true });
        root = await mkdtemp(path.join(temporaryRoot, 'research-lock-test-'));
        lockPath = path.join(root, 'temp/protocol-research.lock');
    });
    afterEach(async () => {
        fault.mode = undefined;
        assert.ok(root.startsWith(temporaryRoot + path.sep));
        await rm(root, { recursive: true, force: true });
    });

    it('holds an exclusive lock and releases only its own contents', async () => {
        const release = await acquireProtocolResearchLock('run-one', root);
        try {
            expect(JSON.parse(await readFile(lockPath, 'utf8'))).toEqual({
                pid: process.pid,
                run: 'run-one',
            });
            await expect(
                acquireProtocolResearchLock('run-two', root),
            ).rejects.toMatchObject({ code: 'EEXIST' });
            expect(JSON.parse(await readFile(lockPath, 'utf8'))).toEqual({
                pid: process.pid,
                run: 'run-one',
            });
        } finally {
            await release();
        }
        await expect(readFile(lockPath)).rejects.toMatchObject({
            code: 'ENOENT',
        });
        const nextRelease = await acquireProtocolResearchLock('run-two', root);
        await nextRelease();
    });

    it.each(['partial-write', 'initial-stat'] as const)(
        'cleans acquisition after %s failure',
        async (mode) => {
            fault.mode = mode;
            await expect(
                acquireProtocolResearchLock('incomplete-run', root),
            ).rejects.toThrow('Injected');
            await expect(readFile(lockPath)).rejects.toMatchObject({
                code: 'ENOENT',
            });
            fault.mode = undefined;
            const release = await acquireProtocolResearchLock('next-run', root);
            await release();
        },
    );

    it('refuses to unlink a replacement lock', async () => {
        const release = await acquireProtocolResearchLock('original-run', root);
        await rename(lockPath, path.join(root, 'original.lock'));
        await writeFile(lockPath, 'replacement', { flag: 'wx' });
        await expect(release()).rejects.toThrow('lock was replaced');
        expect(await readFile(lockPath, 'utf8')).toBe('replacement');
    });

    it('distinguishes file identities that round to the same Number', async () => {
        fault.mode = 'rounded-replacement';
        const release = await acquireProtocolResearchLock('original-run', root);
        await expect(release()).rejects.toThrow('lock was replaced');
        expect(JSON.parse(await readFile(lockPath, 'utf8'))).toEqual({
            pid: process.pid,
            run: 'original-run',
        });
    });

    it('preserves both acquisition and cleanup failures in diagnostics', async () => {
        fault.mode = 'write-and-cleanup';
        const error: unknown = await acquireProtocolResearchLock(
            'incomplete-run',
            root,
        ).catch((value: unknown) => value);
        const diagnostic = serializeErrorDiagnostic(error);
        expect(diagnostic.message).toContain('Injected partial lock write.');
        expect(diagnostic.cause?.message).toBe(
            'Injected lock cleanup failure.',
        );
        expect(await readFile(lockPath, 'utf8')).toHaveLength(9);
    });

    it('reports changed contents without removing them', async () => {
        const release = await acquireProtocolResearchLock('original-run', root);
        await writeFile(lockPath, 'changed');
        await expect(release()).rejects.toThrow('lock contents changed');
        expect(await readFile(lockPath, 'utf8')).toBe('changed');
    });

    it('preserves an ownership failure when closing also fails', async () => {
        const release = await acquireProtocolResearchLock('original-run', root);
        await writeFile(lockPath, 'changed');
        fault.mode = 'close-failure';
        const error: unknown = await release().catch((value: unknown) => value);
        const diagnostic = serializeErrorDiagnostic(error);
        expect(diagnostic.message).toContain(
            'Protocol research lock contents changed.',
        );
        expect(diagnostic.cause?.message).toBe('Injected lock close failure.');
        expect(await readFile(lockPath, 'utf8')).toBe('changed');
    });
});
