import {
    access,
    mkdir,
    mkdtemp,
    rm,
    symlink,
    utimes,
    writeFile,
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import {
    collectGeneratedCleanupCandidates,
    generatedCleanupRepositoryRootPath,
    parseGeneratedCleanupArguments,
    requireAllowlistedGeneratedCleanupTarget,
    runGeneratedCleanup,
} from '#tools/ci/clean-generated-output';

const temporaryRoots: string[] = [];

const createTemporaryWorkspace = async (): Promise<string> => {
    const workspaceRootPath = await mkdtemp(
        path.join(os.tmpdir(), 'sealed-lattice-generated-cleanup-'),
    );
    temporaryRoots.push(workspaceRootPath);
    return workspaceRootPath;
};

const makePathOld = async (candidatePath: string): Promise<void> => {
    const oldTime = new Date('2025-01-01T00:00:00.000Z');
    await utimes(candidatePath, oldTime, oldTime);
};

afterEach(async () => {
    await Promise.all(
        temporaryRoots
            .splice(0)
            .map((temporaryRootPath) =>
                rm(temporaryRootPath, { force: true, recursive: true }),
            ),
    );
});

describe('generated-output cleanup', () => {
    it('is a dry run unless --apply is supplied', () => {
        expect(parseGeneratedCleanupArguments([])).toEqual({ apply: false });
        expect(parseGeneratedCleanupArguments(['--', '--apply'])).toEqual({
            apply: true,
        });
        expect(() => parseGeneratedCleanupArguments(['--force'])).toThrow(
            /only the optional --apply flag/u,
        );
    });

    it('anchors defaults and rejects root, traversal, outside, and unlisted targets', async () => {
        const workspaceRootPath = await createTemporaryWorkspace();
        expect(generatedCleanupRepositoryRootPath).toBe(
            path.resolve(process.cwd()),
        );
        for (const refusedPath of [
            workspaceRootPath,
            path.resolve(workspaceRootPath, '..', 'outside'),
            path.resolve(workspaceRootPath, '.turbo', '..', 'README.md'),
            path.join(
                workspaceRootPath,
                'logs',
                '2026-07-12T12-00-00.000Z-run',
            ),
            path.join(workspaceRootPath, 'unlisted-generated-output'),
        ]) {
            expect(() =>
                requireAllowlistedGeneratedCleanupTarget(
                    workspaceRootPath,
                    refusedPath,
                ),
            ).toThrow(/outside the fixed repository allowlist/u);
        }
        for (const allowedPath of [
            path.join(workspaceRootPath, '.turbo'),
            path.join(workspaceRootPath, 'target'),
            path.join(workspaceRootPath, 'fuzz', 'target'),
            path.join(
                workspaceRootPath,
                'temp',
                'test-checkpoints',
                'proof.bin',
            ),
        ]) {
            expect(() =>
                requireAllowlistedGeneratedCleanupTarget(
                    workspaceRootPath,
                    allowedPath,
                ),
            ).not.toThrow();
        }
    });

    it('selects complete build roots and only expired checkpoints', async () => {
        const workspaceRootPath = await createTemporaryWorkspace();
        const rustBuildFilePath = path.join(
            workspaceRootPath,
            'target',
            'debug',
            'kernel.bin',
        );
        const oldLogRunPath = path.join(workspaceRootPath, 'logs', 'old-run');
        const oldCheckpointPath = path.join(
            workspaceRootPath,
            'temp',
            'test-checkpoints',
            'proofs',
            'old.bin',
        );
        const freshCheckpointPath = path.join(
            workspaceRootPath,
            'temp',
            'test-checkpoints',
            'proofs',
            'fresh.bin',
        );
        await Promise.all([
            mkdir(path.dirname(rustBuildFilePath), { recursive: true }),
            mkdir(oldLogRunPath, { recursive: true }),
            mkdir(path.dirname(oldCheckpointPath), { recursive: true }),
        ]);
        await Promise.all([
            writeFile(rustBuildFilePath, 'build'),
            writeFile(path.join(oldLogRunPath, 'combined.log'), 'old'),
            writeFile(oldCheckpointPath, 'old'),
            writeFile(freshCheckpointPath, 'fresh'),
        ]);
        await Promise.all([
            makePathOld(path.join(oldLogRunPath, 'combined.log')),
            makePathOld(oldLogRunPath),
            makePathOld(oldCheckpointPath),
        ]);

        const candidates = await collectGeneratedCleanupCandidates({
            now: new Date('2026-07-12T00:00:00.000Z'),
            workspaceRootPath,
        });
        expect(candidates.map((candidate) => candidate.relativePath)).toEqual([
            'target',
            'temp/test-checkpoints/proofs/old.bin',
        ]);

        await runGeneratedCleanup({
            apply: false,
            now: new Date('2026-07-12T00:00:00.000Z'),
            workspaceRootPath,
        });
        await expect(access(rustBuildFilePath)).resolves.toBeUndefined();

        await runGeneratedCleanup({
            apply: true,
            now: new Date('2026-07-12T00:00:00.000Z'),
            workspaceRootPath,
        });
        await expect(
            access(path.join(workspaceRootPath, 'target')),
        ).rejects.toThrow();
        await expect(access(oldLogRunPath)).resolves.toBeUndefined();
        await expect(access(oldCheckpointPath)).rejects.toThrow();
        await expect(access(freshCheckpointPath)).resolves.toBeUndefined();
    });

    it('refuses an allowed tree containing a link or junction', async () => {
        const workspaceRootPath = await createTemporaryWorkspace();
        const outsideDirectoryPath = await mkdtemp(
            path.join(os.tmpdir(), 'sealed-lattice-cleanup-outside-'),
        );
        temporaryRoots.push(outsideDirectoryPath);
        const targetPath = path.join(workspaceRootPath, 'target');
        await mkdir(targetPath);
        await symlink(
            outsideDirectoryPath,
            path.join(targetPath, 'outside'),
            process.platform === 'win32' ? 'junction' : 'dir',
        );

        await expect(
            collectGeneratedCleanupCandidates({ workspaceRootPath }),
        ).rejects.toThrow(/refuses symbolic links and junctions/u);
        await expect(access(outsideDirectoryPath)).resolves.toBeUndefined();
    });
});
