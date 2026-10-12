import { lstat, mkdir, rm, rmdir, symlink, unlink } from 'node:fs/promises';
import path from 'node:path';

import {
    createPackageManagerCommand,
    runCheckedCommand,
} from '#tools/ci/command-runner.js';
import type { ActiveLocalRunLog } from '#tools/ci/local-run-log.js';

// The repository directories a renewal worktree reaches through links, so
// its runs join the repository's run history and keep their artifacts there.
const sharedDirectories = [['logs'], ['temp', 'run-artifacts']] as const;

export type RenewalWorktree = Readonly<{
    commit: string;
    remove: () => Promise<void>;
    root: string;
}>;

const errorCode = (error: unknown): unknown =>
    (error as NodeJS.ErrnoException).code;

// Removes each link without following it and confirms it is gone. A path that
// is no longer a link stays and the removal fails, since what it holds may be
// another checkout's.
export const removeDirectoryLinks = async (
    linkPaths: readonly string[],
): Promise<void> => {
    for (const linkPath of linkPaths) {
        try {
            if (!(await lstat(linkPath)).isSymbolicLink())
                throw new Error(
                    `${linkPath} is no longer a link, so the worktree that holds it stays.`,
                );
        } catch (error) {
            if (errorCode(error) === 'ENOENT') continue;
            throw error;
        }
        await unlink(linkPath);
        try {
            await lstat(linkPath);
        } catch (error) {
            if (errorCode(error) === 'ENOENT') continue;
            throw error;
        }
        throw new Error(`${linkPath} remained after its removal.`);
    }
};

// A detached worktree of the commit under the repository's `temp/`, on the
// drive of the package store, with its own dependencies and links to the
// repository's logs and run artifacts. Its removal unlinks those first, so it
// never reaches them.
export const createRenewalWorktree = async (input: {
    readonly commit: string;
    readonly name: string;
    readonly repositoryRoot: string;
    readonly runLog: ActiveLocalRunLog;
}): Promise<RenewalWorktree> => {
    const container = path.join(
        input.repositoryRoot,
        'temp',
        'renewal-worktrees',
    );
    const root = path.join(container, input.name);
    const git = (args: readonly string[], description: string) =>
        runCheckedCommand(
            {
                args,
                command: 'git',
                description,
                workingDirectoryPath: input.repositoryRoot,
            },
            { runLog: input.runLog },
        );
    await mkdir(container, { recursive: true });
    await git(
        ['worktree', 'add', '--detach', root, input.commit],
        `Create a worktree at ${input.commit}`,
    );
    const remove = async (): Promise<void> => {
        await removeDirectoryLinks(
            sharedDirectories.map((segments) => path.join(root, ...segments)),
        );
        await rm(root, { force: true, maxRetries: 5, recursive: true });
        await git(['worktree', 'prune'], 'Prune the removed worktree');
        try {
            await rmdir(container);
        } catch (error) {
            if (errorCode(error) !== 'ENOTEMPTY') throw error;
        }
    };
    try {
        for (const segments of sharedDirectories) {
            const target = path.join(input.repositoryRoot, ...segments);
            const link = path.join(root, ...segments);
            await mkdir(target, { recursive: true });
            await mkdir(path.dirname(link), { recursive: true });
            await symlink(target, link, 'junction');
        }
        // Its own installation, never a link to this checkout's, which a
        // package manager working in the worktree could replace.
        await runCheckedCommand(
            {
                ...createPackageManagerCommand(
                    'Install the worktree dependencies',
                    ['install', '--frozen-lockfile', '--prefer-offline'],
                    { env: { ...process.env, HUSKY: '0' } },
                ),
                workingDirectoryPath: root,
            },
            { runLog: input.runLog },
        );
    } catch (error) {
        try {
            await remove();
        } catch (cleanupError) {
            throw Object.assign(
                new Error(
                    `The worktree at ${root} failed to prepare and stays: ${error instanceof Error ? error.message : String(error)}`,
                ),
                { cause: cleanupError },
            );
        }
        throw error;
    }
    return { commit: input.commit, remove, root };
};
