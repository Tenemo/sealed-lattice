import { lstat, readdir, realpath, rm, rmdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';
import { isWithinDirectory, toPosixPath } from '#tools/internal/files.js';

const millisecondsPerDay = 24 * 60 * 60 * 1_000;
export const generatedCleanupRepositoryRootPath = path.resolve(
    fileURLToPath(new URL('../../', import.meta.url)),
);

export type GeneratedCleanupCandidate = {
    readonly absolutePath: string;
    readonly description: string;
    readonly recursive: boolean;
    readonly relativePath: string;
};

export type GeneratedCleanupOptions = {
    readonly apply: boolean;
};

const completeGeneratedDirectoryDefinitions = [
    { description: 'Turbo build state', relativePath: '.turbo' },
    { description: 'Rust build output', relativePath: 'target' },
    { description: 'Rust fuzz build output', relativePath: 'fuzz/target' },
] as const;

const retentionDirectoryDefinitions = [
    {
        description: 'Local run log older than 14 days',
        groupingDepth: 1,
        maximumAgeDays: 14,
        relativePath: 'logs',
    },
    {
        description: 'Test checkpoint older than 60 days',
        groupingDepth: undefined,
        maximumAgeDays: 60,
        relativePath: 'temp/test-checkpoints',
    },
] as const;

const allowedGeneratedRootRelativePaths = [
    ...completeGeneratedDirectoryDefinitions.map(
        (definition) => definition.relativePath,
    ),
    ...retentionDirectoryDefinitions.map(
        (definition) => definition.relativePath,
    ),
] as const;

export const requireAllowlistedGeneratedCleanupTarget = (
    workspaceRootPath: string,
    candidatePath: string,
): void => {
    const resolvedWorkspaceRootPath = path.resolve(workspaceRootPath);
    const resolvedCandidatePath = path.resolve(candidatePath);
    const isAllowlisted = allowedGeneratedRootRelativePaths.some(
        (relativePath) => {
            const allowedRootPath = path.resolve(
                resolvedWorkspaceRootPath,
                relativePath,
            );
            return (
                resolvedCandidatePath === allowedRootPath ||
                isWithinDirectory(allowedRootPath, resolvedCandidatePath)
            );
        },
    );
    if (
        resolvedCandidatePath === resolvedWorkspaceRootPath ||
        !isWithinDirectory(resolvedWorkspaceRootPath, resolvedCandidatePath) ||
        !isAllowlisted
    ) {
        throw new Error(
            `Generated cleanup target is outside the fixed repository allowlist: ${resolvedCandidatePath}`,
        );
    }
};

export const parseGeneratedCleanupArguments = (
    commandArguments: readonly string[],
): GeneratedCleanupOptions => {
    const argumentsWithoutSeparator = commandArguments.filter(
        (argument) => argument !== '--',
    );
    if (argumentsWithoutSeparator.length === 0) {
        return { apply: false };
    }
    if (
        argumentsWithoutSeparator.length === 1 &&
        argumentsWithoutSeparator[0] === '--apply'
    ) {
        return { apply: true };
    }

    throw new Error(
        'Generated cleanup accepts only the optional --apply flag.',
    );
};

const requireExistingPathWithoutLinks = async (
    workspaceRootPath: string,
    candidatePath: string,
): Promise<void> => {
    requireAllowlistedGeneratedCleanupTarget(workspaceRootPath, candidatePath);

    const relativePath = path.relative(workspaceRootPath, candidatePath);
    let currentPath = workspaceRootPath;
    for (const pathSegment of relativePath.split(path.sep)) {
        currentPath = path.join(currentPath, pathSegment);
        const pathStats = await lstat(currentPath);
        if (pathStats.isSymbolicLink()) {
            throw new Error(
                `Generated cleanup refuses symbolic links and junctions: ${currentPath}`,
            );
        }
    }

    const resolvedCandidatePath = await realpath(candidatePath);
    if (!isWithinDirectory(workspaceRootPath, resolvedCandidatePath)) {
        throw new Error(
            `Generated cleanup target resolves outside the workspace: ${candidatePath}`,
        );
    }
};

const pathExists = async (candidatePath: string): Promise<boolean> => {
    try {
        await lstat(candidatePath);
        return true;
    } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
            return false;
        }
        throw error;
    }
};

const requireTreeWithoutLinks = async (rootPath: string): Promise<void> => {
    const pendingDirectoryPaths = [rootPath];
    while (pendingDirectoryPaths.length > 0) {
        const directoryPath = pendingDirectoryPaths.pop();
        if (directoryPath === undefined) {
            break;
        }
        for (const entry of await readdir(directoryPath, {
            withFileTypes: true,
        })) {
            const entryPath = path.join(directoryPath, entry.name);
            if (entry.isSymbolicLink()) {
                throw new Error(
                    `Generated cleanup refuses symbolic links and junctions: ${entryPath}`,
                );
            }
            if (entry.isDirectory()) {
                pendingDirectoryPaths.push(entryPath);
            }
        }
    }
};

const latestModificationTimeMilliseconds = async (
    candidatePath: string,
): Promise<number> => {
    const candidateStats = await lstat(candidatePath);
    if (candidateStats.isSymbolicLink()) {
        throw new Error(
            `Generated cleanup refuses symbolic links and junctions: ${candidatePath}`,
        );
    }
    if (!candidateStats.isDirectory()) {
        return candidateStats.mtimeMs;
    }

    const entries = await readdir(candidatePath);
    if (entries.length === 0) {
        return candidateStats.mtimeMs;
    }

    let latestMilliseconds = 0;
    for (const entry of entries) {
        latestMilliseconds = Math.max(
            latestMilliseconds,
            await latestModificationTimeMilliseconds(
                path.join(candidatePath, entry),
            ),
        );
    }

    return latestMilliseconds;
};

const cleanupCandidate = (
    workspaceRootPath: string,
    absolutePath: string,
    description: string,
    recursive: boolean,
): GeneratedCleanupCandidate => ({
    absolutePath,
    description,
    recursive,
    relativePath: toPosixPath(path.relative(workspaceRootPath, absolutePath)),
});

const collectGroupedRetentionCandidates = async (input: {
    readonly cutoffMilliseconds: number;
    readonly description: string;
    readonly groupingDepth: number;
    readonly retentionRootPath: string;
    readonly workspaceRootPath: string;
}): Promise<GeneratedCleanupCandidate[]> => {
    let currentPaths = [input.retentionRootPath];
    for (let depth = 0; depth < input.groupingDepth; depth += 1) {
        const nextPaths: string[] = [];
        for (const currentPath of currentPaths) {
            const currentStats = await lstat(currentPath);
            if (currentStats.isSymbolicLink()) {
                throw new Error(
                    `Generated cleanup refuses symbolic links and junctions: ${currentPath}`,
                );
            }
            if (!currentStats.isDirectory()) {
                nextPaths.push(currentPath);
                continue;
            }
            for (const entry of await readdir(currentPath)) {
                nextPaths.push(path.join(currentPath, entry));
            }
        }
        currentPaths = nextPaths;
    }

    const candidates: GeneratedCleanupCandidate[] = [];
    for (const currentPath of currentPaths) {
        const latestModification =
            await latestModificationTimeMilliseconds(currentPath);
        if (latestModification < input.cutoffMilliseconds) {
            const currentStats = await lstat(currentPath);
            candidates.push(
                cleanupCandidate(
                    input.workspaceRootPath,
                    currentPath,
                    input.description,
                    currentStats.isDirectory(),
                ),
            );
        }
    }

    return candidates;
};

const collectFileRetentionCandidates = async (input: {
    readonly cutoffMilliseconds: number;
    readonly description: string;
    readonly retentionRootPath: string;
    readonly workspaceRootPath: string;
}): Promise<GeneratedCleanupCandidate[]> => {
    const candidates: GeneratedCleanupCandidate[] = [];
    const pendingDirectoryPaths = [input.retentionRootPath];
    while (pendingDirectoryPaths.length > 0) {
        const directoryPath = pendingDirectoryPaths.pop();
        if (directoryPath === undefined) {
            break;
        }
        for (const entry of await readdir(directoryPath, {
            withFileTypes: true,
        })) {
            const entryPath = path.join(directoryPath, entry.name);
            if (entry.isSymbolicLink()) {
                throw new Error(
                    `Generated cleanup refuses symbolic links and junctions: ${entryPath}`,
                );
            }
            if (entry.isDirectory()) {
                pendingDirectoryPaths.push(entryPath);
                continue;
            }
            if (
                entry.isFile() &&
                (await lstat(entryPath)).mtimeMs < input.cutoffMilliseconds
            ) {
                candidates.push(
                    cleanupCandidate(
                        input.workspaceRootPath,
                        entryPath,
                        input.description,
                        false,
                    ),
                );
            }
        }
    }

    return candidates;
};

export const collectGeneratedCleanupCandidates = async (
    input: {
        readonly now?: Date;
        readonly workspaceRootPath?: string;
    } = {},
): Promise<readonly GeneratedCleanupCandidate[]> => {
    const workspaceRootPath = await realpath(
        input.workspaceRootPath ?? generatedCleanupRepositoryRootPath,
    );
    const nowMilliseconds = (input.now ?? new Date()).getTime();
    const candidates: GeneratedCleanupCandidate[] = [];

    for (const definition of completeGeneratedDirectoryDefinitions) {
        const absolutePath = path.resolve(
            workspaceRootPath,
            definition.relativePath,
        );
        if (!(await pathExists(absolutePath))) {
            continue;
        }
        await requireExistingPathWithoutLinks(workspaceRootPath, absolutePath);
        await requireTreeWithoutLinks(absolutePath);
        candidates.push(
            cleanupCandidate(
                workspaceRootPath,
                absolutePath,
                definition.description,
                true,
            ),
        );
    }

    for (const definition of retentionDirectoryDefinitions) {
        const retentionRootPath = path.resolve(
            workspaceRootPath,
            definition.relativePath,
        );
        if (!(await pathExists(retentionRootPath))) {
            continue;
        }
        await requireExistingPathWithoutLinks(
            workspaceRootPath,
            retentionRootPath,
        );
        const cutoffMilliseconds =
            nowMilliseconds - definition.maximumAgeDays * millisecondsPerDay;
        candidates.push(
            ...(definition.groupingDepth === undefined
                ? await collectFileRetentionCandidates({
                      cutoffMilliseconds,
                      description: definition.description,
                      retentionRootPath,
                      workspaceRootPath,
                  })
                : await collectGroupedRetentionCandidates({
                      cutoffMilliseconds,
                      description: definition.description,
                      groupingDepth: definition.groupingDepth,
                      retentionRootPath,
                      workspaceRootPath,
                  })),
        );
    }

    return candidates.sort((left, right) =>
        left.relativePath.localeCompare(right.relativePath),
    );
};

const removeEmptyDirectories = async (directoryPath: string): Promise<void> => {
    if (!(await pathExists(directoryPath))) {
        return;
    }
    for (const entry of await readdir(directoryPath, { withFileTypes: true })) {
        if (entry.isSymbolicLink()) {
            throw new Error(
                `Generated cleanup refuses symbolic links and junctions: ${path.join(directoryPath, entry.name)}`,
            );
        }
        if (entry.isDirectory()) {
            await removeEmptyDirectories(path.join(directoryPath, entry.name));
        }
    }
    if ((await readdir(directoryPath)).length === 0) {
        await rmdir(directoryPath);
    }
};

export const runGeneratedCleanup = async (input: {
    readonly apply: boolean;
    readonly now?: Date;
    readonly workspaceRootPath?: string;
}): Promise<readonly GeneratedCleanupCandidate[]> => {
    const workspaceRootPath = await realpath(
        input.workspaceRootPath ?? generatedCleanupRepositoryRootPath,
    );
    const candidates = await collectGeneratedCleanupCandidates({
        now: input.now,
        workspaceRootPath,
    });
    if (!input.apply) {
        return candidates;
    }
    for (const candidate of candidates) {
        await requireExistingPathWithoutLinks(
            workspaceRootPath,
            candidate.absolutePath,
        );
        await rm(candidate.absolutePath, {
            force: false,
            recursive: candidate.recursive,
        });
    }
    for (const definition of retentionDirectoryDefinitions) {
        const retentionRootPath = path.resolve(
            workspaceRootPath,
            definition.relativePath,
        );
        if (await pathExists(retentionRootPath)) {
            await removeEmptyDirectories(retentionRootPath);
        }
    }

    return candidates;
};

const main = async (): Promise<void> => {
    const options = parseGeneratedCleanupArguments(process.argv.slice(2));
    const candidates = await runGeneratedCleanup(options);
    if (candidates.length === 0) {
        console.log('No generated output matches the cleanup policy.');
        return;
    }
    console.log(
        options.apply
            ? 'Removed generated output:'
            : 'Generated output that would be removed:',
    );
    for (const candidate of candidates) {
        console.log(`- ${candidate.relativePath}: ${candidate.description}`);
    }
    if (!options.apply) {
        console.log('Re-run with --apply to remove these paths.');
    }
};

if (isDirectlyInvokedModule(import.meta.url)) {
    void main();
}
