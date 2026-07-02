import { promises as fs } from 'node:fs';
import path from 'node:path';

type CollectFilesOptions = {
    readonly allowMissing?: boolean;
    readonly extensions?: readonly string[];
    readonly fileNamePattern?: RegExp;
};

const matchesFileOptions = (
    filePath: string,
    options: CollectFilesOptions,
): boolean => {
    const extensionMatches =
        options.extensions === undefined ||
        options.extensions.includes(path.extname(filePath));
    const patternMatches =
        options.fileNamePattern === undefined ||
        options.fileNamePattern.test(path.basename(filePath));

    return extensionMatches && patternMatches;
};

export const isWithinDirectory = (
    directoryPath: string,
    candidatePath: string,
): boolean => {
    const relativePath = path.relative(directoryPath, candidatePath);

    return (
        relativePath === '' ||
        (!relativePath.startsWith('..') && !path.isAbsolute(relativePath))
    );
};

export const toPosixPath = (filePath: string): string =>
    filePath.replace(/\\/g, '/');

export const collectFiles = async (
    entryPath: string,
    options: CollectFilesOptions = {},
): Promise<string[]> => {
    let entryStats;
    try {
        entryStats = await fs.stat(entryPath);
    } catch (error) {
        if (options.allowMissing === true) {
            return [];
        }
        throw error;
    }

    if (entryStats.isFile()) {
        return matchesFileOptions(entryPath, options) ? [entryPath] : [];
    }

    if (!entryStats.isDirectory()) {
        return [];
    }

    const files: string[] = [];
    const pendingDirectories = [entryPath];

    while (pendingDirectories.length > 0) {
        const currentDirectoryPath = pendingDirectories.pop()!;

        const entries = await fs.readdir(currentDirectoryPath, {
            withFileTypes: true,
        });

        for (const entry of entries) {
            const childPath = path.join(currentDirectoryPath, entry.name);
            if (entry.isDirectory()) {
                pendingDirectories.push(childPath);
                continue;
            }

            if (entry.isFile() && matchesFileOptions(childPath, options)) {
                files.push(childPath);
            }
        }
    }

    return files.sort();
};

const filesystemRetryDelayMilliseconds = 50;
export const filesystemMaximumRetries = 12;

const transientFilesystemErrorCodes = new Set([
    'ENOENT',
    'EPERM',
    'EACCES',
    'EBUSY',
    'ENOTEMPTY',
    'EMFILE',
    'ENFILE',
]);

const delayMilliseconds = (milliseconds: number): Promise<void> =>
    new Promise((resolve) => {
        setTimeout(resolve, milliseconds);
    });

const isTransientFilesystemError = (error: unknown): boolean => {
    const errorCode = (error as NodeJS.ErrnoException).code;

    return (
        errorCode !== undefined && transientFilesystemErrorCodes.has(errorCode)
    );
};

export const withTransientFilesystemRetries = async <ResultType>(
    operation: () => Promise<ResultType>,
    delay: (milliseconds: number) => Promise<void> = delayMilliseconds,
): Promise<ResultType> => {
    for (let attempt = 1; ; attempt += 1) {
        try {
            return await operation();
        } catch (error) {
            if (
                attempt >= filesystemMaximumRetries ||
                !isTransientFilesystemError(error)
            ) {
                throw error;
            }
            await delay(filesystemRetryDelayMilliseconds * attempt);
        }
    }
};
