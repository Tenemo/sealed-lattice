import { appendFileSync, readFileSync } from 'node:fs';

import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';

const documentationDirectoryPrefixes = ['reference-documents/'] as const;
const licenseFilePattern =
    /(?:^|\/)(?:copying|licen[cs]e|notice)(?:\.(?:md|txt))?$/iu;

const normalizeChangedPath = (changedPath: string): string =>
    changedPath.replace(/\\/gu, '/').replace(/^\.\//u, '');

export const isDocumentationOnlyCiPath = (changedPath: string): boolean => {
    const normalizedPath = normalizeChangedPath(changedPath);
    if (
        normalizedPath.length === 0 ||
        normalizedPath.startsWith('../') ||
        normalizedPath.includes('/../')
    ) {
        return false;
    }

    return (
        normalizedPath.endsWith('.md') ||
        licenseFilePattern.test(normalizedPath) ||
        documentationDirectoryPrefixes.some((directoryPrefix) =>
            normalizedPath.startsWith(directoryPrefix),
        )
    );
};

export const shouldRunHeavyCiLanes = (
    changedPaths: readonly string[],
): boolean =>
    changedPaths.length === 0 ||
    changedPaths.some((changedPath) => !isDocumentationOnlyCiPath(changedPath));

const gitNameStatusPattern = /^[ACDMRTUXB](?:\d+)?$/u;

export const parseNullDelimitedGitNameStatus = (
    nameStatusBuffer: Buffer,
): string[] => {
    const tokens = nameStatusBuffer
        .toString('utf8')
        .split('\0')
        .filter((token) => token.length > 0);
    const changedPaths: string[] = [];

    for (let tokenIndex = 0; tokenIndex < tokens.length; ) {
        const status = tokens[tokenIndex];
        tokenIndex += 1;
        if (status === undefined || !gitNameStatusPattern.test(status)) {
            throw new Error(
                `Unexpected git name-status entry: ${status ?? '<missing>'}`,
            );
        }

        const pathCount =
            status.startsWith('R') || status.startsWith('C') ? 2 : 1;
        const entryPaths = tokens.slice(tokenIndex, tokenIndex + pathCount);
        if (entryPaths.length !== pathCount) {
            throw new Error(
                `Git name-status entry ${status} is missing a path.`,
            );
        }
        changedPaths.push(...entryPaths);
        tokenIndex += pathCount;
    }

    return changedPaths;
};

const main = (): void => {
    const changedPaths = parseNullDelimitedGitNameStatus(readFileSync(0));
    const runHeavyLanes = shouldRunHeavyCiLanes(changedPaths);
    const output = `run_heavy=${runHeavyLanes ? 'true' : 'false'}\n`;
    const githubOutputPath = process.env.GITHUB_OUTPUT;
    if (githubOutputPath !== undefined && githubOutputPath.length > 0) {
        appendFileSync(githubOutputPath, output, 'utf8');
    }
    process.stdout.write(output);
};

if (isDirectlyInvokedModule(import.meta.url)) {
    main();
}
