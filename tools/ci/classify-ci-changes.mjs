import { execFileSync } from 'node:child_process';
import { appendFileSync, readFileSync } from 'node:fs';
import { isDeepStrictEqual } from 'node:util';

/**
 * @typedef {{ readonly paths: readonly string[], readonly status: string }} GitNameStatusEntry
 * @typedef {{ baseRevision?: string, headRevision?: string }} ParsedArguments
 */

const publicPackageManifestPath = 'packages/sdk/package.json';
const documentationDirectoryPrefixes = ['reference-documents/'];
const toolingDirectoryPrefixes = [
    '.github/',
    '.husky/',
    'tests/node/tools/',
    'tools/ci/',
    'tools/internal/',
    'tools/lattigo-oracle/',
];
const toolingFiles = new Set([
    '.editorconfig',
    '.gitattributes',
    '.gitignore',
    '.ignore',
    'AGENTS.md',
    'CLAUDE.md',
    'eslint.config.js',
    'knip.jsonc',
    'tests/node/heavy-test-progress.test.ts',
    'tests/node/terminal-line-filter.test.ts',
    'tsconfig.tools.json',
]);
const heavyRuntimeDirectoryPrefixes = [
    'crates/',
    'fuzz/',
    'packages/crypto/src/',
    'packages/protocol/src/',
    'packages/sdk/src/',
    'packages/types/src/',
    'packages/wasm/src/',
    'packages/wasm/tests/node/transcript-core-kernel/',
    'test-vectors/',
    'tests/support/',
    'tools/process-memory-guard/',
];
const licenseFilePattern =
    /(?:^|\/)(?:copying|licen[cs]e|notice)(?:\.(?:md|txt))?$/iu;
const stablePrototypeVersionPattern =
    /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/u;
const gitNameStatusPattern = /^[ACDMRTUXB](?:\d+)?$/u;

/** @param {string} changedPath */
const normalizeChangedPath = (changedPath) =>
    changedPath.replace(/\\/gu, '/').replace(/^\.\//u, '');

/** @param {string} changedPath */
const isSafeRepositoryPath = (changedPath) =>
    changedPath.length > 0 &&
    !changedPath.startsWith('../') &&
    !changedPath.includes('/../');

/** @param {string} changedPath */
export const isDocumentationOnlyCiPath = (changedPath) => {
    const normalizedPath = normalizeChangedPath(changedPath);
    if (!isSafeRepositoryPath(normalizedPath)) {
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

/** @param {string} changedPath */
export const isToolingOnlyCiPath = (changedPath) => {
    const normalizedPath = normalizeChangedPath(changedPath);
    if (!isSafeRepositoryPath(normalizedPath)) {
        return false;
    }

    return (
        toolingFiles.has(normalizedPath) ||
        toolingDirectoryPrefixes.some((directoryPrefix) =>
            normalizedPath.startsWith(directoryPrefix),
        ) ||
        /^packages\/[^/]+\/tests\//u.test(normalizedPath)
    );
};

/**
 * @param {readonly string[]} changedPaths
 * @param {boolean} [versionOnlyReleaseChange]
 */
export const shouldRunHeavyCiLanes = (
    changedPaths,
    versionOnlyReleaseChange = false,
) => {
    if (changedPaths.length === 0) {
        return true;
    }

    if (
        versionOnlyReleaseChange &&
        changedPaths.length === 1 &&
        normalizeChangedPath(changedPaths[0]) === publicPackageManifestPath
    ) {
        return false;
    }

    return changedPaths.some((changedPath) => {
        const normalizedPath = normalizeChangedPath(changedPath);
        if (
            heavyRuntimeDirectoryPrefixes.some((directoryPrefix) =>
                normalizedPath.startsWith(directoryPrefix),
            )
        ) {
            return true;
        }
        return (
            !isDocumentationOnlyCiPath(normalizedPath) &&
            !isToolingOnlyCiPath(normalizedPath)
        );
    });
};

/** @param {import('node:buffer').Buffer} nameStatusBuffer */
export const parseNullDelimitedGitNameStatus = (nameStatusBuffer) => {
    const tokens = nameStatusBuffer
        .toString('utf8')
        .split('\0')
        .filter((token) => token.length > 0);
    /** @type {GitNameStatusEntry[]} */
    const entries = [];

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
        const paths = tokens.slice(tokenIndex, tokenIndex + pathCount);
        if (paths.length !== pathCount) {
            throw new Error(
                `Git name-status entry ${status} is missing a path.`,
            );
        }
        entries.push({ paths, status });
        tokenIndex += pathCount;
    }

    return entries;
};

/** @param {unknown} version */
const parseStablePrototypeVersion = (version) => {
    if (typeof version !== 'string') {
        return undefined;
    }
    const match = stablePrototypeVersionPattern.exec(version);
    if (match?.[1] !== '0') {
        return undefined;
    }
    return {
        minor: Number(match[2]),
        patch: Number(match[3]),
    };
};

/**
 * @param {string} previousManifestText
 * @param {string} nextManifestText
 */
export const isVersionOnlyReleaseManifestChange = (
    previousManifestText,
    nextManifestText,
) => {
    /** @type {unknown} */
    let previousManifest;
    /** @type {unknown} */
    let nextManifest;
    try {
        previousManifest = JSON.parse(previousManifestText);
        nextManifest = JSON.parse(nextManifestText);
    } catch {
        return false;
    }
    if (
        typeof previousManifest !== 'object' ||
        previousManifest === null ||
        Array.isArray(previousManifest) ||
        typeof nextManifest !== 'object' ||
        nextManifest === null ||
        Array.isArray(nextManifest) ||
        !('name' in previousManifest) ||
        previousManifest.name !== 'sealed-lattice' ||
        !('name' in nextManifest) ||
        nextManifest.name !== 'sealed-lattice'
    ) {
        return false;
    }

    const previousVersion = parseStablePrototypeVersion(
        'version' in previousManifest ? previousManifest.version : undefined,
    );
    const nextVersion = parseStablePrototypeVersion(
        'version' in nextManifest ? nextManifest.version : undefined,
    );
    if (previousVersion === undefined || nextVersion === undefined) {
        return false;
    }

    const previousWithoutVersion = { ...previousManifest };
    const nextWithoutVersion = { ...nextManifest };
    delete previousWithoutVersion.version;
    delete nextWithoutVersion.version;
    if (!isDeepStrictEqual(previousWithoutVersion, nextWithoutVersion)) {
        return false;
    }

    const isPatchIncrement =
        nextVersion.minor === previousVersion.minor &&
        nextVersion.patch === previousVersion.patch + 1;
    const isMinorIncrement =
        nextVersion.minor === previousVersion.minor + 1 &&
        nextVersion.patch === 0;
    return isPatchIncrement || isMinorIncrement;
};

/** @param {string} revision */
const readManifestAtRevision = (revision) =>
    execFileSync('git', ['show', `${revision}:${publicPackageManifestPath}`], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
    });

/** @param {readonly string[]} rawArguments */
const parseArguments = (rawArguments) => {
    /** @type {ParsedArguments} */
    const parsedArguments = {};
    for (let argumentIndex = 0; argumentIndex < rawArguments.length; ) {
        const option = rawArguments[argumentIndex];
        const value = rawArguments[argumentIndex + 1];
        if (
            (option !== '--base' && option !== '--head') ||
            value === undefined
        ) {
            throw new Error(
                'Usage: classify-ci-changes.mjs [--base SHA --head SHA].',
            );
        }
        parsedArguments[option === '--base' ? 'baseRevision' : 'headRevision'] =
            value;
        argumentIndex += 2;
    }
    if (
        (parsedArguments.baseRevision === undefined) !==
        (parsedArguments.headRevision === undefined)
    ) {
        throw new Error('Both --base and --head are required together.');
    }
    return parsedArguments;
};

const main = () => {
    let runHeavyLanes = true;
    try {
        const parsedArguments = parseArguments(process.argv.slice(2));
        const entries = parseNullDelimitedGitNameStatus(readFileSync(0));
        const changedPaths = entries.flatMap((entry) => entry.paths);
        let versionOnlyReleaseChange = false;
        if (
            entries.length === 1 &&
            entries[0].status === 'M' &&
            entries[0].paths.length === 1 &&
            normalizeChangedPath(entries[0].paths[0]) ===
                publicPackageManifestPath &&
            parsedArguments.baseRevision !== undefined &&
            parsedArguments.headRevision !== undefined
        ) {
            versionOnlyReleaseChange = isVersionOnlyReleaseManifestChange(
                readManifestAtRevision(parsedArguments.baseRevision),
                readManifestAtRevision(parsedArguments.headRevision),
            );
        }
        runHeavyLanes = shouldRunHeavyCiLanes(
            changedPaths,
            versionOnlyReleaseChange,
        );
    } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        process.stderr.write(
            `Could not classify changed paths (${message}); running expensive proof lanes.\n`,
        );
    }

    const output = `run_heavy=${runHeavyLanes ? 'true' : 'false'}\n`;
    const githubOutputPath = process.env.GITHUB_OUTPUT;
    if (githubOutputPath !== undefined && githubOutputPath.length > 0) {
        appendFileSync(githubOutputPath, output, 'utf8');
    }
    process.stdout.write(output);
};

if (import.meta.main) {
    main();
}
