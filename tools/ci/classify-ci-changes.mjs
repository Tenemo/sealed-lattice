import { execFileSync } from 'node:child_process';
import { appendFileSync } from 'node:fs';
import { isDeepStrictEqual } from 'node:util';

/**
 * @typedef {{ readonly paths: readonly string[], readonly status: string }} GitNameStatusEntry
 * @typedef {{ readonly baseRevision: string, readonly headRevision: string }} CiRevisions
 */

const publicPackageManifestPath = 'packages/sdk/package.json';
const documentationDirectoryPrefixes = ['reference-documents/'];
const toolingDirectoryPrefixes = [
    '.husky/',
    'tests/node/tools/',
    'tools/internal/',
];
const heavyLaneDefinitionDirectoryPrefixes = [
    '.github/workflows/',
    'tools/ci/',
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
    'packages/crypto/src/',
    'packages/protocol/src/',
    'packages/sdk/src/',
    'packages/types/src/',
    'packages/wasm/src/',
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
export const isDocumentationOnlyCiPath = (changedPath) => {
    const normalizedPath = normalizeChangedPath(changedPath);
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
export const shouldRunRoutineCiLanes = (
    changedPaths,
    versionOnlyReleaseChange = false,
) => {
    if (changedPaths.length === 0) return true;
    if (
        versionOnlyReleaseChange &&
        changedPaths.length === 1 &&
        normalizeChangedPath(changedPaths[0]) === publicPackageManifestPath
    ) {
        return false;
    }

    return !changedPaths.every(isDocumentationOnlyCiPath);
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
            heavyLaneDefinitionDirectoryPrefixes.some((directoryPrefix) =>
                normalizedPath.startsWith(directoryPrefix),
            ) ||
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

/** @param {NodeJS.ProcessEnv} environment */
export const resolveCiRevisions = (environment) => {
    const eventName = environment.EVENT_NAME;
    const headRevision =
        eventName === 'pull_request'
            ? environment.PULL_REQUEST_HEAD_SHA
            : environment.GITHUB_SHA;
    let baseRevision;
    if (eventName === 'pull_request') {
        baseRevision = environment.PULL_REQUEST_BASE_SHA;
    } else if (eventName === 'push') {
        baseRevision = environment.PUSH_BASE_SHA;
        if (/^0+$/u.test(baseRevision ?? '')) {
            throw new Error('The first push has no comparison revision.');
        }
    } else if (eventName === 'workflow_dispatch') {
        if (headRevision === undefined) {
            throw new Error('Workflow dispatch is missing GITHUB_SHA.');
        }
        baseRevision = execFileSync('git', ['rev-parse', `${headRevision}^`], {
            encoding: 'utf8',
            stdio: ['ignore', 'pipe', 'pipe'],
        }).trim();
    } else {
        throw new Error(
            `Unsupported GitHub event: ${eventName ?? '<missing>'}.`,
        );
    }
    if (baseRevision === undefined || headRevision === undefined) {
        throw new Error('The GitHub event is missing comparison revisions.');
    }

    return { baseRevision, headRevision };
};

/** @param {CiRevisions} revisions */
const collectChangedEntries = (revisions) =>
    parseNullDelimitedGitNameStatus(
        execFileSync(
            'git',
            [
                'diff',
                '--name-status',
                '-z',
                revisions.baseRevision,
                revisions.headRevision,
            ],
            { maxBuffer: 10 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] },
        ),
    );

const main = () => {
    let runHeavyLanes = true;
    let runRoutineLanes = true;
    try {
        const revisions = resolveCiRevisions(process.env);
        const entries = collectChangedEntries(revisions);
        const changedPaths = entries.flatMap((entry) => entry.paths);
        let versionOnlyReleaseChange = false;
        if (
            entries.length === 1 &&
            entries[0].status === 'M' &&
            entries[0].paths.length === 1 &&
            normalizeChangedPath(entries[0].paths[0]) ===
                publicPackageManifestPath
        ) {
            versionOnlyReleaseChange = isVersionOnlyReleaseManifestChange(
                readManifestAtRevision(revisions.baseRevision),
                readManifestAtRevision(revisions.headRevision),
            );
        }
        runRoutineLanes = shouldRunRoutineCiLanes(
            changedPaths,
            versionOnlyReleaseChange,
        );
        runHeavyLanes = shouldRunHeavyCiLanes(
            changedPaths,
            versionOnlyReleaseChange,
        );
    } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        process.stderr.write(
            `Could not classify changed paths (${message}); running routine and expensive proof lanes.\n`,
        );
    }

    const output =
        `run_routine=${runRoutineLanes ? 'true' : 'false'}\n` +
        `run_heavy=${runHeavyLanes ? 'true' : 'false'}\n`;
    const githubOutputPath = process.env.GITHUB_OUTPUT;
    if (githubOutputPath !== undefined && githubOutputPath.length > 0) {
        appendFileSync(githubOutputPath, output, 'utf8');
    }
    process.stdout.write(output);
};

if (import.meta.main) {
    main();
}
