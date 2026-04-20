import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));

const buildArtifactRules = [
    {
        description: 'dist output',
        matches: (
            segments: readonly string[],
            normalizedPath: string,
        ): boolean =>
            segments.includes('dist') ||
            normalizedPath.startsWith('docs/dist/'),
    },
    {
        description: 'coverage output',
        matches: (
            segments: readonly string[],
            normalizedPath: string,
        ): boolean =>
            segments.includes('coverage') ||
            normalizedPath === 'docs/public/coverage-badge.json' ||
            normalizedPath === 'docs/public/coverage-summary.json',
    },
    {
        description: 'TypeScript build info',
        matches: (
            _segments: readonly string[],
            normalizedPath: string,
        ): boolean => normalizedPath.endsWith('.tsbuildinfo'),
    },
    {
        description: 'Rust target output',
        matches: (segments: readonly string[]): boolean =>
            segments.includes('target'),
    },
    {
        description: 'Turbo cache output',
        matches: (segments: readonly string[]): boolean =>
            segments.includes('.turbo'),
    },
    {
        description: 'generated docs reference output',
        matches: (
            _segments: readonly string[],
            normalizedPath: string,
        ): boolean =>
            normalizedPath.startsWith('docs/src/content/docs/api/reference/'),
    },
    {
        description: 'Astro cache output',
        matches: (
            _segments: readonly string[],
            normalizedPath: string,
        ): boolean => normalizedPath.startsWith('docs/.astro/'),
    },
];

export const normalizeRepositoryRelativePath = (relativePath: string): string =>
    relativePath.replace(/\\/g, '/');

export const parseTrackedRepositoryPaths = (
    trackedPathOutput: string,
): string[] => {
    return trackedPathOutput
        .split('\0')
        .filter((trackedPath) => trackedPath !== '')
        .map(normalizeRepositoryRelativePath)
        .sort((left, right) => left.localeCompare(right));
};

export const findTrackedBuildArtifactFailures = (
    trackedPaths: readonly string[],
): string[] => {
    const failures: string[] = [];

    for (const trackedPath of trackedPaths) {
        const normalizedPath = normalizeRepositoryRelativePath(trackedPath);
        const pathSegments = normalizedPath.split('/').filter(Boolean);

        for (const rule of buildArtifactRules) {
            if (!rule.matches(pathSegments, normalizedPath)) {
                continue;
            }

            failures.push(
                `Tracked build artifact is forbidden (${rule.description}): ${normalizedPath}`,
            );
        }
    }

    return failures;
};

const loadTrackedPathsFromGit = (): string[] => {
    const result = spawnSync('git', ['ls-files', '-z'], {
        cwd: repoRoot,
        encoding: 'utf8',
        maxBuffer: 100 * 1024 * 1024,
    });

    if (result.error !== undefined) {
        throw new Error(
            `Failed to start git ls-files: ${result.error.message}`,
        );
    }
    if (result.signal !== null) {
        throw new Error(`git ls-files terminated by signal ${result.signal}`);
    }
    if (result.status !== 0) {
        const stderr = result.stderr?.trim();
        const details =
            stderr === '' || stderr === undefined ? '' : `\n${stderr}`;

        throw new Error(
            `git ls-files exited with status ${result.status ?? 'null'}${details}`,
        );
    }

    return parseTrackedRepositoryPaths(result.stdout ?? '');
};

/* v8 ignore start */
const main = (): void => {
    const failures = findTrackedBuildArtifactFailures(
        loadTrackedPathsFromGit(),
    );

    if (failures.length > 0) {
        throw new Error(failures.join('\n'));
    }

    console.log(
        `Repository hygiene verification passed for ${path.basename(repoRoot)}.`,
    );
};

const scriptEntryPoint = process.argv[1];
const isMainModule =
    scriptEntryPoint !== undefined &&
    import.meta.url === pathToFileURL(scriptEntryPoint).href;

if (isMainModule) {
    main();
}
/* v8 ignore stop */
