import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
export const vectorsRootDirectoryPath = path.resolve(repoRoot, 'test-vectors');
export const vectorManifestPath = path.resolve(
    vectorsRootDirectoryPath,
    'manifest.json',
);
const ignoredVectorRelativePathSet = new Set(['README.md', 'manifest.json']);
const sha256Pattern = /^[a-f0-9]{64}$/u;

export type VectorManifestEntry = {
    path: string;
    sha256: string;
};

export type VectorManifest = {
    entries: readonly VectorManifestEntry[];
    schemaVersion: 1;
};

export const normalizeVectorRelativePath = (relativePath: string): string => {
    return relativePath.replace(/\\/g, '/');
};

export const isTrackedVectorRelativePath = (relativePath: string): boolean => {
    return !ignoredVectorRelativePathSet.has(
        normalizeVectorRelativePath(relativePath),
    );
};

export const hashVectorFile = async (filePath: string): Promise<string> => {
    const fileBuffer = await fs.readFile(filePath);

    return createHash('sha256').update(fileBuffer).digest('hex');
};

export const collectTrackedVectorRelativePaths = async (
    rootDirectoryPath: string,
): Promise<string[]> => {
    const trackedRelativePaths: string[] = [];
    const pendingDirectoryPaths = [rootDirectoryPath];

    while (pendingDirectoryPaths.length > 0) {
        const currentDirectoryPath = pendingDirectoryPaths.pop();
        if (currentDirectoryPath === undefined) {
            continue;
        }

        const entries = await fs.readdir(currentDirectoryPath, {
            withFileTypes: true,
        });

        for (const entry of entries) {
            const entryPath = path.join(currentDirectoryPath, entry.name);

            if (entry.isDirectory()) {
                pendingDirectoryPaths.push(entryPath);
                continue;
            }

            if (!entry.isFile()) {
                continue;
            }

            const relativePath = normalizeVectorRelativePath(
                path.relative(rootDirectoryPath, entryPath),
            );
            if (!isTrackedVectorRelativePath(relativePath)) {
                continue;
            }

            trackedRelativePaths.push(relativePath);
        }
    }

    return trackedRelativePaths.sort((left, right) =>
        left.localeCompare(right),
    );
};

export const buildVectorManifestFromDirectory = async (
    rootDirectoryPath: string,
): Promise<VectorManifest> => {
    const trackedRelativePaths =
        await collectTrackedVectorRelativePaths(rootDirectoryPath);
    const entries = await Promise.all(
        trackedRelativePaths.map(async (relativePath) => ({
            path: relativePath,
            sha256: await hashVectorFile(
                path.join(rootDirectoryPath, relativePath),
            ),
        })),
    );

    return {
        schemaVersion: 1,
        entries,
    };
};

export const validateVectorManifest = (
    manifest: VectorManifest,
    actualManifest: VectorManifest,
): string[] => {
    const failures: string[] = [];

    if (manifest.schemaVersion !== 1) {
        failures.push(
            `Unsupported vector manifest schemaVersion: ${String(manifest.schemaVersion)}`,
        );
    }

    const manifestPaths = new Set<string>();
    for (const entry of manifest.entries) {
        const normalizedPath = normalizeVectorRelativePath(entry.path);

        if (normalizedPath !== entry.path) {
            failures.push(
                `Vector manifest path must use forward slashes: ${entry.path}`,
            );
        }
        if (!isTrackedVectorRelativePath(normalizedPath)) {
            failures.push(`Vector manifest path is reserved: ${entry.path}`);
        }
        if (entry.path.startsWith('../') || path.isAbsolute(entry.path)) {
            failures.push(
                `Vector manifest path must stay within test-vectors: ${entry.path}`,
            );
        }
        if (!sha256Pattern.test(entry.sha256)) {
            failures.push(
                `Vector manifest entry ${entry.path} must use a lowercase SHA-256 digest`,
            );
        }
        if (manifestPaths.has(entry.path)) {
            failures.push(`Vector manifest path is duplicated: ${entry.path}`);
        }

        manifestPaths.add(entry.path);
    }

    const expectedEntriesByPath = new Map(
        manifest.entries.map((entry) => [entry.path, entry.sha256]),
    );
    const actualEntriesByPath = new Map(
        actualManifest.entries.map((entry) => [entry.path, entry.sha256]),
    );

    for (const actualEntry of actualManifest.entries) {
        const expectedSha256 = expectedEntriesByPath.get(actualEntry.path);
        if (expectedSha256 === undefined) {
            failures.push(
                `Vector file is missing from manifest: ${actualEntry.path}`,
            );
            continue;
        }
        if (expectedSha256 !== actualEntry.sha256) {
            failures.push(
                `Vector digest drift detected for ${actualEntry.path}: expected ${expectedSha256}, received ${actualEntry.sha256}`,
            );
        }
    }

    for (const entry of manifest.entries) {
        if (!actualEntriesByPath.has(entry.path)) {
            failures.push(
                `Vector manifest entry is missing on disk: ${entry.path}`,
            );
        }
    }

    return failures;
};

export const loadVectorManifest = async (
    manifestPath: string = vectorManifestPath,
): Promise<VectorManifest> => {
    return JSON.parse(
        await fs.readFile(manifestPath, 'utf8'),
    ) as VectorManifest;
};

/* v8 ignore start */
const main = async (
    commandLineArguments: readonly string[] = process.argv.slice(2),
): Promise<void> => {
    if (commandLineArguments.includes('--generate')) {
        const manifest = await buildVectorManifestFromDirectory(
            vectorsRootDirectoryPath,
        );
        await fs.writeFile(
            vectorManifestPath,
            `${JSON.stringify(manifest, null, 2)}\n`,
            'utf8',
        );

        console.log(
            `Vector manifest written to ${path.relative(process.cwd(), vectorManifestPath)}`,
        );
        return;
    }

    const manifest = await loadVectorManifest();
    const actualManifest = await buildVectorManifestFromDirectory(
        vectorsRootDirectoryPath,
    );
    const failures = validateVectorManifest(manifest, actualManifest);

    if (failures.length > 0) {
        throw new Error(failures.join('\n'));
    }

    console.log('Test vectors manifest verification passed.');
};

if (process.argv[1] === fileURLToPath(import.meta.url)) {
    void main();
}
/* v8 ignore stop */
