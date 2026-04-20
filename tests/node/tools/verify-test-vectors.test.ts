import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import {
    buildVectorManifestFromDirectory,
    collectTrackedVectorRelativePaths,
    isTrackedVectorRelativePath,
    normalizeVectorRelativePath,
    validateVectorManifest,
} from '../../../tools/ci/verify-test-vectors';

const tempDirectoryPaths: string[] = [];

const createTempVectorsDirectory = async (): Promise<string> => {
    const directoryPath = await mkdtemp(
        path.join(tmpdir(), 'sealed-lattice-vectors-'),
    );
    tempDirectoryPaths.push(directoryPath);

    return directoryPath;
};

afterEach(async () => {
    await Promise.all(
        tempDirectoryPaths
            .splice(0)
            .map((directoryPath) =>
                rm(directoryPath, { recursive: true, force: true }),
            ),
    );
});

describe('test vector helpers', () => {
    it('normalizes relative paths and filters reserved files', () => {
        expect(normalizeVectorRelativePath('nested\\vector.json')).toBe(
            'nested/vector.json',
        );
        expect(isTrackedVectorRelativePath('README.md')).toBe(false);
        expect(isTrackedVectorRelativePath('manifest.json')).toBe(false);
        expect(isTrackedVectorRelativePath('crypto/example.json')).toBe(true);
    });

    it('collects tracked vector paths and ignores reserved files', async () => {
        const rootDirectoryPath = await createTempVectorsDirectory();

        await writeFile(path.join(rootDirectoryPath, 'README.md'), 'ignored\n');
        await writeFile(
            path.join(rootDirectoryPath, 'manifest.json'),
            '{ "schemaVersion": 1, "entries": [] }\n',
        );
        await mkdir(path.join(rootDirectoryPath, 'crypto'), {
            recursive: true,
        });
        await writeFile(
            path.join(rootDirectoryPath, 'crypto', 'example.json'),
            '{"value":1}\n',
        );

        await expect(
            collectTrackedVectorRelativePaths(rootDirectoryPath),
        ).resolves.toEqual(['crypto/example.json']);
    });

    it('builds a manifest from tracked files', async () => {
        const rootDirectoryPath = await createTempVectorsDirectory();

        await mkdir(path.join(rootDirectoryPath, 'crypto'), {
            recursive: true,
        });
        await writeFile(
            path.join(rootDirectoryPath, 'crypto', 'example.json'),
            '{"value":1}\n',
        );

        await expect(
            buildVectorManifestFromDirectory(rootDirectoryPath),
        ).resolves.toEqual({
            schemaVersion: 1,
            entries: [
                {
                    path: 'crypto/example.json',
                    sha256: '3a37782e8974c48eebf2a0517c866ad15641c53b3d31993188796b56aeb79624',
                },
            ],
        });
    });

    it('reports digest drift, missing files, and duplicate entries', () => {
        const actualManifest = {
            schemaVersion: 1 as const,
            entries: [
                {
                    path: 'crypto/example.json',
                    sha256: '3a37782e8974c48eebf2a0517c866ad15641c53b3d31993188796b56aeb79624',
                },
            ],
        };

        const manifest = {
            schemaVersion: 1 as const,
            entries: [
                {
                    path: 'crypto/example.json',
                    sha256: '0'.repeat(64),
                },
                {
                    path: 'crypto/example.json',
                    sha256: '0'.repeat(64),
                },
                {
                    path: 'missing.json',
                    sha256: '1'.repeat(64),
                },
            ],
        };

        expect(validateVectorManifest(manifest, actualManifest)).toEqual(
            expect.arrayContaining([
                'Vector manifest path is duplicated: crypto/example.json',
                'Vector digest drift detected for crypto/example.json: expected 0000000000000000000000000000000000000000000000000000000000000000, received 3a37782e8974c48eebf2a0517c866ad15641c53b3d31993188796b56aeb79624',
                'Vector manifest entry is missing on disk: missing.json',
            ]),
        );
    });

    it('reports files present on disk but missing from the manifest', () => {
        const manifest = {
            schemaVersion: 1 as const,
            entries: [],
        };
        const actualManifest = {
            schemaVersion: 1 as const,
            entries: [
                {
                    path: 'crypto/example.json',
                    sha256: '2'.repeat(64),
                },
            ],
        };

        expect(validateVectorManifest(manifest, actualManifest)).toEqual([
            'Vector file is missing from manifest: crypto/example.json',
        ]);
    });
});
