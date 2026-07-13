import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { stagePublicPackage } from '#tools/ci/stage-public-package.mjs';

const temporaryRoots: string[] = [];

const createTemporaryRoot = async (): Promise<string> => {
    const temporaryRoot = await mkdtemp(
        path.join(tmpdir(), 'sealed-lattice-stage-package-test-'),
    );
    temporaryRoots.push(temporaryRoot);

    return temporaryRoot;
};

const writeFixtureProject = async (projectRoot: string): Promise<void> => {
    const publicPackageDirectory = path.join(projectRoot, 'packages', 'sdk');
    await mkdir(path.join(publicPackageDirectory, 'dist'), {
        recursive: true,
    });
    await writeFile(
        path.join(projectRoot, 'README.md'),
        '# Root readme\n\nThis is the public package readme.\n',
        'utf8',
    );
    await writeFile(
        path.join(projectRoot, 'LICENSE'),
        'canonical license text\n',
        'utf8',
    );
    await writeFile(
        path.join(publicPackageDirectory, 'package.json'),
        `${JSON.stringify(
            {
                name: 'sealed-lattice',
                version: '0.0.0',
                description: 'Public package description.',
                files: ['dist', 'README.md', 'LICENSE'],
                scripts: {
                    build: 'pnpm run build',
                },
                devDependencies: {
                    '@sealed-lattice/types': 'workspace:*',
                },
            },
            null,
            4,
        )}\n`,
        'utf8',
    );
    await writeFile(
        path.join(publicPackageDirectory, 'dist', 'index.js'),
        'export {};\n',
        'utf8',
    );
};

afterEach(async () => {
    for (const temporaryRoot of temporaryRoots.splice(0)) {
        await rm(temporaryRoot, { recursive: true, force: true });
    }
});

describe('public package staging', () => {
    it('stages the public files and removes workspace-only metadata', async () => {
        const projectRoot = await createTemporaryRoot();
        await writeFixtureProject(projectRoot);
        const destinationPath = path.join(projectRoot, 'staged-package');

        await stagePublicPackage({ destinationPath, projectRoot });

        const stagedManifest = JSON.parse(
            await readFile(path.join(destinationPath, 'package.json'), 'utf8'),
        ) as Record<string, unknown>;
        expect(stagedManifest).toMatchObject({
            description: 'Public package description.',
            name: 'sealed-lattice',
        });
        expect(stagedManifest).not.toHaveProperty('devDependencies');
        expect(stagedManifest).not.toHaveProperty('scripts');
    });

    it('rejects non-empty staging destinations', async () => {
        const projectRoot = await createTemporaryRoot();
        await writeFixtureProject(projectRoot);
        const destinationPath = path.join(projectRoot, 'staged-package');

        await mkdir(destinationPath);
        await writeFile(path.join(destinationPath, 'leftover.txt'), 'old');

        await expect(
            stagePublicPackage({ destinationPath, projectRoot }),
        ).rejects.toThrow(
            `Public package staging directory must be empty: ${destinationPath}`,
        );
    });
});
