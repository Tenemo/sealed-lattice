import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import {
    parseStagePublicPackageArguments,
    sanitizePublicPackageJson,
    stagePublicPackage,
} from '#tools/ci/stage-public-package.mjs';

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
        path.join(projectRoot, 'package.json'),
        `${JSON.stringify(
            {
                description: 'Root public package description.',
            },
            null,
            4,
        )}\n`,
        'utf8',
    );
    await writeFile(
        path.join(publicPackageDirectory, 'README.md'),
        '# SDK readme\n\nThis stays package-local.\n',
        'utf8',
    );
    await writeFile(
        path.join(publicPackageDirectory, 'package.json'),
        `${JSON.stringify(
            {
                name: 'sealed-lattice',
                version: '0.0.0',
                files: ['dist', 'README.md', 'LICENSE', 'public-surface.json'],
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
        path.join(publicPackageDirectory, 'LICENSE'),
        'license text\n',
        'utf8',
    );
    await writeFile(
        path.join(publicPackageDirectory, 'public-surface.json'),
        '{"runtimeExports":[]}\n',
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
    it('stages public package files from the SDK package and root README', async () => {
        const projectRoot = await createTemporaryRoot();
        await writeFixtureProject(projectRoot);
        const destinationPath = path.join(projectRoot, 'staged-package');

        await stagePublicPackage({ destinationPath, projectRoot });

        await expect(
            readFile(path.join(destinationPath, 'README.md'), 'utf8'),
        ).resolves.toBe(
            '# Root readme\n\nThis is the public package readme.\n',
        );
        await expect(
            readFile(path.join(destinationPath, 'dist', 'index.js'), 'utf8'),
        ).resolves.toBe('export {};\n');
        await expect(
            readFile(
                path.join(projectRoot, 'packages', 'sdk', 'README.md'),
                'utf8',
            ),
        ).resolves.toBe('# SDK readme\n\nThis stays package-local.\n');
    });

    it('sanitizes staged package metadata', async () => {
        const projectRoot = await createTemporaryRoot();
        await writeFixtureProject(projectRoot);
        const destinationPath = path.join(projectRoot, 'staged-package');

        await stagePublicPackage({ destinationPath, projectRoot });

        await expect(
            readFile(path.join(destinationPath, 'package.json'), 'utf8').then(
                (contents) => JSON.parse(contents) as Record<string, unknown>,
            ),
        ).resolves.not.toHaveProperty('devDependencies');
        await expect(
            readFile(path.join(destinationPath, 'package.json'), 'utf8').then(
                (contents) => JSON.parse(contents) as Record<string, unknown>,
            ),
        ).resolves.not.toHaveProperty('scripts');
        await expect(
            readFile(path.join(destinationPath, 'package.json'), 'utf8').then(
                (contents) => JSON.parse(contents) as Record<string, unknown>,
            ),
        ).resolves.toMatchObject({
            description: 'Root public package description.',
        });
    });

    it('sanitizes package metadata that only belongs to the workspace build', () => {
        expect(
            JSON.parse(
                sanitizePublicPackageJson(
                    JSON.stringify({
                        name: 'sealed-lattice',
                        version: '0.0.0',
                        scripts: {
                            build: 'pnpm run build',
                        },
                        devDependencies: {
                            '@sealed-lattice/types': 'workspace:*',
                        },
                        dependencies: {
                            '@noble/hashes': '^2.2.0',
                        },
                    }),
                    {
                        description: 'Root public package description.',
                    },
                ),
            ),
        ).toEqual({
            name: 'sealed-lattice',
            version: '0.0.0',
            description: 'Root public package description.',
            dependencies: {
                '@noble/hashes': '^2.2.0',
            },
        });
    });

    it('rejects missing root description metadata', async () => {
        const projectRoot = await createTemporaryRoot();
        await writeFixtureProject(projectRoot);
        const destinationPath = path.join(projectRoot, 'staged-package');
        await writeFile(
            path.join(projectRoot, 'package.json'),
            '{"name":"sealed-lattice-workspace"}\n',
            'utf8',
        );

        await expect(
            stagePublicPackage({ destinationPath, projectRoot }),
        ).rejects.toThrow('Root package.json must define package description.');
    });

    it('rejects missing and empty staging destinations', () => {
        expect(() => parseStagePublicPackageArguments([])).toThrow(
            'Public package staging requires --out',
        );
        expect(() => parseStagePublicPackageArguments(['--out'])).toThrow(
            'Public package staging requires --out',
        );
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
