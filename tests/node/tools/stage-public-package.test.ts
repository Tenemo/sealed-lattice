import { spawnSync } from 'node:child_process';
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
        path.join(publicPackageDirectory, 'LICENSE'),
        'license text\n',
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
    it('parses staging CLI arguments', () => {
        expect(
            parseStagePublicPackageArguments([
                '--out',
                'package-dir',
                '--project-root',
                'project-dir',
            ]),
        ).toEqual({
            destinationPath: 'package-dir',
            projectRoot: 'project-dir',
        });
        expect(() => parseStagePublicPackageArguments([])).toThrow(
            'Usage: node ./tools/ci/stage-public-package.mjs --out <directory> [--project-root <directory>]',
        );
        expect(() => parseStagePublicPackageArguments(['--out'])).toThrow(
            '--out requires a value.',
        );
    });

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

    it('stages public package files through the CLI used by CI', async () => {
        const projectRoot = await createTemporaryRoot();
        await writeFixtureProject(projectRoot);
        const destinationPath = path.join(projectRoot, 'staged-package');
        const result = spawnSync(
            process.execPath,
            [
                path.resolve('tools/ci/stage-public-package.mjs'),
                '--out',
                destinationPath,
                '--project-root',
                projectRoot,
            ],
            {
                cwd: path.resolve('.'),
                encoding: 'utf8',
            },
        );

        expect(result.stderr).toBe('');
        expect(result.status).toBe(0);
        expect(result.stdout).toContain('Staged public package:');
        await expect(
            readFile(path.join(destinationPath, 'package.json'), 'utf8').then(
                (contents) => JSON.parse(contents) as Record<string, unknown>,
            ),
        ).resolves.toMatchObject({
            name: 'sealed-lattice',
            description: 'Root public package description.',
        });
        await expect(
            readFile(path.join(destinationPath, 'README.md'), 'utf8'),
        ).resolves.toBe(
            '# Root readme\n\nThis is the public package readme.\n',
        );
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

    it('rejects empty staging destinations', async () => {
        let thrownError: unknown;

        try {
            await stagePublicPackage({ destinationPath: '' });
        } catch (error) {
            thrownError = error;
        }

        expect(thrownError).toBeInstanceOf(Error);
        expect((thrownError as Error).message).toBe(
            'Public package staging requires a destination path.',
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
