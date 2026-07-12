import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { describe, expect, it, vi } from 'vitest';

import {
    determineNpmPublication,
    verifyCheckedOutReleaseTag,
    verifyReleaseWithoutMutation,
    type ReleaseCommandExecutor,
} from '#tools/ci/release-gates.js';
import {
    requireUnpublishedNpmVersion,
    requireUnusedReleaseTag,
    resolveGitHubRelease,
    resolveNpmPublication,
    validateCheckedOutReleaseCommit,
    validateReleaseMetadataPaths,
    validateUnmovedDefaultBranch,
    type ReleaseCommandProbe,
} from '#tools/ci/release-policy.js';

const successfulProbe = (stdout = ''): ReleaseCommandProbe => ({
    exitCode: 0,
    stderr: '',
    stdout,
});

const failedProbe = (
    exitCode: number,
    stderr: string,
): ReleaseCommandProbe => ({
    exitCode,
    stderr,
    stdout: '',
});

describe('release policy', () => {
    it('requires the default branch and release tag to remain on the expected commits', () => {
        expect(() =>
            validateUnmovedDefaultBranch({
                defaultBranch: 'main',
                remoteRevision: 'new-revision',
                sourceRevision: 'old-revision',
            }),
        ).toThrow('moved during release preparation');
        expect(() =>
            validateCheckedOutReleaseCommit({
                checkedOutRevision: 'other-revision',
                releaseRevision: 'release-revision',
                tag: 'v0.2.1',
            }),
        ).toThrow('does not resolve to the release commit');
    });

    it('allows only the public version manifest and an optional lockfile change', () => {
        expect(() =>
            validateReleaseMetadataPaths({
                changedPaths: ['packages/sdk/package.json', 'pnpm-lock.yaml'],
                untrackedPaths: [],
            }),
        ).not.toThrow();
        expect(() =>
            validateReleaseMetadataPaths({
                changedPaths: ['pnpm-lock.yaml'],
                untrackedPaths: [],
            }),
        ).toThrow('missing the public package version');
        expect(() =>
            validateReleaseMetadataPaths({
                changedPaths: [
                    'packages/sdk/package.json',
                    'packages/crypto/package.json',
                ],
                untrackedPaths: [],
            }),
        ).toThrow('Unexpected release metadata change');
        expect(() =>
            validateReleaseMetadataPaths({
                changedPaths: ['packages/sdk/package.json'],
                untrackedPaths: ['unexpected.txt'],
            }),
        ).toThrow('unexpected untracked file');
    });

    it('distinguishes unused release targets from collisions and lookup failures', () => {
        expect(() =>
            requireUnusedReleaseTag('v0.2.1', failedProbe(2, '')),
        ).not.toThrow();
        expect(() =>
            requireUnusedReleaseTag('v0.2.1', successfulProbe()),
        ).toThrow('already exists');
        expect(() =>
            requireUnusedReleaseTag(
                'v0.2.1',
                failedProbe(128, 'network unavailable'),
            ),
        ).toThrow('Could not verify');

        expect(() =>
            requireUnpublishedNpmVersion(
                '0.2.1',
                failedProbe(1, 'npm error code E404'),
            ),
        ).not.toThrow();
        expect(() =>
            requireUnpublishedNpmVersion('0.2.1', successfulProbe('"0.2.1"')),
        ).toThrow('already exists');
        expect(() =>
            requireUnpublishedNpmVersion(
                '0.2.1',
                failedProbe(1, 'authentication failed'),
            ),
        ).toThrow('Could not verify');
    });

    it('makes npm and GitHub post-tag reruns idempotent without hiding conflicts', () => {
        expect(
            resolveNpmPublication({
                localIntegrity: 'sha512-local',
                packageVersion: '0.2.1',
                registryLookup: failedProbe(1, 'npm error code E404'),
            }),
        ).toEqual({ action: 'publish' });
        expect(
            resolveNpmPublication({
                latestTagLookup: successfulProbe('"0.2.1"'),
                localIntegrity: 'sha512-local',
                packageVersion: '0.2.1',
                registryLookup: successfulProbe('"sha512-local"'),
            }),
        ).toEqual({ action: 'already-identical' });
        expect(() =>
            resolveNpmPublication({
                localIntegrity: 'sha512-local',
                packageVersion: '0.2.1',
                registryLookup: successfulProbe('"sha512-other"'),
            }),
        ).toThrow('different bytes');
        expect(() =>
            resolveNpmPublication({
                localIntegrity: 'sha512-local',
                packageVersion: '0.2.1',
                registryLookup: successfulProbe('{not-json}'),
            }),
        ).toThrow('malformed JSON');
        expect(() =>
            resolveNpmPublication({
                latestTagLookup: successfulProbe('"0.2.2"'),
                localIntegrity: 'sha512-local',
                packageVersion: '0.2.1',
                registryLookup: successfulProbe('"sha512-local"'),
            }),
        ).toThrow('npm latest points to sealed-lattice@0.2.2');
        expect(() =>
            resolveNpmPublication({
                latestTagLookup: failedProbe(1, 'registry unavailable'),
                localIntegrity: 'sha512-local',
                packageVersion: '0.2.1',
                registryLookup: successfulProbe('"sha512-local"'),
            }),
        ).toThrow('Could not verify the npm latest dist-tag');
        expect(() =>
            resolveNpmPublication({
                localIntegrity: 'sha512-local',
                packageVersion: '0.2.1',
                registryLookup: successfulProbe('"sha512-local"'),
            }),
        ).toThrow('latest dist-tag lookup was not performed');

        expect(
            resolveGitHubRelease({
                releaseLookup: failedProbe(1, 'gh: Not Found (HTTP 404)'),
                tag: 'v0.2.1',
            }),
        ).toEqual({ action: 'create' });
        expect(
            resolveGitHubRelease({
                releaseLookup: successfulProbe(
                    JSON.stringify({
                        draft: false,
                        prerelease: false,
                        tag_name: 'v0.2.1',
                    }),
                ),
                tag: 'v0.2.1',
            }),
        ).toEqual({ action: 'already-exists' });
        for (const existingRelease of [
            { draft: true, prerelease: false, tag_name: 'v0.2.1' },
            { draft: false, prerelease: true, tag_name: 'v0.2.1' },
            { draft: false, prerelease: false, tag_name: 'v0.2.2' },
            {},
        ]) {
            expect(() =>
                resolveGitHubRelease({
                    releaseLookup: successfulProbe(
                        JSON.stringify(existingRelease),
                    ),
                    tag: 'v0.2.1',
                }),
            ).toThrow('not an ordinary release');
        }
        expect(() =>
            resolveGitHubRelease({
                releaseLookup: failedProbe(1, 'authentication failed'),
                tag: 'v0.2.1',
            }),
        ).toThrow('Could not verify');
    });

    it('binds npm and tag rerun decisions to the expected package identity and release commit', async () => {
        const packageDirectory = await mkdtemp(
            path.join(tmpdir(), 'sealed-lattice-release-package-'),
        );
        const packageExecutor: ReleaseCommandExecutor = (invocation) => {
            if (invocation.arguments.includes('pack')) {
                return successfulProbe(
                    JSON.stringify([
                        {
                            filename: 'sealed-lattice-0.2.1.tgz',
                            integrity: 'sha512-local',
                            name: 'sealed-lattice',
                            version: '0.2.1',
                        },
                    ]),
                );
            }
            return failedProbe(1, 'npm error code E404');
        };

        try {
            await expect(
                determineNpmPublication({
                    executor: packageExecutor,
                    packageDirectory,
                    releaseVersion: '0.2.1',
                }),
            ).resolves.toBe('publish');

            const existingPackageExecutor = vi.fn<ReleaseCommandExecutor>(
                (invocation) => {
                    if (invocation.arguments.includes('pack')) {
                        return successfulProbe(
                            JSON.stringify([
                                {
                                    filename: 'sealed-lattice-0.2.1.tgz',
                                    integrity: 'sha512-local',
                                    name: 'sealed-lattice',
                                    version: '0.2.1',
                                },
                            ]),
                        );
                    }
                    if (invocation.arguments.includes('dist.integrity')) {
                        return successfulProbe('"sha512-local"');
                    }
                    if (invocation.arguments.includes('dist-tags.latest')) {
                        return successfulProbe('"0.2.1"');
                    }
                    return failedProbe(1, 'unexpected npm command');
                },
            );
            await expect(
                determineNpmPublication({
                    executor: existingPackageExecutor,
                    packageDirectory,
                    releaseVersion: '0.2.1',
                }),
            ).resolves.toBe('already-identical');
            expect(existingPackageExecutor).toHaveBeenCalledTimes(3);

            const wrongVersionExecutor: ReleaseCommandExecutor = (
                invocation,
            ) =>
                invocation.arguments.includes('pack')
                    ? successfulProbe(
                          JSON.stringify([
                              {
                                  filename: 'sealed-lattice-0.2.0.tgz',
                                  integrity: 'sha512-local',
                                  name: 'sealed-lattice',
                                  version: '0.2.0',
                              },
                          ]),
                      )
                    : failedProbe(1, 'npm error code E404');
            await expect(
                determineNpmPublication({
                    executor: wrongVersionExecutor,
                    packageDirectory,
                    releaseVersion: '0.2.1',
                }),
            ).rejects.toThrow('expected sealed-lattice@0.2.1');

            expect(() =>
                verifyCheckedOutReleaseTag({
                    executor: () => successfulProbe('release-revision\n'),
                    releaseRevision: 'release-revision',
                    tag: 'v0.2.1',
                    workingDirectoryPath: packageDirectory,
                }),
            ).not.toThrow();
            expect(() =>
                verifyCheckedOutReleaseTag({
                    executor: () => successfulProbe('other-revision\n'),
                    releaseRevision: 'release-revision',
                    tag: 'v0.2.1',
                    workingDirectoryPath: packageDirectory,
                }),
            ).toThrow('does not resolve to the release commit');
        } finally {
            await rm(packageDirectory, { force: true, recursive: true });
        }
    });
});

describe('mutation-free release verification', () => {
    it('uses the next staged version while leaving release inputs unchanged', async () => {
        const temporaryRepositoryPath = await mkdtemp(
            path.join(tmpdir(), 'sealed-lattice-release-gates-'),
        );
        const manifestPath = path.join(
            temporaryRepositoryPath,
            'packages',
            'sdk',
            'package.json',
        );
        const manifestText = '{"name":"sealed-lattice","version":"0.4.8"}\n';
        const verifiedTargets: string[] = [];
        let publishedVersion = '';

        try {
            await mkdir(path.dirname(manifestPath), { recursive: true });
            await writeFile(manifestPath, manifestText, 'utf8');
            const buildAndSmoke = vi.fn(() => Promise.resolve());
            const result = await verifyReleaseWithoutMutation({
                dependencies: {
                    buildAndSmoke,
                    createTemporaryDirectory: () =>
                        Promise.resolve(
                            path.join(temporaryRepositoryPath, 'staged'),
                        ),
                    inspectWorkingTree: () => Promise.resolve(''),
                    publishDryRun: async (packageDirectory) => {
                        const stagedManifest = JSON.parse(
                            await readFile(
                                path.join(packageDirectory, 'package.json'),
                                'utf8',
                            ),
                        ) as { readonly version: string };
                        publishedVersion = stagedManifest.version;
                    },
                    removeTemporaryDirectory: async (
                        temporaryDirectoryPath,
                    ) => {
                        await rm(temporaryDirectoryPath, {
                            force: true,
                            recursive: true,
                        });
                    },
                    stagePackage: async (temporaryDirectoryPath) => {
                        await mkdir(temporaryDirectoryPath, {
                            recursive: true,
                        });
                        const packageJsonPath = path.join(
                            temporaryDirectoryPath,
                            'package.json',
                        );
                        await writeFile(packageJsonPath, manifestText, 'utf8');
                        return {
                            packageDirectory: temporaryDirectoryPath,
                            packageJsonPath,
                        };
                    },
                    verifyTargets: (releaseVersion) => {
                        verifiedTargets.push(releaseVersion.tag);
                        return Promise.resolve();
                    },
                },
                increment: 'patch',
                manifestPath,
            });

            expect(result).toEqual({
                previousVersion: '0.4.8',
                tag: 'v0.4.9',
                version: '0.4.9',
            });
            expect(buildAndSmoke).toHaveBeenCalledExactlyOnceWith(
                path.join(temporaryRepositoryPath, 'staged'),
                result,
            );
            expect(verifiedTargets).toEqual(['v0.4.9']);
            expect(publishedVersion).toBe('0.4.9');
            expect(await readFile(manifestPath, 'utf8')).toBe(manifestText);
        } finally {
            await rm(temporaryRepositoryPath, {
                force: true,
                recursive: true,
            });
        }
    });

    it('refuses dirty inputs before running release work', async () => {
        const temporaryRepositoryPath = await mkdtemp(
            path.join(tmpdir(), 'sealed-lattice-release-dirty-'),
        );
        const manifestPath = path.join(temporaryRepositoryPath, 'package.json');
        const buildAndSmoke = vi.fn(() => Promise.resolve());

        try {
            await writeFile(
                manifestPath,
                '{"name":"sealed-lattice","version":"0.4.8"}\n',
                'utf8',
            );
            await expect(
                verifyReleaseWithoutMutation({
                    dependencies: {
                        buildAndSmoke,
                        createTemporaryDirectory: () => Promise.resolve(''),
                        inspectWorkingTree: () =>
                            Promise.resolve(' M README.md\n'),
                        publishDryRun: () => Promise.resolve(),
                        removeTemporaryDirectory: () => Promise.resolve(),
                        stagePackage: () =>
                            Promise.reject(new Error('must not stage')),
                        verifyTargets: () => Promise.resolve(),
                    },
                    increment: 'minor',
                    manifestPath,
                }),
            ).rejects.toThrow('clean working tree');
            expect(buildAndSmoke).not.toHaveBeenCalled();
        } finally {
            await rm(temporaryRepositoryPath, {
                force: true,
                recursive: true,
            });
        }
    });
});
