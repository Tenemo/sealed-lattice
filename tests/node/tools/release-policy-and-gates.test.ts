import { createHash } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { describe, expect, it, vi } from 'vitest';

import {
    determineNpmPublication,
    verifyCheckedOutReleaseTag,
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

    it('allows only the public version manifest change', () => {
        expect(() =>
            validateReleaseMetadataPaths({
                changedPaths: ['packages/sdk/package.json'],
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
                changedPaths: ['packages/sdk/package.json', 'pnpm-lock.yaml'],
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

    it('binds npm rerun decisions to the verified tarball and tag decisions to the release commit', async () => {
        const packageDirectory = await mkdtemp(
            path.join(tmpdir(), 'sealed-lattice-release-package-'),
        );
        const packageTarballPath = path.join(
            packageDirectory,
            'sealed-lattice-0.2.1.tgz',
        );
        const packageBytes = Buffer.from('verified package tarball');
        const packageIntegrity = `sha512-${createHash('sha512')
            .update(packageBytes)
            .digest('base64')}`;
        const packageExecutor: ReleaseCommandExecutor = () =>
            Promise.resolve(failedProbe(1, 'npm error code E404'));

        try {
            await writeFile(packageTarballPath, packageBytes);
            await expect(
                determineNpmPublication({
                    executor: packageExecutor,
                    packageIntegrity,
                    packageTarballPath,
                    releaseVersion: '0.2.1',
                }),
            ).resolves.toBe('publish');

            const existingPackageExecutor = vi.fn<ReleaseCommandExecutor>(
                (invocation) => {
                    if (invocation.arguments.includes('dist.integrity')) {
                        return successfulProbe(
                            JSON.stringify(packageIntegrity),
                        );
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
                    packageIntegrity,
                    packageTarballPath,
                    releaseVersion: '0.2.1',
                }),
            ).resolves.toBe('already-identical');
            expect(existingPackageExecutor).toHaveBeenCalledTimes(2);

            await expect(
                determineNpmPublication({
                    executor: packageExecutor,
                    packageIntegrity: 'sha512-wrong',
                    packageTarballPath,
                    releaseVersion: '0.2.1',
                }),
            ).rejects.toThrow('no longer matches');

            await expect(
                verifyCheckedOutReleaseTag({
                    executor: () => successfulProbe('release-revision\n'),
                    releaseRevision: 'release-revision',
                    tag: 'v0.2.1',
                    workingDirectoryPath: packageDirectory,
                }),
            ).resolves.toBeUndefined();
            await expect(
                verifyCheckedOutReleaseTag({
                    executor: () => successfulProbe('other-revision\n'),
                    releaseRevision: 'release-revision',
                    tag: 'v0.2.1',
                    workingDirectoryPath: packageDirectory,
                }),
            ).rejects.toThrow('does not resolve to the release commit');
        } finally {
            await rm(packageDirectory, { force: true, recursive: true });
        }
    });
});
