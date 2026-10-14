import { spawnSync } from 'node:child_process';
import { appendFile, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { repositoryRoot, toolArguments } from '#tools/ci/command-line.js';

type ReleaseIncrement = 'minor' | 'patch';

type ReleaseVersionResult = {
    readonly previousVersion: string;
    readonly tag: string;
    readonly version: string;
};

const publicPackageManifestPath = path.resolve(
    repositoryRoot,
    'packages',
    'sdk',
    'package.json',
);
const prototypeVersionPattern =
    /^0\.(?<minor>0|[1-9]\d*)\.(?<patch>0|[1-9]\d*)$/u;

const parseIncrement = (
    commandLineArguments: readonly string[],
): ReleaseIncrement => {
    const normalizedArguments = toolArguments(commandLineArguments);
    const [increment] = normalizedArguments;
    if (
        normalizedArguments.length !== 1 ||
        (increment !== 'patch' && increment !== 'minor')
    ) {
        throw new Error('Usage: release-version.ts patch|minor.');
    }
    return increment;
};

const parsePrototypeVersion = (version: string) => {
    const match = prototypeVersionPattern.exec(version);
    if (match?.groups === undefined) {
        throw new Error(
            `Expected a stable pre-1.0 semantic version, received ${version}.`,
        );
    }
    const minor = Number(match.groups.minor);
    const patch = Number(match.groups.patch);
    if (!Number.isSafeInteger(minor) || !Number.isSafeInteger(patch)) {
        throw new Error(
            `Version is outside JavaScript's safe range: ${version}.`,
        );
    }
    return { minor, patch };
};

export const incrementPrototypeVersion = (
    currentVersion: string,
    increment: ReleaseIncrement,
): string => {
    const { minor, patch } = parsePrototypeVersion(currentVersion);
    return increment === 'minor'
        ? `0.${String(minor + 1)}.0`
        : `0.${String(minor)}.${String(patch + 1)}`;
};

// The highest prototype version among the repository's release tags.
const latestReleasedVersion = (releaseTags: readonly string[]) =>
    releaseTags
        .map((tag) => tag.replace(/^v/u, ''))
        .filter((version) => prototypeVersionPattern.test(version))
        .map((version) => ({ version, ...parsePrototypeVersion(version) }))
        .sort(
            (left, right) =>
                left.minor - right.minor || left.patch - right.patch,
        )
        .pop()?.version;

export const prepareReleaseVersion = async (input: {
    readonly increment: ReleaseIncrement;
    readonly manifestPath?: string;
    readonly releaseTags: readonly string[];
}): Promise<ReleaseVersionResult> => {
    const manifestPath = path.resolve(
        input.manifestPath ?? publicPackageManifestPath,
    );
    const manifest = JSON.parse(
        await readFile(manifestPath, 'utf8'),
    ) as unknown;
    if (
        typeof manifest !== 'object' ||
        manifest === null ||
        Array.isArray(manifest) ||
        !('name' in manifest) ||
        manifest.name !== 'sealed-lattice' ||
        !('version' in manifest) ||
        typeof manifest.version !== 'string'
    ) {
        throw new Error(
            'The public package manifest must identify sealed-lattice and contain a version.',
        );
    }

    const previousVersion = manifest.version;
    // The release workflow is the manifest version's only writer, so the
    // manifest still names the latest released version.
    const released = latestReleasedVersion(input.releaseTags);
    if (released !== undefined && released !== previousVersion) {
        throw new Error(
            `The public package manifest names ${previousVersion}, but the latest release tag is v${released}.`,
        );
    }
    const version = incrementPrototypeVersion(previousVersion, input.increment);
    manifest.version = version;
    await writeFile(
        manifestPath,
        `${JSON.stringify(manifest, null, 4)}\n`,
        'utf8',
    );
    return { previousVersion, tag: `v${version}`, version };
};

const listReleaseTags = (): string[] => {
    const result = spawnSync('git', ['tag', '--list', 'v*'], {
        cwd: repositoryRoot,
        encoding: 'utf8',
        windowsHide: true,
    });
    if (result.error !== undefined) throw result.error;
    if (result.status !== 0)
        throw new Error('The release tags could not be listed.');
    return result.stdout.split(/\r?\n/u).filter((tag) => tag.length > 0);
};

const main = async (): Promise<void> => {
    const release = await prepareReleaseVersion({
        increment: parseIncrement(process.argv.slice(2)),
        releaseTags: listReleaseTags(),
    });
    if (process.env.GITHUB_OUTPUT !== undefined) {
        await appendFile(
            process.env.GITHUB_OUTPUT,
            `version=${release.version}\ntag=${release.tag}\nprevious_tag=v${release.previousVersion}\n`,
            'utf8',
        );
    }
    console.log(
        `Prepared sealed-lattice ${release.previousVersion} -> ${release.version}.`,
    );
};

if (import.meta.main) void main();
