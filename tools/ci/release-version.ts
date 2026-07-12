import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';
import { withTransientFilesystemRetries } from '#tools/internal/files.js';

export type ReleaseIncrement = 'minor' | 'patch';

export type ReleaseVersionResult = {
    readonly previousVersion: string;
    readonly tag: string;
    readonly version: string;
};

type PublicPackageManifest = Record<string, unknown> & {
    readonly name: 'sealed-lattice';
    version: string;
};

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const defaultPublicPackageManifestPath = path.resolve(
    repoRoot,
    'packages',
    'sdk',
    'package.json',
);
const stableVersionPattern =
    /^(?<major>0|[1-9]\d*)\.(?<minor>0|[1-9]\d*)\.(?<patch>0|[1-9]\d*)$/u;

const isRecord = (value: unknown): value is Record<string, unknown> =>
    typeof value === 'object' && value !== null && !Array.isArray(value);

export const parseReleaseIncrement = (
    commandArguments: readonly string[],
): ReleaseIncrement => {
    const normalizedArguments =
        commandArguments[0] === '--'
            ? commandArguments.slice(1)
            : commandArguments;
    const releaseIncrement = normalizedArguments[0];
    if (
        normalizedArguments.length !== 1 ||
        releaseIncrement === undefined ||
        (releaseIncrement !== 'patch' && releaseIncrement !== 'minor')
    ) {
        throw new Error('Usage: release-version.ts patch|minor.');
    }

    return releaseIncrement;
};

export const incrementPrototypeVersion = (
    currentVersion: string,
    increment: ReleaseIncrement,
): string => {
    const match = stableVersionPattern.exec(currentVersion);
    if (match?.groups === undefined) {
        throw new Error(
            `The public package version must be stable semantic versioning without leading zeroes: ${currentVersion}`,
        );
    }

    const majorVersion = BigInt(match.groups.major);
    const minorVersion = BigInt(match.groups.minor);
    const patchVersion = BigInt(match.groups.patch);
    if (majorVersion !== 0n) {
        throw new Error(
            `Prototype releases must remain below 1.0.0: ${currentVersion}`,
        );
    }

    if (increment === 'minor') {
        return `0.${String(minorVersion + 1n)}.0`;
    }

    return `0.${String(minorVersion)}.${String(patchVersion + 1n)}`;
};

const parsePublicPackageManifest = (
    manifestText: string,
): PublicPackageManifest => {
    let parsedManifest: unknown;
    try {
        parsedManifest = JSON.parse(manifestText) as unknown;
    } catch {
        throw new Error('The public package manifest is not valid JSON.');
    }

    if (
        !isRecord(parsedManifest) ||
        parsedManifest.name !== 'sealed-lattice' ||
        typeof parsedManifest.version !== 'string'
    ) {
        throw new Error(
            'The public package manifest must identify sealed-lattice and define a string version.',
        );
    }

    return parsedManifest as PublicPackageManifest;
};

export const deriveReleaseVersion = (
    manifestText: string,
    increment: ReleaseIncrement,
): ReleaseVersionResult => {
    const manifest = parsePublicPackageManifest(manifestText);
    const previousVersion = manifest.version;
    const version = incrementPrototypeVersion(previousVersion, increment);

    return {
        previousVersion,
        tag: `v${version}`,
        version,
    };
};

const writeManifestAtomically = async (
    manifestPath: string,
    manifestText: string,
): Promise<void> => {
    const temporaryManifestPath = `${manifestPath}.${String(process.pid)}.tmp`;

    await withTransientFilesystemRetries(async () => {
        try {
            await fs.writeFile(temporaryManifestPath, manifestText, 'utf8');
            await fs.rename(temporaryManifestPath, manifestPath);
        } catch (error) {
            await fs.rm(temporaryManifestPath, { force: true }).catch(() => {
                // Preserve the original write or rename failure.
            });
            throw error;
        }
    });
};

export const prepareReleaseVersion = async (input: {
    readonly increment: ReleaseIncrement;
    readonly manifestPath?: string;
}): Promise<ReleaseVersionResult> => {
    const manifestPath = path.resolve(
        input.manifestPath ?? defaultPublicPackageManifestPath,
    );
    const manifestText = await fs.readFile(manifestPath, 'utf8');
    const manifest = parsePublicPackageManifest(manifestText);
    const releaseVersion = deriveReleaseVersion(manifestText, input.increment);
    manifest.version = releaseVersion.version;

    await writeManifestAtomically(
        manifestPath,
        `${JSON.stringify(manifest, null, 4)}\n`,
    );

    return {
        ...releaseVersion,
    };
};

export const formatReleaseGitHubOutput = (
    releaseVersion: ReleaseVersionResult,
): string =>
    [
        `previous_version=${releaseVersion.previousVersion}`,
        `version=${releaseVersion.version}`,
        `tag=${releaseVersion.tag}`,
        '',
    ].join('\n');

const main = async (): Promise<void> => {
    const increment = parseReleaseIncrement(process.argv.slice(2));
    const releaseVersion = await prepareReleaseVersion({ increment });
    const githubOutputPath = process.env.GITHUB_OUTPUT;
    if (githubOutputPath !== undefined && githubOutputPath.length > 0) {
        await fs.appendFile(
            githubOutputPath,
            formatReleaseGitHubOutput(releaseVersion),
            'utf8',
        );
    }

    console.log(
        `Prepared sealed-lattice ${releaseVersion.previousVersion} -> ${releaseVersion.version}.`,
    );
};

if (isDirectlyInvokedModule(import.meta.url)) {
    void main();
}
