import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

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

const deriveReleaseVersionFromManifest = (
    manifest: PublicPackageManifest,
    increment: ReleaseIncrement,
): ReleaseVersionResult => {
    const previousVersion = manifest.version;
    const version = incrementPrototypeVersion(previousVersion, increment);

    return {
        previousVersion,
        tag: `v${version}`,
        version,
    };
};

export const deriveReleaseVersion = (
    manifestText: string,
    increment: ReleaseIncrement,
): ReleaseVersionResult =>
    deriveReleaseVersionFromManifest(
        parsePublicPackageManifest(manifestText),
        increment,
    );

const writeManifestAtomically = async (
    manifestPath: string,
    manifestText: string,
): Promise<void> => {
    const temporaryManifestPath = `${manifestPath}.${String(process.pid)}.tmp`;
    const transientReplacementErrorCodes = new Set([
        'EACCES',
        'EBUSY',
        'EPERM',
    ]);
    const maximumReplacementAttempts = 12;

    for (let attempt = 1; ; attempt += 1) {
        try {
            await fs.writeFile(temporaryManifestPath, manifestText, 'utf8');
            await fs.rename(temporaryManifestPath, manifestPath);
            return;
        } catch (error) {
            try {
                await fs.rm(temporaryManifestPath, { force: true });
            } catch (cleanupError) {
                const replacementError = new Error(
                    `Release manifest replacement failed (${String(error)}) and temporary-file cleanup also failed.`,
                );
                Object.defineProperty(replacementError, 'cause', {
                    configurable: true,
                    value: cleanupError,
                });
                throw replacementError;
            }
            const errorCode = (error as NodeJS.ErrnoException).code;
            if (
                attempt >= maximumReplacementAttempts ||
                errorCode === undefined ||
                !transientReplacementErrorCodes.has(errorCode)
            ) {
                throw error;
            }
            await new Promise((resolve) => {
                setTimeout(resolve, 50 * attempt);
            });
        }
    }
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
    const releaseVersion = deriveReleaseVersionFromManifest(
        manifest,
        input.increment,
    );
    manifest.version = releaseVersion.version;

    await writeManifestAtomically(
        manifestPath,
        `${JSON.stringify(manifest, null, 4)}\n`,
    );

    return releaseVersion;
};

export const formatReleaseGitHubOutput = (
    releaseVersion: ReleaseVersionResult,
): string =>
    [`version=${releaseVersion.version}`, `tag=${releaseVersion.tag}`, ''].join(
        '\n',
    );

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

if (import.meta.main) {
    void main();
}
