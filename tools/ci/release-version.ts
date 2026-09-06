import { appendFile, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export type ReleaseIncrement = 'minor' | 'patch';

export type ReleaseVersionResult = {
    readonly previousVersion: string;
    readonly tag: string;
    readonly version: string;
};

const publicPackageManifestPath = path.resolve(
    fileURLToPath(new URL('../../', import.meta.url)),
    'packages',
    'sdk',
    'package.json',
);
const prototypeVersionPattern =
    /^0\.(?<minor>0|[1-9]\d*)\.(?<patch>0|[1-9]\d*)$/u;

const parseIncrement = (arguments_: readonly string[]): ReleaseIncrement => {
    const normalizedArguments =
        arguments_[0] === '--' ? arguments_.slice(1) : arguments_;
    const [increment] = normalizedArguments;
    if (
        normalizedArguments.length !== 1 ||
        (increment !== 'patch' && increment !== 'minor')
    ) {
        throw new Error('Usage: release-version.ts patch|minor.');
    }
    return increment;
};

export const incrementPrototypeVersion = (
    currentVersion: string,
    increment: ReleaseIncrement,
): string => {
    const match = prototypeVersionPattern.exec(currentVersion);
    if (match?.groups === undefined) {
        throw new Error(
            `Expected a stable pre-1.0 semantic version, received ${currentVersion}.`,
        );
    }
    const minor = Number(match.groups.minor);
    const patch = Number(match.groups.patch);
    if (!Number.isSafeInteger(minor) || !Number.isSafeInteger(patch)) {
        throw new Error(
            `Version is outside JavaScript's safe range: ${currentVersion}.`,
        );
    }
    return increment === 'minor'
        ? `0.${String(minor + 1)}.0`
        : `0.${String(minor)}.${String(patch + 1)}`;
};

export const prepareReleaseVersion = async (input: {
    readonly increment: ReleaseIncrement;
    readonly manifestPath?: string;
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
    const version = incrementPrototypeVersion(previousVersion, input.increment);
    manifest.version = version;
    await writeFile(
        manifestPath,
        `${JSON.stringify(manifest, null, 4)}\n`,
        'utf8',
    );
    return { previousVersion, tag: `v${version}`, version };
};

const main = async (): Promise<void> => {
    const release = await prepareReleaseVersion({
        increment: parseIncrement(process.argv.slice(2)),
    });
    if (process.env.GITHUB_OUTPUT !== undefined) {
        await appendFile(
            process.env.GITHUB_OUTPUT,
            `version=${release.version}\ntag=${release.tag}\n`,
            'utf8',
        );
    }
    console.log(
        `Prepared sealed-lattice ${release.previousVersion} -> ${release.version}.`,
    );
};

if (import.meta.main) void main();
