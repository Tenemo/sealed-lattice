import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
    copyFile,
    mkdtemp,
    mkdir,
    readFile,
    readdir,
    rm,
    writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path, { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
    resolvePackageManagerRunner,
    resolvePackageManagerRunnerFromArguments,
    resolvePackageManagerRunnerForPackageManager,
    runPackageManager,
    runPackageManagerAndCaptureOutput,
    type PackageManager,
} from './run-command.js';
import {
    getRootPackageJsonPath,
    getRootReadmePath,
    stagePublicPackage,
} from './stage-public-package.mjs';

import { normalizeTranscriptCoreKernelBytesForHash } from '#packages/wasm/src/transcript-core-bridge.js';

type PackedFileMetadata = {
    readonly path: string;
};

type PackDryRunMetadataEntry = {
    readonly files: readonly PackedFileMetadata[];
};

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const forbiddenPublishedRuntimePathFragments = [
    'dist/internal/election-foundation/plaintext-oracle/',
] as const;
const forbiddenPublishedTypeSupportPathFragments = [
    'dist/internal/plaintext-oracle.',
] as const;
const forbiddenPublishedOraclePathFragments = [
    'tools/lattigo-oracle/',
    'lattigo-oracle',
    'oracle-vector',
    'oracle-serializer',
] as const;
const forbiddenPublishedTestVectorPathFragments = ['test-vectors/'] as const;
const requiredPublishedPackageFilePaths = [
    'LICENSE',
    'README.md',
    'dist/kernel.js',
    'dist/sealed-lattice-kernel.wasm',
    'dist/internal/board-target.d.ts',
    'dist/internal/field.d.ts',
    'dist/internal/lifecycle.d.ts',
    'dist/internal/protocol-hash.d.ts',
    'dist/internal/protocol-objects.d.ts',
    'dist/internal/roster-recovery.d.ts',
    'dist/internal/target-result.d.ts',
    'dist/internal/transcript-core.d.ts',
] as const;
const forbiddenPublishedOracleFileNames = new Set([
    'Dockerfile',
    'go.mod',
    'go.sum',
]);
const publishedKernelHashPattern =
    /const packagedTranscriptCoreKernelNormalizedSha256Hex\s*=\s*(?<hash>undefined|'[a-f0-9]{64}');/u;

const createDryRunPackArguments = (): readonly string[] => [
    'pack',
    '--dry-run',
    '--json',
    '--ignore-scripts',
];

const createPackArguments = (packDirectory: string): readonly string[] => [
    'pack',
    '--pack-destination',
    packDirectory,
];

const createInstallArguments = (
    packageManager: PackageManager,
    tarballPath: string,
): readonly string[] =>
    packageManager === 'npm'
        ? ['install', '--ignore-scripts', '--silent', tarballPath]
        : ['add', '--ignore-scripts', '--silent', tarballPath];

const isPackedFileMetadata = (value: unknown): value is PackedFileMetadata => {
    if (typeof value !== 'object' || value === null) {
        return false;
    }

    return typeof (value as { readonly path?: unknown }).path === 'string';
};

const isPackDryRunMetadataEntry = (
    value: unknown,
): value is PackDryRunMetadataEntry => {
    if (typeof value !== 'object' || value === null) {
        return false;
    }

    const metadataEntry = value as { readonly files?: unknown };

    return (
        Array.isArray(metadataEntry.files) &&
        metadataEntry.files.every(isPackedFileMetadata)
    );
};

export const parsePackDryRunFilePaths = (
    packDryRunOutput: string,
): string[] => {
    const parsedMetadata = JSON.parse(packDryRunOutput) as unknown;

    if (!Array.isArray(parsedMetadata)) {
        throw new Error(
            'npm pack --dry-run --json returned an unexpected shape',
        );
    }

    const metadataEntries: readonly unknown[] = parsedMetadata;
    const metadataEntry = metadataEntries[0];
    if (!isPackDryRunMetadataEntry(metadataEntry)) {
        throw new Error(
            'npm pack --dry-run --json returned an unexpected shape',
        );
    }

    return metadataEntry.files
        .map((fileMetadata) => fileMetadata.path)
        .sort((left, right) => left.localeCompare(right));
};

export const validatePublishedPackageFilePaths = (
    publishedPackageFilePaths: readonly string[],
): string[] => {
    const failures: string[] = [];

    for (const requiredFilePath of requiredPublishedPackageFilePaths) {
        if (!publishedPackageFilePaths.includes(requiredFilePath)) {
            failures.push(
                `Published package is missing required file: ${requiredFilePath}`,
            );
        }
    }

    for (const publishedPackageFilePath of publishedPackageFilePaths) {
        if (publishedPackageFilePath.endsWith('.tsbuildinfo')) {
            failures.push(
                `Published package must not include TypeScript build metadata: ${publishedPackageFilePath}`,
            );
        }
        if (
            forbiddenPublishedRuntimePathFragments.some((fragment) =>
                publishedPackageFilePath.includes(fragment),
            )
        ) {
            failures.push(
                `Published package must not include internal protocol runtime: ${publishedPackageFilePath}`,
            );
        }
        if (
            forbiddenPublishedTypeSupportPathFragments.some((fragment) =>
                publishedPackageFilePath.includes(fragment),
            )
        ) {
            failures.push(
                `Published package must not include test-only type support: ${publishedPackageFilePath}`,
            );
        }
        if (
            forbiddenPublishedTestVectorPathFragments.some((fragment) =>
                publishedPackageFilePath.includes(fragment),
            )
        ) {
            failures.push(
                `Published package must not include repository test vectors: ${publishedPackageFilePath}`,
            );
        }

        const publishedPackageBaseName = path.basename(
            publishedPackageFilePath,
        );
        if (
            forbiddenPublishedOraclePathFragments.some((fragment) =>
                publishedPackageFilePath.includes(fragment),
            ) ||
            forbiddenPublishedOracleFileNames.has(publishedPackageBaseName) ||
            publishedPackageFilePath.endsWith('.go')
        ) {
            failures.push(
                `Published package must not include development oracle artifact: ${publishedPackageFilePath}`,
            );
        }
    }

    return failures;
};

export const validatePublishedPackageMetadata = (
    publishedPackageJson: Record<string, unknown>,
    expectedDescription: string,
): string[] => {
    const failures: string[] = [];

    if (publishedPackageJson.description !== expectedDescription) {
        failures.push(
            'Published package metadata description must match the root package description',
        );
    }
    if ('devDependencies' in publishedPackageJson) {
        failures.push(
            'Published package metadata must not include devDependencies',
        );
    }
    if ('scripts' in publishedPackageJson) {
        failures.push('Published package metadata must not include scripts');
    }

    return failures;
};

export const hashPublishedKernelBytesSha256Hex = (bytes: Uint8Array): string =>
    createHash('sha256')
        .update(normalizeTranscriptCoreKernelBytesForHash(bytes))
        .digest('hex');

export const extractPublishedKernelHash = (
    kernelRuntimeText: string,
): string | undefined => {
    const match = publishedKernelHashPattern.exec(kernelRuntimeText);
    const hash = match?.groups?.hash;
    if (hash === undefined || hash === 'undefined') {
        return undefined;
    }

    return hash.slice(1, -1);
};

export const validatePublishedKernelIntegrity = (
    kernelRuntimeText: string,
    kernelBytes: Uint8Array,
): string[] => {
    const expectedHash = extractPublishedKernelHash(kernelRuntimeText);
    if (expectedHash === undefined) {
        return [
            'Published package kernel loader must pin the packaged transcript-core WASM hash',
        ];
    }

    const actualHash = hashPublishedKernelBytesSha256Hex(kernelBytes);
    if (actualHash !== expectedHash) {
        return [
            `Published package kernel hash mismatch: expected ${expectedHash}, received ${actualHash}`,
        ];
    }

    return [];
};

const runPublint = (packageDirectory: string): void => {
    runPackageManager(
        resolvePackageManagerRunner(),
        [
            'exec',
            'publint',
            'run',
            packageDirectory,
            '--pack',
            'false',
            '--strict',
        ],
        repoRoot,
    );
};

const runSmokeEntryPoint = (consumerDirectory: string): void => {
    const commandArguments = ['smoke.mjs'];
    const result = spawnSync(process.execPath, commandArguments, {
        cwd: consumerDirectory,
        env: process.env,
        encoding: 'utf8',
        maxBuffer: 100 * 1024 * 1024,
    });

    if (result.error !== undefined) {
        throw new Error(
            `Failed to start smoke entry point: ${result.error.message}`,
        );
    }
    if (result.signal !== null) {
        throw new Error(
            `Smoke entry point terminated by signal ${result.signal}`,
        );
    }
    if (result.status !== 0) {
        throw new Error(
            `Smoke entry point failed:\n${[result.stdout, result.stderr]
                .filter(Boolean)
                .join('\n')}`,
        );
    }
};

const main = async (): Promise<void> => {
    const packageManagerRunner = resolvePackageManagerRunnerFromArguments(
        process.argv.slice(2),
    );
    const npmPackRunner = resolvePackageManagerRunnerForPackageManager('npm');
    const tempRoot = await mkdtemp(join(tmpdir(), 'sealed-lattice-packed-'));
    const packDirectory = join(tempRoot, 'pack');
    const consumerDirectory = join(tempRoot, 'consumer');
    const packageDirectory = join(tempRoot, 'package');

    try {
        await mkdir(packDirectory, { recursive: true });
        await mkdir(consumerDirectory, { recursive: true });
        const stagedPackage = await stagePublicPackage({
            destinationPath: packageDirectory,
        });

        const [rootReadmeText, stagedReadmeText] = await Promise.all([
            readFile(getRootReadmePath(repoRoot), 'utf8'),
            readFile(stagedPackage.readmePath, 'utf8'),
        ]);
        if (stagedReadmeText !== rootReadmeText) {
            throw new Error(
                'Staged public package README must be copied from the repository root README',
            );
        }

        const publishedPackageJson = JSON.parse(
            await readFile(join(packageDirectory, 'package.json'), 'utf8'),
        ) as Record<string, unknown>;
        const rootPackageJson = JSON.parse(
            await readFile(getRootPackageJsonPath(repoRoot), 'utf8'),
        ) as Record<string, unknown>;
        if (
            typeof rootPackageJson.description !== 'string' ||
            rootPackageJson.description.length === 0
        ) {
            throw new Error(
                'Root package.json must define package description.',
            );
        }

        const metadataFailures = validatePublishedPackageMetadata(
            publishedPackageJson,
            rootPackageJson.description,
        );
        if (metadataFailures.length > 0) {
            throw new Error(metadataFailures.join('\n'));
        }

        runPublint(packageDirectory);

        const publishedPackageFilePaths = parsePackDryRunFilePaths(
            runPackageManagerAndCaptureOutput(
                npmPackRunner,
                createDryRunPackArguments(),
                packageDirectory,
            ),
        );
        const pathFailures = validatePublishedPackageFilePaths(
            publishedPackageFilePaths,
        );
        if (pathFailures.length > 0) {
            throw new Error(pathFailures.join('\n'));
        }

        const kernelIntegrityFailures = validatePublishedKernelIntegrity(
            await readFile(join(packageDirectory, 'dist', 'kernel.js'), 'utf8'),
            await readFile(
                join(packageDirectory, 'dist', 'sealed-lattice-kernel.wasm'),
            ),
        );
        if (kernelIntegrityFailures.length > 0) {
            throw new Error(kernelIntegrityFailures.join('\n'));
        }

        runPackageManager(
            packageManagerRunner,
            createPackArguments(packDirectory),
            packageDirectory,
        );

        const tarballs = (await readdir(packDirectory)).filter((entry) =>
            entry.endsWith('.tgz'),
        );
        if (tarballs.length !== 1) {
            throw new Error(
                `Expected exactly one packed tarball, received ${tarballs.length}`,
            );
        }

        const tarballPath = join(packDirectory, tarballs[0]);

        await writeFile(
            join(consumerDirectory, 'package.json'),
            `${JSON.stringify(
                {
                    name: 'sealed-lattice-smoke-consumer',
                    private: true,
                    type: 'module',
                },
                null,
                2,
            )}\n`,
            'utf8',
        );
        await copyFile(
            path.join(repoRoot, 'tools', 'ci', 'packed-package-smoke.mjs'),
            join(consumerDirectory, 'smoke.mjs'),
        );

        runPackageManager(
            packageManagerRunner,
            createInstallArguments(packageManagerRunner.kind, tarballPath),
            consumerDirectory,
        );
        runSmokeEntryPoint(consumerDirectory);

        console.log(
            `Packed package smoke test passed with ${packageManagerRunner.kind}.`,
        );
    } finally {
        await rm(tempRoot, { recursive: true, force: true });
    }
};

if (process.argv[1] === fileURLToPath(import.meta.url)) {
    void main();
}
