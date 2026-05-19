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

import { normalizeTranscriptCoreKernelBytesForDigest } from '../../packages/wasm/src/transcript-core-bridge.js';

import {
    getRootReadmePath,
    stagePublicPackage,
} from './stage-public-package.mjs';

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));

export type PackageManager = 'npm' | 'pnpm';

type PackageManagerRunner = {
    command: string;
    commandArgsPrefix: readonly string[];
    kind: PackageManager;
};

type SpawnCommand = {
    args: readonly string[];
    command: string;
    description: string;
};

type PackedFileMetadata = {
    path: string;
};

type PackDryRunMetadataEntry = {
    files: readonly PackedFileMetadata[];
};

const supportedPackageManagers = new Set<PackageManager>(['npm', 'pnpm']);
const forbiddenPublishedRuntimePathFragments = [
    'dist/internal/election-foundation/plaintext-oracle/',
    'dist/internal/election-foundation/target-acceptance/',
] as const;
const forbiddenPublishedTestVectorPathFragments = [
    'test-vectors/',
    'ballot-field-linear-proof-vectors.json',
    'encoded-ballot-linear-relation-vectors.json',
    'proof-backend-linear-vectors.json',
    'proof-stack-profile.json',
    'receiver-key-linear-proof-vectors.json',
    'receiver-key-proof-vectors.json',
] as const;
const requiredPublishedPackageFilePaths = [
    'LICENSE',
    'README.md',
    'dist/kernel.js',
    'dist/sealed-lattice-kernel.wasm',
    'dist/internal/board-target.d.ts',
    'dist/internal/lifecycle.d.ts',
    'dist/internal/plaintext-oracle.d.ts',
    'dist/internal/protocol-digest.d.ts',
    'dist/internal/protocol-objects.d.ts',
    'dist/internal/roster-recovery.d.ts',
    'dist/internal/transcript-core.d.ts',
    'public-surface.json',
] as const;
const publishedKernelDigestPattern =
    /const packagedTranscriptCoreKernelNormalizedSha256Hex\s*=\s*(?<digest>undefined|'[a-f0-9]{64}');/u;

export const getPublicPackageDirectory = (
    projectRoot: string = repoRoot,
): string => path.resolve(projectRoot, 'packages', 'sdk');

export const parsePackageManagerOverride = (
    commandLineArguments: readonly string[],
): PackageManager | undefined => {
    const packageManagerIndex =
        commandLineArguments.indexOf('--package-manager');
    if (packageManagerIndex === -1) {
        return undefined;
    }

    const packageManager = commandLineArguments[packageManagerIndex + 1];
    if (packageManager === undefined) {
        throw new Error('--package-manager requires a value');
    }
    if (!supportedPackageManagers.has(packageManager as PackageManager)) {
        throw new Error(
            `Unsupported package manager override: ${packageManager}`,
        );
    }

    return packageManager as PackageManager;
};

export const detectPackageManager = (
    packageManagerEntryPointPath: string,
): PackageManager => {
    const normalizedEntryPointPath = packageManagerEntryPointPath.toLowerCase();
    if (normalizedEntryPointPath.includes('pnpm')) {
        return 'pnpm';
    }
    if (normalizedEntryPointPath.includes('npm')) {
        return 'npm';
    }

    throw new Error(
        `Unsupported package manager entry point: ${packageManagerEntryPointPath}`,
    );
};

export const getPackageManagerExecutableName = (
    packageManager: PackageManager,
    platform: NodeJS.Platform = process.platform,
): string => {
    return platform === 'win32' ? `${packageManager}.cmd` : packageManager;
};

export const resolvePackageManagerRunner = (
    commandLineArguments: readonly string[],
    packageManagerEntryPointPath = process.env.npm_execpath,
): PackageManagerRunner => {
    const packageManagerOverride =
        parsePackageManagerOverride(commandLineArguments);
    if (packageManagerOverride !== undefined) {
        return {
            command: getPackageManagerExecutableName(packageManagerOverride),
            commandArgsPrefix: [],
            kind: packageManagerOverride,
        };
    }

    if (packageManagerEntryPointPath === undefined) {
        throw new Error(
            'npm_execpath is required to run package manager commands when --package-manager is not provided',
        );
    }

    return {
        command: process.execPath,
        commandArgsPrefix: [packageManagerEntryPointPath],
        kind: detectPackageManager(packageManagerEntryPointPath),
    };
};

export const createPackArguments = (
    packDirectory: string,
): readonly string[] => ['pack', '--pack-destination', packDirectory];

export const createDryRunPackArguments = (): readonly string[] => [
    'pack',
    '--dry-run',
    '--json',
    '--ignore-scripts',
];

export const createInstallArguments = (
    packageManager: PackageManager,
    tarballPath: string,
): readonly string[] => {
    return packageManager === 'npm'
        ? ['install', '--ignore-scripts', '--silent', tarballPath]
        : ['add', '--ignore-scripts', '--silent', tarballPath];
};

export const createPackageManagerSpawnCommand = (
    runner: PackageManagerRunner,
    commandArguments: readonly string[],
    commandShell: string = process.env.ComSpec ?? 'cmd.exe',
): SpawnCommand => {
    const commandArgs = [...runner.commandArgsPrefix, ...commandArguments];
    const description = [runner.command, ...commandArgs].join(' ');

    if (runner.command.endsWith('.cmd')) {
        return {
            command: commandShell,
            args: ['/d', '/s', '/c', runner.command, ...commandArgs],
            description,
        };
    }

    return {
        command: runner.command,
        args: commandArgs,
        description,
    };
};

const runPackageManagerAndCaptureOutput = (
    runner: PackageManagerRunner,
    commandArguments: readonly string[],
    cwd: string,
): string => {
    const spawnCommand = createPackageManagerSpawnCommand(
        runner,
        commandArguments,
    );
    const result = spawnSync(spawnCommand.command, spawnCommand.args, {
        cwd,
        env: process.env,
        encoding: 'utf8',
        maxBuffer: 100 * 1024 * 1024,
    });

    if (result.error !== undefined) {
        throw new Error(
            `Failed to start command: ${spawnCommand.description}: ${result.error.message}`,
        );
    }
    if (result.signal !== null) {
        throw new Error(
            `Command terminated by signal ${result.signal}: ${spawnCommand.description}`,
        );
    }
    if (result.status !== 0) {
        const stdout = result.stdout?.trim();
        const stderr = result.stderr?.trim();
        const formattedOutput =
            stdout !== '' || stderr !== ''
                ? `\n${[stdout, stderr].filter(Boolean).join('\n')}`
                : '';

        throw new Error(
            `Command exited with status ${result.status ?? 'null'}: ${spawnCommand.description}${formattedOutput}`,
        );
    }

    return result.stdout ?? '';
};

const runPackageManager = (
    runner: PackageManagerRunner,
    commandArguments: readonly string[],
    cwd: string,
): void => {
    runPackageManagerAndCaptureOutput(runner, commandArguments, cwd);
};

const isPackedFileMetadata = (value: unknown): value is PackedFileMetadata => {
    if (typeof value !== 'object' || value === null) {
        return false;
    }

    const packedFileMetadata = value as { path?: unknown };

    return typeof packedFileMetadata.path === 'string';
};

const isPackDryRunMetadataEntry = (
    value: unknown,
): value is PackDryRunMetadataEntry => {
    if (typeof value !== 'object' || value === null) {
        return false;
    }

    const packDryRunMetadataEntry = value as {
        files?: unknown;
    };

    return (
        Array.isArray(packDryRunMetadataEntry.files) &&
        packDryRunMetadataEntry.files.every(isPackedFileMetadata)
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

    const parsedMetadataEntries = parsedMetadata as readonly unknown[];
    const metadataEntry = parsedMetadataEntries[0];

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

    const typeScriptBuildInfoPaths = publishedPackageFilePaths.filter(
        (filePath) => filePath.endsWith('.tsbuildinfo'),
    );
    for (const typeScriptBuildInfoPath of typeScriptBuildInfoPaths) {
        failures.push(
            `Published package must not include TypeScript build metadata: ${typeScriptBuildInfoPath}`,
        );
    }
    for (const publishedPackageFilePath of publishedPackageFilePaths) {
        for (const forbiddenPathFragment of forbiddenPublishedRuntimePathFragments) {
            if (publishedPackageFilePath.includes(forbiddenPathFragment)) {
                failures.push(
                    `Published package must not include internal protocol runtime: ${publishedPackageFilePath}`,
                );
            }
        }
        if (
            forbiddenPublishedTestVectorPathFragments.some(
                (forbiddenPathFragment) =>
                    publishedPackageFilePath.includes(forbiddenPathFragment),
            )
        ) {
            failures.push(
                `Published package must not include repository test vectors: ${publishedPackageFilePath}`,
            );
        }
    }

    return failures;
};

export const validatePublishedPackageMetadata = (
    publishedPackageJson: Record<string, unknown>,
): string[] => {
    const failures: string[] = [];

    if ('description' in publishedPackageJson) {
        failures.push(
            'Published package metadata must not include a description field',
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
        .update(normalizeTranscriptCoreKernelBytesForDigest(bytes))
        .digest('hex');

export const extractPublishedKernelDigest = (
    kernelRuntimeText: string,
): string | undefined => {
    const match = publishedKernelDigestPattern.exec(kernelRuntimeText);
    const digest = match?.groups?.digest;
    if (digest === undefined || digest === 'undefined') {
        return undefined;
    }

    return digest.slice(1, -1);
};

export const validatePublishedKernelIntegrity = (
    kernelRuntimeText: string,
    kernelBytes: Uint8Array,
): string[] => {
    const expectedDigest = extractPublishedKernelDigest(kernelRuntimeText);
    if (expectedDigest === undefined) {
        return [
            'Published package kernel loader must pin the packaged transcript-core WASM digest',
        ];
    }

    const actualDigest = hashPublishedKernelBytesSha256Hex(kernelBytes);
    if (actualDigest !== expectedDigest) {
        return [
            `Published package kernel digest mismatch: expected ${expectedDigest}, received ${actualDigest}`,
        ];
    }

    return [];
};

const main = async (): Promise<void> => {
    const packageManagerRunner = resolvePackageManagerRunner(
        process.argv.slice(2),
    );
    const npmPackRunner: PackageManagerRunner = {
        command: getPackageManagerExecutableName('npm'),
        commandArgsPrefix: [],
        kind: 'npm',
    };
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
        const packageMetadataValidationFailures =
            validatePublishedPackageMetadata(publishedPackageJson);
        if (packageMetadataValidationFailures.length > 0) {
            throw new Error(packageMetadataValidationFailures.join('\n'));
        }
        const publishedPackageFilePaths = parsePackDryRunFilePaths(
            runPackageManagerAndCaptureOutput(
                npmPackRunner,
                createDryRunPackArguments(),
                packageDirectory,
            ),
        );
        const publishedPackageValidationFailures =
            validatePublishedPackageFilePaths(publishedPackageFilePaths);
        if (publishedPackageValidationFailures.length > 0) {
            throw new Error(publishedPackageValidationFailures.join('\n'));
        }
        const packageKernelIntegrityFailures = validatePublishedKernelIntegrity(
            await readFile(join(packageDirectory, 'dist', 'kernel.js'), 'utf8'),
            await readFile(
                join(packageDirectory, 'dist', 'sealed-lattice-kernel.wasm'),
            ),
        );
        if (packageKernelIntegrityFailures.length > 0) {
            throw new Error(packageKernelIntegrityFailures.join('\n'));
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
            JSON.stringify(
                {
                    name: 'sealed-lattice-smoke-consumer',
                    private: true,
                    type: 'module',
                },
                null,
                2,
            ),
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

        const commandArgs = ['smoke.mjs'];
        const commandDescription = [process.execPath, ...commandArgs].join(' ');
        const result = spawnSync(process.execPath, commandArgs, {
            cwd: consumerDirectory,
            env: process.env,
            encoding: 'utf8',
            maxBuffer: 100 * 1024 * 1024,
        });
        if (result.error !== undefined) {
            throw new Error(
                `Failed to start smoke entry point: ${commandDescription}: ${result.error.message}`,
            );
        }
        if (result.signal !== null) {
            throw new Error(
                `Smoke entry point terminated by signal ${result.signal}: ${commandDescription}`,
            );
        }
        if (result.status !== 0) {
            const stdout = result.stdout?.trim();
            const stderr = result.stderr?.trim();
            const formattedOutput =
                stdout !== '' || stderr !== ''
                    ? `\n${[stdout, stderr].filter(Boolean).join('\n')}`
                    : '';

            throw new Error(
                `Smoke entry point exited with status ${result.status ?? 'null'}: ${commandDescription}${formattedOutput}`,
            );
        }

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
