import { spawnSync } from 'node:child_process';
import {
    copyFile,
    mkdtemp,
    mkdir,
    readdir,
    rm,
    writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path, { join } from 'node:path';
import { fileURLToPath } from 'node:url';

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

    if (!publishedPackageFilePaths.includes('LICENSE')) {
        failures.push('Published package is missing LICENSE');
    }

    const typeScriptBuildInfoPaths = publishedPackageFilePaths.filter(
        (filePath) => filePath.endsWith('.tsbuildinfo'),
    );
    for (const typeScriptBuildInfoPath of typeScriptBuildInfoPaths) {
        failures.push(
            `Published package must not include TypeScript build metadata: ${typeScriptBuildInfoPath}`,
        );
    }

    return failures;
};

const main = async (): Promise<void> => {
    const packageManagerRunner = resolvePackageManagerRunner(
        process.argv.slice(2),
    );
    const packageDirectory = getPublicPackageDirectory();
    const npmPackRunner: PackageManagerRunner = {
        command: getPackageManagerExecutableName('npm'),
        commandArgsPrefix: [],
        kind: 'npm',
    };
    const tempRoot = await mkdtemp(join(tmpdir(), 'sealed-lattice-packed-'));
    const packDirectory = join(tempRoot, 'pack');
    const consumerDirectory = join(tempRoot, 'consumer');

    try {
        await mkdir(packDirectory, { recursive: true });
        await mkdir(consumerDirectory, { recursive: true });

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
