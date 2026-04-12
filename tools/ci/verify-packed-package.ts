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
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));

export type PackageManager = 'npm' | 'pnpm';

type PackageManagerRunner = {
    command: string;
    commandArgsPrefix: readonly string[];
    kind: PackageManager;
};

const supportedPackageManagers = new Set<PackageManager>(['npm', 'pnpm']);

export const parsePackageManagerOverride = (
    argv: readonly string[],
): PackageManager | undefined => {
    const packageManagerIndex = argv.indexOf('--package-manager');
    if (packageManagerIndex === -1) {
        return undefined;
    }

    const packageManager = argv[packageManagerIndex + 1];
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
    packageManagerEntrypoint: string,
): PackageManager => {
    const normalizedEntrypoint = packageManagerEntrypoint.toLowerCase();
    if (normalizedEntrypoint.includes('pnpm')) {
        return 'pnpm';
    }
    if (normalizedEntrypoint.includes('npm')) {
        return 'npm';
    }

    throw new Error(
        `Unsupported package manager entrypoint: ${packageManagerEntrypoint}`,
    );
};

export const getPackageManagerExecutableName = (
    packageManager: PackageManager,
    platform: NodeJS.Platform = process.platform,
): string => {
    return platform === 'win32' ? `${packageManager}.cmd` : packageManager;
};

export const resolvePackageManagerRunner = (
    argv: readonly string[],
    packageManagerEntrypoint = process.env.npm_execpath,
): PackageManagerRunner => {
    const packageManagerOverride = parsePackageManagerOverride(argv);
    if (packageManagerOverride !== undefined) {
        return {
            command: getPackageManagerExecutableName(packageManagerOverride),
            commandArgsPrefix: [],
            kind: packageManagerOverride,
        };
    }

    if (packageManagerEntrypoint === undefined) {
        throw new Error(
            'npm_execpath is required to run package manager commands when --package-manager is not provided',
        );
    }

    return {
        command: process.execPath,
        commandArgsPrefix: [packageManagerEntrypoint],
        kind: detectPackageManager(packageManagerEntrypoint),
    };
};

export const createPackArguments = (
    packDirectory: string,
): readonly string[] => ['pack', '--pack-destination', packDirectory];

export const createInstallArguments = (
    packageManager: PackageManager,
    tarballPath: string,
): readonly string[] => {
    return packageManager === 'npm'
        ? ['install', '--ignore-scripts', '--silent', tarballPath]
        : ['add', '--ignore-scripts', '--silent', tarballPath];
};

const runPackageManager = (
    runner: PackageManagerRunner,
    args: readonly string[],
    cwd: string,
): void => {
    const commandArgs = [...runner.commandArgsPrefix, ...args];
    const isWindowsCommandShim = runner.command.endsWith('.cmd');
    const commandDescription = [runner.command, ...commandArgs].join(' ');
    const result = isWindowsCommandShim
        ? spawnSync(
              process.env.ComSpec ?? 'cmd.exe',
              ['/d', '/s', '/c', commandDescription],
              {
                  cwd,
                  env: process.env,
                  encoding: 'utf8',
                  maxBuffer: 100 * 1024 * 1024,
              },
          )
        : spawnSync(runner.command, commandArgs, {
              cwd,
              env: process.env,
              encoding: 'utf8',
              maxBuffer: 100 * 1024 * 1024,
          });

    if (result.error !== undefined) {
        throw new Error(
            `Failed to start command: ${commandDescription}: ${result.error.message}`,
        );
    }
    if (result.signal !== null) {
        throw new Error(
            `Command terminated by signal ${result.signal}: ${commandDescription}`,
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
            `Command exited with status ${result.status ?? 'null'}: ${commandDescription}${formattedOutput}`,
        );
    }
};

const main = async (): Promise<void> => {
    const packageManagerRunner = resolvePackageManagerRunner(
        process.argv.slice(2),
    );
    const tempRoot = await mkdtemp(join(tmpdir(), 'sealed-lattice-packed-'));
    const packDirectory = join(tempRoot, 'pack');
    const consumerDirectory = join(tempRoot, 'consumer');

    try {
        await mkdir(packDirectory, { recursive: true });
        await mkdir(consumerDirectory, { recursive: true });

        runPackageManager(
            packageManagerRunner,
            createPackArguments(packDirectory),
            repoRoot,
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
            join(repoRoot, 'tools/ci/packed-package-smoke.mjs'),
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
                `Failed to start smoke entrypoint: ${commandDescription}: ${result.error.message}`,
            );
        }
        if (result.signal !== null) {
            throw new Error(
                `Smoke entrypoint terminated by signal ${result.signal}: ${commandDescription}`,
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
                `Smoke entrypoint exited with status ${result.status ?? 'null'}: ${commandDescription}${formattedOutput}`,
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
