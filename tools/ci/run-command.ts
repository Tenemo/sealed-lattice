import { spawn, spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { createWriteStream, type WriteStream } from 'node:fs';
import path from 'node:path';

import type { ActiveLocalRunLog, CommandLogFiles } from './local-run-log.js';

export type PackageManager = 'npm' | 'pnpm';

export type CommandInvocation = {
    readonly args: readonly string[];
    readonly command: string;
    readonly description: string;
    readonly env?: NodeJS.ProcessEnv;
    readonly logFileSlug?: string;
};

export type PackageManagerRunner = {
    readonly command: string;
    readonly commandArgumentsPrefix: readonly string[];
    readonly kind: PackageManager;
};

export type PackageManagerSpawnCommand = {
    readonly args: readonly string[];
    readonly command: string;
    readonly description: string;
};

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
    if (packageManager !== 'npm') {
        throw new Error(
            `Unsupported package manager override: ${packageManager}`,
        );
    }

    return packageManager;
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

export const buildPackageManagerEntryPointCandidates = (
    packageManager: PackageManager,
    pathEnvironment: string = process.env.PATH ?? '',
    nodeExecutablePath: string = process.execPath,
): readonly string[] => {
    const nodeDirectoryPath = path.dirname(nodeExecutablePath);
    const pathDirectoryPaths = pathEnvironment
        .split(path.delimiter)
        .filter((directoryPath) => directoryPath.length > 0);
    const baseDirectoryPaths = [nodeDirectoryPath, ...pathDirectoryPaths];
    const relativeEntryPointPaths =
        packageManager === 'npm'
            ? [
                  path.join('node_modules', 'npm', 'bin', 'npm-cli.js'),
                  path.join(
                      '..',
                      'lib',
                      'node_modules',
                      'npm',
                      'bin',
                      'npm-cli.js',
                  ),
              ]
            : [
                  path.join('node_modules', 'corepack', 'dist', 'pnpm.js'),
                  path.join('node_modules', 'pnpm', 'bin', 'pnpm.cjs'),
                  path.join(
                      '..',
                      'lib',
                      'node_modules',
                      'pnpm',
                      'bin',
                      'pnpm.cjs',
                  ),
              ];

    return baseDirectoryPaths.flatMap((baseDirectoryPath) =>
        relativeEntryPointPaths.map((relativeEntryPointPath) =>
            path.resolve(baseDirectoryPath, relativeEntryPointPath),
        ),
    );
};

export const resolvePackageManagerEntryPoint = (
    packageManager: PackageManager,
    packageManagerEntryPointPath = process.env.npm_execpath,
    pathEnvironment: string = process.env.PATH ?? '',
    nodeExecutablePath: string = process.execPath,
    pathExists: (candidatePath: string) => boolean = existsSync,
): string => {
    if (packageManagerEntryPointPath !== undefined) {
        try {
            if (
                detectPackageManager(packageManagerEntryPointPath) ===
                packageManager
            ) {
                return packageManagerEntryPointPath;
            }
        } catch {
            // Keep searching for a real Node entry point below.
        }
    }

    const entryPointPath = buildPackageManagerEntryPointCandidates(
        packageManager,
        pathEnvironment,
        nodeExecutablePath,
    ).find(pathExists);

    if (entryPointPath === undefined) {
        throw new Error(
            `Cannot find a Node entry point for ${packageManager}. Avoid shell shims and run through npm_execpath or a Node-installed package-manager CLI.`,
        );
    }

    return entryPointPath;
};

export const resolvePackageManagerRunner = (
    packageManagerEntryPointPath = process.env.npm_execpath,
    pathEnvironment: string = process.env.PATH ?? '',
    nodeExecutablePath: string = process.execPath,
    pathExists: (candidatePath: string) => boolean = existsSync,
): PackageManagerRunner => {
    const resolvedPackageManagerEntryPointPath =
        packageManagerEntryPointPath ??
        resolvePackageManagerEntryPoint(
            'pnpm',
            undefined,
            pathEnvironment,
            nodeExecutablePath,
            pathExists,
        );

    return {
        command: nodeExecutablePath,
        commandArgumentsPrefix: [resolvedPackageManagerEntryPointPath],
        kind: detectPackageManager(resolvedPackageManagerEntryPointPath),
    };
};

export const resolvePackageManagerRunnerForPackageManager = (
    packageManager: PackageManager,
    packageManagerEntryPointPath = process.env.npm_execpath,
    pathEnvironment: string = process.env.PATH ?? '',
    nodeExecutablePath: string = process.execPath,
    pathExists: (candidatePath: string) => boolean = existsSync,
): PackageManagerRunner => {
    const entryPointPath = resolvePackageManagerEntryPoint(
        packageManager,
        packageManagerEntryPointPath,
        pathEnvironment,
        nodeExecutablePath,
        pathExists,
    );

    return {
        command: nodeExecutablePath,
        commandArgumentsPrefix: [entryPointPath],
        kind: packageManager,
    };
};

export const resolvePackageManagerRunnerFromArguments = (
    commandLineArguments: readonly string[],
    packageManagerEntryPointPath = process.env.npm_execpath,
    pathEnvironment: string = process.env.PATH ?? '',
    nodeExecutablePath: string = process.execPath,
    pathExists: (candidatePath: string) => boolean = existsSync,
): PackageManagerRunner => {
    const packageManagerOverride =
        parsePackageManagerOverride(commandLineArguments);
    if (packageManagerOverride !== undefined) {
        return resolvePackageManagerRunnerForPackageManager(
            packageManagerOverride,
            packageManagerEntryPointPath,
            pathEnvironment,
            nodeExecutablePath,
            pathExists,
        );
    }

    if (packageManagerEntryPointPath === undefined) {
        throw new Error(
            'npm_execpath is required to run package manager commands when --package-manager is not provided',
        );
    }

    return {
        command: nodeExecutablePath,
        commandArgumentsPrefix: [packageManagerEntryPointPath],
        kind: detectPackageManager(packageManagerEntryPointPath),
    };
};

export const createPackageManagerCommand = (
    description: string,
    commandArguments: readonly string[],
    input: {
        readonly env?: NodeJS.ProcessEnv;
        readonly logFileSlug?: string;
        readonly packageManagerRunner?: PackageManagerRunner;
    } = {},
): CommandInvocation => {
    const packageManagerRunner =
        input.packageManagerRunner ?? resolvePackageManagerRunner();

    return {
        args: [
            ...packageManagerRunner.commandArgumentsPrefix,
            ...commandArguments,
        ],
        command: packageManagerRunner.command,
        description,
        env: input.env,
        logFileSlug: input.logFileSlug,
    };
};

export const runCommand = (invocation: CommandInvocation): number => {
    console.log(`\n${invocation.description}`);
    const result = spawnSync(invocation.command, invocation.args, {
        env: invocation.env ?? process.env,
        stdio: 'inherit',
    });

    if (result.error !== undefined) {
        throw result.error;
    }

    return result.status ?? 1;
};

export const createPackageManagerSpawnCommand = (
    runner: PackageManagerRunner,
    commandArguments: readonly string[],
): PackageManagerSpawnCommand => {
    const commandArgs = [...runner.commandArgumentsPrefix, ...commandArguments];
    const description = [runner.command, ...commandArgs].join(' ');

    return {
        command: runner.command,
        args: commandArgs,
        description,
    };
};

export const runPackageManagerAndCaptureOutput = (
    runner: PackageManagerRunner,
    commandArguments: readonly string[],
    workingDirectoryPath: string,
): string => {
    const spawnCommand = createPackageManagerSpawnCommand(
        runner,
        commandArguments,
    );
    const result = spawnSync(spawnCommand.command, spawnCommand.args, {
        cwd: workingDirectoryPath,
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

export const runPackageManager = (
    runner: PackageManagerRunner,
    commandArguments: readonly string[],
    workingDirectoryPath: string,
): void => {
    runPackageManagerAndCaptureOutput(
        runner,
        commandArguments,
        workingDirectoryPath,
    );
};

const runCommandInParallel = (invocation: CommandInvocation): Promise<number> =>
    new Promise((resolve, reject) => {
        console.log(`\n${invocation.description}`);
        const childProcess = spawn(invocation.command, invocation.args, {
            env: invocation.env ?? process.env,
            stdio: 'inherit',
        });
        let settled = false;
        childProcess.once('error', (error) => {
            if (settled) {
                return;
            }
            settled = true;
            reject(error);
        });
        childProcess.once('close', (exitCode, signal) => {
            if (settled) {
                return;
            }
            settled = true;
            if (signal !== null) {
                console.error(
                    `${invocation.description} terminated by signal ${signal}.`,
                );
                resolve(1);
                return;
            }

            resolve(exitCode ?? 1);
        });
    });

const closeWritableStream = async (stream: WriteStream): Promise<void> =>
    new Promise((resolve, reject) => {
        stream.once('error', reject);
        stream.end(resolve);
    });

const openCommandLogStreams = (
    files: CommandLogFiles,
): {
    readonly combined: WriteStream;
    readonly stderr: WriteStream;
    readonly stdout: WriteStream;
} => ({
    combined: createWriteStream(files.combinedPath, { flags: 'a' }),
    stderr: createWriteStream(files.stderrPath, { flags: 'a' }),
    stdout: createWriteStream(files.stdoutPath, { flags: 'a' }),
});

const closeCommandLogStreams = async (streams: {
    readonly combined: WriteStream;
    readonly stderr: WriteStream;
    readonly stdout: WriteStream;
}): Promise<void> => {
    await Promise.all([
        closeWritableStream(streams.combined),
        closeWritableStream(streams.stderr),
        closeWritableStream(streams.stdout),
    ]);
};

const runCommandWithOptionalLog = async (
    invocation: CommandInvocation,
    runLog?: ActiveLocalRunLog,
): Promise<number> => {
    if (runLog === undefined) {
        return runCommandInParallel(invocation);
    }

    const commandLogFiles = runLog.createCommandLogFiles({
        description: invocation.description,
        preferredSlug: invocation.logFileSlug,
    });
    const commandLogStreams = openCommandLogStreams(commandLogFiles);
    const heading = `\n${invocation.description}\n`;
    process.stdout.write(heading);
    commandLogStreams.combined.write(heading);
    runLog.writeCombinedOutput(heading);

    return new Promise((resolve, reject) => {
        const childProcess = spawn(invocation.command, invocation.args, {
            env: invocation.env ?? process.env,
            stdio: ['ignore', 'pipe', 'pipe'],
        });
        const writeChunk = (
            streamName: 'stderr' | 'stdout',
            chunk: string | Uint8Array,
        ): void => {
            const terminalStream =
                streamName === 'stdout' ? process.stdout : process.stderr;
            const childStream =
                streamName === 'stdout'
                    ? commandLogStreams.stdout
                    : commandLogStreams.stderr;
            terminalStream.write(chunk);
            childStream.write(chunk);
            commandLogStreams.combined.write(chunk);
            runLog.writeCombinedOutput(chunk);
        };
        let settled = false;
        childProcess.stdout.setEncoding('utf8');
        childProcess.stderr.setEncoding('utf8');
        childProcess.stdout.on('data', (chunk: string) => {
            writeChunk('stdout', chunk);
        });
        childProcess.stderr.on('data', (chunk: string) => {
            writeChunk('stderr', chunk);
        });
        childProcess.once('error', (error) => {
            if (settled) {
                return;
            }
            settled = true;
            void (async () => {
                try {
                    await closeCommandLogStreams(commandLogStreams);
                } catch {
                    // Preserve the original process start failure.
                }
                reject(error);
            })();
        });
        childProcess.once('close', (exitCode, signal) => {
            if (settled) {
                return;
            }
            settled = true;
            void (async () => {
                try {
                    if (signal !== null) {
                        const signalMessage = `${invocation.description} terminated by signal ${signal}.\n`;
                        process.stderr.write(signalMessage);
                        commandLogStreams.stderr.write(signalMessage);
                        commandLogStreams.combined.write(signalMessage);
                        runLog.writeCombinedOutput(signalMessage);
                    }
                    await closeCommandLogStreams(commandLogStreams);
                    resolve(signal === null ? (exitCode ?? 1) : 1);
                } catch (error) {
                    reject(
                        error instanceof Error
                            ? error
                            : new Error(String(error)),
                    );
                }
            })();
        });
    });
};

export const runCommandsInParallel = async (
    invocations: readonly CommandInvocation[],
    input: { readonly runLog?: ActiveLocalRunLog } = {},
): Promise<number> => {
    const exitCodes = await Promise.all(
        invocations.map((invocation) =>
            runCommandWithOptionalLog(invocation, input.runLog),
        ),
    );

    return exitCodes.find((exitCode) => exitCode !== 0) ?? 0;
};

export const runCommandsInSeries = async (
    invocations: readonly CommandInvocation[],
    input: { readonly runLog?: ActiveLocalRunLog } = {},
): Promise<number> => {
    for (const invocation of invocations) {
        const exitCode = await runCommandWithOptionalLog(
            invocation,
            input.runLog,
        );
        if (exitCode !== 0) {
            return exitCode;
        }
    }

    return 0;
};
