import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

export type CommandInvocation = {
    readonly args: readonly string[];
    readonly command: string;
    readonly description: string;
    readonly env?: NodeJS.ProcessEnv;
};

export type PackageManagerRunner = {
    readonly command: string;
    readonly commandArgumentsPrefix: readonly string[];
};

export const resolvePackageManagerRunner = (
    packageManagerEntryPointPath = process.env.npm_execpath,
): PackageManagerRunner => {
    if (packageManagerEntryPointPath === undefined) {
        throw new Error(
            'npm_execpath is required to run package manager commands through the Node entry point.',
        );
    }

    return {
        command: process.execPath,
        commandArgumentsPrefix: [packageManagerEntryPointPath],
    };
};

export const createPackageManagerCommand = (
    description: string,
    commandArguments: readonly string[],
    input: {
        readonly env?: NodeJS.ProcessEnv;
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

export const runCommands = (
    invocations: readonly CommandInvocation[],
): number => {
    for (const invocation of invocations) {
        const exitCode = runCommand(invocation);
        if (exitCode !== 0) {
            return exitCode;
        }
    }

    return 0;
};

const main = (): void => {
    const separatorIndex = process.argv.indexOf('--');
    if (separatorIndex === -1) {
        throw new Error('run-command requires -- followed by command args.');
    }

    const commandArguments = process.argv.slice(separatorIndex + 1);
    if (commandArguments.length === 0) {
        throw new Error('run-command requires at least one command argument.');
    }

    process.exitCode = runCommand({
        args: commandArguments.slice(1),
        command: commandArguments[0] ?? '',
        description: commandArguments.join(' '),
    });
};

const scriptEntryPoint = process.argv[1];
const isMainModule =
    scriptEntryPoint !== undefined &&
    import.meta.url === pathToFileURL(scriptEntryPoint).href;

if (isMainModule) {
    main();
}
