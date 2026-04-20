import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

export const cacheOverrideEnvironmentVariableName =
    'SEALED_LATTICE_TURBO_CACHE';

export type TurboInvocation = {
    readonly command: string;
    readonly args: readonly string[];
};

export const getPnpmExecutableName = (
    platform: NodeJS.Platform = process.platform,
): string => {
    return platform === 'win32' ? 'pnpm.cmd' : 'pnpm';
};

export const splitTurboArguments = (
    commandLineArguments: readonly string[],
): {
    readonly tasks: readonly string[];
    readonly turboArguments: readonly string[];
} => {
    const tasks: string[] = [];
    const turboArguments: string[] = [];
    let encounteredTurboArgument = false;

    for (const commandLineArgument of commandLineArguments) {
        if (
            !encounteredTurboArgument &&
            !commandLineArgument.startsWith('--')
        ) {
            tasks.push(commandLineArgument);
            continue;
        }

        encounteredTurboArgument = true;
        turboArguments.push(commandLineArgument);
    }

    if (tasks.length === 0) {
        throw new Error('At least one Turbo task name is required.');
    }

    return {
        tasks,
        turboArguments,
    };
};

export const buildTurboInvocation = (
    commandLineArguments: readonly string[],
    cacheOverride: string | undefined = process.env[
        cacheOverrideEnvironmentVariableName
    ],
    platform: NodeJS.Platform = process.platform,
    commandShell: string = process.env.ComSpec ?? 'cmd.exe',
): TurboInvocation => {
    const { tasks, turboArguments } = splitTurboArguments(commandLineArguments);
    const packageManagerCommand = getPnpmExecutableName(platform);
    const packageManagerArguments = [
        'exec',
        'turbo',
        'run',
        ...tasks,
        ...turboArguments,
    ];

    if (cacheOverride !== undefined && cacheOverride.trim() !== '') {
        packageManagerArguments.push(`--cache=${cacheOverride.trim()}`);
    }

    if (platform === 'win32') {
        return {
            command: commandShell,
            args: [
                '/d',
                '/s',
                '/c',
                packageManagerCommand,
                ...packageManagerArguments,
            ],
        };
    }

    return {
        command: packageManagerCommand,
        args: packageManagerArguments,
    };
};

/* v8 ignore start */
const main = (): void => {
    const invocation = buildTurboInvocation(process.argv.slice(2));
    const result = spawnSync(invocation.command, invocation.args, {
        stdio: 'inherit',
        env: process.env,
    });

    if (result.error !== undefined) {
        throw result.error;
    }

    process.exitCode = result.status ?? 1;
};

const scriptEntryPoint = process.argv[1];
const isMainModule =
    scriptEntryPoint !== undefined &&
    import.meta.url === pathToFileURL(scriptEntryPoint).href;

if (isMainModule) {
    main();
}
/* v8 ignore stop */
