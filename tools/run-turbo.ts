import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

import {
    resolvePackageManagerRunner,
    type PackageManagerRunner,
} from './ci/run-command.js';

export const cacheOverrideEnvironmentVariableName =
    'SEALED_LATTICE_TURBO_CACHE';

export type TurboInvocation = {
    readonly command: string;
    readonly args: readonly string[];
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
    packageManagerRunner: PackageManagerRunner = resolvePackageManagerRunner(),
): TurboInvocation => {
    const { tasks, turboArguments } = splitTurboArguments(commandLineArguments);
    const packageManagerArguments = [
        ...packageManagerRunner.commandArgumentsPrefix,
        'exec',
        'turbo',
        'run',
        ...tasks,
        ...turboArguments,
    ];

    if (cacheOverride !== undefined && cacheOverride.trim() !== '') {
        packageManagerArguments.push(`--cache=${cacheOverride.trim()}`);
    }

    return {
        command: packageManagerRunner.command,
        args: packageManagerArguments,
    };
};

export const runTurboInvocation = (invocation: TurboInvocation): number => {
    const result = spawnSync(invocation.command, invocation.args, {
        env: process.env,
        stdio: 'inherit',
    });

    if (result.error !== undefined) {
        throw result.error;
    }

    return result.status ?? 1;
};

/* v8 ignore start */
const main = (): void => {
    const invocation = buildTurboInvocation(process.argv.slice(2));
    process.exitCode = runTurboInvocation(invocation);
};

const scriptEntryPoint = process.argv[1];
const isMainModule =
    scriptEntryPoint !== undefined &&
    import.meta.url === pathToFileURL(scriptEntryPoint).href;

if (isMainModule) {
    main();
}
/* v8 ignore stop */
