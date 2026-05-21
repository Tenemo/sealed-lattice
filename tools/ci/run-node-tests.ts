import { pathToFileURL } from 'node:url';

import {
    createPackageManagerCommand,
    resolvePackageManagerRunner,
    runCommands,
    type CommandInvocation,
    type PackageManagerRunner,
} from './run-command.js';

export const buildNodeTestCommands = (
    input: {
        readonly packageManagerRunner?: PackageManagerRunner;
    } = {},
): readonly CommandInvocation[] => {
    const packageManagerRunner =
        input.packageManagerRunner ?? resolvePackageManagerRunner();
    const buildCommand = (
        description: string,
        commandArguments: readonly string[],
    ): CommandInvocation =>
        createPackageManagerCommand(description, commandArguments, {
            packageManagerRunner,
        });

    return [
        buildCommand('Run fast and heavy Node tests', [
            'exec',
            'vitest',
            '--project',
            'node',
            '--project',
            'node-heavy',
            '--run',
        ]),
        buildCommand('Run heavy Node kernel tests', [
            'exec',
            'vitest',
            '--project',
            'node-kernel-heavy',
            '--run',
        ]),
    ];
};

const main = (): void => {
    process.exitCode = runCommands(buildNodeTestCommands());
};

const scriptEntryPoint = process.argv[1];
const isMainModule =
    scriptEntryPoint !== undefined &&
    import.meta.url === pathToFileURL(scriptEntryPoint).href;

if (isMainModule) {
    main();
}
