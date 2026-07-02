import { createLocalRunLog, currentProcessExitCode } from './local-run-log.js';
import {
    resolvePackageManagerRunner,
    type PackageManagerRunner,
} from './package-manager-runner.js';
import {
    createPackageManagerCommand,
    runCommandsAfterSeriesGate,
    type CommandInvocation,
} from './run-command.js';

const buildWorkspaceBuildCommand = (
    packageManagerRunner: PackageManagerRunner,
): CommandInvocation =>
    createPackageManagerCommand('Build workspace packages', ['run', 'build'], {
        logFileSlug: 'build',
        packageManagerRunner,
    });

export const buildVitestProjectsCommand = (input: {
    readonly commandDescription: string;
    readonly packageManagerRunner: PackageManagerRunner;
    readonly projectNames: readonly string[];
}): CommandInvocation =>
    createPackageManagerCommand(
        input.commandDescription,
        [
            'exec',
            'vitest',
            ...input.projectNames.flatMap((projectName) => [
                '--project',
                projectName,
            ]),
            '--run',
        ],
        {
            logFileSlug: input.projectNames.join('-'),
            packageManagerRunner: input.packageManagerRunner,
        },
    );

export const buildVitestProjectCommand = (input: {
    readonly commandDescription: string;
    readonly packageManagerRunner: PackageManagerRunner;
    readonly projectName: string;
}): CommandInvocation =>
    buildVitestProjectsCommand({
        commandDescription: input.commandDescription,
        packageManagerRunner: input.packageManagerRunner,
        projectNames: [input.projectName],
    });

export const runWorkspaceBuildThenParallelCommands = async <
    Lane extends string,
>(input: {
    readonly buildCommands: (
        packageManagerRunner: PackageManagerRunner,
    ) => readonly CommandInvocation[];
    readonly commandLineArguments: readonly string[];
    readonly extraGateCommands?: (
        packageManagerRunner: PackageManagerRunner,
    ) => readonly CommandInvocation[];
    readonly lanes: readonly Lane[];
    readonly scriptName: string;
}): Promise<void> => {
    const packageManagerRunner = resolvePackageManagerRunner();
    const runLog = await createLocalRunLog({
        commandLineArguments: input.commandLineArguments,
        lanes: input.lanes,
        scriptName: input.scriptName,
    });

    try {
        const extraGateCommands =
            input.extraGateCommands?.(packageManagerRunner) ?? [];
        process.exitCode = await runCommandsAfterSeriesGate(
            {
                gateCommands: [
                    buildWorkspaceBuildCommand(packageManagerRunner),
                    ...extraGateCommands,
                ],
                parallelCommands: input.buildCommands(packageManagerRunner),
            },
            { runLog },
        );
    } finally {
        await runLog.finish({ exitCode: currentProcessExitCode() });
    }
};
