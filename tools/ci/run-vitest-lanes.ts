import { createLocalRunLog, currentProcessExitCode } from './local-run-log.js';
import {
    createPackageManagerCommand,
    resolvePackageManagerRunner,
    runCommandsInParallel,
    runCommandsInSeries,
    type CommandInvocation,
    type PackageManagerRunner,
} from './run-command.js';

export const buildWorkspaceBuildCommand = (
    packageManagerRunner: PackageManagerRunner,
): CommandInvocation =>
    createPackageManagerCommand('Build workspace packages', ['run', 'build'], {
        logFileSlug: 'build',
        packageManagerRunner,
    });

export const buildVitestProjectCommand = (input: {
    readonly commandDescription: string;
    readonly packageManagerRunner: PackageManagerRunner;
    readonly projectName: string;
}): CommandInvocation =>
    createPackageManagerCommand(
        input.commandDescription,
        ['exec', 'vitest', '--project', input.projectName, '--run'],
        {
            logFileSlug: input.projectName,
            packageManagerRunner: input.packageManagerRunner,
        },
    );

export const runWorkspaceBuildThenParallelCommands = async <
    Lane extends string,
>(input: {
    readonly buildCommands: (
        packageManagerRunner: PackageManagerRunner,
    ) => readonly CommandInvocation[];
    readonly commandLineArguments: readonly string[];
    readonly lanes: readonly Lane[];
    readonly scriptName: string;
    readonly shouldCreateRunLog: boolean;
}): Promise<void> => {
    const packageManagerRunner = resolvePackageManagerRunner();
    const runLog = input.shouldCreateRunLog
        ? await createLocalRunLog({
              commandLineArguments: input.commandLineArguments,
              lanes: input.lanes,
              scriptName: input.scriptName,
          })
        : undefined;

    try {
        const buildExitCode = await runCommandsInSeries(
            [buildWorkspaceBuildCommand(packageManagerRunner)],
            { runLog },
        );
        if (buildExitCode !== 0) {
            process.exitCode = buildExitCode;

            return;
        }
        process.exitCode = await runCommandsInParallel(
            input.buildCommands(packageManagerRunner),
            { runLog },
        );
    } finally {
        await runLog?.finish({ exitCode: currentProcessExitCode() });
    }
};
