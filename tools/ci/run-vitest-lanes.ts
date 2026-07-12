import { runWithLocalRunLog } from './local-run-log.js';
import {
    resolvePackageManagerRunner,
    type PackageManagerRunner,
} from './package-manager-runner.js';
import {
    createPackageManagerCommand,
    runCommandsAfterSeriesGate,
    type CommandInvocation,
} from './run-command.js';
import { buildTestDiagnosticEnvironment } from './test-diagnostic-environment.js';

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
    readonly runDirectoryPath?: string;
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
            env:
                input.runDirectoryPath === undefined
                    ? undefined
                    : buildTestDiagnosticEnvironment({
                          projectLabel: input.projectNames.join('-'),
                          runDirectoryPath: input.runDirectoryPath,
                      }),
            logFileSlug: input.projectNames.join('-'),
            packageManagerRunner: input.packageManagerRunner,
        },
    );

export const buildVitestProjectCommand = (input: {
    readonly commandDescription: string;
    readonly packageManagerRunner: PackageManagerRunner;
    readonly projectName: string;
    readonly runDirectoryPath?: string;
}): CommandInvocation =>
    buildVitestProjectsCommand({
        commandDescription: input.commandDescription,
        packageManagerRunner: input.packageManagerRunner,
        projectNames: [input.projectName],
        runDirectoryPath: input.runDirectoryPath,
    });

export const runWorkspaceBuildThenParallelCommands = async <
    Lane extends string,
>(input: {
    readonly buildCommands: (
        packageManagerRunner: PackageManagerRunner,
        runDirectoryPath: string,
    ) => readonly CommandInvocation[];
    readonly commandLineArguments: readonly string[];
    readonly extraGateCommands?: (
        packageManagerRunner: PackageManagerRunner,
    ) => readonly CommandInvocation[];
    readonly lanes: readonly Lane[];
    readonly scriptName: string;
}): Promise<void> => {
    await runWithLocalRunLog(
        {
            commandLineArguments: input.commandLineArguments,
            lanes: input.lanes,
            scriptName: input.scriptName,
        },
        async (runLog) => {
            const packageManagerRunner = resolvePackageManagerRunner();
            const extraGateCommands =
                input.extraGateCommands?.(packageManagerRunner) ?? [];
            process.exitCode = await runCommandsAfterSeriesGate(
                {
                    gateCommands: [
                        buildWorkspaceBuildCommand(packageManagerRunner),
                        ...extraGateCommands,
                    ],
                    parallelCommands: input.buildCommands(
                        packageManagerRunner,
                        runLog.runDirectoryPath,
                    ),
                },
                { runLog },
            );
        },
    );
};
