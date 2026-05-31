import {
    createLocalRunLog,
    currentProcessExitCode,
    removeRunLogArguments,
    runLogDisabledByArguments,
} from './local-run-log.js';
import {
    createPackageManagerCommand,
    resolvePackageManagerRunner,
    runCommandsInParallel,
    runCommandsInSeries,
    type CommandInvocation,
    type PackageManagerRunner,
} from './run-command.js';
import { browserTestLaneDefinitions } from './test-lanes.js';

import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';

const parseBrowserTestArguments = (
    commandArguments: readonly string[],
): void => {
    if (commandArguments.length > 0) {
        throw new Error('Usage: run-browser-tests.ts [--no-run-log].');
    }
};

const buildWorkspaceBuildCommand = (
    packageManagerRunner: PackageManagerRunner,
): CommandInvocation =>
    createPackageManagerCommand('Build workspace packages', ['run', 'build'], {
        logFileSlug: 'build',
        packageManagerRunner,
    });

const buildBrowserTestCommands = (
    packageManagerRunner: PackageManagerRunner,
): readonly CommandInvocation[] =>
    (['desktop', 'mobile'] as const).map((lane) => {
        const laneDefinition = browserTestLaneDefinitions[lane];

        return createPackageManagerCommand(
            `Run ${lane} browser tests`,
            [
                'exec',
                'vitest',
                '--project',
                laneDefinition.projectName,
                '--run',
            ],
            {
                logFileSlug: laneDefinition.projectName,
                packageManagerRunner,
            },
        );
    });

const main = async (): Promise<void> => {
    const rawArguments = process.argv.slice(2);
    const commandArguments = removeRunLogArguments(rawArguments);
    parseBrowserTestArguments(commandArguments);
    const packageManagerRunner = resolvePackageManagerRunner();
    const runLog = runLogDisabledByArguments(rawArguments)
        ? undefined
        : await createLocalRunLog({
              commandLineArguments: rawArguments,
              lanes: ['desktop', 'mobile'],
              scriptName: 'test:browser',
          });

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
            buildBrowserTestCommands(packageManagerRunner),
            { runLog },
        );
    } finally {
        await runLog?.finish({ exitCode: currentProcessExitCode() });
    }
};

if (isDirectlyInvokedModule(import.meta.url)) {
    void main();
}
