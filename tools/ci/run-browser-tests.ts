import { type PackageManagerRunner } from './package-manager-runner.js';
import { type CommandInvocation } from './run-command.js';
import {
    buildVitestProjectCommand,
    runWorkspaceBuildThenParallelCommands,
} from './run-vitest-lanes.js';
import { browserTestLaneDefinitions } from './test-lanes.js';

import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';

const parseBrowserTestArguments = (
    commandArguments: readonly string[],
): void => {
    if (commandArguments.length > 0) {
        throw new Error('Usage: run-browser-tests.ts.');
    }
};

const buildBrowserTestCommands = (
    packageManagerRunner: PackageManagerRunner,
    runDirectoryPath?: string,
): readonly CommandInvocation[] =>
    (['desktop', 'mobile'] as const).flatMap((lane) => {
        const laneDefinition = browserTestLaneDefinitions[lane];

        return laneDefinition.instanceProjectNames.map((instanceProjectName) =>
            buildVitestProjectCommand({
                commandDescription: `Run ${lane} browser tests (${instanceProjectName})`,
                packageManagerRunner,
                projectName: instanceProjectName,
                runDirectoryPath,
            }),
        );
    });

const main = async (): Promise<void> => {
    const rawArguments = process.argv.slice(2);
    await runWorkspaceBuildThenParallelCommands({
        buildCommands: (packageManagerRunner, runDirectoryPath) => {
            parseBrowserTestArguments(rawArguments);
            return buildBrowserTestCommands(
                packageManagerRunner,
                runDirectoryPath,
            );
        },
        commandLineArguments: rawArguments,
        lanes: ['desktop', 'mobile'],
        scriptName: 'test:browser',
    });
};

if (isDirectlyInvokedModule(import.meta.url)) {
    void main();
}
