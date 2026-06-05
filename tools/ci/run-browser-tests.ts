import {
    removeRunLogArguments,
    runLogDisabledByArguments,
} from './local-run-log.js';
import {
    type CommandInvocation,
    type PackageManagerRunner,
} from './run-command.js';
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
        throw new Error('Usage: run-browser-tests.ts [--no-run-log].');
    }
};

const buildBrowserTestCommands = (
    packageManagerRunner: PackageManagerRunner,
): readonly CommandInvocation[] =>
    (['desktop', 'mobile'] as const).map((lane) => {
        const laneDefinition = browserTestLaneDefinitions[lane];

        return buildVitestProjectCommand({
            commandDescription: `Run ${lane} browser tests`,
            packageManagerRunner,
            projectName: laneDefinition.projectName,
        });
    });

const main = async (): Promise<void> => {
    const rawArguments = process.argv.slice(2);
    const commandArguments = removeRunLogArguments(rawArguments);
    parseBrowserTestArguments(commandArguments);
    await runWorkspaceBuildThenParallelCommands({
        buildCommands: buildBrowserTestCommands,
        commandLineArguments: rawArguments,
        lanes: ['desktop', 'mobile'],
        scriptName: 'test:browser',
        shouldCreateRunLog: !runLogDisabledByArguments(rawArguments),
    });
};

if (isDirectlyInvokedModule(import.meta.url)) {
    void main();
}
