import {
    createLocalRunLog,
    currentProcessExitCode,
    removeRunLogArguments,
    runLogDisabledByArguments,
} from './local-run-log.js';
import { runCommandsInSeries, type CommandInvocation } from './run-command.js';

import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';

const heavyAcceptedSetupTestPattern = 'heavy_accepted_setup';

const rustKernelHeavyTestCommand: CommandInvocation = {
    args: [
        'test',
        '-p',
        'sealed-lattice-kernel',
        heavyAcceptedSetupTestPattern,
        '--',
        '--ignored',
        '--show-output',
    ],
    command: 'cargo',
    description: 'cargo test heavy accepted setup tests',
    env: {
        ...process.env,
        CARGO_INCREMENTAL: '0',
    },
    logFileSlug: 'cargo-test-heavy-accepted-setup',
};

const main = async (): Promise<void> => {
    const rawArguments = process.argv.slice(2);
    const commandArguments = removeRunLogArguments(rawArguments);
    if (commandArguments.length > 0) {
        throw new Error(
            'Usage: run-rust-kernel-heavy-tests.ts [--no-run-log].',
        );
    }
    const runLog = runLogDisabledByArguments(rawArguments)
        ? undefined
        : await createLocalRunLog({
              commandLineArguments: rawArguments,
              lanes: ['Rust kernel heavy'],
              scriptName: 'test:rust:kernel:heavy',
          });

    let exitCode: number | undefined;
    try {
        exitCode = await runCommandsInSeries([rustKernelHeavyTestCommand], {
            outputMode: 'inherit',
            runLog,
        });
        process.exitCode = exitCode;
    } finally {
        await runLog?.finish({
            exitCode: exitCode ?? currentProcessExitCode(),
        });
    }
};

if (isDirectlyInvokedModule(import.meta.url)) {
    void main();
}
