import { createLocalRunLog, currentProcessExitCode } from './local-run-log.js';
import { buildProcessMemoryGuardVerificationCommand } from './process-memory-guard.js';
import { runCommandsInSeries } from './run-command.js';

import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';

export const runProcessMemoryGuardTests = async (): Promise<void> => {
    const rawArguments = process.argv
        .slice(2)
        .filter((argument) => argument !== '--');
    if (rawArguments.length > 0) {
        throw new Error(
            'test:rust:process-memory-guard does not accept test filters.',
        );
    }

    const runLog = await createLocalRunLog({
        commandLineArguments: process.argv.slice(2),
        lanes: ['Rust process memory guard'],
        scriptName: 'test:rust:process-memory-guard',
    });
    let exitCode: number | undefined;
    try {
        exitCode = await runCommandsInSeries(
            [buildProcessMemoryGuardVerificationCommand()],
            { outputMode: 'inherit', runLog },
        );
        process.exitCode = exitCode;
    } finally {
        await runLog.finish({
            exitCode: exitCode ?? currentProcessExitCode(),
        });
    }
};

if (isDirectlyInvokedModule(import.meta.url)) {
    void runProcessMemoryGuardTests();
}
