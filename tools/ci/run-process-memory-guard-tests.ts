import path from 'node:path';

import { createHeavyTestProgressReporter } from './heavy-test-progress.js';
import { runWithLocalRunLog } from './local-run-log.js';
import { buildProcessMemoryGuardVerificationCommand } from './process-memory-guard.js';
import { runCommandsInSeries } from './run-command.js';

export const runProcessMemoryGuardTests = async (): Promise<void> => {
    const commandLineArguments = process.argv.slice(2);
    await runWithLocalRunLog(
        {
            commandLineArguments,
            lanes: ['Rust process memory guard'],
            scriptName: 'test:rust:process-memory-guard',
        },
        async (runLog) => {
            const rawArguments = commandLineArguments.filter(
                (argument) => argument !== '--',
            );
            if (rawArguments.length > 0) {
                throw new Error(
                    'test:rust:process-memory-guard does not accept test filters.',
                );
            }

            const progressReporter = createHeavyTestProgressReporter({
                eventFilePath: path.join(
                    runLog.runDirectoryPath,
                    'tests',
                    'rust-process-memory-guard.jsonl',
                ),
                label: 'rust-process-memory-guard',
                threadCount: 1,
            });
            try {
                process.exitCode = await runCommandsInSeries(
                    [buildProcessMemoryGuardVerificationCommand()],
                    {
                        observer: progressReporter.observer,
                        outputMode: 'inherit',
                        runLog,
                        terminalOutputFilter:
                            progressReporter.terminalOutputFilter,
                    },
                );
            } finally {
                progressReporter.stop();
            }
        },
    );
};

if (import.meta.main) {
    void runProcessMemoryGuardTests();
}
