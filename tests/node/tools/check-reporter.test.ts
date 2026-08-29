import { describe, expect, it, vi } from 'vitest';

import { CheckReporter } from '#tools/ci/check-reporter';

const command = {
    args: ['run'],
    command: 'tool',
    description: 'Compile sources',
} as const;

describe('plain check reporter', () => {
    it('retains the most recent actionable failure output', () => {
        const write = vi
            .spyOn(process.stdout, 'write')
            .mockImplementation(() => true);
        try {
            const reporter = new CheckReporter();
            const observer = reporter.createCommandObserver('Type-check');
            observer.onCommandStart?.({
                invocation: command,
                logFiles: {
                    combinedPath: 'logs/type-check/output.log',
                    commandId: 'type-check-1',
                },
                startedAtMilliseconds: 10,
            });
            observer.onCommandOutput?.({
                chunk: `${Array.from({ length: 25 }, (_, index) => `\u001b[31merror-${index}\u001b[0m`).join('\n')}\n\n`,
                invocation: command,
                streamName: 'stderr',
            });
            observer.onCommandExit?.({
                durationMilliseconds: 1_234,
                exitCode: 2,
                invocation: command,
                terminationSignal: null,
            });

            expect(reporter.failureDetails()).toEqual([
                {
                    commandDescription: 'Compile sources',
                    exitCode: 2,
                    laneName: 'Type-check',
                    logPath: 'logs/type-check/output.log',
                    recentOutputLines: Array.from(
                        { length: 20 },
                        (_, index) => `error-${index + 5}`,
                    ),
                },
            ]);
        } finally {
            write.mockRestore();
        }
    });
});
