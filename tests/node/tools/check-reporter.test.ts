import { describe, expect, it, vi } from 'vitest';

import { CheckReporter } from '#tools/ci/check-reporter';

const command = {
    args: ['run'],
    command: 'tool',
    description: 'Compile sources',
} as const;

describe('plain check reporter', () => {
    it('prints line-oriented status and retains actionable failure output', () => {
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
                    stderrPath: 'logs/type-check/stderr.log',
                    stdoutPath: 'logs/type-check/stdout.log',
                },
                startedAtMilliseconds: 10,
            });
            observer.onCommandOutput?.({
                chunk: '\u001b[31mfirst error\u001b[0m\npartial',
                invocation: command,
                streamName: 'stderr',
            });
            observer.onCommandOutput?.({
                chunk: ' message\n',
                invocation: command,
                streamName: 'stderr',
            });
            observer.onCommandExit?.({
                durationMilliseconds: 1_234,
                exitCode: 2,
                invocation: command,
                terminationSignal: null,
            });

            expect(write.mock.calls.map(([line]) => String(line))).toEqual([
                'RUN  Type-check - Compile sources\n',
                'FAIL Type-check (1.2s) - Compile sources\n',
            ]);
            expect(reporter.failureDetails()).toEqual([
                {
                    commandDescription: 'Compile sources',
                    exitCode: 2,
                    laneName: 'Type-check',
                    logPath: 'logs/type-check/output.log',
                    recentOutputLines: ['first error', 'partial message'],
                },
            ]);
        } finally {
            write.mockRestore();
        }
    });

    it('keeps only the most recent non-empty output lines', () => {
        const write = vi
            .spyOn(process.stdout, 'write')
            .mockImplementation(() => true);
        try {
            const reporter = new CheckReporter();
            const observer = reporter.createCommandObserver('Lint');
            observer.onCommandStart?.({
                invocation: command,
                startedAtMilliseconds: 0,
            });
            observer.onCommandOutput?.({
                chunk: `${Array.from({ length: 25 }, (_, index) => `line-${index}`).join('\n')}\n\n`,
                invocation: command,
                streamName: 'stdout',
            });
            observer.onCommandExit?.({
                durationMilliseconds: 50,
                exitCode: 1,
                invocation: command,
                terminationSignal: null,
            });

            expect(reporter.failureDetails()[0]?.recentOutputLines).toEqual(
                Array.from({ length: 20 }, (_, index) => `line-${index + 5}`),
            );
        } finally {
            write.mockRestore();
        }
    });
});
