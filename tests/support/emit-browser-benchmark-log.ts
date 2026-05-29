// Browser-only helper. Vitest forwards headless browser console to a TTY/UI but
// not to the piped stdout the local run log tees, so browser proof-benchmark
// reports never reach logs/. This pushes a report line to the node process via
// the `writeBenchmarkLogLine` custom command registered in vitest.config.ts,
// which writes it to stdout so it is captured under logs/ like the node lane.
import { commands } from 'vitest/browser';

type BenchmarkLogCommands = {
    readonly writeBenchmarkLogLine: (line: string) => Promise<void>;
};

export const emitBrowserBenchmarkLogLine = async (
    line: string,
): Promise<void> => {
    await (commands as unknown as BenchmarkLogCommands).writeBenchmarkLogLine(
        line,
    );
};
