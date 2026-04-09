import { performance } from 'node:perf_hooks';

import { sha256Hex } from '#root';

type BenchmarkCase = {
    input: string | Uint8Array;
    iterations: number;
    label: string;
};

const benchmarkCases: readonly BenchmarkCase[] = [
    {
        label: 'short-text',
        input: 'sealed-lattice',
        iterations: 1000,
    },
    {
        label: 'unicode-text',
        input: 'zażółć gęślą jaźń',
        iterations: 1000,
    },
    {
        label: '4kb-bytes',
        input: Uint8Array.from({ length: 4096 }, (_, index) => index % 256),
        iterations: 250,
    },
] as const;

const runCase = async (benchmarkCase: BenchmarkCase): Promise<void> => {
    const startedAt = performance.now();

    for (let index = 0; index < benchmarkCase.iterations; index += 1) {
        await sha256Hex(benchmarkCase.input);
    }

    const durationMs = performance.now() - startedAt;
    const perSecond = (benchmarkCase.iterations / durationMs) * 1000;

    console.log(
        `${benchmarkCase.label}: ${benchmarkCase.iterations} iterations in ${durationMs.toFixed(2)} ms (${perSecond.toFixed(2)} ops/s)`,
    );
};

const main = async (): Promise<void> => {
    for (const benchmarkCase of benchmarkCases) {
        await runCase(benchmarkCase);
    }
};

void main();
