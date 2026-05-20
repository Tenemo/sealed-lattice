export type TimedTestStepMetric = {
    readonly durationMs: number;
    readonly name: string;
    readonly reusedCheckpoint?: boolean;
};

const runtimeNowMs = (): number => globalThis.performance?.now() ?? Date.now();

export const runTimedTestStep = <Result>(
    steps: TimedTestStepMetric[],
    name: string,
    action: () => Result,
    options: {
        readonly reusedCheckpoint?: boolean;
    } = {},
): Result => {
    const startedAtMs = runtimeNowMs();

    try {
        return action();
    } finally {
        const metric: TimedTestStepMetric = {
            durationMs: runtimeNowMs() - startedAtMs,
            name,
            ...(options.reusedCheckpoint === true
                ? { reusedCheckpoint: true }
                : {}),
        };
        steps.push(metric);
        console.info(
            JSON.stringify({
                event: 'test-step-complete',
                ...metric,
            }),
        );
    }
};
