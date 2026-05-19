export const midTierMobileBenchmarkScore = 1_000;

const defaultBenchmarkDurationMs = 250;
const defaultScoreTolerance = 10;
const defaultMaximumIterations = 8;
const defaultMaximumThrottleRate = 20;

export type BrowserCpuThrottleRateSetter = (
    throttleRate: number,
) => Promise<void>;

export type CpuThrottleCalibrationSource = 'chromium-devtools-mid-tier-mobile';

export type CpuThrottleCalibrationSuccess = {
    readonly baselineScore: number;
    readonly calibrated: true;
    readonly measuredScore: number;
    readonly source: CpuThrottleCalibrationSource;
    readonly targetScore: number;
    readonly throttleRate: number;
};

export type CpuThrottleCalibrationFailure = {
    readonly baselineScore: number;
    readonly calibrated: false;
    readonly reason: 'host-browser-too-slow';
    readonly source: CpuThrottleCalibrationSource;
    readonly targetScore: number;
};

export type CpuThrottleCalibrationResult =
    | CpuThrottleCalibrationFailure
    | CpuThrottleCalibrationSuccess;

type CpuThrottleCalibrationInput = {
    readonly benchmarkScoreAtThrottleRate: (
        throttleRate: number,
    ) => number | Promise<number>;
    readonly maximumIterations?: number;
    readonly maximumThrottleRate?: number;
    readonly scoreTolerance?: number;
    readonly source?: CpuThrottleCalibrationSource;
    readonly targetScore?: number;
};

const truncateThrottleRate = (throttleRate: number): number =>
    Number(throttleRate.toFixed(2));

const requireFinitePositiveNumber = (input: {
    readonly name: string;
    readonly value: number;
}): void => {
    if (!Number.isFinite(input.value) || input.value <= 0) {
        throw new Error(`${input.name} must be a finite positive number.`);
    }
};

const requireBenchmarkScore = async (input: {
    readonly benchmarkScoreAtThrottleRate: (
        throttleRate: number,
    ) => number | Promise<number>;
    readonly throttleRate: number;
}): Promise<number> => {
    const score = await input.benchmarkScoreAtThrottleRate(input.throttleRate);
    requireFinitePositiveNumber({
        name: `Benchmark score at ${input.throttleRate}x CPU throttle`,
        value: score,
    });

    return score;
};

export const calibrateCpuThrottleRate = async (
    input: CpuThrottleCalibrationInput,
): Promise<CpuThrottleCalibrationResult> => {
    const targetScore = input.targetScore ?? midTierMobileBenchmarkScore;
    const scoreTolerance = input.scoreTolerance ?? defaultScoreTolerance;
    const maximumIterations =
        input.maximumIterations ?? defaultMaximumIterations;
    const maximumThrottleRate =
        input.maximumThrottleRate ?? defaultMaximumThrottleRate;
    const source = input.source ?? 'chromium-devtools-mid-tier-mobile';

    requireFinitePositiveNumber({ name: 'Target score', value: targetScore });
    requireFinitePositiveNumber({
        name: 'Score tolerance',
        value: scoreTolerance,
    });
    requireFinitePositiveNumber({
        name: 'Maximum throttle rate',
        value: maximumThrottleRate,
    });

    if (!Number.isSafeInteger(maximumIterations) || maximumIterations < 1) {
        throw new Error('Maximum iteration count must be a positive integer.');
    }

    let baselineScore = await requireBenchmarkScore({
        benchmarkScoreAtThrottleRate: input.benchmarkScoreAtThrottleRate,
        throttleRate: 1,
    });

    if (baselineScore < targetScore) {
        baselineScore = await requireBenchmarkScore({
            benchmarkScoreAtThrottleRate: input.benchmarkScoreAtThrottleRate,
            throttleRate: 1,
        });
        if (baselineScore < targetScore) {
            return {
                baselineScore,
                calibrated: false,
                reason: 'host-browser-too-slow',
                source,
                targetScore,
            };
        }
    }

    let lowerRate = 1;
    let lowerScore = baselineScore;
    let upperRate = Math.min(
        maximumThrottleRate,
        Math.max(1.01, (baselineScore / targetScore) * 1.5),
    );
    let upperScore = await requireBenchmarkScore({
        benchmarkScoreAtThrottleRate: input.benchmarkScoreAtThrottleRate,
        throttleRate: upperRate,
    });

    while (upperScore > targetScore && upperRate < maximumThrottleRate) {
        lowerRate = upperRate;
        lowerScore = upperScore;
        upperRate = Math.min(maximumThrottleRate, upperRate * 1.5);
        upperScore = await requireBenchmarkScore({
            benchmarkScoreAtThrottleRate: input.benchmarkScoreAtThrottleRate,
            throttleRate: upperRate,
        });
    }

    let throttleRate = upperScore > targetScore ? upperRate : lowerRate;
    let measuredScore = upperScore > targetScore ? upperScore : lowerScore;

    for (
        let calibrationIteration = 0;
        calibrationIteration < maximumIterations;
        calibrationIteration += 1
    ) {
        throttleRate = truncateThrottleRate((lowerRate + upperRate) / 2);
        measuredScore = await requireBenchmarkScore({
            benchmarkScoreAtThrottleRate: input.benchmarkScoreAtThrottleRate,
            throttleRate,
        });

        if (Math.abs(targetScore - measuredScore) <= scoreTolerance) {
            break;
        }

        if (measuredScore < targetScore) {
            upperRate = throttleRate;
        } else {
            lowerRate = throttleRate;
        }
    }

    return {
        baselineScore,
        calibrated: true,
        measuredScore,
        source,
        targetScore,
        throttleRate,
    };
};

const benchmarkStringAllocation = (durationMs: number): number => {
    const startMs = Date.now();
    let iterationCount = 0;

    while (Date.now() - startMs < durationMs) {
        let generatedText = '';
        for (
            let characterIndex = 0;
            characterIndex < 10_000;
            characterIndex += 1
        ) {
            generatedText += 'a';
        }
        if (generatedText.length === 1) {
            throw new Error('Unexpected benchmark string length.');
        }

        iterationCount += 1;
    }

    const elapsedSeconds = (Date.now() - startMs) / 1_000;

    return Math.round(iterationCount / 10 / elapsedSeconds);
};

const benchmarkArrayCopy = (durationMs: number): number => {
    const firstValues: number[] = [];
    const secondValues: number[] = [];
    for (let valueIndex = 0; valueIndex < 100_000; valueIndex += 1) {
        firstValues[valueIndex] = valueIndex;
        secondValues[valueIndex] = valueIndex;
    }

    const startMs = Date.now();
    let iterationCount = 0;

    while (iterationCount % 10 !== 0 || Date.now() - startMs < durationMs) {
        const sourceValues =
            iterationCount % 2 === 0 ? firstValues : secondValues;
        const targetValues =
            iterationCount % 2 === 0 ? secondValues : firstValues;

        for (
            let valueIndex = 0;
            valueIndex < sourceValues.length;
            valueIndex += 1
        ) {
            targetValues[valueIndex] = sourceValues[valueIndex] ?? 0;
        }

        iterationCount += 1;
    }

    const elapsedSeconds = (Date.now() - startMs) / 1_000;

    return Math.round(iterationCount / 10 / elapsedSeconds);
};

export const computeCpuBenchmarkScore = (
    durationMs = defaultBenchmarkDurationMs,
): number => {
    requireFinitePositiveNumber({
        name: 'Benchmark duration',
        value: durationMs,
    });

    const componentDurationMs = durationMs / 2;

    return (
        (benchmarkStringAllocation(componentDurationMs) +
            benchmarkArrayCopy(componentDurationMs)) /
        2
    );
};

export const setBrowserCpuThrottleRate = async (input: {
    readonly setCpuThrottleRate: BrowserCpuThrottleRateSetter;
    readonly throttleRate: number;
}): Promise<void> => {
    requireFinitePositiveNumber({
        name: 'CPU throttle rate',
        value: input.throttleRate,
    });

    await input.setCpuThrottleRate(input.throttleRate);
};

export const applyCalibratedMidTierMobileCpuThrottle = async (input: {
    readonly benchmarkDurationMs?: number;
    readonly setCpuThrottleRate: BrowserCpuThrottleRateSetter;
}): Promise<CpuThrottleCalibrationSuccess> => {
    const calibration = await calibrateCpuThrottleRate({
        benchmarkScoreAtThrottleRate: async (throttleRate) => {
            await setBrowserCpuThrottleRate({
                setCpuThrottleRate: input.setCpuThrottleRate,
                throttleRate,
            });

            return computeCpuBenchmarkScore(input.benchmarkDurationMs);
        },
    });

    if (!calibration.calibrated) {
        throw new Error(
            `Cannot calibrate mobile CPU throttle: unthrottled browser score ${calibration.baselineScore.toFixed(
                1,
            )} is below the mid-tier mobile target score ${calibration.targetScore.toFixed(
                1,
            )}.`,
        );
    }

    await setBrowserCpuThrottleRate({
        setCpuThrottleRate: input.setCpuThrottleRate,
        throttleRate: calibration.throttleRate,
    });

    return calibration;
};
