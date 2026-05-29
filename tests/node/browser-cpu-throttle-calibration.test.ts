import { describe, expect, it } from 'vitest';

import {
    calibrateCpuThrottleRate,
    midTierMobileBenchmarkScore,
} from '#tests/support/browser-cpu-throttle-calibration';

describe('Browser CPU throttle calibration', () => {
    it('calibrates a predictable host score to the target mobile score', async () => {
        const calibration = await calibrateCpuThrottleRate({
            benchmarkScoreAtThrottleRate: (throttleRate) =>
                3_000 / throttleRate,
        });

        if (!calibration.calibrated) {
            throw new Error('Expected calibration to succeed.');
        }

        expect(calibration.baselineScore).toBe(3_000);
        expect(calibration.targetScore).toBe(midTierMobileBenchmarkScore);
        expect(calibration.throttleRate).toBeGreaterThanOrEqual(2.99);
        expect(calibration.throttleRate).toBeLessThanOrEqual(3.05);
        expect(calibration.measuredScore).toBeGreaterThanOrEqual(990);
        expect(calibration.measuredScore).toBeLessThanOrEqual(1_010);
    });

    it('stays stable when benchmark scores include deterministic measurement noise', async () => {
        const scoreOffsets = [6, -5, 4, -3, 2, -1, 1, 0] as const;
        let measurementCount = 0;

        const calibration = await calibrateCpuThrottleRate({
            benchmarkScoreAtThrottleRate: (throttleRate) => {
                const offset =
                    scoreOffsets[measurementCount % scoreOffsets.length];
                measurementCount += 1;

                return 2_400 / throttleRate + offset;
            },
        });

        if (!calibration.calibrated) {
            throw new Error('Expected calibration to succeed.');
        }

        expect(calibration.throttleRate).toBeGreaterThanOrEqual(2.35);
        expect(calibration.throttleRate).toBeLessThanOrEqual(2.45);
        expect(calibration.measuredScore).toBeGreaterThanOrEqual(990);
        expect(calibration.measuredScore).toBeLessThanOrEqual(1_010);
    });

    it('keeps the calibrated rate close to unthrottled when the host is barely faster than the target', async () => {
        const calibration = await calibrateCpuThrottleRate({
            benchmarkScoreAtThrottleRate: (throttleRate) =>
                1_005 / throttleRate,
        });

        if (!calibration.calibrated) {
            throw new Error('Expected calibration to succeed.');
        }

        expect(calibration.baselineScore).toBe(1_005);
        expect(calibration.throttleRate).toBeGreaterThanOrEqual(1);
        expect(calibration.throttleRate).toBeLessThanOrEqual(1.02);
        expect(calibration.measuredScore).toBeGreaterThanOrEqual(990);
        expect(calibration.measuredScore).toBeLessThanOrEqual(1_010);
    });

    it('reports a host browser that is already slower than the target mobile score', async () => {
        const unthrottledScores = [980, 990] as const;
        let measurementCount = 0;

        const calibration = await calibrateCpuThrottleRate({
            benchmarkScoreAtThrottleRate: (throttleRate) => {
                expect(throttleRate).toBe(1);
                const score =
                    unthrottledScores[
                        Math.min(measurementCount, unthrottledScores.length - 1)
                    ];
                measurementCount += 1;

                return score;
            },
        });

        expect(calibration).toEqual({
            baselineScore: 990,
            calibrated: false,
            reason: 'host-browser-too-slow',
            source: 'chromium-devtools-mid-tier-mobile',
            targetScore: midTierMobileBenchmarkScore,
        });
        expect(measurementCount).toBe(2);
    });
});
