import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { cdp, server } from 'vitest/browser';

import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';
import {
    formatProofBenchmarkReport,
    runAggregateDerivationProofBenchmark,
    runMandatoryBallotProofRecordBenchmark,
    runReceiverKeyProofBenchmark,
    type RuntimeBenchmarkContext,
} from '#tests/support/ballot-privacy-proof-benchmarks';
import {
    applyCalibratedMidTierMobileCpuThrottle,
    setBrowserCpuThrottleRate,
    type BrowserCpuThrottleRateSetter,
    type CpuThrottleCalibrationSuccess,
} from '#tests/support/browser-cpu-throttle-calibration';

const proofBenchmarkTimeoutMs = 60 * 60_000;
let mobileCpuThrottleCalibration: CpuThrottleCalibrationSuccess | undefined;

const setCpuThrottleRate: BrowserCpuThrottleRateSetter = async (
    throttleRate,
) => {
    await cdp().send('Emulation.setCPUThrottlingRate', {
        rate: throttleRate,
    });
};

const hasMobileBrowserUserAgent = (): boolean =>
    /Mobile|Android|iPhone|iPad/u.test(navigator.userAgent);

const resetBrowserCpuThrottle = async (): Promise<void> => {
    await setBrowserCpuThrottleRate({
        setCpuThrottleRate,
        throttleRate: 1,
    });
};

const mobileCpuThrottleContext = ():
    | RuntimeBenchmarkContext['cpuThrottle']
    | undefined => {
    if (mobileCpuThrottleCalibration === undefined) {
        return undefined;
    }

    return {
        baselineScore: mobileCpuThrottleCalibration.baselineScore,
        measuredScore: mobileCpuThrottleCalibration.measuredScore,
        source: mobileCpuThrottleCalibration.source,
        targetScore: mobileCpuThrottleCalibration.targetScore,
        throttleRate: mobileCpuThrottleCalibration.throttleRate,
    };
};

const browserRuntimeContext = (): RuntimeBenchmarkContext => {
    const userAgent = navigator.userAgent;
    const hasMobileUserAgent = hasMobileBrowserUserAgent();
    const deviceClass = hasMobileUserAgent ? 'mobile' : 'desktop';

    return {
        browser: server.browser,
        cpuThrottle: mobileCpuThrottleContext(),
        deviceClass,
        provider: server.provider,
        runtimeLabel: `${server.provider}-${server.browser}-${deviceClass}`,
        userAgent,
        viewportHeight: window.innerHeight,
        viewportWidth: window.innerWidth,
    };
};

const expectPositiveFiniteDuration = (durationMs: number): void => {
    expect(Number.isFinite(durationMs)).toBe(true);
    expect(durationMs).toBeGreaterThan(0);
};

describe('ballot privacy proof benchmarks in browsers', () => {
    beforeAll(async () => {
        if (!hasMobileBrowserUserAgent()) {
            return;
        }
        if (server.provider !== 'playwright' || server.browser !== 'chromium') {
            throw new Error(
                'Mobile proof benchmark CPU calibration requires Playwright Chromium.',
            );
        }

        try {
            mobileCpuThrottleCalibration =
                await applyCalibratedMidTierMobileCpuThrottle({
                    setCpuThrottleRate,
                });
        } catch (error) {
            await resetBrowserCpuThrottle();
            throw error;
        }
    }, proofBenchmarkTimeoutMs);

    afterAll(async () => {
        if (mobileCpuThrottleCalibration === undefined) {
            return;
        }

        await resetBrowserCpuThrottle();
        mobileCpuThrottleCalibration = undefined;
    });

    it(
        'records mandatory ballot proof generation, proof verification, and package boundary metrics',
        async () => {
            const kernel = await loadTranscriptCoreKernel();
            const runtime = browserRuntimeContext();
            const {
                ballotPackage,
                claimVerification,
                fixture,
                generation,
                report,
                verification,
            } = runMandatoryBallotProofRecordBenchmark({
                kernel,
                runtime,
            });
            const aggregateBenchmark = runAggregateDerivationProofBenchmark({
                ballotPackage,
                fixture,
                kernel,
                runtime,
            });

            expect(generation).toMatchObject({
                ok: true,
                generatedProofBytes: true,
                operation: 'generateBallotProofRecord',
                unresolvedReason: null,
            });
            expect(verification).toMatchObject({
                ok: true,
                operation: 'verifyBallotProof',
                unresolvedReason: null,
            });
            expect(claimVerification).toMatchObject({
                ok: true,
                operation: 'verifyClaimBearingBallotPackage',
                unresolvedReason: null,
            });
            expect(aggregateBenchmark.generation).toMatchObject({
                ok: true,
                generatedProofBytes: true,
                operation: 'generateAggregateDerivationProof',
                unresolvedReason: null,
            });
            expect(aggregateBenchmark.verification).toMatchObject({
                ok: true,
                operation: 'verifyAggregateDerivationProof',
                unresolvedReason: null,
            });
            expect(report.proofSizeBytes).toBeGreaterThan(0);
            expect(report.totalComponentProofSizeBytes).toBeGreaterThan(0);
            expect(report.componentProofs).toHaveLength(5);
            expectPositiveFiniteDuration(report.generationMs);
            expectPositiveFiniteDuration(report.verificationMs);
            expectPositiveFiniteDuration(report.packageVerificationMs);
            const claimBearingProofSizes = report.componentProofs
                .filter(
                    (componentProof) =>
                        componentProof.componentId !==
                        'receiver-key-binding-component',
                )
                .map((componentProof) => componentProof.proofSizeBytes);
            expect(claimBearingProofSizes).toHaveLength(4);
            for (const proofSizeBytes of claimBearingProofSizes) {
                expect(proofSizeBytes).toBeGreaterThan(0);
            }
            expect(aggregateBenchmark.report.proofSizeBytes).toBeGreaterThan(0);
            expect(aggregateBenchmark.report.statementRows).toBe(224);
            expect(aggregateBenchmark.report.statementColumns).toBe(724);
            expect(aggregateBenchmark.report.canonicalTurnout).toBe(1);
            expectPositiveFiniteDuration(
                aggregateBenchmark.report.generationMs,
            );
            expectPositiveFiniteDuration(
                aggregateBenchmark.report.verificationMs,
            );
            console.info(formatProofBenchmarkReport(report));
            console.info(formatProofBenchmarkReport(aggregateBenchmark.report));
        },
        proofBenchmarkTimeoutMs,
    );

    it(
        'records receiver-key proof generation and verification metrics',
        async () => {
            const kernel = await loadTranscriptCoreKernel();
            const { generation, report, verification } =
                runReceiverKeyProofBenchmark({
                    kernel,
                    runtime: browserRuntimeContext(),
                });

            expect(generation).toMatchObject({
                ok: true,
                generatedProofBytes: true,
                operation: 'generateReceiverKeyProof',
                unresolvedReason: null,
            });
            expect(verification).toMatchObject({
                ok: true,
                operation: 'verifyReceiverKeyProof',
                unresolvedReason: null,
            });
            expect(report.proofSizeBytes).toBeGreaterThan(0);
            expectPositiveFiniteDuration(report.generationMs);
            expectPositiveFiniteDuration(report.verificationMs);
            console.info(formatProofBenchmarkReport(report));
        },
        proofBenchmarkTimeoutMs,
    );
});
