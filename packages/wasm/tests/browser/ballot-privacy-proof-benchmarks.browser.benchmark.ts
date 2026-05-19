import { describe, expect, it } from 'vitest';
import { server } from 'vitest/browser';

import {
    formatProofBenchmarkReport,
    runMandatoryBallotProofRecordBenchmark,
    runReceiverKeyProofBenchmark,
    type RuntimeBenchmarkContext,
} from '../../../../tests/support/ballot-privacy-proof-benchmarks';
import { loadTranscriptCoreKernel } from '../../src/index';

const proofBenchmarkTimeoutMs = 60 * 60_000;

const browserRuntimeContext = (): RuntimeBenchmarkContext => {
    const userAgent = navigator.userAgent;
    const hasMobileUserAgent = /Mobile|Android|iPhone|iPad/u.test(userAgent);
    const deviceClass = hasMobileUserAgent ? 'mobile' : 'desktop';

    return {
        browser: server.browser,
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
    it(
        'records mandatory ballot proof generation and verification metrics',
        async () => {
            const kernel = await loadTranscriptCoreKernel();
            const { generation, report, verification } =
                runMandatoryBallotProofRecordBenchmark({
                    kernel,
                    runtime: browserRuntimeContext(),
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
            expect(report.proofSizeBytes).toBeGreaterThan(0);
            expect(report.totalComponentProofSizeBytes).toBeGreaterThan(0);
            expect(report.componentProofs).toHaveLength(5);
            expectPositiveFiniteDuration(report.generationMs);
            expectPositiveFiniteDuration(report.verificationMs);
            for (const componentProof of report.componentProofs) {
                if (
                    componentProof.componentId !==
                    'receiver-key-binding-component'
                ) {
                    expect(componentProof.proofSizeBytes).toBeGreaterThan(0);
                }
            }
            console.info(formatProofBenchmarkReport(report));
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
