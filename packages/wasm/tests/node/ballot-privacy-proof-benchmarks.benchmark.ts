import { describe, expect, it } from 'vitest';

import { loadTranscriptCoreKernel } from '../../src/index';

import {
    formatProofBenchmarkReport,
    runMandatoryBallotProofRecordBenchmark,
    runReceiverKeyProofBenchmark,
    type RuntimeBenchmarkContext,
} from '#tests/support/ballot-privacy-proof-benchmarks';
import {
    createJsonCheckpointStore,
    shouldResumeFromTestCheckpoints,
} from '#tests/support/node-test-checkpoints';

const proofBenchmarkTimeoutMs = 60 * 60_000;

const nodeRuntimeContext = (): RuntimeBenchmarkContext => ({
    deviceClass: 'node',
    runtimeLabel: `node-${process.version}`,
});

const expectPositiveFiniteDuration = (durationMs: number): void => {
    expect(Number.isFinite(durationMs)).toBe(true);
    expect(durationMs).toBeGreaterThan(0);
};

describe('ballot privacy proof benchmarks', () => {
    it(
        'records mandatory ballot proof generation and verification metrics through WASM',
        async () => {
            const kernel = await loadTranscriptCoreKernel();
            const { claimVerification, generation, report, verification } =
                runMandatoryBallotProofRecordBenchmark({
                    checkpoints: createJsonCheckpointStore(),
                    kernel,
                    resumeFromCheckpoints: shouldResumeFromTestCheckpoints(),
                    runtime: nodeRuntimeContext(),
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
            expect(report.proofSizeBytes).toBeGreaterThan(0);
            expect(report.totalComponentProofSizeBytes).toBeGreaterThan(0);
            expect(report.componentProofs).toHaveLength(5);
            expectPositiveFiniteDuration(report.generationMs);
            expectPositiveFiniteDuration(report.verificationMs);
            expectPositiveFiniteDuration(report.packageVerificationMs);
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
        'records receiver-key proof generation and verification metrics through WASM',
        async () => {
            const kernel = await loadTranscriptCoreKernel();
            const { generation, report, verification } =
                runReceiverKeyProofBenchmark({
                    kernel,
                    runtime: nodeRuntimeContext(),
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
