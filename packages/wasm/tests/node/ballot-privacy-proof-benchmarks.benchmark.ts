import { describe, expect, it } from 'vitest';

import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';
import {
    formatProofBenchmarkReport,
    runAggregateDerivationProofBenchmark,
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
        'records mandatory ballot proof generation, proof verification, and package boundary metrics through WASM',
        async () => {
            const kernel = await loadTranscriptCoreKernel();
            const checkpoints = createJsonCheckpointStore();
            const resumeFromCheckpoints = shouldResumeFromTestCheckpoints();
            const runtime = nodeRuntimeContext();
            const {
                ballotPackage,
                claimVerification,
                fixture,
                generation,
                report,
                verification,
            } = runMandatoryBallotProofRecordBenchmark({
                checkpoints,
                kernel,
                resumeFromCheckpoints,
                runtime,
            });
            const aggregateBenchmark = runAggregateDerivationProofBenchmark({
                ballotPackage,
                checkpoints,
                fixture,
                kernel,
                resumeFromCheckpoints,
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
