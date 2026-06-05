import { describe, expect, it } from 'vitest';
import { server } from 'vitest/browser';

import {
    createDirectBallotSetupPackage,
    directBallotScores,
    runMeasuredDirectEncryptedBallotPrototype,
} from '../node/transcript-core-kernel/direct-encrypted-ballot-prototype';

import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';
import { emitBrowserBenchmarkLogLine } from '#tests/support/emit-browser-benchmark-log';

const directBallotBrowserBenchmarkTimeoutMs = 60 * 60_000;

const browserRuntimeContext = (): Record<string, unknown> => {
    const userAgent = navigator.userAgent;
    const deviceClass = /Mobile|Android|iPhone|iPad/u.test(userAgent)
        ? 'mobile'
        : 'desktop';

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

describe('direct encrypted ballot prototype in browsers', () => {
    it(
        'verifies one widened direct ballot proof and aggregates through browser WASM',
        async () => {
            const kernel = await loadTranscriptCoreKernel();
            const setupPackage = createDirectBallotSetupPackage(kernel);
            const startedAtMs = performance.now();
            const { result, memory } =
                await runMeasuredDirectEncryptedBallotPrototype({
                    setupPackage,
                });
            const wallTimeMs = performance.now() - startedAtMs;

            expect(result.operation).toBe('runDirectEncryptedBallotPrototype');
            expect(result.input.ballotCount).toBe(1);
            expect(result.proofAttempt.proofAccounting).toMatchObject({
                challengeBits: 192,
                minimumIndependentRepetitionsForTarget: 1,
            });
            expect(
                result.proofAttempt.proofAccounting
                    .classicalSoundnessBitsAfterSupportUnionBound,
            ).toBeGreaterThanOrEqual(128);
            expect(
                result.proofAttempt.proofAccounting
                    .zeroKnowledgeShiftSlackBitsAfterResponseUnionBound,
            ).toBeGreaterThanOrEqual(128);
            expect(result.proofAttempt.proofSizeBytes).toBe(18_626_400);
            expect(result.proofAttempt.proofTransport).toMatchObject({
                encoding: 'binary proof chunks',
                chunkSizeBytes: 1_048_576,
                chunksPerProof: 18,
                chunksForBatch: 18,
                transportedProofSizeBytes: result.proofAttempt.proofSizeBytes,
                transportedProofBytesHash: result.proofAttempt.proofBytesHash,
            });
            expect(
                result.proofAttempt.proofTransport.firstProofChunkMerkleRoot,
            ).toHaveLength(128);
            expect(result.proofAttempt.proofMaskRandomness).toMatchObject({
                source: 'fresh-csprng',
                ballotProofRandomnessCount: 1,
                refreshShareProofRandomnessCount: 0,
                randomnessBytesPerProof: 32,
            });
            expect(
                result.ballotPackages.ballotEncryptionRandomness,
            ).toMatchObject({
                source: 'fresh-csprng',
                ballotEncryptionRandomnessCount: 1,
                randomnessBytesPerBallot: 32,
            });
            expect(result.aggregation.aggregateScores).toEqual(
                result.aggregation.plaintextOracleScores,
            );
            expect(result.aggregation.aggregateScores).toEqual(
                directBallotScores,
            );

            await emitBrowserBenchmarkLogLine(
                JSON.stringify({
                    event: 'direct-encrypted-ballot-browser-proof-smoke',
                    runtime: browserRuntimeContext(),
                    proofSizeBytes: result.proofAttempt.proofSizeBytes,
                    proofTransport: result.proofAttempt.proofTransport,
                    proofMaskRandomness:
                        result.proofAttempt.proofMaskRandomness,
                    wallTimeMs,
                    runtimeMemoryBefore: memory.runtimeBefore,
                    runtimeMemoryAfter: memory.runtimeAfter,
                    wasmLinearMemoryBytesBefore:
                        memory.wasmLinearMemoryBytesBefore,
                    wasmLinearMemoryBytesAfter:
                        memory.wasmLinearMemoryBytesAfter,
                }),
            );
        },
        directBallotBrowserBenchmarkTimeoutMs,
    );

    it(
        'replays one prefix target through browser WASM from the direct aggregate',
        async () => {
            const kernel = await loadTranscriptCoreKernel();
            const setupPackage = createDirectBallotSetupPackage(kernel);
            const startedAtMs = performance.now();
            const { result, memory } =
                await runMeasuredDirectEncryptedBallotPrototype({
                    setupPackage,
                    topCount: 1,
                });
            const wallTimeMs = performance.now() - startedAtMs;

            expect(result.operation).toBe('runDirectEncryptedBallotPrototype');
            expect(result.input.ballotCount).toBe(1);
            expect(result.proofAttempt.proofSizeBytes).toBe(18_626_400);
            expect(result.proofAttempt.proofTransport).toMatchObject({
                encoding: 'binary proof chunks',
                chunkSizeBytes: 1_048_576,
                chunksPerProof: 18,
                chunksForBatch: 18,
                transportedProofSizeBytes: result.proofAttempt.proofSizeBytes,
                transportedProofBytesHash: result.proofAttempt.proofBytesHash,
            });
            expect(
                result.proofAttempt.proofTransport.firstProofChunkMerkleRoot,
            ).toHaveLength(128);
            expect(result.proofAttempt.proofMaskRandomness).toMatchObject({
                source: 'fresh-csprng',
                ballotProofRandomnessCount: 1,
                refreshShareProofRandomnessCount: 3,
                randomnessBytesPerProof: 32,
            });
            expect(
                result.ballotPackages.ballotEncryptionRandomness,
            ).toMatchObject({
                source: 'fresh-csprng',
                ballotEncryptionRandomnessCount: 1,
                randomnessBytesPerBallot: 32,
            });
            expect(result.evaluatorReplay).not.toBeTypeOf('string');
            const evaluatorReplay = result.evaluatorReplay as Exclude<
                typeof result.evaluatorReplay,
                string
            >;
            expect(evaluatorReplay.topCount).toBe(1);
            expect(evaluatorReplay.decodedTargetIds).toEqual(
                evaluatorReplay.plaintextOracleTargetIds,
            );
            expect(evaluatorReplay.decodedTargetOrders).toEqual(
                evaluatorReplay.plaintextOracleTargetOrders,
            );
            expect(evaluatorReplay.decodedTargetIds).toEqual([
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]);
            expect(evaluatorReplay.rankRefresh).not.toBeTypeOf('string');
            const rankRefresh = evaluatorReplay.rankRefresh as Exclude<
                typeof evaluatorReplay.rankRefresh,
                string
            >;
            const refreshShareChunkCount =
                rankRefresh.thresholdOpening.shareReports.reduce(
                    (total, shareReport) => total + shareReport.proofChunkCount,
                    0,
                );
            expect(rankRefresh.thresholdOpening.proofTransport).toMatchObject({
                encoding: 'binary proof chunks',
                chunkSizeBytes: 1_048_576,
                chunksForOpening: refreshShareChunkCount,
            });
            expect(
                rankRefresh.thresholdOpening.shareReports[0]
                    ?.proofTransportedBytesHash,
            ).toBe(
                rankRefresh.thresholdOpening.shareReports[0]?.proofBytesHash,
            );
            expect(
                rankRefresh.thresholdOpening.shareReports[0]
                    ?.proofChunkMerkleRoot,
            ).toHaveLength(128);

            await emitBrowserBenchmarkLogLine(
                JSON.stringify({
                    event: 'direct-encrypted-ballot-browser-evaluator-smoke',
                    runtime: browserRuntimeContext(),
                    proofSizeBytes: result.proofAttempt.proofSizeBytes,
                    proofTransport: result.proofAttempt.proofTransport,
                    proofMaskRandomness:
                        result.proofAttempt.proofMaskRandomness,
                    topCount: evaluatorReplay.topCount,
                    wallTimeMs,
                    evaluatorTimingStatus: evaluatorReplay.timingStatus,
                    evaluatorReplayTimeMilliseconds:
                        evaluatorReplay.replayTimeMilliseconds,
                    runtimeMemoryBefore: memory.runtimeBefore,
                    runtimeMemoryAfter: memory.runtimeAfter,
                    wasmLinearMemoryBytesBefore:
                        memory.wasmLinearMemoryBytesBefore,
                    wasmLinearMemoryBytesAfter:
                        memory.wasmLinearMemoryBytesAfter,
                }),
            );
        },
        directBallotBrowserBenchmarkTimeoutMs,
    );
});
