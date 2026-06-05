import { describe, expect, it } from 'vitest';

import {
    createDirectBallotSetupPackage,
    runMeasuredDirectEncryptedBallotPrototype,
} from './transcript-core-kernel/direct-encrypted-ballot-prototype';

import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';
import { requiredRuntimeMemoryBytes } from '#tests/support/ballot-privacy-proof-benchmark-memory';

const directBallotEvaluatorBenchmarkTimeoutMs = 60 * 60_000;

const directBallotBenchmarkTopCount = (): number => {
    const rawTopCount = process.env.SEALED_LATTICE_DIRECT_BALLOT_TOP_COUNT;
    if (rawTopCount === undefined) {
        return 1;
    }
    const topCount = Number.parseInt(rawTopCount, 10);
    if (!Number.isInteger(topCount) || topCount < 1 || topCount > 20) {
        throw new Error(
            'SEALED_LATTICE_DIRECT_BALLOT_TOP_COUNT must be an integer from 1 through 20.',
        );
    }

    return topCount;
};

describe('direct encrypted ballot evaluator benchmark', () => {
    it(
        'replays a prefix target through Node/WASM from the direct aggregate',
        async () => {
            const kernel = await loadTranscriptCoreKernel();
            const setupPackage = createDirectBallotSetupPackage(kernel);
            const topCount = directBallotBenchmarkTopCount();
            const startedAtMs = performance.now();
            const { result, memory } =
                await runMeasuredDirectEncryptedBallotPrototype({
                    setupPackage,
                    topCount,
                });
            const wallTimeMs = performance.now() - startedAtMs;
            const externalMemoryDeltaBytes =
                requiredRuntimeMemoryBytes(
                    memory.runtimeAfter,
                    'externalBytes',
                    'runtime external memory after evaluator replay',
                ) -
                requiredRuntimeMemoryBytes(
                    memory.runtimeBefore,
                    'externalBytes',
                    'runtime external memory before evaluator replay',
                );
            const residentSetDeltaBytes =
                requiredRuntimeMemoryBytes(
                    memory.runtimeAfter,
                    'residentSetBytes',
                    'resident set after evaluator replay',
                ) -
                requiredRuntimeMemoryBytes(
                    memory.runtimeBefore,
                    'residentSetBytes',
                    'resident set before evaluator replay',
                );
            const wasmLinearMemoryDeltaBytes =
                memory.wasmLinearMemoryBytesAfter -
                memory.wasmLinearMemoryBytesBefore;

            expect(result.operation).toBe('runDirectEncryptedBallotPrototype');
            expect(result.input.ballotCount).toBe(1);
            expect(result.proofAttempt.proofSizeBytes).toBeGreaterThan(
                10_000_000,
            );
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
                refreshShareProofRandomnessCount: topCount === 20 ? 0 : 3,
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
            expect(result.evaluatorReplay).not.toBeTypeOf('string');
            const evaluatorReplay = result.evaluatorReplay as Exclude<
                typeof result.evaluatorReplay,
                string
            >;
            expect(evaluatorReplay.topCount).toBe(topCount);
            expect(evaluatorReplay.decodedTargetIds).toEqual(
                evaluatorReplay.plaintextOracleTargetIds,
            );
            expect(evaluatorReplay.decodedTargetOrders).toEqual(
                evaluatorReplay.plaintextOracleTargetOrders,
            );
            const topCountOneSparseTarget = [
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ];
            if (
                topCount === 1 &&
                (JSON.stringify(evaluatorReplay.decodedTargetIds) !==
                    JSON.stringify(topCountOneSparseTarget) ||
                    JSON.stringify(evaluatorReplay.decodedTargetOrders) !==
                        JSON.stringify(topCountOneSparseTarget))
            ) {
                throw new Error(
                    'Top-count-one sparse target did not match the expected first-option result.',
                );
            }
            if (topCount !== 20) {
                if (typeof evaluatorReplay.rankRefresh === 'string') {
                    throw new Error(
                        'Prefix replay must report rank refresh evidence.',
                    );
                }
                const rankRefresh = evaluatorReplay.rankRefresh;
                const refreshShareChunkCount =
                    rankRefresh.thresholdOpening.shareReports.reduce(
                        (total, shareReport) =>
                            total + shareReport.proofChunkCount,
                        0,
                    );
                if (
                    rankRefresh.thresholdOpening.proofTransport.encoding !==
                        'binary proof chunks' ||
                    rankRefresh.thresholdOpening.proofTransport
                        .chunkSizeBytes !== 1_048_576 ||
                    rankRefresh.thresholdOpening.proofTransport
                        .chunksForOpening !== refreshShareChunkCount
                ) {
                    throw new Error(
                        'Refresh-share proofs were not verified through the expected binary chunk transport.',
                    );
                }
                const firstShareReport =
                    rankRefresh.thresholdOpening.shareReports[0];
                if (
                    firstShareReport === undefined ||
                    firstShareReport.proofTransportedBytesHash !==
                        firstShareReport.proofBytesHash ||
                    firstShareReport.proofChunkMerkleRoot.length !== 128
                ) {
                    throw new Error(
                        'Refresh-share proof transport metadata did not match the proof hash and chunk root expectations.',
                    );
                }
            }
            console.info(
                JSON.stringify({
                    event: 'direct-encrypted-ballot-node-wasm-evaluator',
                    topCount: evaluatorReplay.topCount,
                    proofSizeBytes: result.proofAttempt.proofSizeBytes,
                    wallTimeMs,
                    evaluatorTimingStatus: evaluatorReplay.timingStatus,
                    evaluatorReplayTimeMilliseconds:
                        evaluatorReplay.replayTimeMilliseconds,
                    proofTransport: result.proofAttempt.proofTransport,
                    proofMaskRandomness:
                        result.proofAttempt.proofMaskRandomness,
                    externalMemoryDeltaBytes,
                    externalMemoryDeltaToProofBytesRatio:
                        externalMemoryDeltaBytes /
                        result.proofAttempt.totalProofBytes,
                    residentSetDeltaBytes,
                    residentSetDeltaToProofBytesRatio:
                        residentSetDeltaBytes /
                        result.proofAttempt.totalProofBytes,
                    wasmLinearMemoryDeltaBytes,
                    wasmLinearMemoryDeltaToProofBytesRatio:
                        wasmLinearMemoryDeltaBytes /
                        result.proofAttempt.totalProofBytes,
                    runtimeMemoryBefore: memory.runtimeBefore,
                    runtimeMemoryAfter: memory.runtimeAfter,
                    wasmLinearMemoryBytesBefore:
                        memory.wasmLinearMemoryBytesBefore,
                    wasmLinearMemoryBytesAfter:
                        memory.wasmLinearMemoryBytesAfter,
                }),
            );
        },
        directBallotEvaluatorBenchmarkTimeoutMs,
    );
});
