import { describe, expect, it } from 'vitest';

import {
    createDirectBallotInputs,
    createDirectBallotSetupPackage,
    runMeasuredDirectEncryptedBallotPrototype,
} from './transcript-core-kernel/direct-encrypted-ballot-prototype';

import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';
import { requiredRuntimeMemoryBytes } from '#tests/support/ballot-privacy-proof-benchmark-memory';

const directBallotProofBatchBenchmarkTimeoutMs = 60 * 60_000;

const aggregateScores = (
    ballots: ReturnType<typeof createDirectBallotInputs>,
): readonly number[] => {
    const aggregate = Array.from({ length: 20 }, () => 0);
    for (const ballot of ballots) {
        ballot.scores.forEach((score, optionIndex) => {
            aggregate[optionIndex] += score;
        });
    }

    return aggregate;
};

describe('direct encrypted ballot proof batch benchmark', () => {
    it(
        'generates and verifies twenty direct ballot proofs and aggregates them through Node/WASM',
        async () => {
            const kernel = await loadTranscriptCoreKernel();
            const setupPackage = createDirectBallotSetupPackage(kernel);
            const ballots = createDirectBallotInputs(20);
            const startedAtMs = performance.now();
            const { result, memory } =
                await runMeasuredDirectEncryptedBallotPrototype({
                    ballots,
                    setupPackage,
                });
            const wallTimeMs = performance.now() - startedAtMs;
            const externalMemoryDeltaBytes =
                requiredRuntimeMemoryBytes(
                    memory.runtimeAfter,
                    'externalBytes',
                    'runtime external memory after the proof batch',
                ) -
                requiredRuntimeMemoryBytes(
                    memory.runtimeBefore,
                    'externalBytes',
                    'runtime external memory before the proof batch',
                );
            const residentSetDeltaBytes =
                requiredRuntimeMemoryBytes(
                    memory.runtimeAfter,
                    'residentSetBytes',
                    'resident set after the proof batch',
                ) -
                requiredRuntimeMemoryBytes(
                    memory.runtimeBefore,
                    'residentSetBytes',
                    'resident set before the proof batch',
                );
            const wasmLinearMemoryDeltaBytes =
                memory.wasmLinearMemoryBytesAfter -
                memory.wasmLinearMemoryBytesBefore;

            expect(result.operation).toBe('runDirectEncryptedBallotPrototype');
            expect(result.input.ballotCount).toBe(20);
            expect(result.proofAttempt.proofCount).toBe(20);
            expect(result.proofAttempt.proofSizeBytes).toBeGreaterThan(
                10_000_000,
            );
            expect(result.proofAttempt.totalProofBytes).toBe(
                result.proofAttempt.proofSizeBytes * 20,
            );
            expect(
                result.proofAttempt.proofAccounting
                    .estimatedRepeatedTotalProofBytes,
            ).toBe(result.proofAttempt.totalProofBytes);
            expect(result.proofAttempt.proofTransport).toMatchObject({
                encoding: 'binary proof chunks',
                chunkSizeBytes: 1_048_576,
                chunksPerProof: 18,
                chunksForBatch: 356,
                transportedProofSizeBytes: result.proofAttempt.proofSizeBytes,
                transportedProofBytesHash: result.proofAttempt.proofBytesHash,
            });
            expect(
                result.proofAttempt.proofTransport.firstProofChunkMerkleRoot,
            ).toHaveLength(128);
            expect(result.proofAttempt.proofMaskRandomness).toMatchObject({
                source: 'fresh-csprng',
                ballotProofRandomnessCount: 20,
                refreshShareProofRandomnessCount: 0,
                randomnessBytesPerProof: 32,
            });
            expect(
                result.ballotPackages.ballotEncryptionRandomness,
            ).toMatchObject({
                source: 'fresh-csprng',
                ballotEncryptionRandomnessCount: 20,
                randomnessBytesPerBallot: 32,
            });
            expect(externalMemoryDeltaBytes).toBeLessThan(
                result.proofAttempt.totalProofBytes * 2,
            );
            expect(result.aggregation.ballotCount).toBe(20);
            expect(result.aggregation.aggregateScores).toEqual(
                result.aggregation.plaintextOracleScores,
            );
            expect(result.aggregation.aggregateScores).toEqual(
                aggregateScores(ballots),
            );
            expect(result.evaluatorReplay).toBe(
                'Not run in this command. Supply topCount to attempt the packed batched-pair evaluator route over the direct aggregate.',
            );
            console.info(
                JSON.stringify({
                    event: 'direct-encrypted-ballot-node-wasm-proof-batch',
                    ballotCount: result.input.ballotCount,
                    proofSizeBytes: result.proofAttempt.proofSizeBytes,
                    totalProofBytes: result.proofAttempt.totalProofBytes,
                    wallTimeMs,
                    proofTimingStatus: result.proofAttempt.timingStatus,
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
        directBallotProofBatchBenchmarkTimeoutMs,
    );
});
