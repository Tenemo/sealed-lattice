import { describe, expect, it } from 'vitest';

import {
    createDirectBallotSetupPackage,
    runMeasuredDirectEncryptedBallot,
} from './transcript-core-kernel/direct-encrypted-ballot';

import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';
import { requiredRuntimeMemoryBytes } from '#tests/support/proof-benchmark-memory';

const directBallotEvaluatorBenchmarkTimeoutMs = 60 * 60_000;

const directBallotBenchmarkTopCount = (): number => {
    const rawTopCount = process.env.SEALED_LATTICE_DIRECT_BALLOT_TOP_COUNT;
    if (rawTopCount === undefined) {
        return 20;
    }
    const topCount = Number.parseInt(rawTopCount, 10);
    if (!Number.isSafeInteger(topCount) || topCount < 1 || topCount > 20) {
        throw new Error(
            'SEALED_LATTICE_DIRECT_BALLOT_TOP_COUNT must be an integer from 1 through 20.',
        );
    }

    return topCount;
};

describe('direct encrypted ballot evaluator benchmark', () => {
    it(
        'replays the encrypted sparse target through Node/WASM from the direct aggregate',
        async () => {
            const kernel = await loadTranscriptCoreKernel();
            const setupPackage = createDirectBallotSetupPackage(kernel);
            const topCount = directBallotBenchmarkTopCount();
            const startedAtMs = performance.now();
            const { result, memory } = await runMeasuredDirectEncryptedBallot({
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

            expect(result.operation).toBe('runDirectEncryptedBallot');
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
                randomnessBytesPerProof: 32,
            });
            expect(
                result.encryptedBallots.ballotEncryptionRandomness,
            ).toMatchObject({
                source: 'fresh-csprng',
                ballotEncryptionRandomnessCount: 1,
                randomnessBytesPerBallot: 32,
            });
            expect(result.aggregation.aggregateCiphertextRoot).toHaveLength(
                128,
            );
            expect(
                result.aggregation.aggregateCiphertextCanonicalByteLength,
            ).toBeGreaterThan(0);
            expect(result.aggregation).not.toHaveProperty('aggregateScores');
            expect(result.aggregation).not.toHaveProperty(
                'plaintextOracleScores',
            );
            expect(result.evaluatorReplay).not.toBeTypeOf('string');
            const evaluatorReplay = result.evaluatorReplay;
            if (typeof evaluatorReplay === 'string' || Array.isArray(evaluatorReplay)) {
                throw new Error('Expected one evaluator replay result.');
            }
            expect(evaluatorReplay.topCount).toBe(topCount);
            expect(evaluatorReplay.targetProjection).toContain(
                'Encrypted sparse target projection completed',
            );
            expect(evaluatorReplay.targetCiphertextHash).toHaveLength(128);
            expect(evaluatorReplay.targetIdRoot).toHaveLength(128);
            expect(evaluatorReplay.targetOrderRoot).toHaveLength(128);
            expect(evaluatorReplay).not.toHaveProperty('decodedTargetIds');
            expect(evaluatorReplay).not.toHaveProperty('decodedTargetOrders');
            expect(evaluatorReplay).not.toHaveProperty(
                'plaintextOracleTargetIds',
            );
            expect(evaluatorReplay).not.toHaveProperty(
                'plaintextOracleTargetOrders',
            );
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
