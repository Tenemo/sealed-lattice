import { describe, expect, it } from 'vitest';
import { server } from 'vitest/browser';

import {
    createDirectBallotSetupPackage,
    runMeasuredDirectEncryptedBallot,
} from '../node/transcript-core-kernel/direct-encrypted-ballot';

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

describe('direct encrypted ballot in browsers', () => {
    it(
        'verifies one widened direct ballot proof and aggregates through browser WASM',
        async () => {
            const kernel = await loadTranscriptCoreKernel();
            const setupPackage = createDirectBallotSetupPackage(kernel);
            const startedAtMs = performance.now();
            const { result, memory } = await runMeasuredDirectEncryptedBallot({
                setupPackage,
            });
            const wallTimeMs = performance.now() - startedAtMs;

            expect(result.operation).toBe('runDirectEncryptedBallot');
            expect(result.input.ballotCount).toBe(1);
            expect(result.proofAttempt.proofAccounting).toMatchObject({
                challengeBits: 192,
                proofModelAccepted: false,
                weakestRelationEffectiveBitsPerCheck: 16,
                minimumIndependentRepetitionsForTarget: null,
            });
            expect(
                result.proofAttempt.proofAccounting
                    .classicalSoundnessBitsAfterSupportUnionBound,
            ).toBeNull();
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
            expect(
                result.proofAttempt.proofTransport.firstProofChunkHashes,
            ).toHaveLength(18);
            expect(
                result.proofAttempt.proofTransport
                    .firstProofPublicTransportHash,
            ).toHaveLength(128);
            expect(
                result.proofAttempt.proofTransport.firstProofStatementHash,
            ).toHaveLength(128);
            expect(
                result.proofAttempt.proofTransport.proofProfileHash,
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
            expect(result.aggregation.privateCorrectnessCheck).toBe(
                'aggregate score slots matched the plaintext oracle',
            );
            expect(result.aggregation).not.toHaveProperty('aggregateScores');
            expect(result.aggregation).not.toHaveProperty(
                'plaintextOracleScores',
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
});
