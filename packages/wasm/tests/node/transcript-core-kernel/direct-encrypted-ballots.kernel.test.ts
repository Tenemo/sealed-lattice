import { describe, expect, it } from 'vitest';

import {
    createDirectBallotInputs,
    createDirectBallotSetupPackage,
    directBallotScores,
    runMeasuredDirectEncryptedBallotPrototype,
} from './direct-encrypted-ballot-prototype';

import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';
import type { BgvPassiveSetupPackage } from '#packages/wasm/src/transcript-core-bridge/kernel-contracts';

describe('direct encrypted ballot prototype kernel command', () => {
    it('generates and verifies one full direct ballot proof through Node/WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const setupPackage = createDirectBallotSetupPackage(kernel);
        const { result, memory } =
            await runMeasuredDirectEncryptedBallotPrototype({
                setupPackage,
            });

        expect(result.operation).toBe('runDirectEncryptedBallotPrototype');
        expect(result.input.ballotCount).toBe(1);
        expect(result.ballotLayout.optionCount).toBe(20);
        expect(result.profile.dataPrimeCount).toBe(17);
        expect(result.proofAttempt).toMatchObject({
            proofCount: 1,
            rnsLimbCount: 17,
        });
        expect(result.proofAttempt.proofGate).toContain('yellow');
        expect(result.proofAttempt).toMatchObject({
            timingStatus: 'not measured on wasm32-unknown-unknown',
        });
        expect(result.proofAttempt.coverage).toContain(
            'all RNS limb encryption equations',
        );
        expect(result.proofAttempt.challengeSoundness).toContain(
            'support-degree union accounting and mask-shift accounting are reported',
        );
        expect(result.proofAttempt.proofAccounting).toMatchObject({
            challengeBits: 192,
            targetClassicalSoundnessBits: 128,
            minimumIndependentRepetitionsForTarget: 1,
        });
        expect(
            result.proofAttempt.proofAccounting.estimatedRepeatedProofSizeBytes,
        ).toBe(result.proofAttempt.proofSizeBytes);
        expect(
            result.proofAttempt.proofAccounting
                .estimatedRepeatedTotalProofBytes,
        ).toBe(result.proofAttempt.totalProofBytes);
        expect(
            result.proofAttempt.proofAccounting
                .classicalSoundnessBitsAfterSupportUnionBound,
        ).toBeGreaterThanOrEqual(128);
        expect(
            result.proofAttempt.proofAccounting
                .zeroKnowledgeShiftSlackBitsAfterResponseUnionBound,
        ).toBeGreaterThanOrEqual(128);
        expect(result.proofAttempt.proofAccounting.decision).toContain(
            'no naive transcript repetition is needed',
        );
        expect(result.ballotPackages.ballotEncryptionRandomness).toMatchObject({
            source: 'fresh-csprng',
            ballotEncryptionRandomnessCount: 1,
            randomnessBytesPerBallot: 32,
        });
        expect(
            result.ballotPackages.ballotEncryptionRandomness.retention,
        ).toContain('not returned');
        expect(result.proofAttempt.proofTransport).toMatchObject({
            encoding: 'binary proof chunks',
            chunkSizeBytes: 1_048_576,
            chunksPerProof: 18,
            chunksForBatch: 18,
            transportedProofSizeBytes: result.proofAttempt.proofSizeBytes,
            transportedProofBytesHash: result.proofAttempt.proofBytesHash,
        });
        expect(result.proofAttempt.proofTransport.status).toContain(
            'reassembled, and verified from the transported bytes',
        );
        expect(
            result.proofAttempt.proofTransport.firstProofChunkMerkleRoot,
        ).toHaveLength(128);
        expect(result.proofAttempt.proofTransport.retention).toContain(
            'verified and then dropped',
        );
        expect(result.proofAttempt.proofMaskRandomness).toMatchObject({
            source: 'fresh-csprng',
            ballotProofRandomnessCount: 1,
            refreshShareProofRandomnessCount: 0,
            randomnessBytesPerProof: 32,
        });
        expect(result.proofAttempt.proofMaskRandomness.retention).toContain(
            'not returned',
        );
        expect(result.proofAttempt.proofSizeBytes).toBeGreaterThan(10_000_000);
        expect(result.proofAttempt.proofSizeBytes).toBeLessThanOrEqual(
            20_000_000,
        );
        expect(result.proofAttempt.verifiedProofSizeBytes).toBe(
            result.proofAttempt.proofSizeBytes,
        );
        expect(result.proofAttempt.totalProofBytes).toBe(
            result.proofAttempt.proofSizeBytes,
        );
        expect(
            result.proofAttempt.sharedShortResponseVectorLength,
        ).toBeLessThan(result.proofAttempt.duplicatedShortResponseVectorLength);
        expect(result.aggregation.ballotCount).toBe(1);
        expect(result.aggregation.aggregateScores).toEqual(
            result.aggregation.plaintextOracleScores,
        );
        expect(result.aggregation.aggregateScores).toEqual(directBallotScores);
        expect(memory.wasmLinearMemoryBytesAfter).toBeGreaterThanOrEqual(
            memory.wasmLinearMemoryBytesBefore,
        );
        expect(memory.runtimeBefore).toBeTypeOf('object');
        expect(memory.runtimeAfter).toBeTypeOf('object');
        expect(result.evaluatorReplay).toBe(
            'Not run in this command. Supply topCount to attempt the packed batched-pair evaluator route over the direct aggregate.',
        );

        expect(setupPackage).toMatchObject({
            setupProfileId:
                'sealed-lattice-bgv-rns-passive-full-roster-setup-v1',
        } satisfies Partial<BgvPassiveSetupPackage>);
    });

    it('rejects duplicate voter identities before proof generation through Node/WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const setupPackage = createDirectBallotSetupPackage(kernel);
        const ballots = createDirectBallotInputs(2).map((ballot) => ({
            ...ballot,
            voterIdentity: 'duplicate-voter',
        }));

        await expect(
            runMeasuredDirectEncryptedBallotPrototype({
                ballots,
                setupPackage,
            }),
        ).rejects.toThrow('duplicate voter identity');
    });

    it('rejects out-of-order voter identities before proof generation through Node/WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const setupPackage = createDirectBallotSetupPackage(kernel);
        const ballots = [...createDirectBallotInputs(2)].reverse();

        await expect(
            runMeasuredDirectEncryptedBallotPrototype({
                ballots,
                setupPackage,
            }),
        ).rejects.toThrow('deterministic voter identity order');
    });

    it('rejects invalid direct ballot scores before proof generation through Node/WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const setupPackage = createDirectBallotSetupPackage(kernel);
        const ballot = createDirectBallotInputs(1)[0];
        if (ballot === undefined) {
            throw new Error('direct ballot test input was not created.');
        }

        await expect(
            runMeasuredDirectEncryptedBallotPrototype({
                ballots: [
                    {
                        ...ballot,
                        scores: ballot.scores.map((score, optionIndex) =>
                            optionIndex === 8 ? 11 : score,
                        ),
                    },
                ],
                setupPackage,
            }),
        ).rejects.toThrow('score at option 8');
    });

    it('rejects a mismatched setup witness seed before proof generation through Node/WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const setupPackage = createDirectBallotSetupPackage(kernel);

        await expect(
            runMeasuredDirectEncryptedBallotPrototype({
                setupPackage,
                setupSeed: 'direct-encrypted-ballot-wrong-setup-seed',
            }),
        ).rejects.toThrow('private setup witness seed commitment');
    });
});
