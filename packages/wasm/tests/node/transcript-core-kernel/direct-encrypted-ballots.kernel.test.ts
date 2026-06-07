import { describe, expect, it } from 'vitest';

import {
    createDirectBallotInputs,
    createDirectBallotSetupPackage,
    runDirectEncryptedBallot,
} from './direct-encrypted-ballot';

import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';
import type { BgvPassiveSetupPackage } from '#packages/wasm/src/transcript-core-bridge/kernel-contracts';

describe('direct encrypted ballot kernel command', () => {
    it('generates and verifies one full direct ballot proof through Node/WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const setupPackage = createDirectBallotSetupPackage(kernel);
        const result = await runDirectEncryptedBallot({
            setupPackage,
        });

        expect(result.operation).toBe('runDirectEncryptedBallot');
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
            'claim soundness is not accepted',
        );
        expect(result.proofAttempt.proofAccounting).toMatchObject({
            proofModelAccepted: false,
            targetClassicalSoundnessBits: 128,
            minimumIndependentRepetitionsForTarget: null,
        });
        expect(result.proofAttempt.proofAccounting.challengeBits).toBe(
            result.proofAttempt.proofAccounting.nominalChallengeBits,
        );
        expect(
            result.proofAttempt.proofAccounting.challengeBits,
        ).toBeGreaterThanOrEqual(128);
        expect(
            result.proofAttempt.proofAccounting
                .weakestRelationEffectiveBitsPerCheck,
        ).toBeGreaterThan(0);
        expect(
            result.proofAttempt.proofAccounting.supportRelationModulusBits,
        ).toBeGreaterThan(0);
        expect(
            result.proofAttempt.proofAccounting
                .estimatedIndependentRepetitionsFromWeakestRelationBeforeUnionLosses,
        ).toBeGreaterThan(0);
        expect(
            result.proofAttempt.proofAccounting.estimatedRepeatedProofSizeBytes,
        ).toBe(result.proofAttempt.proofSizeBytes * 8);
        expect(
            result.proofAttempt.proofAccounting
                .estimatedRepeatedTotalProofBytes,
        ).toBe(result.proofAttempt.totalProofBytes * 8);
        expect(
            result.proofAttempt.proofAccounting
                .classicalSoundnessBitsAfterSupportUnionBound,
        ).toBeNull();
        expect(
            result.proofAttempt.proofAccounting
                .zeroKnowledgeShiftSlackBitsAfterResponseUnionBound,
        ).toBeGreaterThanOrEqual(128);
        expect(result.proofAttempt.proofAccounting.decision).toContain(
            'claim soundness is not accepted',
        );
        expect(
            result.encryptedBallots.ballotEncryptionRandomness,
        ).toMatchObject({
            source: 'fresh-csprng',
            ballotEncryptionRandomnessCount: 1,
            randomnessBytesPerBallot: 32,
        });
        expect(
            result.encryptedBallots.ballotEncryptionRandomness.retention,
        ).toContain('not returned');
        expect(result.proofAttempt.proofTransport).toMatchObject({
            encoding: 'binary proof chunks',
            transportedProofSizeBytes: result.proofAttempt.proofSizeBytes,
            transportedProofBytesHash: result.proofAttempt.proofBytesHash,
        });
        expect(
            result.proofAttempt.proofTransport.chunkSizeBytes,
        ).toBeGreaterThan(0);
        expect(
            result.proofAttempt.proofTransport.chunksPerProof,
        ).toBeGreaterThan(0);
        expect(result.proofAttempt.proofTransport.chunksForBatch).toBe(
            result.proofAttempt.proofTransport.chunksPerProof,
        );
        expect(result.proofAttempt.proofTransport.status).toContain(
            'chunk-hash checked',
        );
        expect(
            result.proofAttempt.proofTransport.firstProofChunkMerkleRoot,
        ).toHaveLength(128);
        expect(
            result.proofAttempt.proofTransport.firstProofChunkHashes,
        ).toHaveLength(result.proofAttempt.proofTransport.chunksPerProof);
        expect(
            result.proofAttempt.proofTransport.firstProofChunkHashes[0],
        ).toHaveLength(128);
        expect(
            result.proofAttempt.proofTransport.firstProofPublicTransportHash,
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
        expect(result.proofAttempt.responseEncoding).toBe(
            'full BGV-degree signed response polynomials plus direct ballot score scalars',
        );
        expect(result.proofAttempt.responsePolynomialDegree).toBeGreaterThan(
            64,
        );
        expect(
            result.proofAttempt.sharedResponsePolynomialCount,
        ).toBeGreaterThan(0);
        expect(result.proofAttempt).not.toHaveProperty('proofRingDegree');
        expect(result.proofAttempt).not.toHaveProperty(
            'sharedShortResponseVectorLength',
        );
        expect(result.proofAttempt).not.toHaveProperty(
            'duplicatedShortResponseVectorLength',
        );
        expect(result.aggregation.ballotCount).toBe(1);
        expect(result.aggregation.aggregateCiphertextRoot).toHaveLength(128);
        expect(
            result.aggregation.aggregateCiphertextCanonicalByteLength,
        ).toBeGreaterThan(0);
        expect(result.aggregation.result).toContain(
            'without publishing aggregate scores',
        );
        expect(result.aggregation.privateCorrectnessCheck).toBe(
            'aggregate score slots matched the plaintext oracle',
        );
        expect(result.aggregation).not.toHaveProperty('aggregateScores');
        expect(result.aggregation).not.toHaveProperty('plaintextOracleScores');
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
            runDirectEncryptedBallot({
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
            runDirectEncryptedBallot({
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
            runDirectEncryptedBallot({
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
            runDirectEncryptedBallot({
                setupPackage,
                setupSeed: 'direct-encrypted-ballot-wrong-setup-seed',
            }),
        ).rejects.toThrow('private setup witness seed commitment');
    });
});
