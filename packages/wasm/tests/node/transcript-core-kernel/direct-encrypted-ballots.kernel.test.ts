import { describe, expect, it } from 'vitest';

import {
    acceptedDirectBallotPublicMaterialForSetupPublicMaterial,
    createDirectEncryptedBallotPackages,
    createDirectBallotInputs,
    createDirectBallotSetupPackage,
    runDirectEncryptedBallot,
    verifyDirectEncryptedBallotPackage,
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
        expect(result.proofAttempt.proofGate).toContain('red');
        expect(result.proofAttempt).toMatchObject({
            timingStatus: 'not measured on wasm32-unknown-unknown',
        });
        expect(result.proofAttempt.coverage).toContain(
            'projected BGV rows and projected no-wrap carry rows for every RNS limb component',
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
            result.proofAttempt.proofTransport.firstProofChunkManifestRoot,
        ).toHaveLength(128);
        expect(
            result.proofAttempt.proofTransport.firstProofChunkManifest
                .objectType,
        ).toBe('BallotProofChunkManifest');
        expect(
            result.proofAttempt.proofTransport.firstProofChunkManifest
                .statementHash,
        ).toBe(result.proofAttempt.proofTransport.firstProofStatementHash);
        expect(
            result.proofAttempt.proofTransport.firstEncryptedBallotPackageRoot,
        ).toHaveLength(128);
        expect(
            result.proofAttempt.proofTransport.firstEncryptedBallotPackage
                .objectType,
        ).toBe('EncryptedBallotPackage');
        expect(
            result.proofAttempt.proofTransport.firstEncryptedBallotPackage
                .proofChunkRoot,
        ).toBe(result.proofAttempt.proofTransport.firstProofChunkManifestRoot);
        expect(
            result.proofAttempt.proofTransport.firstEncryptedBallotPackage
                .proofStatementHash,
        ).toBe(result.proofAttempt.proofTransport.firstProofStatementHash);
        expect(
            result.proofAttempt.proofTransport.firstProofStatementHash,
        ).toHaveLength(128);
        expect(
            result.proofAttempt.proofTransport.proofProfileHash,
        ).toHaveLength(128);
        expect(
            result.proofAttempt.proofTransport.arithmeticCertificateHash,
        ).toHaveLength(128);
        expect(result.proofAttempt.proofMaskRandomness).toMatchObject({
            source: 'fresh-csprng',
            ballotProofRandomnessCount: 1,
            randomnessBytesPerProof: 32,
        });
        expect(result.proofAttempt.proofMaskRandomness.retention).toContain(
            'not returned',
        );
        expect(result.proofAttempt.proofSizeBytes).toBeGreaterThan(
            result.proofAttempt.proofTransport.chunkSizeBytes * 30,
        );
        expect(result.proofAttempt.proofSizeBytes).toBeLessThanOrEqual(
            result.proofAttempt.proofTransport.chunkSizeBytes * 31,
        );
        expect(result.proofAttempt.proofTransport.chunksPerProof).toBe(31);
        expect(result.proofAttempt.verifiedProofSizeBytes).toBe(
            result.proofAttempt.proofSizeBytes,
        );
        expect(result.proofAttempt.totalProofBytes).toBe(
            result.proofAttempt.proofSizeBytes,
        );
        expect(result.proofAttempt.responseEncoding).toBe(
            'full BGV-degree signed response polynomials, direct ballot score scalars, one-hot scalars, and projected BGV no-wrap carry scalars',
        );
        expect(result.proofAttempt.bgvCommitmentEncoding).toBe(
            'statement-derived projected scalar commitments',
        );
        expect(
            result.proofAttempt.projectedBgvRelationProjectionsPerLimbComponent,
        ).toBe(3);
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

    it('creates public encrypted ballot packages without setup private witness through Node/WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const setupPublicMaterial = createDirectBallotSetupPackage(kernel);
        const { acceptedPublicKeyMaterial, acceptedSetupHandoff } =
            acceptedDirectBallotPublicMaterialForSetupPublicMaterial(
                kernel,
                setupPublicMaterial,
            );
        const result = await createDirectEncryptedBallotPackages({
            acceptedPublicKeyMaterial,
            acceptedSetupHandoff,
        });

        expect(result.operation).toBe('createDirectEncryptedBallotPackages');
        expect(result.input.ballotCount).toBe(1);
        expect(result.encryptedBallotPackages).toHaveLength(1);
        expect(result).not.toHaveProperty('aggregation');
        expect(result).not.toHaveProperty('evaluatorReplay');
        expect(result.packageCreation.witnessBoundary).toContain(
            'does not accept setupPackage',
        );
        expect(result.packageCreation.setupHandoffRoot).toBe(
            acceptedSetupHandoff.acceptedSetupHandoffRoot,
        );
        expect(result.packageCreation.proofBytesRetention).toContain(
            'returned as chunk records',
        );
        expect(
            acceptedSetupHandoff.directBallotEncryptionHandoff
                .directBallotReservedSlotRuleHash,
        ).toBe(acceptedPublicKeyMaterial.directBallotReservedSlotRuleHash);
        expect(
            acceptedSetupHandoff.directBallotEncryptionHandoff
                .directBallotEncoderMatrixRoot,
        ).toBe(acceptedPublicKeyMaterial.directBallotEncoderMatrixRoot);
        expect(
            acceptedSetupHandoff.directBallotEncryptionHandoff
                .witnessPartitionProfileHash,
        ).toHaveLength(128);
        expect(
            acceptedSetupHandoff.directBallotEncryptionHandoff
                .arithmeticCertificateHash,
        ).toBe(acceptedPublicKeyMaterial.arithmeticCertificateHash);
        expect(
            acceptedSetupHandoff.directBallotEncryptionHandoff
                .ballotValidityProofProfileHash,
        ).toBe(acceptedPublicKeyMaterial.ballotValidityProofProfileHash);

        const packageRecord = result.encryptedBallotPackages[0];
        if (packageRecord === undefined) {
            throw new Error('public package result did not return a package.');
        }

        expect(packageRecord.proofChunkManifest.objectType).toBe(
            'BallotProofChunkManifest',
        );
        expect(packageRecord.encryptedBallotPackage.objectType).toBe(
            'EncryptedBallotPackage',
        );
        expect(packageRecord.statementHash).toBe(
            result.proofAttempt.proofTransport.firstProofStatementHash,
        );
        expect(packageRecord.proofBytesHash).toBe(
            result.proofAttempt.proofBytesHash,
        );
        expect(packageRecord.proofChunkManifestRoot).toBe(
            result.proofAttempt.proofTransport.firstProofChunkManifestRoot,
        );
        expect(packageRecord.encryptedBallotPackageRoot).toBe(
            result.proofAttempt.proofTransport.firstEncryptedBallotPackageRoot,
        );
        expect(packageRecord.encryptedBallotPackage.proofChunkRoot).toBe(
            packageRecord.proofChunkManifestRoot,
        );
        expect(packageRecord.encryptedBallotPackage.proofStatementHash).toBe(
            packageRecord.statementHash,
        );
        expect(
            packageRecord.encryptedBallotPackage.batchLayoutBindingHash,
        ).toBe(acceptedPublicKeyMaterial.batchLayoutBindingHash);
        expect(
            packageRecord.encryptedBallotPackage.ballotScoreEncodingProfileHash,
        ).toBe(acceptedPublicKeyMaterial.ballotScoreEncodingProfileHash);
        expect(
            packageRecord.encryptedBallotPackage.encryptedBallotLayoutHash,
        ).toBe(acceptedPublicKeyMaterial.encryptedBallotLayoutHash);
        expect(
            packageRecord.encryptedBallotPackage
                .directBallotReservedSlotRuleHash,
        ).toBe(acceptedPublicKeyMaterial.directBallotReservedSlotRuleHash);
        expect(
            packageRecord.encryptedBallotPackage.directBallotEncoderMatrixRoot,
        ).toBe(acceptedPublicKeyMaterial.directBallotEncoderMatrixRoot);
        expect(
            packageRecord.encryptedBallotPackage.witnessPartitionProfileHash,
        ).toBe(
            acceptedSetupHandoff.directBallotEncryptionHandoff
                .witnessPartitionProfileHash,
        );
        expect(
            packageRecord.encryptedBallotPackage.arithmeticCertificateHash,
        ).toBe(
            acceptedSetupHandoff.directBallotEncryptionHandoff
                .arithmeticCertificateHash,
        );
        expect(packageRecord.encryptedBallotPackage.proofProfileHash).toBe(
            acceptedSetupHandoff.directBallotEncryptionHandoff
                .ballotValidityProofProfileHash,
        );
        expect(packageRecord.encryptedBallotPackage).not.toHaveProperty(
            'proofStatement',
        );
        expect(packageRecord.encryptedBallotPackage.signature).toMatchObject({
            objectType: 'DevelopmentEncryptedBallotPackageSignaturePlaceholder',
            signedObjectRoot: packageRecord.encryptedBallotPackageRoot,
            proofStatementHash: packageRecord.statementHash,
            proofChunkRoot: packageRecord.proofChunkManifestRoot,
        });
        expect(
            result.encryptedBallots.ballotEncryptionRandomness,
        ).toMatchObject({
            source: 'fresh-csprng',
            ballotEncryptionRandomnessCount: 1,
        });
        expect(result.proofAttempt.proofMaskRandomness).toMatchObject({
            source: 'fresh-csprng',
            ballotProofRandomnessCount: 1,
        });
        expect(result.proofAttempt.proofTransport.chunksPerProof).toBe(
            packageRecord.proofChunkManifest.chunkCount,
        );
        expect(packageRecord.proofChunks).toHaveLength(
            packageRecord.proofChunkManifest.chunkCount,
        );
        expect(packageRecord.proofChunks[0]?.bytesHex).toHaveLength(
            packageRecord.proofChunkManifest.chunkSizeBytes * 2,
        );

        const verification = await verifyDirectEncryptedBallotPackage({
            acceptedPublicKeyMaterial,
            acceptedSetupHandoff,
            encryptedBallotPackage: packageRecord.encryptedBallotPackage,
            proofChunks: packageRecord.proofChunks,
        });

        expect(verification.operation).toBe(
            'verifyDirectEncryptedBallotPackage',
        );
        expect(verification.verificationStatus).toContain('setup handoff');
        expect(verification.acceptedSetupHandoffRoot).toBe(
            acceptedSetupHandoff.acceptedSetupHandoffRoot,
        );
        expect(verification.packageRoot).toBe(
            packageRecord.encryptedBallotPackageRoot,
        );
        expect(verification.proofStatementHash).toBe(
            packageRecord.statementHash,
        );
        expect(verification.verifiedStatementHash).toBe(
            packageRecord.statementHash,
        );
        expect(verification.proofBytesHash).toBe(packageRecord.proofBytesHash);
        expect(verification.proofChunkRoot).toBe(
            packageRecord.proofChunkManifestRoot,
        );
        expect(verification.proofChunkCount).toBe(
            packageRecord.proofChunkManifest.chunkCount,
        );
        expect(verification.claimBoundary).toContain('development evidence');
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
