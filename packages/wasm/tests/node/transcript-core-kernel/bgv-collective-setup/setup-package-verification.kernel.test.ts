import { describe, expect, it } from 'vitest';

import { setupRequest } from '../bgv-passive-setup-fixtures.js';

import {
    acceptedActiveStaticSetupTheoremCertificate,
    acceptedCompactVssMaterial,
    acceptedPublicKeyShareMaterial,
    acceptedShapedSetupPackage,
    acceptedVssCoefficientCommitments,
    acceptedVssComplaintSet,
    publicKeyShareSuccinctProofsWithDriftedStatementHashes,
    rebindCollectiveSetupPackageHash,
    sameSecretProofsWithDriftedStatementHashes,
    sameSecretProofsWithGeneratedProofs,
} from './accepted-setup-package-fixtures.js';
import { jsonRecord, type JsonRecord } from './setup-fixture-primitives.js';

import { type PublicKeyShareSet } from '#packages/protocol/src/setup/public-key-share-records';
import { type CollectiveBgvSetupContext } from '#packages/protocol/src/setup/vss-share-verification-records';
import {
    loadTranscriptCoreKernel,
    TranscriptCoreKernelCommandError,
} from '#packages/wasm/src/index';

describe('collective BGV setup kernel commands', () => {
    it('classifies passive setup packages as outside profile', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const passiveSetup = kernel.generateBgvPassiveSetup(setupRequest);

        const result = kernel.verifyCollectiveBgvSetup({
            setupPackage: passiveSetup,
        });

        expect(result).toMatchObject({
            ok: false,
            operation: 'verifyCollectiveBgvSetupPackage',
            setupProfileId: 'CollectiveBgvSetup-v1',
            verifierStatus: 'outsideProfile',
        });
        expect(result.refusedObjects[0]?.reasonCode).toBe(
            'outsideCollectiveBgvSetupProfile',
        );
        expect(result.acceptedSetupHandoff).toBeUndefined();
    });

    it('maps malformed accepted setup command errors to neutral protocol errors', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(() => {
            kernel.verifyCollectiveBgvSetup({
                setupPackage: undefined,
            });
        }).toThrow(TranscriptCoreKernelCommandError);

        let thrownError: unknown;
        try {
            kernel.verifyCollectiveBgvSetup({
                setupPackage: undefined,
            });
            throw new Error('verifyCollectiveBgvSetup should have failed.');
        } catch (error) {
            thrownError = error;
        }
        expect(thrownError).toBeInstanceOf(TranscriptCoreKernelCommandError);
        const commandError = thrownError as TranscriptCoreKernelCommandError;
        expect(commandError.code).toBe('InvalidProtocolObject');
        expect(commandError.message).not.toContain('InvalidFixture');
        expect(commandError.message).toContain('setupPackage is required');
    });

    it('reports accepted-shaped setup as pending before reduced-ring public VSS profile checks', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const profile = kernel.describeCollectiveBgvSetupProfile();
        const setupPackage = await acceptedShapedSetupPackage(kernel, profile);

        const result = kernel.verifyCollectiveBgvSetup({
            setupPackage,
            expectedManifestHash: setupRequest.manifestHash,
            expectedRosterHash: String(
                (setupPackage.setupContext as JsonRecord).rosterHash,
            ),
        });

        expect(result).toMatchObject({
            ok: false,
            verifierStatus: 'pending',
            currentPhase: 'setupPackageVerification',
            missingObjects: [
                'sameSecretProofs',
                'publicKeyShareMaterial',
                'publicKeyShareSuccinctProofs',
                'collectivePublicKey',
                'collectivePublicKeyRoot',
            ],
            refusedObjects: [],
        });
    });

    it('verifies compact VSS public material and bridge evidence before later pending', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const profile = kernel.describeCollectiveBgvSetupProfile();
        const setupPackage = await acceptedShapedSetupPackage(kernel, profile);
        const setupContext =
            setupPackage.setupContext as CollectiveBgvSetupContext;
        const commonRandomness = setupPackage.commonRandomness as JsonRecord;
        const vssCoefficientCommitmentBundle =
            acceptedVssCoefficientCommitments(
                setupContext,
                profile,
                String(commonRandomness.publicMatrixSeedHash),
            );
        setupPackage.sameSecretProofs = sameSecretProofsWithGeneratedProofs(
            kernel,
            profile,
            setupPackage,
            vssCoefficientCommitmentBundle,
        );
        Object.assign(
            setupPackage,
            acceptedCompactVssMaterial({
                kernel,
                profile,
                setupPackage,
                vssCoefficientCommitmentBundle,
            }),
        );
        const activeStaticSetupTheoremCertificate =
            acceptedActiveStaticSetupTheoremCertificate(kernel, setupPackage);
        setupPackage.activeStaticSetupTheoremCertificate =
            activeStaticSetupTheoremCertificate;
        setupPackage.activeStaticSetupTheoremCertificateHash =
            activeStaticSetupTheoremCertificate.activeStaticSetupTheoremCertificateHash;
        rebindCollectiveSetupPackageHash(kernel, setupPackage);

        const result = kernel.verifyCollectiveBgvSetup({
            setupPackage,
            expectedManifestHash: setupRequest.manifestHash,
            expectedRosterHash: String(
                (setupPackage.setupContext as JsonRecord).rosterHash,
            ),
        });

        expect(result).toMatchObject({
            ok: false,
            verifierStatus: 'pending',
            currentPhase: 'setupPackageVerification',
            missingObjects: [
                'publicKeyShareMaterial',
                'publicKeyShareSuccinctProofs',
                'collectivePublicKey',
                'collectivePublicKeyRoot',
            ],
            refusedObjects: [],
        });
        expect(result.acceptedHashes).toEqual([]);

        const bridgeRootDriftPackage = structuredClone(setupPackage);
        const bridgeRootDriftStatementSet = jsonRecord(
            bridgeRootDriftPackage.compactSameSecretBridgeStatementSet,
            'compactSameSecretBridgeStatementSet',
        );
        const bridgeRootDriftRecords =
            bridgeRootDriftStatementSet.statementRecords as readonly unknown[];
        const bridgeRootDriftRecord = jsonRecord(
            bridgeRootDriftRecords[0],
            'compactSameSecretBridgeStatementSet.statementRecords.0',
        );
        bridgeRootDriftRecord.sameSecretProofRoot = '0'.repeat(128);
        rebindCollectiveSetupPackageHash(kernel, bridgeRootDriftPackage);

        const bridgeRootDriftResult = kernel.verifyCollectiveBgvSetup({
            setupPackage: bridgeRootDriftPackage,
            expectedManifestHash: setupRequest.manifestHash,
            expectedRosterHash: String(
                (bridgeRootDriftPackage.setupContext as JsonRecord).rosterHash,
            ),
        });

        expect(bridgeRootDriftResult.verifierStatus).toBe('refused');
        expect(bridgeRootDriftResult.refusedObjects[0]).toMatchObject({
            reasonCode: 'compactSameSecretBridgeMalformed',
        });
        expect(
            String(bridgeRootDriftResult.refusedObjects[0]?.message),
        ).toContain('compact VSS same-secret bridge statement root');
        expect(bridgeRootDriftResult.missingObjects).toEqual([]);
        expect(bridgeRootDriftResult.acceptedSetupHandoff).toBeUndefined();

        const targetConstantDriftPackage = structuredClone(setupPackage);
        const targetConstantDriftStatementSet = jsonRecord(
            targetConstantDriftPackage.compactSameSecretBridgeStatementSet,
            'compactSameSecretBridgeStatementSet',
        );
        const targetConstantDriftRecords =
            targetConstantDriftStatementSet.statementRecords as readonly unknown[];
        const targetConstantDriftRecord = jsonRecord(
            targetConstantDriftRecords[0],
            'compactSameSecretBridgeStatementSet.statementRecords.0',
        );
        const targetConstantCommitments =
            targetConstantDriftRecord.targetConstantCoefficientCommitments as readonly unknown[];
        const targetConstantCommitment = jsonRecord(
            targetConstantCommitments[0],
            'compactSameSecretBridgeStatementSet.statementRecords.0.targetConstantCoefficientCommitments.0',
        );
        targetConstantCommitment.commitment = structuredClone(
            targetConstantCommitment.commitment,
        );
        const targetCommitmentBody = jsonRecord(
            targetConstantCommitment.commitment,
            'targetConstantCoefficientCommitments.0.commitment',
        );
        const targetCommitmentLimbs =
            targetCommitmentBody.commitmentLimbs as readonly unknown[];
        const targetCommitmentLimb = jsonRecord(
            targetCommitmentLimbs[0],
            'targetConstantCoefficientCommitments.0.commitment.commitmentLimbs.0',
        );
        const targetCoordinates = targetCommitmentLimb.coordinates as number[];
        const targetCommitmentModulus = Number(targetCommitmentLimb.modulus);
        targetCoordinates[0] =
            (Number(targetCoordinates[0]) + 1) % targetCommitmentModulus;
        rebindCollectiveSetupPackageHash(kernel, targetConstantDriftPackage);

        const targetConstantDriftResult = kernel.verifyCollectiveBgvSetup({
            setupPackage: targetConstantDriftPackage,
            expectedManifestHash: setupRequest.manifestHash,
            expectedRosterHash: String(
                (targetConstantDriftPackage.setupContext as JsonRecord)
                    .rosterHash,
            ),
        });

        expect(targetConstantDriftResult.verifierStatus).toBe('refused');
        expect(targetConstantDriftResult.refusedObjects[0]).toMatchObject({
            reasonCode: 'compactSameSecretBridgeMalformed',
        });
        expect(
            String(targetConstantDriftResult.refusedObjects[0]?.message),
        ).toContain('target constant commitment body root');
        expect(targetConstantDriftResult.missingObjects).toEqual([]);
        expect(targetConstantDriftResult.acceptedSetupHandoff).toBeUndefined();
    }, 540_000);

    it('refuses protocol-built setup packages with malformed setup context before later pending', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const profile = kernel.describeCollectiveBgvSetupProfile();

        for (const [fieldName, malformedValue] of [
            ['setupEpoch', 'setup-epoch 1'],
            ['ceremonyId', 'ceremony-1\nfork'],
        ] as const) {
            const setupPackage = await acceptedShapedSetupPackage(
                kernel,
                profile,
            );
            const setupContext = setupPackage.setupContext as JsonRecord;
            setupContext[fieldName] = malformedValue;
            delete setupPackage.phaseTranscript;
            rebindCollectiveSetupPackageHash(kernel, setupPackage);

            const result = kernel.verifyCollectiveBgvSetup({
                setupPackage,
                expectedManifestHash: setupRequest.manifestHash,
                expectedRosterHash: String(
                    (setupPackage.setupContext as JsonRecord).rosterHash,
                ),
            });

            expect(result.verifierStatus).toBe('refused');
            expect(result.refusedObjects[0]).toMatchObject({
                reasonCode: 'setupContextTokenMalformed',
                objectPath: `setupPackage.setupContext.${fieldName}`,
            });
            expect(result.missingObjects).toEqual([]);
            expect(result.acceptedSetupHandoff).toBeUndefined();
        }
    });

    it('refuses protocol-built same-secret proofs with statement-hash drift before later pending', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const profile = kernel.describeCollectiveBgvSetupProfile();
        const setupPackage = await acceptedShapedSetupPackage(kernel, profile);
        setupPackage.sameSecretProofs =
            sameSecretProofsWithDriftedStatementHashes(profile, setupPackage);
        const activeStaticSetupTheoremCertificate =
            acceptedActiveStaticSetupTheoremCertificate(kernel, setupPackage);
        setupPackage.activeStaticSetupTheoremCertificate =
            activeStaticSetupTheoremCertificate;
        setupPackage.activeStaticSetupTheoremCertificateHash =
            activeStaticSetupTheoremCertificate.activeStaticSetupTheoremCertificateHash;
        rebindCollectiveSetupPackageHash(kernel, setupPackage);

        const result = kernel.verifyCollectiveBgvSetup({
            setupPackage,
            expectedManifestHash: setupRequest.manifestHash,
            expectedRosterHash: String(
                (setupPackage.setupContext as JsonRecord).rosterHash,
            ),
        });

        expect(result.verifierStatus).toBe('refused');
        expect(result.refusedObjects[0]).toMatchObject({
            reasonCode: 'sameSecretProofVerificationFailed',
        });
        expect(String(result.refusedObjects[0]?.message)).toContain(
            'statementHash must match',
        );
        expect(result.missingObjects).toEqual([]);
        expect(result.acceptedSetupHandoff).toBeUndefined();
    });

    it('refuses protocol-built public-key share succinct proofs with statement-hash drift before later pending', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const profile = kernel.describeCollectiveBgvSetupProfile();
        const setupPackage = await acceptedShapedSetupPackage(kernel, profile);
        const setupContext =
            setupPackage.setupContext as CollectiveBgvSetupContext;
        const commonRandomness = setupPackage.commonRandomness as JsonRecord;
        const vssCoefficientCommitmentBundle =
            acceptedVssCoefficientCommitments(
                setupContext,
                profile,
                String(commonRandomness.publicMatrixSeedHash),
            );
        setupPackage.sameSecretProofs = sameSecretProofsWithGeneratedProofs(
            kernel,
            profile,
            setupPackage,
            vssCoefficientCommitmentBundle,
        );
        setupPackage.publicKeyShareMaterial = acceptedPublicKeyShareMaterial(
            setupContext,
            profile,
            commonRandomness,
            setupPackage.publicKeyShares as PublicKeyShareSet,
        );
        setupPackage.publicKeyShareSuccinctProofs =
            publicKeyShareSuccinctProofsWithDriftedStatementHashes(
                profile,
                setupPackage,
            );
        const activeStaticSetupTheoremCertificate =
            acceptedActiveStaticSetupTheoremCertificate(kernel, setupPackage);
        setupPackage.activeStaticSetupTheoremCertificate =
            activeStaticSetupTheoremCertificate;
        setupPackage.activeStaticSetupTheoremCertificateHash =
            activeStaticSetupTheoremCertificate.activeStaticSetupTheoremCertificateHash;
        rebindCollectiveSetupPackageHash(kernel, setupPackage);

        const result = kernel.verifyCollectiveBgvSetup({
            setupPackage,
            expectedManifestHash: setupRequest.manifestHash,
            expectedRosterHash: String(
                (setupPackage.setupContext as JsonRecord).rosterHash,
            ),
        });

        expect(result.verifierStatus).toBe('refused');
        expect(result.refusedObjects[0]).toMatchObject({
            reasonCode: 'publicKeyShareSuccinctProofVerificationFailed',
        });
        expect(String(result.refusedObjects[0]?.message)).toContain(
            'statementHash must match',
        );
        expect(result.missingObjects).toEqual([]);
        expect(result.acceptedSetupHandoff).toBeUndefined();
    });

    it('aborts accepted-shaped setup on a protocol-built VSS complaint', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const profile = kernel.describeCollectiveBgvSetupProfile();
        const setupPackage = await acceptedShapedSetupPackage(kernel, profile);
        setupPackage.vssComplaints = await acceptedVssComplaintSet(
            setupPackage.setupContext as JsonRecord,
            setupPackage.privateVssEnvelopeCommitments as JsonRecord,
        );
        rebindCollectiveSetupPackageHash(kernel, setupPackage);

        const result = kernel.verifyCollectiveBgvSetup({
            setupPackage,
            expectedManifestHash: setupRequest.manifestHash,
            expectedRosterHash: String(
                (setupPackage.setupContext as JsonRecord).rosterHash,
            ),
        });

        expect(result).toMatchObject({
            ok: false,
            verifierStatus: 'aborted',
            currentPhase: 'vssAcceptanceOrComplaint',
        });
        expect(result.refusedObjects[0]?.reasonCode).toBe(
            'vssComplaintAcceptedAbort',
        );
        expect(result.acceptedHashes).toEqual([]);
    });
});
