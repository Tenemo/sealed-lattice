import { describe, expect, it } from 'vitest';

import { setupRequest } from '../bgv-passive-setup-fixtures.js';

import {
    acceptedActiveStaticSetupTheoremCertificate,
    acceptedPublicKeyShareMaterial,
    acceptedShapedSetupPackage,
    acceptedVssCoefficientCommitments,
    acceptedVssComplaintSet,
    publicKeyShareSuccinctProofsWithDriftedStatementHashes,
    rebindCollectiveSetupPackageHash,
    sameSecretProofsWithDriftedStatementHashes,
    sameSecretProofsWithGeneratedProofs,
} from './accepted-setup-package-fixtures.js';
import { type JsonRecord } from './setup-fixture-primitives.js';

import { type PublicKeyShareSet } from '#packages/protocol/src/setup/public-key-share-records';
import { type CollectiveBgvSetupContext } from '#packages/protocol/src/setup/vss-share-verification-records';
import {
    loadTranscriptCoreKernel,
    TranscriptCoreKernelCommandError,
} from '#packages/wasm/src/index';

describe('collective BGV setup kernel commands', () => {
    it('classifies passive setup packages as outside parameters', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const passiveSetup = kernel.generateBgvPassiveSetup(setupRequest);

        const result = kernel.verifyCollectiveBgvSetup({
            setupPackage: passiveSetup,
        });

        expect(result).toMatchObject({
            ok: false,
            operation: 'verifyCollectiveBgvSetupPackage',
            verifierStatus: 'outsideAcceptedParameters',
        });
        expect(result.refusedObjects[0]?.reasonCode).toBe(
            'outsideCollectiveBgvSetupParameters',
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

    it('reports accepted-shaped setup as pending before reduced-ring public VSS parameters checks', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const parameters = kernel.describeCollectiveBgvSetupParameters();
        const setupPackage = await acceptedShapedSetupPackage(
            kernel,
            parameters,
        );

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

    it('refuses protocol-built setup packages with malformed setup context before later pending', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const parameters = kernel.describeCollectiveBgvSetupParameters();

        for (const [fieldName, malformedValue] of [
            ['setupEpoch', 'setup-epoch 1'],
            ['ceremonyId', 'ceremony-1\nfork'],
        ] as const) {
            const setupPackage = await acceptedShapedSetupPackage(
                kernel,
                parameters,
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
        const parameters = kernel.describeCollectiveBgvSetupParameters();
        const setupPackage = await acceptedShapedSetupPackage(
            kernel,
            parameters,
        );
        setupPackage.sameSecretProofs =
            sameSecretProofsWithDriftedStatementHashes(
                parameters,
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
        const parameters = kernel.describeCollectiveBgvSetupParameters();
        const setupPackage = await acceptedShapedSetupPackage(
            kernel,
            parameters,
        );
        const setupContext =
            setupPackage.setupContext as CollectiveBgvSetupContext;
        const commonRandomness = setupPackage.commonRandomness as JsonRecord;
        const vssCoefficientCommitmentBundle =
            acceptedVssCoefficientCommitments(
                setupContext,
                parameters,
                String(commonRandomness.publicMatrixSeedHash),
            );
        setupPackage.sameSecretProofs = sameSecretProofsWithGeneratedProofs(
            kernel,
            parameters,
            setupPackage,
            vssCoefficientCommitmentBundle,
        );
        setupPackage.publicKeyShareMaterial = acceptedPublicKeyShareMaterial(
            setupContext,
            parameters,
            commonRandomness,
            setupPackage.publicKeyShares as PublicKeyShareSet,
        );
        setupPackage.publicKeyShareSuccinctProofs =
            publicKeyShareSuccinctProofsWithDriftedStatementHashes(
                parameters,
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
        const parameters = kernel.describeCollectiveBgvSetupParameters();
        const setupPackage = await acceptedShapedSetupPackage(
            kernel,
            parameters,
        );
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
