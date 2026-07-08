import { describe, expect, it } from 'vitest';

import { setupRequest, validHash } from '../bgv-passive-setup-fixtures.js';

import {
    acceptedShapedSetupPackage,
    acceptedShapedSetupVerificationCompanions,
    acceptedVssComplaintSet,
    rebindCollectiveSetupPackageHash,
} from './accepted-setup-package-fixtures.js';
import { type JsonRecord } from './setup-fixture-primitives.js';

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
            isValid: false,
            operation: 'verifyCollectiveBgvSetupPackage',
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
        const parameters = kernel.describeCollectiveBgvSetupParameters({
            participantCount: 3,
        });
        const setupPackage = await acceptedShapedSetupPackage(
            kernel,
            parameters,
        );
        const verificationCompanions =
            await acceptedShapedSetupVerificationCompanions(kernel, parameters);

        const result = kernel.verifyCollectiveBgvSetup({
            setupPackage,
            ...verificationCompanions,
            expectedManifestHash: setupRequest.manifestHash,
            expectedRosterHash: String(
                (setupPackage.setupContext as JsonRecord).rosterHash,
            ),
        });

        expect(result).toMatchObject({
            isValid: false,
            currentPhase: 'setupPackageVerification',
            missingObjects: [
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
        const parameters = kernel.describeCollectiveBgvSetupParameters({
            participantCount: 3,
        });

        for (const [fieldName, malformedValue] of [
            ['setupEpoch', 'setup-epoch 1'],
            ['ceremonyId', 'ceremony-1\nfork'],
        ] as const) {
            // Each verify consumes and evicts its streamed proof-material handles,
            // so this loop streams a fresh companions set for every iteration.
            const verificationCompanions =
                await acceptedShapedSetupVerificationCompanions(
                    kernel,
                    parameters,
                );
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
                ...verificationCompanions,
                expectedManifestHash: setupRequest.manifestHash,
                expectedRosterHash: String(
                    (setupPackage.setupContext as JsonRecord).rosterHash,
                ),
            });

            expect(result.isValid).toBe(false);
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
        const parameters = kernel.describeCollectiveBgvSetupParameters({
            participantCount: 3,
        });
        const setupPackage = await acceptedShapedSetupPackage(
            kernel,
            parameters,
        );
        const verificationCompanions =
            await acceptedShapedSetupVerificationCompanions(kernel, parameters);
        // Drift a same-secret proof statement hash. The same-secret
        // bridge binds the same-secret proof set root, so the recomputed root no
        // longer matches the bound root and the package is refused.
        const sameSecretProofs = setupPackage.sameSecretProofs as JsonRecord;
        const sameSecretProofRecords =
            sameSecretProofs.proofRecords as JsonRecord[];
        const driftedSameSecretProof = sameSecretProofRecords[0];
        if (driftedSameSecretProof === undefined) {
            throw new Error('Expected a same-secret proof record to drift.');
        }
        driftedSameSecretProof.statementHash = validHash('7');
        rebindCollectiveSetupPackageHash(kernel, setupPackage);

        const result = kernel.verifyCollectiveBgvSetup({
            setupPackage,
            ...verificationCompanions,
            expectedManifestHash: setupRequest.manifestHash,
            expectedRosterHash: String(
                (setupPackage.setupContext as JsonRecord).rosterHash,
            ),
        });

        expect(result.isValid).toBe(false);
        expect(result.refusedObjects.length).toBeGreaterThan(0);
        expect(result.acceptedSetupHandoff).toBeUndefined();
    });

    it('aborts accepted-shaped setup on a protocol-built VSS complaint', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const parameters = kernel.describeCollectiveBgvSetupParameters({
            participantCount: 3,
        });
        const setupPackage = await acceptedShapedSetupPackage(
            kernel,
            parameters,
        );
        const verificationCompanions =
            await acceptedShapedSetupVerificationCompanions(kernel, parameters);
        setupPackage.vssComplaints = await acceptedVssComplaintSet(
            setupPackage.setupContext as JsonRecord,
            setupPackage.privateVssEnvelopeCommitments as JsonRecord,
        );
        rebindCollectiveSetupPackageHash(kernel, setupPackage);

        const result = kernel.verifyCollectiveBgvSetup({
            setupPackage,
            ...verificationCompanions,
            expectedManifestHash: setupRequest.manifestHash,
            expectedRosterHash: String(
                (setupPackage.setupContext as JsonRecord).rosterHash,
            ),
        });

        expect(result).toMatchObject({
            isValid: false,
            currentPhase: 'vssAcceptanceOrComplaint',
        });
        expect(result.refusedObjects[0]?.reasonCode).toBe(
            'vssComplaintAcceptedAbort',
        );
    });
});
