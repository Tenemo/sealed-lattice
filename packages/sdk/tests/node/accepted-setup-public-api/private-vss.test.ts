import { describe, expect, it } from 'vitest';

import {
    hashFromKernel,
    loadPublicTranscriptCoreKernel,
    privateVssEnvelopeReference,
    publicSetupApi,
    setupContextFromKernel,
    setupIntentSigner,
    trusteeIdentity,
} from './support.js';

describe('accepted setup public package API in Node', () => {
    it('verifies private VSS shares and signs acceptance or complaint from local verification', async () => {
        const kernel = await loadPublicTranscriptCoreKernel();
        const setupContext = setupContextFromKernel(kernel);
        const envelopeReference = privateVssEnvelopeReference(
            kernel,
            setupContext,
        );
        const { keyFixture, signRoot } = setupIntentSigner(
            'accepted-setup-public-api-vss-recipient',
        );

        const malformedVerification =
            await publicSetupApi.verifyPrivateVssShare({
                setupContext,
                publicMatrixSeedHash: hashFromKernel(
                    kernel,
                    'vss-public-matrix-seed',
                ),
                sourceTrusteeCoefficientCommitmentRecord: {
                    objectType: 'VssSourceTrusteeCoefficientCommitments',
                },
                sourceTrusteeCoefficientCommitmentMaterialRecords: [],
                privateEnvelope: {
                    objectType: 'PrivateVssShareEnvelope',
                    objectVersion: 1,
                },
            });
        expect(malformedVerification).toMatchObject({
            ok: false,
            operation: 'verifyPrivateVssShareEnvelope',
            verifierStatus: 'refused',
        });
        expect(JSON.stringify(malformedVerification)).not.toMatch(
            /shareValues|coefficientMessage|randomnessByColumn/u,
        );

        const acceptedLocalVerification = {
            ok: true,
            operation: 'verifyPrivateVssShareEnvelope',
            verifierStatus: 'accepted',
            privateEnvelopeHash: envelopeReference.privateEnvelopeHash,
            localVerificationRoot: envelopeReference.localVerificationRoot,
            limbVerifications: [],
            refusedObjects: [],
        };
        const refusedLocalVerification = {
            ok: false,
            operation: 'verifyPrivateVssShareEnvelope',
            verifierStatus: 'refused',
            privateEnvelopeHash: envelopeReference.privateEnvelopeHash,
            localVerificationRoot: null,
            limbVerifications: [],
            refusedObjects: [
                {
                    reasonCode: 'private-vss-opening-verification-failed',
                    message:
                        'recipient local private VSS opening verification failed',
                    objectPath: 'privateEnvelope.rnsShareOpenings.0',
                },
            ],
        };

        const acceptance = await publicSetupApi.createVssShareAcceptance({
            setupContext,
            privateVssEnvelopeCommitmentRoot:
                envelopeReference.privateEnvelopeCommitmentRoot,
            envelopeReference,
            localVerification: acceptedLocalVerification,
            recoveryEpoch: 0,
            deviceEpoch: 2,
            signingPublicKeyHash: keyFixture.publicKeyHash,
            signRoot,
        });
        expect(acceptance).toMatchObject({
            objectType: 'VssShareAcceptance',
            sourceTrusteeIdentity: 'trustee-1',
            recipientIdentity: trusteeIdentity,
            privateEnvelopeHash: envelopeReference.privateEnvelopeHash,
            localVerificationRoot: envelopeReference.localVerificationRoot,
        });
        expect(String(acceptance.acceptanceRoot)).toHaveLength(128);
        expect(JSON.stringify(acceptance)).not.toMatch(
            /shareValues|coefficientMessage|randomnessByColumn/u,
        );

        await expect(
            publicSetupApi.createVssShareAcceptance({
                setupContext,
                privateVssEnvelopeCommitmentRoot:
                    envelopeReference.privateEnvelopeCommitmentRoot,
                envelopeReference,
                localVerification: refusedLocalVerification,
                recoveryEpoch: 0,
                deviceEpoch: 2,
                signingPublicKeyHash: keyFixture.publicKeyHash,
                signRoot,
            }),
        ).rejects.toThrow(/must be accepted/u);
        await expect(
            publicSetupApi.createVssShareAcceptance({
                setupContext,
                privateVssEnvelopeCommitmentRoot:
                    envelopeReference.privateEnvelopeCommitmentRoot,
                envelopeReference,
                localVerification: {
                    ...acceptedLocalVerification,
                    localVerificationRoot: hashFromKernel(
                        kernel,
                        'stale-local-verification',
                    ),
                },
                recoveryEpoch: 0,
                deviceEpoch: 2,
                signingPublicKeyHash: keyFixture.publicKeyHash,
                signRoot,
            }),
        ).rejects.toThrow(/localVerificationRoot/u);

        const complaint = await publicSetupApi.createVssComplaint({
            setupContext,
            privateVssEnvelopeCommitmentRoot:
                envelopeReference.privateEnvelopeCommitmentRoot,
            envelopeReference,
            localVerification: refusedLocalVerification,
            recoveryEpoch: 0,
            deviceEpoch: 2,
            signingPublicKeyHash: keyFixture.publicKeyHash,
            signRoot,
        });
        expect(complaint).toMatchObject({
            objectType: 'VssShareComplaint',
            sourceTrusteeIdentity: 'trustee-1',
            recipientIdentity: trusteeIdentity,
            privateEnvelopeHash: envelopeReference.privateEnvelopeHash,
            complaintReasonCode: 'private-vss-opening-verification-failed',
        });
        expect(String(complaint.complaintRoot)).toHaveLength(128);
        expect(JSON.stringify(complaint)).not.toMatch(
            /shareValues|coefficientMessage|randomnessByColumn/u,
        );
        await expect(
            publicSetupApi.createVssComplaint({
                setupContext,
                privateVssEnvelopeCommitmentRoot:
                    envelopeReference.privateEnvelopeCommitmentRoot,
                envelopeReference,
                localVerification: acceptedLocalVerification,
                recoveryEpoch: 0,
                deviceEpoch: 2,
                signingPublicKeyHash: keyFixture.publicKeyHash,
                signRoot,
            }),
        ).rejects.toThrow(/must be refused/u);
    });
});
