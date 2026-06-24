import { describe, expect, it } from 'vitest';

import { setupRequest, validHash } from '../bgv-passive-setup-fixtures.js';

import {
    acceptedCommonRandomness,
    acceptedShapedSetupPackage,
    acceptedVssCoefficientCommitments,
    focusedPrivateVssSourceDeliveryReferences,
    publicPrivateVssEnvelopeCommitmentReference,
    rebindCollectiveSetupPackageHash,
} from './accepted-setup-package-fixtures.js';
import {
    cloneJsonRecord,
    collectiveSetupRosterHash,
    firstProfileDecryptionThreshold,
    firstProfileParticipantCount,
    protocolHashPattern,
    type JsonRecord,
} from './setup-fixture-primitives.js';

import { type CollectiveBgvSetupContext } from '#packages/protocol/src/setup/vss-share-verification-records';
import {
    loadTranscriptCoreKernel,
    TranscriptCoreKernelCommandError,
} from '#packages/wasm/src/index';

describe('collective BGV setup kernel commands', () => {
    it('refuses undeclared generic key-switch material', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const profile = kernel.describeCollectiveBgvSetupProfile();
        const baseSetupPackage = await acceptedShapedSetupPackage(
            kernel,
            profile,
        );
        const genericKeySwitchPackage = cloneJsonRecord(baseSetupPackage);
        genericKeySwitchPackage.genericKeySwitchKeys = {
            keyRoot: validHash('8'),
        };
        rebindCollectiveSetupPackageHash(kernel, genericKeySwitchPackage);

        const genericKeySwitchResult = kernel.verifyCollectiveBgvSetup({
            setupPackage: genericKeySwitchPackage,
        });

        expect(genericKeySwitchResult.verifierStatus).toBe('refused');
        expect(genericKeySwitchResult.refusedObjects[0]?.reasonCode).toBe(
            'genericKeySwitchOutsideProfile',
        );
    });

    it('refuses malformed commitment security certificates', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const profile = kernel.describeCollectiveBgvSetupProfile();
        const baseSetupPackage = await acceptedShapedSetupPackage(
            kernel,
            profile,
        );
        const malformedCommitmentCertificatePackage =
            cloneJsonRecord(baseSetupPackage);
        const malformedCommitmentCertificate =
            malformedCommitmentCertificatePackage.setupCommitmentSecurityCertificate as JsonRecord;
        (
            malformedCommitmentCertificate.aggregateOpeningBounds as JsonRecord
        ).thresholdShareOpeningInfinityBound = 11_109;
        rebindCollectiveSetupPackageHash(
            kernel,
            malformedCommitmentCertificatePackage,
        );

        const malformedCommitmentCertificateResult =
            kernel.verifyCollectiveBgvSetup({
                setupPackage: malformedCommitmentCertificatePackage,
            });

        expect(malformedCommitmentCertificateResult.verifierStatus).toBe(
            'refused',
        );
        expect(
            malformedCommitmentCertificateResult.refusedObjects[0]?.reasonCode,
        ).toBe('commitmentSecurityCertificatePayloadMismatch');
    });

    it('refuses JSON setup transport certificates', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const profile = kernel.describeCollectiveBgvSetupProfile();
        const baseSetupPackage = await acceptedShapedSetupPackage(
            kernel,
            profile,
        );
        const jsonTransportPackage = cloneJsonRecord(baseSetupPackage);
        (
            jsonTransportPackage.setupTransportCertificate as JsonRecord
        ).largeObjectEncoding = 'json';
        rebindCollectiveSetupPackageHash(kernel, jsonTransportPackage);

        const jsonTransportResult = kernel.verifyCollectiveBgvSetup({
            setupPackage: jsonTransportPackage,
        });

        expect(jsonTransportResult.verifierStatus).toBe('refused');
        expect(jsonTransportResult.refusedObjects[0]?.reasonCode).toBe(
            'transportEncodingMismatch',
        );
    });

    it('refuses setup transport chunk hash count mismatches', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const profile = kernel.describeCollectiveBgvSetupProfile();
        const baseSetupPackage = await acceptedShapedSetupPackage(
            kernel,
            profile,
        );
        const malformedTransportPackage = cloneJsonRecord(baseSetupPackage);
        const malformedTransportCertificate =
            malformedTransportPackage.setupTransportCertificate as JsonRecord;
        (malformedTransportCertificate.chunkHashes as string[]).pop();
        rebindCollectiveSetupPackageHash(kernel, malformedTransportPackage);

        const malformedTransportResult = kernel.verifyCollectiveBgvSetup({
            setupPackage: malformedTransportPackage,
        });

        expect(malformedTransportResult.verifierStatus).toBe('refused');
        expect(malformedTransportResult.refusedObjects[0]?.reasonCode).toBe(
            'transportChunkHashCountMismatch',
        );
    });

    it('routes private VSS share envelope verification refusals', async () => {
        const kernel = await loadTranscriptCoreKernel();

        const result = kernel.verifyPrivateVssShareEnvelope({
            setupContext: {},
            publicMatrixSeedHash: validHash('1'),
            sourceTrusteeCoefficientCommitmentRecord: {},
            sourceTrusteeCoefficientCommitmentMaterialRecords: [],
            privateEnvelope: {},
        });

        expect(result).toMatchObject({
            ok: false,
            operation: 'verifyPrivateVssShareEnvelope',
            setupProfileId: 'CollectiveBgvSetup-v1',
            verifierStatus: 'refused',
        });
        expect(result.refusedObjects[0]?.reasonCode).toBe(
            'setupContextFieldMissing',
        );
    });

    it('routes threshold share commitment derivation errors', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(() => {
            kernel.deriveThresholdShareCommitments({
                setupContext: {},
                publicMatrixSeedHash: validHash('1'),
                sourceTrusteeCoefficientCommitmentRecords: [],
                coefficientCommitments: [],
            });
        }).toThrow(TranscriptCoreKernelCommandError);
        expect(() => {
            kernel.deriveThresholdShareCommitments({
                setupContext: {},
                publicMatrixSeedHash: validHash('1'),
                sourceTrusteeCoefficientCommitmentRecords: [],
                coefficientCommitments: [],
            });
        }).toThrow(/setupContext\.ceremonyId is required/);
    });

    it('builds proof-shaped private VSS envelope references without public ciphertext leakage', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const profile = kernel.describeCollectiveBgvSetupProfile();
        const setupContext = {
            ceremonyId: setupRequest.ceremonyId,
            manifestHash: setupRequest.manifestHash,
            rosterHash: collectiveSetupRosterHash((input) =>
                kernel.deriveProtocolHash(input),
            ),
            setupProfileHash: profile.setupProfileHash,
            qShareHash: profile.qShareHash,
            carryAwareVssShareRelationProfileHash:
                profile.carryAwareVssShareRelationProfileHash,
            commitmentProfileHash: profile.commitmentProfileHash,
            setupEpoch: 'setup-epoch-1',
            participantCount: firstProfileParticipantCount,
            qSetupComplete: 10,
            qBallotRelease: 10,
            qFinal: 10,
            qDec: firstProfileDecryptionThreshold,
        } satisfies CollectiveBgvSetupContext;
        const commonRandomness = acceptedCommonRandomness(kernel, profile);
        const vssCoefficientCommitmentBundle =
            acceptedVssCoefficientCommitments(
                setupContext,
                profile,
                String(commonRandomness.publicMatrixSeedHash),
            );
        const envelopeReferences =
            await focusedPrivateVssSourceDeliveryReferences(
                kernel,
                profile,
                setupContext,
                commonRandomness,
                vssCoefficientCommitmentBundle.commitmentSet,
                vssCoefficientCommitmentBundle.privateOpeningMaterialBySourceTrustee,
            );
        const envelopeReference = envelopeReferences[0];
        if (envelopeReference === undefined) {
            throw new Error(
                'Missing generated private VSS envelope reference.',
            );
        }
        expect(
            envelopeReference.transportedPrivateVssShareProofMaterial,
        ).toMatchObject({
            objectType: 'SetupTransportedPrivateVssShareProofMaterialSet',
            proofFamily: 'vss-opening-carry',
        });

        const publicEnvelopeReference =
            publicPrivateVssEnvelopeCommitmentReference(envelopeReference);

        expect(publicEnvelopeReference.encryptedEnvelope).toBeUndefined();
        expect(
            publicEnvelopeReference.transportedPrivateVssShareProofMaterial,
        ).toBeUndefined();
        expect(publicEnvelopeReference.openingVerificationStatus).toBe(
            'accepted-local-private-vss-opening',
        );
        expect(String(publicEnvelopeReference.privateEnvelopeHash)).toMatch(
            protocolHashPattern,
        );
        expect(String(publicEnvelopeReference.encryptedEnvelopeHash)).toMatch(
            protocolHashPattern,
        );
        expect(String(publicEnvelopeReference.localVerificationRoot)).toMatch(
            protocolHashPattern,
        );
        expect(
            String(publicEnvelopeReference.privateEnvelopeCommitmentRoot),
        ).toMatch(protocolHashPattern);
    });
});
