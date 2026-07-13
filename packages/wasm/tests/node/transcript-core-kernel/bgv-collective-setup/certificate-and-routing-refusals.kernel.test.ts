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
    firstRosterDecryptionThreshold,
    firstRosterParticipantCount,
    protocolHashPattern,
    type JsonRecord,
} from './setup-fixture-primitives.js';

import { type CollectiveBgvSetupContext } from '#packages/protocol/src/setup/vss-share-verification-records';
import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';

describe('collective BGV setup kernel commands', () => {
    it('refuses undeclared generic key-switch material', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const parameters = kernel.describeCollectiveBgvSetupParameters({
            participantCount: 3,
        });
        const baseSetupPackage = await acceptedShapedSetupPackage(
            kernel,
            parameters,
        );
        const genericKeySwitchPackage = cloneJsonRecord(baseSetupPackage);
        genericKeySwitchPackage.genericKeySwitchKeys = {
            keyRoot: validHash('8'),
        };
        rebindCollectiveSetupPackageHash(kernel, genericKeySwitchPackage);

        const genericKeySwitchResult = kernel.beginAcceptedSetupSession().verifyCollectiveBgvSetup({
            setupPackage: genericKeySwitchPackage,
        });

        expect(genericKeySwitchResult.isValid).toBe(false);
        expect(genericKeySwitchResult.refusedObjects[0]?.reasonCode).toBe(
            'genericKeySwitchOutsideParameters',
        );
    });

    it('refuses JSON setup transport certificates', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const parameters = kernel.describeCollectiveBgvSetupParameters({
            participantCount: 3,
        });
        const baseSetupPackage = await acceptedShapedSetupPackage(
            kernel,
            parameters,
        );
        const jsonTransportPackage = cloneJsonRecord(baseSetupPackage);
        (
            jsonTransportPackage.setupTransportCertificate as JsonRecord
        ).largeObjectEncoding = 'json';
        rebindCollectiveSetupPackageHash(kernel, jsonTransportPackage);

        const jsonTransportResult = kernel.beginAcceptedSetupSession().verifyCollectiveBgvSetup({
            setupPackage: jsonTransportPackage,
        });

        expect(jsonTransportResult.isValid).toBe(false);
        expect(jsonTransportResult.refusedObjects[0]?.reasonCode).toBe(
            'transportEncodingMismatch',
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
            isValid: false,
        });
        expect(result.refusedObjects[0]?.reasonCode).toBe(
            'setupContextFieldMissing',
        );
    });

    it('builds proof-shaped private VSS envelope references without public ciphertext leakage', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const parameters = kernel.describeCollectiveBgvSetupParameters();
        const setupContext = {
            ceremonyId: setupRequest.ceremonyId,
            manifestHash: setupRequest.manifestHash,
            rosterHash: collectiveSetupRosterHash((input) =>
                kernel.deriveCanonicalObjectHash(input),
            ),
            setupParametersHash: parameters.setupParametersHash,
            setupEpoch: 'setup-epoch-1',
            participantCount: firstRosterParticipantCount,
            qSetupComplete: 10,
            qBallotRelease: 10,
            qFinal: 10,
            qDec: firstRosterDecryptionThreshold,
        } satisfies CollectiveBgvSetupContext;
        const commonRandomness = acceptedCommonRandomness(kernel, parameters);
        const vssCoefficientCommitmentBundle =
            acceptedVssCoefficientCommitments(
                setupContext,
                parameters,
                String(commonRandomness.publicMatrixSeedHash),
            );
        const envelopeReferences =
            await focusedPrivateVssSourceDeliveryReferences(
                kernel,
                parameters,
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
