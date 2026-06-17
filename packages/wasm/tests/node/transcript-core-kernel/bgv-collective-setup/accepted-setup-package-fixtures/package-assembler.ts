import { setupRequest } from '../../bgv-passive-setup-fixtures.js';
import {
    cloneJsonRecord,
    firstProfileDecryptionThreshold,
    firstProfileParticipantCount,
    privateVssMailboxKeyPairForRosterPosition,
    privateVssMailboxPublicKeyBytesHash,
    type JsonRecord,
} from '../setup-fixture-primitives.js';

import {
    acceptedActiveStaticSetupTheoremCertificate,
    acceptedHeSecurityCertificate,
    acceptedSetupCommitmentSecurityCertificate,
    acceptedSetupProofAccountingCertificate,
    acceptedSetupTransportCertificate,
    rebindCollectiveSetupPackageHash,
} from './certificates.js';
import {
    acceptedCommonRandomness,
    publicPrivateVssEnvelopeCommitmentSet,
} from './common-randomness.js';
import { acceptedEvaluatorKeySchedule } from './evaluator-schedule.js';
import {
    acceptedVssShareAcceptances,
    packageShapePrivateVssEnvelopeCommitments,
} from './private-vss-delivery.js';
import {
    acceptedPublicKeyShareProofs,
    acceptedPublicKeyShares,
} from './public-key-shares.js';
import { acceptedSameSecretConsistency } from './same-secret.js';
import { acceptedVssCoefficientCommitments } from './vss-commitments.js';

import {
    createMlDsaKeyPairFixture,
    createMlDsaSignatureProfileFixture,
    createProtocolSignatureFixture,
} from '#packages/crypto/tests/support/protocol-signature-fixtures';
import {
    createSetupPhaseParticipantObject,
    createSetupPhaseRecord,
} from '#packages/protocol/src/setup/setup-phase-records';
import {
    type CollectiveBgvSetupContext,
    type ProtocolRootSigner,
} from '#packages/protocol/src/setup/vss-share-verification-records';
import type {
    BgvCollectiveSetupProfileDescription,
    TranscriptCoreKernel,
} from '#packages/wasm/src/index';

const acceptedShapedSetupPackageCacheByProfileKey = new Map<
    string,
    Promise<JsonRecord>
>();

function acceptedShapedSetupPackageCacheKey(
    kernel: TranscriptCoreKernel,
    profile: BgvCollectiveSetupProfileDescription,
): string {
    const bgvProfile = kernel.describeBgvRnsProfile();

    return [
        profile.setupProfileId,
        profile.setupProfileHash,
        profile.qShareHash,
        profile.carryAwareVssShareRelationProfileHash,
        profile.commitmentProfileHash,
        bgvProfile.profileHash,
        bgvProfile.backendProfileHash,
    ].join('|');
}

async function buildAcceptedShapedSetupPackage(
    kernel: TranscriptCoreKernel,
    profile: BgvCollectiveSetupProfileDescription,
): Promise<JsonRecord> {
    let previousPhaseRoot: string | null = null;
    const setupContext = {
        ceremonyId: setupRequest.ceremonyId,
        manifestHash: setupRequest.manifestHash,
        rosterHash: setupRequest.rosterHash,
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
    const phaseTranscript: JsonRecord[] = [];
    for (const phase of profile.phaseOrder) {
        const participantPhaseObjects = await Promise.all(
            Array.from({ length: 10 }, async (_unusedSlot, rosterPosition) => {
                const trusteeIdentity = `trustee-${String(rosterPosition)}`;
                const signatureSeedLabel = `${trusteeIdentity}-${phase.phaseId}`;
                const keyFixture =
                    createMlDsaKeyPairFixture(signatureSeedLabel);
                const mailboxKeyPair =
                    privateVssMailboxKeyPairForRosterPosition(rosterPosition);
                const signRoot: ProtocolRootSigner = (signedRoot) =>
                    createProtocolSignatureFixture({
                        profile: createMlDsaSignatureProfileFixture(),
                        publicKeyBytesHex: keyFixture.publicKeyBytesHex,
                        publicKeyHash: keyFixture.publicKeyHash,
                        secretKeyBytesHex: keyFixture.secretKeyBytesHex,
                        signedRoot,
                    });

                return createSetupPhaseParticipantObject({
                    setupContext,
                    phaseId: phase.phaseId,
                    phaseNumber: phase.phaseNumber,
                    trusteeIdentity,
                    rosterPosition,
                    recoveryEpoch: 0,
                    deviceEpoch: 0,
                    signingPublicKeyHash: keyFixture.publicKeyHash,
                    ...(phase.phaseId === 'setupIntent'
                        ? {
                              privateVssMailboxPublicKeyHash:
                                  mailboxKeyPair.publicKeyHash,
                              privateVssMailboxPublicKeyBytesHash:
                                  privateVssMailboxPublicKeyBytesHash(
                                      mailboxKeyPair.publicKeyBytesHex,
                                  ),
                          }
                        : {}),
                    signRoot,
                });
            }),
        );
        const phaseRecord = createSetupPhaseRecord({
            setupContext,
            phaseId: phase.phaseId,
            phaseNumber: phase.phaseNumber,
            previousPhaseRoot,
            participantPhaseObjects,
        });
        phaseTranscript.push(phaseRecord);
        previousPhaseRoot = phaseRecord.phaseRoot;
    }
    const commonRandomness = acceptedCommonRandomness(kernel, profile);
    const vssCoefficientCommitmentBundle = acceptedVssCoefficientCommitments(
        setupContext,
        profile,
        String(commonRandomness.publicMatrixSeedHash),
    );
    const vssCoefficientCommitments =
        vssCoefficientCommitmentBundle.commitmentSet;
    const vssCoefficientCommitmentMaterial =
        vssCoefficientCommitmentBundle.materialSet;
    const thresholdShareCommitments = kernel.deriveThresholdShareCommitments({
        setupContext,
        publicMatrixSeedHash: String(commonRandomness.publicMatrixSeedHash),
        sourceTrusteeCoefficientCommitmentRecords:
            vssCoefficientCommitments.sourceTrusteeRecords.map(
                (sourceTrusteeRecord) => sourceTrusteeRecord as JsonRecord,
            ),
        coefficientCommitments:
            vssCoefficientCommitmentMaterial.coefficientCommitments.map(
                (coefficientCommitment) => coefficientCommitment as JsonRecord,
            ),
    }).thresholdShareCommitments;
    const privateVssEnvelopeCommitments =
        packageShapePrivateVssEnvelopeCommitments(
            kernel,
            profile,
            setupContext,
            commonRandomness,
            vssCoefficientCommitments,
        );
    const publicPrivateVssEnvelopeCommitments =
        publicPrivateVssEnvelopeCommitmentSet(privateVssEnvelopeCommitments);
    const privateVssEnvelopeCommitmentRoot = String(
        privateVssEnvelopeCommitments.privateVssEnvelopeCommitmentRoot,
    );
    const vssShareAcceptances = await acceptedVssShareAcceptances(
        setupContext,
        publicPrivateVssEnvelopeCommitments,
    );
    const sameSecretConsistency = acceptedSameSecretConsistency(
        setupContext,
        profile,
        vssCoefficientCommitments,
    );
    const publicKeyShares = acceptedPublicKeyShares(
        setupContext,
        profile,
        commonRandomness,
        sameSecretConsistency,
    );
    const publicKeyShareProofs = acceptedPublicKeyShareProofs(
        setupContext,
        profile,
        commonRandomness,
        sameSecretConsistency,
        publicKeyShares,
    );
    const evaluatorKeySchedule = acceptedEvaluatorKeySchedule(
        setupContext,
        profile,
        commonRandomness,
        sameSecretConsistency,
        publicKeyShares,
        publicKeyShareProofs,
    );
    const setupCommitmentSecurityCertificate =
        acceptedSetupCommitmentSecurityCertificate(profile);
    const setupProofAccountingCertificate =
        acceptedSetupProofAccountingCertificate(profile);
    const heSecurityCertificate = acceptedHeSecurityCertificate(profile);
    const setupTransportCertificate = acceptedSetupTransportCertificate(
        kernel,
        profile,
        vssCoefficientCommitmentMaterial,
    );
    const setupPackage: JsonRecord = {
        objectType: 'SetupPackage',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupContext,
        qShare: profile.qShare,
        phaseTranscript,
        commonRandomness,
        vssCoefficientCommitments,
        vssCoefficientCommitmentMaterial,
        privateVssEnvelopeCommitments: publicPrivateVssEnvelopeCommitments,
        privateVssEnvelopeCommitmentRoot,
        vssShareAcceptances,
        thresholdShareCommitments,
        sameSecretConsistency,
        publicKeyShares,
        publicKeyShareProofs,
        evaluatorKeySchedule,
        relinearizationKeyShareRounds: {},
        galoisKeyShareBatches: [],
        trusteeEvaluationKeyProofs: {},
        evaluationKeys: {},
        setupCommitmentSecurityCertificate,
        setupCommitmentSecurityCertificateHash:
            setupCommitmentSecurityCertificate.setupCommitmentSecurityCertificateHash,
        setupTransportCertificate,
        setupTransportCertificateHash:
            setupTransportCertificate.setupTransportCertificateHash,
        setupProofAccountingCertificate,
        setupProofAccountingCertificateHash:
            setupProofAccountingCertificate.setupProofAccountingCertificateHash,
        heSecurityCertificate,
        heSecurityCertificateHash:
            heSecurityCertificate.heSecurityCertificateHash,
    };
    const activeStaticSetupTheoremCertificate =
        acceptedActiveStaticSetupTheoremCertificate(kernel, setupPackage);
    setupPackage.activeStaticSetupTheoremCertificate =
        activeStaticSetupTheoremCertificate;
    setupPackage.activeStaticSetupTheoremCertificateHash =
        activeStaticSetupTheoremCertificate.activeStaticSetupTheoremCertificateHash;
    rebindCollectiveSetupPackageHash(kernel, setupPackage);

    return setupPackage;
}

export async function acceptedShapedSetupPackage(
    kernel: TranscriptCoreKernel,
    profile: BgvCollectiveSetupProfileDescription,
): Promise<JsonRecord> {
    const cacheKey = acceptedShapedSetupPackageCacheKey(kernel, profile);
    let acceptedShapedSetupPackagePromise =
        acceptedShapedSetupPackageCacheByProfileKey.get(cacheKey);
    if (acceptedShapedSetupPackagePromise === undefined) {
        acceptedShapedSetupPackagePromise = buildAcceptedShapedSetupPackage(
            kernel,
            profile,
        );
        acceptedShapedSetupPackageCacheByProfileKey.set(
            cacheKey,
            acceptedShapedSetupPackagePromise,
        );
    }

    return cloneJsonRecord(await acceptedShapedSetupPackagePromise);
}
