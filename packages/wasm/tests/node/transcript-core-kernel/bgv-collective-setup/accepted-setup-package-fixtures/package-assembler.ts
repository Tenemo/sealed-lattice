import { setupRequest } from '../../bgv-passive-setup-fixtures.js';
import {
    cloneJsonRecord,
    collectiveSetupRosterHash,
    privateVssMailboxKeyPairForRosterPosition,
    privateVssMailboxPublicKeyBytesHash,
    setupTrusteeSignatureSeedLabel,
    type JsonRecord,
} from '../setup-fixture-primitives.js';

import {
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
import {
    acceptedSameSecretBridge,
    acceptedVssPublicMaterial,
} from './vss-material.js';

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
import {
    loadFreshTranscriptCoreKernel,
    BgvCollectiveSetupParametersDescription,
    type TranscriptCoreKernel,
} from '#packages/wasm/src/index';

const acceptedShapedSetupPackageCacheByParametersKey = new Map<
    string,
    Promise<JsonRecord>
>();

function acceptedShapedSetupPackageCacheKey(
    kernel: TranscriptCoreKernel,
    setupParameters: BgvCollectiveSetupParametersDescription,
): string {
    const bgvParameters = kernel.describeBgvRnsParameters();

    return [
        setupParameters.setupParametersHash,
        bgvParameters.bgvParametersHash,
    ].join('|');
}

async function buildAcceptedShapedSetupPackage(
    kernel: TranscriptCoreKernel,
    setupParameters: BgvCollectiveSetupParametersDescription,
): Promise<JsonRecord> {
    let previousPhaseRoot: string | null = null;
    const participantCount = setupParameters.participantCount;
    const setupContext = {
        ceremonyId: setupRequest.ceremonyId,
        manifestHash: setupRequest.manifestHash,
        rosterHash: collectiveSetupRosterHash(
            (input) => kernel.deriveCanonicalObjectHash(input),
            participantCount,
        ),
        setupParametersHash: setupParameters.setupParametersHash,
        setupEpoch: 'setup-epoch-1',
        participantCount,
        qSetupComplete: setupParameters.qSetupComplete,
        qBallotRelease: setupParameters.qBallotRelease,
        qFinal: setupParameters.qFinal,
        qDec: setupParameters.qDec,
    } satisfies CollectiveBgvSetupContext;
    const phaseTranscript: JsonRecord[] = [];
    for (const phase of setupParameters.phaseOrder) {
        const participantPhaseObjects = await Promise.all(
            Array.from(
                { length: participantCount },
                async (_unusedSlot, rosterPosition) => {
                    const trusteeIdentity = `trustee-${String(rosterPosition)}`;
                    const signatureSeedLabel =
                        setupTrusteeSignatureSeedLabel(trusteeIdentity);
                    const keyFixture =
                        createMlDsaKeyPairFixture(signatureSeedLabel);
                    const mailboxKeyPair =
                        privateVssMailboxKeyPairForRosterPosition(
                            rosterPosition,
                        );
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
                },
            ),
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
    const commonRandomness = acceptedCommonRandomness(kernel, setupParameters);
    const publicMatrixSeedHash = String(commonRandomness.publicMatrixSeedHash);
    // Heavy VSS commitments and proofs generate on a throwaway kernel whose
    // linear memory is reclaimed once this build returns and the local reference
    // drops. The separate assembly kernel performs only package derivations. The
    // cached template retains neither kernel nor the generated chunk sources.
    const generationKernel = await loadFreshTranscriptCoreKernel();
    const vssPublicMaterial = await acceptedVssPublicMaterial(
        generationKernel,
        setupContext,
        setupParameters,
        publicMatrixSeedHash,
    );
    const sameSecretBridge = await acceptedSameSecretBridge(
        generationKernel,
        setupContext,
        setupParameters,
        publicMatrixSeedHash,
        vssPublicMaterial,
    );
    const privateVssEnvelopeCommitments =
        packageShapePrivateVssEnvelopeCommitments(
            kernel,
            setupParameters,
            setupContext,
            commonRandomness,
            vssPublicMaterial.coefficientCommitmentSet,
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
    const publicKeyShares = acceptedPublicKeyShares(
        setupContext,
        setupParameters,
        commonRandomness,
    );
    const publicKeyShareProofs = acceptedPublicKeyShareProofs(
        setupContext,
        setupParameters,
        commonRandomness,
        publicKeyShares,
    );
    const evaluatorKeySchedule = acceptedEvaluatorKeySchedule(
        setupContext,
        setupParameters,
        commonRandomness,
        publicKeyShares,
        publicKeyShareProofs,
    );
    const setupTransportCertificate = acceptedSetupTransportCertificate(
        kernel,
        setupParameters,
    );
    const setupPackage: JsonRecord = {
        objectType: 'SetupPackage',
        setupContext,
        qShare: setupParameters.qShare,
        phaseTranscript,
        commonRandomness,
        vssCoefficientCommitments:
            sameSecretBridge.sourceCoefficientCommitmentSet,
        vssPublicCoefficientCommitmentSet:
            vssPublicMaterial.coefficientCommitmentSet,
        vssPublicRecipientShareCommitmentSet:
            vssPublicMaterial.recipientShareCommitmentSet,
        vssPublicAggregateThresholdCommitmentSet:
            vssPublicMaterial.aggregateThresholdCommitmentSet,
        vssShareLinkageStatement: vssPublicMaterial.shareLinkageStatement,
        vssShareLinkageProofMaterialSet:
            vssPublicMaterial.shareLinkageProofMaterialSet,
        privateVssEnvelopeCommitments: publicPrivateVssEnvelopeCommitments,
        privateVssEnvelopeCommitmentRoot,
        vssShareAcceptances,
        thresholdShareCommitments:
            vssPublicMaterial.thresholdShareCommitmentBinding,
        sameSecretBridgeStatementSet: sameSecretBridge.bridgeStatementSet,
        sameSecretBridgeProofMaterialSet:
            sameSecretBridge.bridgeProofMaterialSet,
        publicKeyShares,
        publicKeyShareProofs,
        evaluatorKeySchedule,
        relinearizationKeyShareRounds: {},
        galoisKeyShareBatches: [],
        trusteeEvaluationKeyProofs: {},
        evaluationKeys: {},
        setupTransportCertificate,
        setupTransportCertificateHash:
            setupTransportCertificate.setupTransportCertificateHash,
    };
    rebindCollectiveSetupPackageHash(kernel, setupPackage);

    return setupPackage;
}

async function acceptedShapedSetupPackageTemplate(
    kernel: TranscriptCoreKernel,
    setupParameters: BgvCollectiveSetupParametersDescription,
): Promise<JsonRecord> {
    const cacheKey = acceptedShapedSetupPackageCacheKey(
        kernel,
        setupParameters,
    );
    let acceptedShapedSetupPackagePromise =
        acceptedShapedSetupPackageCacheByParametersKey.get(cacheKey);
    if (acceptedShapedSetupPackagePromise === undefined) {
        acceptedShapedSetupPackagePromise = (async () => {
            const assemblyKernel = await loadFreshTranscriptCoreKernel();

            return buildAcceptedShapedSetupPackage(
                assemblyKernel,
                setupParameters,
            );
        })();
        acceptedShapedSetupPackageCacheByParametersKey.set(
            cacheKey,
            acceptedShapedSetupPackagePromise,
        );
    }

    try {
        return await acceptedShapedSetupPackagePromise;
    } catch (error) {
        if (
            acceptedShapedSetupPackageCacheByParametersKey.get(cacheKey) ===
            acceptedShapedSetupPackagePromise
        ) {
            acceptedShapedSetupPackageCacheByParametersKey.delete(cacheKey);
        }
        throw error;
    }
}

export async function acceptedShapedSetupPackage(
    kernel: TranscriptCoreKernel,
    setupParameters: BgvCollectiveSetupParametersDescription,
): Promise<JsonRecord> {
    const setupPackage = await acceptedShapedSetupPackageTemplate(
        kernel,
        setupParameters,
    );

    return cloneJsonRecord(setupPackage);
}
