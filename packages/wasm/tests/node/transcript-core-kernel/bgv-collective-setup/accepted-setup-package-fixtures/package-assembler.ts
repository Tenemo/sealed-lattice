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
    acceptedSameSecretConsistency,
    acceptedSameSecretProofs,
} from './same-secret.js';
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
    chunklessSetupProofMaterialSetForVerificationInput,
    type VerifiedSetupProofMaterial,
    type VerifiedSetupProofMaterialSet,
} from '#packages/protocol/src/setup/setup-proof-material-transport';
import {
    type CollectiveBgvSetupContext,
    type ProtocolRootSigner,
} from '#packages/protocol/src/setup/vss-share-verification-records';
import type {
    BgvCollectiveSetupParametersDescription,
    TranscriptCoreKernel,
} from '#packages/wasm/src/index';
import type {
    BgvCollectiveSetupTransportCompanions,
    BgvTransportedSetupProofMaterialSet,
} from '#packages/wasm/src/transcript-core-bridge/kernel-types/bgv';

const acceptedShapedSetupPackageCacheByParametersKey = new Map<
    string,
    Promise<AcceptedShapedSetupPackageFixture>
>();
const acceptedShapedSetupVerificationCompanionsCacheByKernel = new WeakMap<
    TranscriptCoreKernel,
    Map<string, Promise<AcceptedShapedSetupVerificationCompanions>>
>();

type AcceptedShapedSetupPackageFixture = {
    readonly setupPackage: JsonRecord;
} & Required<
    Pick<
        BgvCollectiveSetupTransportCompanions,
        | 'transportedVssShareLinkageProofMaterial'
        | 'transportedSameSecretBridgeProofMaterial'
    >
>;

export type AcceptedShapedSetupVerificationCompanions = Required<
    Pick<
        BgvCollectiveSetupTransportCompanions,
        | 'transportedVssShareLinkageProofMaterial'
        | 'transportedSameSecretBridgeProofMaterial'
        | 'verifiedSetupProofMaterials'
    >
>;

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
): Promise<AcceptedShapedSetupPackageFixture> {
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
    const vssPublicMaterial = acceptedVssPublicMaterial(
        kernel,
        setupContext,
        setupParameters,
        publicMatrixSeedHash,
    );
    const sameSecretConsistency = acceptedSameSecretConsistency(
        setupContext,
        setupParameters,
        vssPublicMaterial.coefficientCommitmentSet,
    );
    const sameSecretProofs = acceptedSameSecretProofs(
        kernel,
        setupContext,
        setupParameters,
        publicMatrixSeedHash,
        sameSecretConsistency,
        vssPublicMaterial.coefficientCommitmentSet.coefficientCommitmentRoot,
        vssPublicMaterial.ringDegree,
    );
    const sameSecretBridge = acceptedSameSecretBridge(
        kernel,
        setupContext,
        setupParameters,
        publicMatrixSeedHash,
        vssPublicMaterial,
        sameSecretConsistency,
        sameSecretProofs,
    );
    // The private VSS envelope and share-acceptance material bind the coefficient
    // commitment roots. Present the commitment set through a view that aliases the
    // full-VSS field name to the source record root.
    const coefficientCommitmentView = {
        vssCoefficientCommitmentRoot:
            vssPublicMaterial.coefficientCommitmentSet
                .coefficientCommitmentRoot,
        sourceTrusteeRecords:
            vssPublicMaterial.coefficientCommitmentSet.sourceTrusteeRecords.map(
                (sourceTrusteeRecord) => ({
                    ...sourceTrusteeRecord,
                    sourceTrusteeCommitmentRoot:
                        sourceTrusteeRecord.sourceCoefficientCommitmentRoot,
                }),
            ),
    };
    const privateVssEnvelopeCommitments =
        packageShapePrivateVssEnvelopeCommitments(
            kernel,
            setupParameters,
            setupContext,
            commonRandomness,
            coefficientCommitmentView,
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
        sameSecretConsistency,
    );
    const publicKeyShareProofs = acceptedPublicKeyShareProofs(
        setupContext,
        setupParameters,
        commonRandomness,
        sameSecretConsistency,
        publicKeyShares,
    );
    const evaluatorKeySchedule = acceptedEvaluatorKeySchedule(
        setupContext,
        setupParameters,
        commonRandomness,
        sameSecretConsistency,
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
        sameSecretConsistency,
        sameSecretProofs,
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

    return {
        setupPackage,
        transportedVssShareLinkageProofMaterial:
            vssPublicMaterial.transportedVssShareLinkageProofMaterial,
        transportedSameSecretBridgeProofMaterial:
            sameSecretBridge.transportedSameSecretBridgeProofMaterial,
    };
}

const streamTransportedSetupProofMaterialSet = (
    kernel: TranscriptCoreKernel,
    materialSet: BgvTransportedSetupProofMaterialSet,
    verificationIdPrefix: string,
): readonly VerifiedSetupProofMaterial[] => {
    const proofMaterials = materialSet.proofMaterials;
    if (!Array.isArray(proofMaterials)) {
        throw new TypeError(
            `${verificationIdPrefix} proofMaterials must be an array.`,
        );
    }

    return proofMaterials.map((proofMaterialValue, proofMaterialIndex) => {
        const proofMaterial = proofMaterialValue as JsonRecord;
        const chunks = proofMaterial.chunks;
        if (!Array.isArray(chunks)) {
            throw new TypeError(
                `${verificationIdPrefix} proof material chunks must be an array.`,
            );
        }
        const { chunks: omittedChunks, ...transportReference } = proofMaterial;
        void omittedChunks;
        const proofMaterialRoot = String(proofMaterial.proofMaterialRoot);
        const verificationId = [
            verificationIdPrefix,
            String(proofMaterialIndex),
            proofMaterialRoot.slice(0, 16),
        ].join('-');
        kernel.beginSetupProofMaterialTransportStream({
            verificationId,
            transportedSetupProofMaterial: transportReference,
        });
        for (const chunkValue of chunks) {
            const chunk = chunkValue as JsonRecord;
            kernel.absorbSetupProofMaterialTransportStreamChunk({
                verificationId,
                chunkIndex: Number(chunk.chunkIndex),
                bytesHex: String(chunk.bytesHex),
            });
        }
        const verification = kernel.finishSetupProofMaterialTransportStream({
            verificationId,
        }) as unknown as JsonRecord;
        const verifiedSetupProofMaterial =
            verification.verifiedSetupProofMaterial;
        if (
            typeof verifiedSetupProofMaterial !== 'object' ||
            verifiedSetupProofMaterial === null ||
            Array.isArray(verifiedSetupProofMaterial)
        ) {
            throw new Error(
                `${verificationIdPrefix} stream verification did not return a verified setup proof material handle.`,
            );
        }

        return verifiedSetupProofMaterial as VerifiedSetupProofMaterial;
    });
};

export async function acceptedShapedSetupPackageFixture(
    kernel: TranscriptCoreKernel,
    setupParameters: BgvCollectiveSetupParametersDescription,
): Promise<AcceptedShapedSetupPackageFixture> {
    const cacheKey = acceptedShapedSetupPackageCacheKey(
        kernel,
        setupParameters,
    );
    let acceptedShapedSetupPackagePromise =
        acceptedShapedSetupPackageCacheByParametersKey.get(cacheKey);
    if (acceptedShapedSetupPackagePromise === undefined) {
        acceptedShapedSetupPackagePromise = buildAcceptedShapedSetupPackage(
            kernel,
            setupParameters,
        );
        acceptedShapedSetupPackageCacheByParametersKey.set(
            cacheKey,
            acceptedShapedSetupPackagePromise,
        );
    }

    return acceptedShapedSetupPackagePromise;
}

const buildAcceptedShapedSetupVerificationCompanions = async (
    kernel: TranscriptCoreKernel,
    setupParameters: BgvCollectiveSetupParametersDescription,
): Promise<AcceptedShapedSetupVerificationCompanions> => {
    const fixture = await acceptedShapedSetupPackageFixture(
        kernel,
        setupParameters,
    );
    const verificationIdHashFragment =
        setupParameters.setupParametersHash.slice(0, 16);
    const proofMaterials = [
        ...streamTransportedSetupProofMaterialSet(
            kernel,
            fixture.transportedVssShareLinkageProofMaterial,
            `accepted-setup-vss-share-linkage-${verificationIdHashFragment}`,
        ),
        ...streamTransportedSetupProofMaterialSet(
            kernel,
            fixture.transportedSameSecretBridgeProofMaterial,
            `accepted-setup-same-secret-bridge-${verificationIdHashFragment}`,
        ),
    ];
    const verifiedSetupProofMaterials = {
        objectType: 'VerifiedSetupProofMaterialSet',
        proofMaterials,
    } satisfies VerifiedSetupProofMaterialSet;

    return {
        transportedVssShareLinkageProofMaterial:
            chunklessSetupProofMaterialSetForVerificationInput(
                fixture.transportedVssShareLinkageProofMaterial,
                verifiedSetupProofMaterials,
            ),
        transportedSameSecretBridgeProofMaterial:
            chunklessSetupProofMaterialSetForVerificationInput(
                fixture.transportedSameSecretBridgeProofMaterial,
                verifiedSetupProofMaterials,
            ),
        verifiedSetupProofMaterials,
    };
};

export async function acceptedShapedSetupVerificationCompanions(
    kernel: TranscriptCoreKernel,
    setupParameters: BgvCollectiveSetupParametersDescription,
): Promise<AcceptedShapedSetupVerificationCompanions> {
    const cacheKey = acceptedShapedSetupPackageCacheKey(
        kernel,
        setupParameters,
    );
    let cacheByParametersKey =
        acceptedShapedSetupVerificationCompanionsCacheByKernel.get(kernel);
    if (cacheByParametersKey === undefined) {
        cacheByParametersKey = new Map();
        acceptedShapedSetupVerificationCompanionsCacheByKernel.set(
            kernel,
            cacheByParametersKey,
        );
    }
    let companionsPromise = cacheByParametersKey.get(cacheKey);
    if (companionsPromise === undefined) {
        companionsPromise = buildAcceptedShapedSetupVerificationCompanions(
            kernel,
            setupParameters,
        );
        cacheByParametersKey.set(cacheKey, companionsPromise);
    }

    return companionsPromise;
}

export async function acceptedShapedSetupPackage(
    kernel: TranscriptCoreKernel,
    setupParameters: BgvCollectiveSetupParametersDescription,
): Promise<JsonRecord> {
    const fixture = await acceptedShapedSetupPackageFixture(
        kernel,
        setupParameters,
    );

    return cloneJsonRecord(fixture.setupPackage);
}
