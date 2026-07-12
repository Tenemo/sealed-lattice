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
    acceptedSetupVssCoefficientCommitmentMaterialReference,
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
import type { SetupProofMaterialChunkSource } from '#packages/protocol/src/setup/setup-proof-material-transport';
import {
    type CollectiveBgvSetupContext,
    type ProtocolRootSigner,
} from '#packages/protocol/src/setup/vss-share-verification-records';
import {
    bgvCanonicalStreamFamilies,
    loadFreshTranscriptCoreKernel,
    openBgvCanonicalStreamRuntime,
    type BgvCanonicalStreamFamily,
    type BgvCanonicalStreamRuntime,
    BgvCollectiveSetupParametersDescription,
    type TranscriptCoreKernel,
} from '#packages/wasm/src/index';
import type {
    BgvCollectiveSetupTransportCompanions,
    BgvTransportedSetupProofMaterialSet,
} from '#packages/wasm/src/transcript-core-bridge/kernel-types/bgv';

const acceptedShapedSetupPackageCacheByParametersKey = new Map<
    string,
    Promise<AcceptedShapedSetupPackageFixture>
>();

type CompanionVssShareLinkageProofMaterial = Required<
    Pick<
        BgvCollectiveSetupTransportCompanions,
        'transportedVssShareLinkageProofMaterial'
    >
>['transportedVssShareLinkageProofMaterial'];
type CompanionSameSecretBridgeProofMaterial = Required<
    Pick<
        BgvCollectiveSetupTransportCompanions,
        'transportedSameSecretBridgeProofMaterial'
    >
>['transportedSameSecretBridgeProofMaterial'];

type AcceptedShapedSetupPackageFixture = {
    readonly setupPackage: JsonRecord;
    readonly vssShareLinkageProofMaterial: CompanionVssShareLinkageProofMaterial;
    readonly vssShareLinkageProofMaterialSources: readonly SetupProofMaterialChunkSource[];
    readonly sameSecretBridgeProofMaterial: CompanionSameSecretBridgeProofMaterial;
    readonly sameSecretBridgeProofMaterialSources: readonly SetupProofMaterialChunkSource[];
};

export type AcceptedShapedSetupVerificationCompanions = Required<
    Pick<
        BgvCollectiveSetupTransportCompanions,
        | 'transportedVssShareLinkageProofMaterial'
        | 'transportedSameSecretBridgeProofMaterial'
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
    // Heavy VSS commitments and proofs generate on a throwaway kernel whose linear
    // memory is reclaimed once this build returns and the local reference drops.
    // The caller's singleton kernel handles the light hash derivations, streaming,
    // and verification, so the prover's transient peak never ratchets it. The
    // fixture returned below holds only data, never this kernel or its computers.
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
        sameSecretBridge.sourceCoefficientCommitmentMaterialSet,
    );
    const vssCoefficientCommitmentMaterial =
        acceptedSetupVssCoefficientCommitmentMaterialReference(
            sameSecretBridge.sourceCoefficientCommitmentMaterialSet,
            setupTransportCertificate,
        );
    const setupPackage: JsonRecord = {
        objectType: 'SetupPackage',
        setupContext,
        qShare: setupParameters.qShare,
        phaseTranscript,
        commonRandomness,
        vssCoefficientCommitments:
            sameSecretBridge.sourceCoefficientCommitmentSet,
        vssCoefficientCommitmentMaterial,
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

    return {
        setupPackage,
        vssShareLinkageProofMaterial:
            vssPublicMaterial.transportedVssShareLinkageProofMaterial,
        vssShareLinkageProofMaterialSources:
            vssPublicMaterial.proofMaterialChunkSources,
        sameSecretBridgeProofMaterial:
            sameSecretBridge.transportedSameSecretBridgeProofMaterial,
        sameSecretBridgeProofMaterialSources:
            sameSecretBridge.proofMaterialChunkSources,
    };
}

// Authenticate each canonical binary window directly into the family-specific
// semantic sink before terminal setup verification consumes the references.
const streamTransportedProofMaterialSet = async (
    runtime: BgvCanonicalStreamRuntime,
    materialSet: BgvTransportedSetupProofMaterialSet,
    materialSources: readonly SetupProofMaterialChunkSource[],
    family: BgvCanonicalStreamFamily,
): Promise<void> => {
    const sourcesByRoot = new Map(
        materialSources.map((source) => [source.proofMaterialRoot, source]),
    );
    for (
        let materialIndex = 0;
        materialIndex < materialSet.proofMaterials.length;
        materialIndex += 1
    ) {
        const proofMaterialReference = materialSet.proofMaterials[
            materialIndex
        ] as JsonRecord;
        const proofMaterialRoot = String(
            proofMaterialReference.proofMaterialRoot,
        );
        const source = sourcesByRoot.get(proofMaterialRoot);
        if (source === undefined) {
            throw new Error(
                `transported setup proof material is missing a bounded source for material ${String(materialIndex)}.`,
            );
        }
        const descriptorBytes = proofMaterialReference.descriptorBytes;
        if (
            !ArrayBuffer.isView(descriptorBytes) ||
            Object.prototype.toString.call(descriptorBytes) !==
                '[object Uint8Array]'
        ) {
            throw new TypeError(
                'transported setup proof material requires descriptor bytes.',
            );
        }
        await runtime.readMaterial({
            descriptorBytes: descriptorBytes as Uint8Array,
            family,
            materialRoot: proofMaterialRoot,
            pullChunk: source.pullChunk,
        });
        sourcesByRoot.delete(proofMaterialRoot);
    }
    if (sourcesByRoot.size !== 0) {
        throw new Error(
            'transported setup proof material sources must match references exactly.',
        );
    }
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

// Authenticate fresh proof material on every call. Terminal verification evicts
// the roots it consumes, so each verification stages the cached chunks again.
export async function acceptedShapedSetupVerificationCompanions(
    kernel: TranscriptCoreKernel,
    setupParameters: BgvCollectiveSetupParametersDescription,
): Promise<AcceptedShapedSetupVerificationCompanions> {
    const fixture = await acceptedShapedSetupPackageFixture(
        kernel,
        setupParameters,
    );
    const runtime = openBgvCanonicalStreamRuntime({ kernel });
    await streamTransportedProofMaterialSet(
        runtime,
        fixture.vssShareLinkageProofMaterial,
        fixture.vssShareLinkageProofMaterialSources,
        bgvCanonicalStreamFamilies.vssShareLinkage,
    );
    await streamTransportedProofMaterialSet(
        runtime,
        fixture.sameSecretBridgeProofMaterial,
        fixture.sameSecretBridgeProofMaterialSources,
        bgvCanonicalStreamFamilies.sameSecretBridge,
    );

    return {
        transportedVssShareLinkageProofMaterial:
            fixture.vssShareLinkageProofMaterial,
        transportedSameSecretBridgeProofMaterial:
            fixture.sameSecretBridgeProofMaterial,
    };
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
