import { setupRequest } from '../../bgv-passive-setup-fixtures.js';
import {
    bytesToHex,
    cloneJsonRecord,
    collectiveSetupRosterHash,
    hexToBytes,
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
    setupProofTransportChunkSizeBytes,
    type VerifiedSetupProofMaterial,
    type VerifiedSetupProofMaterialSet,
} from '#packages/protocol/src/setup/setup-proof-material-transport';
import {
    type CollectiveBgvSetupContext,
    type ProtocolRootSigner,
} from '#packages/protocol/src/setup/vss-share-verification-records';
import { loadFreshTranscriptCoreKernel } from '#packages/wasm/src/index';
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

// One transported proof-material set held compactly: the chunkless transported
// reference set (small, immutable, reused directly as verification input) paired
// with each material's contiguous proof bytes, decoded once from the transport
// builder's chunked output. The raw chunk hex strings are dropped so the
// parameters-keyed cache retains one Uint8Array per material for the worker
// lifetime instead of roughly twice its size as V8 heap strings. The set type is
// preserved so each material set keeps its specific objectType literal.
type CompactTransportedProofMaterialSet<
    MaterialSet extends BgvTransportedSetupProofMaterialSet =
        BgvTransportedSetupProofMaterialSet,
> = {
    readonly chunklessSet: MaterialSet;
    readonly materialBytes: readonly Uint8Array[];
};

type AcceptedShapedSetupPackageFixture = {
    readonly setupPackage: JsonRecord;
    readonly vssShareLinkageProofMaterial: CompactTransportedProofMaterialSet<CompanionVssShareLinkageProofMaterial>;
    readonly sameSecretBridgeProofMaterial: CompactTransportedProofMaterialSet<CompanionSameSecretBridgeProofMaterial>;
};

export type AcceptedShapedSetupVerificationCompanions = Required<
    Pick<
        BgvCollectiveSetupTransportCompanions,
        | 'transportedVssShareLinkageProofMaterial'
        | 'transportedSameSecretBridgeProofMaterial'
        | 'verifiedSetupProofMaterials'
    >
>;

// A per-process sequence prefix keeps every streamed verificationId unique
// across companions calls, mirroring the SDK's counter in
// setup-verification-input.ts, so a fresh stream never collides with a prior
// call's handle (which the kernel evicts once its verify returns) or with a
// session a mid-stream failure wedged.
let setupProofMaterialFixtureVerificationSequence = 0;

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

// Decode a transport builder's chunked material set into the compact cached
// form: each material's chunk hex is concatenated once into a single Uint8Array,
// and the chunkless transported reference (metadata only) is kept for streaming
// and for the verification input. Every material is streamed and verified, so
// the chunkless reference is always safe to reuse directly as verification input.
const compactTransportedProofMaterialSet = <
    MaterialSet extends BgvTransportedSetupProofMaterialSet,
>(
    materialSet: MaterialSet,
): CompactTransportedProofMaterialSet<MaterialSet> => {
    const proofMaterials = materialSet.proofMaterials;
    if (!Array.isArray(proofMaterials)) {
        throw new TypeError(
            'transported proof material set proofMaterials must be an array.',
        );
    }
    const materialBytes: Uint8Array[] = [];
    const chunklessProofMaterials = proofMaterials.map((proofMaterialValue) => {
        const proofMaterial = proofMaterialValue as JsonRecord;
        const chunks = proofMaterial.chunks;
        if (!Array.isArray(chunks)) {
            throw new TypeError(
                'transported proof material chunks must be an array.',
            );
        }
        const chunkByteArrays = chunks.map((chunkValue) =>
            hexToBytes(String((chunkValue as JsonRecord).bytesHex)),
        );
        const totalByteLength = chunkByteArrays.reduce(
            (runningLength, chunkBytes) =>
                runningLength + chunkBytes.byteLength,
            0,
        );
        const proofBytes = new Uint8Array(totalByteLength);
        let writeOffset = 0;
        for (const chunkBytes of chunkByteArrays) {
            proofBytes.set(chunkBytes, writeOffset);
            writeOffset += chunkBytes.byteLength;
        }
        materialBytes.push(proofBytes);
        const { chunks: omittedChunks, ...chunklessReference } = proofMaterial;
        void omittedChunks;

        return chunklessReference;
    });

    return {
        chunklessSet: {
            ...materialSet,
            proofMaterials: chunklessProofMaterials,
        },
        materialBytes,
    };
};

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
    const vssPublicMaterial = acceptedVssPublicMaterial(
        generationKernel,
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
        generationKernel,
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
        vssShareLinkageProofMaterial: compactTransportedProofMaterialSet(
            vssPublicMaterial.transportedVssShareLinkageProofMaterial,
        ),
        sameSecretBridgeProofMaterial: compactTransportedProofMaterialSet(
            sameSecretBridge.transportedSameSecretBridgeProofMaterial,
        ),
    };
}

// Stream a compact material set fresh through begin/absorb/finish, re-encoding
// each 1 MiB window to hex transiently. Each call mints unique sequence-prefixed
// verificationIds and returns the verified handles; the caller threads those into
// verifiedSetupProofMaterials for one verify, after which the kernel evicts them.
const streamCompactTransportedProofMaterialSet = (
    kernel: TranscriptCoreKernel,
    compactSet: CompactTransportedProofMaterialSet,
    verificationIdPrefix: string,
): readonly VerifiedSetupProofMaterial[] =>
    compactSet.chunklessSet.proofMaterials.map(
        (proofMaterialReference, materialIndex) => {
            const proofBytes = compactSet.materialBytes[materialIndex];
            if (proofBytes === undefined) {
                throw new Error(
                    `${verificationIdPrefix} is missing decoded proof bytes for material ${String(materialIndex)}.`,
                );
            }
            setupProofMaterialFixtureVerificationSequence += 1;
            const proofMaterialRoot = String(
                (proofMaterialReference as JsonRecord).proofMaterialRoot,
            );
            const verificationId = [
                verificationIdPrefix,
                String(setupProofMaterialFixtureVerificationSequence),
                String(materialIndex),
                proofMaterialRoot.slice(0, 16),
            ].join('-');
            kernel.beginSetupProofMaterialTransportStream({
                verificationId,
                transportedSetupProofMaterial: proofMaterialReference,
            });
            let chunkIndex = 0;
            for (
                let chunkStart = 0;
                chunkStart < proofBytes.byteLength;
                chunkStart += setupProofTransportChunkSizeBytes
            ) {
                const chunkEnd = Math.min(
                    chunkStart + setupProofTransportChunkSizeBytes,
                    proofBytes.byteLength,
                );
                kernel.absorbSetupProofMaterialTransportStreamChunk({
                    verificationId,
                    chunkIndex,
                    bytesHex: bytesToHex(
                        proofBytes.subarray(chunkStart, chunkEnd),
                    ),
                });
                chunkIndex += 1;
            }
            const verification = kernel.finishSetupProofMaterialTransportStream(
                {
                    verificationId,
                },
            ) as unknown as JsonRecord;
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
        },
    );

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

// Stream fresh verified proof-material handles on every call. The kernel evicts
// a request's handles once its verify returns, so companions cannot be cached and
// reused across verifies; each verify gets its own freshly streamed set. The
// chunkless transported reference sets are immutable and shared from the cache.
// Cost per call is hashing the roughly 60-90 MB of proof bytes, well under a
// second in a lane with minute-scale test timeouts.
export async function acceptedShapedSetupVerificationCompanions(
    kernel: TranscriptCoreKernel,
    setupParameters: BgvCollectiveSetupParametersDescription,
): Promise<AcceptedShapedSetupVerificationCompanions> {
    const fixture = await acceptedShapedSetupPackageFixture(
        kernel,
        setupParameters,
    );
    const verificationIdHashFragment =
        setupParameters.setupParametersHash.slice(0, 16);
    const proofMaterials = [
        ...streamCompactTransportedProofMaterialSet(
            kernel,
            fixture.vssShareLinkageProofMaterial,
            `accepted-setup-vss-share-linkage-${verificationIdHashFragment}`,
        ),
        ...streamCompactTransportedProofMaterialSet(
            kernel,
            fixture.sameSecretBridgeProofMaterial,
            `accepted-setup-same-secret-bridge-${verificationIdHashFragment}`,
        ),
    ];
    const verifiedSetupProofMaterials = {
        objectType: 'VerifiedSetupProofMaterialSet',
        proofMaterials,
    } satisfies VerifiedSetupProofMaterialSet;

    return {
        transportedVssShareLinkageProofMaterial:
            fixture.vssShareLinkageProofMaterial.chunklessSet,
        transportedSameSecretBridgeProofMaterial:
            fixture.sameSecretBridgeProofMaterial.chunklessSet,
        verifiedSetupProofMaterials,
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
