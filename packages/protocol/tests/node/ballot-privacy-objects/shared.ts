// Shared ballot privacy object fixtures.
import { deriveProtocolHash } from '@sealed-lattice/crypto';
import type {
    BallotProofComponentId,
    BallotProofComponentProofBundle,
    BallotProofReceiverPayloadReference,
    BallotProofReceiverPublicKeyReference,
    BallotProofShareCommitmentReference,
    BallotProofStatement,
    ProtocolHash,
    ReceiverKeyProofRootEvidence,
    ReceiverPayload,
    ShareCommitment,
} from '@sealed-lattice/types';

import {
    buildBallotProofStatement,
    createBallotPrivacyProfileSet,
    createBallotProofComponentProofBundle,
    createBallotProofComponentProofRecord,
    createReceiverKeyProofRootEvidence,
    createReceiverPayloadShell,
    createShareCommitmentMessageBoundCert,
    createShareCommitmentShell,
    deriveBallotProofComponentProofRoot,
    deriveBallotProofEncodingProfileHash,
    deriveBallotProofParameterSetHash,
    deriveBallotProofPublicRandomnessHash,
    deriveClaimBearingBallotPackageHash,
    deriveProofBytesHash,
    verifyClaimBearingBallotPackage,
    type BallotProofComponentProofVerificationInput,
} from '#packages/protocol/src/ballot-privacy/index';

const hash = (label: string): ProtocolHash =>
    deriveProtocolHash('ActionContextHash', { label });

const defaultParticipantCount = 20;

const createReceiverPublicKeyReferences = (
    participantCount = defaultParticipantCount,
): readonly BallotProofReceiverPublicKeyReference[] =>
    Array.from({ length: participantCount }, (_, participantIndex) => {
        const receiverRosterPosition = participantIndex + 1;

        return {
            receiverIdentity: `receiver-${receiverRosterPosition}`,
            receiverRosterPosition,
            receiverPublicKeyHash: hash(
                `receiver-public-key-${receiverRosterPosition}`,
            ),
        };
    });

const createReceiverPayloadReferences = (
    receiverPublicKeyReferences: ReturnType<
        typeof createReceiverPublicKeyReferences
    >,
): readonly BallotProofReceiverPayloadReference[] =>
    receiverPublicKeyReferences.map((receiverPublicKeyReference) => ({
        receiverIdentity: receiverPublicKeyReference.receiverIdentity,
        receiverRosterPosition:
            receiverPublicKeyReference.receiverRosterPosition,
        receiverPayloadHash: hash(
            `receiver-payload-${receiverPublicKeyReference.receiverRosterPosition}`,
        ),
        receiverPayloadCiphertextRoot: hash(
            `receiver-ciphertext-${receiverPublicKeyReference.receiverRosterPosition}`,
        ),
    }));

const createShareCommitmentReferences = (
    receiverPublicKeyReferences: ReturnType<
        typeof createReceiverPublicKeyReferences
    >,
): readonly BallotProofShareCommitmentReference[] =>
    receiverPublicKeyReferences.map((receiverPublicKeyReference) => ({
        receiverIdentity: receiverPublicKeyReference.receiverIdentity,
        receiverRosterPosition:
            receiverPublicKeyReference.receiverRosterPosition,
        shareCommitmentHash: hash(
            `share-commitment-${receiverPublicKeyReference.receiverRosterPosition}`,
        ),
    }));

type ClaimBearingPackageVerificationInput = Parameters<
    typeof verifyClaimBearingBallotPackage
>[0]['ballotPackage'];

const requiredComponentIds = [
    'score-and-shamir-field-component',
    'payload-plaintext-field-component',
    'share-commitment-component',
    'receiver-encryption-component',
    'receiver-key-binding-component',
] as const satisfies readonly BallotProofComponentId[];

const createStatement = (
    overrides: Partial<BallotProofStatement> = {},
): BallotProofStatement => {
    const profileOptionCount =
        typeof overrides.optionCount === 'number' &&
        overrides.optionCount >= 2 &&
        overrides.optionCount <= 20
            ? overrides.optionCount
            : 20;
    const profileSet = createBallotPrivacyProfileSet({
        optionCount: profileOptionCount,
    });
    const boundCertificate = createShareCommitmentMessageBoundCert({
        maximumCanonicalTurnout: 20,
        shareCommitmentProfile: profileSet.shareCommitmentProfile,
    });
    const receiverPublicKeys = createReceiverPublicKeyReferences();

    return buildBallotProofStatement({
        ceremonyId: 'ceremony-1',
        manifestHash: hash('manifest'),
        rosterHash: hash('roster'),
        pollSpecHash: hash('poll-spec'),
        thresholdProfileHash: hash('threshold-profile'),
        duplicateBallotPolicyHash: hash('duplicate-policy'),
        scoreDomainHash: hash('score-domain'),
        tiePolicyHash: hash('tie-policy'),
        topOptionCount: 3,
        optionCount: 20,
        voterIdentityHash: hash('voter-1'),
        voterRosterPosition: 1,
        voterSigningKeyHash: hash('voter-signing-key'),
        actionContextHash: hash('action-context'),
        rosterExternalAcceptanceHash: hash('external-acceptance'),
        receiverKeyRoot: hash('receiver-key-root'),
        receiverKeyProofRoot: hash('receiver-key-proof-root'),
        receiverPublicKeys,
        receiverPayloads: createReceiverPayloadReferences(receiverPublicKeys),
        shareCommitments: createShareCommitmentReferences(receiverPublicKeys),
        shareCommitmentProfileHash:
            profileSet.shareCommitmentProfile.shareCommitmentProfileHash,
        receiverEncryptionProfileHash:
            profileSet.receiverEncryptionProfile.receiverEncryptionProfileHash,
        ballotProofProfileHash:
            profileSet.ballotProofProfile.ballotProofProfileHash,
        scoreMembershipProfileHash:
            profileSet.scoreMembershipProfile.scoreMembershipProfileHash,
        ballotScoreEncodingProfileHash:
            profileSet.ballotScoreEncodingProfile
                .ballotScoreEncodingProfileHash,
        ballotShareLayoutProfileHash:
            profileSet.ballotShareLayoutProfile.ballotShareLayoutProfileHash,
        aggregateInputEncodingProfileHash:
            profileSet.aggregateInputEncodingProfile
                .aggregateInputEncodingProfileHash,
        encodedShareVectorLayoutHash:
            profileSet.encodedShareVectorLayoutProfile
                .encodedShareVectorLayoutHash,
        encodedAggregateLayoutHash:
            profileSet.encodedAggregateLayoutProfile.encodedAggregateLayoutHash,
        shareCommitmentMessageBoundCertHash:
            boundCertificate.shareCommitmentMessageBoundCertHash,
        ballotPackageHash: hash('ballot-package'),
        ...overrides,
    });
};

function createComponentProofStatementFixture(input: {
    readonly componentId: BallotProofComponentId;
    readonly componentProofStatementHash?: ProtocolHash;
    readonly componentStatementHash: ProtocolHash;
    readonly proofStatementFormat: BallotProofComponentProofVerificationInput['proofStatementFormat'];
}): unknown {
    if (
        input.proofStatementFormat === 'dense-polynomial-matrix-linear-proof-v1'
    ) {
        const statementPayload = {
            componentId: input.componentId,
            componentStatementHash: input.componentStatementHash,
            objectType: 'BallotProofLinearProofStatement',
            objectVersion: 1,
            proofStatementFormat: input.proofStatementFormat,
        };

        return {
            ...statementPayload,
            statementHash: deriveProtocolHash('ChallengeDomainHash', {
                payload: statementPayload,
                purpose: 'ballot-proof-linear-proof-statement-v1',
            }),
        };
    }
    if (
        input.proofStatementFormat ===
        'sparse-polynomial-matrix-linear-proof-v1'
    ) {
        const statementPayload = {
            componentId: input.componentId,
            componentStatementHash: input.componentStatementHash,
            objectType: 'BallotProofSparseComponentLinearProofStatement',
            objectVersion: 1,
            proofStatementFormat: input.proofStatementFormat,
        };

        return {
            ...statementPayload,
            statementHash: deriveProtocolHash('ChallengeDomainHash', {
                payload: statementPayload,
                purpose: 'ballot-proof-sparse-linear-proof-statement-v1',
            }),
        };
    }
    const statementPayload = {
        backendStatementHash: hash(`${input.componentId}-backend`),
        coefficientModulus:
            input.componentId === 'share-commitment-component'
                ? '18446744069414584321'
                : input.componentId === 'score-and-shamir-field-component' ||
                    input.componentId === 'payload-plaintext-field-component'
                  ? '65537'
                  : '12289',
        componentId: input.componentId,
        componentStatementHash: input.componentStatementHash,
        denseCoefficientCount:
            input.proofStatementFormat ===
            'structured-module-lwe-linear-proof-v1'
                ? '1024'
                : null,
        matrixHash: hash(`${input.componentId}-matrix`),
        objectType: 'BallotProofComponentProofStatementDescriptor',
        objectVersion: 1,
        proofBackendRequirement:
            input.proofStatementFormat ===
            'structured-module-lwe-linear-proof-v1'
                ? 'structured-proof-statement-required'
                : input.proofStatementFormat ===
                    'structured-module-sis-share-commitment-v1'
                  ? 'sparse-proof-statement-required'
                  : 'public-binding-check-only',
        proofLoweringStatus: 'explicitRowsAvailable',
        proofStatementFormat: input.proofStatementFormat,
        proofSystemRingDegree:
            input.proofStatementFormat ===
            'structured-module-lwe-linear-proof-v1'
                ? 64
                : null,
        relation: 'A*w + t = 0',
        relationStatementHash: hash(`${input.componentId}-relation`),
        rowBatchMatrixHashes: [hash(`${input.componentId}-row-matrix`)],
        rowBatchNames: [
            input.proofStatementFormat ===
            'structured-module-lwe-linear-proof-v1'
                ? 'receiver_payload_encryption_equation_rows'
                : input.proofStatementFormat ===
                    'structured-module-sis-share-commitment-v1'
                  ? 'share_commitment_equation_rows'
                  : 'receiver_key_binding_rows',
        ],
        rowBatchTargetVectorHashes: [hash(`${input.componentId}-row-target`)],
        rowBatchTermCounts: [
            input.proofStatementFormat ===
                'structured-module-lwe-linear-proof-v1' ||
            input.proofStatementFormat ===
                'structured-module-sis-share-commitment-v1'
                ? '1024'
                : '0',
        ],
        rowCount: 1,
        sparseTermCount: null,
        sourceRingDegree:
            input.proofStatementFormat ===
            'structured-module-lwe-linear-proof-v1'
                ? 256
                : null,
        structuredCiphertextChunkCount:
            input.proofStatementFormat ===
            'structured-module-lwe-linear-proof-v1'
                ? 1
                : null,
        structuredReceiverCount:
            input.proofStatementFormat ===
            'structured-module-lwe-linear-proof-v1'
                ? 1
                : null,
        structuredWitnessTermCount:
            input.proofStatementFormat ===
            'structured-module-lwe-linear-proof-v1'
                ? '1024'
                : null,
        targetVectorHash: hash(`${input.componentId}-target`),
        variableColumnCount:
            input.proofStatementFormat ===
            'structured-module-lwe-linear-proof-v1'
                ? 1
                : 0,
        variableColumnIndices:
            input.proofStatementFormat ===
            'structured-module-lwe-linear-proof-v1'
                ? [0]
                : [],
    };

    return {
        ...statementPayload,
        componentProofStatementHash:
            input.componentProofStatementHash ??
            deriveProtocolHash('ChallengeDomainHash', {
                payload: statementPayload,
                purpose: 'ballot-proof-component-proof-statement-descriptor-v1',
            }),
    };
}

function createComponentProofVerificationInputFixture(
    componentId: BallotProofComponentId,
    statementHash = hash(`${componentId}-statement`),
): BallotProofComponentProofVerificationInput {
    const componentIndex = requiredComponentIds.indexOf(componentId);
    const randomnessByte = (componentIndex + 1).toString(16).padStart(2, '0');
    const proofStatementFormat =
        componentId === 'receiver-encryption-component'
            ? 'structured-module-lwe-linear-proof-v1'
            : componentId === 'share-commitment-component'
              ? 'structured-module-sis-share-commitment-v1'
              : componentId === 'receiver-key-binding-component'
                ? 'public-binding-check-only-v1'
                : componentId === 'score-and-shamir-field-component'
                  ? 'dense-polynomial-matrix-linear-proof-v1'
                  : 'sparse-polynomial-matrix-linear-proof-v1';
    const componentProofStatementHash = hash(`${componentId}-proof-statement`);
    const proofStatement = createComponentProofStatementFixture({
        componentId,
        componentProofStatementHash:
            proofStatementFormat ===
                'structured-module-sis-share-commitment-v1' ||
            proofStatementFormat === 'structured-module-lwe-linear-proof-v1' ||
            proofStatementFormat === 'public-binding-check-only-v1'
                ? undefined
                : componentProofStatementHash,
        componentStatementHash: statementHash,
        proofStatementFormat,
    }) as {
        readonly componentProofStatementHash?: ProtocolHash;
        readonly statementHash?: ProtocolHash;
    };
    const boundComponentProofStatementHash =
        proofStatement.componentProofStatementHash ??
        proofStatement.statementHash ??
        componentProofStatementHash;
    const proofBytesHex =
        proofStatementFormat === 'public-binding-check-only-v1'
            ? ''
            : hash(`${componentId}-proof-bytes-material`);

    return {
        componentId,
        componentProofStatementHash: boundComponentProofStatementHash,
        proofBytesHex,
        proofEncoding: {
            profileId: 'ballot-proof-component-encoding-v1',
            componentId,
        },
        proofParameterSet: {
            profileId: 'ballot-proof-component-parameter-set-v1',
            componentId,
        },
        proofStatement,
        proofStatementFormat,
        publicRandomnessHex: randomnessByte.repeat(32),
        statementHash,
    };
}

const createComponentProofBundleFixture = (
    statement: BallotProofStatement,
    componentIds: readonly BallotProofComponentId[] = requiredComponentIds,
): BallotProofComponentProofBundle => {
    const backendStatementHash = hash('component-backend-statement');
    const relationStatementHash = hash('component-relation-statement');
    const componentProofs = componentIds.map((componentId) => {
        const proofInput = createComponentProofVerificationInputFixture(
            componentId,
            hash(`${componentId}-statement`),
        );
        const proofBytesHash = deriveProofBytesHash({
            allowEmpty:
                proofInput.proofStatementFormat ===
                'public-binding-check-only-v1',
            proofBytesHex: proofInput.proofBytesHex,
        });
        const proofEncodingProfileHash = deriveBallotProofEncodingProfileHash({
            proofEncoding: proofInput.proofEncoding,
        });
        const proofParameterSetHash = deriveBallotProofParameterSetHash({
            parameterSet: proofInput.proofParameterSet,
        });
        const publicRandomnessHash = deriveBallotProofPublicRandomnessHash({
            publicRandomnessHex: proofInput.publicRandomnessHex,
        });

        return createBallotProofComponentProofRecord({
            backendStatementHash,
            ballotProofStatementHash: statement.ballotProofStatementHash,
            componentId,
            componentProofStatementHash: proofInput.componentProofStatementHash,
            componentStatementHash: proofInput.statementHash,
            proofBytesHash,
            proofEncodingProfileHash,
            proofParameterSetHash,
            proofRoot: deriveBallotProofComponentProofRoot({
                componentId,
                componentProofStatementHash:
                    proofInput.componentProofStatementHash,
                componentStatementHash: proofInput.statementHash,
                proofBytesHash,
                proofEncodingProfileHash,
                proofParameterSetHash,
                proofStatementFormat: proofInput.proofStatementFormat,
                publicRandomnessHash,
                statementHash: proofInput.statementHash,
            }),
            proofSizeBytes: proofInput.proofBytesHex.length / 2,
            publicRandomnessHash,
            relationStatementHash,
        });
    });
    const componentBundleStatement = {
        backendStatementHash,
        ballotProofStatementHash: statement.ballotProofStatementHash,
        bundleCoverage: 'full-encoded-score-ballot-relation' as const,
        componentBundleStatementHash: hash('component-bundle-statement'),
        componentStatements: [],
        objectType: 'BallotProofComponentBundleStatement' as const,
        objectVersion: 1 as const,
        relationLabel: 'BallotPrivacyPvssRelation' as const,
        relationStatementHash,
        requiredComponentIds,
    } satisfies Parameters<
        typeof createBallotProofComponentProofBundle
    >[0]['componentBundleStatement'];

    return createBallotProofComponentProofBundle({
        componentBundleStatement,
        componentProofs,
    });
};

const createComponentProofVerificationInputsFixture = (
    componentProofBundle: BallotProofComponentProofBundle,
): readonly BallotProofComponentProofVerificationInput[] =>
    componentProofBundle.componentProofs.map((componentProof) =>
        createComponentProofVerificationInputFixture(
            componentProof.componentId,
            componentProof.componentStatementHash,
        ),
    );

const createStructurallyBoundObjects = (
    input: {
        readonly optionCount?: number;
        readonly participantCount?: number;
    } = {},
): {
    readonly statement: BallotProofStatement;
    readonly receiverKeyProofRootEvidence: ReceiverKeyProofRootEvidence;
    readonly receiverPayloads: readonly ReceiverPayload[];
    readonly shareCommitments: readonly ShareCommitment[];
} => {
    const optionCount = input.optionCount ?? 20;
    const participantCount = input.participantCount ?? defaultParticipantCount;
    const profileSet = createBallotPrivacyProfileSet({ optionCount });
    const boundCertificate = createShareCommitmentMessageBoundCert({
        maximumCanonicalTurnout: Math.max(20, participantCount),
        shareCommitmentProfile: profileSet.shareCommitmentProfile,
    });
    const receiverPublicKeyReferences =
        createReceiverPublicKeyReferences(participantCount);
    const receiverPayloads = receiverPublicKeyReferences.map(
        (receiverPublicKeyReference) =>
            createReceiverPayloadShell({
                ceremonyId: 'ceremony-1',
                ciphertextBodyHash: hash(
                    `ciphertext-body-${receiverPublicKeyReference.receiverRosterPosition}`,
                ),
                manifestHash: hash('manifest'),
                payloadContextHash: hash(
                    `payload-context-${receiverPublicKeyReference.receiverRosterPosition}`,
                ),
                pollSpecHash: hash('poll-spec'),
                receiverEncryptionProfileHash:
                    profileSet.receiverEncryptionProfile
                        .receiverEncryptionProfileHash,
                receiverIdentity: receiverPublicKeyReference.receiverIdentity,
                receiverPublicKeyHash:
                    receiverPublicKeyReference.receiverPublicKeyHash,
                receiverRosterPosition:
                    receiverPublicKeyReference.receiverRosterPosition,
                rosterHash: hash('roster'),
                voterIdentityHash: hash('voter-1'),
            }),
    );
    const shareCommitments = receiverPublicKeyReferences.map(
        (receiverPublicKeyReference) =>
            createShareCommitmentShell({
                ceremonyId: 'ceremony-1',
                commitmentBodyHash: hash(
                    `commitment-body-${receiverPublicKeyReference.receiverRosterPosition}`,
                ),
                manifestHash: hash('manifest'),
                receiverIdentity: receiverPublicKeyReference.receiverIdentity,
                receiverRosterPosition:
                    receiverPublicKeyReference.receiverRosterPosition,
                rosterHash: hash('roster'),
                shareCommitmentProfileHash:
                    profileSet.shareCommitmentProfile
                        .shareCommitmentProfileHash,
                shareVectorWidth:
                    profileSet.shareCommitmentProfile.shareVectorWidth,
            }),
    );
    const receiverKeyProofRootEvidence = createReceiverKeyProofRootEvidence({
        acceptedReceiverKeyProofCount: receiverPublicKeyReferences.length,
        ceremonyId: 'ceremony-1',
        evidenceStatus: 'ReceiverKeyProofRootAccepted',
        manifestHash: hash('manifest'),
        receiverKeyProofRoot: hash('receiver-key-proof-root'),
        receiverKeyRoot: hash('receiver-key-root'),
        receiverPublicKeys: receiverPublicKeyReferences,
        rosterHash: hash('roster'),
    });
    const statementInput = {
        ceremonyId: 'ceremony-1',
        manifestHash: hash('manifest'),
        rosterHash: hash('roster'),
        pollSpecHash: hash('poll-spec'),
        thresholdProfileHash: hash('threshold-profile'),
        duplicateBallotPolicyHash: hash('duplicate-policy'),
        scoreDomainHash: hash('score-domain'),
        tiePolicyHash: hash('tie-policy'),
        topOptionCount: 3,
        optionCount,
        voterIdentityHash: hash('voter-1'),
        voterRosterPosition: 1,
        voterSigningKeyHash: hash('voter-signing-key'),
        actionContextHash: hash('action-context'),
        rosterExternalAcceptanceHash: hash('external-acceptance'),
        receiverKeyRoot: hash('receiver-key-root'),
        receiverKeyProofRoot: hash('receiver-key-proof-root'),
        receiverPublicKeys: receiverPublicKeyReferences,
        receiverPayloads: receiverPayloads.map((receiverPayload) => ({
            receiverIdentity: receiverPayload.receiverIdentity,
            receiverPayloadCiphertextRoot:
                receiverPayload.receiverPayloadCiphertextRoot,
            receiverPayloadHash: receiverPayload.receiverPayloadHash,
            receiverRosterPosition: receiverPayload.receiverRosterPosition,
        })),
        shareCommitments: shareCommitments.map((shareCommitment) => ({
            receiverIdentity: shareCommitment.receiverIdentity,
            receiverRosterPosition: shareCommitment.receiverRosterPosition,
            shareCommitmentHash: shareCommitment.shareCommitmentHash,
        })),
        shareCommitmentProfileHash:
            profileSet.shareCommitmentProfile.shareCommitmentProfileHash,
        receiverEncryptionProfileHash:
            profileSet.receiverEncryptionProfile.receiverEncryptionProfileHash,
        ballotProofProfileHash:
            profileSet.ballotProofProfile.ballotProofProfileHash,
        scoreMembershipProfileHash:
            profileSet.scoreMembershipProfile.scoreMembershipProfileHash,
        ballotScoreEncodingProfileHash:
            profileSet.ballotScoreEncodingProfile
                .ballotScoreEncodingProfileHash,
        ballotShareLayoutProfileHash:
            profileSet.ballotShareLayoutProfile.ballotShareLayoutProfileHash,
        aggregateInputEncodingProfileHash:
            profileSet.aggregateInputEncodingProfile
                .aggregateInputEncodingProfileHash,
        encodedShareVectorLayoutHash:
            profileSet.encodedShareVectorLayoutProfile
                .encodedShareVectorLayoutHash,
        encodedAggregateLayoutHash:
            profileSet.encodedAggregateLayoutProfile.encodedAggregateLayoutHash,
        shareCommitmentMessageBoundCertHash:
            boundCertificate.shareCommitmentMessageBoundCertHash,
    };
    const placeholderStatement = buildBallotProofStatement({
        ...statementInput,
        ballotPackageHash: hash('ballot-package-placeholder'),
    });
    const ballotPackageHash = deriveClaimBearingBallotPackageHash({
        ballotProofStatement: placeholderStatement,
        receiverKeyProofRootEvidence,
        receiverPayloads,
        shareCommitments,
    });
    const statement = buildBallotProofStatement({
        ...statementInput,
        ballotPackageHash,
    });

    return {
        receiverKeyProofRootEvidence,
        receiverPayloads,
        shareCommitments,
        statement,
    };
};

export {
    hash,
    requiredComponentIds,
    createStatement,
    createComponentProofStatementFixture,
    createComponentProofBundleFixture,
    createComponentProofVerificationInputsFixture,
    createStructurallyBoundObjects,
};
export type { ClaimBearingPackageVerificationInput };
