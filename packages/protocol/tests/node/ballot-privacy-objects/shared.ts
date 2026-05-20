// Shared ballot privacy object fixtures.
import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import type {
    BallotProofComponentId,
    BallotProofComponentProofBundle,
    BallotProofStatement,
    ProtocolDigest,
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
    deriveBallotProofEncodingProfileDigest,
    deriveBallotProofParameterSetDigest,
    deriveBallotProofPublicRandomnessDigest,
    deriveClaimBearingBallotPackageDigest,
    deriveProofBytesDigest,
    verifyClaimBearingBallotPackage,
    type BallotProofComponentProofVerificationInput,
} from '../../../src/ballot-privacy/index';

const digest = (label: string): ProtocolDigest =>
    deriveProtocolDigest('ActionContextDigest', { label });

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
    const profileSet = createBallotPrivacyProfileSet();
    const boundCertificate = createShareCommitmentMessageBoundCert({
        maximumCanonicalTurnout: 20,
        shareCommitmentProfile: profileSet.shareCommitmentProfile,
    });

    return buildBallotProofStatement({
        ceremonyId: 'ceremony-1',
        manifestDigest: digest('manifest'),
        rosterDigest: digest('roster'),
        pollSpecDigest: digest('poll-spec'),
        thresholdProfileDigest: digest('threshold-profile'),
        duplicateBallotPolicyDigest: digest('duplicate-policy'),
        scoreDomainDigest: digest('score-domain'),
        tiePolicyDigest: digest('tie-policy'),
        topOptionCount: 3,
        optionCount: 20,
        voterIdentityDigest: digest('voter-1'),
        voterRosterPosition: 1,
        voterSigningKeyDigest: digest('voter-signing-key'),
        actionContextDigest: digest('action-context'),
        rosterExternalAcceptanceDigest: digest('external-acceptance'),
        receiverKeyRoot: digest('receiver-key-root'),
        receiverKeyProofRoot: digest('receiver-key-proof-root'),
        receiverPublicKeys: [
            {
                receiverIdentity: 'receiver-1',
                receiverRosterPosition: 1,
                receiverPublicKeyDigest: digest('receiver-public-key-1'),
            },
            {
                receiverIdentity: 'receiver-2',
                receiverRosterPosition: 2,
                receiverPublicKeyDigest: digest('receiver-public-key-2'),
            },
        ],
        receiverPayloads: [
            {
                receiverIdentity: 'receiver-1',
                receiverRosterPosition: 1,
                receiverPayloadDigest: digest('receiver-payload-1'),
                receiverPayloadCiphertextRoot: digest('receiver-ciphertext-1'),
            },
            {
                receiverIdentity: 'receiver-2',
                receiverRosterPosition: 2,
                receiverPayloadDigest: digest('receiver-payload-2'),
                receiverPayloadCiphertextRoot: digest('receiver-ciphertext-2'),
            },
        ],
        shareCommitments: [
            {
                receiverIdentity: 'receiver-1',
                receiverRosterPosition: 1,
                shareCommitmentDigest: digest('share-commitment-1'),
            },
            {
                receiverIdentity: 'receiver-2',
                receiverRosterPosition: 2,
                shareCommitmentDigest: digest('share-commitment-2'),
            },
        ],
        shareCommitmentProfileDigest:
            profileSet.shareCommitmentProfile.shareCommitmentProfileDigest,
        receiverEncryptionProfileDigest:
            profileSet.receiverEncryptionProfile
                .receiverEncryptionProfileDigest,
        ballotProofProfileDigest:
            profileSet.ballotProofProfile.ballotProofProfileDigest,
        scoreMembershipProfileDigest:
            profileSet.scoreMembershipProfile.scoreMembershipProfileDigest,
        ballotScoreEncodingProfileDigest:
            profileSet.ballotScoreEncodingProfile
                .ballotScoreEncodingProfileDigest,
        ballotShareLayoutProfileDigest:
            profileSet.ballotShareLayoutProfile.ballotShareLayoutProfileDigest,
        aggregateInputEncodingProfileDigest:
            profileSet.aggregateInputEncodingProfile
                .aggregateInputEncodingProfileDigest,
        encodedShareVectorLayoutDigest:
            profileSet.encodedShareVectorLayoutProfile
                .encodedShareVectorLayoutDigest,
        encodedAggregateLayoutDigest:
            profileSet.encodedAggregateLayoutProfile
                .encodedAggregateLayoutDigest,
        shareCommitmentMessageBoundCertDigest:
            boundCertificate.shareCommitmentMessageBoundCertDigest,
        ballotPackageDigest: digest('ballot-package'),
        ...overrides,
    });
};

function createComponentProofStatementFixture(input: {
    readonly componentId: BallotProofComponentId;
    readonly componentProofStatementDigest?: ProtocolDigest;
    readonly componentStatementDigest: ProtocolDigest;
    readonly proofStatementFormat: BallotProofComponentProofVerificationInput['proofStatementFormat'];
}): unknown {
    if (
        input.proofStatementFormat === 'dense-polynomial-matrix-linear-proof-v1'
    ) {
        const statementPayload = {
            componentId: input.componentId,
            componentStatementDigest: input.componentStatementDigest,
            objectType: 'BallotProofLinearProofStatement',
            objectVersion: 1,
            proofStatementFormat: input.proofStatementFormat,
        };

        return {
            ...statementPayload,
            statementDigest: deriveProtocolDigest('ChallengeDomainDigest', {
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
            componentStatementDigest: input.componentStatementDigest,
            objectType: 'BallotProofSparseComponentLinearProofStatement',
            objectVersion: 1,
            proofStatementFormat: input.proofStatementFormat,
        };

        return {
            ...statementPayload,
            statementDigest: deriveProtocolDigest('ChallengeDomainDigest', {
                payload: statementPayload,
                purpose: 'ballot-proof-sparse-linear-proof-statement-v1',
            }),
        };
    }
    const statementPayload = {
        backendStatementDigest: digest(`${input.componentId}-backend`),
        coefficientModulus:
            input.componentId === 'share-commitment-component'
                ? '18446744069414584321'
                : input.componentId === 'score-and-shamir-field-component' ||
                    input.componentId === 'payload-plaintext-field-component'
                  ? '65537'
                  : '12289',
        componentId: input.componentId,
        componentStatementDigest: input.componentStatementDigest,
        denseCoefficientCount:
            input.proofStatementFormat ===
            'structured-module-lwe-linear-proof-v1'
                ? '1024'
                : null,
        matrixDigest: digest(`${input.componentId}-matrix`),
        objectType: 'BallotProofComponentProofStatementPlan',
        objectVersion: 1,
        proofBytesAvailability:
            input.proofStatementFormat ===
                'structured-module-lwe-linear-proof-v1' ||
            input.proofStatementFormat ===
                'structured-module-sis-share-commitment-v1'
                ? 'requires-structured-proof-statement'
                : 'public-zero-witness-binding-check',
        proofLoweringStatus: 'explicitRowsAvailable',
        proofStatementFormat: input.proofStatementFormat,
        proofSystemRingDegree:
            input.proofStatementFormat ===
            'structured-module-lwe-linear-proof-v1'
                ? 64
                : null,
        relation: 'A*w + t = 0',
        relationStatementDigest: digest(`${input.componentId}-relation`),
        rowBatchMatrixDigests: [digest(`${input.componentId}-row-matrix`)],
        rowBatchNames: [
            input.proofStatementFormat ===
            'structured-module-lwe-linear-proof-v1'
                ? 'receiver_payload_encryption_equation_rows'
                : input.proofStatementFormat ===
                    'structured-module-sis-share-commitment-v1'
                  ? 'share_commitment_equation_rows'
                  : 'receiver_key_binding_rows',
        ],
        rowBatchTargetVectorDigests: [
            digest(`${input.componentId}-row-target`),
        ],
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
        targetVectorDigest: digest(`${input.componentId}-target`),
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
        componentProofStatementDigest:
            input.componentProofStatementDigest ??
            deriveProtocolDigest('ChallengeDomainDigest', {
                payload: statementPayload,
                purpose: 'ballot-proof-component-proof-statement-plan-v1',
            }),
    };
}

function createComponentProofVerificationInputFixture(
    componentId: BallotProofComponentId,
    statementDigest = digest(`${componentId}-statement`),
): BallotProofComponentProofVerificationInput {
    const componentIndex = requiredComponentIds.indexOf(componentId);
    const randomnessByte = (componentIndex + 1).toString(16).padStart(2, '0');
    const proofStatementFormat =
        componentId === 'receiver-encryption-component'
            ? 'structured-module-lwe-linear-proof-v1'
            : componentId === 'share-commitment-component'
              ? 'structured-module-sis-share-commitment-v1'
              : componentId === 'receiver-key-binding-component'
                ? 'public-zero-witness-binding-check-v1'
                : componentId === 'score-and-shamir-field-component'
                  ? 'dense-polynomial-matrix-linear-proof-v1'
                  : 'sparse-polynomial-matrix-linear-proof-v1';
    const componentProofStatementDigest = digest(
        `${componentId}-proof-statement`,
    );
    const proofStatement = createComponentProofStatementFixture({
        componentId,
        componentProofStatementDigest:
            proofStatementFormat ===
                'structured-module-sis-share-commitment-v1' ||
            proofStatementFormat === 'structured-module-lwe-linear-proof-v1' ||
            proofStatementFormat === 'public-zero-witness-binding-check-v1'
                ? undefined
                : componentProofStatementDigest,
        componentStatementDigest: statementDigest,
        proofStatementFormat,
    }) as {
        readonly componentProofStatementDigest?: ProtocolDigest;
        readonly statementDigest?: ProtocolDigest;
    };
    const boundComponentProofStatementDigest =
        proofStatement.componentProofStatementDigest ??
        proofStatement.statementDigest ??
        componentProofStatementDigest;
    const proofBytesHex =
        proofStatementFormat === 'public-zero-witness-binding-check-v1'
            ? ''
            : digest(`${componentId}-proof-bytes-material`);

    return {
        componentId,
        componentProofStatementDigest: boundComponentProofStatementDigest,
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
        statementDigest,
    };
}

const createComponentProofBundleFixture = (
    statement: BallotProofStatement,
    componentIds: readonly BallotProofComponentId[] = requiredComponentIds,
): BallotProofComponentProofBundle => {
    const backendStatementDigest = digest('component-backend-statement');
    const relationStatementDigest = digest('component-relation-statement');
    const componentProofs = componentIds.map((componentId) => {
        const proofInput = createComponentProofVerificationInputFixture(
            componentId,
            digest(`${componentId}-statement`),
        );
        const proofBytesDigest = deriveProofBytesDigest({
            allowEmpty:
                proofInput.proofStatementFormat ===
                'public-zero-witness-binding-check-v1',
            proofBytesHex: proofInput.proofBytesHex,
        });
        const proofEncodingProfileDigest =
            deriveBallotProofEncodingProfileDigest({
                proofEncoding: proofInput.proofEncoding,
            });
        const proofParameterSetDigest = deriveBallotProofParameterSetDigest({
            parameterSet: proofInput.proofParameterSet,
        });
        const publicRandomnessDigest = deriveBallotProofPublicRandomnessDigest({
            publicRandomnessHex: proofInput.publicRandomnessHex,
        });

        return createBallotProofComponentProofRecord({
            backendStatementDigest,
            ballotProofStatementDigest: statement.ballotProofStatementDigest,
            componentId,
            componentProofStatementDigest:
                proofInput.componentProofStatementDigest,
            componentStatementDigest: proofInput.statementDigest,
            proofBytesDigest,
            proofEncodingProfileDigest,
            proofParameterSetDigest,
            proofRoot: deriveBallotProofComponentProofRoot({
                componentId,
                componentProofStatementDigest:
                    proofInput.componentProofStatementDigest,
                componentStatementDigest: proofInput.statementDigest,
                proofBytesDigest,
                proofEncodingProfileDigest,
                proofParameterSetDigest,
                proofStatementFormat: proofInput.proofStatementFormat,
                publicRandomnessDigest,
                statementDigest: proofInput.statementDigest,
            }),
            proofSizeBytes: proofInput.proofBytesHex.length / 2,
            publicRandomnessDigest,
            relationStatementDigest,
        });
    });
    const componentBundleStatement = {
        backendStatementDigest,
        ballotProofStatementDigest: statement.ballotProofStatementDigest,
        bundleCoverage: 'full-encoded-score-ballot-relation' as const,
        componentBundleStatementDigest: digest('component-bundle-statement'),
        componentStatements: [],
        objectType: 'BallotProofComponentBundleStatement' as const,
        objectVersion: 1 as const,
        relationLabel: 'BallotPrivacyPvssRelation' as const,
        relationStatementDigest,
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
            componentProof.componentStatementDigest,
        ),
    );

const createStructurallyBoundObjects = (): {
    readonly statement: BallotProofStatement;
    readonly receiverKeyProofRootEvidence: ReceiverKeyProofRootEvidence;
    readonly receiverPayloads: readonly ReceiverPayload[];
    readonly shareCommitments: readonly ShareCommitment[];
} => {
    const profileSet = createBallotPrivacyProfileSet();
    const boundCertificate = createShareCommitmentMessageBoundCert({
        maximumCanonicalTurnout: 20,
        shareCommitmentProfile: profileSet.shareCommitmentProfile,
    });
    const receiverPublicKeyReferences = [
        {
            receiverIdentity: 'receiver-1',
            receiverRosterPosition: 1,
            receiverPublicKeyDigest: digest('receiver-public-key-1'),
        },
        {
            receiverIdentity: 'receiver-2',
            receiverRosterPosition: 2,
            receiverPublicKeyDigest: digest('receiver-public-key-2'),
        },
    ];
    const receiverPayloads = receiverPublicKeyReferences.map(
        (receiverPublicKeyReference) =>
            createReceiverPayloadShell({
                ceremonyId: 'ceremony-1',
                ciphertextBodyDigest: digest(
                    `ciphertext-body-${receiverPublicKeyReference.receiverRosterPosition}`,
                ),
                manifestDigest: digest('manifest'),
                payloadContextDigest: digest(
                    `payload-context-${receiverPublicKeyReference.receiverRosterPosition}`,
                ),
                pollSpecDigest: digest('poll-spec'),
                receiverEncryptionProfileDigest:
                    profileSet.receiverEncryptionProfile
                        .receiverEncryptionProfileDigest,
                receiverIdentity: receiverPublicKeyReference.receiverIdentity,
                receiverPublicKeyDigest:
                    receiverPublicKeyReference.receiverPublicKeyDigest,
                receiverRosterPosition:
                    receiverPublicKeyReference.receiverRosterPosition,
                rosterDigest: digest('roster'),
                voterIdentityDigest: digest('voter-1'),
            }),
    );
    const shareCommitments = receiverPublicKeyReferences.map(
        (receiverPublicKeyReference) =>
            createShareCommitmentShell({
                ceremonyId: 'ceremony-1',
                commitmentBodyDigest: digest(
                    `commitment-body-${receiverPublicKeyReference.receiverRosterPosition}`,
                ),
                manifestDigest: digest('manifest'),
                receiverIdentity: receiverPublicKeyReference.receiverIdentity,
                receiverRosterPosition:
                    receiverPublicKeyReference.receiverRosterPosition,
                rosterDigest: digest('roster'),
                shareCommitmentProfileDigest:
                    profileSet.shareCommitmentProfile
                        .shareCommitmentProfileDigest,
                shareVectorWidth:
                    profileSet.shareCommitmentProfile.shareVectorWidth,
            }),
    );
    const receiverKeyProofRootEvidence = createReceiverKeyProofRootEvidence({
        acceptedReceiverKeyProofCount: receiverPublicKeyReferences.length,
        ceremonyId: 'ceremony-1',
        evidenceStatus: 'ReceiverKeyProofRootAccepted',
        manifestDigest: digest('manifest'),
        receiverKeyProofRoot: digest('receiver-key-proof-root'),
        receiverKeyRoot: digest('receiver-key-root'),
        receiverPublicKeys: receiverPublicKeyReferences,
        rosterDigest: digest('roster'),
    });
    const statementInput = {
        ceremonyId: 'ceremony-1',
        manifestDigest: digest('manifest'),
        rosterDigest: digest('roster'),
        pollSpecDigest: digest('poll-spec'),
        thresholdProfileDigest: digest('threshold-profile'),
        duplicateBallotPolicyDigest: digest('duplicate-policy'),
        scoreDomainDigest: digest('score-domain'),
        tiePolicyDigest: digest('tie-policy'),
        topOptionCount: 3,
        optionCount: 20,
        voterIdentityDigest: digest('voter-1'),
        voterRosterPosition: 1,
        voterSigningKeyDigest: digest('voter-signing-key'),
        actionContextDigest: digest('action-context'),
        rosterExternalAcceptanceDigest: digest('external-acceptance'),
        receiverKeyRoot: digest('receiver-key-root'),
        receiverKeyProofRoot: digest('receiver-key-proof-root'),
        receiverPublicKeys: receiverPublicKeyReferences,
        receiverPayloads: receiverPayloads.map((receiverPayload) => ({
            receiverIdentity: receiverPayload.receiverIdentity,
            receiverPayloadCiphertextRoot:
                receiverPayload.receiverPayloadCiphertextRoot,
            receiverPayloadDigest: receiverPayload.receiverPayloadDigest,
            receiverRosterPosition: receiverPayload.receiverRosterPosition,
        })),
        shareCommitments: shareCommitments.map((shareCommitment) => ({
            receiverIdentity: shareCommitment.receiverIdentity,
            receiverRosterPosition: shareCommitment.receiverRosterPosition,
            shareCommitmentDigest: shareCommitment.shareCommitmentDigest,
        })),
        shareCommitmentProfileDigest:
            profileSet.shareCommitmentProfile.shareCommitmentProfileDigest,
        receiverEncryptionProfileDigest:
            profileSet.receiverEncryptionProfile
                .receiverEncryptionProfileDigest,
        ballotProofProfileDigest:
            profileSet.ballotProofProfile.ballotProofProfileDigest,
        scoreMembershipProfileDigest:
            profileSet.scoreMembershipProfile.scoreMembershipProfileDigest,
        ballotScoreEncodingProfileDigest:
            profileSet.ballotScoreEncodingProfile
                .ballotScoreEncodingProfileDigest,
        ballotShareLayoutProfileDigest:
            profileSet.ballotShareLayoutProfile.ballotShareLayoutProfileDigest,
        aggregateInputEncodingProfileDigest:
            profileSet.aggregateInputEncodingProfile
                .aggregateInputEncodingProfileDigest,
        encodedShareVectorLayoutDigest:
            profileSet.encodedShareVectorLayoutProfile
                .encodedShareVectorLayoutDigest,
        encodedAggregateLayoutDigest:
            profileSet.encodedAggregateLayoutProfile
                .encodedAggregateLayoutDigest,
        shareCommitmentMessageBoundCertDigest:
            boundCertificate.shareCommitmentMessageBoundCertDigest,
    };
    const placeholderStatement = buildBallotProofStatement({
        ...statementInput,
        ballotPackageDigest: digest('ballot-package-placeholder'),
    });
    const ballotPackageDigest = deriveClaimBearingBallotPackageDigest({
        ballotProofStatement: placeholderStatement,
        receiverKeyProofRootEvidence,
        receiverPayloads,
        shareCommitments,
    });
    const statement = buildBallotProofStatement({
        ...statementInput,
        ballotPackageDigest,
    });

    return {
        receiverKeyProofRootEvidence,
        receiverPayloads,
        shareCommitments,
        statement,
    };
};

export {
    digest,
    requiredComponentIds,
    createStatement,
    createComponentProofStatementFixture,
    createComponentProofBundleFixture,
    createComponentProofVerificationInputsFixture,
    createStructurallyBoundObjects,
};
export type { ClaimBearingPackageVerificationInput };
