import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import type {
    BallotProofComponentId,
    BallotProofComponentProofBundle,
    BallotProofStatement,
    ReceiverPayload,
    ProtocolDigest,
    ShareCommitment,
} from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    buildBallotProofStatement,
    createBallotPrivacyProfileSet,
    createBallotProofComponentProofBundle,
    createBallotProofComponentProofRecord,
    createBallotProofRecordShell,
    createReceiverEncryptionPublicKeyShell,
    createReceiverKeyProofShell,
    createReceiverPayloadShell,
    createShareCommitmentMessageBoundCert,
    createShareCommitmentShell,
    deriveBallotProofEncodingProfileDigest,
    deriveBallotProofParameterSetDigest,
    deriveBallotProofPublicRandomnessDigest,
    deriveProofBytesDigest,
    deriveReceiverKeyProofEncodingProfileDigest,
    deriveReceiverKeyProofPublicRandomnessDigest,
    describeBallotPrivacyProofBackend,
    verifyBallotProof,
    verifyClaimBearingBallotPackage,
    verifyReceiverKeyProof,
} from '../../src/ballot-privacy/index';

const digest = (label: string): ProtocolDigest =>
    deriveProtocolDigest('ActionContextDigest', { label });
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

const createComponentProofBundleFixture = (
    statement: BallotProofStatement,
    componentIds: readonly BallotProofComponentId[] = requiredComponentIds,
): BallotProofComponentProofBundle => {
    const backendStatementDigest = digest('component-backend-statement');
    const relationStatementDigest = digest('component-relation-statement');
    const componentProofs = componentIds.map((componentId) =>
        createBallotProofComponentProofRecord({
            backendStatementDigest,
            ballotProofStatementDigest: statement.ballotProofStatementDigest,
            componentId,
            componentStatementDigest: digest(`${componentId}-statement`),
            proofBytesDigest: digest(`${componentId}-proof-bytes`),
            proofEncodingProfileDigest: digest(`${componentId}-encoding`),
            proofParameterSetDigest: digest(`${componentId}-parameters`),
            proofRoot: digest(`${componentId}-proof-root`),
            proofSizeBytes: 64,
            publicRandomnessDigest: digest(`${componentId}-randomness`),
            relationStatementDigest,
        }),
    );
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

const createStructurallyBoundObjects = (): {
    readonly statement: BallotProofStatement;
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
    const statement = buildBallotProofStatement({
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
        ballotPackageDigest: digest('ballot-package'),
    });

    return {
        receiverPayloads,
        shareCommitments,
        statement,
    };
};

describe('ballot privacy proof object boundary', () => {
    it('derives production-shaped receiver key, payload, and commitment shells without witness material', () => {
        const profileSet = createBallotPrivacyProfileSet();
        const receiverPublicKey = createReceiverEncryptionPublicKeyShell({
            ceremonyId: 'ceremony-1',
            manifestDigest: digest('manifest'),
            rosterDigest: digest('roster'),
            receiverIdentity: 'receiver-1',
            receiverRosterPosition: 1,
            recoveryEpoch: 0,
            receiverEncryptionProfileDigest:
                profileSet.receiverEncryptionProfile
                    .receiverEncryptionProfileDigest,
            keyMaterialDigest: digest('receiver-key-material'),
        });
        const receiverKeyProof = createReceiverKeyProofShell({
            ceremonyId: receiverPublicKey.ceremonyId,
            manifestDigest: receiverPublicKey.manifestDigest,
            rosterDigest: receiverPublicKey.rosterDigest,
            receiverIdentity: receiverPublicKey.receiverIdentity,
            receiverRosterPosition: receiverPublicKey.receiverRosterPosition,
            recoveryEpoch: receiverPublicKey.recoveryEpoch,
            receiverPublicKeyDigest: receiverPublicKey.receiverPublicKeyDigest,
            receiverEncryptionProfileDigest:
                receiverPublicKey.receiverEncryptionProfileDigest,
            proofBackend: 'LaZerStyleLocalLatticeRelation',
            proofRoot: digest('receiver-key-proof-root'),
        });
        const receiverPayload = createReceiverPayloadShell({
            ceremonyId: receiverPublicKey.ceremonyId,
            manifestDigest: receiverPublicKey.manifestDigest,
            rosterDigest: receiverPublicKey.rosterDigest,
            pollSpecDigest: digest('poll-spec'),
            voterIdentityDigest: digest('voter-1'),
            receiverIdentity: receiverPublicKey.receiverIdentity,
            receiverRosterPosition: receiverPublicKey.receiverRosterPosition,
            receiverPublicKeyDigest: receiverPublicKey.receiverPublicKeyDigest,
            receiverEncryptionProfileDigest:
                receiverPublicKey.receiverEncryptionProfileDigest,
            payloadContextDigest: digest('payload-context'),
            ciphertextBodyDigest: digest('ciphertext-body'),
        });
        const shareCommitment = createShareCommitmentShell({
            ceremonyId: receiverPublicKey.ceremonyId,
            manifestDigest: receiverPublicKey.manifestDigest,
            rosterDigest: receiverPublicKey.rosterDigest,
            receiverIdentity: receiverPublicKey.receiverIdentity,
            receiverRosterPosition: receiverPublicKey.receiverRosterPosition,
            shareCommitmentProfileDigest:
                profileSet.shareCommitmentProfile.shareCommitmentProfileDigest,
            shareVectorWidth:
                profileSet.shareCommitmentProfile.shareVectorWidth,
            commitmentBodyDigest: digest('share-commitment-body'),
        });

        expect(receiverPublicKey.receiverPublicKeyDigest).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(receiverKeyProof.receiverKeyProofRoot).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(receiverPayload.receiverPayloadDigest).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(receiverPayload).not.toHaveProperty('receiverShareVector');
        expect(receiverPayload).not.toHaveProperty('shareCommitmentOpening');
        expect(shareCommitment.shareCommitmentDigest).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(shareCommitment).not.toHaveProperty('openingRandomness');
    });

    it('builds a deterministic statement that binds every public transcript input', () => {
        const statement = createStatement();
        const changedStatement = createStatement({
            manifestDigest: digest('changed-manifest'),
        });

        expect(statement.objectType).toBe('BallotProofStatement');
        expect(statement.shareVectorWidth).toBe(220);
        expect(statement.ballotScoreEncodingProfileDigest).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(statement.ballotShareLayoutProfileDigest).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(statement.aggregateInputEncodingProfileDigest).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(statement.encodedShareVectorLayoutDigest).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(statement.encodedAggregateLayoutDigest).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(statement.ballotProofStatementDigest).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(statement.challengeDomainDigest).toMatch(/^[a-f0-9]{128}$/u);
        expect(changedStatement.ballotProofStatementDigest).not.toBe(
            statement.ballotProofStatementDigest,
        );
        expect(changedStatement.challengeDomainDigest).toBe(
            statement.challengeDomainDigest,
        );
    });

    it('binds the encoded-score layout digests into the challenge domain and proof record', () => {
        const statement = createStatement();
        const changedLayoutStatement = createStatement({
            encodedShareVectorLayoutDigest: digest(
                'changed-encoded-share-vector-layout',
            ),
        });
        const proofRecord = createBallotProofRecordShell({
            statement,
            relationStatementDigest: digest('relation-statement'),
            proofRoot: digest('proof-root'),
            proofBytesDigest: digest('proof-bytes'),
            proofSizeBytes: 1_024,
        });
        const changedLayoutProofRecord = createBallotProofRecordShell({
            statement: changedLayoutStatement,
            relationStatementDigest: digest('changed-relation-statement'),
            proofRoot: digest('proof-root'),
            proofBytesDigest: digest('proof-bytes'),
            proofSizeBytes: 1_024,
        });

        expect(changedLayoutStatement.challengeDomainDigest).not.toBe(
            statement.challengeDomainDigest,
        );
        expect(changedLayoutStatement.ballotProofStatementDigest).not.toBe(
            statement.ballotProofStatementDigest,
        );
        expect(changedLayoutProofRecord.challengeDigest).not.toBe(
            proofRecord.challengeDigest,
        );
    });

    it('binds proof shell challenge to statement and proof roots', () => {
        const statement = createStatement();
        const proofRecord = createBallotProofRecordShell({
            statement,
            relationStatementDigest: digest('relation-statement'),
            proofRoot: digest('proof-root'),
            proofBytesDigest: digest('proof-bytes'),
            proofSizeBytes: 1_024,
        });
        const changedProofRecord = createBallotProofRecordShell({
            statement,
            relationStatementDigest: digest('relation-statement'),
            proofRoot: digest('changed-proof-root'),
            proofBytesDigest: digest('proof-bytes'),
            proofSizeBytes: 1_024,
        });
        const changedRelationProofRecord = createBallotProofRecordShell({
            statement,
            relationStatementDigest: digest('changed-relation-statement'),
            proofRoot: digest('proof-root'),
            proofBytesDigest: digest('proof-bytes'),
            proofSizeBytes: 1_024,
        });

        expect(proofRecord.objectType).toBe('BallotProofRecord');
        expect(proofRecord.ballotProofStatementDigest).toBe(
            statement.ballotProofStatementDigest,
        );
        expect(proofRecord.relationStatementDigest).toBe(
            digest('relation-statement'),
        );
        expect(proofRecord.challengeDigest).not.toBe(
            changedProofRecord.challengeDigest,
        );
        expect(proofRecord.challengeDigest).not.toBe(
            changedRelationProofRecord.challengeDigest,
        );
        expect(proofRecord.ballotProofRecordDigest).not.toBe(
            changedProofRecord.ballotProofRecordDigest,
        );
    });

    it('binds ballot proof records to complete linear backend proof metadata', () => {
        const statement = createStatement();
        const proofBytesHex = '001122aabbcc';
        const proofEncoding = {
            profileId: 'ballot-proof-linear-proof-encoding-v1',
        };
        const parameterSet = {
            profileId: 'ballot-proof-linear-parameter-set-v1',
        };
        const publicRandomnessHex = '00'.repeat(32);
        const proofRecord = createBallotProofRecordShell({
            backendStatementDigest: digest('ballot-backend-statement'),
            linearStatementDigest: digest('ballot-linear-statement'),
            proofBytesDigest: deriveProofBytesDigest({ proofBytesHex }),
            proofEncodingProfileDigest: deriveBallotProofEncodingProfileDigest({
                proofEncoding,
            }),
            proofParameterSetDigest: deriveBallotProofParameterSetDigest({
                parameterSet,
            }),
            proofRoot: digest('ballot-proof-root'),
            proofSizeBytes: proofBytesHex.length / 2,
            publicRandomnessDigest: deriveBallotProofPublicRandomnessDigest({
                publicRandomnessHex,
            }),
            relationStatementDigest: digest('relation-statement'),
            statement,
            statementMatrixDigest: digest('ballot-statement-matrix'),
            targetVectorDigest: digest('ballot-target-vector'),
        });
        const changedRandomnessProofRecord = createBallotProofRecordShell({
            backendStatementDigest: digest('ballot-backend-statement'),
            linearStatementDigest: digest('ballot-linear-statement'),
            proofBytesDigest: deriveProofBytesDigest({ proofBytesHex }),
            proofEncodingProfileDigest: deriveBallotProofEncodingProfileDigest({
                proofEncoding,
            }),
            proofParameterSetDigest: deriveBallotProofParameterSetDigest({
                parameterSet,
            }),
            proofRoot: digest('ballot-proof-root'),
            proofSizeBytes: proofBytesHex.length / 2,
            publicRandomnessDigest: deriveBallotProofPublicRandomnessDigest({
                publicRandomnessHex: '11'.repeat(32),
            }),
            relationStatementDigest: digest('relation-statement'),
            statement,
            statementMatrixDigest: digest('ballot-statement-matrix'),
            targetVectorDigest: digest('ballot-target-vector'),
        });
        const incompleteBackendMetadataProofRecord =
            createBallotProofRecordShell({
                linearStatementDigest: digest('ballot-linear-statement'),
                proofBytesDigest: deriveProofBytesDigest({ proofBytesHex }),
                proofRoot: digest('ballot-proof-root'),
                proofSizeBytes: proofBytesHex.length / 2,
                relationStatementDigest: digest('relation-statement'),
                statement,
            });

        expect(proofRecord.backendStatementDigest).toBe(
            digest('ballot-backend-statement'),
        );
        expect(proofRecord.proofParameterSetDigest).toBe(
            deriveBallotProofParameterSetDigest({ parameterSet }),
        );
        expect(proofRecord.challengeDigest).not.toBe(
            changedRandomnessProofRecord.challengeDigest,
        );
        expect(
            verifyBallotProof({
                ballotProof: proofRecord,
                proofBytesHex,
                statement,
            }),
        ).toMatchObject({
            ok: false,
            unresolvedReason: 'OperationUnavailable',
        });
        expect(
            verifyBallotProof({
                ballotProof: incompleteBackendMetadataProofRecord,
                statement,
            }),
        ).toMatchObject({
            ok: false,
            unresolvedReason: 'BallotPackageInvalid',
        });
    });

    it('binds ballot proof records to ordered component proof bundles', () => {
        const statement = createStatement();
        const proofBytesHex = '001122aabbcc';
        const componentProofBundle =
            createComponentProofBundleFixture(statement);
        const proofRecord = createBallotProofRecordShell({
            backendStatementDigest: componentProofBundle.backendStatementDigest,
            componentBundleStatementDigest:
                componentProofBundle.componentBundleStatementDigest,
            componentProofBundleDigest:
                componentProofBundle.componentProofBundleDigest,
            linearStatementDigest: digest('component-linear-statement'),
            proofBytesDigest: deriveProofBytesDigest({ proofBytesHex }),
            proofEncodingProfileDigest: digest('ballot-proof-encoding'),
            proofParameterSetDigest: digest('ballot-proof-parameters'),
            proofRoot: digest('ballot-proof-root'),
            proofSizeBytes: proofBytesHex.length / 2,
            publicRandomnessDigest: digest('ballot-proof-randomness'),
            relationStatementDigest:
                componentProofBundle.relationStatementDigest,
            statement,
            statementMatrixDigest: digest('ballot-statement-matrix'),
            targetVectorDigest: digest('ballot-target-vector'),
        });
        const reorderedComponentProofBundle = createComponentProofBundleFixture(
            statement,
            [...requiredComponentIds].reverse(),
        );
        const reorderedProofRecord = createBallotProofRecordShell({
            backendStatementDigest:
                reorderedComponentProofBundle.backendStatementDigest,
            componentBundleStatementDigest:
                reorderedComponentProofBundle.componentBundleStatementDigest,
            componentProofBundleDigest:
                reorderedComponentProofBundle.componentProofBundleDigest,
            linearStatementDigest: digest('component-linear-statement'),
            proofBytesDigest: deriveProofBytesDigest({ proofBytesHex }),
            proofEncodingProfileDigest: digest('ballot-proof-encoding'),
            proofParameterSetDigest: digest('ballot-proof-parameters'),
            proofRoot: digest('ballot-proof-root'),
            proofSizeBytes: proofBytesHex.length / 2,
            publicRandomnessDigest: digest('ballot-proof-randomness'),
            relationStatementDigest:
                reorderedComponentProofBundle.relationStatementDigest,
            statement,
            statementMatrixDigest: digest('ballot-statement-matrix'),
            targetVectorDigest: digest('ballot-target-vector'),
        });

        expect(
            verifyBallotProof({
                ballotProof: proofRecord,
                componentProofBundle,
                proofBytesHex,
                statement,
            }),
        ).toMatchObject({
            ok: false,
            unresolvedReason: 'OperationUnavailable',
        });
        expect(
            verifyBallotProof({
                ballotProof: proofRecord,
                proofBytesHex,
                statement,
            }),
        ).toMatchObject({
            ok: false,
            unresolvedReason: 'BallotPackageInvalid',
        });
        expect(
            verifyBallotProof({
                ballotProof: {
                    ...proofRecord,
                    componentProofBundleDigest: digest(
                        'wrong-component-proof-bundle',
                    ),
                },
                componentProofBundle,
                proofBytesHex,
                statement,
            }),
        ).toMatchObject({
            ok: false,
            unresolvedReason: 'BallotPackageInvalid',
        });
        expect(
            verifyBallotProof({
                ballotProof: reorderedProofRecord,
                componentProofBundle: reorderedComponentProofBundle,
                proofBytesHex,
                statement,
            }),
        ).toMatchObject({
            ok: false,
            unresolvedReason: 'BallotPackageInvalid',
        });
    });

    it('checks supplied ballot proof bytes against the proof record before the backend gate', () => {
        const statement = createStatement();
        const proofBytesHex = '001122aabbcc';
        const proofRecord = createBallotProofRecordShell({
            statement,
            relationStatementDigest: digest('relation-statement'),
            proofRoot: digest('proof-root'),
            proofBytesDigest: deriveProofBytesDigest({ proofBytesHex }),
            proofSizeBytes: proofBytesHex.length / 2,
        });
        const wrongProofBytes = '001122aabbcd';
        const shortProofRecord = createBallotProofRecordShell({
            statement,
            relationStatementDigest: digest('relation-statement'),
            proofRoot: digest('proof-root'),
            proofBytesDigest: deriveProofBytesDigest({ proofBytesHex }),
            proofSizeBytes: proofBytesHex.length / 2 + 1,
        });

        expect(
            verifyBallotProof({
                statement,
                ballotProof: proofRecord,
                proofBytesHex,
            }),
        ).toMatchObject({
            ok: false,
            unresolvedReason: 'OperationUnavailable',
        });
        expect(
            verifyBallotProof({
                statement,
                ballotProof: proofRecord,
                proofBytesHex: wrongProofBytes,
            }),
        ).toMatchObject({
            ok: false,
            unresolvedReason: 'BallotPackageInvalid',
        });
        expect(
            verifyBallotProof({
                statement,
                ballotProof: shortProofRecord,
                proofBytesHex,
            }),
        ).toMatchObject({
            ok: false,
            unresolvedReason: 'BallotPackageInvalid',
        });
        expect(
            verifyBallotProof({
                statement,
                ballotProof: proofRecord,
                proofBytesHex: 'AA',
            }),
        ).toMatchObject({
            ok: false,
            unresolvedReason: 'BallotPackageInvalid',
        });
    });

    it('checks supplied receiver-key proof bytes against proof-byte metadata before the backend gate', () => {
        const proofBytesHex = '001122aabbcc';
        const wrongProofBytesHex = '001122aabbcd';
        const proofEncoding = {
            profileId: 'receiver-key-linear-proof-encoding-v1',
        };
        const publicRandomnessHex = '00'.repeat(32);
        const receiverKeyProof = createReceiverKeyProofShell({
            backendStatementDigest: digest('receiver-key-backend-statement'),
            ceremonyId: 'ceremony-1',
            linearStatementDigest: digest('receiver-key-linear-statement'),
            manifestDigest: digest('manifest'),
            proofBackend: 'LaZerStyleLocalLatticeRelation',
            proofBytesDigest: deriveProofBytesDigest({ proofBytesHex }),
            proofEncodingProfileDigest:
                deriveReceiverKeyProofEncodingProfileDigest({
                    proofEncoding,
                }),
            proofRoot: digest('receiver-key-proof-root'),
            proofSizeBytes: proofBytesHex.length / 2,
            publicRandomnessDigest:
                deriveReceiverKeyProofPublicRandomnessDigest({
                    publicRandomnessHex,
                }),
            receiverEncryptionProfileDigest: digest(
                'receiver-encryption-profile',
            ),
            receiverIdentity: 'receiver-1',
            receiverPublicKeyDigest: digest('receiver-public-key-1'),
            receiverRosterPosition: 1,
            recoveryEpoch: 0,
            rosterDigest: digest('roster'),
        });
        const incompleteProofMetadata = createReceiverKeyProofShell({
            ceremonyId: 'ceremony-1',
            linearStatementDigest: digest('receiver-key-linear-statement'),
            manifestDigest: digest('manifest'),
            proofBackend: 'LaZerStyleLocalLatticeRelation',
            proofRoot: digest('receiver-key-proof-root'),
            receiverEncryptionProfileDigest: digest(
                'receiver-encryption-profile',
            ),
            receiverIdentity: 'receiver-1',
            receiverPublicKeyDigest: digest('receiver-public-key-1'),
            receiverRosterPosition: 1,
            recoveryEpoch: 0,
            rosterDigest: digest('roster'),
        });

        expect(
            verifyReceiverKeyProof({
                proofBytesHex,
                receiverKeyProof,
            }),
        ).toMatchObject({
            ok: false,
            unresolvedReason: 'OperationUnavailable',
        });
        expect(
            verifyReceiverKeyProof({
                proofBytesHex: wrongProofBytesHex,
                receiverKeyProof,
            }),
        ).toMatchObject({
            ok: false,
            unresolvedReason: 'BallotPackageInvalid',
        });
        expect(
            verifyReceiverKeyProof({
                proofBytesHex: 'AA',
                receiverKeyProof,
            }),
        ).toMatchObject({
            ok: false,
            unresolvedReason: 'BallotPackageInvalid',
        });
        expect(
            verifyReceiverKeyProof({
                receiverKeyProof: incompleteProofMetadata,
            }),
        ).toMatchObject({
            ok: false,
            unresolvedReason: 'BallotPackageInvalid',
        });
    });

    it('keeps proof verification fail-closed until the lattice backend is integrated', () => {
        const statement = createStatement();
        const proofRecord = createBallotProofRecordShell({
            statement,
            relationStatementDigest: digest('relation-statement'),
            proofRoot: digest('proof-root'),
            proofBytesDigest: digest('proof-bytes'),
            proofSizeBytes: 1_024,
        });
        const receiverKeyProof = createReceiverKeyProofShell({
            ceremonyId: statement.ceremonyId,
            manifestDigest: statement.manifestDigest,
            rosterDigest: statement.rosterDigest,
            receiverIdentity: 'receiver-1',
            receiverRosterPosition: 1,
            recoveryEpoch: 0,
            receiverPublicKeyDigest: digest('receiver-public-key-1'),
            receiverEncryptionProfileDigest:
                statement.receiverEncryptionProfileDigest,
            proofBackend: 'LaZerStyleLocalLatticeRelation' as const,
            proofRoot: digest('receiver-key-proof'),
        });
        const structurallyBoundObjects = createStructurallyBoundObjects();
        const structurallyBoundProofRecord = createBallotProofRecordShell({
            proofBytesDigest: digest('bound-proof-bytes'),
            relationStatementDigest: digest('bound-relation-statement'),
            proofRoot: digest('bound-proof-root'),
            proofSizeBytes: 1_024,
            statement: structurallyBoundObjects.statement,
        });

        expect(
            verifyBallotProof({ statement, ballotProof: proofRecord }),
        ).toMatchObject({
            ok: false,
            backendAvailable: false,
            backendStatus: {
                portableRustWasmPortRequired: true,
                upstreamDirectDependencyUsableInBrowser: false,
            },
            unresolvedReason: 'OperationUnavailable',
        });
        expect(
            verifyBallotProof({ statement, ballotProof: proofRecord })
                .backendStatus?.requiredComponents,
        ).toContain('tbox proof generation and verification');
        expect(verifyReceiverKeyProof({ receiverKeyProof })).toMatchObject({
            ok: false,
            backendAvailable: false,
            unresolvedReason: 'OperationUnavailable',
        });
        expect(
            verifyClaimBearingBallotPackage({
                ballotPackage: {
                    objectType: 'BallotPackage',
                    objectVersion: 1,
                    ballotPackageDigest:
                        structurallyBoundObjects.statement.ballotPackageDigest,
                    ballotProofStatement: structurallyBoundObjects.statement,
                    ballotProof: structurallyBoundProofRecord,
                    receiverPayloads: structurallyBoundObjects.receiverPayloads,
                    shareCommitments: structurallyBoundObjects.shareCommitments,
                },
            }),
        ).toMatchObject({
            ok: false,
            backendAvailable: false,
            unresolvedReason: 'OperationUnavailable',
        });
    });

    it('rejects malformed claim-bearing package shells before the backend gate', () => {
        const structurallyBoundObjects = createStructurallyBoundObjects();
        const firstReceiverPayload =
            structurallyBoundObjects.receiverPayloads[0];
        const firstReceiverPayloadReference =
            structurallyBoundObjects.statement.receiverPayloads[0];
        const firstShareCommitment =
            structurallyBoundObjects.shareCommitments[0];
        if (
            firstReceiverPayload === undefined ||
            firstReceiverPayloadReference === undefined ||
            firstShareCommitment === undefined
        ) {
            throw new Error('receiver fixture should contain a first receiver');
        }
        const proofRecord = createBallotProofRecordShell({
            proofBytesDigest: digest('bound-proof-bytes'),
            relationStatementDigest: digest('bound-relation-statement'),
            proofRoot: digest('bound-proof-root'),
            proofSizeBytes: 1_024,
            statement: structurallyBoundObjects.statement,
        });
        const changedChallengeProofRecord = {
            ...proofRecord,
            challengeDigest: digest('changed-challenge'),
        };
        const packageWithChangedChallenge = verifyClaimBearingBallotPackage({
            ballotPackage: {
                objectType: 'BallotPackage',
                objectVersion: 1,
                ballotPackageDigest:
                    structurallyBoundObjects.statement.ballotPackageDigest,
                ballotProofStatement: structurallyBoundObjects.statement,
                ballotProof: changedChallengeProofRecord,
                receiverPayloads: structurallyBoundObjects.receiverPayloads,
                shareCommitments: structurallyBoundObjects.shareCommitments,
            },
        });
        const packageWithLeakedWitness = verifyClaimBearingBallotPackage({
            ballotPackage: {
                objectType: 'BallotPackage',
                objectVersion: 1,
                ballotPackageDigest:
                    structurallyBoundObjects.statement.ballotPackageDigest,
                ballotProofStatement: structurallyBoundObjects.statement,
                ballotProof: proofRecord,
                receiverPayloads: [
                    {
                        ...firstReceiverPayload,
                        receiverShareVector: [1, 2, 3],
                    } as unknown as ReceiverPayload,
                    ...structurallyBoundObjects.receiverPayloads.slice(1),
                ],
                shareCommitments: structurallyBoundObjects.shareCommitments,
            },
        });
        const zeroCommitmentPolynomialVector = Array.from({ length: 4 }, () =>
            Array.from({ length: 256 }, () => '0'),
        );
        const malformedCommitmentVector = createShareCommitmentShell({
            ceremonyId: firstShareCommitment.ceremonyId,
            commitmentBodyDigest: digest('wrong-commitment-body'),
            commitmentPolynomialVector: zeroCommitmentPolynomialVector,
            manifestDigest: firstShareCommitment.manifestDigest,
            receiverIdentity: firstShareCommitment.receiverIdentity,
            receiverRosterPosition: firstShareCommitment.receiverRosterPosition,
            rosterDigest: firstShareCommitment.rosterDigest,
            shareCommitmentProfileDigest:
                firstShareCommitment.shareCommitmentProfileDigest,
            shareVectorWidth: firstShareCommitment.shareVectorWidth,
        });
        const packageWithMalformedCommitmentVector =
            verifyClaimBearingBallotPackage({
                ballotPackage: {
                    objectType: 'BallotPackage',
                    objectVersion: 1,
                    ballotPackageDigest:
                        structurallyBoundObjects.statement.ballotPackageDigest,
                    ballotProofStatement: structurallyBoundObjects.statement,
                    ballotProof: proofRecord,
                    receiverPayloads: structurallyBoundObjects.receiverPayloads,
                    shareCommitments: [
                        malformedCommitmentVector,
                        ...structurallyBoundObjects.shareCommitments.slice(1),
                    ],
                },
            });
        const duplicateReceiverStatement = createStatement({
            receiverPayloads: [
                firstReceiverPayloadReference,
                firstReceiverPayloadReference,
            ],
        });
        const duplicateReceiverProofRecord = createBallotProofRecordShell({
            proofBytesDigest: digest('duplicate-proof-bytes'),
            relationStatementDigest: digest('duplicate-relation-statement'),
            proofRoot: digest('duplicate-proof-root'),
            proofSizeBytes: 1_024,
            statement: duplicateReceiverStatement,
        });

        expect(packageWithChangedChallenge).toMatchObject({
            ok: false,
            unresolvedReason: 'BallotPackageInvalid',
        });
        expect(packageWithLeakedWitness).toMatchObject({
            ok: false,
            unresolvedReason: 'BallotPackageInvalid',
        });
        expect(packageWithMalformedCommitmentVector).toMatchObject({
            ok: false,
            unresolvedReason: 'BallotPackageInvalid',
        });
        expect(
            packageWithMalformedCommitmentVector.refusedObjects.some(
                (refusal) =>
                    refusal.message.includes(
                        'Share commitment polynomial vector is malformed or not bound',
                    ),
            ),
        ).toBe(true);
        expect(
            verifyBallotProof({
                ballotProof: duplicateReceiverProofRecord,
                statement: duplicateReceiverStatement,
            }),
        ).toMatchObject({
            ok: false,
            unresolvedReason: 'BallotPackageInvalid',
        });
    });

    it('describes the exact portable proof backend gap', () => {
        const backendStatus = describeBallotPrivacyProofBackend();

        expect(backendStatus.backendAvailable).toBe(false);
        expect(backendStatus.portableRustWasmPortRequired).toBe(true);
        expect(backendStatus.upstreamDirectDependencyUsableInBrowser).toBe(
            false,
        );
        expect(backendStatus.requiredComponents).toEqual(
            expect.arrayContaining([
                'generated linear proof parameters from lin-codegen.sage',
                'ABDLop commitment key generation, commitment, and commitment hashing',
                'proof byte coder and decoder',
                'browser-safe prover randomness source',
            ]),
        );
        expect(backendStatus.upstreamReferenceFiles).toEqual(
            expect.arrayContaining([
                'src/lin-proofs.c',
                'src/lnp-tbox.c',
                'src/abdlop.c',
                'scripts/lin-codegen.sage',
            ]),
        );
    });
});
