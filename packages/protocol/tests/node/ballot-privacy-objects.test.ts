import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import type {
    BallotProofStatement,
    ProtocolDigest,
} from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    buildBallotProofStatement,
    createBallotPrivacyProfileSet,
    createBallotProofRecordShell,
    createReceiverEncryptionPublicKeyShell,
    createReceiverKeyProofShell,
    createReceiverPayloadShell,
    createShareCommitmentMessageBoundCert,
    createShareCommitmentShell,
    verifyBallotProof,
    verifyClaimBearingBallotPackage,
    verifyReceiverKeyProof,
} from '../../src/ballot-privacy/index';

const digest = (label: string): ProtocolDigest =>
    deriveProtocolDigest('ActionContextDigest', { label });

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
        shareCommitmentMessageBoundCertDigest:
            boundCertificate.shareCommitmentMessageBoundCertDigest,
        ballotPackageDigest: digest('ballot-package'),
        ...overrides,
    });
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
        expect(statement.shareVectorWidth).toBe(20);
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

    it('binds proof shell challenge to statement and proof roots', () => {
        const statement = createStatement();
        const proofRecord = createBallotProofRecordShell({
            statement,
            proofRoot: digest('proof-root'),
            proofBytesDigest: digest('proof-bytes'),
            proofSizeBytes: 1_024,
        });
        const changedProofRecord = createBallotProofRecordShell({
            statement,
            proofRoot: digest('changed-proof-root'),
            proofBytesDigest: digest('proof-bytes'),
            proofSizeBytes: 1_024,
        });

        expect(proofRecord.objectType).toBe('BallotProofRecord');
        expect(proofRecord.ballotProofStatementDigest).toBe(
            statement.ballotProofStatementDigest,
        );
        expect(proofRecord.challengeDigest).not.toBe(
            changedProofRecord.challengeDigest,
        );
        expect(proofRecord.ballotProofRecordDigest).not.toBe(
            changedProofRecord.ballotProofRecordDigest,
        );
    });

    it('keeps proof verification fail-closed until the lattice backend is integrated', () => {
        const statement = createStatement();
        const proofRecord = createBallotProofRecordShell({
            statement,
            proofRoot: digest('proof-root'),
            proofBytesDigest: digest('proof-bytes'),
            proofSizeBytes: 1_024,
        });
        const receiverKeyProof = {
            objectType: 'ReceiverKeyProof' as const,
            objectVersion: 1 as const,
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
            receiverKeyProofRoot: statement.receiverKeyProofRoot,
        };

        expect(
            verifyBallotProof({ statement, ballotProof: proofRecord }),
        ).toMatchObject({
            ok: false,
            backendAvailable: false,
            unresolvedReason: 'OperationUnavailable',
        });
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
                    ballotPackageDigest: statement.ballotPackageDigest,
                    ballotProofStatement: statement,
                    ballotProof: proofRecord,
                    receiverPayloads: [],
                    shareCommitments: [],
                },
            }),
        ).toMatchObject({
            ok: false,
            backendAvailable: false,
            unresolvedReason: 'OperationUnavailable',
        });
    });
});
