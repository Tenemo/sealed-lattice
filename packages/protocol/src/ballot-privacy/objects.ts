import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import type {
    BallotPrivacyVerification,
    BallotProofRecord,
    BallotProofStatement,
    ClaimBearingBallotPackage,
    ProtocolDigest,
    ReceiverEncryptionPublicKey,
    ReceiverKeyProof,
    ReceiverPayload,
    RefusalRecord,
    ShareCommitment,
} from '@sealed-lattice/types';

import { createRefusal } from '../common/verification-helpers.js';
import { pvssBallotShareVectorWidth } from '../pvss-ballot/common.js';

type ReceiverEncryptionPublicKeyPayload = Omit<
    ReceiverEncryptionPublicKey,
    'receiverPublicKeyDigest'
>;
type ReceiverKeyProofPayload = Omit<ReceiverKeyProof, 'receiverKeyProofRoot'>;
type ReceiverPayloadCiphertextPayload = Pick<
    ReceiverPayload,
    | 'ceremonyId'
    | 'manifestDigest'
    | 'payloadContextDigest'
    | 'receiverEncryptionProfileDigest'
    | 'receiverIdentity'
    | 'receiverPublicKeyDigest'
    | 'receiverRosterPosition'
    | 'ciphertextBodyDigest'
>;
type ReceiverPayloadPayload = Omit<ReceiverPayload, 'receiverPayloadDigest'>;
type ShareCommitmentPayload = Omit<ShareCommitment, 'shareCommitmentDigest'>;
type BallotProofStatementPayload = Omit<
    BallotProofStatement,
    'ballotProofStatementDigest'
>;
type BallotProofRecordPayload = Omit<
    BallotProofRecord,
    'ballotProofRecordDigest'
>;
type ReceiverEncryptionPublicKeyInput = Omit<
    ReceiverEncryptionPublicKey,
    'objectType' | 'objectVersion' | 'receiverPublicKeyDigest'
>;
type ReceiverKeyProofInput = Omit<
    ReceiverKeyProof,
    'objectType' | 'objectVersion' | 'receiverKeyProofRoot'
>;
type ReceiverPayloadInput = Omit<
    ReceiverPayload,
    | 'objectType'
    | 'objectVersion'
    | 'receiverPayloadCiphertextRoot'
    | 'receiverPayloadDigest'
>;
type ShareCommitmentInput = Omit<
    ShareCommitment,
    | 'objectType'
    | 'objectVersion'
    | 'shareVectorWidth'
    | 'shareCommitmentDigest'
>;

const unavailableProofBackendMessage =
    'Ballot privacy proof verification requires the frozen LaZer-style lattice proof backend, which is not implemented in this build.';

type BallotProofStatementInput = Omit<
    BallotProofStatement,
    | 'objectType'
    | 'objectVersion'
    | 'ballotProofStatementDigest'
    | 'challengeDomainDigest'
    | 'shareVectorWidth'
> & {
    readonly challengeDomainLabel?: string;
};

const deriveReceiverEncryptionPublicKeyDigest = (
    publicKey: ReceiverEncryptionPublicKeyPayload,
): ProtocolDigest => deriveProtocolDigest('PublicKeyDigest', publicKey);

const deriveReceiverKeyProofRoot = (
    receiverKeyProof: ReceiverKeyProofPayload,
): ProtocolDigest =>
    deriveProtocolDigest('ReceiverKeyProofRoot', receiverKeyProof);

const deriveReceiverPayloadCiphertextRoot = (
    receiverPayload: ReceiverPayloadCiphertextPayload,
): ProtocolDigest =>
    deriveProtocolDigest('ReceiverPayloadCiphertextRoot', receiverPayload);

const deriveReceiverPayloadDigest = (
    receiverPayload: ReceiverPayloadPayload,
): ProtocolDigest =>
    deriveProtocolDigest('ReceiverPayloadDigest', receiverPayload);

const deriveShareCommitmentDigest = (
    shareCommitment: ShareCommitmentPayload,
): ProtocolDigest =>
    deriveProtocolDigest('ShareCommitmentDigest', shareCommitment);

const deriveBallotProofStatementDigest = (
    statement: BallotProofStatementPayload,
): ProtocolDigest =>
    deriveProtocolDigest('BallotProofStatementDigest', statement);

const deriveBallotProofRecordDigest = (
    proofRecord: BallotProofRecordPayload,
): ProtocolDigest =>
    deriveProtocolDigest('BallotProofRecordDigest', proofRecord);

const deriveBallotProofChallengeDigest = (input: {
    readonly statement: BallotProofStatement;
    readonly proofRoot: ProtocolDigest;
    readonly proofBytesDigest: ProtocolDigest;
}): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        ballotProofStatementDigest: input.statement.ballotProofStatementDigest,
        challengeDomainDigest: input.statement.challengeDomainDigest,
        proofBytesDigest: input.proofBytesDigest,
        proofRoot: input.proofRoot,
    });

export const createReceiverEncryptionPublicKeyShell = (
    input: ReceiverEncryptionPublicKeyInput,
): ReceiverEncryptionPublicKey => {
    const publicKeyPayload: ReceiverEncryptionPublicKeyPayload = {
        objectType: 'ReceiverEncryptionPublicKey',
        objectVersion: 1,
        ...input,
    };

    return {
        ...publicKeyPayload,
        receiverPublicKeyDigest:
            deriveReceiverEncryptionPublicKeyDigest(publicKeyPayload),
    };
};

export const createReceiverKeyProofShell = (
    input: ReceiverKeyProofInput,
): ReceiverKeyProof => {
    const receiverKeyProofPayload: ReceiverKeyProofPayload = {
        objectType: 'ReceiverKeyProof',
        objectVersion: 1,
        ...input,
    };

    return {
        ...receiverKeyProofPayload,
        receiverKeyProofRoot: deriveReceiverKeyProofRoot(
            receiverKeyProofPayload,
        ),
    };
};

export const createReceiverPayloadShell = (
    input: ReceiverPayloadInput,
): ReceiverPayload => {
    const ciphertextRoot = deriveReceiverPayloadCiphertextRoot({
        ceremonyId: input.ceremonyId,
        manifestDigest: input.manifestDigest,
        payloadContextDigest: input.payloadContextDigest,
        receiverEncryptionProfileDigest: input.receiverEncryptionProfileDigest,
        receiverIdentity: input.receiverIdentity,
        receiverPublicKeyDigest: input.receiverPublicKeyDigest,
        receiverRosterPosition: input.receiverRosterPosition,
        ciphertextBodyDigest: input.ciphertextBodyDigest,
    });
    const receiverPayloadPayload: ReceiverPayloadPayload = {
        objectType: 'ReceiverPayload',
        objectVersion: 1,
        ...input,
        receiverPayloadCiphertextRoot: ciphertextRoot,
    };

    return {
        ...receiverPayloadPayload,
        receiverPayloadDigest: deriveReceiverPayloadDigest(
            receiverPayloadPayload,
        ),
    };
};

export const createShareCommitmentShell = (
    input: ShareCommitmentInput,
): ShareCommitment => {
    const shareCommitmentPayload: ShareCommitmentPayload = {
        objectType: 'ShareCommitment',
        objectVersion: 1,
        ...input,
        shareVectorWidth: pvssBallotShareVectorWidth,
    };

    return {
        ...shareCommitmentPayload,
        shareCommitmentDigest: deriveShareCommitmentDigest(
            shareCommitmentPayload,
        ),
    };
};

export const buildBallotProofStatement = (
    input: BallotProofStatementInput,
): BallotProofStatement => {
    const challengeDomainDigest = deriveProtocolDigest(
        'ChallengeDomainDigest',
        {
            ballotProofProfileDigest: input.ballotProofProfileDigest,
            challengeDomainLabel:
                input.challengeDomainLabel ??
                'sealed.vote/v1/ballot-proof/challenge',
            receiverEncryptionProfileDigest:
                input.receiverEncryptionProfileDigest,
            scoreMembershipProfileDigest: input.scoreMembershipProfileDigest,
            shareCommitmentMessageBoundCertDigest:
                input.shareCommitmentMessageBoundCertDigest,
            shareCommitmentProfileDigest: input.shareCommitmentProfileDigest,
        },
    );
    const statementPayload: BallotProofStatementPayload = {
        objectType: 'BallotProofStatement',
        objectVersion: 1,
        ceremonyId: input.ceremonyId,
        manifestDigest: input.manifestDigest,
        rosterDigest: input.rosterDigest,
        pollSpecDigest: input.pollSpecDigest,
        thresholdProfileDigest: input.thresholdProfileDigest,
        duplicateBallotPolicyDigest: input.duplicateBallotPolicyDigest,
        scoreDomainDigest: input.scoreDomainDigest,
        tiePolicyDigest: input.tiePolicyDigest,
        topOptionCount: input.topOptionCount,
        optionCount: input.optionCount,
        shareVectorWidth: pvssBallotShareVectorWidth,
        voterIdentityDigest: input.voterIdentityDigest,
        voterRosterPosition: input.voterRosterPosition,
        voterSigningKeyDigest: input.voterSigningKeyDigest,
        actionContextDigest: input.actionContextDigest,
        rosterExternalAcceptanceDigest: input.rosterExternalAcceptanceDigest,
        receiverKeyRoot: input.receiverKeyRoot,
        receiverKeyProofRoot: input.receiverKeyProofRoot,
        receiverPublicKeys: input.receiverPublicKeys,
        receiverPayloads: input.receiverPayloads,
        shareCommitments: input.shareCommitments,
        shareCommitmentProfileDigest: input.shareCommitmentProfileDigest,
        receiverEncryptionProfileDigest: input.receiverEncryptionProfileDigest,
        ballotProofProfileDigest: input.ballotProofProfileDigest,
        scoreMembershipProfileDigest: input.scoreMembershipProfileDigest,
        shareCommitmentMessageBoundCertDigest:
            input.shareCommitmentMessageBoundCertDigest,
        ballotPackageDigest: input.ballotPackageDigest,
        challengeDomainDigest,
    };

    return {
        ...statementPayload,
        ballotProofStatementDigest:
            deriveBallotProofStatementDigest(statementPayload),
    };
};

export const createBallotProofRecordShell = (input: {
    readonly statement: BallotProofStatement;
    readonly proofRoot: ProtocolDigest;
    readonly proofBytesDigest: ProtocolDigest;
    readonly proofSizeBytes: number;
}): BallotProofRecord => {
    const challengeDigest = deriveBallotProofChallengeDigest({
        statement: input.statement,
        proofRoot: input.proofRoot,
        proofBytesDigest: input.proofBytesDigest,
    });
    const proofRecordPayload: BallotProofRecordPayload = {
        objectType: 'BallotProofRecord',
        objectVersion: 1,
        ballotProofStatementDigest: input.statement.ballotProofStatementDigest,
        ballotProofProfileDigest: input.statement.ballotProofProfileDigest,
        proofBackend: 'LaZerStyleLocalLatticeRelation',
        challengeDigest,
        proofRoot: input.proofRoot,
        proofBytesDigest: input.proofBytesDigest,
        proofSizeBytes: input.proofSizeBytes,
    };

    return {
        ...proofRecordPayload,
        ballotProofRecordDigest:
            deriveBallotProofRecordDigest(proofRecordPayload),
    };
};

const createUnavailableProofBackendVerification = (
    operation: string,
    objectDigest?: ProtocolDigest,
): BallotPrivacyVerification => {
    const refusedObjects: RefusalRecord[] = [
        createRefusal(
            'OperationUnavailable',
            `${operation}: ${unavailableProofBackendMessage}`,
            objectDigest,
        ),
    ];

    return {
        ok: false,
        backendAvailable: false,
        statusLabels: [],
        acceptedDigests: [],
        refusedObjects,
        unresolvedReason: 'OperationUnavailable',
    };
};

export const verifyReceiverKeyProof = (input: {
    readonly receiverKeyProof: ReceiverKeyProof;
}): BallotPrivacyVerification =>
    createUnavailableProofBackendVerification(
        'verifyReceiverKeyProof',
        input.receiverKeyProof.receiverKeyProofRoot,
    );

export const verifyBallotProof = (input: {
    readonly statement: BallotProofStatement;
    readonly ballotProof: BallotProofRecord;
}): BallotPrivacyVerification =>
    createUnavailableProofBackendVerification(
        'verifyBallotProof',
        input.ballotProof.ballotProofRecordDigest,
    );

export const verifyClaimBearingBallotPackage = (input: {
    readonly ballotPackage: ClaimBearingBallotPackage;
}): BallotPrivacyVerification =>
    createUnavailableProofBackendVerification(
        'verifyClaimBearingBallotPackage',
        input.ballotPackage.ballotPackageDigest,
    );
