import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import type {
    BallotPrivacyVerification,
    BallotProofRecord,
    BallotProofStatement,
    ProtocolDigest,
    ReceiverKeyProof,
    ReceiverKeyProofRootEvidence,
    ReceiverPayload,
    RefusalRecord,
    ShareCommitment,
} from '@sealed-lattice/types';

import { createRefusal } from '../../common/verification-helpers.js';
import { getBallotPrivacyEncodedShareVectorWidth } from '../encoded-share-layout.js';

import type {
    BallotProofRecordPayload,
    BallotProofStatementInput,
    BallotProofStatementPayload,
    ReceiverPayloadInput,
    ReceiverPayloadPayload,
    ShareCommitmentInput,
    ShareCommitmentPayload,
} from './object-contracts.js';
import {
    collectReceiverReferenceRefusals,
    createReceiverReferenceKey,
    deriveBallotProofChallengeDigest,
    deriveBallotProofRecordDigest,
    deriveBallotProofStatementDigest,
    deriveProofBytesDigest,
    deriveReceiverKeyProofRoot,
    deriveReceiverKeyProofRootEvidenceDigest,
    deriveReceiverPayloadCiphertextRoot,
    deriveReceiverPayloadDigest,
    deriveShareCommitmentDigest,
    describeBallotPrivacyProofBackend,
    isUnknownObject,
    omitProperty,
    proofBytesHexPattern,
    protocolDigestPattern,
    unavailableProofBackendMessage,
} from './object-contracts.js';

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
            aggregateInputEncodingProfileDigest:
                input.aggregateInputEncodingProfileDigest,
            challengeDomainLabel:
                input.challengeDomainLabel ??
                'sealed.vote/v1/ballot-proof/challenge',
            ballotScoreEncodingProfileDigest:
                input.ballotScoreEncodingProfileDigest,
            ballotShareLayoutProfileDigest:
                input.ballotShareLayoutProfileDigest,
            encodedAggregateLayoutDigest: input.encodedAggregateLayoutDigest,
            encodedShareVectorLayoutDigest:
                input.encodedShareVectorLayoutDigest,
            receiverEncryptionProfileDigest:
                input.receiverEncryptionProfileDigest,
            scoreMembershipProfileDigest: input.scoreMembershipProfileDigest,
            shareCommitmentMessageBoundCertDigest:
                input.shareCommitmentMessageBoundCertDigest,
            shareCommitmentProfileDigest: input.shareCommitmentProfileDigest,
        },
    );
    const shareVectorWidth = getBallotPrivacyEncodedShareVectorWidth(
        input.optionCount,
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
        shareVectorWidth,
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
        ballotScoreEncodingProfileDigest:
            input.ballotScoreEncodingProfileDigest,
        ballotShareLayoutProfileDigest: input.ballotShareLayoutProfileDigest,
        aggregateInputEncodingProfileDigest:
            input.aggregateInputEncodingProfileDigest,
        encodedShareVectorLayoutDigest: input.encodedShareVectorLayoutDigest,
        encodedAggregateLayoutDigest: input.encodedAggregateLayoutDigest,
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
    readonly backendStatementDigest?: ProtocolDigest;
    readonly componentBundleStatementDigest?: ProtocolDigest;
    readonly componentProofBundleDigest?: ProtocolDigest;
    readonly relationStatementDigest: ProtocolDigest;
    readonly linearStatementDigest?: ProtocolDigest;
    readonly statementMatrixDigest?: ProtocolDigest;
    readonly targetVectorDigest?: ProtocolDigest;
    readonly proofRoot: ProtocolDigest;
    readonly proofBytesDigest: ProtocolDigest;
    readonly proofEncodingProfileDigest?: ProtocolDigest;
    readonly proofParameterSetDigest?: ProtocolDigest;
    readonly proofSizeBytes: number;
    readonly publicRandomnessDigest?: ProtocolDigest;
}): BallotProofRecord => {
    const challengeDigest = deriveBallotProofChallengeDigest({
        statement: input.statement,
        backendStatementDigest: input.backendStatementDigest,
        componentBundleStatementDigest: input.componentBundleStatementDigest,
        componentProofBundleDigest: input.componentProofBundleDigest,
        relationStatementDigest: input.relationStatementDigest,
        linearStatementDigest: input.linearStatementDigest,
        statementMatrixDigest: input.statementMatrixDigest,
        targetVectorDigest: input.targetVectorDigest,
        proofRoot: input.proofRoot,
        proofBytesDigest: input.proofBytesDigest,
        proofEncodingProfileDigest: input.proofEncodingProfileDigest,
        proofParameterSetDigest: input.proofParameterSetDigest,
        publicRandomnessDigest: input.publicRandomnessDigest,
    });
    const proofRecordPayload: BallotProofRecordPayload = {
        objectType: 'BallotProofRecord',
        objectVersion: 1,
        ballotProofStatementDigest: input.statement.ballotProofStatementDigest,
        ...(input.backendStatementDigest === undefined
            ? {}
            : { backendStatementDigest: input.backendStatementDigest }),
        ...(input.componentBundleStatementDigest === undefined
            ? {}
            : {
                  componentBundleStatementDigest:
                      input.componentBundleStatementDigest,
              }),
        ...(input.componentProofBundleDigest === undefined
            ? {}
            : {
                  componentProofBundleDigest: input.componentProofBundleDigest,
              }),
        relationStatementDigest: input.relationStatementDigest,
        ...(input.linearStatementDigest === undefined
            ? {}
            : { linearStatementDigest: input.linearStatementDigest }),
        ...(input.statementMatrixDigest === undefined
            ? {}
            : { statementMatrixDigest: input.statementMatrixDigest }),
        ...(input.targetVectorDigest === undefined
            ? {}
            : { targetVectorDigest: input.targetVectorDigest }),
        ballotProofProfileDigest: input.statement.ballotProofProfileDigest,
        proofBackend: 'LocalLinearLatticeRelation',
        challengeDigest,
        proofRoot: input.proofRoot,
        proofBytesDigest: input.proofBytesDigest,
        ...(input.proofEncodingProfileDigest === undefined
            ? {}
            : {
                  proofEncodingProfileDigest: input.proofEncodingProfileDigest,
              }),
        ...(input.proofParameterSetDigest === undefined
            ? {}
            : { proofParameterSetDigest: input.proofParameterSetDigest }),
        proofSizeBytes: input.proofSizeBytes,
        ...(input.publicRandomnessDigest === undefined
            ? {}
            : { publicRandomnessDigest: input.publicRandomnessDigest }),
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
        backendStatus: describeBallotPrivacyProofBackend(),
        statusLabels: [],
        acceptedDigests: [],
        refusedObjects,
        unresolvedReason: 'OperationUnavailable',
    };
};

const createBallotPrivacyStructuralRejection = (
    refusedObjects: readonly RefusalRecord[],
): BallotPrivacyVerification => ({
    ok: false,
    backendAvailable: false,
    backendStatus: describeBallotPrivacyProofBackend(),
    statusLabels: [],
    acceptedDigests: [],
    refusedObjects,
    unresolvedReason: refusedObjects[0]?.code ?? 'BallotPackageInvalid',
});

const digestForInvalidComponentInput = (): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        purpose: 'invalid-ballot-proof-component-input-v1',
    });

const collectReceiverKeyProofStructuralRefusals = (
    receiverKeyProof: ReceiverKeyProof,
    proofBytesHex?: string,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const receiverKeyProofPayload = omitProperty(
        receiverKeyProof,
        'receiverKeyProofRoot',
    );
    const expectedReceiverKeyProofRoot = deriveReceiverKeyProofRoot(
        receiverKeyProofPayload,
    );

    if (
        receiverKeyProof.objectType !== 'ReceiverKeyProof' ||
        receiverKeyProof.objectVersion !== 1 ||
        receiverKeyProof.proofBackend !== 'LocalLinearLatticeRelation' ||
        !protocolDigestPattern.test(receiverKeyProof.proofRoot) ||
        (receiverKeyProof.backendStatementDigest !== undefined &&
            !protocolDigestPattern.test(
                receiverKeyProof.backendStatementDigest,
            )) ||
        (receiverKeyProof.linearStatementDigest !== undefined &&
            !protocolDigestPattern.test(
                receiverKeyProof.linearStatementDigest,
            )) ||
        (receiverKeyProof.proofBytesDigest !== undefined &&
            !protocolDigestPattern.test(receiverKeyProof.proofBytesDigest)) ||
        (receiverKeyProof.proofEncodingProfileDigest !== undefined &&
            !protocolDigestPattern.test(
                receiverKeyProof.proofEncodingProfileDigest,
            )) ||
        (receiverKeyProof.proofParameterSetDigest !== undefined &&
            !protocolDigestPattern.test(
                receiverKeyProof.proofParameterSetDigest,
            )) ||
        (receiverKeyProof.publicRandomnessDigest !== undefined &&
            !protocolDigestPattern.test(
                receiverKeyProof.publicRandomnessDigest,
            )) ||
        (receiverKeyProof.proofSizeBytes !== undefined &&
            (!Number.isSafeInteger(receiverKeyProof.proofSizeBytes) ||
                receiverKeyProof.proofSizeBytes <= 0))
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Receiver key proof shell has an invalid canonical shape.',
                receiverKeyProof.receiverKeyProofRoot,
            ),
        );
    }
    const proofMetadataFieldNames = [
        'linearStatementDigest',
        'proofBytesDigest',
        'proofEncodingProfileDigest',
        'proofParameterSetDigest',
        'proofSizeBytes',
        'publicRandomnessDigest',
    ] as const;
    const presentProofMetadataFieldCount = proofMetadataFieldNames.filter(
        (fieldName) => receiverKeyProof[fieldName] !== undefined,
    ).length;
    if (
        presentProofMetadataFieldCount > 0 &&
        presentProofMetadataFieldCount !== proofMetadataFieldNames.length
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Receiver key proof byte metadata must be complete when any proof-byte field is present.',
                receiverKeyProof.receiverKeyProofRoot,
            ),
        );
    }
    if (proofBytesHex !== undefined) {
        if (receiverKeyProof.proofBytesDigest === undefined) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    'Receiver key proof bytes require a proof-byte-bearing receiver key proof record.',
                    receiverKeyProof.receiverKeyProofRoot,
                ),
            );
        } else if (!proofBytesHexPattern.test(proofBytesHex)) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    'Receiver key proof bytes must be non-empty lowercase hexadecimal bytes.',
                    receiverKeyProof.receiverKeyProofRoot,
                ),
            );
        } else {
            const proofSizeBytes = proofBytesHex.length / 2;
            const proofBytesDigest = deriveProofBytesDigest({
                proofBytesHex,
            });
            if (proofSizeBytes !== receiverKeyProof.proofSizeBytes) {
                refusedObjects.push(
                    createRefusal(
                        'BallotPackageInvalid',
                        'Receiver key proof byte length does not match the proof record.',
                        receiverKeyProof.receiverKeyProofRoot,
                    ),
                );
            }
            if (proofBytesDigest !== receiverKeyProof.proofBytesDigest) {
                refusedObjects.push(
                    createRefusal(
                        'BallotPackageInvalid',
                        'Receiver key proof bytes do not match the proof record digest.',
                        receiverKeyProof.receiverKeyProofRoot,
                    ),
                );
            }
        }
    }
    if (
        receiverKeyProof.receiverKeyProofRoot !== expectedReceiverKeyProofRoot
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Receiver key proof root does not match its canonical payload.',
                receiverKeyProof.receiverKeyProofRoot,
            ),
        );
    }

    return refusedObjects;
};

const collectReceiverKeyProofRootEvidenceStructuralRefusals = (
    receiverKeyProofRootEvidence: unknown,
    statement: BallotProofStatement,
): readonly RefusalRecord[] => {
    if (!isUnknownObject(receiverKeyProofRootEvidence)) {
        return [
            createRefusal(
                'BallotPackageInvalid',
                'Receiver-key proof root evidence has an invalid canonical shape.',
                undefined,
            ),
        ];
    }
    const evidence =
        receiverKeyProofRootEvidence as ReceiverKeyProofRootEvidence;
    const refusedObjects: RefusalRecord[] = [];
    const evidencePayload = omitProperty(
        evidence,
        'receiverKeyProofRootEvidenceDigest',
    );
    const expectedEvidenceDigest =
        deriveReceiverKeyProofRootEvidenceDigest(evidencePayload);
    const statementReceiverKeyReferences = new Map(
        statement.receiverPublicKeys.map((receiverKeyReference) => [
            createReceiverReferenceKey(receiverKeyReference),
            receiverKeyReference,
        ]),
    );

    if (
        evidence.objectType !== 'ReceiverKeyProofRootEvidence' ||
        evidence.objectVersion !== 1 ||
        evidence.evidenceStatus !== 'ReceiverKeyProofRootAccepted' ||
        !protocolDigestPattern.test(
            evidence.receiverKeyProofRootEvidenceDigest,
        ) ||
        !protocolDigestPattern.test(evidence.receiverKeyRoot) ||
        !protocolDigestPattern.test(evidence.receiverKeyProofRoot) ||
        !Number.isSafeInteger(evidence.acceptedReceiverKeyProofCount) ||
        evidence.acceptedReceiverKeyProofCount <= 0
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Receiver-key proof root evidence has an invalid canonical shape.',
                evidence.receiverKeyProofRootEvidenceDigest,
            ),
        );
    }
    if (
        evidence.receiverKeyProofRootEvidenceDigest !== expectedEvidenceDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Receiver-key proof root evidence digest does not match its canonical payload.',
                evidence.receiverKeyProofRootEvidenceDigest,
            ),
        );
    }
    refusedObjects.push(
        ...collectReceiverReferenceRefusals({
            label: 'Receiver-key proof root evidence receiver-key references',
            objectDigest: evidence.receiverKeyProofRootEvidenceDigest,
            references: evidence.receiverPublicKeys,
        }),
    );
    if (
        evidence.ceremonyId !== statement.ceremonyId ||
        evidence.manifestDigest !== statement.manifestDigest ||
        evidence.rosterDigest !== statement.rosterDigest ||
        evidence.receiverKeyRoot !== statement.receiverKeyRoot ||
        evidence.receiverKeyProofRoot !== statement.receiverKeyProofRoot ||
        evidence.receiverPublicKeys.length !==
            statement.receiverPublicKeys.length ||
        evidence.acceptedReceiverKeyProofCount !==
            statement.receiverPublicKeys.length
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Receiver-key proof root evidence is not bound to the ballot proof statement receiver set.',
                evidence.receiverKeyProofRootEvidenceDigest,
            ),
        );
    }
    for (const receiverKeyReference of evidence.receiverPublicKeys) {
        const statementReceiverKeyReference =
            statementReceiverKeyReferences.get(
                createReceiverReferenceKey(receiverKeyReference),
            );
        if (
            statementReceiverKeyReference?.receiverPublicKeyDigest !==
            receiverKeyReference.receiverPublicKeyDigest
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    'Receiver-key proof root evidence includes a receiver key outside the ballot proof statement.',
                    evidence.receiverKeyProofRootEvidenceDigest,
                ),
            );
        }
    }

    return refusedObjects;
};

export {
    createUnavailableProofBackendVerification,
    createBallotPrivacyStructuralRejection,
    digestForInvalidComponentInput,
    collectReceiverKeyProofStructuralRefusals,
    collectReceiverKeyProofRootEvidenceStructuralRefusals,
};
