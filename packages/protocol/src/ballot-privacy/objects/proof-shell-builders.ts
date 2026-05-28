import { deriveProtocolHash } from '@sealed-lattice/crypto';
import type {
    BallotPrivacyVerification,
    BallotProofRecord,
    BallotProofStatement,
    ProtocolHash,
    ReceiverKeyProof,
    ReceiverKeyProofRootEvidence,
    ReceiverPayload,
    RefusalRecord,
    ShareCommitment,
} from '@sealed-lattice/types';

import { createRefusal } from '../../common/verification-helpers.js';
import { getBallotPrivacyEncodedShareVectorWidth } from '../protocol-parameters.js';

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
    deriveBallotProofChallengeHash,
    deriveBallotProofRecordHash,
    deriveBallotProofStatementHash,
    deriveProofBytesHash,
    deriveReceiverKeyProofRoot,
    deriveReceiverKeyProofRootEvidenceHash,
    deriveReceiverPayloadCiphertextRoot,
    deriveReceiverPayloadHash,
    deriveShareCommitmentHash,
    describeBallotPrivacyProofBackend,
    isUnknownObject,
    omitProperty,
    proofBytesHexPattern,
    protocolHashPattern,
    unavailableProofBackendMessage,
} from './object-contracts.js';

export const createReceiverPayloadShell = (
    input: ReceiverPayloadInput,
): ReceiverPayload => {
    const ciphertextRoot = deriveReceiverPayloadCiphertextRoot({
        ceremonyId: input.ceremonyId,
        manifestHash: input.manifestHash,
        payloadContextHash: input.payloadContextHash,
        receiverEncryptionProfileHash: input.receiverEncryptionProfileHash,
        receiverIdentity: input.receiverIdentity,
        receiverPublicKeyHash: input.receiverPublicKeyHash,
        receiverRosterPosition: input.receiverRosterPosition,
        ciphertextBodyHash: input.ciphertextBodyHash,
    });
    const receiverPayloadPayload: ReceiverPayloadPayload = {
        objectType: 'ReceiverPayload',
        objectVersion: 1,
        ...input,
        receiverPayloadCiphertextRoot: ciphertextRoot,
    };

    return {
        ...receiverPayloadPayload,
        receiverPayloadHash: deriveReceiverPayloadHash(receiverPayloadPayload),
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
        shareCommitmentHash: deriveShareCommitmentHash(shareCommitmentPayload),
    };
};

export const buildBallotProofStatement = (
    input: BallotProofStatementInput,
): BallotProofStatement => {
    const challengeDomainHash = deriveProtocolHash('ChallengeDomainHash', {
        ballotProofProfileHash: input.ballotProofProfileHash,
        aggregateInputEncodingProfileHash:
            input.aggregateInputEncodingProfileHash,
        challengeDomainLabel:
            input.challengeDomainLabel ??
            'sealed.vote/v1/ballot-proof/challenge',
        ballotScoreEncodingProfileHash: input.ballotScoreEncodingProfileHash,
        ballotShareLayoutProfileHash: input.ballotShareLayoutProfileHash,
        encodedAggregateLayoutHash: input.encodedAggregateLayoutHash,
        encodedShareVectorLayoutHash: input.encodedShareVectorLayoutHash,
        receiverEncryptionProfileHash: input.receiverEncryptionProfileHash,
        scoreMembershipProfileHash: input.scoreMembershipProfileHash,
        shareCommitmentMessageBoundCertHash:
            input.shareCommitmentMessageBoundCertHash,
        shareCommitmentProfileHash: input.shareCommitmentProfileHash,
    });
    const shareVectorWidth = getBallotPrivacyEncodedShareVectorWidth(
        input.optionCount,
    );
    const statementPayload: BallotProofStatementPayload = {
        objectType: 'BallotProofStatement',
        objectVersion: 1,
        ceremonyId: input.ceremonyId,
        manifestHash: input.manifestHash,
        rosterHash: input.rosterHash,
        pollSpecHash: input.pollSpecHash,
        thresholdProfileHash: input.thresholdProfileHash,
        duplicateBallotPolicyHash: input.duplicateBallotPolicyHash,
        scoreDomainHash: input.scoreDomainHash,
        tiePolicyHash: input.tiePolicyHash,
        topOptionCount: input.topOptionCount,
        optionCount: input.optionCount,
        shareVectorWidth,
        voterIdentityHash: input.voterIdentityHash,
        voterRosterPosition: input.voterRosterPosition,
        voterSigningKeyHash: input.voterSigningKeyHash,
        actionContextHash: input.actionContextHash,
        rosterExternalAcceptanceHash: input.rosterExternalAcceptanceHash,
        receiverKeyRoot: input.receiverKeyRoot,
        receiverKeyProofRoot: input.receiverKeyProofRoot,
        receiverPublicKeys: input.receiverPublicKeys,
        receiverPayloads: input.receiverPayloads,
        shareCommitments: input.shareCommitments,
        shareCommitmentProfileHash: input.shareCommitmentProfileHash,
        receiverEncryptionProfileHash: input.receiverEncryptionProfileHash,
        ballotProofProfileHash: input.ballotProofProfileHash,
        scoreMembershipProfileHash: input.scoreMembershipProfileHash,
        ballotScoreEncodingProfileHash: input.ballotScoreEncodingProfileHash,
        ballotShareLayoutProfileHash: input.ballotShareLayoutProfileHash,
        aggregateInputEncodingProfileHash:
            input.aggregateInputEncodingProfileHash,
        encodedShareVectorLayoutHash: input.encodedShareVectorLayoutHash,
        encodedAggregateLayoutHash: input.encodedAggregateLayoutHash,
        shareCommitmentMessageBoundCertHash:
            input.shareCommitmentMessageBoundCertHash,
        ballotPackageHash: input.ballotPackageHash,
        challengeDomainHash,
    };

    return {
        ...statementPayload,
        ballotProofStatementHash:
            deriveBallotProofStatementHash(statementPayload),
    };
};

export const createBallotProofRecordShell = (input: {
    readonly statement: BallotProofStatement;
    readonly backendStatementHash?: ProtocolHash;
    readonly componentBundleStatementHash?: ProtocolHash;
    readonly componentProofBundleHash?: ProtocolHash;
    readonly relationStatementHash: ProtocolHash;
    readonly linearStatementHash?: ProtocolHash;
    readonly statementMatrixHash?: ProtocolHash;
    readonly targetVectorHash?: ProtocolHash;
    readonly proofRoot: ProtocolHash;
    readonly proofBytesHash: ProtocolHash;
    readonly proofEncodingProfileHash?: ProtocolHash;
    readonly proofParameterSetHash?: ProtocolHash;
    readonly proofSizeBytes: number;
    readonly publicRandomnessHash?: ProtocolHash;
}): BallotProofRecord => {
    const challengeHash = deriveBallotProofChallengeHash({
        statement: input.statement,
        backendStatementHash: input.backendStatementHash,
        componentBundleStatementHash: input.componentBundleStatementHash,
        componentProofBundleHash: input.componentProofBundleHash,
        relationStatementHash: input.relationStatementHash,
        linearStatementHash: input.linearStatementHash,
        statementMatrixHash: input.statementMatrixHash,
        targetVectorHash: input.targetVectorHash,
        proofRoot: input.proofRoot,
        proofBytesHash: input.proofBytesHash,
        proofEncodingProfileHash: input.proofEncodingProfileHash,
        proofParameterSetHash: input.proofParameterSetHash,
        publicRandomnessHash: input.publicRandomnessHash,
    });
    const proofRecordPayload: BallotProofRecordPayload = {
        objectType: 'BallotProofRecord',
        objectVersion: 1,
        ballotProofStatementHash: input.statement.ballotProofStatementHash,
        ...(input.backendStatementHash === undefined
            ? {}
            : { backendStatementHash: input.backendStatementHash }),
        ...(input.componentBundleStatementHash === undefined
            ? {}
            : {
                  componentBundleStatementHash:
                      input.componentBundleStatementHash,
              }),
        ...(input.componentProofBundleHash === undefined
            ? {}
            : {
                  componentProofBundleHash: input.componentProofBundleHash,
              }),
        relationStatementHash: input.relationStatementHash,
        ...(input.linearStatementHash === undefined
            ? {}
            : { linearStatementHash: input.linearStatementHash }),
        ...(input.statementMatrixHash === undefined
            ? {}
            : { statementMatrixHash: input.statementMatrixHash }),
        ...(input.targetVectorHash === undefined
            ? {}
            : { targetVectorHash: input.targetVectorHash }),
        ballotProofProfileHash: input.statement.ballotProofProfileHash,
        proofBackend: 'LocalLinearLatticeRelation',
        challengeHash,
        proofRoot: input.proofRoot,
        proofBytesHash: input.proofBytesHash,
        ...(input.proofEncodingProfileHash === undefined
            ? {}
            : {
                  proofEncodingProfileHash: input.proofEncodingProfileHash,
              }),
        ...(input.proofParameterSetHash === undefined
            ? {}
            : { proofParameterSetHash: input.proofParameterSetHash }),
        proofSizeBytes: input.proofSizeBytes,
        ...(input.publicRandomnessHash === undefined
            ? {}
            : { publicRandomnessHash: input.publicRandomnessHash }),
    };

    return {
        ...proofRecordPayload,
        ballotProofRecordHash: deriveBallotProofRecordHash(proofRecordPayload),
    };
};

const createUnavailableProofBackendVerification = (
    operation: string,
    objectHash?: ProtocolHash,
): BallotPrivacyVerification => {
    const refusedObjects: RefusalRecord[] = [
        createRefusal(
            'OperationUnavailable',
            `${operation}: ${unavailableProofBackendMessage}`,
            objectHash,
        ),
    ];

    return {
        ok: false,
        backendAvailable: false,
        backendStatus: describeBallotPrivacyProofBackend(),
        statusLabels: [],
        acceptedHashes: [],
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
    acceptedHashes: [],
    refusedObjects,
    unresolvedReason: refusedObjects[0]?.code ?? 'BallotPackageInvalid',
});

const hashForInvalidComponentInput = (): ProtocolHash =>
    deriveProtocolHash('ChallengeDomainHash', {
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
        !protocolHashPattern.test(receiverKeyProof.proofRoot) ||
        (receiverKeyProof.backendStatementHash !== undefined &&
            !protocolHashPattern.test(receiverKeyProof.backendStatementHash)) ||
        (receiverKeyProof.linearStatementHash !== undefined &&
            !protocolHashPattern.test(receiverKeyProof.linearStatementHash)) ||
        (receiverKeyProof.proofBytesHash !== undefined &&
            !protocolHashPattern.test(receiverKeyProof.proofBytesHash)) ||
        (receiverKeyProof.proofEncodingProfileHash !== undefined &&
            !protocolHashPattern.test(
                receiverKeyProof.proofEncodingProfileHash,
            )) ||
        (receiverKeyProof.proofParameterSetHash !== undefined &&
            !protocolHashPattern.test(
                receiverKeyProof.proofParameterSetHash,
            )) ||
        (receiverKeyProof.publicRandomnessHash !== undefined &&
            !protocolHashPattern.test(receiverKeyProof.publicRandomnessHash)) ||
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
        'linearStatementHash',
        'proofBytesHash',
        'proofEncodingProfileHash',
        'proofParameterSetHash',
        'proofSizeBytes',
        'publicRandomnessHash',
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
        if (receiverKeyProof.proofBytesHash === undefined) {
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
            const proofBytesHash = deriveProofBytesHash({
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
            if (proofBytesHash !== receiverKeyProof.proofBytesHash) {
                refusedObjects.push(
                    createRefusal(
                        'BallotPackageInvalid',
                        'Receiver key proof bytes do not match the proof record hash.',
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
        'receiverKeyProofRootEvidenceHash',
    );
    const expectedEvidenceHash =
        deriveReceiverKeyProofRootEvidenceHash(evidencePayload);
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
        !protocolHashPattern.test(evidence.receiverKeyProofRootEvidenceHash) ||
        !protocolHashPattern.test(evidence.receiverKeyRoot) ||
        !protocolHashPattern.test(evidence.receiverKeyProofRoot) ||
        !Number.isSafeInteger(evidence.acceptedReceiverKeyProofCount) ||
        evidence.acceptedReceiverKeyProofCount <= 0
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Receiver-key proof root evidence has an invalid canonical shape.',
                evidence.receiverKeyProofRootEvidenceHash,
            ),
        );
    }
    if (evidence.receiverKeyProofRootEvidenceHash !== expectedEvidenceHash) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Receiver-key proof root evidence hash does not match its canonical payload.',
                evidence.receiverKeyProofRootEvidenceHash,
            ),
        );
    }
    refusedObjects.push(
        ...collectReceiverReferenceRefusals({
            label: 'Receiver-key proof root evidence receiver-key references',
            objectHash: evidence.receiverKeyProofRootEvidenceHash,
            references: evidence.receiverPublicKeys,
        }),
    );
    if (
        evidence.ceremonyId !== statement.ceremonyId ||
        evidence.manifestHash !== statement.manifestHash ||
        evidence.rosterHash !== statement.rosterHash ||
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
                evidence.receiverKeyProofRootEvidenceHash,
            ),
        );
    }
    for (const receiverKeyReference of evidence.receiverPublicKeys) {
        const statementReceiverKeyReference =
            statementReceiverKeyReferences.get(
                createReceiverReferenceKey(receiverKeyReference),
            );
        if (
            statementReceiverKeyReference?.receiverPublicKeyHash !==
            receiverKeyReference.receiverPublicKeyHash
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    'Receiver-key proof root evidence includes a receiver key outside the ballot proof statement.',
                    evidence.receiverKeyProofRootEvidenceHash,
                ),
            );
        }
    }

    return refusedObjects;
};

export {
    createUnavailableProofBackendVerification,
    createBallotPrivacyStructuralRejection,
    hashForInvalidComponentInput,
    collectReceiverKeyProofStructuralRefusals,
    collectReceiverKeyProofRootEvidenceStructuralRefusals,
};
