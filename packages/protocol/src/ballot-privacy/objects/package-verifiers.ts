import { deriveProtocolHash } from '@sealed-lattice/crypto';
import type {
    BallotPrivacyVerification,
    BallotProofComponentProofBundle,
    BallotProofRecord,
    BallotProofStatement,
    ReceiverKeyProof,
    RefusalRecord,
    ShareCommitment,
} from '@sealed-lattice/types';

import { createRefusal } from '../../common/verification-helpers.js';

import { collectBallotProofStructuralRefusals } from './ballot-proof-structure-checks.js';
import {
    collectBallotProofComponentProofBundleRefusals,
    collectReceiverPayloadStructuralRefusals,
} from './component-and-payload-checks.js';
import type {
    BallotProofComponentProofVerificationInput,
    ScopedRelationBearingBallotPackageVerificationShell,
} from './object-contracts.js';
import {
    createReceiverReferenceKey,
    deriveClaimBearingBallotPackageHash,
    deriveShareCommitmentHash,
    hasOwnProperty,
    isUnknownObject,
    omitProperty,
    shareCommitmentModuleDegree,
    shareCommitmentModuleRank,
    shareCommitmentModulus,
} from './object-contracts.js';
import {
    collectReceiverKeyProofRootEvidenceStructuralRefusals,
    collectReceiverKeyProofStructuralRefusals,
    createBallotPrivacyStructuralRejection,
    createUnavailableProofBackendVerification,
} from './proof-shell-builders.js';

const collectShareCommitmentStructuralRefusals = (
    shareCommitment: ShareCommitment,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const shareCommitmentPayload = omitProperty(
        shareCommitment,
        'shareCommitmentHash',
    );
    const expectedShareCommitmentHash = deriveShareCommitmentHash(
        shareCommitmentPayload,
    );

    if (
        shareCommitment.objectType !== 'ShareCommitment' ||
        shareCommitment.objectVersion !== 1 ||
        !Number.isSafeInteger(shareCommitment.shareVectorWidth) ||
        shareCommitment.shareVectorWidth <= 0 ||
        shareCommitment.shareCommitmentHash !== expectedShareCommitmentHash
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Share commitment shell hash or shape is invalid.',
                shareCommitment.shareCommitmentHash,
            ),
        );
    }
    if (shareCommitment.commitmentPolynomialVector !== undefined) {
        const commitmentPolynomialVector =
            shareCommitment.commitmentPolynomialVector;
        const vectorShapeIsValid =
            commitmentPolynomialVector.length === shareCommitmentModuleRank &&
            commitmentPolynomialVector.every(
                (commitmentPolynomial) =>
                    commitmentPolynomial.length ===
                        shareCommitmentModuleDegree &&
                    commitmentPolynomial.every((coefficient) => {
                        if (!/^(?:0|[1-9][0-9]*)$/u.test(coefficient)) {
                            return false;
                        }

                        return BigInt(coefficient) < shareCommitmentModulus;
                    }),
            );
        const expectedCommitmentBodyHash = deriveProtocolHash(
            'ShareCommitmentHash',
            {
                commitmentPolynomialVector,
                profileHash: shareCommitment.shareCommitmentProfileHash,
            },
        );

        if (
            !vectorShapeIsValid ||
            shareCommitment.commitmentBodyHash !== expectedCommitmentBodyHash
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    'Share commitment polynomial vector is malformed or not bound to the commitment body hash.',
                    shareCommitment.shareCommitmentHash,
                ),
            );
        }
    }
    if (
        hasOwnProperty(shareCommitment, 'openingRandomness') ||
        hasOwnProperty(shareCommitment, 'receiverShareVector') ||
        hasOwnProperty(shareCommitment, 'proofWitness')
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Share commitment shell must not expose witness material.',
                shareCommitment.shareCommitmentHash,
            ),
        );
    }

    return refusedObjects;
};

const collectScopedRelationBearingPackageStructuralRefusals = (
    ballotPackage: ScopedRelationBearingBallotPackageVerificationShell,
    options: {
        readonly casualMicroRosterAcknowledged?: boolean;
    } = {},
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [
        ...collectBallotProofStructuralRefusals(
            ballotPackage.ballotProofStatement,
            ballotPackage.ballotProof,
            ballotPackage.proofBytesHex,
            {
                casualMicroRosterAcknowledged:
                    options.casualMicroRosterAcknowledged,
                claimBearingPackage: true,
                dynamicRosterProfileEvidence:
                    ballotPackage.dynamicRosterProfileEvidence,
            },
        ),
        ...collectReceiverKeyProofRootEvidenceStructuralRefusals(
            ballotPackage.receiverKeyProofRootEvidence,
            ballotPackage.ballotProofStatement,
        ),
        ...collectBallotProofComponentProofBundleRefusals({
            ballotProof: ballotPackage.ballotProof,
            componentProofBundle: ballotPackage.componentProofBundle,
            componentProofInputs: ballotPackage.componentProofInputs,
            statement: ballotPackage.ballotProofStatement,
        }),
    ];
    const statement = ballotPackage.ballotProofStatement;
    const statementReceiverKeyReferences = new Map(
        statement.receiverPublicKeys.map((receiverKeyReference) => [
            createReceiverReferenceKey(receiverKeyReference),
            receiverKeyReference,
        ]),
    );
    const statementPayloadReferences = new Map(
        statement.receiverPayloads.map((payloadReference) => [
            createReceiverReferenceKey(payloadReference),
            payloadReference,
        ]),
    );
    const statementCommitmentReferences = new Map(
        statement.shareCommitments.map((commitmentReference) => [
            createReceiverReferenceKey(commitmentReference),
            commitmentReference,
        ]),
    );
    const expectedPackageHash = isUnknownObject(
        ballotPackage.receiverKeyProofRootEvidence,
    )
        ? deriveClaimBearingBallotPackageHash({
              ballotProofStatement: statement,
              receiverKeyProofRootEvidence:
                  ballotPackage.receiverKeyProofRootEvidence,
              receiverPayloads: ballotPackage.receiverPayloads,
              shareCommitments: ballotPackage.shareCommitments,
          })
        : undefined;

    if (
        ballotPackage.objectType !== 'ClaimBearingBallotPackage' ||
        ballotPackage.objectVersion !== 1 ||
        ballotPackage.ballotPackageHash !== statement.ballotPackageHash ||
        expectedPackageHash === undefined ||
        ballotPackage.ballotPackageHash !== expectedPackageHash
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Claim-bearing ballot package shell hash or shape is invalid.',
                ballotPackage.ballotPackageHash,
            ),
        );
    }
    if (
        ballotPackage.componentProofBundle !== undefined &&
        ballotPackage.proofBytesHex === undefined
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Claim-bearing ballot package verification requires the public ballot proof bytes when a component proof bundle is supplied.',
                ballotPackage.ballotPackageHash,
            ),
        );
    }
    if (
        ballotPackage.receiverPayloads.length !==
        statement.receiverPayloads.length
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Claim-bearing ballot package must include every receiver payload referenced by the statement.',
                ballotPackage.ballotPackageHash,
            ),
        );
    }
    if (
        ballotPackage.shareCommitments.length !==
        statement.shareCommitments.length
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Claim-bearing ballot package must include every share commitment referenced by the statement.',
                ballotPackage.ballotPackageHash,
            ),
        );
    }
    for (const receiverPayload of ballotPackage.receiverPayloads) {
        refusedObjects.push(
            ...collectReceiverPayloadStructuralRefusals(receiverPayload),
        );
        const receiverReferenceKey =
            createReceiverReferenceKey(receiverPayload);
        const payloadReference =
            statementPayloadReferences.get(receiverReferenceKey);
        const receiverKeyReference =
            statementReceiverKeyReferences.get(receiverReferenceKey);
        if (
            payloadReference?.receiverPayloadHash !==
                receiverPayload.receiverPayloadHash ||
            payloadReference.receiverPayloadCiphertextRoot !==
                receiverPayload.receiverPayloadCiphertextRoot
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    'Receiver payload shell is not bound to the ballot proof statement reference.',
                    receiverPayload.receiverPayloadHash,
                ),
            );
        }
        if (
            receiverKeyReference?.receiverPublicKeyHash !==
                receiverPayload.receiverPublicKeyHash ||
            receiverPayload.ceremonyId !== statement.ceremonyId ||
            receiverPayload.manifestHash !== statement.manifestHash ||
            receiverPayload.rosterHash !== statement.rosterHash ||
            receiverPayload.pollSpecHash !== statement.pollSpecHash ||
            receiverPayload.voterIdentityHash !== statement.voterIdentityHash ||
            receiverPayload.receiverEncryptionProfileHash !==
                statement.receiverEncryptionProfileHash
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    'Receiver payload shell is not bound to the statement context or receiver key.',
                    receiverPayload.receiverPayloadHash,
                ),
            );
        }
    }
    for (const shareCommitment of ballotPackage.shareCommitments) {
        refusedObjects.push(
            ...collectShareCommitmentStructuralRefusals(shareCommitment),
        );
        const receiverReferenceKey =
            createReceiverReferenceKey(shareCommitment);
        const commitmentReference =
            statementCommitmentReferences.get(receiverReferenceKey);
        const receiverKeyReference =
            statementReceiverKeyReferences.get(receiverReferenceKey);
        if (
            commitmentReference?.shareCommitmentHash !==
            shareCommitment.shareCommitmentHash
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    'Share commitment shell is not bound to the ballot proof statement reference.',
                    shareCommitment.shareCommitmentHash,
                ),
            );
        }
        if (
            receiverKeyReference?.receiverIdentity !==
                shareCommitment.receiverIdentity ||
            receiverKeyReference?.receiverRosterPosition !==
                shareCommitment.receiverRosterPosition ||
            shareCommitment.ceremonyId !== statement.ceremonyId ||
            shareCommitment.manifestHash !== statement.manifestHash ||
            shareCommitment.rosterHash !== statement.rosterHash ||
            shareCommitment.shareVectorWidth !== statement.shareVectorWidth ||
            shareCommitment.shareCommitmentProfileHash !==
                statement.shareCommitmentProfileHash
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    'Share commitment shell is not bound to the statement context or receiver set.',
                    shareCommitment.shareCommitmentHash,
                ),
            );
        }
    }

    return refusedObjects;
};

export const verifyReceiverKeyProof = (input: {
    readonly receiverKeyProof: ReceiverKeyProof;
    readonly proofBytesHex?: string;
}): BallotPrivacyVerification => {
    const structuralRefusals = collectReceiverKeyProofStructuralRefusals(
        input.receiverKeyProof,
        input.proofBytesHex,
    );
    if (structuralRefusals.length > 0) {
        return createBallotPrivacyStructuralRejection(structuralRefusals);
    }

    return createUnavailableProofBackendVerification(
        'verifyReceiverKeyProof',
        input.receiverKeyProof.receiverKeyProofRoot,
    );
};

export const verifyBallotProof = (input: {
    readonly statement: BallotProofStatement;
    readonly ballotProof: BallotProofRecord;
    readonly componentProofBundle?: BallotProofComponentProofBundle;
    readonly componentProofInputs?: readonly BallotProofComponentProofVerificationInput[];
    readonly dynamicRosterProfileEvidence?: ScopedRelationBearingBallotPackageVerificationShell['dynamicRosterProfileEvidence'];
    readonly proofBytesHex?: string;
    readonly casualMicroRosterAcknowledged?: boolean;
}): BallotPrivacyVerification => {
    const structuralRefusals = [
        ...collectBallotProofStructuralRefusals(
            input.statement,
            input.ballotProof,
            input.proofBytesHex,
            {
                casualMicroRosterAcknowledged:
                    input.casualMicroRosterAcknowledged,
                dynamicRosterProfileEvidence:
                    input.dynamicRosterProfileEvidence,
            },
        ),
        ...collectBallotProofComponentProofBundleRefusals({
            ballotProof: input.ballotProof,
            componentProofBundle: input.componentProofBundle,
            componentProofInputs: input.componentProofInputs,
            statement: input.statement,
        }),
    ];
    if (structuralRefusals.length > 0) {
        return createBallotPrivacyStructuralRejection(structuralRefusals);
    }
    if (input.componentProofBundle !== undefined) {
        return createUnavailableProofBackendVerification(
            'verifyBallotProof',
            input.ballotProof.ballotProofRecordHash,
        );
    }

    return createUnavailableProofBackendVerification(
        'verifyBallotProof',
        input.ballotProof.ballotProofRecordHash,
    );
};

export const verifyClaimBearingBallotPackage = (input: {
    readonly ballotPackage: ScopedRelationBearingBallotPackageVerificationShell;
    readonly casualMicroRosterAcknowledged?: boolean;
}): BallotPrivacyVerification => {
    const structuralRefusals =
        collectScopedRelationBearingPackageStructuralRefusals(
            input.ballotPackage,
            {
                casualMicroRosterAcknowledged:
                    input.casualMicroRosterAcknowledged,
            },
        );
    if (structuralRefusals.length > 0) {
        return createBallotPrivacyStructuralRejection(structuralRefusals);
    }
    if (input.ballotPackage.componentProofBundle !== undefined) {
        return createUnavailableProofBackendVerification(
            'verifyClaimBearingBallotPackage',
            input.ballotPackage.ballotPackageHash,
        );
    }

    return createUnavailableProofBackendVerification(
        'verifyClaimBearingBallotPackage',
        input.ballotPackage.ballotPackageHash,
    );
};
