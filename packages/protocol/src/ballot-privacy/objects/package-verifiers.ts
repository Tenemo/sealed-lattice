import { deriveProtocolDigest } from '@sealed-lattice/crypto';
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
    ClaimBearingBallotPackageVerificationShell,
} from './object-contracts.js';
import {
    createReceiverReferenceKey,
    deriveClaimBearingBallotPackageDigest,
    deriveShareCommitmentDigest,
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
        'shareCommitmentDigest',
    );
    const expectedShareCommitmentDigest = deriveShareCommitmentDigest(
        shareCommitmentPayload,
    );

    if (
        shareCommitment.objectType !== 'ShareCommitment' ||
        shareCommitment.objectVersion !== 1 ||
        !Number.isSafeInteger(shareCommitment.shareVectorWidth) ||
        shareCommitment.shareVectorWidth <= 0 ||
        shareCommitment.shareCommitmentDigest !== expectedShareCommitmentDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Share commitment shell digest or shape is invalid.',
                shareCommitment.shareCommitmentDigest,
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
        const expectedCommitmentBodyDigest = deriveProtocolDigest(
            'ShareCommitmentDigest',
            {
                commitmentPolynomialVector,
                profileDigest: shareCommitment.shareCommitmentProfileDigest,
            },
        );

        if (
            !vectorShapeIsValid ||
            shareCommitment.commitmentBodyDigest !==
                expectedCommitmentBodyDigest
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    'Share commitment polynomial vector is malformed or not bound to the commitment body digest.',
                    shareCommitment.shareCommitmentDigest,
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
                shareCommitment.shareCommitmentDigest,
            ),
        );
    }

    return refusedObjects;
};

const collectClaimBearingPackageStructuralRefusals = (
    ballotPackage: ClaimBearingBallotPackageVerificationShell,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [
        ...collectBallotProofStructuralRefusals(
            ballotPackage.ballotProofStatement,
            ballotPackage.ballotProof,
            ballotPackage.proofBytesHex,
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
    const expectedPackageDigest = isUnknownObject(
        ballotPackage.receiverKeyProofRootEvidence,
    )
        ? deriveClaimBearingBallotPackageDigest({
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
        ballotPackage.ballotPackageDigest !== statement.ballotPackageDigest ||
        expectedPackageDigest === undefined ||
        ballotPackage.ballotPackageDigest !== expectedPackageDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Claim-bearing ballot package shell digest or shape is invalid.',
                ballotPackage.ballotPackageDigest,
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
                ballotPackage.ballotPackageDigest,
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
                ballotPackage.ballotPackageDigest,
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
                ballotPackage.ballotPackageDigest,
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
            payloadReference?.receiverPayloadDigest !==
                receiverPayload.receiverPayloadDigest ||
            payloadReference.receiverPayloadCiphertextRoot !==
                receiverPayload.receiverPayloadCiphertextRoot
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    'Receiver payload shell is not bound to the ballot proof statement reference.',
                    receiverPayload.receiverPayloadDigest,
                ),
            );
        }
        if (
            receiverKeyReference?.receiverPublicKeyDigest !==
                receiverPayload.receiverPublicKeyDigest ||
            receiverPayload.ceremonyId !== statement.ceremonyId ||
            receiverPayload.manifestDigest !== statement.manifestDigest ||
            receiverPayload.rosterDigest !== statement.rosterDigest ||
            receiverPayload.pollSpecDigest !== statement.pollSpecDigest ||
            receiverPayload.voterIdentityDigest !==
                statement.voterIdentityDigest ||
            receiverPayload.receiverEncryptionProfileDigest !==
                statement.receiverEncryptionProfileDigest
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    'Receiver payload shell is not bound to the statement context or receiver key.',
                    receiverPayload.receiverPayloadDigest,
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
            commitmentReference?.shareCommitmentDigest !==
            shareCommitment.shareCommitmentDigest
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    'Share commitment shell is not bound to the ballot proof statement reference.',
                    shareCommitment.shareCommitmentDigest,
                ),
            );
        }
        if (
            receiverKeyReference?.receiverIdentity !==
                shareCommitment.receiverIdentity ||
            receiverKeyReference?.receiverRosterPosition !==
                shareCommitment.receiverRosterPosition ||
            shareCommitment.ceremonyId !== statement.ceremonyId ||
            shareCommitment.manifestDigest !== statement.manifestDigest ||
            shareCommitment.rosterDigest !== statement.rosterDigest ||
            shareCommitment.shareVectorWidth !== statement.shareVectorWidth ||
            shareCommitment.shareCommitmentProfileDigest !==
                statement.shareCommitmentProfileDigest
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    'Share commitment shell is not bound to the statement context or receiver set.',
                    shareCommitment.shareCommitmentDigest,
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
    readonly proofBytesHex?: string;
}): BallotPrivacyVerification => {
    const structuralRefusals = [
        ...collectBallotProofStructuralRefusals(
            input.statement,
            input.ballotProof,
            input.proofBytesHex,
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
            input.ballotProof.ballotProofRecordDigest,
        );
    }

    return createUnavailableProofBackendVerification(
        'verifyBallotProof',
        input.ballotProof.ballotProofRecordDigest,
    );
};

export const verifyClaimBearingBallotPackage = (input: {
    readonly ballotPackage: ClaimBearingBallotPackageVerificationShell;
}): BallotPrivacyVerification => {
    const structuralRefusals = collectClaimBearingPackageStructuralRefusals(
        input.ballotPackage,
    );
    if (structuralRefusals.length > 0) {
        return createBallotPrivacyStructuralRejection(structuralRefusals);
    }
    if (input.ballotPackage.componentProofBundle !== undefined) {
        return createUnavailableProofBackendVerification(
            'verifyClaimBearingBallotPackage',
            input.ballotPackage.ballotPackageDigest,
        );
    }

    return createUnavailableProofBackendVerification(
        'verifyClaimBearingBallotPackage',
        input.ballotPackage.ballotPackageDigest,
    );
};
