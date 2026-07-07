import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import type {
    CastReceipt,
    CastReceiptVerification,
    CastReceiptVerificationInput,
    CloseRecord,
    CloseRecordVerification,
    CloseRecordVerificationInput,
    ProtocolHash,
    RefusalRecord,
} from '@sealed-lattice/types';

import {
    buildSignedBoardShellVerificationBase,
    collectSignedBoardInclusionEvidence,
} from '../board/shell-evidence.js';
import {
    createRefusal,
    defaultSignedRootContextHash,
    isNonNegativeInteger,
    verificationExceptionMessage,
} from '../common/verification-helpers.js';

export const deriveCastReceiptHash = (
    receipt: Omit<CastReceipt, 'castReceiptHash' | 'signature'>,
): ProtocolHash =>
    deriveCanonicalObjectHash({
        boardPosition: receipt.boardPosition,
        boardSequence: receipt.boardSequence,
        ceremonyId: receipt.ceremonyId,
        contextHash: receipt.contextHash,
        deviceEpoch: receipt.deviceEpoch,
        electionManifestHash: receipt.electionManifestHash,
        encryptedBallotHash: receipt.encryptedBallotHash,
        objectType: receipt.objectType,
        recoveryEpoch: receipt.recoveryEpoch,
        voterIdentity: receipt.voterIdentity,
    });

export const derivePostVotingClosedContextHash = (input: {
    readonly ceremonyId: string;
    readonly closeRecordHash: ProtocolHash;
    readonly electionManifestHash: ProtocolHash;
    readonly votingClosedBoardHeadHash: ProtocolHash;
}): ProtocolHash =>
    deriveCanonicalObjectHash({
        objectType: 'PostVotingClosedContext',
        ceremonyId: input.ceremonyId,
        closeRecordHash: input.closeRecordHash,
        electionManifestHash: input.electionManifestHash,
        votingClosedBoardHeadHash: input.votingClosedBoardHeadHash,
    });

export const deriveCloseRecordHash = (
    closeRecord: Omit<
        CloseRecord,
        'closeRecordHash' | 'postVotingClosedContextHash' | 'signature'
    >,
): ProtocolHash =>
    deriveCanonicalObjectHash({
        boardPosition: closeRecord.boardPosition,
        boardSequence: closeRecord.boardSequence,
        ceremonyId: closeRecord.ceremonyId,
        closeKind: closeRecord.closeKind,
        closedBoardHeadHash: closeRecord.closedBoardHeadHash,
        electionManifestHash: closeRecord.electionManifestHash,
        objectType: closeRecord.objectType,
        organizerIdentity: closeRecord.organizerIdentity,
    });

const verifyCastReceiptShape = (
    input: CastReceiptVerificationInput,
): readonly RefusalRecord[] => {
    const { receipt } = input;
    const refusedObjects: RefusalRecord[] = [];
    const expectedHash = deriveCastReceiptHash({
        boardPosition: receipt.boardPosition,
        boardSequence: receipt.boardSequence,
        ceremonyId: receipt.ceremonyId,
        contextHash: receipt.contextHash,
        deviceEpoch: receipt.deviceEpoch,
        electionManifestHash: receipt.electionManifestHash,
        encryptedBallotHash: receipt.encryptedBallotHash,
        objectType: receipt.objectType,
        recoveryEpoch: receipt.recoveryEpoch,
        voterIdentity: receipt.voterIdentity,
    });

    if (receipt.castReceiptHash !== expectedHash) {
        refusedObjects.push(
            createRefusal(
                'CastReceiptInvalid',
                'Cast receipt hash does not match its canonical payload.',
                receipt.castReceiptHash,
                'CastReceipt',
            ),
        );
    }
    if (
        receipt.objectType !== 'CastReceipt' ||
        !isNonNegativeInteger(receipt.boardSequence) ||
        !isNonNegativeInteger(receipt.boardPosition) ||
        !isNonNegativeInteger(receipt.recoveryEpoch) ||
        !isNonNegativeInteger(receipt.deviceEpoch)
    ) {
        refusedObjects.push(
            createRefusal(
                'CastReceiptInvalid',
                'Cast receipt object shape is not canonical.',
                receipt.castReceiptHash,
                'CastReceipt',
            ),
        );
    }
    if (receipt.ceremonyId !== input.boardEvidence.ceremonyId) {
        refusedObjects.push(
            createRefusal(
                'WrongCeremony',
                'Cast receipt ceremony does not match the board evidence.',
                receipt.castReceiptHash,
                'CastReceipt',
            ),
        );
    }
    if (receipt.electionManifestHash !== input.expectedElectionManifestHash) {
        refusedObjects.push(
            createRefusal(
                'CastReceiptInvalid',
                'Cast receipt does not bind the expected election manifest.',
                receipt.castReceiptHash,
                'CastReceipt',
            ),
        );
    }
    if (
        input.receiptInclusionProof.includedObjectType !== 'CastReceipt' ||
        input.receiptInclusionProof.includedObjectHash !==
            receipt.castReceiptHash
    ) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Cast receipt inclusion proof does not bind the receipt.',
                input.receiptInclusionProof.inclusionProofHash,
                'CastReceipt',
            ),
        );
    }
    if (
        input.receiptInclusionProof.boardSequence !== receipt.boardSequence ||
        input.receiptInclusionProof.boardPosition !== receipt.boardPosition
    ) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Cast receipt board position must match its inclusion proof.',
                input.receiptInclusionProof.inclusionProofHash,
                'CastReceipt',
            ),
        );
    }

    return refusedObjects;
};

const verifyCastReceiptShellUnchecked = (
    input: CastReceiptVerificationInput,
): CastReceiptVerification => {
    const evidence = collectSignedBoardInclusionEvidence({
        boardEvidence: input.boardEvidence,
        inclusionProof: input.receiptInclusionProof,
        objectRefusals: verifyCastReceiptShape(input),
        signature: input.receipt.signature,
        signatureExpectation: {
            objectType: 'CastReceipt',
            signerRole: 'Voter',
            signerIdentity: input.receipt.voterIdentity,
            ceremonyId: input.receipt.ceremonyId,
            publicKeyHash: input.expectedVoterPublicKeyHash,
            manifestHash: input.expectedElectionManifestHash,
            objectRoot: input.receipt.castReceiptHash,
            boardHeadHash: input.receiptInclusionProof.boardHeadHash,
            contextHash: input.receipt.contextHash,
            recoveryEpoch: input.receipt.recoveryEpoch,
            deviceEpoch: input.receipt.deviceEpoch,
        },
        acceptedObjectHash: input.receipt.castReceiptHash,
    });
    const verificationBase = buildSignedBoardShellVerificationBase(evidence);

    return {
        ...verificationBase,
        castReceiptHash: verificationBase.isValid
            ? input.receipt.castReceiptHash
            : undefined,
    };
};

export const verifyCastReceiptShell = (
    input: CastReceiptVerificationInput,
): CastReceiptVerification => {
    try {
        return verifyCastReceiptShellUnchecked(input);
    } catch (error) {
        return {
            isValid: false,
            refusedObjects: [
                createRefusal(
                    'CastReceiptInvalid',
                    verificationExceptionMessage(
                        'Cast receipt evidence could not be canonicalized or validated.',
                        error,
                    ),
                ),
            ],
        };
    }
};

const verifyCloseRecordShape = (
    input: CloseRecordVerificationInput,
): readonly RefusalRecord[] => {
    const { closeRecord } = input;
    const refusedObjects: RefusalRecord[] = [];
    const expectedHash = deriveCloseRecordHash({
        boardPosition: closeRecord.boardPosition,
        boardSequence: closeRecord.boardSequence,
        ceremonyId: closeRecord.ceremonyId,
        closeKind: closeRecord.closeKind,
        closedBoardHeadHash: closeRecord.closedBoardHeadHash,
        electionManifestHash: closeRecord.electionManifestHash,
        objectType: closeRecord.objectType,
        organizerIdentity: closeRecord.organizerIdentity,
    });

    if (closeRecord.closeRecordHash !== expectedHash) {
        refusedObjects.push(
            createRefusal(
                'CloseRecordInvalid',
                'Close record hash does not match its canonical payload.',
                closeRecord.closeRecordHash,
                'CloseRecord',
            ),
        );
    }
    if (
        closeRecord.objectType !== 'CloseRecord' ||
        !isNonNegativeInteger(closeRecord.boardSequence) ||
        !isNonNegativeInteger(closeRecord.boardPosition)
    ) {
        refusedObjects.push(
            createRefusal(
                'CloseRecordInvalid',
                'Close record object shape is not canonical.',
                closeRecord.closeRecordHash,
                'CloseRecord',
            ),
        );
    }
    if (closeRecord.ceremonyId !== input.boardEvidence.ceremonyId) {
        refusedObjects.push(
            createRefusal(
                'WrongCeremony',
                'Close record ceremony does not match the board evidence.',
                closeRecord.closeRecordHash,
                'CloseRecord',
            ),
        );
    }
    if (
        closeRecord.electionManifestHash !== input.expectedElectionManifestHash
    ) {
        refusedObjects.push(
            createRefusal(
                'CloseRecordInvalid',
                'Close record does not bind the expected election manifest.',
                closeRecord.closeRecordHash,
                'CloseRecord',
            ),
        );
    }
    if (closeRecord.organizerIdentity !== input.expectedOrganizerIdentity) {
        refusedObjects.push(
            createRefusal(
                'CloseRecordInvalid',
                'Close record organizer does not match the expected identity.',
                closeRecord.closeRecordHash,
                'CloseRecord',
            ),
        );
    }
    if (
        input.closeRecordInclusionProof.includedObjectType !== 'CloseRecord' ||
        input.closeRecordInclusionProof.includedObjectHash !==
            closeRecord.closeRecordHash
    ) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Close record inclusion proof does not bind the record.',
                input.closeRecordInclusionProof.inclusionProofHash,
                'CloseRecord',
            ),
        );
    }
    if (
        input.closeRecordInclusionProof.boardSequence !==
            closeRecord.boardSequence ||
        input.closeRecordInclusionProof.boardPosition !==
            closeRecord.boardPosition
    ) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Close record board placement must match its inclusion proof.',
                input.closeRecordInclusionProof.inclusionProofHash,
                'CloseRecord',
            ),
        );
    }
    if (closeRecord.closeKind === 'VotingClosed') {
        const expectedPostVotingClosedContextHash =
            derivePostVotingClosedContextHash({
                ceremonyId: closeRecord.ceremonyId,
                closeRecordHash: closeRecord.closeRecordHash,
                electionManifestHash: closeRecord.electionManifestHash,
                votingClosedBoardHeadHash:
                    input.closeRecordInclusionProof.boardHeadHash,
            });

        if (
            closeRecord.postVotingClosedContextHash !==
            expectedPostVotingClosedContextHash
        ) {
            refusedObjects.push(
                createRefusal(
                    'CloseRecordInvalid',
                    'Voting-closed record must bind the post-voting closed context hash.',
                    closeRecord.closeRecordHash,
                    'CloseRecord',
                ),
            );
        }
    } else if (closeRecord.postVotingClosedContextHash !== null) {
        refusedObjects.push(
            createRefusal(
                'CloseRecordInvalid',
                'Registration-closed record must not bind a post-voting closed context hash.',
                closeRecord.closeRecordHash,
                'CloseRecord',
            ),
        );
    }

    return refusedObjects;
};

const verifyCloseRecordShellUnchecked = (
    input: CloseRecordVerificationInput,
): CloseRecordVerification => {
    const evidence = collectSignedBoardInclusionEvidence({
        boardEvidence: input.boardEvidence,
        extraAcceptedHashes:
            input.closeRecord.postVotingClosedContextHash === null
                ? []
                : [input.closeRecord.postVotingClosedContextHash],
        inclusionProof: input.closeRecordInclusionProof,
        objectRefusals: verifyCloseRecordShape(input),
        signature: input.closeRecord.signature,
        signatureExpectation: {
            objectType: 'CloseRecord',
            signerRole: 'Organizer',
            signerIdentity: input.closeRecord.organizerIdentity,
            ceremonyId: input.closeRecord.ceremonyId,
            publicKeyHash: input.expectedOrganizerPublicKeyHash,
            manifestHash: input.expectedElectionManifestHash,
            objectRoot: input.closeRecord.closeRecordHash,
            boardHeadHash: input.closeRecordInclusionProof.boardHeadHash,
            contextHash:
                input.closeRecord.postVotingClosedContextHash ??
                defaultSignedRootContextHash,
            recoveryEpoch: 0,
            deviceEpoch: 0,
        },
        acceptedObjectHash: input.closeRecord.closeRecordHash,
    });
    const { headsByHash, refusedObjects } = evidence;
    if (!headsByHash.has(input.closeRecord.closedBoardHeadHash)) {
        refusedObjects.push(
            createRefusal(
                'UnknownBoardHead',
                'Close record binds an unknown closed board head.',
                input.closeRecord.closedBoardHeadHash,
                'BoardHead',
            ),
        );
    }
    const closeRecordInclusionHead = headsByHash.get(
        input.closeRecordInclusionProof.boardHeadHash,
    );
    if (
        closeRecordInclusionHead?.previousHeadHash !==
        input.closeRecord.closedBoardHeadHash
    ) {
        refusedObjects.push(
            createRefusal(
                'CloseRecordInvalid',
                'Close record inclusion must extend the closed board head.',
                input.closeRecord.closeRecordHash,
                'CloseRecord',
            ),
        );
    }
    const verificationBase = buildSignedBoardShellVerificationBase(evidence);

    return {
        ...verificationBase,
        closeRecordHash: verificationBase.isValid
            ? input.closeRecord.closeRecordHash
            : undefined,
        postVotingClosedContextHash: verificationBase.isValid
            ? (input.closeRecord.postVotingClosedContextHash ?? undefined)
            : undefined,
    };
};

export const verifyCloseRecordShell = (
    input: CloseRecordVerificationInput,
): CloseRecordVerification => {
    try {
        return verifyCloseRecordShellUnchecked(input);
    } catch (error) {
        return {
            isValid: false,
            refusedObjects: [
                createRefusal(
                    'CloseRecordInvalid',
                    verificationExceptionMessage(
                        'Close record evidence could not be canonicalized or validated.',
                        error,
                    ),
                ),
            ],
        };
    }
};
