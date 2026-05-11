import type {
    CastReceipt,
    CastReceiptVerification,
    CastReceiptVerificationInput,
    CloseRecord,
    CloseRecordVerification,
    CloseRecordVerificationInput,
    ProtocolDigest,
    RefusalRecord,
    SignedBoardHead,
} from '@sealed-lattice/types';

import {
    verifyBoardConsistency,
    verifyInclusionProof,
} from '../board/index.js';
import { deriveProtocolDigest } from '../common/digests.js';
import { verifySignedObjectSignature } from '../common/signatures.js';
import {
    createRefusal,
    uniqueStrings,
} from '../common/verification-helpers.js';

const isNonNegativeInteger = (value: number): boolean =>
    Number.isInteger(value) && value >= 0;

const buildHeadMap = (
    heads: readonly SignedBoardHead[],
): Map<ProtocolDigest, SignedBoardHead> =>
    new Map(heads.map((head) => [head.headDigest, head]));

export const deriveCastReceiptDigest = (
    receipt: Omit<CastReceipt, 'castReceiptDigest' | 'signature'>,
): ProtocolDigest =>
    deriveProtocolDigest('CastReceiptDigest', {
        ballotPackageDigest: receipt.ballotPackageDigest,
        boardPosition: receipt.boardPosition,
        boardSeq: receipt.boardSeq,
        ceremonyId: receipt.ceremonyId,
        contextDigest: receipt.contextDigest,
        deviceEpoch: receipt.deviceEpoch,
        electionManifestDigest: receipt.electionManifestDigest,
        objectType: receipt.objectType,
        objectVersion: receipt.objectVersion,
        recoveryEpoch: receipt.recoveryEpoch,
        voterIdentity: receipt.voterIdentity,
    });

export const derivePostVotingClosedContextDigest = (input: {
    readonly ceremonyId: string;
    readonly closeRecordDigest: ProtocolDigest;
    readonly electionManifestDigest: ProtocolDigest;
    readonly votingClosedBoardHeadDigest: ProtocolDigest;
}): ProtocolDigest =>
    deriveProtocolDigest('PostVotingClosedContextDigest', {
        ceremonyId: input.ceremonyId,
        closeRecordDigest: input.closeRecordDigest,
        electionManifestDigest: input.electionManifestDigest,
        votingClosedBoardHeadDigest: input.votingClosedBoardHeadDigest,
    });

export const deriveCloseRecordDigest = (
    closeRecord: Omit<
        CloseRecord,
        'closeRecordDigest' | 'postVotingClosedContextDigest' | 'signature'
    >,
): ProtocolDigest =>
    deriveProtocolDigest('CloseRecordDigest', {
        boardPosition: closeRecord.boardPosition,
        boardSeq: closeRecord.boardSeq,
        ceremonyId: closeRecord.ceremonyId,
        closeKind: closeRecord.closeKind,
        closedBoardHeadDigest: closeRecord.closedBoardHeadDigest,
        electionManifestDigest: closeRecord.electionManifestDigest,
        objectType: closeRecord.objectType,
        objectVersion: closeRecord.objectVersion,
        organizerIdentity: closeRecord.organizerIdentity,
    });

const verifyCastReceiptShape = (
    input: CastReceiptVerificationInput,
): readonly RefusalRecord[] => {
    const { receipt } = input;
    const refusedObjects: RefusalRecord[] = [];
    const expectedDigest = deriveCastReceiptDigest({
        ballotPackageDigest: receipt.ballotPackageDigest,
        boardPosition: receipt.boardPosition,
        boardSeq: receipt.boardSeq,
        ceremonyId: receipt.ceremonyId,
        contextDigest: receipt.contextDigest,
        deviceEpoch: receipt.deviceEpoch,
        electionManifestDigest: receipt.electionManifestDigest,
        objectType: receipt.objectType,
        objectVersion: receipt.objectVersion,
        recoveryEpoch: receipt.recoveryEpoch,
        voterIdentity: receipt.voterIdentity,
    });

    if (receipt.castReceiptDigest !== expectedDigest) {
        refusedObjects.push(
            createRefusal(
                'CastReceiptInvalid',
                'Cast receipt digest does not match its canonical payload.',
                receipt.castReceiptDigest,
                'CastReceipt',
            ),
        );
    }
    if (
        receipt.objectType !== 'CastReceipt' ||
        receipt.objectVersion !== 1 ||
        !isNonNegativeInteger(receipt.boardSeq) ||
        !isNonNegativeInteger(receipt.boardPosition) ||
        !isNonNegativeInteger(receipt.recoveryEpoch) ||
        !isNonNegativeInteger(receipt.deviceEpoch)
    ) {
        refusedObjects.push(
            createRefusal(
                'CastReceiptInvalid',
                'Cast receipt object shape is not canonical.',
                receipt.castReceiptDigest,
                'CastReceipt',
            ),
        );
    }
    if (receipt.ceremonyId !== input.boardEvidence.ceremonyId) {
        refusedObjects.push(
            createRefusal(
                'WrongCeremony',
                'Cast receipt ceremony does not match the board evidence.',
                receipt.castReceiptDigest,
                'CastReceipt',
            ),
        );
    }
    if (
        receipt.electionManifestDigest !== input.expectedElectionManifestDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'CastReceiptInvalid',
                'Cast receipt does not bind the expected election manifest.',
                receipt.castReceiptDigest,
                'CastReceipt',
            ),
        );
    }
    if (
        input.receiptInclusionProof.includedObjectType !== 'CastReceipt' ||
        input.receiptInclusionProof.includedObjectDigest !==
            receipt.castReceiptDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Cast receipt inclusion proof does not bind the receipt.',
                input.receiptInclusionProof.inclusionProofDigest,
                'CastReceipt',
            ),
        );
    }
    if (
        input.receiptInclusionProof.boardSeq !== receipt.boardSeq ||
        input.receiptInclusionProof.boardPosition !== receipt.boardPosition
    ) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Cast receipt board position must match its inclusion proof.',
                input.receiptInclusionProof.inclusionProofDigest,
                'CastReceipt',
            ),
        );
    }

    return refusedObjects;
};

export const verifyCastReceiptShell = (
    input: CastReceiptVerificationInput,
): CastReceiptVerification => {
    const boardResult = verifyBoardConsistency(input.boardEvidence);
    const headsByDigest = buildHeadMap(input.boardEvidence.signedBoardHeads);
    const refusedObjects: RefusalRecord[] = [
        ...boardResult.refusedObjects,
        ...verifyCastReceiptShape(input),
        ...verifyInclusionProof(input.receiptInclusionProof, headsByDigest),
    ];
    const signatureResult = verifySignedObjectSignature(
        input.receipt.signature,
        {
            objectType: 'CastReceipt',
            objectVersion: 1,
            signerRole: 'Voter',
            signerIdentity: input.receipt.voterIdentity,
            ceremonyId: input.receipt.ceremonyId,
            publicKeyDigest: input.expectedVoterPublicKeyDigest,
            manifestHash: input.expectedElectionManifestDigest,
            objectRoot: input.receipt.castReceiptDigest,
            boardHeadHash: input.receiptInclusionProof.boardHeadDigest,
            contextDigest: input.receipt.contextDigest,
        },
    );
    refusedObjects.push(...signatureResult.refusedObjects);

    return {
        ok: refusedObjects.length === 0,
        statusLabels: boardResult.statusLabels,
        acceptedDigests:
            refusedObjects.length === 0
                ? uniqueStrings([
                      ...boardResult.acceptedDigests,
                      input.receipt.castReceiptDigest,
                      input.receiptInclusionProof.inclusionProofDigest,
                  ])
                : [],
        refusedObjects,
        forkEvidence: boardResult.forkEvidence,
        castReceiptDigest:
            refusedObjects.length === 0
                ? input.receipt.castReceiptDigest
                : undefined,
    };
};

const verifyCloseRecordShape = (
    input: CloseRecordVerificationInput,
): readonly RefusalRecord[] => {
    const { closeRecord } = input;
    const refusedObjects: RefusalRecord[] = [];
    const expectedDigest = deriveCloseRecordDigest({
        boardPosition: closeRecord.boardPosition,
        boardSeq: closeRecord.boardSeq,
        ceremonyId: closeRecord.ceremonyId,
        closeKind: closeRecord.closeKind,
        closedBoardHeadDigest: closeRecord.closedBoardHeadDigest,
        electionManifestDigest: closeRecord.electionManifestDigest,
        objectType: closeRecord.objectType,
        objectVersion: closeRecord.objectVersion,
        organizerIdentity: closeRecord.organizerIdentity,
    });

    if (closeRecord.closeRecordDigest !== expectedDigest) {
        refusedObjects.push(
            createRefusal(
                'CloseRecordInvalid',
                'Close record digest does not match its canonical payload.',
                closeRecord.closeRecordDigest,
                'CloseRecord',
            ),
        );
    }
    if (
        closeRecord.objectType !== 'CloseRecord' ||
        closeRecord.objectVersion !== 1 ||
        !isNonNegativeInteger(closeRecord.boardSeq) ||
        !isNonNegativeInteger(closeRecord.boardPosition)
    ) {
        refusedObjects.push(
            createRefusal(
                'CloseRecordInvalid',
                'Close record object shape is not canonical.',
                closeRecord.closeRecordDigest,
                'CloseRecord',
            ),
        );
    }
    if (closeRecord.ceremonyId !== input.boardEvidence.ceremonyId) {
        refusedObjects.push(
            createRefusal(
                'WrongCeremony',
                'Close record ceremony does not match the board evidence.',
                closeRecord.closeRecordDigest,
                'CloseRecord',
            ),
        );
    }
    if (
        closeRecord.electionManifestDigest !==
        input.expectedElectionManifestDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'CloseRecordInvalid',
                'Close record does not bind the expected election manifest.',
                closeRecord.closeRecordDigest,
                'CloseRecord',
            ),
        );
    }
    if (closeRecord.organizerIdentity !== input.expectedOrganizerIdentity) {
        refusedObjects.push(
            createRefusal(
                'CloseRecordInvalid',
                'Close record organizer does not match the expected identity.',
                closeRecord.closeRecordDigest,
                'CloseRecord',
            ),
        );
    }
    if (
        input.closeRecordInclusionProof.includedObjectType !== 'CloseRecord' ||
        input.closeRecordInclusionProof.includedObjectDigest !==
            closeRecord.closeRecordDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Close record inclusion proof does not bind the record.',
                input.closeRecordInclusionProof.inclusionProofDigest,
                'CloseRecord',
            ),
        );
    }
    if (
        input.closeRecordInclusionProof.boardSeq !== closeRecord.boardSeq ||
        input.closeRecordInclusionProof.boardPosition !==
            closeRecord.boardPosition
    ) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Close record board placement must match its inclusion proof.',
                input.closeRecordInclusionProof.inclusionProofDigest,
                'CloseRecord',
            ),
        );
    }
    if (closeRecord.closeKind === 'VotingClosed') {
        const expectedPostVotingClosedContextDigest =
            derivePostVotingClosedContextDigest({
                ceremonyId: closeRecord.ceremonyId,
                closeRecordDigest: closeRecord.closeRecordDigest,
                electionManifestDigest: closeRecord.electionManifestDigest,
                votingClosedBoardHeadDigest:
                    input.closeRecordInclusionProof.boardHeadDigest,
            });

        if (
            closeRecord.postVotingClosedContextDigest !==
            expectedPostVotingClosedContextDigest
        ) {
            refusedObjects.push(
                createRefusal(
                    'CloseRecordInvalid',
                    'Voting-closed record must bind the post-voting closed context digest.',
                    closeRecord.closeRecordDigest,
                    'CloseRecord',
                ),
            );
        }
    } else if (closeRecord.postVotingClosedContextDigest !== null) {
        refusedObjects.push(
            createRefusal(
                'CloseRecordInvalid',
                'Registration-closed record must not bind a post-voting closed context digest.',
                closeRecord.closeRecordDigest,
                'CloseRecord',
            ),
        );
    }

    return refusedObjects;
};

export const verifyCloseRecordShell = (
    input: CloseRecordVerificationInput,
): CloseRecordVerification => {
    const boardResult = verifyBoardConsistency(input.boardEvidence);
    const headsByDigest = buildHeadMap(input.boardEvidence.signedBoardHeads);
    const refusedObjects: RefusalRecord[] = [
        ...boardResult.refusedObjects,
        ...verifyCloseRecordShape(input),
        ...verifyInclusionProof(input.closeRecordInclusionProof, headsByDigest),
    ];
    if (!headsByDigest.has(input.closeRecord.closedBoardHeadDigest)) {
        refusedObjects.push(
            createRefusal(
                'UnknownBoardHead',
                'Close record binds an unknown closed board head.',
                input.closeRecord.closedBoardHeadDigest,
                'BoardHead',
            ),
        );
    }
    const signatureResult = verifySignedObjectSignature(
        input.closeRecord.signature,
        {
            objectType: 'CloseRecord',
            objectVersion: 1,
            signerRole: 'Organizer',
            signerIdentity: input.closeRecord.organizerIdentity,
            ceremonyId: input.closeRecord.ceremonyId,
            publicKeyDigest: input.expectedOrganizerPublicKeyDigest,
            manifestHash: input.expectedElectionManifestDigest,
            objectRoot: input.closeRecord.closeRecordDigest,
            boardHeadHash: input.closeRecordInclusionProof.boardHeadDigest,
        },
    );
    refusedObjects.push(...signatureResult.refusedObjects);

    return {
        ok: refusedObjects.length === 0,
        statusLabels: boardResult.statusLabels,
        acceptedDigests:
            refusedObjects.length === 0
                ? uniqueStrings([
                      ...boardResult.acceptedDigests,
                      input.closeRecord.closeRecordDigest,
                      input.closeRecordInclusionProof.inclusionProofDigest,
                      ...(input.closeRecord.postVotingClosedContextDigest ===
                      null
                          ? []
                          : [input.closeRecord.postVotingClosedContextDigest]),
                  ])
                : [],
        refusedObjects,
        forkEvidence: boardResult.forkEvidence,
        closeRecordDigest:
            refusedObjects.length === 0
                ? input.closeRecord.closeRecordDigest
                : undefined,
        postVotingClosedContextDigest:
            refusedObjects.length === 0
                ? (input.closeRecord.postVotingClosedContextDigest ?? undefined)
                : undefined,
    };
};
