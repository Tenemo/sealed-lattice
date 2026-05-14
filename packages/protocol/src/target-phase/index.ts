import type {
    AcceptedTargetFinalityCheckpoint,
    EvaluationReplayAttestation,
    EvaluationReplayAttestationVerification,
    EvaluationReplayAttestationVerificationInput,
    ProtocolDigest,
    RefusalRecord,
    TargetAcceptedRecord,
    TargetAcceptedRecordVerification,
    TargetAcceptedRecordVerificationInput,
    TargetFinalityRecord,
    TargetFinalityVerification,
    TopKDecryptionShareShell,
    TopKDecryptionShareShellVerification,
    TopKDecryptionShareShellVerificationInput,
} from '@sealed-lattice/types';

import { collectBoardInclusionEvidence } from '../board/shell-evidence.js';
import { deriveProtocolDigest } from '../common/digests.js';
import { verifySignedObjectSignature } from '../common/signatures.js';
import {
    createRefusal,
    isNonNegativeInteger,
    uniqueStrings,
} from '../common/verification-helpers.js';

const targetFinalityIsAccepted = (
    record: TargetFinalityRecord,
    verification: TargetFinalityVerification,
): boolean =>
    verification.ok &&
    verification.targetFinalityRecordDigest ===
        record.targetFinalityRecordDigest &&
    verification.finalizedBoardHeadDigest === record.finalizedBoardHeadDigest;

export const deriveAcceptedTargetFinalityCheckpoint = (
    record: TargetFinalityRecord,
    verification: TargetFinalityVerification,
): AcceptedTargetFinalityCheckpoint | undefined =>
    targetFinalityIsAccepted(record, verification)
        ? {
              finalizedBoardHeadDigest: record.finalizedBoardHeadDigest,
              targetFinalityPolicyDigest: record.targetFinalityPolicyDigest,
              targetFinalityRecordDigest: record.targetFinalityRecordDigest,
              targetPhase: record.targetPhase,
              topKEvaluationRecordDigest: record.topKEvaluationRecordDigest,
              witnessPolicyDigest: record.witnessPolicyDigest,
          }
        : undefined;

export const deriveEvaluationReplayAttestationDigest = (
    attestation: Omit<
        EvaluationReplayAttestation,
        'evaluationReplayAttestationDigest' | 'signature'
    >,
): ProtocolDigest =>
    deriveProtocolDigest('EvaluationReplayAttestationDigest', {
        boardPosition: attestation.boardPosition,
        boardSequence: attestation.boardSequence,
        ceremonyId: attestation.ceremonyId,
        deviceEpoch: attestation.deviceEpoch,
        electionManifestDigest: attestation.electionManifestDigest,
        finalizedBoardHeadDigest: attestation.finalizedBoardHeadDigest,
        objectType: attestation.objectType,
        objectVersion: attestation.objectVersion,
        recoveryEpoch: attestation.recoveryEpoch,
        replayContextDigest: attestation.replayContextDigest,
        signerIdentity: attestation.signerIdentity,
        targetFinalityRecordDigest: attestation.targetFinalityRecordDigest,
        topKEvaluationRecordDigest: attestation.topKEvaluationRecordDigest,
    });

export const deriveTargetAcceptedRecordDigest = (
    record: Omit<
        TargetAcceptedRecord,
        'targetAcceptedRecordDigest' | 'signature'
    >,
): ProtocolDigest =>
    deriveProtocolDigest('TargetAcceptedRecordDigest', {
        boardPosition: record.boardPosition,
        boardSequence: record.boardSequence,
        ceremonyId: record.ceremonyId,
        electionManifestDigest: record.electionManifestDigest,
        objectType: record.objectType,
        objectVersion: record.objectVersion,
        optionalEvaluationProofRoot: record.optionalEvaluationProofRoot,
        organizerIdentity: record.organizerIdentity,
        replayAttestationDigests: record.replayAttestationDigests,
        targetFinalityRecordDigest: record.targetFinalityRecordDigest,
        targetPhase: record.targetPhase,
        topKEvaluationRecordDigest: record.topKEvaluationRecordDigest,
    });

export const deriveTopKDecryptionShareDigest = (
    share: Omit<
        TopKDecryptionShareShell,
        'topKDecryptionShareDigest' | 'signature'
    >,
): ProtocolDigest =>
    deriveProtocolDigest('TopKDecryptionShareDigest', {
        boardPosition: share.boardPosition,
        boardSequence: share.boardSequence,
        ceremonyId: share.ceremonyId,
        deviceEpoch: share.deviceEpoch,
        electionManifestDigest: share.electionManifestDigest,
        objectType: share.objectType,
        objectVersion: share.objectVersion,
        recoveryEpoch: share.recoveryEpoch,
        shareRoot: share.shareRoot,
        targetAcceptedRecordDigest: share.targetAcceptedRecordDigest,
        targetFinalityRecordDigest: share.targetFinalityRecordDigest,
        topKEvaluationRecordDigest: share.topKEvaluationRecordDigest,
        trusteeIdentity: share.trusteeIdentity,
    });

const verifyReplayAttestationShape = (
    input: EvaluationReplayAttestationVerificationInput,
): readonly RefusalRecord[] => {
    const { attestation, targetFinalityRecord } = input;
    const refusedObjects: RefusalRecord[] = [];
    const expectedDigest = deriveEvaluationReplayAttestationDigest({
        boardPosition: attestation.boardPosition,
        boardSequence: attestation.boardSequence,
        ceremonyId: attestation.ceremonyId,
        deviceEpoch: attestation.deviceEpoch,
        electionManifestDigest: attestation.electionManifestDigest,
        finalizedBoardHeadDigest: attestation.finalizedBoardHeadDigest,
        objectType: attestation.objectType,
        objectVersion: attestation.objectVersion,
        recoveryEpoch: attestation.recoveryEpoch,
        replayContextDigest: attestation.replayContextDigest,
        signerIdentity: attestation.signerIdentity,
        targetFinalityRecordDigest: attestation.targetFinalityRecordDigest,
        topKEvaluationRecordDigest: attestation.topKEvaluationRecordDigest,
    });

    if (attestation.evaluationReplayAttestationDigest !== expectedDigest) {
        refusedObjects.push(
            createRefusal(
                'ReplayAttestationInvalid',
                'Replay attestation digest does not match its canonical payload.',
                attestation.evaluationReplayAttestationDigest,
                'EvaluationReplayAttestation',
            ),
        );
    }
    if (
        attestation.objectType !== 'EvaluationReplayAttestation' ||
        attestation.objectVersion !== 1 ||
        !isNonNegativeInteger(attestation.boardSequence) ||
        !isNonNegativeInteger(attestation.boardPosition) ||
        !isNonNegativeInteger(attestation.recoveryEpoch) ||
        !isNonNegativeInteger(attestation.deviceEpoch)
    ) {
        refusedObjects.push(
            createRefusal(
                'ReplayAttestationInvalid',
                'Replay attestation object shape is not canonical.',
                attestation.evaluationReplayAttestationDigest,
                'EvaluationReplayAttestation',
            ),
        );
    }
    if (attestation.ceremonyId !== input.boardEvidence.ceremonyId) {
        refusedObjects.push(
            createRefusal(
                'WrongCeremony',
                'Replay attestation ceremony does not match the board evidence.',
                attestation.evaluationReplayAttestationDigest,
                'EvaluationReplayAttestation',
            ),
        );
    }
    if (
        !targetFinalityIsAccepted(
            targetFinalityRecord,
            input.targetFinalityVerification,
        )
    ) {
        refusedObjects.push(
            createRefusal(
                'TargetPhaseAuthorizationFailure',
                'Replay attestation requires an accepted target-finality record.',
                attestation.evaluationReplayAttestationDigest,
                'EvaluationReplayAttestation',
            ),
        );
    }
    if (
        attestation.targetFinalityRecordDigest !==
            targetFinalityRecord.targetFinalityRecordDigest ||
        attestation.finalizedBoardHeadDigest !==
            targetFinalityRecord.finalizedBoardHeadDigest ||
        attestation.topKEvaluationRecordDigest !==
            targetFinalityRecord.topKEvaluationRecordDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'ReplayAttestationInvalid',
                'Replay attestation must bind the accepted top-k proposal and target-finality record.',
                attestation.evaluationReplayAttestationDigest,
                'EvaluationReplayAttestation',
            ),
        );
    }
    if (
        input.attestationInclusionProof.includedObjectType !==
            'EvaluationReplayAttestation' ||
        input.attestationInclusionProof.includedObjectDigest !==
            attestation.evaluationReplayAttestationDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Replay attestation inclusion proof does not bind the attestation.',
                input.attestationInclusionProof.inclusionProofDigest,
                'EvaluationReplayAttestation',
            ),
        );
    }
    if (
        input.attestationInclusionProof.boardSequence !==
            attestation.boardSequence ||
        input.attestationInclusionProof.boardPosition !==
            attestation.boardPosition
    ) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Replay attestation board placement must match its inclusion proof.',
                input.attestationInclusionProof.inclusionProofDigest,
                'EvaluationReplayAttestation',
            ),
        );
    }

    return refusedObjects;
};

const verifyEvaluationReplayAttestationShellUnchecked = (
    input: EvaluationReplayAttestationVerificationInput,
): EvaluationReplayAttestationVerification => {
    const { boardResult, refusedObjects } = collectBoardInclusionEvidence({
        boardEvidence: input.boardEvidence,
        inclusionProof: input.attestationInclusionProof,
        objectRefusals: verifyReplayAttestationShape(input),
    });
    const signatureResult = verifySignedObjectSignature(
        input.attestation.signature,
        {
            objectType: 'EvaluationReplayAttestation',
            objectVersion: 1,
            signerRole: 'Participant',
            signerIdentity: input.attestation.signerIdentity,
            ceremonyId: input.attestation.ceremonyId,
            publicKeyDigest: input.expectedSignerPublicKeyDigest,
            manifestDigest: input.attestation.electionManifestDigest,
            objectRoot: input.attestation.evaluationReplayAttestationDigest,
            boardHeadDigest: input.attestationInclusionProof.boardHeadDigest,
            contextDigest: input.attestation.replayContextDigest,
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
                      input.attestation.evaluationReplayAttestationDigest,
                      input.attestationInclusionProof.inclusionProofDigest,
                  ])
                : [],
        refusedObjects,
        forkEvidence: boardResult.forkEvidence,
        evaluationReplayAttestationDigest:
            refusedObjects.length === 0
                ? input.attestation.evaluationReplayAttestationDigest
                : undefined,
        targetFinalityRecordDigest:
            refusedObjects.length === 0
                ? input.attestation.targetFinalityRecordDigest
                : undefined,
    };
};

export const verifyEvaluationReplayAttestationShell = (
    input: EvaluationReplayAttestationVerificationInput,
): EvaluationReplayAttestationVerification => {
    try {
        return verifyEvaluationReplayAttestationShellUnchecked(input);
    } catch {
        return {
            ok: false,
            statusLabels: [],
            acceptedDigests: [],
            refusedObjects: [
                createRefusal(
                    'ReplayAttestationInvalid',
                    'Replay attestation evidence could not be canonicalized or validated.',
                    undefined,
                    'EvaluationReplayAttestation',
                ),
            ],
        };
    }
};

const verifyTargetAcceptedRecordShape = (
    input: TargetAcceptedRecordVerificationInput,
): readonly RefusalRecord[] => {
    const { targetAcceptedRecord, targetFinalityRecord } = input;
    const refusedObjects: RefusalRecord[] = [];
    const expectedDigest = deriveTargetAcceptedRecordDigest({
        boardPosition: targetAcceptedRecord.boardPosition,
        boardSequence: targetAcceptedRecord.boardSequence,
        ceremonyId: targetAcceptedRecord.ceremonyId,
        electionManifestDigest: targetAcceptedRecord.electionManifestDigest,
        objectType: targetAcceptedRecord.objectType,
        objectVersion: targetAcceptedRecord.objectVersion,
        optionalEvaluationProofRoot:
            targetAcceptedRecord.optionalEvaluationProofRoot,
        organizerIdentity: targetAcceptedRecord.organizerIdentity,
        replayAttestationDigests: targetAcceptedRecord.replayAttestationDigests,
        targetFinalityRecordDigest:
            targetAcceptedRecord.targetFinalityRecordDigest,
        targetPhase: targetAcceptedRecord.targetPhase,
        topKEvaluationRecordDigest:
            targetAcceptedRecord.topKEvaluationRecordDigest,
    });

    if (targetAcceptedRecord.targetAcceptedRecordDigest !== expectedDigest) {
        refusedObjects.push(
            createRefusal(
                'TargetAcceptedRecordInvalid',
                'Target-accepted record digest does not match its canonical payload.',
                targetAcceptedRecord.targetAcceptedRecordDigest,
                'TargetAcceptedRecord',
            ),
        );
    }
    if (
        targetAcceptedRecord.objectType !== 'TargetAcceptedRecord' ||
        targetAcceptedRecord.objectVersion !== 1 ||
        !isNonNegativeInteger(targetAcceptedRecord.boardSequence) ||
        !isNonNegativeInteger(targetAcceptedRecord.boardPosition)
    ) {
        refusedObjects.push(
            createRefusal(
                'TargetAcceptedRecordInvalid',
                'Target-accepted record object shape is not canonical.',
                targetAcceptedRecord.targetAcceptedRecordDigest,
                'TargetAcceptedRecord',
            ),
        );
    }
    if (targetAcceptedRecord.ceremonyId !== input.boardEvidence.ceremonyId) {
        refusedObjects.push(
            createRefusal(
                'WrongCeremony',
                'Target-accepted record ceremony does not match the board evidence.',
                targetAcceptedRecord.targetAcceptedRecordDigest,
                'TargetAcceptedRecord',
            ),
        );
    }
    if (
        !targetFinalityIsAccepted(
            targetFinalityRecord,
            input.targetFinalityVerification,
        )
    ) {
        refusedObjects.push(
            createRefusal(
                'TargetPhaseAuthorizationFailure',
                'Target acceptance requires an accepted target-finality record.',
                targetAcceptedRecord.targetAcceptedRecordDigest,
                'TargetAcceptedRecord',
            ),
        );
    }
    if (
        targetAcceptedRecord.targetFinalityRecordDigest !==
            targetFinalityRecord.targetFinalityRecordDigest ||
        targetAcceptedRecord.topKEvaluationRecordDigest !==
            targetFinalityRecord.topKEvaluationRecordDigest ||
        targetAcceptedRecord.targetPhase !== targetFinalityRecord.targetPhase
    ) {
        refusedObjects.push(
            createRefusal(
                'TargetAcceptedRecordInvalid',
                'Target-accepted record must bind the accepted top-k proposal and target-finality record.',
                targetAcceptedRecord.targetAcceptedRecordDigest,
                'TargetAcceptedRecord',
            ),
        );
    }
    const acceptedReplayAttestationDigestSet = new Set(
        input.acceptedReplayAttestationDigests,
    );
    const missingReplayAttestationDigest =
        targetAcceptedRecord.replayAttestationDigests.find(
            (digest) => !acceptedReplayAttestationDigestSet.has(digest),
        );
    if (
        targetAcceptedRecord.optionalEvaluationProofRoot === null &&
        targetAcceptedRecord.replayAttestationDigests.length === 0
    ) {
        refusedObjects.push(
            createRefusal(
                'TargetAcceptedRecordInvalid',
                'Target-accepted record must bind replay attestations or an optional proof root.',
                targetAcceptedRecord.targetAcceptedRecordDigest,
                'TargetAcceptedRecord',
            ),
        );
    }
    if (missingReplayAttestationDigest !== undefined) {
        refusedObjects.push(
            createRefusal(
                'TargetAcceptedRecordInvalid',
                'Target-accepted record references a replay attestation that was not supplied as accepted.',
                missingReplayAttestationDigest,
                'EvaluationReplayAttestation',
            ),
        );
    }
    if (
        input.targetAcceptedRecordInclusionProof.includedObjectType !==
            'TargetAcceptedRecord' ||
        input.targetAcceptedRecordInclusionProof.includedObjectDigest !==
            targetAcceptedRecord.targetAcceptedRecordDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Target-accepted record inclusion proof does not bind the record.',
                input.targetAcceptedRecordInclusionProof.inclusionProofDigest,
                'TargetAcceptedRecord',
            ),
        );
    }
    if (
        input.targetAcceptedRecordInclusionProof.boardSequence !==
            targetAcceptedRecord.boardSequence ||
        input.targetAcceptedRecordInclusionProof.boardPosition !==
            targetAcceptedRecord.boardPosition
    ) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Target-accepted record board placement must match its inclusion proof.',
                input.targetAcceptedRecordInclusionProof.inclusionProofDigest,
                'TargetAcceptedRecord',
            ),
        );
    }

    return refusedObjects;
};

const verifyTargetAcceptedRecordShellUnchecked = (
    input: TargetAcceptedRecordVerificationInput,
): TargetAcceptedRecordVerification => {
    const { boardResult, refusedObjects } = collectBoardInclusionEvidence({
        boardEvidence: input.boardEvidence,
        inclusionProof: input.targetAcceptedRecordInclusionProof,
        objectRefusals: verifyTargetAcceptedRecordShape(input),
    });
    const signatureResult = verifySignedObjectSignature(
        input.targetAcceptedRecord.signature,
        {
            objectType: 'TargetAcceptedRecord',
            objectVersion: 1,
            signerRole: 'Organizer',
            signerIdentity: input.targetAcceptedRecord.organizerIdentity,
            ceremonyId: input.targetAcceptedRecord.ceremonyId,
            publicKeyDigest: input.expectedOrganizerPublicKeyDigest,
            manifestDigest: input.targetAcceptedRecord.electionManifestDigest,
            objectRoot: input.targetAcceptedRecord.targetAcceptedRecordDigest,
            boardHeadDigest:
                input.targetAcceptedRecordInclusionProof.boardHeadDigest,
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
                      input.targetAcceptedRecord.targetAcceptedRecordDigest,
                      input.targetAcceptedRecordInclusionProof
                          .inclusionProofDigest,
                  ])
                : [],
        refusedObjects,
        forkEvidence: boardResult.forkEvidence,
        targetAcceptedRecordDigest:
            refusedObjects.length === 0
                ? input.targetAcceptedRecord.targetAcceptedRecordDigest
                : undefined,
        targetFinalityRecordDigest:
            refusedObjects.length === 0
                ? input.targetAcceptedRecord.targetFinalityRecordDigest
                : undefined,
    };
};

export const verifyTargetAcceptedRecordShell = (
    input: TargetAcceptedRecordVerificationInput,
): TargetAcceptedRecordVerification => {
    try {
        return verifyTargetAcceptedRecordShellUnchecked(input);
    } catch {
        return {
            ok: false,
            statusLabels: [],
            acceptedDigests: [],
            refusedObjects: [
                createRefusal(
                    'TargetAcceptedRecordInvalid',
                    'Target-accepted record evidence could not be canonicalized or validated.',
                    undefined,
                    'TargetAcceptedRecord',
                ),
            ],
        };
    }
};

const verifyTopKDecryptionShareShape = (
    input: TopKDecryptionShareShellVerificationInput,
): readonly RefusalRecord[] => {
    const { decryptionShare, targetAcceptedRecord } = input;
    const refusedObjects: RefusalRecord[] = [];
    const expectedDigest = deriveTopKDecryptionShareDigest({
        boardPosition: decryptionShare.boardPosition,
        boardSequence: decryptionShare.boardSequence,
        ceremonyId: decryptionShare.ceremonyId,
        deviceEpoch: decryptionShare.deviceEpoch,
        electionManifestDigest: decryptionShare.electionManifestDigest,
        objectType: decryptionShare.objectType,
        objectVersion: decryptionShare.objectVersion,
        recoveryEpoch: decryptionShare.recoveryEpoch,
        shareRoot: decryptionShare.shareRoot,
        targetAcceptedRecordDigest: decryptionShare.targetAcceptedRecordDigest,
        targetFinalityRecordDigest: decryptionShare.targetFinalityRecordDigest,
        topKEvaluationRecordDigest: decryptionShare.topKEvaluationRecordDigest,
        trusteeIdentity: decryptionShare.trusteeIdentity,
    });

    if (decryptionShare.topKDecryptionShareDigest !== expectedDigest) {
        refusedObjects.push(
            createRefusal(
                'DecryptionShareInvalid',
                'Decryption-share shell digest does not match its canonical payload.',
                decryptionShare.topKDecryptionShareDigest,
                'TopKDecryptionShare',
            ),
        );
    }
    if (
        decryptionShare.objectType !== 'TopKDecryptionShare' ||
        decryptionShare.objectVersion !== 1 ||
        !isNonNegativeInteger(decryptionShare.boardSequence) ||
        !isNonNegativeInteger(decryptionShare.boardPosition) ||
        !isNonNegativeInteger(decryptionShare.recoveryEpoch) ||
        !isNonNegativeInteger(decryptionShare.deviceEpoch)
    ) {
        refusedObjects.push(
            createRefusal(
                'DecryptionShareInvalid',
                'Decryption-share shell object shape is not canonical.',
                decryptionShare.topKDecryptionShareDigest,
                'TopKDecryptionShare',
            ),
        );
    }
    if (decryptionShare.ceremonyId !== input.boardEvidence.ceremonyId) {
        refusedObjects.push(
            createRefusal(
                'WrongCeremony',
                'Decryption-share shell ceremony does not match the board evidence.',
                decryptionShare.topKDecryptionShareDigest,
                'TopKDecryptionShare',
            ),
        );
    }
    if (
        !input.targetAcceptedRecordVerification.ok ||
        input.targetAcceptedRecordVerification.targetAcceptedRecordDigest !==
            targetAcceptedRecord.targetAcceptedRecordDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'TargetPhaseAuthorizationFailure',
                'Decryption-share shell requires an accepted target record.',
                decryptionShare.topKDecryptionShareDigest,
                'TopKDecryptionShare',
            ),
        );
    }
    if (
        decryptionShare.targetAcceptedRecordDigest !==
            targetAcceptedRecord.targetAcceptedRecordDigest ||
        decryptionShare.targetFinalityRecordDigest !==
            targetAcceptedRecord.targetFinalityRecordDigest ||
        decryptionShare.topKEvaluationRecordDigest !==
            targetAcceptedRecord.topKEvaluationRecordDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'DecryptionShareInvalid',
                'Decryption-share shell must bind the accepted target and target-finality record.',
                decryptionShare.topKDecryptionShareDigest,
                'TopKDecryptionShare',
            ),
        );
    }
    if (
        input.decryptionShareInclusionProof.includedObjectType !==
            'TopKDecryptionShare' ||
        input.decryptionShareInclusionProof.includedObjectDigest !==
            decryptionShare.topKDecryptionShareDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Decryption-share shell inclusion proof does not bind the share.',
                input.decryptionShareInclusionProof.inclusionProofDigest,
                'TopKDecryptionShare',
            ),
        );
    }
    if (
        input.decryptionShareInclusionProof.boardSequence !==
            decryptionShare.boardSequence ||
        input.decryptionShareInclusionProof.boardPosition !==
            decryptionShare.boardPosition
    ) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Decryption-share shell board placement must match its inclusion proof.',
                input.decryptionShareInclusionProof.inclusionProofDigest,
                'TopKDecryptionShare',
            ),
        );
    }

    return refusedObjects;
};

const verifyTopKDecryptionShareShellUnchecked = (
    input: TopKDecryptionShareShellVerificationInput,
): TopKDecryptionShareShellVerification => {
    const { boardResult, refusedObjects } = collectBoardInclusionEvidence({
        boardEvidence: input.boardEvidence,
        inclusionProof: input.decryptionShareInclusionProof,
        objectRefusals: verifyTopKDecryptionShareShape(input),
    });
    const signatureResult = verifySignedObjectSignature(
        input.decryptionShare.signature,
        {
            objectType: 'TopKDecryptionShare',
            objectVersion: 1,
            signerRole: 'Trustee',
            signerIdentity: input.decryptionShare.trusteeIdentity,
            ceremonyId: input.decryptionShare.ceremonyId,
            publicKeyDigest: input.expectedTrusteePublicKeyDigest,
            manifestDigest: input.decryptionShare.electionManifestDigest,
            objectRoot: input.decryptionShare.topKDecryptionShareDigest,
            boardHeadDigest:
                input.decryptionShareInclusionProof.boardHeadDigest,
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
                      input.decryptionShare.topKDecryptionShareDigest,
                      input.decryptionShareInclusionProof.inclusionProofDigest,
                  ])
                : [],
        refusedObjects,
        forkEvidence: boardResult.forkEvidence,
        topKDecryptionShareDigest:
            refusedObjects.length === 0
                ? input.decryptionShare.topKDecryptionShareDigest
                : undefined,
        targetAcceptedRecordDigest:
            refusedObjects.length === 0
                ? input.decryptionShare.targetAcceptedRecordDigest
                : undefined,
        targetFinalityRecordDigest:
            refusedObjects.length === 0
                ? input.decryptionShare.targetFinalityRecordDigest
                : undefined,
    };
};

export const verifyTopKDecryptionShareShell = (
    input: TopKDecryptionShareShellVerificationInput,
): TopKDecryptionShareShellVerification => {
    try {
        return verifyTopKDecryptionShareShellUnchecked(input);
    } catch {
        return {
            ok: false,
            statusLabels: [],
            acceptedDigests: [],
            refusedObjects: [
                createRefusal(
                    'DecryptionShareInvalid',
                    'Decryption-share shell evidence could not be canonicalized or validated.',
                    undefined,
                    'TopKDecryptionShare',
                ),
            ],
        };
    }
};
