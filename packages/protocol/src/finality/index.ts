import {
    deriveProtocolDigest,
    verifySignedObjectSignature,
} from '@sealed-lattice/crypto';
import type {
    ConflictingHeadEvidence,
    ProtocolDigest,
    ProtocolVerificationStatusLabel,
    RefusalRecord,
    TargetFinalityCheckpoint,
    TargetFinalityPolicy,
    TargetProposal,
    TargetFinalityRecord,
    TargetFinalityVerification,
    TargetFinalityVerificationInput,
    WitnessCheckpoint,
    WitnessPolicy,
} from '@sealed-lattice/types';

import {
    verifyBoardConsistency,
    verifyInclusionProof,
} from '../board/index.js';
import {
    buildBoardHeadMap,
    compareCanonicalStrings,
    createRefusal,
    defaultSignedRootContextDigest,
    isProtocolDigestString,
    signedObjectRootByteLength,
    uniqueStrings,
} from '../common/verification-helpers.js';

export const deriveWitnessCheckpointDigest = (
    checkpoint: Omit<WitnessCheckpoint, 'checkpointDigest' | 'signature'>,
): ProtocolDigest =>
    deriveProtocolDigest('WitnessCheckpointDigest', {
        ceremonyId: checkpoint.ceremonyId,
        objectType: checkpoint.objectType,
        objectVersion: checkpoint.objectVersion,
        targetFinalityCheckpointDigest:
            checkpoint.targetFinalityCheckpointDigest,
        targetFinalityPolicyDigest: checkpoint.targetFinalityPolicyDigest,
        targetFinalityScope: checkpoint.targetFinalityScope,
        targetProposalDigest: checkpoint.targetProposalDigest,
        witnessIdentity: checkpoint.witnessIdentity,
        witnessPolicyDigest: checkpoint.witnessPolicyDigest,
    });

export const deriveTargetProposalDigest = (
    proposal: Omit<TargetProposal, 'targetProposalDigest'>,
): ProtocolDigest =>
    deriveProtocolDigest('TargetProposalDigest', {
        targetCiphertextDigest: proposal.targetCiphertextDigest,
        topKCiphertextDigest: proposal.topKCiphertextDigest,
        ceremonyId: proposal.ceremonyId,
        electionManifestDigest: proposal.electionManifestDigest,
        evaluationContextDigest: proposal.evaluationContextDigest,
        evaluationProofProfileDigest: proposal.evaluationProofProfileDigest,
        publicSlotMaskDigest: proposal.publicSlotMaskDigest,
        targetFinalityPolicyDigest: proposal.targetFinalityPolicyDigest,
        targetLayoutDigest: proposal.targetLayoutDigest,
        topKEvaluationRecordDigest: proposal.topKEvaluationRecordDigest,
    });

export const deriveTargetFinalityCheckpointDigest = (
    checkpoint: Omit<
        TargetFinalityCheckpoint,
        'targetFinalityCheckpointDigest'
    >,
): ProtocolDigest =>
    deriveProtocolDigest('TargetFinalityCheckpointDigest', {
        boardPolicyDigest: checkpoint.boardPolicyDigest,
        targetCiphertextDigest: checkpoint.targetCiphertextDigest,
        topKCiphertextDigest: checkpoint.topKCiphertextDigest,
        ceremonyId: checkpoint.ceremonyId,
        electionManifestDigest: checkpoint.electionManifestDigest,
        evaluationContextDigest: checkpoint.evaluationContextDigest,
        evaluationProofProfileDigest: checkpoint.evaluationProofProfileDigest,
        finalizedBoardHeadDigest: checkpoint.finalizedBoardHeadDigest,
        objectType: checkpoint.objectType,
        objectVersion: checkpoint.objectVersion,
        publicSlotMaskDigest: checkpoint.publicSlotMaskDigest,
        targetFinalityPolicyDigest: checkpoint.targetFinalityPolicyDigest,
        targetLayoutDigest: checkpoint.targetLayoutDigest,
        targetProposalDigest: checkpoint.targetProposalDigest,
        topKEvaluationRecordDigest: checkpoint.topKEvaluationRecordDigest,
        witnessPolicyDigest: checkpoint.witnessPolicyDigest,
    });

export const deriveWitnessPolicyDigest = (
    policy: Omit<WitnessPolicy, 'witnessPolicyDigest'>,
): ProtocolDigest =>
    deriveProtocolDigest('WitnessPolicyDigest', {
        totalWitnesses: policy.totalWitnesses,
        witnessIdentities: [...policy.witnessIdentities].sort(
            compareCanonicalStrings,
        ),
        witnessQuorum: policy.witnessQuorum,
    });

export const deriveTargetFinalityPolicyDigest = (
    policy: Omit<TargetFinalityPolicy, 'targetFinalityPolicyDigest'>,
): ProtocolDigest =>
    deriveProtocolDigest('TargetFinalityPolicyDigest', {
        targetFinalityScope: policy.targetFinalityScope,
        totalWitnesses: policy.totalWitnesses,
        witnessQuorum: policy.witnessQuorum,
    });

export const deriveTargetFinalityRecordDigest = (
    record: Omit<TargetFinalityRecord, 'targetFinalityRecordDigest'>,
): ProtocolDigest =>
    deriveProtocolDigest('TargetFinalityRecordDigest', {
        ceremonyId: record.ceremonyId,
        inclusionProof: record.inclusionProof,
        objectType: record.objectType,
        objectVersion: record.objectVersion,
        targetFinalityCheckpointDigest:
            record.targetFinalityCheckpoint.targetFinalityCheckpointDigest,
        targetFinalityPolicyDigest: record.targetFinalityPolicyDigest,
        targetFinalityScope: record.targetFinalityScope,
        targetProposalDigest: record.targetProposalDigest,
        witnessCheckpoints: record.witnessCheckpoints.map(
            (checkpoint) => checkpoint.checkpointDigest,
        ),
        witnessPolicyDigest: record.witnessPolicyDigest,
    });

const deriveWitnessEquivocationEvidenceDigest = (
    evidence: Omit<ConflictingHeadEvidence, 'evidenceDigest'>,
): ProtocolDigest =>
    deriveProtocolDigest('WitnessEquivocationEvidenceDigest', {
        boardPolicyDigest: evidence.boardPolicyDigest,
        ceremonyId: evidence.ceremonyId,
        equivocatingWitnessIdentities:
            evidence.equivocatingWitnessIdentities ?? [],
        leftBoardHeadDigest: evidence.leftBoardHeadDigest,
        rightBoardHeadDigest: evidence.rightBoardHeadDigest,
        targetFinalityScope: evidence.targetFinalityScope ?? null,
    });

const verifyTargetRecordShape = (
    input: TargetFinalityVerificationInput,
    record: TargetFinalityRecord = input.record,
): readonly RefusalRecord[] => {
    const { targetFinalityPolicy, witnessPolicy } = input;
    const checkpoint = record.targetFinalityCheckpoint;
    const refusedObjects: RefusalRecord[] = [];
    const expectedRecordDigest = deriveTargetFinalityRecordDigest({
        ceremonyId: record.ceremonyId,
        inclusionProof: record.inclusionProof,
        objectType: record.objectType,
        objectVersion: record.objectVersion,
        targetFinalityCheckpoint: checkpoint,
        targetFinalityPolicyDigest: record.targetFinalityPolicyDigest,
        targetFinalityScope: record.targetFinalityScope,
        targetProposalDigest: record.targetProposalDigest,
        witnessCheckpoints: record.witnessCheckpoints,
        witnessPolicyDigest: record.witnessPolicyDigest,
    });
    const expectedProposalDigest = deriveTargetProposalDigest({
        targetCiphertextDigest: checkpoint.targetCiphertextDigest,
        topKCiphertextDigest: checkpoint.topKCiphertextDigest,
        ceremonyId: checkpoint.ceremonyId,
        electionManifestDigest: checkpoint.electionManifestDigest,
        evaluationContextDigest: checkpoint.evaluationContextDigest,
        evaluationProofProfileDigest: checkpoint.evaluationProofProfileDigest,
        publicSlotMaskDigest: checkpoint.publicSlotMaskDigest,
        targetFinalityPolicyDigest: checkpoint.targetFinalityPolicyDigest,
        targetLayoutDigest: checkpoint.targetLayoutDigest,
        topKEvaluationRecordDigest: checkpoint.topKEvaluationRecordDigest,
    });
    const expectedCheckpointDigest = deriveTargetFinalityCheckpointDigest({
        boardPolicyDigest: checkpoint.boardPolicyDigest,
        targetCiphertextDigest: checkpoint.targetCiphertextDigest,
        topKCiphertextDigest: checkpoint.topKCiphertextDigest,
        ceremonyId: checkpoint.ceremonyId,
        electionManifestDigest: checkpoint.electionManifestDigest,
        evaluationContextDigest: checkpoint.evaluationContextDigest,
        evaluationProofProfileDigest: checkpoint.evaluationProofProfileDigest,
        finalizedBoardHeadDigest: checkpoint.finalizedBoardHeadDigest,
        objectType: checkpoint.objectType,
        objectVersion: checkpoint.objectVersion,
        publicSlotMaskDigest: checkpoint.publicSlotMaskDigest,
        targetFinalityPolicyDigest: checkpoint.targetFinalityPolicyDigest,
        targetLayoutDigest: checkpoint.targetLayoutDigest,
        targetProposalDigest: checkpoint.targetProposalDigest,
        topKEvaluationRecordDigest: checkpoint.topKEvaluationRecordDigest,
        witnessPolicyDigest: checkpoint.witnessPolicyDigest,
    });

    if (record.targetFinalityRecordDigest !== expectedRecordDigest) {
        refusedObjects.push(
            createRefusal(
                'TargetFinalityPolicyMismatch',
                'Target finality record digest does not match its canonical payload.',
                record.targetFinalityRecordDigest,
                'TargetFinalityRecord',
            ),
        );
    }
    if (
        record.objectType !== 'TargetFinalityRecord' ||
        record.objectVersion !== 1 ||
        checkpoint.objectType !== 'TargetFinalityCheckpoint' ||
        checkpoint.objectVersion !== 1
    ) {
        refusedObjects.push(
            createRefusal(
                'TargetFinalityPolicyMismatch',
                'Target finality record object shape is not canonical.',
                record.targetFinalityRecordDigest,
                'TargetFinalityRecord',
            ),
        );
    }
    if (record.ceremonyId !== input.boardEvidence.ceremonyId) {
        refusedObjects.push(
            createRefusal(
                'WrongCeremony',
                'Target finality record ceremony does not match the board evidence.',
                record.targetFinalityRecordDigest,
                'TargetFinalityRecord',
            ),
        );
    }
    if (
        checkpoint.targetProposalDigest !== expectedProposalDigest ||
        record.targetProposalDigest !== expectedProposalDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'TargetFinalityPolicyMismatch',
                'Target finality must bind the exact target proposal digest.',
                record.targetFinalityRecordDigest,
                'TargetFinalityRecord',
            ),
        );
    }
    if (
        checkpoint.targetFinalityCheckpointDigest !== expectedCheckpointDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'TargetFinalityPolicyMismatch',
                'Target finality checkpoint digest does not match its canonical payload.',
                checkpoint.targetFinalityCheckpointDigest,
                'TargetFinalityCheckpoint',
            ),
        );
    }
    if (
        checkpoint.ceremonyId !== record.ceremonyId ||
        checkpoint.boardPolicyDigest !== input.boardEvidence.boardPolicyDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'TargetFinalityPolicyMismatch',
                'Target finality checkpoint does not bind the ceremony and board policy.',
                checkpoint.targetFinalityCheckpointDigest,
                'TargetFinalityCheckpoint',
            ),
        );
    }
    if (
        record.targetFinalityPolicyDigest !==
            targetFinalityPolicy.targetFinalityPolicyDigest ||
        record.targetFinalityScope !==
            targetFinalityPolicy.targetFinalityScope ||
        checkpoint.targetFinalityPolicyDigest !==
            targetFinalityPolicy.targetFinalityPolicyDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'TargetFinalityPolicyMismatch',
                'Target finality record does not match the target-finality policy.',
                record.targetFinalityRecordDigest,
                'TargetFinalityRecord',
            ),
        );
    }
    if (
        record.witnessPolicyDigest !== witnessPolicy.witnessPolicyDigest ||
        checkpoint.witnessPolicyDigest !== witnessPolicy.witnessPolicyDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'WitnessPolicyMismatch',
                'Target finality record does not match the witness policy.',
                record.targetFinalityRecordDigest,
                'TargetFinalityRecord',
            ),
        );
    }
    if (
        witnessPolicy.witnessPolicyDigest !==
        deriveWitnessPolicyDigest({
            totalWitnesses: witnessPolicy.totalWitnesses,
            witnessIdentities: witnessPolicy.witnessIdentities,
            witnessQuorum: witnessPolicy.witnessQuorum,
        })
    ) {
        refusedObjects.push(
            createRefusal(
                'WitnessPolicyMismatch',
                'Witness policy digest does not match its canonical payload.',
                record.targetFinalityRecordDigest,
                'TargetFinalityRecord',
            ),
        );
    }
    if (
        targetFinalityPolicy.targetFinalityPolicyDigest !==
        deriveTargetFinalityPolicyDigest({
            targetFinalityScope: targetFinalityPolicy.targetFinalityScope,
            totalWitnesses: targetFinalityPolicy.totalWitnesses,
            witnessQuorum: targetFinalityPolicy.witnessQuorum,
        })
    ) {
        refusedObjects.push(
            createRefusal(
                'TargetFinalityPolicyMismatch',
                'Target-finality policy digest does not match its canonical payload.',
                record.targetFinalityRecordDigest,
                'TargetFinalityRecord',
            ),
        );
    }
    if (
        witnessPolicy.totalWitnesses !== 7 ||
        witnessPolicy.witnessQuorum !== 5 ||
        targetFinalityPolicy.totalWitnesses !== 7 ||
        targetFinalityPolicy.witnessQuorum !== 5
    ) {
        refusedObjects.push(
            createRefusal(
                'WitnessPolicyMismatch',
                'Target finality requires the mandatory 5-of-7 witness policy.',
                record.targetFinalityRecordDigest,
                'TargetFinalityRecord',
            ),
        );
    }
    if (
        witnessPolicy.witnessIdentities.length !== 7 ||
        new Set(witnessPolicy.witnessIdentities).size !== 7
    ) {
        refusedObjects.push(
            createRefusal(
                'WitnessPolicyMismatch',
                'Target finality requires seven distinct witness identities.',
                record.targetFinalityRecordDigest,
                'TargetFinalityRecord',
            ),
        );
    }
    const witnessPublicKeyDigests = witnessPolicy.witnessIdentities.map(
        (witnessIdentity) => input.witnessPublicKeyDigests[witnessIdentity],
    );
    if (
        witnessPublicKeyDigests.some(
            (publicKeyDigest) => !isProtocolDigestString(publicKeyDigest),
        ) ||
        new Set(witnessPublicKeyDigests).size !==
            witnessPolicy.witnessIdentities.length
    ) {
        refusedObjects.push(
            createRefusal(
                'WitnessPolicyMismatch',
                'Target finality requires seven distinct canonical witness public-key digests.',
                record.targetFinalityRecordDigest,
                'TargetFinalityRecord',
            ),
        );
    }
    if (
        record.inclusionProof.boardHeadDigest !==
            checkpoint.finalizedBoardHeadDigest ||
        record.inclusionProof.includedObjectType !== 'TopKEvaluationRecord' ||
        record.inclusionProof.includedObjectDigest !==
            checkpoint.topKEvaluationRecordDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'TopKEvaluationRecordNotIncluded',
                'Target finality must finalize a board head containing the typed top-k evaluation record digest.',
                record.targetFinalityRecordDigest,
                'TargetFinalityRecord',
            ),
        );
    }

    return refusedObjects;
};

const verifyWitnessCheckpoint = (
    input: TargetFinalityVerificationInput,
    record: TargetFinalityRecord,
    checkpoint: WitnessCheckpoint,
): readonly RefusalRecord[] => {
    const { targetFinalityPolicy, witnessPolicy } = input;
    const finalityCheckpoint = record.targetFinalityCheckpoint;
    const refusedObjects: RefusalRecord[] = [];
    const expectedCheckpointDigest = deriveWitnessCheckpointDigest({
        ceremonyId: checkpoint.ceremonyId,
        objectType: checkpoint.objectType,
        objectVersion: checkpoint.objectVersion,
        targetFinalityCheckpointDigest:
            checkpoint.targetFinalityCheckpointDigest,
        targetFinalityPolicyDigest: checkpoint.targetFinalityPolicyDigest,
        targetFinalityScope: checkpoint.targetFinalityScope,
        targetProposalDigest: checkpoint.targetProposalDigest,
        witnessIdentity: checkpoint.witnessIdentity,
        witnessPolicyDigest: checkpoint.witnessPolicyDigest,
    });
    const expectedPublicKeyDigest =
        input.witnessPublicKeyDigests[checkpoint.witnessIdentity];

    if (checkpoint.checkpointDigest !== expectedCheckpointDigest) {
        refusedObjects.push(
            createRefusal(
                'InvalidSignedRoot',
                'Witness checkpoint digest does not match its canonical payload.',
                checkpoint.checkpointDigest,
                'WitnessCheckpoint',
            ),
        );
    }
    if (!witnessPolicy.witnessIdentities.includes(checkpoint.witnessIdentity)) {
        refusedObjects.push(
            createRefusal(
                'UnknownWitness',
                'Witness checkpoint signer is not in the witness policy.',
                checkpoint.checkpointDigest,
                'WitnessCheckpoint',
            ),
        );
    }
    if (
        checkpoint.objectType !== 'WitnessCheckpoint' ||
        checkpoint.objectVersion !== 1
    ) {
        refusedObjects.push(
            createRefusal(
                'InvalidSignedRoot',
                'Witness checkpoint object shape is not canonical.',
                checkpoint.checkpointDigest,
                'WitnessCheckpoint',
            ),
        );
    }
    if (expectedPublicKeyDigest === undefined) {
        refusedObjects.push(
            createRefusal(
                'UnknownWitness',
                'Witness checkpoint signer has no known public key.',
                checkpoint.checkpointDigest,
                'WitnessCheckpoint',
            ),
        );
    }
    if (
        checkpoint.ceremonyId !== record.ceremonyId ||
        checkpoint.targetProposalDigest !== record.targetProposalDigest ||
        checkpoint.targetFinalityCheckpointDigest !==
            finalityCheckpoint.targetFinalityCheckpointDigest ||
        checkpoint.witnessPolicyDigest !== witnessPolicy.witnessPolicyDigest ||
        checkpoint.targetFinalityPolicyDigest !==
            targetFinalityPolicy.targetFinalityPolicyDigest ||
        checkpoint.targetFinalityScope !== record.targetFinalityScope
    ) {
        refusedObjects.push(
            createRefusal(
                'TargetFinalityPolicyMismatch',
                'Witness checkpoint does not bind the exact finalized head and policies.',
                checkpoint.checkpointDigest,
                'WitnessCheckpoint',
            ),
        );
    }

    const signatureResult = verifySignedObjectSignature(checkpoint.signature, {
        objectType: 'WitnessCheckpoint',
        objectVersion: 1,
        signerRole: 'Witness',
        signerIdentity: checkpoint.witnessIdentity,
        ceremonyId: record.ceremonyId,
        publicKeyDigest: expectedPublicKeyDigest,
        manifestDigest: finalityCheckpoint.electionManifestDigest,
        objectRoot: checkpoint.checkpointDigest,
        boardHeadDigest: finalityCheckpoint.finalizedBoardHeadDigest,
        byteLength: signedObjectRootByteLength,
        recoveryEpoch: 0,
        deviceEpoch: 0,
        contextDigest: defaultSignedRootContextDigest,
    });
    refusedObjects.push(...signatureResult.refusedObjects);

    return refusedObjects;
};

const collectValidWitnessIdentitiesForRecord = (
    input: TargetFinalityVerificationInput,
    record: TargetFinalityRecord,
): readonly string[] | undefined => {
    const headsByDigest = buildBoardHeadMap(
        input.boardEvidence.signedBoardHeads,
    );
    const refusedObjects: RefusalRecord[] = [
        ...verifyTargetRecordShape(input, record),
        ...verifyInclusionProof(record.inclusionProof, headsByDigest),
    ];
    const validWitnessIdentities: string[] = [];
    const seenWitnessIdentities = new Set<string>();

    for (const checkpoint of record.witnessCheckpoints) {
        if (seenWitnessIdentities.has(checkpoint.witnessIdentity)) {
            refusedObjects.push(
                createRefusal(
                    'DuplicateWitness',
                    'Duplicate witness signatures do not count twice.',
                    record.targetFinalityRecordDigest,
                    'TargetFinalityRecord',
                ),
            );
            continue;
        }
        seenWitnessIdentities.add(checkpoint.witnessIdentity);

        const checkpointRefusals = verifyWitnessCheckpoint(
            input,
            record,
            checkpoint,
        );
        refusedObjects.push(...checkpointRefusals);
        if (checkpointRefusals.length === 0) {
            validWitnessIdentities.push(checkpoint.witnessIdentity);
        }
    }

    if (validWitnessIdentities.length < input.witnessPolicy.witnessQuorum) {
        refusedObjects.push(
            createRefusal(
                'WitnessQuorumNotReached',
                'Target finality requires five distinct valid witness checkpoints.',
                record.targetFinalityRecordDigest,
                'TargetFinalityRecord',
            ),
        );
    }

    return refusedObjects.length === 0 ? validWitnessIdentities : undefined;
};

const findFinalityForkEvidence = (
    input: TargetFinalityVerificationInput,
    validWitnessIdentities: readonly string[],
): ConflictingHeadEvidence | undefined => {
    for (const conflictingRecord of input.conflictingRecords ?? []) {
        if (
            conflictingRecord.ceremonyId !== input.record.ceremonyId ||
            conflictingRecord.targetFinalityScope !==
                input.record.targetFinalityScope ||
            conflictingRecord.targetProposalDigest ===
                input.record.targetProposalDigest
        ) {
            continue;
        }

        const validConflictingWitnessIdentities =
            collectValidWitnessIdentitiesForRecord(input, conflictingRecord);
        if (validConflictingWitnessIdentities === undefined) {
            continue;
        }
        const conflictingWitnesses = new Set(validConflictingWitnessIdentities);
        const equivocatingWitnessIdentities = validWitnessIdentities.filter(
            (witnessIdentity) => conflictingWitnesses.has(witnessIdentity),
        );
        if (
            equivocatingWitnessIdentities.length <
            2 * input.witnessPolicy.witnessQuorum -
                input.witnessPolicy.totalWitnesses
        ) {
            continue;
        }
        const evidence = {
            ceremonyId: input.record.ceremonyId,
            boardPolicyDigest: input.boardEvidence.boardPolicyDigest,
            leftBoardHeadDigest:
                input.record.targetFinalityCheckpoint.finalizedBoardHeadDigest,
            rightBoardHeadDigest:
                conflictingRecord.targetFinalityCheckpoint
                    .finalizedBoardHeadDigest,
            targetFinalityScope: input.record.targetFinalityScope,
            equivocatingWitnessIdentities,
        };

        return {
            ...evidence,
            evidenceDigest: deriveWitnessEquivocationEvidenceDigest(evidence),
        };
    }

    return undefined;
};

const verifyTargetFinalityUnchecked = (
    input: TargetFinalityVerificationInput,
): TargetFinalityVerification => {
    const boardResult = verifyBoardConsistency(input.boardEvidence);
    const headsByDigest = buildBoardHeadMap(
        input.boardEvidence.signedBoardHeads,
    );
    const refusedObjects: RefusalRecord[] = [
        ...boardResult.refusedObjects,
        ...verifyTargetRecordShape(input, input.record),
        ...verifyInclusionProof(input.record.inclusionProof, headsByDigest),
    ];
    const validWitnessIdentities: string[] = [];
    const duplicateWitnessIdentities = new Set<string>();
    const seenWitnessIdentities = new Set<string>();

    for (const checkpoint of input.record.witnessCheckpoints) {
        if (seenWitnessIdentities.has(checkpoint.witnessIdentity)) {
            duplicateWitnessIdentities.add(checkpoint.witnessIdentity);
        }
        seenWitnessIdentities.add(checkpoint.witnessIdentity);

        const checkpointRefusals = verifyWitnessCheckpoint(
            input,
            input.record,
            checkpoint,
        );
        refusedObjects.push(...checkpointRefusals);
        if (
            checkpointRefusals.length === 0 &&
            !validWitnessIdentities.includes(checkpoint.witnessIdentity)
        ) {
            validWitnessIdentities.push(checkpoint.witnessIdentity);
        }
    }

    for (const witnessIdentity of duplicateWitnessIdentities) {
        refusedObjects.push(
            createRefusal(
                'DuplicateWitness',
                'Duplicate witness signatures do not count twice.',
                input.record.targetFinalityRecordDigest,
                'TargetFinalityRecord',
            ),
        );
        const duplicateIndex = validWitnessIdentities.indexOf(witnessIdentity);
        if (duplicateIndex >= 0) {
            validWitnessIdentities.splice(duplicateIndex, 1);
        }
    }

    if (validWitnessIdentities.length < input.witnessPolicy.witnessQuorum) {
        refusedObjects.push(
            createRefusal(
                'WitnessQuorumNotReached',
                'Target finality requires five distinct valid witness checkpoints.',
                input.record.targetFinalityRecordDigest,
                'TargetFinalityRecord',
            ),
        );
    }

    const finalityForkEvidence = findFinalityForkEvidence(
        input,
        validWitnessIdentities,
    );
    const forkEvidence = finalityForkEvidence ?? boardResult.forkEvidence;
    const equivocatingWitnessIdentities =
        forkEvidence?.equivocatingWitnessIdentities ?? [];
    const statusLabels: readonly ProtocolVerificationStatusLabel[] =
        forkEvidence === undefined
            ? []
            : uniqueStrings([
                  'BoardForkSuspected',
                  'BoardEvidencePublished',
                  'ForkedElection',
                  ...(equivocatingWitnessIdentities.length > 0
                      ? (['WitnessEquivocationEvidence'] as const)
                      : []),
              ]);
    const acceptedDigests = uniqueStrings([
        ...boardResult.acceptedDigests,
        input.record.targetFinalityRecordDigest,
        ...input.record.witnessCheckpoints.map(
            (checkpoint) => checkpoint.checkpointDigest,
        ),
    ]);
    const finalityAccepted =
        refusedObjects.length === 0 && forkEvidence === undefined;

    return {
        ok: finalityAccepted,
        statusLabels,
        acceptedDigests: finalityAccepted ? acceptedDigests : [],
        refusedObjects:
            forkEvidence === undefined
                ? refusedObjects
                : [
                      ...refusedObjects,
                      createRefusal(
                          'BoardForkDetected',
                          'Supplied target-finality evidence contains conflicting finalized heads.',
                          forkEvidence.evidenceDigest,
                      ),
                  ],
        forkEvidence,
        targetFinalityRecordDigest:
            refusedObjects.length === 0 && forkEvidence === undefined
                ? input.record.targetFinalityRecordDigest
                : undefined,
        targetProposalDigest:
            refusedObjects.length === 0 && forkEvidence === undefined
                ? input.record.targetProposalDigest
                : undefined,
        targetFinalityCheckpointDigest:
            refusedObjects.length === 0 && forkEvidence === undefined
                ? input.record.targetFinalityCheckpoint
                      .targetFinalityCheckpointDigest
                : undefined,
        validWitnessIdentities,
        equivocatingWitnessIdentities,
    };
};

export const verifyTargetFinality = (
    input: TargetFinalityVerificationInput,
): TargetFinalityVerification => {
    try {
        return verifyTargetFinalityUnchecked(input);
    } catch {
        return {
            ok: false,
            statusLabels: [],
            acceptedDigests: [],
            refusedObjects: [
                createRefusal(
                    'TargetFinalityPolicyMismatch',
                    'Target finality evidence could not be canonicalized or validated.',
                    undefined,
                    'TargetFinalityRecord',
                ),
            ],
            validWitnessIdentities: [],
            equivocatingWitnessIdentities: [],
        };
    }
};
