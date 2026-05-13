import type {
    ConflictingHeadEvidence,
    ProtocolDigest,
    ProtocolVerificationStatusLabel,
    RefusalRecord,
    TargetFinalityPolicy,
    TargetFinalityRecord,
    TargetFinalityVerification,
    TargetFinalityVerificationInput,
    WitnessCheckpoint,
    WitnessPolicy,
} from '@sealed-lattice/types';

import {
    deriveConflictingHeadEvidenceDigest,
    isVerifiedAncestor,
    verifyBoardConsistency,
    verifyInclusionProof,
} from '../board/index.js';
import { deriveProtocolDigest } from '../common/digests.js';
import { verifySignedObjectSignature } from '../common/signatures.js';
import {
    buildBoardHeadMap,
    createRefusal,
    uniqueStrings,
} from '../common/verification-helpers.js';

export const deriveWitnessCheckpointDigest = (
    checkpoint: Omit<WitnessCheckpoint, 'checkpointDigest' | 'signature'>,
): ProtocolDigest =>
    deriveProtocolDigest('WitnessCheckpointDigest', {
        ceremonyId: checkpoint.ceremonyId,
        finalizedBoardHeadDigest: checkpoint.finalizedBoardHeadDigest,
        objectType: checkpoint.objectType,
        objectVersion: checkpoint.objectVersion,
        targetFinalityPolicyDigest: checkpoint.targetFinalityPolicyDigest,
        targetPhase: checkpoint.targetPhase,
        witnessIdentity: checkpoint.witnessIdentity,
        witnessPolicyDigest: checkpoint.witnessPolicyDigest,
    });

export const deriveWitnessPolicyDigest = (
    policy: Omit<WitnessPolicy, 'witnessPolicyDigest'>,
): ProtocolDigest =>
    deriveProtocolDigest('WitnessPolicyDigest', {
        totalWitnesses: policy.totalWitnesses,
        witnessIdentities: [...policy.witnessIdentities].sort((left, right) =>
            left.localeCompare(right),
        ),
        witnessQuorum: policy.witnessQuorum,
    });

export const deriveTargetFinalityPolicyDigest = (
    policy: Omit<TargetFinalityPolicy, 'targetFinalityPolicyDigest'>,
): ProtocolDigest =>
    deriveProtocolDigest('TargetFinalityPolicyDigest', {
        targetPhase: policy.targetPhase,
        totalWitnesses: policy.totalWitnesses,
        witnessQuorum: policy.witnessQuorum,
    });

export const deriveTargetFinalityRecordDigest = (
    record: Omit<TargetFinalityRecord, 'targetFinalityRecordDigest'>,
): ProtocolDigest =>
    deriveProtocolDigest('TargetFinalityRecordDigest', {
        ceremonyId: record.ceremonyId,
        finalizedBoardHeadDigest: record.finalizedBoardHeadDigest,
        inclusionProof: record.inclusionProof,
        objectType: record.objectType,
        objectVersion: record.objectVersion,
        targetFinalityPolicyDigest: record.targetFinalityPolicyDigest,
        targetPhase: record.targetPhase,
        topKEvaluationRecordDigest: record.topKEvaluationRecordDigest,
        witnessCheckpoints: record.witnessCheckpoints.map(
            (checkpoint) => checkpoint.checkpointDigest,
        ),
        witnessPolicyDigest: record.witnessPolicyDigest,
    });

const verifyTargetRecordShape = (
    input: TargetFinalityVerificationInput,
    record: TargetFinalityRecord = input.record,
): readonly RefusalRecord[] => {
    const { targetFinalityPolicy, witnessPolicy } = input;
    const refusedObjects: RefusalRecord[] = [];
    const expectedRecordDigest = deriveTargetFinalityRecordDigest({
        ceremonyId: record.ceremonyId,
        finalizedBoardHeadDigest: record.finalizedBoardHeadDigest,
        inclusionProof: record.inclusionProof,
        objectType: record.objectType,
        objectVersion: record.objectVersion,
        targetFinalityPolicyDigest: record.targetFinalityPolicyDigest,
        targetPhase: record.targetPhase,
        topKEvaluationRecordDigest: record.topKEvaluationRecordDigest,
        witnessCheckpoints: record.witnessCheckpoints,
        witnessPolicyDigest: record.witnessPolicyDigest,
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
        record.objectVersion !== 1
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
        record.targetFinalityPolicyDigest !==
            targetFinalityPolicy.targetFinalityPolicyDigest ||
        record.targetPhase !== targetFinalityPolicy.targetPhase
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
    if (record.witnessPolicyDigest !== witnessPolicy.witnessPolicyDigest) {
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
            targetPhase: targetFinalityPolicy.targetPhase,
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
    if (
        record.inclusionProof.boardHeadDigest !==
            record.finalizedBoardHeadDigest ||
        record.inclusionProof.includedObjectType !== 'TopKEvaluationRecord' ||
        record.inclusionProof.includedObjectDigest !==
            record.topKEvaluationRecordDigest
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
    const refusedObjects: RefusalRecord[] = [];
    const expectedCheckpointDigest = deriveWitnessCheckpointDigest({
        ceremonyId: checkpoint.ceremonyId,
        finalizedBoardHeadDigest: checkpoint.finalizedBoardHeadDigest,
        objectType: checkpoint.objectType,
        objectVersion: checkpoint.objectVersion,
        targetFinalityPolicyDigest: checkpoint.targetFinalityPolicyDigest,
        targetPhase: checkpoint.targetPhase,
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
        checkpoint.finalizedBoardHeadDigest !==
            record.finalizedBoardHeadDigest ||
        checkpoint.witnessPolicyDigest !== witnessPolicy.witnessPolicyDigest ||
        checkpoint.targetFinalityPolicyDigest !==
            targetFinalityPolicy.targetFinalityPolicyDigest ||
        checkpoint.targetPhase !== record.targetPhase
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
        manifestHash: null,
        objectRoot: checkpoint.checkpointDigest,
        boardHeadHash: record.finalizedBoardHeadDigest,
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
    const headsByDigest = buildBoardHeadMap(
        input.boardEvidence.signedBoardHeads,
    );

    for (const conflictingRecord of input.conflictingRecords ?? []) {
        if (
            conflictingRecord.ceremonyId !== input.record.ceremonyId ||
            conflictingRecord.targetPhase !== input.record.targetPhase ||
            conflictingRecord.finalizedBoardHeadDigest ===
                input.record.finalizedBoardHeadDigest
        ) {
            continue;
        }

        const leftIsAncestor = isVerifiedAncestor(
            input.record.finalizedBoardHeadDigest,
            conflictingRecord.finalizedBoardHeadDigest,
            headsByDigest,
        );
        const rightIsAncestor = isVerifiedAncestor(
            conflictingRecord.finalizedBoardHeadDigest,
            input.record.finalizedBoardHeadDigest,
            headsByDigest,
        );
        if (leftIsAncestor || rightIsAncestor) {
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
            leftBoardHeadDigest: input.record.finalizedBoardHeadDigest,
            rightBoardHeadDigest: conflictingRecord.finalizedBoardHeadDigest,
            targetPhase: input.record.targetPhase,
            equivocatingWitnessIdentities,
        };

        return {
            ...evidence,
            evidenceDigest: deriveConflictingHeadEvidenceDigest(evidence),
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
            : [
                  'BoardForkSuspected',
                  'BoardEvidencePublished',
                  'ForkedElection',
              ];
    const acceptedDigests = uniqueStrings([
        ...boardResult.acceptedDigests,
        input.record.targetFinalityRecordDigest,
        ...input.record.witnessCheckpoints.map(
            (checkpoint) => checkpoint.checkpointDigest,
        ),
    ]);

    return {
        ok: refusedObjects.length === 0 && forkEvidence === undefined,
        statusLabels,
        acceptedDigests,
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
        finalizedBoardHeadDigest:
            refusedObjects.length === 0 && forkEvidence === undefined
                ? input.record.finalizedBoardHeadDigest
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
